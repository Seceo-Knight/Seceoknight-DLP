"""
Deterministic Decision Engine

Strict evaluation algorithm:
1. Fetch candidate policies (active, matching channel/action)
2. Sort by priority DESC (highest priority first)
3. Evaluate conditions (AND/OR tree)
4. First matching policy wins
5. Conflict resolution: BLOCK > ALERT > ENCRYPT > ALLOW
6. Default: ALLOW + log

Performance target: <100ms decision latency
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import structlog

from app.policies.database_policy_evaluator import DatabasePolicyEvaluator, PolicyMatch

logger = structlog.get_logger()

# Action precedence: higher number = takes priority in conflicts
ACTION_PRECEDENCE = {
    "block": 100,
    "quarantine": 90,
    "encrypt": 80,
    "alert": 50,
    "warn": 40,
    "allow": 10,
    "log": 5,
}

DEFAULT_CACHE_TTL = 300  # 5 minutes


@dataclass
class Decision:
    """Final enforcement decision returned to the agent"""
    action: str              # block, allow, alert, encrypt, quarantine
    reason: str              # human-readable explanation
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    severity: Optional[str] = None
    cache_ttl: int = DEFAULT_CACHE_TTL
    classification_level: Optional[str] = None
    confidence_score: float = 0.0
    matched_policies: List[Dict[str, Any]] = field(default_factory=list)
    should_log: bool = True
    should_create_incident: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.action,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "severity": self.severity,
            "cache_ttl": self.cache_ttl,
            "classification_level": self.classification_level,
            "confidence_score": self.confidence_score,
            "matched_policies": self.matched_policies,
            "should_log": self.should_log,
            "should_create_incident": self.should_create_incident,
        }


class DecisionEngine:
    """
    Deterministic policy decision engine.

    Algorithm:
    1. Get all policy matches from DatabasePolicyEvaluator
    2. Sort matches by priority DESC
    3. For each match, extract the highest-precedence action
    4. Apply conflict resolution: highest priority wins; on tie, BLOCK > ALERT > ALLOW
    5. Return single deterministic decision
    """

    def __init__(self, policy_evaluator: Optional[DatabasePolicyEvaluator] = None):
        self._evaluator = policy_evaluator or DatabasePolicyEvaluator()

    async def evaluate(
        self,
        event: Dict[str, Any],
        classification_level: Optional[str] = None,
        confidence_score: float = 0.0,
    ) -> Decision:
        """
        Evaluate event against all policies and return a single deterministic decision.

        Args:
            event: Normalized event data with fields like event_type, file_name, channel, etc.
            classification_level: Pre-computed classification (Public/Internal/Confidential/Restricted)
            confidence_score: Classification confidence 0.0-1.0

        Returns:
            Decision object with action, reason, and metadata
        """
        start_time = datetime.utcnow()

        # Inject classification into event for policy condition matching
        if classification_level:
            event.setdefault("classification_metadata", {})["classification_level"] = classification_level
            event.setdefault("classification_metadata", {})["confidence_score"] = confidence_score

        # Step 1: Get all matching policies
        try:
            matches = await self._evaluator.evaluate_event(event)
        except Exception as e:
            logger.error("Policy evaluation failed, defaulting to ALLOW", error=str(e))
            return Decision(
                action="allow",
                reason=f"Policy evaluation error: {str(e)} — defaulting to allow",
                should_log=True,
            )

        if not matches:
            return Decision(
                action="allow",
                reason="No policy matched — default allow",
                classification_level=classification_level,
                confidence_score=confidence_score,
                should_log=True,
            )

        # Step 2: Sort by priority DESC (higher number = higher priority)
        sorted_matches = sorted(matches, key=lambda m: m.priority, reverse=True)

        # Step 3+4: Resolve conflicts using priority + action precedence
        decision = self._resolve_conflicts(sorted_matches)

        # Enrich with classification data
        decision.classification_level = classification_level
        decision.confidence_score = confidence_score

        # Determine if incident should be created
        if decision.action in ("block", "quarantine") or (decision.severity in ("high", "critical")):
            decision.should_create_incident = True

        elapsed_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        logger.info(
            "Decision rendered",
            action=decision.action,
            policy=decision.policy_name,
            elapsed_ms=round(elapsed_ms, 1),
            matched_count=len(matches),
        )

        return decision

    def _resolve_conflicts(self, sorted_matches: List[PolicyMatch]) -> Decision:
        """
        Conflict resolution algorithm:
        - Group by highest priority tier
        - Within the same priority, BLOCK > QUARANTINE > ENCRYPT > ALERT > ALLOW
        - Return the winning decision
        """
        if not sorted_matches:
            return Decision(action="allow", reason="No matches")

        # Get the highest priority value
        top_priority = sorted_matches[0].priority

        # Collect all matches at the highest priority level
        top_tier = [m for m in sorted_matches if m.priority == top_priority]

        # Within the top tier, find the highest-precedence action
        best_action = "allow"
        best_precedence = 0
        winning_match: Optional[PolicyMatch] = None

        for match in top_tier:
            for action_config in match.actions:
                action_type = (action_config.get("type") or "log").lower()
                precedence = ACTION_PRECEDENCE.get(action_type, 0)

                if precedence > best_precedence:
                    best_precedence = precedence
                    best_action = action_type
                    winning_match = match

        if not winning_match:
            winning_match = top_tier[0]

        # Build matched_policies summary for all matches
        all_matched = []
        for m in sorted_matches:
            actions_list = [a.get("type", "log") for a in m.actions]
            all_matched.append({
                "policy_id": m.policy_id,
                "policy_name": m.policy_name,
                "priority": m.priority,
                "severity": m.severity,
                "actions": actions_list,
            })

        # Build reason
        reason_parts = [f"Policy '{winning_match.policy_name}' (priority {winning_match.priority})"]
        if len(sorted_matches) > 1:
            reason_parts.append(f"{len(sorted_matches)} policies matched, highest priority wins")
        if len(top_tier) > 1:
            reason_parts.append(f"tie broken by action precedence ({best_action} > others)")

        # Determine cache TTL based on action type
        cache_ttl = DEFAULT_CACHE_TTL
        if best_action == "block":
            cache_ttl = 60  # shorter cache for blocks (re-evaluate sooner)
        elif best_action == "allow":
            cache_ttl = 600  # longer cache for allows

        return Decision(
            action=best_action,
            reason=" — ".join(reason_parts),
            policy_id=winning_match.policy_id,
            policy_name=winning_match.policy_name,
            severity=winning_match.severity,
            cache_ttl=cache_ttl,
            matched_policies=all_matched,
            should_log=True,
        )
