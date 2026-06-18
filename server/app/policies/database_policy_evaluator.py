"""
Database Policy Evaluator
Evaluates incoming events against policies stored in PostgreSQL
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Callable, AsyncIterator
import re
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_postgres_session
from app.services.policy_service import PolicyService

logger = structlog.get_logger()

from app.policies.cache_control import get_policy_cache_generation


@dataclass
class PolicyMatch:
    """Represents a matched policy and the actions that should execute"""

    policy_id: str
    policy_name: str
    severity: Optional[str]
    priority: int
    actions: List[Dict[str, Any]]
    matched_rules: List[Dict[str, Any]]
    rule_id: str = "root"


class DatabasePolicyEvaluator:
    """
    Loads enabled policies from PostgreSQL and evaluates events against them.
    """

    def __init__(
        self,
        session_provider: Callable[[], AsyncIterator[AsyncSession]] = get_postgres_session,
        cache_ttl_seconds: int = 5,
    ):
        self._session_provider = session_provider
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self._cached_policies: List[Any] = []
        self._cache_expires_at: Optional[datetime] = None
        self._cache_generation: int = -1  # Force first load
        self._regex_cache: Dict[str, re.Pattern] = {}

    async def evaluate_event(self, event: Dict[str, Any]) -> List[PolicyMatch]:
        """
        Evaluate an event against all enabled policies.
        Returns a list of PolicyMatch objects for policies that matched.
        """
        policies = await self._get_cached_policies()
        if not policies:
            return []

        matches: List[PolicyMatch] = []

        for policy in policies:
            conditions = policy.conditions or {}
            if not conditions.get("rules"):
                continue

            match_result, matched_rules = self._evaluate_conditions(conditions, event)
            if not match_result:
                continue

            prepared_actions = self._prepare_actions(policy)
            matches.append(
                PolicyMatch(
                    policy_id=str(policy.id),
                    policy_name=policy.name,
                    severity=policy.severity,
                    priority=policy.priority or 0,
                    actions=prepared_actions,
                    matched_rules=matched_rules,
                    rule_id=f"{policy.id}-root",
                )
            )

        return matches

    async def _get_cached_policies(self) -> List[Any]:
        current_gen = get_policy_cache_generation()
        cache_valid = (
            self._cache_expires_at
            and self._cache_expires_at > datetime.now(timezone.utc)
            and self._cached_policies
            and self._cache_generation == current_gen
        )
        if cache_valid:
            return self._cached_policies

        async with self._session_provider() as session:
            service = PolicyService(session)
            policies = await service.get_enabled_policies()

        self._cached_policies = policies
        self._cache_expires_at = datetime.now(timezone.utc) + self._cache_ttl
        self._cache_generation = current_gen

        logger.info(
            "Policy cache refreshed",
            policy_count=len(policies),
            cache_ttl=int(self._cache_ttl.total_seconds()),
        )

        return policies

    def _evaluate_conditions(self, conditions: Dict[str, Any], event: Dict[str, Any]) -> (bool, List[Dict[str, Any]]):
        match_type = conditions.get("match", "all").lower()
        rules: List[Dict[str, Any]] = conditions.get("rules", [])

        if not rules:
            return False, []

        matched_rules: List[Dict[str, Any]] = []
        results: List[bool] = []

        for rule in rules:
            if "rules" in rule:
                result, nested_matches = self._evaluate_conditions(rule, event)
                results.append(result)
                if result:
                    matched_rules.extend(nested_matches)
                continue

            result = self._evaluate_rule(rule, event)
            results.append(result)
            if result:
                matched_rules.append(rule)

        if match_type == "all":
            return all(results), matched_rules
        if match_type == "any":
            return any(results), matched_rules
        if match_type == "none":
            return (not any(results)), matched_rules

        return False, matched_rules

    def _evaluate_rule(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        field = rule.get("field")
        operator = rule.get("operator", "equals")
        value = rule.get("value")

        if field is None:
            return False

        event_value = self._extract_field_value(event, field)
        if event_value is None:
            return False

        try:
            # Numeric comparison operators (for confidence scores, counts, etc.)
            if operator in [">=", "greater_than_or_equal"]:
                return float(event_value) >= float(value)
            if operator in ["<=", "less_than_or_equal"]:
                return float(event_value) <= float(value)
            if operator in [">", "greater_than"]:
                return float(event_value) > float(value)
            if operator in ["<", "less_than"]:
                return float(event_value) < float(value)

            # String/pattern operators
            if operator == "matches_regex":
                pattern = self._get_regex(str(value))
                return bool(pattern.search(str(event_value)))
            if operator == "starts_with":
                return str(event_value).lower().startswith(str(value).lower())
            if operator == "matches_any_prefix":
                prefixes = value if isinstance(value, list) else [value]
                candidate = str(event_value).lower()
                return any(candidate.startswith(str(prefix).lower()) for prefix in prefixes)
            if operator == "in":
                options = value if isinstance(value, list) else [value]
                if isinstance(event_value, list):
                    return any(item in options for item in event_value)
                return str(event_value) in [str(opt) for opt in options]
            if operator == "equals":
                return str(event_value).lower() == str(value).lower()
            if operator == "contains":
                return str(value).lower() in str(event_value).lower()
        except Exception as exc:
            logger.warning(
                "Failed to evaluate rule",
                error=str(exc),
                field=field,
                operator=operator,
            )
            return False

        return False

    def _extract_field_value(self, event: Dict[str, Any], field: str) -> Optional[Any]:
        field_mappings = {
            "event_type": ["event.type", "event_type"],
            "event_subtype": ["event.subtype", "event_subtype"],
            "severity": ["event.severity", "severity"],
            "file_path": ["file.path", "file_path"],
            "file_extension": ["file.extension", "file_extension"],
            "clipboard_content": ["clipboard.content", "content", "clipboard_content"],
            "usb_event_type": ["usb.event_type", "usb_event_type"],
            "source_path": ["source_path", "file.source_path"],
            "destination_type": ["destination_type", "destination.type"],
            "source": ["source", "event.source"],
            "connection_id": ["connection_id", "metadata.connection_id"],
            "folder_id": ["folder_id", "metadata.folder_id"],
            # Classification fields
            "classification_level": ["classification_metadata.classification_level", "classification_level"],
            "confidence_score": ["classification_metadata.confidence_score", "confidence_score"],
            "matched_rules_count": ["classification_metadata.matched_rules_count", "matched_rules_count"],
            "total_matches": ["classification_metadata.total_matches", "total_matches"],
            "classification_engine": ["classification_metadata.engine", "classification_engine"],
        }

        candidate_paths = field_mappings.get(field, [field])

        for path in candidate_paths:
            value = self._get_value_by_path(event, path)
            if value is not None:
                return value

        return None

    def _get_value_by_path(self, data: Dict[str, Any], path: str) -> Optional[Any]:
        parts = path.split(".")
        current: Any = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current

    def _prepare_actions(self, policy) -> List[Dict[str, Any]]:
        actions_dict = policy.actions or {}
        prepared_actions: List[Dict[str, Any]] = []

        for action_type, params in actions_dict.items():
            if action_type == "log":
                continue

            action_payload = {"type": action_type}
            if isinstance(params, dict):
                action_payload.update(params)

            metadata = action_payload.setdefault("metadata", {})
            metadata.setdefault("policy_id", str(policy.id))
            metadata.setdefault("policy_name", policy.name)
            metadata.setdefault("policy_severity", policy.severity)

            prepared_actions.append(action_payload)

        return prepared_actions

    def _get_regex(self, pattern: str) -> re.Pattern:
        if pattern not in self._regex_cache:
            self._regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
        return self._regex_cache[pattern]

