"""
Policy Service - Business logic for DLP policy management
"""

from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.policy import Policy
from app.policies.cache_control import bump_policy_cache


class PolicyService:
    """Service for policy-related operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_policy_by_id(self, policy_id: str) -> Optional[Policy]:
        """
        Fetch policy by ID

        Args:
            policy_id: UUID of the policy

        Returns:
            Policy object or None if not found
        """
        result = await self.db.execute(
            select(Policy)
            .where(Policy.id == policy_id)
            .where(Policy.deleted_at == None)  # noqa: E711
        )
        return result.scalar_one_or_none()

    async def get_policy_by_name(self, name: str) -> Optional[Policy]:
        """
        Fetch policy by name

        Args:
            name: Policy name

        Returns:
            Policy object or None if not found
        """
        result = await self.db.execute(
            select(Policy).where(Policy.name == name)
        )
        return result.scalar_one_or_none()

    async def get_all_policies(
        self,
        skip: int = 0,
        limit: int = 100,
        enabled_only: bool = False,
    ) -> List[Policy]:
        """
        Fetch all policies with optional filtering

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            enabled_only: If True, return only enabled policies

        Returns:
            List of Policy objects
        """
        query = select(Policy).where(Policy.deleted_at == None)  # noqa: E711

        if enabled_only:
            query = query.where(Policy.status == "active")

        query = query.offset(skip).limit(limit).order_by(Policy.priority.desc(), Policy.created_at.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def create_policy(
        self,
        name: str,
        description: str,
        conditions: dict,
        actions: dict,
        created_by: str,
        enabled: bool = True,
        priority: int = 100,
        compliance_tags: Optional[List[str]] = None,
        type: Optional[str] = None,
        severity: Optional[str] = None,
        config: Optional[dict] = None,
        agent_ids: Optional[List[str]] = None,
    ) -> Policy:
        """
        Create a new DLP policy

        Args:
            name: Policy name
            description: Policy description
            conditions: Detection conditions (JSON)
            actions: Actions to take when policy matches (JSON)
            created_by: UUID of user creating the policy
            enabled: Whether policy is enabled
            priority: Policy priority (higher = evaluated first)
            compliance_tags: Compliance framework tags (GDPR, HIPAA, etc.)

        Returns:
            Created Policy object

        Raises:
            ValueError: If policy with name already exists or invalid structure
        """
        # Check if policy already exists
        existing_policy = await self.get_policy_by_name(name)
        if existing_policy:
            raise ValueError(f"Policy with name '{name}' already exists")

        # Validate policy structure
        self._validate_policy_structure(conditions, actions)

        # Create new policy
        policy = Policy(
            name=name,
            description=description,
            status="active" if enabled else "inactive",
            priority=priority,
            conditions=conditions,
            actions=actions,
            compliance_tags=compliance_tags or [],
            created_by=created_by,
            type=type,
            severity=severity,
            config=config,
            agent_ids=agent_ids or [],
        )

        self.db.add(policy)
        await self.db.commit()
        await self.db.refresh(policy)
        bump_policy_cache()

        return policy

    async def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        conditions: Optional[dict] = None,
        actions: Optional[dict] = None,
        enabled: Optional[bool] = None,
        priority: Optional[int] = None,
        compliance_tags: Optional[List[str]] = None,
        type: Optional[str] = None,
        severity: Optional[str] = None,
        config: Optional[dict] = None,
        agent_ids: Optional[List[str]] = None,
    ) -> Optional[Policy]:
        """
        Update policy details

        Args:
            policy_id: UUID of the policy
            name: New policy name
            description: New description
            conditions: New conditions
            actions: New actions
            enabled: New enabled status
            priority: New priority
            compliance_tags: New compliance tags

        Returns:
            Updated Policy object or None if not found

        Raises:
            ValueError: If invalid structure
        """
        policy = await self.get_policy_by_id(policy_id)
        if not policy:
            return None

        if name is not None:
            # Check if new name conflicts with a DIFFERENT policy
            existing = await self.get_policy_by_name(name)
            if existing and str(existing.id) != str(policy_id):
                raise ValueError(f"Policy with name '{name}' already exists")
            policy.name = name

        if description is not None:
            policy.description = description

        if conditions is not None:
            self._validate_conditions(conditions)
            policy.conditions = conditions

        if actions is not None:
            self._validate_actions(actions)
            policy.actions = actions

        if enabled is not None:
            policy.status = "active" if enabled else "inactive"

        if priority is not None:
            policy.priority = priority

        if compliance_tags is not None:
            policy.compliance_tags = compliance_tags

        if type is not None:
            policy.type = type

        if severity is not None:
            policy.severity = severity

        if config is not None:
            policy.config = config

        if agent_ids is not None:
            policy.agent_ids = agent_ids

        await self.db.commit()
        await self.db.refresh(policy)
        bump_policy_cache()

        return policy

    async def delete_policy(self, policy_id: str) -> bool:
        """
        Delete a policy

        Args:
            policy_id: UUID of the policy

        Returns:
            True if policy was deleted, False if not found
        """
        policy = await self.get_policy_by_id(policy_id)
        if not policy:
            return False

        # Soft delete — preserve for audit trail
        policy.deleted_at = datetime.now(timezone.utc)
        policy.status = "inactive"
        await self.db.commit()
        bump_policy_cache()
        return True

    async def enable_policy(self, policy_id: str) -> Optional[Policy]:
        """
        Enable a policy

        Args:
            policy_id: UUID of the policy

        Returns:
            Updated Policy object or None if not found
        """
        policy = await self.get_policy_by_id(policy_id)
        if not policy:
            return None

        policy.status = "active"

        await self.db.commit()
        await self.db.refresh(policy)
        bump_policy_cache()

        return policy

    async def disable_policy(self, policy_id: str) -> Optional[Policy]:
        """
        Disable a policy

        Args:
            policy_id: UUID of the policy

        Returns:
            Updated Policy object or None if not found
        """
        policy = await self.get_policy_by_id(policy_id)
        if not policy:
            return None

        policy.status = "inactive"

        await self.db.commit()
        await self.db.refresh(policy)
        bump_policy_cache()

        return policy

    async def get_enabled_policies(self) -> List[Policy]:
        """
        Get all enabled policies ordered by priority

        Returns:
            List of enabled Policy objects
        """
        return await self.get_all_policies(enabled_only=True, limit=1000)

    async def get_policy_count(self, enabled_only: bool = False) -> int:
        """
        Get total count of policies

        Args:
            enabled_only: If True, count only enabled policies

        Returns:
            Number of policies
        """
        from sqlalchemy import func

        query = select(func.count(Policy.id)).where(Policy.deleted_at == None)  # noqa: E711

        if enabled_only:
            query = query.where(Policy.status == "active")

        result = await self.db.execute(query)
        return result.scalar_one()

    async def get_policy_stats(self) -> dict:
        """
        Get policy statistics summary

        Returns:
            Dictionary with total, active, inactive counts
        """
        from sqlalchemy import func

        # Total policies (excluding soft-deleted)
        total_query = select(func.count(Policy.id)).where(Policy.deleted_at == None)  # noqa: E711
        total_result = await self.db.execute(total_query)
        total = total_result.scalar_one()

        # Active policies
        active_query = (
            select(func.count(Policy.id))
            .where(Policy.status == "active")
            .where(Policy.deleted_at == None)  # noqa: E711
        )
        active_result = await self.db.execute(active_query)
        active = active_result.scalar_one()

        # Inactive policies
        inactive = total - active

        # TODO: Add violations count when events are integrated
        # For now, return 0
        violations = 0

        return {
            "total": total,
            "active": active,
            "inactive": inactive,
            "violations": violations,
        }

    def _validate_policy_structure(self, conditions: dict, actions: dict) -> None:
        """
        Validate policy conditions and actions structure

        Args:
            conditions: Policy conditions
            actions: Policy actions

        Raises:
            ValueError: If structure is invalid
        """
        self._validate_conditions(conditions)
        self._validate_actions(actions)

    _VALID_OPERATORS = frozenset({
        "equals", "contains", "in", "starts_with", "matches_regex",
        ">=", "<=", ">", "<",
        "greater_than", "less_than",
        "greater_than_or_equal", "less_than_or_equal",
        "matches_any_prefix",
    })

    def _validate_conditions(self, conditions: dict) -> None:
        """
        Validate the JSON conditions structure used by the policy evaluator.

        Expected schema::

            {
              "match": "all" | "any" | "none",
              "rules": [
                {"field": "...", "operator": "...", "value": "..."},
                {"match": "any", "rules": [...]},   # nested group
              ]
            }
        """
        if not isinstance(conditions, dict):
            raise ValueError("Conditions must be a dictionary")

        if "match" not in conditions:
            raise ValueError("Conditions must contain 'match' field")

        valid_match_types = ["all", "any", "none"]
        if conditions["match"] not in valid_match_types:
            raise ValueError(f"Match type must be one of: {valid_match_types}")

        if "rules" not in conditions:
            raise ValueError("Conditions must contain 'rules' field")

        if not isinstance(conditions["rules"], list):
            raise ValueError("Rules must be a list")

        self._validate_rules_recursive(conditions["rules"], depth=0)

    def _validate_rules_recursive(self, rules: list, depth: int) -> None:
        """Validate each rule or nested group, with depth limit to prevent abuse."""
        if depth > 5:
            raise ValueError("Condition nesting exceeds maximum depth of 5")

        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"Rule at index {idx} must be a dictionary")

            # Nested group
            if "rules" in rule:
                if "match" not in rule:
                    raise ValueError(f"Nested group at index {idx} must contain 'match'")
                self._validate_rules_recursive(rule["rules"], depth + 1)
                continue

            # Leaf rule — must have field + operator + value
            if "field" not in rule:
                raise ValueError(f"Rule at index {idx} missing 'field'")
            if "operator" not in rule:
                raise ValueError(f"Rule at index {idx} missing 'operator'")
            if "value" not in rule:
                raise ValueError(f"Rule at index {idx} missing 'value'")
            if rule["operator"] not in self._VALID_OPERATORS:
                raise ValueError(
                    f"Rule at index {idx} has invalid operator '{rule['operator']}'. "
                    f"Valid operators: {sorted(self._VALID_OPERATORS)}"
                )

    def _validate_actions(self, actions: dict) -> None:
        """
        Validate policy actions structure

        Args:
            actions: Policy actions

        Raises:
            ValueError: If actions are invalid
        """
        if not isinstance(actions, dict):
            raise ValueError("Actions must be a dictionary")

        # Valid action types
        valid_actions = ["alert", "block", "quarantine", "encrypt", "redact", "log"]

        # At least one action must be specified
        if not any(action in actions for action in valid_actions):
            raise ValueError(f"At least one action must be specified: {valid_actions}")

