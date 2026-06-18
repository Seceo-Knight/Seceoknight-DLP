"""
Rule Service
Handles CRUD operations for classification rules
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
import hashlib
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func
from sqlalchemy.exc import IntegrityError

from app.models.rule import Rule

logger = structlog.get_logger()


class RuleService:
    """Service for managing classification rules"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_rule(
        self,
        name: str,
        type: str,
        created_by: UUID,
        description: Optional[str] = None,
        pattern: Optional[str] = None,
        regex_flags: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        case_sensitive: bool = False,
        dictionary_path: Optional[str] = None,
        threshold: int = 1,
        weight: float = 0.5,
        classification_labels: Optional[List[str]] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        enabled: bool = True,
    ) -> Rule:
        """
        Create a new rule.

        Args:
            name: Unique rule name
            type: Rule type ('regex', 'keyword', 'dictionary')
            created_by: User ID who created the rule
            ... other parameters

        Returns:
            Created Rule object

        Raises:
            ValueError: If validation fails
            IntegrityError: If name already exists
        """
        # Validate rule type
        valid_types = ['regex', 'keyword', 'dictionary']
        if type not in valid_types:
            raise ValueError(f"Invalid rule type. Must be one of: {valid_types}")

        # Validate type-specific fields
        if type == 'regex' and not pattern:
            raise ValueError("Regex rules require a pattern")
        if type == 'keyword' and not keywords:
            raise ValueError("Keyword rules require keywords list")
        if type == 'dictionary' and not dictionary_path:
            raise ValueError("Dictionary rules require dictionary_path")

        # Validate weight
        if not (0.0 <= weight <= 1.0):
            raise ValueError("Weight must be between 0.0 and 1.0")

        # Validate threshold
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")

        # Validate severity
        if severity:
            valid_severities = ['low', 'medium', 'high', 'critical']
            if severity not in valid_severities:
                raise ValueError(f"Invalid severity. Must be one of: {valid_severities}")

        # Calculate dictionary hash if provided
        dictionary_hash = None
        if dictionary_path:
            try:
                with open(dictionary_path, 'rb') as f:
                    dictionary_hash = hashlib.sha256(f.read()).hexdigest()
            except FileNotFoundError:
                logger.warning("Dictionary file not found", path=dictionary_path)

        rule = Rule(
            name=name,
            description=description,
            type=type,
            pattern=pattern,
            regex_flags=regex_flags,
            keywords=keywords,
            case_sensitive=case_sensitive,
            dictionary_path=dictionary_path,
            dictionary_hash=dictionary_hash,
            threshold=threshold,
            weight=weight,
            classification_labels=classification_labels,
            severity=severity,
            category=category,
            tags=tags,
            enabled=enabled,
            created_by=created_by,
        )

        self.session.add(rule)
        try:
            await self.session.commit()
            await self.session.refresh(rule)
        except IntegrityError as e:
            await self.session.rollback()
            raise ValueError(f"Rule with name '{name}' already exists") from e

        logger.info(
            "Rule created",
            rule_id=str(rule.id),
            rule_name=rule.name,
            rule_type=rule.type
        )

        return rule

    async def get_rule(self, rule_id: UUID) -> Optional[Rule]:
        """Get rule by ID"""
        stmt = select(Rule).where(Rule.id == rule_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_rule_by_name(self, name: str) -> Optional[Rule]:
        """Get rule by name"""
        stmt = select(Rule).where(Rule.name == name)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_rules(
        self,
        enabled_only: bool = False,
        type: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Rule]:
        """
        List rules with optional filters.

        Args:
            enabled_only: Only return enabled rules
            type: Filter by rule type
            category: Filter by category
            severity: Filter by severity
            skip: Pagination offset
            limit: Maximum results

        Returns:
            List of Rule objects
        """
        stmt = select(Rule)

        if enabled_only:
            stmt = stmt.where(Rule.enabled == True)
        if type:
            stmt = stmt.where(Rule.type == type)
        if category:
            stmt = stmt.where(Rule.category == category)
        if severity:
            stmt = stmt.where(Rule.severity == severity)

        stmt = stmt.order_by(Rule.weight.desc(), Rule.created_at.desc())
        stmt = stmt.offset(skip).limit(limit)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_rules(
        self,
        enabled_only: bool = False,
        type: Optional[str] = None,
        category: Optional[str] = None,
    ) -> int:
        """Count rules with filters"""
        stmt = select(func.count(Rule.id))

        if enabled_only:
            stmt = stmt.where(Rule.enabled == True)
        if type:
            stmt = stmt.where(Rule.type == type)
        if category:
            stmt = stmt.where(Rule.category == category)

        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def update_rule(
        self,
        rule_id: UUID,
        **updates: Dict[str, Any]
    ) -> Optional[Rule]:
        """
        Update rule fields.

        Args:
            rule_id: Rule ID to update
            **updates: Fields to update

        Returns:
            Updated Rule object or None if not found
        """
        # Validate updates
        if 'weight' in updates:
            if not (0.0 <= updates['weight'] <= 1.0):
                raise ValueError("Weight must be between 0.0 and 1.0")

        if 'threshold' in updates:
            if updates['threshold'] < 1:
                raise ValueError("Threshold must be at least 1")

        if 'severity' in updates:
            valid_severities = ['low', 'medium', 'high', 'critical']
            if updates['severity'] not in valid_severities:
                raise ValueError(f"Invalid severity. Must be one of: {valid_severities}")

        # Update dictionary hash if dictionary_path changed
        if 'dictionary_path' in updates:
            path = updates['dictionary_path']
            try:
                with open(path, 'rb') as f:
                    updates['dictionary_hash'] = hashlib.sha256(f.read()).hexdigest()
            except FileNotFoundError:
                logger.warning("Dictionary file not found", path=path)

        stmt = (
            update(Rule)
            .where(Rule.id == rule_id)
            .values(**updates)
            .returning(Rule)
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        rule = result.scalar_one_or_none()
        if rule:
            logger.info("Rule updated", rule_id=str(rule_id), updates=list(updates.keys()))

        return rule

    async def delete_rule(self, rule_id: UUID) -> bool:
        """
        Delete a rule.

        Returns:
            True if deleted, False if not found
        """
        stmt = delete(Rule).where(Rule.id == rule_id)
        result = await self.session.execute(stmt)
        await self.session.commit()

        deleted = result.rowcount > 0
        if deleted:
            logger.info("Rule deleted", rule_id=str(rule_id))

        return deleted

    async def toggle_rule(self, rule_id: UUID, enabled: bool) -> Optional[Rule]:
        """Enable or disable a rule"""
        return await self.update_rule(rule_id, enabled=enabled)

    async def increment_match_count(self, rule_id: UUID) -> None:
        """Increment match count for analytics"""
        from datetime import datetime
        await self.update_rule(
            rule_id,
            match_count=Rule.match_count + 1,
            last_matched_at=datetime.utcnow()
        )

    async def get_rule_statistics(self) -> Dict[str, Any]:
        """Get overall rule statistics"""
        total = await self.count_rules()
        enabled = await self.count_rules(enabled_only=True)

        # Count by type
        regex_count = await self.count_rules(type='regex')
        keyword_count = await self.count_rules(type='keyword')
        dictionary_count = await self.count_rules(type='dictionary')

        return {
            "total_rules": total,
            "enabled_rules": enabled,
            "disabled_rules": total - enabled,
            "by_type": {
                "regex": regex_count,
                "keyword": keyword_count,
                "dictionary": dictionary_count,
            }
        }
