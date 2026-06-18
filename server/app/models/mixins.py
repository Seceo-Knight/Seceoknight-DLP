"""
SQLAlchemy Mixins for SeceoKnight DLP models.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, event
from sqlalchemy.orm import Query


class SoftDeleteMixin:
    """
    Mixin that adds ``deleted_at`` column and helper methods.

    Usage:
        class MyModel(Base, SoftDeleteMixin):
            ...

    Querying:
        - Use ``MyModel.active()`` to get a base query that excludes
          soft-deleted rows.
        - Use ``instance.soft_delete()`` instead of ``session.delete(instance)``.
    """

    deleted_at = Column(DateTime(timezone=True), nullable=True, default=None)

    def soft_delete(self) -> None:
        """Mark the record as deleted without removing from DB."""
        self.deleted_at = datetime.now(timezone.utc)

    def restore(self) -> None:
        """Un-delete a soft-deleted record."""
        self.deleted_at = None

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None
