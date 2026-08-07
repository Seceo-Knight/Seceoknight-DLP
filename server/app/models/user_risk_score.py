"""
Per-user behavioral risk score -- SeceoKnight-original, not ported from
CyberSentinel-DLP.

Both SeceoKnight and CyberSentinel decide "is this event bad?" purely from
the content of a SINGLE event: does it match a regex, does it trip a Luhn
check, is the file extension denylisted. That answers "is this one action
risky?" but never "is this a suspicious PATTERN of activity?" -- a user who
never touches USB drives who suddenly copies 40 files to one in a night
generates the same single-event severity as someone who does that every
Tuesday, because neither product looks at behavior over time or across
channels.

This model stores the output of RiskScoringService's rolling-window
analysis: a 0-100 score combining event volume, channel diversity (using
USB *and* network-exfil *and* print in one window is worse than heavy use
of just one), off-hours activity, block ratio, and severity mix, plus a
short-term trend. It is intentionally NOT machine-learned (no training
data or GPU available to validate a model in this environment) -- it is
transparent, auditable statistical baselining, which is arguably the more
defensible choice for a security product anyway: an analyst can see
exactly why a score is what it is instead of trusting a black box.

See app/services/risk_scoring_service.py for how this is computed and
app/api/v1/risk_scoring.py for how it's surfaced.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Integer, Float, JSON, CheckConstraint, Index
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class UserRiskScore(Base):
    __tablename__ = "user_risk_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # One current row per user -- recompute overwrites rather than appends,
    # so this table stays small (rows = distinct active users, not
    # rows = distinct users * recompute runs). History, if ever wanted, would
    # be a separate append-only table; out of scope here.
    user_email = Column(String(255), nullable=False, unique=True, index=True)
    username = Column(String(255), nullable=True)
    department = Column(String(255), nullable=True)

    # 0-100. See RiskScoringService.WEIGHTS for exactly how this is composed.
    score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(20), nullable=False, default="low")  # low|medium|high|critical

    # Transparent component breakdown so a score is never a black box --
    # an analyst opening a user's risk detail sees exactly which signals
    # contributed and by how much. Keys: volume, channel_diversity,
    # off_hours, block_ratio, severity_mix (each 0-100 before weighting).
    components = Column(JSON, nullable=True)

    # Rolling-window stats behind the components, for the detail view.
    event_count = Column(Integer, nullable=False, default=0)
    blocked_count = Column(Integer, nullable=False, default=0)
    critical_high_count = Column(Integer, nullable=False, default=0)
    distinct_channels = Column(JSON, nullable=True)  # list[str]
    off_hours_count = Column(Integer, nullable=False, default=0)

    # score_previous lets the API report a delta/trend arrow without a
    # separate history table -- each recompute shifts current -> previous.
    score_previous = Column(Float, nullable=True)
    trend = Column(String(10), nullable=True)  # rising|stable|falling

    window_days = Column(Integer, nullable=False, default=14)
    window_start = Column(DateTime(timezone=True), nullable=True)
    window_end = Column(DateTime(timezone=True), nullable=True)

    computed_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        CheckConstraint("risk_level IN ('low', 'medium', 'high', 'critical')",
                         name="ck_user_risk_level"),
        CheckConstraint("score >= 0 AND score <= 100", name="ck_user_risk_score_range"),
        Index("idx_user_risk_score_desc", "score"),
        Index("idx_user_risk_level", "risk_level"),
    )

    def __repr__(self):
        return f"<UserRiskScore {self.user_email} score={self.score:.1f} ({self.risk_level})>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "user_email": self.user_email,
            "username": self.username,
            "department": self.department,
            "score": round(self.score, 1),
            "risk_level": self.risk_level,
            "components": self.components,
            "event_count": self.event_count,
            "blocked_count": self.blocked_count,
            "critical_high_count": self.critical_high_count,
            "distinct_channels": self.distinct_channels,
            "off_hours_count": self.off_hours_count,
            "score_previous": round(self.score_previous, 1) if self.score_previous is not None else None,
            "trend": self.trend,
            "window_days": self.window_days,
            "window_start": format_iso(self.window_start),
            "window_end": format_iso(self.window_end),
            "computed_at": format_iso(self.computed_at),
        }
