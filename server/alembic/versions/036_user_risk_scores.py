"""user_risk_scores — behavioral risk-scoring engine (SeceoKnight-original, task #120)

Not ported from CyberSentinel-DLP -- neither product currently scores users
by behavior over time, only by single-event content matches. See the
module docstring on app/models/user_risk_score.py for the full rationale.

Revision ID: 036_user_risk_scores
Revises: 035_data_match_sources
Create Date: 2026-08-07
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "036_user_risk_scores"
down_revision = "035_data_match_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(sa.text("""
        CREATE TABLE IF NOT EXISTS user_risk_scores (
            id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_email            VARCHAR(255) NOT NULL UNIQUE,
            username              VARCHAR(255),
            department            VARCHAR(255),
            score                 DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            risk_level            VARCHAR(20) NOT NULL DEFAULT 'low',
            components            JSON,
            event_count           INTEGER NOT NULL DEFAULT 0,
            blocked_count         INTEGER NOT NULL DEFAULT 0,
            critical_high_count   INTEGER NOT NULL DEFAULT 0,
            distinct_channels     JSON,
            off_hours_count       INTEGER NOT NULL DEFAULT 0,
            score_previous        DOUBLE PRECISION,
            trend                 VARCHAR(10),
            window_days           INTEGER NOT NULL DEFAULT 14,
            window_start          TIMESTAMPTZ,
            window_end            TIMESTAMPTZ,
            computed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at            TIMESTAMPTZ,
            CONSTRAINT ck_user_risk_level CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
            CONSTRAINT ck_user_risk_score_range CHECK (score >= 0 AND score <= 100)
        )
    """))
    op.get_bind().execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_user_risk_score_desc ON user_risk_scores (score)"
    ))
    op.get_bind().execute(sa.text(
        "CREATE INDEX IF NOT EXISTS idx_user_risk_level ON user_risk_scores (risk_level)"
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS user_risk_scores"))
