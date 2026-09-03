"""
Behavioral risk-scoring engine -- SeceoKnight-original (task #120).

Every detection rule in both SeceoKnight and CyberSentinel today answers one
question: "does THIS event's content look bad?" (a regex match, a Luhn hit,
a denylisted extension). Neither product asks the second question a real
SOC analyst always asks next: "does this PERSON's behavior look bad?" A
user who has never touched a USB drive suddenly copying 40 files to one at
11pm on a Saturday generates the exact same single-event severity as a
warehouse-inventory clerk who does that every week, because nothing looks
at volume, channel diversity, or timing across a window of activity.

This service closes that gap with transparent, auditable statistical
baselining -- deliberately NOT a black-box ML model, since there is no
labelled training data or way to validate a model's accuracy in this
environment, and a security product where nobody can explain why a score
is what it is invites both false trust and prompt "just ignore the risk
score" fatigue. Every component below is a named, inspectable number.

Algorithm (see WEIGHTS): for every user with at least one event in a
rolling window, compute five 0-100 sub-scores from population statistics
(z-scores clamped and rescaled) plus straightforward ratios, weight-combine
them into one 0-100 score, and classify into low/medium/high/critical.
Recomputing is idempotent (upsert-by-user_email) and cheap enough to run
on a schedule or on demand via POST /risk-scoring/recompute -- there is no
background scheduler wired up in this pass (see the API module's
docstring), matching this sandbox's inability to verify a long-running
cron-style job actually fires correctly.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.event import Event
from app.models.user_risk_score import UserRiskScore

logger = structlog.get_logger()

# Relative importance of each behavioral signal. Channel diversity and
# block ratio are weighted highest deliberately: using three different
# exfil channels in one window, or getting blocked repeatedly, are much
# stronger tells than raw event volume alone (a legitimately busy user can
# generate a lot of low-risk events; a user who suddenly starts spanning
# USB + network-share + print in the same week is the pattern worth an
# analyst's attention even if each individual event was only "medium").
WEIGHTS = {
    "volume": 0.15,
    "channel_diversity": 0.25,
    "off_hours": 0.15,
    "block_ratio": 0.25,
    "severity_mix": 0.20,
}

# Every channel the two agents + server collectively recognize today (see
# Event.event_type / Event.channel across agent.cpp, network_exfil_monitor,
# print_monitor, google_drive_polling, onedrive_polling, smtp_relay). Used
# only to normalize the channel-diversity sub-score (distinct/known*100) --
# not an exhaustive contract, just the current denominator.
KNOWN_CHANNELS = {
    "clipboard", "file", "file_transfer", "usb", "network_exfil",
    "network_share_transfer", "print", "google_drive", "onedrive",
    "email", "messaging", "screen_capture", "ransomware",
    "bluetooth_file_transfer", "classification",
}

RISK_THRESHOLDS = [
    (75.0, "critical"),
    (50.0, "high"),
    (25.0, "medium"),
    (0.0, "low"),
]


def _risk_level(score: float) -> str:
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


# Office hours used for the "off hours" behavioral signal, in the
# configured APP_TIMEZONE (see app/core/timezone.py) -- 09:30-18:30,
# Monday-Friday. No per-tenant/per-department schedule concept exists in
# this schema, so this is one fixed window for the whole deployment; if
# that ever needs to vary, it should move to settings.
_BUSINESS_START_MINUTES = 9 * 60 + 30   # 09:30
_BUSINESS_END_MINUTES = 18 * 60 + 30    # 18:30


def _is_off_hours(ts: datetime) -> bool:
    """Outside business hours or a weekend, in the deployment's configured
    local timezone -- NOT the timestamp's raw UTC hour.

    Event timestamps are stored in UTC. Comparing UTC hour directly
    against a business-hours cutoff silently disagreed with the actual
    local time whenever APP_TIMEZONE isn't UTC: an 11:26am IST event is
    ~05:56 UTC, which read as "before 07:00" under the old UTC-only check
    and got flagged off-hours even though it's the middle of the
    workday. Converting to the display timezone first fixes that.
    """
    from app.core.timezone import to_display_tz

    local = to_display_tz(ts)
    if local.weekday() >= 5:
        return True
    minutes = local.hour * 60 + local.minute
    return minutes < _BUSINESS_START_MINUTES or minutes >= _BUSINESS_END_MINUTES


@dataclass
class _RawUserStats:
    user_email: str
    username: Optional[str]
    department: Optional[str]
    event_count: int = 0
    blocked_count: int = 0
    critical_high_count: int = 0
    off_hours_count: int = 0
    channels: set = None

    def __post_init__(self):
        if self.channels is None:
            self.channels = set()


def _zscore_to_0_100(value: float, mean: float, stdev: float) -> float:
    """Map a value's population z-score onto 0-100, centered at 50.

    A user exactly at the population mean scores 50 (neutral). +/-2
    standard deviations saturates to ~100/~0. stdev==0 (every user
    identical, or a population of one) collapses to a flat 50 rather than
    dividing by zero -- "no signal" is the honest answer there, not an
    extreme score.
    """
    if stdev <= 1e-9:
        return 50.0
    z = (value - mean) / stdev
    scaled = 50.0 + (z * 25.0)  # +/-2 stdev -> 0/100
    return max(0.0, min(100.0, scaled))


class RiskScoringService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _collect_raw_stats(self, window_start: datetime, window_end: datetime) -> Dict[str, _RawUserStats]:
        """One pass over events in the window, grouped in Python by
        user_email. A GROUP BY-in-SQL version would be faster at real scale,
        but needs multiple conditional aggregates (blocked/critical/
        off-hours/channels) that are awkward to express portably across
        Postgres JSON channel storage -- straightforward Python aggregation
        over a single indexed range query (idx_event_user_timestamp) is
        simpler to get right and to audit.
        """
        result = await self.db.execute(
            select(
                Event.user_email, Event.username, Event.department,
                Event.severity, Event.action, Event.event_type,
                Event.channel, Event.timestamp,
            ).where(
                Event.timestamp >= window_start,
                Event.timestamp < window_end,
                Event.user_email.is_not(None),
            )
        )
        stats: Dict[str, _RawUserStats] = {}
        for row in result.all():
            email = row.user_email
            s = stats.get(email)
            if s is None:
                s = _RawUserStats(user_email=email, username=row.username, department=row.department)
                stats[email] = s
            elif row.username and not s.username:
                s.username = row.username

            s.event_count += 1
            if (row.action or "").lower() in ("blocked", "quarantined"):
                s.blocked_count += 1
            if (row.severity or "").lower() in ("critical", "high"):
                s.critical_high_count += 1
            ts = row.timestamp
            if ts is not None and _is_off_hours(ts):
                s.off_hours_count += 1
            channel = (row.channel or row.event_type or "").lower()
            if channel:
                s.channels.add(channel)
        return stats

    def _score_user(self, s: _RawUserStats, pop: Dict[str, tuple]) -> Dict[str, Any]:
        volume = _zscore_to_0_100(s.event_count, *pop["event_count"])
        channel_diversity = min(100.0, (len(s.channels) / max(1, len(KNOWN_CHANNELS))) * 100.0 * 2.5)
        # *2.5: touching 2-3 distinct channels is already meaningfully
        # diverse for one person in a two-week window; requiring all ~14
        # known channel types to reach 100 would make this sub-score nearly
        # always near-zero and useless as a signal. Capped at 100 either way.
        off_hours_ratio = (s.off_hours_count / s.event_count * 100.0) if s.event_count else 0.0
        block_ratio = (s.blocked_count / s.event_count * 100.0) if s.event_count else 0.0
        severity_mix = (s.critical_high_count / s.event_count * 100.0) if s.event_count else 0.0

        components = {
            "volume": round(volume, 1),
            "channel_diversity": round(channel_diversity, 1),
            "off_hours": round(off_hours_ratio, 1),
            "block_ratio": round(block_ratio, 1),
            "severity_mix": round(severity_mix, 1),
        }
        score = sum(WEIGHTS[k] * v for k, v in components.items())
        return {"score": round(score, 1), "components": components}

    async def recompute_all(self, window_days: int = 14) -> List[UserRiskScore]:
        """Recompute every user's risk score from the last `window_days` of
        events. Upserts by user_email -- safe to call repeatedly (e.g. from
        an external cron hitting POST /risk-scoring/recompute), and cheap
        enough for on-demand use at the data volumes a single-deployment
        DLP install actually sees."""
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(days=window_days)

        raw = await self._collect_raw_stats(window_start, window_end)
        if not raw:
            logger.info("risk_scoring: no events in window, nothing to score",
                        window_days=window_days)
            return []

        event_counts = [s.event_count for s in raw.values()]
        pop = {
            "event_count": (
                statistics.fmean(event_counts),
                statistics.pstdev(event_counts) if len(event_counts) > 1 else 0.0,
            ),
        }

        # Load existing rows for these users in one query so we can carry
        # score -> score_previous and compute a trend, instead of N queries.
        existing_result = await self.db.execute(
            select(UserRiskScore).where(UserRiskScore.user_email.in_(list(raw.keys())))
        )
        existing_by_email = {r.user_email: r for r in existing_result.scalars().all()}

        updated: List[UserRiskScore] = []
        for email, s in raw.items():
            scored = self._score_user(s, pop)
            row = existing_by_email.get(email)
            prev_score = row.score if row else None

            if row is None:
                row = UserRiskScore(user_email=email)
                self.db.add(row)

            trend = "stable"
            if prev_score is not None:
                if scored["score"] > prev_score + 3:
                    trend = "rising"
                elif scored["score"] < prev_score - 3:
                    trend = "falling"

            row.username = s.username
            row.department = s.department
            row.score = scored["score"]
            row.risk_level = _risk_level(scored["score"])
            row.components = scored["components"]
            row.event_count = s.event_count
            row.blocked_count = s.blocked_count
            row.critical_high_count = s.critical_high_count
            row.distinct_channels = sorted(s.channels)
            row.off_hours_count = s.off_hours_count
            row.score_previous = prev_score
            row.trend = trend
            row.window_days = window_days
            row.window_start = window_start
            row.window_end = window_end
            row.computed_at = datetime.now(timezone.utc)
            updated.append(row)

        await self.db.commit()
        logger.info("risk_scoring: recomputed", users=len(updated), window_days=window_days)
        return updated

    async def list_scores(
        self, limit: int = 50, offset: int = 0, min_level: Optional[str] = None
    ) -> List[UserRiskScore]:
        query = select(UserRiskScore).order_by(UserRiskScore.score.desc())
        if min_level:
            levels_at_or_above = {
                "low": ["low", "medium", "high", "critical"],
                "medium": ["medium", "high", "critical"],
                "high": ["high", "critical"],
                "critical": ["critical"],
            }.get(min_level.lower())
            if levels_at_or_above:
                query = query.where(UserRiskScore.risk_level.in_(levels_at_or_above))
        query = query.offset(offset).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_score(self, user_email: str) -> Optional[UserRiskScore]:
        result = await self.db.execute(
            select(UserRiskScore).where(UserRiskScore.user_email == user_email)
        )
        return result.scalars().first()

    # Component keys that map onto a clean per-event predicate -- must
    # match COMPONENT_META/filterEventsByComponent on the frontend
    # (dashboard/src/pages/RiskScoring.tsx). "volume" (every event counts)
    # and unrecognized values fall through to "no filter, all events".
    _EVENT_PREDICATES = ("off_hours", "block_ratio", "severity_mix", "channel_diversity")

    def _event_matches_component(self, event: Event, component: str) -> bool:
        if component == "off_hours":
            return bool(event.timestamp) and _is_off_hours(event.timestamp)
        if component == "block_ratio":
            return (event.action or "").lower() in ("blocked", "quarantined")
        if component == "severity_mix":
            return (event.severity or "").lower() in ("critical", "high")
        return True

    async def get_events_for_user(
        self,
        user_email: str,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        component: Optional[str] = None,
        limit: int = 100,
    ) -> tuple[List[Event], int]:
        """The contributing events behind a score, for the detail view --
        an analyst should never have to trust a number without being able
        to see what produced it. Optionally filtered to exactly the
        predicate one component tile represents.

        Scoped to [window_start, window_end) -- the same rolling window
        `_score_user` actually computed the components from -- rather than
        just "this user's N most recent events regardless of window".

        Returns (events_to_display, total_matching_count). Critically,
        the predicate is applied across the user's ENTIRE window, not
        just a capped "most recent N" slice -- a user can easily have
        hundreds of events in a 14-day window, and if the off-hours (or
        blocked, or high-severity) ones aren't among the most recent N,
        a "most recent N, then filter" approach silently shows zero
        matches for a component tile that clearly reads a nonzero score
        (confirmed live: an "Off Hours" component of 26 with 0 of the 50
        most-recent events matching, because this user's off-hours
        activity happened earlier in a 282-event window). Fetching the
        full window and filtering in Python -- rather than pushing each
        predicate into SQL -- mirrors `_collect_raw_stats`'s own
        reasoning above: one straightforward, auditable pass beats
        several dialect-specific conditional-aggregate queries, and a
        single user's 14-day window is not large enough for this to
        matter at this deployment's scale.
        """
        query = select(Event).where(Event.user_email == user_email)
        if window_start is not None:
            query = query.where(Event.timestamp >= window_start)
        if window_end is not None:
            query = query.where(Event.timestamp < window_end)
        query = query.order_by(Event.timestamp.desc())
        result = await self.db.execute(query)
        all_events = list(result.scalars().all())

        if component == "channel_diversity":
            seen: set = set()
            matching: List[Event] = []
            for e in all_events:
                ch = (e.channel or e.event_type or "").lower()
                if ch and ch not in seen:
                    seen.add(ch)
                    matching.append(e)
        elif component in self._EVENT_PREDICATES:
            matching = [e for e in all_events if self._event_matches_component(e, component)]
        else:
            matching = all_events

        return matching[:limit], len(matching)

    async def count_by_level(self) -> Dict[str, int]:
        result = await self.db.execute(
            select(UserRiskScore.risk_level, func.count(UserRiskScore.id))
            .group_by(UserRiskScore.risk_level)
        )
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for level, count in result.all():
            if level in counts:
                counts[level] = count
        return counts
