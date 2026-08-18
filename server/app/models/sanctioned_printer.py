"""
Sanctioned printers — the allow/deny registry for printers on endpoints.

Ported from the CyberSentinel-DLP reference project; extended with an
explicit ``decision`` column (ported from their commit b7dc3f3, mirroring
the pattern SeceoKnight already has for USB via SanctionedUsbDevice.decision).

Two independent things a row can do:
  * decision="allow" (default) + scope="allowlist" -- a print job is allowed
    only if its printer NAME matches an enabled allow row here; every other
    printer is blocked. Only consulted when the active printer_control
    policy's scope is "allowlist".
  * decision="deny" -- a sticky, audited "never let this printer through",
    checked in EVERY scope (block_all/block_network/block_local/allowlist),
    not just allowlist mode. This is what makes "block this one printer,
    leave the rest of the fleet alone" expressible without moving the whole
    estate into allowlist scope.

Printers are matched on ``printer_name`` (what the endpoint reports at print
time). ``printer_type`` (local/network) is captured for display only.

Agent-side enforcement: GET /agents/{agent_id}/printer-policy (in
app/api/v1/agents.py) ships allow rows only when scope="allowlist", but
ships deny rows unconditionally; ShouldBlockPrinter() in agent.cpp checks
the deny set first (any scope), then falls back to the scope-based allow
logic.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class SanctionedPrinter(Base):
    __tablename__ = "sanctioned_printers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # The match key — the printer name as reported by the endpoint.
    printer_name = Column(String(500), nullable=False, unique=True)
    label = Column(String(255), nullable=True)
    printer_type = Column(String(20), nullable=True)   # local | network | unknown
    # 'allow' (default) or 'deny' — see module docstring. A deny row beats
    # an allow row for the same name and is checked in every policy scope.
    decision = Column(String(10), nullable=False, default="allow", server_default="allow")
    is_enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    notes = Column(String(1000), nullable=True)
    approved_by = Column(UUID(as_uuid=True), nullable=True)
    approved_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self):
        return f"<SanctionedPrinter {self.printer_name} decision={self.decision} enabled={self.is_enabled}>"
