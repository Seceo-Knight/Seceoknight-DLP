"""
SIEM identity -> DLP role/attribute mapping for SSO.

Ported from CyberSentinel-DLP (commit ad46e71, gap-scan of August 26 2026).
SeceoKnight's own UserRole enum (app/models/user.py) already has the exact
same eight values CyberSentinel's does -- ADMIN, ANALYST, MANAGER, VIEWER,
AGENT, THREAT_ADMIN, DATA_PROTECTION_ADMIN, ACCESS_CONTROL_ADMIN -- and the
User model already carries department/clearance_level columns with the same
"NULL department denies everything" ABAC rule (app/services/abac_service.py).
That parallel design is what makes this table portable close to verbatim.

The SIEM authenticates the human; this module decides what that human is
inside the DLP. It is deliberately a *translation table*, not an identity
mapping, because the two products do not have the same role vocabulary:

    SIEM                          DLP
    ------------------------      --------------------------------------
    Administrator                 ADMIN
    L3 / L2 / L1 analyst          ANALYST, MANAGER, VIEWER,
    x read-write / read-only      + three domain-scoped admin roles

The DLP additionally splits "see that an event happened" from "see the
payload it captured" (view_sensitive_content) -- a distinction the SIEM has
no concept of. That split is the reason the read-only column lands on roles
that are not merely "the read-write role with writes removed".

NOTHING here removes or rewrites the DLP's own RBAC. The DLP roles,
permissions and domain scoping are untouched; this module only chooses
which of the existing roles an SSO login lands on.

Security note -- the exchange token can be signed with DLP_SSO_SECRET, a
secret shared with another product. Before this module, forging one bought
an attacker the access of an already-provisioned user. Now it can also
choose the role, so the ceiling in SSO_MAX_ROLE exists to bound the blast
radius: set it to anything below ADMIN and no SSO login -- forged or
genuine -- can exceed it. It defaults to ADMIN (no clamp) so that an SSO
Administrator lands on a DLP ADMIN as configured; tighten it if the SIEM's
release pipeline is not trusted to the same level as the DLP's. Moving the
exchange to RS256 (see app/core/sso_jwks.py / sso_verify.py) removes the
DLP's ability to forge a token at all, which is the real fix -- SSO_MAX_ROLE
is the belt-and-suspenders for whatever window remains while HS256 is still
accepted.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import structlog

logger = structlog.get_logger()


# -- Normalization -----------------------------------------------------
# The SIEM may spell a role "L1", "l1", "L1 Analyst", "Tier-1", and the
# access mode "read-write", "readWrite", "rw". Strip everything that is not
# alphanumeric and uppercase, then look up an alias table, so cosmetic
# changes on the SIEM side cannot silently drop a user to the default role.

def _key(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", str(value or "")).upper()


_ROLE_ALIASES: dict[str, str] = {
    "ADMINISTRATOR": "ADMINISTRATOR",
    "ADMIN": "ADMINISTRATOR",
    "SIEMADMIN": "ADMINISTRATOR",
    "SUPERADMIN": "ADMINISTRATOR",
    "L1": "L1", "L1ANALYST": "L1", "TIER1": "L1", "T1": "L1", "LEVEL1": "L1",
    "L2": "L2", "L2ANALYST": "L2", "TIER2": "L2", "T2": "L2", "LEVEL2": "L2",
    "L3": "L3", "L3ANALYST": "L3", "TIER3": "L3", "T3": "L3", "LEVEL3": "L3",
}

_ACCESS_ALIASES: dict[str, str] = {
    "RW": "rw", "READWRITE": "rw", "WRITE": "rw", "READANDWRITE": "rw",
    "FULL": "rw", "EDIT": "rw",
    "RO": "ro", "READONLY": "ro", "READ": "ro", "VIEW": "ro", "VIEWONLY": "ro",
}


# -- Default translation table -------------------------------------------
# Overridable wholesale via the SSO_ROLE_MAP setting (JSON).
#
# Rationale for each cell:
#   Administrator/rw -> ADMIN     full platform ownership, mirrors the SIEM.
#   Administrator/ro -> MANAGER   every event + export + trends, no payload,
#                                 no writes. The honest read-only admin.
#   L3/rw -> DATA_PROTECTION_ADMIN  senior analysts tune detection; this is
#                                 the domain-scoped role that can author
#                                 policy without owning identity management.
#   L3/ro, L2/*     -> ANALYST    investigation needs the captured payload
#                                 (view_sensitive_content). ANALYST holds no
#                                 write permissions, so rw and ro coincide
#                                 for L2 -- the DLP has no "L2 can write"
#                                 concept to promote into.
#   L1/*  -> VIEWER                triage: events, alerts, incidents and
#                                 dashboards, with every captured payload
#                                 redacted on read.
_DEFAULT_MAP: dict[str, dict[str, Any]] = {
    "ADMINISTRATOR": {"rw": "ADMIN", "ro": "MANAGER", "clearance": 5},
    "L3":            {"rw": "DATA_PROTECTION_ADMIN", "ro": "ANALYST", "clearance": 4},
    "L2":            {"rw": "ANALYST", "ro": "ANALYST", "clearance": 3},
    "L1":            {"rw": "VIEWER", "ro": "VIEWER", "clearance": 2},
}


# Total order used only for clamping to SSO_MAX_ROLE. The domain admins are
# siblings, not a chain, so they share a rank; ACCESS_CONTROL_ADMIN sits
# above them because it also carries manage_users/manage_roles.
_ROLE_RANK: dict[str, int] = {
    "AGENT": 0,
    "VIEWER": 10,
    "MANAGER": 20,
    "ANALYST": 30,
    "THREAT_ADMIN": 40,
    "DATA_PROTECTION_ADMIN": 40,
    "ACCESS_CONTROL_ADMIN": 45,
    "ADMIN": 100,
}

VALID_DLP_ROLES = frozenset(_ROLE_RANK) - {"AGENT"}


class SSOIdentity:
    """Resolved DLP identity for one SSO login."""

    __slots__ = ("role", "department", "clearance_level", "siem_role",
                 "siem_access", "mapped", "clamped_from")

    def __init__(self, role: str, department: Optional[str],
                 clearance_level: Optional[int], siem_role: str,
                 siem_access: str, mapped: bool,
                 clamped_from: Optional[str] = None):
        self.role = role
        self.department = department
        self.clearance_level = clearance_level
        self.siem_role = siem_role
        self.siem_access = siem_access
        # False when the SIEM sent no role claim, or one we do not recognise --
        # the caller uses this to decide whether a sync should touch the row.
        self.mapped = mapped
        # Set when SSO_MAX_ROLE downgraded the mapped role.
        self.clamped_from = clamped_from

    def as_log(self) -> dict:
        return {
            "siem_role": self.siem_role,
            "siem_access": self.siem_access,
            "dlp_role": self.role,
            "department": self.department,
            "clearance_level": self.clearance_level,
            "mapped": self.mapped,
            "clamped_from": self.clamped_from,
        }


def _load_map() -> dict[str, dict[str, Any]]:
    """Return the active translation table (default, or SSO_ROLE_MAP)."""
    from app.core.config import settings

    raw = (getattr(settings, "SSO_ROLE_MAP", "") or "").strip()
    if not raw:
        return _DEFAULT_MAP

    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("SSO_ROLE_MAP must be a JSON object")
    except Exception as e:
        # A malformed override must not silently hand everyone the default
        # role -- but it must also not lock every SSO user out. Fall back to
        # the built-in table and make the misconfiguration loud.
        logger.error("SSO_ROLE_MAP is invalid, using built-in map", error=str(e))
        return _DEFAULT_MAP

    table: dict[str, dict[str, Any]] = {}
    for siem_role, spec in parsed.items():
        canon = _ROLE_ALIASES.get(_key(siem_role), _key(siem_role))
        if isinstance(spec, str):
            # Shorthand: {"L1": "VIEWER"} applies to both access modes.
            table[canon] = {"rw": spec.upper(), "ro": spec.upper()}
        elif isinstance(spec, dict):
            entry: dict[str, Any] = {}
            for mode in ("rw", "ro"):
                val = spec.get(mode) or spec.get(mode.upper())
                if isinstance(val, str):
                    entry[mode] = val.upper()
            if "clearance" in spec:
                try:
                    entry["clearance"] = int(spec["clearance"])
                except (TypeError, ValueError):
                    pass
            if entry:
                table[canon] = entry
    return table or _DEFAULT_MAP


def _clamp(role: str) -> tuple[str, Optional[str]]:
    """Apply the SSO_MAX_ROLE ceiling. Returns (role, clamped_from)."""
    from app.core.config import settings

    ceiling = str(getattr(settings, "SSO_MAX_ROLE", "ADMIN") or "ADMIN").upper()
    if ceiling not in _ROLE_RANK:
        logger.error("SSO_MAX_ROLE is not a DLP role, ignoring ceiling",
                     value=ceiling)
        return role, None
    if _ROLE_RANK.get(role, 0) > _ROLE_RANK[ceiling]:
        return ceiling, role
    return role, None


def resolve(payload: dict) -> SSOIdentity:
    """
    Translate the claims on a verified SIEM exchange token into a DLP role
    and ABAC attributes.

    Recognised claims (all optional -- an unmapped login falls back to
    SSO_DEFAULT_ROLE, which is what every SSO account got before this
    module existed, so behaviour is unchanged for a SIEM that has not been
    updated to send them):

        role             "Administrator" | "L1" | "L2" | "L3"
        access           "read-write" | "read-only"
        department       ABAC department string
        clearance_level  ABAC clearance integer

    A missing/unrecognised `access` claim resolves to read-only. The SIEM
    exposes the toggle, so its absence means "not stated" -- and between
    over- and under-granting on an unstated claim, under-granting is the
    only safe default.
    """
    from app.core.config import settings

    raw_role = payload.get("role") or payload.get("siem_role") or ""
    raw_access = (payload.get("access") or payload.get("access_level")
                  or payload.get("permission") or "")

    siem_role = _ROLE_ALIASES.get(_key(raw_role), "")
    access = _ACCESS_ALIASES.get(_key(raw_access), "ro")

    default_role = str(
        getattr(settings, "SSO_DEFAULT_ROLE", "VIEWER") or "VIEWER"
    ).upper()
    if default_role not in VALID_DLP_ROLES:
        default_role = "VIEWER"

    table = _load_map()
    entry = table.get(siem_role) if siem_role else None

    mapped = False
    role = default_role
    tier_clearance: Optional[int] = None

    if entry:
        candidate = entry.get(access) or entry.get("ro") or entry.get("rw")
        if candidate in VALID_DLP_ROLES:
            role, mapped = candidate, True
        elif candidate:
            logger.error("SSO role map points at an unknown DLP role",
                         siem_role=siem_role, dlp_role=candidate)
        tier_clearance = entry.get("clearance")
    elif raw_role:
        # The SIEM sent a role we do not know. Do not guess upward.
        logger.warning("SSO exchange: unrecognised SIEM role claim",
                       role=str(raw_role)[:64])

    role, clamped_from = _clamp(role)

    # -- ABAC attributes ---------------------------------------------------
    # A NULL department denies the user EVERY event (abac_service.py's
    # build_abac_sql_filter / build_abac_mongo_filter -- see _user_attrs_valid),
    # so these are not cosmetic -- they are the other half of "same level of
    # access". An explicit claim always wins over the tier default.
    department = payload.get("department") or payload.get("dept")
    department = str(department).strip() if department else None

    clearance = payload.get("clearance_level", payload.get("clearance"))
    try:
        clearance_level = int(clearance) if clearance is not None else None
    except (TypeError, ValueError):
        clearance_level = None
    if clearance_level is not None:
        clearance_level = max(0, min(10, clearance_level))
    elif mapped and tier_clearance is not None:
        clearance_level = max(0, min(10, int(tier_clearance)))

    return SSOIdentity(
        role=role,
        department=department,
        clearance_level=clearance_level,
        siem_role=siem_role or str(raw_role)[:64],
        siem_access=access,
        mapped=mapped,
        clamped_from=clamped_from,
    )
