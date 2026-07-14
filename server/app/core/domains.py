"""
Policy domains for granular, domain-scoped RBAC.

Every policy belongs to exactly one *domain*. Domain-admin roles are scoped to
their domain: they may view/manage only the policies — and the events / alerts
/ incidents / dashboards derived from them — within that domain. The global
``ADMIN`` (super admin) is unscoped and sees every domain.

  threat          — exfiltration / attack vectors (USB, network exfil,
                    screen capture, print)
  data_protection — content handling (clipboard, file system, file transfer,
                    Google Drive, OneDrive, classification-aware)
  access_control  — device-access authorization + identity administration
  general         — fallback for anything unmapped
"""
from enum import Enum
from typing import Optional, Set


class PolicyDomain(str, Enum):
    THREAT = "threat"
    DATA_PROTECTION = "data_protection"
    ACCESS_CONTROL = "access_control"
    GENERAL = "general"


ALL_DOMAINS: Set[str] = {d.value for d in PolicyDomain}


# Policy ``type`` (as used by the policy creator / agent bundle) → domain.
POLICY_TYPE_DOMAIN = {
    # Threat — exfiltration / attack vectors
    "usb_device_monitoring": PolicyDomain.THREAT,
    "usb_file_transfer_monitoring": PolicyDomain.THREAT,
    "usb": PolicyDomain.THREAT,
    "network_exfil": PolicyDomain.THREAT,
    "network_exfiltration": PolicyDomain.THREAT,
    "screen_capture": PolicyDomain.THREAT,
    "screen_capture_monitoring": PolicyDomain.THREAT,
    "print": PolicyDomain.THREAT,
    "print_monitoring": PolicyDomain.THREAT,
    # Data Protection — content handling
    "clipboard_monitoring": PolicyDomain.DATA_PROTECTION,
    "clipboard": PolicyDomain.DATA_PROTECTION,
    "file_system_monitoring": PolicyDomain.DATA_PROTECTION,
    "file_transfer_monitoring": PolicyDomain.DATA_PROTECTION,
    "file": PolicyDomain.DATA_PROTECTION,
    "google_drive_local_monitoring": PolicyDomain.DATA_PROTECTION,
    "google_drive_cloud_monitoring": PolicyDomain.DATA_PROTECTION,
    "onedrive_cloud_monitoring": PolicyDomain.DATA_PROTECTION,
    "classification_aware_policy": PolicyDomain.DATA_PROTECTION,
    # Access Control — device authorization (future-facing types)
    "usb_device_authorization": PolicyDomain.ACCESS_CONTROL,
    "device_access": PolicyDomain.ACCESS_CONTROL,
}

# Event ``event_type`` → domain, so events without a resolvable matched-policy
# still get a domain stamp at ingest (keeps reporting filterable).
EVENT_TYPE_DOMAIN = {
    "usb": PolicyDomain.THREAT,
    "network_exfil": PolicyDomain.THREAT,
    "screen_capture": PolicyDomain.THREAT,
    "print_attempt": PolicyDomain.THREAT,
    "print": PolicyDomain.THREAT,
    "clipboard": PolicyDomain.DATA_PROTECTION,
    "file": PolicyDomain.DATA_PROTECTION,
    "file_transfer": PolicyDomain.DATA_PROTECTION,
    "google_drive": PolicyDomain.DATA_PROTECTION,
    "onedrive": PolicyDomain.DATA_PROTECTION,
    "classification": PolicyDomain.DATA_PROTECTION,
}


def domain_for_policy_type(policy_type: Optional[str]) -> str:
    if not policy_type:
        return PolicyDomain.GENERAL.value
    d = POLICY_TYPE_DOMAIN.get(str(policy_type).strip().lower())
    return d.value if d else PolicyDomain.GENERAL.value


def domain_for_event_type(event_type: Optional[str]) -> str:
    if not event_type:
        return PolicyDomain.GENERAL.value
    d = EVENT_TYPE_DOMAIN.get(str(event_type).strip().lower())
    return d.value if d else PolicyDomain.GENERAL.value


# Domain-admin role → the set of domains it may access. A role absent from
# this map (ADMIN, ANALYST, MANAGER, VIEWER, …) is unrestricted by domain.
DOMAIN_ADMIN_ROLES = {
    "THREAT_ADMIN": {PolicyDomain.THREAT.value},
    "DATA_PROTECTION_ADMIN": {PolicyDomain.DATA_PROTECTION.value},
    "ACCESS_CONTROL_ADMIN": {PolicyDomain.ACCESS_CONTROL.value},
}


def domains_for_role(role: Optional[str]) -> Optional[Set[str]]:
    """Allowed-domain set for a role, or ``None`` for unrestricted (super
    admin / analyst / viewer)."""
    if not role:
        return None
    return DOMAIN_ADMIN_ROLES.get(str(role).upper())


def is_domain_admin(role: Optional[str]) -> bool:
    return domains_for_role(role) is not None
