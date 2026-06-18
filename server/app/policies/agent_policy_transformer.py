"""
Agent Policy Transformer
Turns database policies into agent-friendly bundles.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Dict, Iterable, List, Optional

from app.models.policy import Policy


POLICY_PLATFORM_SUPPORT: Dict[str, List[str]] = {
    "clipboard_monitoring": ["windows"],
    "file_system_monitoring": ["windows", "linux"],
    "file_transfer_monitoring": ["windows", "linux"],
    "usb_device_monitoring": ["windows"],
    "usb_file_transfer_monitoring": ["windows"],
    "google_drive_local_monitoring": ["windows"],
}

POLICY_CAPABILITY_MAP: Dict[str, str] = {
    "clipboard_monitoring": "clipboard_monitoring",
    "file_system_monitoring": "file_monitoring",
    "file_transfer_monitoring": "file_monitoring",
    "usb_device_monitoring": "usb_monitoring",
    "usb_file_transfer_monitoring": "usb_monitoring",
    "google_drive_local_monitoring": "file_monitoring",
}


class AgentPolicyTransformer:
    """
    Builds agent-ready bundles grouped by policy type with version metadata.
    """

    def build_bundle(
        self,
        policies: Iterable[Policy],
        platform: str,
        capabilities: Optional[Dict[str, bool]] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        platform_key = (platform or "windows").lower()
        capability_flags = {k: bool(v) for k, v in (capabilities or {}).items()}

        filtered: List[Policy] = [
            policy
            for policy in policies
            if self._supports_policy(policy, platform_key, capability_flags, agent_id)
        ]

        grouped = self._group_policies(filtered)
        version = self._calculate_version(filtered)

        return {
            "version": version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "policy_count": sum(len(items) for items in grouped.values()),
            "policies": grouped,
        }

    def _supports_policy(
        self,
        policy: Policy,
        platform: str,
        capabilities: Dict[str, bool],
        agent_id: Optional[str],
    ) -> bool:
        if not policy.enabled:
            return False

        policy_type = (policy.type or "").lower()
        if not policy_type:
            return False

        # Agent scoping via JSON agent_ids (junction table migration pending)
        scoped_agents = policy.agent_ids or []
        if scoped_agents:
            if not agent_id or str(agent_id) not in [str(a) for a in scoped_agents]:
                return False

        supported_platforms = POLICY_PLATFORM_SUPPORT.get(policy_type, [])
        if supported_platforms and platform not in supported_platforms:
            return False

        capability_flag = POLICY_CAPABILITY_MAP.get(policy_type)
        if capability_flag and capability_flag in capabilities:
            return capabilities[capability_flag]

        # Default to True when capability flag is unknown/missing
        return True

    def _group_policies(self, policies: Iterable[Policy]) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for policy in sorted(policies, key=lambda p: (p.priority or 0), reverse=True):
            policy_type = (policy.type or "unknown").lower()
            grouped.setdefault(policy_type, []).append(self._serialize_policy(policy))

        return grouped

    def _serialize_policy(self, policy: Policy) -> Dict[str, Any]:
        updated_at = policy.updated_at or policy.created_at or datetime.now(timezone.utc)
        return {
            "id": str(policy.id),
            "name": policy.name,
            "description": policy.description,
            "priority": policy.priority,
            "severity": policy.severity,
            "type": policy.type,
            "config": policy.config or {},
            "actions": policy.actions or {},
            "compliance_tags": policy.compliance_tags or [],
            "updated_at": updated_at.isoformat(),
        }

    def _calculate_version(self, policies: Iterable[Policy]) -> str:
        hasher = sha256()
        for policy in sorted(policies, key=lambda p: str(p.id)):
            updated_at = policy.updated_at or policy.created_at or datetime.now(timezone.utc)
            hasher.update(str(policy.id).encode("utf-8"))
            hasher.update(updated_at.isoformat().encode("utf-8"))
            hasher.update(json.dumps(policy.config or {}, sort_keys=True).encode("utf-8"))
            hasher.update(json.dumps(policy.actions or {}, sort_keys=True).encode("utf-8"))
            hasher.update(json.dumps(policy.agent_ids or [], sort_keys=True).encode("utf-8"))
        return hasher.hexdigest()


