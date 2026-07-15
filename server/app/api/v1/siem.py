"""
SIEM Integration API Endpoints
Manage SIEM connectors and event forwarding
"""

import ipaddress
import socket
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user, require_role
from app.core.database import get_db
from app.integrations.siem.integration_service import siem_service
from app.integrations.siem.elk_connector import ELKConnector
from app.integrations.siem.splunk_connector import SplunkConnector
from app.integrations.siem.syslog_connector import SyslogConnector
from app.integrations.siem.base import SIEMType
from app.integrations.siem.registry import persist_connector, delete_persisted_connector
from app.core.observability import StructuredLogger

router = APIRouter()
logger = StructuredLogger(__name__)


def _uid(user):
    """Extract the user id from either a User ORM object (what require_role
    returns) or a legacy JWT-claims dict."""
    if user is None:
        return None
    if isinstance(user, dict):
        return user.get("sub") or user.get("id")
    return getattr(user, "id", None)


# ═══════════════════════════════════════════════════════════════════════
# SSRF guard for SIEM connector hosts
#
# Without this, any admin (or any authenticated user on a mis-configured
# deployment) could register a connector pointed at:
#   * 169.254.169.254 — AWS / GCP / Azure instance metadata
#   * 127.0.0.1 / ::1 — internal services on the manager host
#   * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — LAN hosts
#   * fe80::/10 — IPv6 link-local
# and use the /test and /forward-event endpoints to probe internal
# networks, exfiltrate metadata credentials, or pivot.
# ═══════════════════════════════════════════════════════════════════════
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),       # link-local + metadata
    ipaddress.ip_network("100.64.0.0/10"),         # carrier-grade NAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),           # multicast
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),              # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),             # IPv6 link-local
]


# Metadata / link-local / bogon ranges that are NEVER a legitimate syslog
# target — blocked even for fire-and-forget syslog connectors.
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),        # link-local + cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),           # multicast
    ipaddress.ip_network("fe80::/10"),             # IPv6 link-local
]


def _assert_safe_siem_host(host: str, allow_internal: bool = False) -> None:
    """Resolve `host` and reject any address that lives in a blocked
    network range. Raises HTTPException(400) on rejection.

    ``allow_internal=True`` relaxes the RFC1918/loopback block for
    write-only syslog connectors — on-prem SIEMs legitimately live on the
    internal LAN, and syslog is fire-and-forget (no response body is ever
    returned to the caller), so the SSRF exfiltration risk is minimal.
    Metadata/link-local/bogon ranges stay blocked regardless.
    """
    if not host or len(host) > 253:
        raise HTTPException(status_code=400, detail="Invalid host.")

    blocked = _ALWAYS_BLOCKED_NETWORKS if allow_internal else _BLOCKED_NETWORKS

    # Resolve every A/AAAA record so DNS rebinding against a single
    # public-looking hostname that also resolves to 127.0.0.1 is caught.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Cannot resolve host: {host}")

    seen: set = set()
    for info in infos:
        ip_str = info[4][0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP resolved: {ip_str}")
        for net in blocked:
            if ip in net:
                logger.logger.warning(
                    "siem_connector_blocked_host",
                    host=host, resolved=ip_str, network=str(net),
                )
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"SIEM connector host {host} resolves to {ip_str} "
                        f"which is in the blocked network {net}. "
                        f"Loopback, link-local, metadata, and RFC1918 "
                        f"targets are not allowed."
                    ),
                )


class SIEMConnectorConfig(BaseModel):
    """SIEM connector configuration"""
    name: str
    siem_type: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    hec_token: Optional[str] = None
    use_ssl: bool = True
    verify_certs: bool = True
    index_prefix: Optional[str] = None
    index: Optional[str] = None
    source: Optional[str] = None
    sourcetype: Optional[str] = None
    # Syslog-specific
    protocol: Optional[str] = None       # udp | tcp | tls
    log_format: Optional[str] = None     # cef | leef
    facility: Optional[str] = None       # local0..local7
    min_severity: Optional[str] = None   # info|low|medium|high|critical


@router.get("/connectors")
async def list_connectors(
    current_user: dict = Depends(require_role("admin"))
):
    """
    List all registered SIEM connectors.

    SECURITY: admin role required. Connector records contain host/port
    plus credential fingerprints; must not be exposed to ordinary users.
    """
    try:
        connectors = siem_service.list_connectors()

        logger.logger.info("siem_connectors_listed",
                          user_id=_uid(current_user),
                          count=len(connectors))

        return {
            "success": True,
            "connectors": connectors,
            "total": len(connectors)
        }

    except Exception as e:
        logger.log_error(e, {"endpoint": "list_connectors"})
        raise HTTPException(status_code=500, detail="Failed to list SIEM connectors")


@router.post("/connectors")
async def register_connector(
    config: SIEMConnectorConfig,
    current_user: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new SIEM connector.

    SECURITY:
      * Admin role required.
      * `host` is DNS-resolved and rejected if it lands in a blocked network.
        For HTTP-push connectors (ELK/Splunk) the full block applies (loopback,
        link-local, metadata, RFC1918, IPv6 ULA) to prevent SSRF against the
        cloud metadata service or internal LAN. For write-only **syslog**
        connectors, RFC1918/loopback is allowed (on-prem SIEMs live there) but
        metadata/link-local/bogon ranges stay blocked.

    Connector config is persisted (secrets encrypted) so it survives restart.
    """
    siem_type = config.siem_type.lower()
    is_syslog = siem_type == "syslog"

    # ── SSRF guard ──────────────────────────────────────────────
    _assert_safe_siem_host(config.host, allow_internal=is_syslog)
    if not (1 <= config.port <= 65535):
        raise HTTPException(status_code=400, detail="Port out of range.")

    try:
        # Create connector based on type
        if is_syslog:
            connector = SyslogConnector(
                name=config.name,
                host=config.host,
                port=config.port,
                protocol=(config.protocol or "udp"),
                log_format=(config.log_format or "cef"),
                facility=(config.facility or "local0"),
                verify_certs=config.verify_certs,
                min_severity=(config.min_severity or "low"),
            )

        elif config.siem_type.lower() == "elk":
            connector = ELKConnector(
                name=config.name,
                host=config.host,
                port=config.port,
                username=config.username,
                password=config.password,
                api_key=config.api_key,
                use_ssl=config.use_ssl,
                verify_certs=config.verify_certs,
                index_prefix=config.index_prefix or "dlp-events"
            )

        elif config.siem_type.lower() == "splunk":
            connector = SplunkConnector(
                name=config.name,
                host=config.host,
                port=config.port,
                hec_token=config.hec_token,
                username=config.username,
                password=config.password,
                use_ssl=config.use_ssl,
                verify_certs=config.verify_certs,
                source=config.source or "seceoknight_dlp",
                sourcetype=config.sourcetype or "dlp:event",
                index=config.index or "dlp"
            )

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported SIEM type: {config.siem_type}"
            )

        # Register connector
        success = siem_service.register_connector(connector)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to register connector")

        # Attempt connection
        connected = await connector.connect()

        # Mark active so the auto-forward hook (send_event_to_all / forward_event)
        # will deliver to it. The manual register path bypasses connect_all,
        # which is what normally populates active_connectors.
        if connected and config.name not in siem_service.active_connectors:
            siem_service.active_connectors.append(config.name)

        # Persist so the connector is rebuilt on the next restart.
        try:
            await persist_connector(db, config.model_dump(), created_by=_uid(current_user))
        except Exception as e:  # noqa: BLE001 — persistence failure shouldn't 500 a working connector
            logger.log_error(e, {"endpoint": "register_connector", "op": "persist"})

        logger.logger.info("siem_connector_registered",
                          user_id=_uid(current_user),
                          name=config.name,
                          siem_type=config.siem_type,
                          connected=connected)

        return {
            "success": True,
            "message": "SIEM connector registered successfully",
            "connector": {
                "name": config.name,
                "siem_type": config.siem_type,
                "connected": connected
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(e, {"endpoint": "register_connector"})
        raise HTTPException(status_code=500, detail=f"Failed to register connector: {str(e)}")


@router.delete("/connectors/{connector_name}")
async def unregister_connector(
    connector_name: str,
    current_user: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Unregister a SIEM connector

    **Parameters:**
    - **connector_name**: Name of the connector to remove

    **Returns:** Deletion result
    """
    try:
        # Disconnect first
        connector = siem_service.get_connector(connector_name)
        if connector:
            await connector.disconnect()

        # Unregister from the in-memory registry
        success = siem_service.unregister_connector(connector_name)

        # Always remove the persisted row too (idempotent even if not in memory)
        await delete_persisted_connector(db, connector_name)

        if not success:
            raise HTTPException(status_code=404, detail="Connector not found")

        logger.logger.info("siem_connector_unregistered",
                          user_id=_uid(current_user),
                          name=connector_name)

        return {
            "success": True,
            "message": f"Connector '{connector_name}' unregistered successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(e, {"endpoint": "unregister_connector"})
        raise HTTPException(status_code=500, detail="Failed to unregister connector")


@router.post("/connectors/{connector_name}/test")
async def test_connector(
    connector_name: str,
    current_user: dict = Depends(require_role("admin"))
):
    """
    Test a SIEM connector connection

    **Parameters:**
    - **connector_name**: Name of the connector to test

    **Returns:** Connection test results
    """
    try:
        connector = siem_service.get_connector(connector_name)

        if not connector:
            raise HTTPException(status_code=404, detail="Connector not found")

        # Test connection
        result = await connector.test_connection()

        logger.logger.info("siem_connector_tested",
                          user_id=_uid(current_user),
                          name=connector_name,
                          success=result.get("success"))

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(e, {"endpoint": "test_connector"})
        raise HTTPException(status_code=500, detail="Connection test failed")


@router.get("/connectors/health")
async def health_check_all(
    current_user: dict = Depends(require_role("admin"))
):
    """
    Perform health check on all SIEM connectors

    **Returns:** Health status for each connector
    """
    try:
        health_results = await siem_service.health_check_all()

        logger.logger.info("siem_health_check_all",
                          user_id=_uid(current_user),
                          total=len(health_results))

        return {
            "success": True,
            "connectors": health_results,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.log_error(e, {"endpoint": "health_check_all"})
        raise HTTPException(status_code=500, detail="Health check failed")


@router.post("/forward-event")
async def forward_event_to_siems(
    event: Dict[str, Any] = Body(...),
    connector_name: Optional[str] = None,
    current_user: dict = Depends(require_role("analyst"))
):
    """
    Forward a single event to SIEM(s)

    **Request Body:**
    ```json
    {
      "event_id": "evt_123",
      "timestamp": "2025-01-13T10:00:00Z",
      "severity": "high",
      "classification_type": "credit_card",
      "agent_name": "laptop-01",
      ...
    }
    ```

    **Query Parameters:**
    - **connector_name** (optional): Forward to specific connector only

    **Returns:** Forward results
    """
    try:
        if connector_name:
            # Forward to specific connector
            connector = siem_service.get_connector(connector_name)
            if not connector:
                raise HTTPException(status_code=404, detail="Connector not found")

            success = await connector.send_event(event)

            return {
                "success": success,
                "connector": connector_name,
                "event_id": event.get("event_id")
            }

        else:
            # Forward to all active connectors
            results = await siem_service.send_event_to_all(event)

            logger.logger.info("event_forwarded_to_siems",
                              user_id=_uid(current_user),
                              event_id=event.get("event_id"),
                              connectors=len(results))

            return {
                "success": True,
                "results": results,
                "event_id": event.get("event_id"),
                "total_connectors": len(results),
                "successful": sum(1 for v in results.values() if v)
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(e, {"endpoint": "forward_event_to_siems"})
        raise HTTPException(status_code=500, detail="Event forwarding failed")


@router.post("/forward-batch")
async def forward_batch_to_siems(
    events: List[Dict[str, Any]] = Body(...),
    connector_name: Optional[str] = None,
    current_user: dict = Depends(require_role("analyst"))
):
    """
    Forward a batch of events to SIEM(s)

    **Request Body:** Array of event objects

    **Query Parameters:**
    - **connector_name** (optional): Forward to specific connector only

    **Returns:** Batch forward results
    """
    try:
        if connector_name:
            # Forward to specific connector
            connector = siem_service.get_connector(connector_name)
            if not connector:
                raise HTTPException(status_code=404, detail="Connector not found")

            result = await connector.send_batch(events)

            return {
                "success": result.get("success", False),
                "connector": connector_name,
                "total": len(events),
                "result": result
            }

        else:
            # Forward to all active connectors
            results = await siem_service.send_batch_to_all(events)

            logger.logger.info("batch_forwarded_to_siems",
                              user_id=_uid(current_user),
                              events=len(events),
                              connectors=len(results))

            return {
                "success": True,
                "results": results,
                "total_events": len(events),
                "total_connectors": len(results)
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(e, {"endpoint": "forward_batch_to_siems"})
        raise HTTPException(status_code=500, detail="Batch forwarding failed")
