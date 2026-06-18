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

from app.core.security import get_current_user, require_role
from app.integrations.siem.integration_service import siem_service
from app.integrations.siem.elk_connector import ELKConnector
from app.integrations.siem.splunk_connector import SplunkConnector
from app.integrations.siem.base import SIEMType
from app.core.observability import StructuredLogger

router = APIRouter()
logger = StructuredLogger(__name__)


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


def _assert_safe_siem_host(host: str) -> None:
    """Resolve `host` and reject any address that lives in a blocked
    network range. Raises HTTPException(400) on rejection."""
    if not host or len(host) > 253:
        raise HTTPException(status_code=400, detail="Invalid host.")

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
        for net in _BLOCKED_NETWORKS:
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
                          user_id=current_user.get("sub"),
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
    current_user: dict = Depends(require_role("admin"))
):
    """
    Register a new SIEM connector.

    SECURITY:
      * Admin role required.
      * `host` is DNS-resolved and rejected if it lands in any blocked
        network (loopback, link-local, metadata, RFC1918, IPv6 ULA).
        Prevents the connector from being used as an SSRF primitive
        against the cloud metadata service or internal LAN.
    """
    # ── SSRF guard ──────────────────────────────────────────────
    _assert_safe_siem_host(config.host)
    if not (1 <= config.port <= 65535):
        raise HTTPException(status_code=400, detail="Port out of range.")

    try:
        # Create connector based on type
        if config.siem_type.lower() == "elk":
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

        logger.logger.info("siem_connector_registered",
                          user_id=current_user.get("sub"),
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
    current_user: dict = Depends(require_role("admin"))
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

        # Unregister
        success = siem_service.unregister_connector(connector_name)

        if not success:
            raise HTTPException(status_code=404, detail="Connector not found")

        logger.logger.info("siem_connector_unregistered",
                          user_id=current_user.get("sub"),
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
                          user_id=current_user.get("sub"),
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
                          user_id=current_user.get("sub"),
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
                              user_id=current_user.get("sub"),
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
                              user_id=current_user.get("sub"),
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
