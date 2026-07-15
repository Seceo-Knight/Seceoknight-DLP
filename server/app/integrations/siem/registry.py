"""
SIEM connector persistence + factory.

Bridges the ``siem_connectors`` DB table and the in-memory
``SIEMIntegrationService`` registry:

  * build_connector()          — config dict → live SIEMConnector instance
  * persist_connector()        — upsert a row (secrets encrypted at rest)
  * delete_persisted_connector — remove a row
  * load_persisted_connectors  — rebuild + connect the registry on startup
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.crypto import encrypt_str, decrypt_str
from app.models.siem_connector import SIEMConnectorConfigModel
from app.integrations.siem.base import SIEMConnector
from app.integrations.siem.elk_connector import ELKConnector
from app.integrations.siem.splunk_connector import SplunkConnector
from app.integrations.siem.syslog_connector import SyslogConnector
from app.integrations.siem.integration_service import siem_service

logger = structlog.get_logger()

_SECRET_FIELDS = ("password", "api_key", "hec_token")


def build_connector(cfg: Dict[str, Any]) -> SIEMConnector:
    """Construct a connector from a plain config dict (secrets already decrypted)."""
    siem_type = str(cfg.get("siem_type", "")).lower()

    if siem_type == "syslog":
        return SyslogConnector(
            name=cfg["name"],
            host=cfg["host"],
            port=int(cfg.get("port") or 514),
            protocol=cfg.get("protocol") or "udp",
            log_format=cfg.get("log_format") or "cef",
            facility=cfg.get("facility") or "local0",
            verify_certs=bool(cfg.get("verify_certs", True)),
            min_severity=cfg.get("min_severity") or "low",
        )
    if siem_type == "elk":
        return ELKConnector(
            name=cfg["name"], host=cfg["host"], port=int(cfg["port"]),
            username=cfg.get("username"), password=cfg.get("password"),
            api_key=cfg.get("api_key"), use_ssl=bool(cfg.get("use_ssl", True)),
            verify_certs=bool(cfg.get("verify_certs", True)),
            index_prefix=cfg.get("index_prefix") or "dlp-events",
        )
    if siem_type == "splunk":
        return SplunkConnector(
            name=cfg["name"], host=cfg["host"], port=int(cfg["port"]),
            hec_token=cfg.get("hec_token"), username=cfg.get("username"),
            password=cfg.get("password"), use_ssl=bool(cfg.get("use_ssl", True)),
            verify_certs=bool(cfg.get("verify_certs", True)),
            source=cfg.get("source") or "seceoknight_dlp",
            sourcetype=cfg.get("sourcetype") or "dlp:event",
            index=cfg.get("index") or "dlp",
        )
    raise ValueError(f"Unsupported SIEM type: {siem_type}")


def _row_to_cfg(row: SIEMConnectorConfigModel) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "name": row.name, "siem_type": row.siem_type, "host": row.host,
        "port": row.port, "protocol": row.protocol, "log_format": row.log_format,
        "facility": row.facility, "min_severity": row.min_severity,
        "use_ssl": row.use_ssl, "verify_certs": row.verify_certs,
        "index_prefix": row.index_prefix, "index": row.index,
        "source": row.source, "sourcetype": row.sourcetype, "username": row.username,
    }
    if row.secrets_enc:
        try:
            cfg.update(json.loads(decrypt_str(row.secrets_enc)))
        except Exception:  # noqa: BLE001 — corrupt/rotated key: build without secrets
            logger.warning("siem_connector_secret_decrypt_failed", name=row.name)
    return cfg


async def persist_connector(db: AsyncSession, config: Dict[str, Any], created_by=None) -> None:
    """Upsert one connector config, encrypting secret fields at rest."""
    secrets = {k: config.get(k) for k in _SECRET_FIELDS if config.get(k)}
    secrets_enc = encrypt_str(json.dumps(secrets)) if secrets else None

    row = (await db.execute(
        select(SIEMConnectorConfigModel).where(SIEMConnectorConfigModel.name == config["name"])
    )).scalar_one_or_none()

    fields = dict(
        siem_type=str(config["siem_type"]).lower(), host=config["host"], port=int(config["port"]),
        protocol=config.get("protocol"), log_format=config.get("log_format"),
        facility=config.get("facility"), min_severity=config.get("min_severity"),
        use_ssl=bool(config.get("use_ssl", True)), verify_certs=bool(config.get("verify_certs", True)),
        index_prefix=config.get("index_prefix"), index=config.get("index"),
        source=config.get("source"), sourcetype=config.get("sourcetype"),
        username=config.get("username"), secrets_enc=secrets_enc, enabled=True,
    )
    if row:
        for k, v in fields.items():
            setattr(row, k, v)
    else:
        db.add(SIEMConnectorConfigModel(name=config["name"], created_by=created_by, **fields))
    await db.commit()


async def delete_persisted_connector(db: AsyncSession, name: str) -> None:
    await db.execute(delete(SIEMConnectorConfigModel).where(SIEMConnectorConfigModel.name == name))
    await db.commit()


async def load_persisted_connectors(db: AsyncSession) -> int:
    """Rebuild the in-memory registry from DB rows and connect them. Called at
    startup. Returns the number of connectors registered."""
    rows = (await db.execute(
        select(SIEMConnectorConfigModel).where(SIEMConnectorConfigModel.enabled == True)  # noqa: E712
    )).scalars().all()

    count = 0
    for row in rows:
        try:
            connector = build_connector(_row_to_cfg(row))
            siem_service.register_connector(connector)
            count += 1
        except Exception as e:  # noqa: BLE001 — one bad row must not block startup
            logger.warning("siem_connector_reload_failed", name=row.name, error=str(e))

    if count:
        try:
            await siem_service.connect_all()
        except Exception as e:  # noqa: BLE001
            logger.warning("siem_connect_all_failed", error=str(e))
    logger.info("siem_connectors_reloaded", count=count)
    return count
