"""
Cloud Upload Guard — admin-managed monitored destinations. Admin only.

The browser extension (Cloud Upload Guard) ships with a hardcoded baseline
list of cloud destinations (Gmail, Outlook, Drive, Dropbox, ...) compiled
into inject.js. Previously, adding a new destination (e.g. a partner's
SharePoint tenant, a niche file-sharing service) meant editing that file and
redeploying it to every machine — impractical at fleet scale.

This table lets an admin add EXTRA destinations from the dashboard instead.
It's purely additive: rows here only ever extend the monitored-destination
list on top of the extension's built-in baseline, never replace or disable
it — so a mistake here can't silently turn off protection for a destination
that ships built in.

The extension's native host (skdlp_host.py) polls GET /agents/{agent_id}/
cloud-upload-hosts (agent-authenticated, see agents.py) to fetch the current
enabled set and pushes it down to the extension, which merges it with its
own baseline CLOUD_HOSTS list at runtime.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import require_role
from app.core.database import get_db
from app.models.user import User
from app.models.cloud_upload_hosts import CloudUploadHost
from app.services.audit_service import audit_log

logger = structlog.get_logger()
router = APIRouter()


class CloudUploadHostCreate(BaseModel):
    domain: str = Field(..., description="Bare domain to monitor, e.g. sharefile.com (subdomains matched too)")
    label: Optional[str] = Field(None, description="Human-readable note, e.g. 'Partner SFTP portal'")


def _normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    # Be forgiving of a pasted URL instead of a bare domain.
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/")[0]
    if not d or "." not in d:
        raise HTTPException(status_code=400, detail=f"'{domain}' doesn't look like a valid domain.")
    return d


def _entry_out(e: CloudUploadHost) -> dict:
    return {
        "id": str(e.id),
        "domain": e.domain,
        "label": e.label,
        "is_enabled": e.is_enabled,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


@router.get("/cloud-upload-hosts")
async def list_cloud_upload_hosts(
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(CloudUploadHost).order_by(CloudUploadHost.created_at))).scalars().all()
    return {"entries": [_entry_out(e) for e in rows]}


@router.post("/cloud-upload-hosts", status_code=status.HTTP_201_CREATED)
async def add_cloud_upload_host(
    body: CloudUploadHostCreate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    domain = _normalize_domain(body.domain)

    existing = (await db.execute(select(CloudUploadHost).where(CloudUploadHost.domain == domain))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"{domain} is already monitored.")

    db.add(CloudUploadHost(domain=domain, label=body.label, created_by=current_user.id, is_enabled=True))
    await db.commit()
    await audit_log(current_user.id, "security.cloud_upload_hosts.add", {"domain": domain})
    return {"added": domain}


@router.delete("/cloud-upload-hosts/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cloud_upload_host(
    entry_id: str,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(delete(CloudUploadHost).where(CloudUploadHost.id == entry_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Entry not found.")
    await db.commit()
    await audit_log(current_user.id, "security.cloud_upload_hosts.delete", {"id": entry_id})
    return None
