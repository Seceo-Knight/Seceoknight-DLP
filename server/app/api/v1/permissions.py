"""
Permissions API.

Read-only listing of the canonical permission catalog. Used by the admin
UI to render the per-user permission checklist. Management of the catalog
(add/remove permissions) is not exposed — the set is defined by migration.
"""

from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_permission
from app.core.database import get_db
from app.services.permission_service import list_all_permissions

router = APIRouter()


class PermissionOut(BaseModel):
    id: str
    name: str
    description: str = ""


@router.get("/", response_model=List[PermissionOut])
async def list_permissions(
    _=Depends(require_permission("view_users")),
    db: AsyncSession = Depends(get_db),
):
    """Return the full permission catalog (admin UI picker)."""
    return await list_all_permissions(db)
