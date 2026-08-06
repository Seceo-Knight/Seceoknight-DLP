"""
Exact Data Matching (EDM) + document fingerprinting -- management API.

Upload a protected dataset or document; the server indexes it into keyed
one-way digests and DISCARDS the plaintext. Only the index is stored, so this
API cannot leak the protected data back out -- GET never returns the index,
and there is no "download source" endpoint by design.

Ported from a comparable API in CyberSentinel-DLP (a competitor product).
Registered at prefix /data-matching -- distinct from SeceoKnight's existing
/fingerprints router (app/api/v1/fingerprints.py), which is a different,
older feature: exact whole-file SHA-256 hash matching for the file-identity
denylist (task #78). This module instead does content-level matching (row
combinations from a structured dataset, or a winnowed-shingle passage from a
document), which catches a paragraph copy-pasted out of a protected doc or a
CSV export of real customer records -- neither of which the whole-file-hash
denylist can see at all.
"""
import base64
import binascii
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.services.data_match_index_service import DataMatchIndexService
from app.services.document_extract import extract_text

logger = structlog.get_logger()
router = APIRouter()


# -- schemas ----------------------------------------------------------------
class EdmCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    columns: Optional[List[str]] = Field(
        None, description="Columns to index. Defaults to the CSV header.")
    rows: Optional[List[Dict[str, Any]]] = Field(
        None, description="Records as JSON objects (alternative to csv_b64).")
    csv_b64: Optional[str] = Field(
        None, description="Base64 of a CSV file (alternative to rows).")
    min_fields: int = Field(2, ge=1, le=20,
        description="Distinct columns of one record required to fire.")
    classification: str = Field("Restricted", max_length=30)


class FingerprintCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    content: Optional[str] = Field(None, description="Raw document text.")
    file_b64: Optional[str] = Field(None, description="Base64 of a document file.")
    filename: Optional[str] = Field(None, max_length=500,
        description="Original filename (drives extraction of file_b64).")
    min_shingles: int = Field(4, ge=1, le=1000)
    min_containment: float = Field(0.25, ge=0.01, le=1.0)
    classification: str = Field("Restricted", max_length=30)


class SourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    enabled: Optional[bool] = None
    min_fields: Optional[int] = Field(None, ge=1, le=20)
    min_shingles: Optional[int] = Field(None, ge=1, le=1000)
    min_containment: Optional[float] = Field(None, ge=0.01, le=1.0)
    classification: Optional[str] = Field(None, max_length=30)


class TestRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Text to test against all sources.")


def _b64(data: str, field: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{field} is not valid base64")


# -- create -------------------------------------------------------------------
@router.post("/edm", status_code=status.HTTP_201_CREATED)
async def create_edm(
    body: EdmCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    """Index a structured dataset for Exact Data Matching. Requires admin --
    the source is real PII, and the plaintext is discarded after indexing."""
    svc = DataMatchIndexService(db)
    rows = body.rows
    columns = body.columns

    if body.csv_b64:
        try:
            csv_text = _b64(body.csv_b64, "csv_b64").decode("utf-8-sig", errors="replace")
        except Exception:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "csv_b64 is not decodable text")
        rows, columns = svc.parse_csv(csv_text, body.columns)

    if not rows:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide rows or csv_b64")
    if not columns:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No columns to index")

    src = await svc.create_edm(
        name=body.name, columns=columns, rows=rows,
        description=body.description, min_fields=body.min_fields,
        classification=body.classification,
    )
    await db.commit()
    logger.info("EDM source created", user=getattr(current_user, "email", None),
                name=body.name, rows=src.row_count)
    return src.to_dict()


@router.post("/fingerprint", status_code=status.HTTP_201_CREATED)
async def create_fingerprint(
    body: FingerprintCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    """Register a sensitive document for fingerprint matching. Requires admin."""
    svc = DataMatchIndexService(db)
    text = body.content

    if not text and body.file_b64:
        data = _b64(body.file_b64, "file_b64")
        ex = extract_text(body.filename or body.name, data)
        if not ex.ok or not ex.text.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Could not extract text to fingerprint (kind={ex.kind}: {ex.reason})",
            )
        text = ex.text

    if not text or not text.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide content or file_b64")

    src = await svc.create_fingerprint(
        name=body.name, text=text, description=body.description,
        min_shingles=body.min_shingles, min_containment=body.min_containment,
        classification=body.classification,
    )
    await db.commit()
    logger.info("Fingerprint source created", user=getattr(current_user, "email", None),
                name=body.name, shingles=src.shingle_count)
    return src.to_dict()


# -- manage -------------------------------------------------------------------
@router.get("/")
async def list_sources(
    source_type: Optional[str] = Query(None, pattern="^(edm|fingerprint)$"),
    enabled: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    svc = DataMatchIndexService(db)
    sources = await svc.list_sources(source_type=source_type, enabled=enabled)
    return [s.to_dict() for s in sources]


@router.get("/{source_id}")
async def get_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    svc = DataMatchIndexService(db)
    src = await svc.get(source_id)
    if not src:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    return src.to_dict()


@router.patch("/{source_id}")
async def update_source(
    source_id: UUID,
    body: SourceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    svc = DataMatchIndexService(db)
    src = await svc.update(source_id, **body.model_dump(exclude_unset=True))
    if not src:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    await db.commit()
    return src.to_dict()


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    svc = DataMatchIndexService(db)
    if not await svc.delete(source_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    await db.commit()


# -- test (dry-run; does not create an event) --------------------------------
@router.post("/test")
async def test_content(
    body: TestRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Run text against all enabled sources and report matches, without
    creating an event or taking action. For tuning thresholds from the UI."""
    svc = DataMatchIndexService(db)
    matches = await svc.match_content(body.content)
    return {"matched": bool(matches), "match_count": len(matches), "matches": matches}
