"""
Classification API Endpoints
Standalone classification service — accepts raw content and returns label + matched rules.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel, Field, ConfigDict
import structlog

from app.core.security import get_current_user
from app.core.database import get_mongodb, get_db
from app.services.classification_engine import ClassificationEngine

from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()
router = APIRouter()


# ────────────────────────────────────────────────────────────────────────────
# Request / Response schemas
# ────────────────────────────────────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    """Input for the standalone classify endpoint"""
    content: str = Field(..., min_length=1, description="Text content to classify (file body, clipboard, etc.)")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional metadata (file_type, source, etc.)")

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "content": "Customer SSN: 123-45-6789. Card: 4111-1111-1111-1111",
            "context": {"file_type": ".txt", "source": "clipboard"}
        }
    })


class MatchedRuleOut(BaseModel):
    rule_id: str
    rule_name: str
    rule_type: str
    match_count: int
    weight: float
    priority: int
    classification_labels: List[str] = []
    severity: Optional[str] = None
    category: Optional[str] = None
    label: Optional[Dict[str, Any]] = None


class ClassifyResponse(BaseModel):
    """Output of the standalone classify endpoint"""
    label: str = Field(..., description="Classification level: Public / Internal / Confidential / Restricted")
    confidence_score: float = Field(..., description="0.0 – 1.0")
    matched_rules: List[MatchedRuleOut] = Field(default_factory=list)
    total_matches: int = 0
    content_length: int = 0
    rules_evaluated: int = 0


class ClassifiedFile(BaseModel):
    """Classified file model"""
    file_id: str = Field(..., description="Unique file ID")
    filename: str = Field(..., description="Original filename")
    file_path: str = Field(..., description="File path")
    file_type: str = Field(..., description="File extension/type")
    file_size: int = Field(..., description="File size in bytes")
    classification: str = Field(..., description="Classification level")
    patterns_detected: List[str] = Field(default=[], description="Detected sensitive patterns")
    agent_id: str = Field(..., description="Agent that scanned the file")
    user_email: str = Field(..., description="User who owns/created the file")
    scanned_at: datetime = Field(..., description="Scan timestamp")
    confidence_score: float = Field(..., description="Classification confidence (0-1)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "file_id": "file-001",
                "filename": "financial_report_Q4.xlsx",
                "file_path": "C:/Users/john/Documents/financial_report_Q4.xlsx",
                "file_type": ".xlsx",
                "file_size": 524288,
                "classification": "confidential",
                "patterns_detected": ["credit_card", "ssn"],
                "agent_id": "agt-001",
                "user_email": "john.doe@company.com",
                "scanned_at": "2025-01-02T10:30:00Z",
                "confidence_score": 0.95
            }
        }
    )


# ────────────────────────────────────────────────────────────────────────────
# Core classify endpoint  (the standalone service the user asked for)
# ────────────────────────────────────────────────────────────────────────────

@router.post("/classify", response_model=ClassifyResponse)
async def classify_content(
    request: ClassifyRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    **Standalone Classification Service**

    Accepts raw text (file content, clipboard data, etc.) and returns:
    - **label**: Public / Internal / Confidential / Restricted
    - **matched_rules**: which rules fired and why
    - **confidence_score**: aggregated 0.0–1.0

    SECURITY: Requires a valid X-Agent-Key header. Previously this
    endpoint was intentionally anonymous, which let external callers
    (a) use it as an oracle to tune exfiltration so it lands as
    "Public" and (b) DoS the server via arbitrarily large `content`
    against expensive regex rules.
    """
    from app.api.v1.agents import verify_agent_key
    await verify_agent_key(http_request)

    engine = ClassificationEngine(session)
    result = await engine.classify_content(request.content, request.context)

    return ClassifyResponse(
        label=result.classification,
        confidence_score=round(result.confidence_score, 4),
        matched_rules=[MatchedRuleOut(**r) for r in result.matched_rules],
        total_matches=result.total_matches,
        content_length=result.details.get("content_length", len(request.content)),
        rules_evaluated=result.details.get("rules_evaluated", 0),
    )


# ────────────────────────────────────────────────────────────────────────────
# Detection patterns — now database-driven instead of hardcoded
# ────────────────────────────────────────────────────────────────────────────

@router.get("/patterns")
async def list_detection_patterns(
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all enabled detection patterns (rules) from the database.
    """
    from sqlalchemy import select
    from app.models.rule import Rule

    stmt = (
        select(Rule)
        .where(Rule.enabled == True)
        .order_by(Rule.priority.asc(), Rule.weight.desc())
    )
    rows = await session.execute(stmt)
    rules = rows.scalars().all()

    patterns = []
    for r in rules:
        patterns.append({
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "type": r.type,
            "severity": r.severity,
            "category": r.category,
            "weight": r.weight,
            "priority": r.priority,
            "enabled": r.enabled,
            "match_count": r.match_count,
        })

    return {"patterns": patterns, "total": len(patterns)}


# ────────────────────────────────────────────────────────────────────────────
# Data labels CRUD (lightweight)
# ────────────────────────────────────────────────────────────────────────────

@router.get("/labels")
async def list_labels(
    session: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    List all data labels (Public, Internal, Confidential, Restricted, plus custom).

    SECURITY: Requires a valid JWT. Previously anonymous — leaked the
    internal label taxonomy to anyone probing the API.
    """
    from sqlalchemy import select
    from app.models.data_label import DataLabel

    rows = await session.execute(select(DataLabel).order_by(DataLabel.severity.desc()))
    labels = rows.scalars().all()
    return {
        "labels": [l.to_dict() for l in labels],
        "total": len(labels),
    }


# ────────────────────────────────────────────────────────────────────────────
# Admin: cache invalidation
# ────────────────────────────────────────────────────────────────────────────

@router.post("/cache/invalidate")
async def invalidate_classification_cache(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Force-clear the classification engine's rule and regex caches.
    New/updated rules take effect on the very next classification call.
    """
    from app.services.classification_engine import clear_module_cache
    clear_module_cache()
    return {"status": "ok", "message": "Classification caches cleared — new rules active immediately"}


# ────────────────────────────────────────────────────────────────────────────
# Existing classified-files endpoints (MongoDB)
# ────────────────────────────────────────────────────────────────────────────

@router.get("/files", response_model=List[ClassifiedFile])
async def list_classified_files(
    classification: Optional[str] = Query(None, description="Filter by classification level"),
    file_type: Optional[str] = Query(None, description="Filter by file type"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    skip: int = Query(0, ge=0, description="Number of results to skip"),
    current_user: dict = Depends(get_current_user),
) -> List[ClassifiedFile]:
    """List classified files from MongoDB."""
    db = get_mongodb()
    files_collection = db["classified_files"]

    query = {}
    if classification:
        query["classification"] = classification
    if file_type:
        query["file_type"] = file_type

    files_cursor = files_collection.find(query).sort("scanned_at", -1).skip(skip).limit(limit)
    files = []

    async for file_doc in files_cursor:
        file_doc["file_id"] = str(file_doc["_id"])
        del file_doc["_id"]
        files.append(ClassifiedFile(**file_doc))

    logger.info("Listed classified files", count=len(files), filters=query)
    return files


@router.get("/files/{file_id}", response_model=ClassifiedFile)
async def get_classified_file(
    file_id: str,
    current_user: dict = Depends(get_current_user),
) -> ClassifiedFile:
    """Get details of a specific classified file."""
    db = get_mongodb()
    files_collection = db["classified_files"]

    from bson import ObjectId
    file_doc = await files_collection.find_one({"_id": ObjectId(file_id)})

    if not file_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File {file_id} not found"
        )

    file_doc["file_id"] = str(file_doc["_id"])
    del file_doc["_id"]
    return ClassifiedFile(**file_doc)


@router.get("/stats/summary")
async def get_classification_summary(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get summary statistics of classified files."""
    db = get_mongodb()
    files_collection = db["classified_files"]

    total = await files_collection.count_documents({})
    public = await files_collection.count_documents({"classification": "public"})
    internal = await files_collection.count_documents({"classification": "internal"})
    confidential = await files_collection.count_documents({"classification": "confidential"})
    restricted = await files_collection.count_documents({"classification": "restricted"})

    patterns_pipeline = [
        {"$unwind": "$patterns_detected"},
        {"$group": {"_id": "$patterns_detected", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    patterns_cursor = files_collection.aggregate(patterns_pipeline)
    top_patterns = []
    async for pattern in patterns_cursor:
        top_patterns.append({
            "pattern": pattern["_id"],
            "count": pattern["count"]
        })

    return {
        "total_files": total,
        "by_classification": {
            "public": public,
            "internal": internal,
            "confidential": confidential,
            "restricted": restricted,
        },
        "top_patterns": top_patterns,
    }


@router.get("/stats/by-type")
async def get_classification_by_type(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get classification statistics grouped by file type."""
    db = get_mongodb()
    files_collection = db["classified_files"]

    pipeline = [
        {
            "$group": {
                "_id": "$file_type",
                "count": {"$sum": 1},
                "total_size": {"$sum": "$file_size"}
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": 20}
    ]

    cursor = files_collection.aggregate(pipeline)
    file_types = []

    async for item in cursor:
        file_types.append({
            "file_type": item["_id"],
            "count": item["count"],
            "total_size_bytes": item["total_size"]
        })

    return {"file_types": file_types}
