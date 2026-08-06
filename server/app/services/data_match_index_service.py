"""
DB-aware orchestration for EDM datasets + fingerprinted documents.

Wraps the pure engine (app.services.data_matching_service) with persistence.
The protected plaintext (CSV rows, document text) is used only to BUILD the
keyed index and is then dropped -- it is never assigned to the model, so it
never reaches the database or the ORM identity map.

The HMAC key is derived here, once, from settings.SECRET_KEY. It is passed to
the engine in memory and never stored.

Ported from a comparable service in CyberSentinel-DLP (a competitor product).
"""
import csv
import io
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import settings
from app.models.data_match_source import DataMatchSource
from app.services import data_matching_service as dm

logger = structlog.get_logger()


def _key() -> bytes:
    return dm.derive_key(settings.SECRET_KEY)


class DataMatchIndexService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # -- build --------------------------------------------------------------
    @staticmethod
    def parse_csv(csv_text: str, columns: Optional[Sequence[str]] = None):
        """Parse a CSV into rows + the column list to index. Returns
        (rows, columns). Only columns present in the header are kept."""
        reader = csv.DictReader(io.StringIO(csv_text))
        header = reader.fieldnames or []
        rows = [dict(r) for r in reader]
        cols = list(columns) if columns else list(header)
        cols = [c for c in cols if c in header]
        return rows, cols

    async def create_edm(
        self,
        name: str,
        columns: Sequence[str],
        rows: Sequence[Dict[str, Any]],
        description: Optional[str] = None,
        min_fields: int = 2,
        classification: str = "Restricted",
    ) -> DataMatchSource:
        index = dm.build_edm_index(rows, columns, _key())   # plaintext consumed here
        src = DataMatchSource(
            source_type="edm",
            name=name,
            description=description,
            index=index,                                    # digests only
            columns=list(columns),
            row_count=index.get("row_count"),
            min_fields=min_fields,
            classification=classification,
        )
        self.db.add(src)
        await self.db.flush()
        logger.info("EDM source indexed", name=name, rows=index.get("row_count"),
                    columns=len(columns), cells=len(index.get("cells", {})))
        return src

    async def create_fingerprint(
        self,
        name: str,
        text: str,
        description: Optional[str] = None,
        min_shingles: int = 4,
        min_containment: float = 0.25,
        classification: str = "Restricted",
    ) -> DataMatchSource:
        index = dm.build_fingerprint_index(text, _key())    # text consumed here
        src = DataMatchSource(
            source_type="fingerprint",
            name=name,
            description=description,
            index=index,                                    # digests only
            shingle_count=len(index.get("fp", [])),
            min_shingles=min_shingles,
            min_containment=min_containment,
            classification=classification,
        )
        self.db.add(src)
        await self.db.flush()
        logger.info("Fingerprint source indexed", name=name,
                    shingles=len(index.get("fp", [])))
        return src

    # -- manage ---------------------------------------------------------------
    async def list_sources(self, source_type=None, enabled=None) -> List[DataMatchSource]:
        q = select(DataMatchSource)
        if source_type:
            q = q.where(DataMatchSource.source_type == source_type)
        if enabled is not None:
            q = q.where(DataMatchSource.enabled == enabled)
        q = q.order_by(DataMatchSource.created_at.desc())
        res = await self.db.execute(q)
        return list(res.scalars().all())

    async def get(self, source_id: UUID) -> Optional[DataMatchSource]:
        res = await self.db.execute(
            select(DataMatchSource).where(DataMatchSource.id == source_id)
        )
        return res.scalar_one_or_none()

    async def update(self, source_id: UUID, **fields) -> Optional[DataMatchSource]:
        src = await self.get(source_id)
        if not src:
            return None
        allowed = {"name", "description", "enabled", "min_fields",
                   "min_shingles", "min_containment", "classification"}
        for k, v in fields.items():
            if k in allowed and v is not None:
                setattr(src, k, v)
        await self.db.flush()
        return src

    async def delete(self, source_id: UUID) -> bool:
        src = await self.get(source_id)
        if not src:
            return False
        await self.db.delete(src)
        return True

    # -- match (also usable by the classification pipeline) -----------------
    async def match_content(self, content: str) -> List[Dict[str, Any]]:
        """Run `content` against every ENABLED source. Returns a list of match
        descriptors (no plaintext -- row coordinates and counts only)."""
        if not content:
            return []
        key = _key()
        res = await self.db.execute(
            select(DataMatchSource).where(DataMatchSource.enabled.is_(True))
        )
        matches: List[Dict[str, Any]] = []
        for s in res.scalars().all():
            try:
                if s.source_type == "edm":
                    m = dm.match_edm(content, s.index, key, min_fields=s.min_fields)
                    if m["matched"]:
                        matches.append({
                            "source_id": str(s.id), "name": s.name, "type": "edm",
                            "classification": s.classification,
                            "matched_rows": m["matched_row_count"],
                            "rows": m["rows"][:5],   # coordinates only, no values
                        })
                else:
                    m = dm.match_fp(content, s.index, key,
                                    min_shingles=s.min_shingles,
                                    min_containment=s.min_containment)
                    if m["matched"]:
                        matches.append({
                            "source_id": str(s.id), "name": s.name, "type": "fingerprint",
                            "classification": s.classification,
                            "overlap": m["overlap"], "containment": m["containment"],
                        })
            except Exception as e:  # a bad index must never break classification
                logger.warning("data-match source failed", source_id=str(s.id), error=str(e))
        return matches
