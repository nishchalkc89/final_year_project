"""
Blacklist management routes.
GET    /api/admin/blacklist        — list all entries
POST   /api/admin/blacklist        — add URL/domain
DELETE /api/admin/blacklist/{id}   — remove entry
"""

import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database.database import get_db
from database.models import BlacklistEntry
from routes.admin import _get_current_admin

router = APIRouter()


def _extract_domain(url: str) -> str:
    """Pull the bare domain from a URL or plain hostname string."""
    url = url.strip().lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    domain = url.split("/")[0].split("?")[0].split("#")[0]
    return domain


class BlacklistAddRequest(BaseModel):
    url: str
    reason: Optional[str] = None


@router.get("/admin/blacklist")
async def list_blacklist(
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    rows = (await db.execute(
        select(BlacklistEntry).order_by(desc(BlacklistEntry.created_at))
    )).scalars().all()
    return {
        "total": len(rows),
        "entries": [_serialize(r) for r in rows],
    }


@router.post("/admin/blacklist", status_code=201)
async def add_to_blacklist(
    body: BlacklistAddRequest,
    db: AsyncSession = Depends(get_db),
    admin: str = Depends(_get_current_admin),
):
    raw = body.url.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    domain = _extract_domain(raw)

    # Check for duplicate domain
    existing = (await db.execute(
        select(BlacklistEntry).where(BlacklistEntry.domain == domain)
    )).scalars().first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Domain '{domain}' is already in the blacklist (id={existing.id})",
        )

    entry = BlacklistEntry(
        url=raw,
        domain=domain,
        reason=body.reason.strip() if body.reason else None,
        added_by=admin,
        created_at=datetime.utcnow(),
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return _serialize(entry)


@router.delete("/admin/blacklist/{entry_id}")
async def remove_from_blacklist(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    entry = await db.get(BlacklistEntry, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Blacklist entry not found")
    await db.delete(entry)
    await db.commit()
    return {"message": "Removed from blacklist", "id": entry_id}


# ── Public helper for heuristic engine integration ────────────────────────────

async def get_db_blacklist_set(db: AsyncSession) -> set:
    """Return a set of all blacklisted domains for use in the heuristic engine."""
    rows = (await db.execute(select(BlacklistEntry.domain))).scalars().all()
    return {r.lower() for r in rows if r}


def _serialize(r: BlacklistEntry) -> dict:
    return {
        "id": r.id,
        "url": r.url,
        "domain": r.domain,
        "reason": r.reason,
        "added_by": r.added_by,
        "created_at": r.created_at.isoformat(),
    }
