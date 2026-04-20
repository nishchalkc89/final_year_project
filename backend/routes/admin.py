"""
Admin API routes — full CRUD + enhanced filtering.
POST   /api/admin/login
GET    /api/admin/scans          — paginated + filtered list
GET    /api/admin/scans/{id}     — full detail
PUT    /api/admin/scans/{id}     — update label / score / notes / override
DELETE /api/admin/scans/{id}     — delete scan
DELETE /api/admin/scans/bulk     — bulk delete by list of ids
GET    /api/admin/stats          — aggregate statistics
"""

import json
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select, func, desc, asc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database.database import get_db
from database.models import ScanResult
from config import (
    ADMIN_USERNAME, ADMIN_PASSWORD,
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
)

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/admin/login")


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UpdateScanRequest(BaseModel):
    final_label: Optional[str] = None       # Legitimate / Suspicious / Phishing
    risk_score: Optional[float] = None      # 0–100
    notes: Optional[str] = None
    is_manual_override: Optional[bool] = None


class BulkDeleteRequest(BaseModel):
    ids: List[int]


def _create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + expires_delta
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def _get_current_admin(token: str = Depends(oauth2_scheme)):
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != ADMIN_USERNAME:
            raise exc
    except JWTError:
        raise exc
    return payload["sub"]


@router.post("/admin/login")
async def admin_login(body: LoginRequest):
    if body.username != ADMIN_USERNAME or body.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = _create_token(
        {"sub": body.username},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer", "username": body.username}


# ── Scan Listing (enhanced filters) ──────────────────────────────────────────

@router.get("/admin/scans")
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    label: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "timestamp",
    order: str = "desc",
    risk_min: Optional[float] = None,
    risk_max: Optional[float] = None,
    date_from: Optional[str] = None,   # ISO date string YYYY-MM-DD
    date_to: Optional[str] = None,
    override_only: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    query = select(ScanResult)
    conditions = []

    if label:
        conditions.append(ScanResult.final_label == label)
    if search:
        conditions.append(ScanResult.url.ilike(f"%{search}%"))
    if risk_min is not None:
        conditions.append(ScanResult.risk_score >= risk_min)
    if risk_max is not None:
        conditions.append(ScanResult.risk_score <= risk_max)
    if date_from:
        try:
            dt_from = datetime.strptime(date_from, "%Y-%m-%d")
            conditions.append(ScanResult.timestamp >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
            conditions.append(ScanResult.timestamp < dt_to)
        except ValueError:
            pass
    if override_only:
        conditions.append(ScanResult.is_manual_override == True)

    if conditions:
        query = query.where(and_(*conditions))

    allowed_sort = {"timestamp", "risk_score", "ml_score", "heuristic_score", "behavioral_score", "final_label"}
    sort_col = getattr(ScanResult, sort_by if sort_by in allowed_sort else "timestamp")
    query = query.order_by(desc(sort_col) if order == "desc" else asc(sort_col))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    offset = (page - 1) * per_page
    rows = (await db.execute(query.offset(offset).limit(per_page))).scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
        "results": [_serialize_scan(r) for r in rows],
    }


# ── Scan Detail ───────────────────────────────────────────────────────────────

@router.get("/admin/scans/{scan_id}")
async def get_scan_detail(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    r = await db.get(ScanResult, scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serialize_scan(r, full=True)


# ── UPDATE Scan (NEW) ─────────────────────────────────────────────────────────

@router.put("/admin/scans/{scan_id}")
async def update_scan(
    scan_id: int,
    body: UpdateScanRequest,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    r = await db.get(ScanResult, scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found")

    if body.final_label is not None:
        if body.final_label not in ("Legitimate", "Suspicious", "Phishing"):
            raise HTTPException(status_code=400, detail="Invalid label")
        r.final_label = body.final_label

    if body.risk_score is not None:
        if not (0 <= body.risk_score <= 100):
            raise HTTPException(status_code=400, detail="risk_score must be 0–100")
        r.risk_score = round(body.risk_score, 2)

    if body.notes is not None:
        r.notes = body.notes.strip() or None

    if body.is_manual_override is not None:
        r.is_manual_override = body.is_manual_override

    await db.commit()
    await db.refresh(r)
    return _serialize_scan(r, full=True)


# ── DELETE Scan ───────────────────────────────────────────────────────────────

@router.delete("/admin/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    r = await db.get(ScanResult, scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(r)
    await db.commit()
    return {"message": "Scan deleted", "id": scan_id}


# ── BULK DELETE (NEW) ─────────────────────────────────────────────────────────

@router.delete("/admin/scans")
async def bulk_delete_scans(
    body: BulkDeleteRequest,
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    if not body.ids:
        raise HTTPException(status_code=400, detail="No IDs provided")
    deleted = 0
    for scan_id in body.ids:
        r = await db.get(ScanResult, scan_id)
        if r:
            await db.delete(r)
            deleted += 1
    await db.commit()
    return {"message": f"Deleted {deleted} scan(s)", "deleted": deleted}


# ── Statistics ────────────────────────────────────────────────────────────────

@router.get("/admin/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _admin: str = Depends(_get_current_admin),
):
    total = (await db.execute(select(func.count()).select_from(ScanResult))).scalar() or 0

    label_counts = {}
    for label in ("Phishing", "Suspicious", "Legitimate"):
        cnt = (await db.execute(
            select(func.count()).where(ScanResult.final_label == label)
        )).scalar() or 0
        label_counts[label.lower()] = cnt

    overrides = (await db.execute(
        select(func.count()).where(ScanResult.is_manual_override == True)
    )).scalar() or 0

    avg_risk = (await db.execute(select(func.avg(ScanResult.risk_score)))).scalar() or 0.0

    # Last 7 days daily counts
    daily = []
    for i in range(6, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        cnt = (await db.execute(
            select(func.count()).where(
                ScanResult.timestamp >= day_start,
                ScanResult.timestamp < day_end,
            )
        )).scalar() or 0
        daily.append({"date": day.isoformat(), "count": cnt})

    recent = (await db.execute(
        select(ScanResult).order_by(desc(ScanResult.timestamp)).limit(5)
    )).scalars().all()

    return {
        "total_scans": total,
        "label_distribution": label_counts,
        "manual_overrides": overrides,
        "average_risk_score": round(float(avg_risk), 2),
        "daily_scans": daily,
        "recent_scans": [_serialize_scan(r) for r in recent],
    }


# ── Serializer ────────────────────────────────────────────────────────────────

def _serialize_scan(r: ScanResult, full: bool = False) -> dict:
    base = {
        "id": r.id,
        "url": r.url,
        "timestamp": r.timestamp.isoformat(),
        "final_label": r.final_label,
        "risk_score": r.risk_score,
        "ml_score": r.ml_score,
        "heuristic_score": r.heuristic_score,
        "behavioral_score": r.behavioral_score,
        "scan_duration": r.scan_duration,
        "notes": r.notes,
        "is_manual_override": bool(r.is_manual_override),
        "heuristic_flags": json.loads(r.heuristic_flags or "[]"),
        "behavioral_anomalies": json.loads(r.behavioral_anomalies or "[]"),
        "explanation": json.loads(r.explanation or "[]"),
    }
    if full:
        base["url_features"] = json.loads(r.url_features or "{}")
    return base
