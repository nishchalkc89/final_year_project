"""
Scan API routes.
POST /api/scan      — analyze a URL
GET  /api/scan/{id} — retrieve a scan result
"""

import asyncio
import json
import time
from datetime import datetime
from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database.database import get_db
from database.models import ScanResult
from feature_extraction.url_features import extract_url_features
from feature_extraction.domain_features import extract_domain_features
from feature_extraction.content_features import extract_content_features
from engines.heuristic_engine import run_heuristic_engine
from engines.ml_engine import run_ml_engine
from engines.behavioral_engine import run_behavioral_engine
from fusion.decision_fusion import fuse_decisions
from routes.blacklist import get_db_blacklist_set

router = APIRouter()


class ScanRequest(BaseModel):
    url: str


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


@router.post("/scan")
async def scan_url(
    body: ScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    url = _normalize_url(body.url)
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL too long (max 2048 characters)")

    start_time = time.time()

    # 1. URL features (instant, sync)
    url_features = extract_url_features(url)
    domain = url_features.get("domain", "")

    # 2. Parallel: domain features + content features + DB blacklist
    domain_features, content_features, db_blacklist = await asyncio.gather(
        asyncio.get_event_loop().run_in_executor(None, extract_domain_features, domain),
        asyncio.get_event_loop().run_in_executor(None, extract_content_features, url),
        get_db_blacklist_set(db),
    )

    # 3. Parallel: all three engines (DB blacklist passed to heuristic)
    heuristic_result, ml_result, behavioral_result = await asyncio.gather(
        asyncio.get_event_loop().run_in_executor(
            None, run_heuristic_engine, url, url_features, db_blacklist
        ),
        asyncio.get_event_loop().run_in_executor(
            None, run_ml_engine, url_features, content_features, domain_features
        ),
        asyncio.get_event_loop().run_in_executor(
            None, run_behavioral_engine, url, url_features, content_features, domain_features
        ),
    )

    # 4. Decision fusion
    fusion = fuse_decisions(heuristic_result, ml_result, behavioral_result)
    scan_duration = round(time.time() - start_time, 3)

    # 5. Persist
    record = ScanResult(
        url=url,
        timestamp=datetime.utcnow(),
        risk_score=fusion["final_score"],
        ml_score=ml_result["score"],
        heuristic_score=heuristic_result["score"],
        behavioral_score=behavioral_result["score"],
        final_label=fusion["final_label"],
        heuristic_flags=json.dumps(heuristic_result.get("flags", [])),
        behavioral_anomalies=json.dumps(behavioral_result.get("anomalies", [])),
        url_features=json.dumps({
            k: v for k, v in url_features.items()
            if k not in ("domain", "scheme", "subdomain", "tld")
        }),
        explanation=json.dumps(fusion.get("explanation", [])),
        scan_duration=scan_duration,
        client_ip=request.client.host if request.client else None,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    return {
        "id": record.id,
        "url": url,
        "timestamp": record.timestamp.isoformat(),
        "final_label": fusion["final_label"],
        "risk_score": fusion["final_score"],
        "confidence": fusion["confidence"],
        "explanation": fusion["explanation"],
        "breakdown": {
            "heuristic": {
                "score": heuristic_result["score"],
                "flags": heuristic_result["flags"],
                "is_blacklisted": heuristic_result["is_blacklisted"],
            },
            "ml": {
                "score": ml_result["score"],
                "rf_probability": ml_result.get("rf_probability"),
                "xgb_probability": ml_result.get("xgb_probability"),
                "model_available": ml_result.get("model_available"),
                "top_features": ml_result.get("top_features", []),
            },
            "behavioral": {
                "score": behavioral_result["score"],
                "anomalies": behavioral_result["anomalies"],
                "session_risk": behavioral_result["session_risk"],
            },
        },
        "score_breakdown": fusion["score_breakdown"],
        "url_features": {
            k: v for k, v in url_features.items()
            if k not in ("domain", "scheme", "subdomain", "tld")
        },
        "domain_features": domain_features,
        "content_features": {k: v for k, v in content_features.items() if k != "page_title"},
        "scan_duration": scan_duration,
    }


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.get(ScanResult, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": result.id,
        "url": result.url,
        "timestamp": result.timestamp.isoformat(),
        "final_label": result.final_label,
        "risk_score": result.risk_score,
        "ml_score": result.ml_score,
        "heuristic_score": result.heuristic_score,
        "behavioral_score": result.behavioral_score,
        "heuristic_flags": json.loads(result.heuristic_flags or "[]"),
        "behavioral_anomalies": json.loads(result.behavioral_anomalies or "[]"),
        "url_features": json.loads(result.url_features or "{}"),
        "explanation": json.loads(result.explanation or "[]"),
        "notes": result.notes,
        "is_manual_override": bool(result.is_manual_override),
        "scan_duration": result.scan_duration,
    }
