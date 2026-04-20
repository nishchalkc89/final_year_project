"""
PhishGuard - FastAPI Backend Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from database.database import init_db
from routes.scan import router as scan_router
from routes.admin import router as admin_router
from routes.blacklist import router as blacklist_router
from config import CORS_ORIGINS


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    print("[OK] PhishGuard backend started - database initialized")
    yield
    print("[STOP] PhishGuard backend shutting down")


app = FastAPI(
    title="PhishGuard API",
    description="Hybrid Phishing Detection System - Heuristic + ML + Behavioral",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(blacklist_router, prefix="/api")


@app.get("/")
async def root():
    return {"name": "PhishGuard API", "version": "1.1.0", "status": "running", "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "ok"}
