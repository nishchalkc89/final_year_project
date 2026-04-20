import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "database" / "phisguard.db"
MODEL_DIR = BASE_DIR / "ml_model" / "models"
DATA_DIR = Path(__file__).parent / "data"
BLACKLIST_FILE = DATA_DIR / "blacklist.txt"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "phishguard-secret-key-change-in-production-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

PHISHING_THRESHOLD = 65
SUSPICIOUS_THRESHOLD = 35

HEURISTIC_WEIGHT = 0.35
ML_WEIGHT = 0.45
BEHAVIORAL_WEIGHT = 0.20

REQUEST_TIMEOUT = 8

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]
