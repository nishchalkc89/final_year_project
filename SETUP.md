# PhishGuard — Setup Guide

## Prerequisites
- Python 3.10+ installed
- Node.js 18+ installed
- Git (optional)

---

## Quick Start (3 Steps)

### Step 1 — Train the ML Model (first time only)
Double-click `train_model.bat`
This will:
- Create a Python virtual environment
- Install all Python dependencies
- Generate `ml_model/dataset.csv` (1000 samples)
- Train Random Forest + XGBoost models
- Save models to `ml_model/models/`

### Step 2 — Start the Backend
Double-click `start_backend.bat`
- Starts FastAPI on http://localhost:8000
- API docs available at http://localhost:8000/docs

### Step 3 — Start the Frontend
Double-click `start_frontend.bat`
- Installs npm packages (first time)
- Starts React app on http://localhost:5173

---

## Project Structure

```
PhisGuard/
├── backend/
│   ├── main.py                    ← FastAPI app entry point
│   ├── config.py                  ← Configuration (thresholds, weights, credentials)
│   ├── requirements.txt
│   ├── database/
│   │   ├── database.py            ← SQLAlchemy async engine
│   │   └── models.py              ← ScanResult ORM model
│   ├── feature_extraction/
│   │   ├── url_features.py        ← 25 URL-based features
│   │   ├── domain_features.py     ← SSL, WHOIS, DNS features
│   │   └── content_features.py    ← HTML page analysis
│   ├── engines/
│   │   ├── heuristic_engine.py    ← 13 rule-based checks + blacklist
│   │   ├── ml_engine.py           ← RF + XGBoost ensemble
│   │   └── behavioral_engine.py   ← Anomaly simulation
│   ├── fusion/
│   │   └── decision_fusion.py     ← Weighted score combination
│   ├── routes/
│   │   ├── scan.py               ← POST /api/scan
│   │   └── admin.py              ← Admin CRUD + stats endpoints
│   └── data/
│       └── blacklist.txt          ← Local phishing domain blacklist
├── ml_model/
│   ├── generate_dataset.py        ← Generates dataset.csv
│   ├── train.py                   ← Trains and saves models
│   └── models/                    ← rf_model.pkl, xgb_model.pkl, scaler.pkl
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Home.jsx           ← User-facing landing page
│   │   │   ├── AdminLogin.jsx     ← Admin login
│   │   │   └── Admin.jsx          ← Full admin dashboard
│   │   ├── components/
│   │   │   ├── Navbar.jsx
│   │   │   ├── Hero.jsx
│   │   │   ├── ScanInput.jsx      ← URL scan form + ResultCard
│   │   │   ├── ResultCard.jsx     ← Detailed scan results
│   │   │   ├── HowItWorks.jsx
│   │   │   ├── AboutUs.jsx
│   │   │   └── Footer.jsx
│   │   └── api/
│   │       └── phishguard.js      ← API client
│   └── package.json
├── database/
│   └── phisguard.db               ← SQLite database (auto-created)
├── start_backend.bat
├── start_frontend.bat
├── train_model.bat
└── VIVA_EXPLANATION.md
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| POST | /api/scan | Scan a URL |
| GET | /api/scan/{id} | Get scan by ID |
| POST | /api/admin/login | Admin login (returns JWT) |
| GET | /api/admin/scans | List all scans (paginated, filterable) |
| GET | /api/admin/stats | Aggregate statistics + charts data |
| GET | /api/admin/scans/{id} | Full scan detail |
| DELETE | /api/admin/scans/{id} | Delete a scan |

---

## Admin Panel

- URL: http://localhost:5173/admin/login
- Default credentials: **admin / admin123**
- Change in `backend/config.py` (ADMIN_USERNAME, ADMIN_PASSWORD)

---

## Detection Thresholds

Edit in `backend/config.py`:
```python
PHISHING_THRESHOLD = 65    # score >= 65 → Phishing
SUSPICIOUS_THRESHOLD = 35  # score 35-64 → Suspicious
                           # score < 35  → Legitimate

# Engine weights (must sum to 1.0)
HEURISTIC_WEIGHT = 0.35
ML_WEIGHT = 0.45
BEHAVIORAL_WEIGHT = 0.20
```

---

## Troubleshooting

**"Model not available" in results:**
Run `train_model.bat` first. The system works without ML (uses neutral 50% score) but is less accurate.

**Backend won't start:**
Check Python 3.10+ is installed: `python --version`

**Frontend can't connect to backend:**
Make sure backend is running on port 8000. Check `vite.config.js` proxy setting.

**WHOIS lookups fail:**
Install python-whois: `pip install python-whois`
Domain age will show as -1 if WHOIS is unavailable (system still works).
