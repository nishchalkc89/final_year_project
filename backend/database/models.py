from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean
from database.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Composite risk score (0-100)
    risk_score = Column(Float, default=0.0)

    # Individual engine scores (0-100)
    ml_score = Column(Float, default=0.0)
    heuristic_score = Column(Float, default=0.0)
    behavioral_score = Column(Float, default=0.0)

    # Final classification: Legitimate / Suspicious / Phishing
    final_label = Column(String(20), default="Unknown")

    # JSON-encoded detail arrays
    heuristic_flags = Column(Text, default="[]")
    behavioral_anomalies = Column(Text, default="[]")
    url_features = Column(Text, default="{}")
    explanation = Column(Text, default="[]")

    # Metadata
    scan_duration = Column(Float, default=0.0)
    client_ip = Column(String(50), nullable=True)

    # Admin CRUD fields (added in v1.1)
    notes = Column(Text, nullable=True)
    is_manual_override = Column(Boolean, default=False)


class BlacklistEntry(Base):
    __tablename__ = "blacklist"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(255), nullable=True, index=True)
    reason = Column(String(500), nullable=True)
    added_by = Column(String(100), default="admin")
    created_at = Column(DateTime, default=datetime.utcnow)
