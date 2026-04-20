"""
Behavioral & Transaction Analysis Engine.
Simulates behavioral anomaly detection based on URL/content signals.
In a production system, this would analyze real user session telemetry.
"""

import random
import hashlib
from datetime import datetime


def _stable_random(seed_str: str, lo: float, hi: float) -> float:
    """Deterministic pseudo-random float from a string seed (reproducible per URL)."""
    h = int(hashlib.md5(seed_str.encode()).hexdigest(), 16)
    normalized = (h % 10000) / 10000.0
    return lo + normalized * (hi - lo)


def run_behavioral_engine(
    url: str,
    url_features: dict,
    content_features: dict,
    domain_features: dict,
) -> dict:
    """
    Simulate behavioral risk scoring with anomaly detection.
    Returns score (0-100) and list of detected anomalies.
    """
    anomalies = []
    penalty = 0.0

    # ---- Session Anomaly Signals ----

    # New/unknown domain = elevated session risk
    age = domain_features.get("domain_age_days", -1)
    if age == 0:
        anomalies.append("Brand-new domain (0 days old) — high session risk")
        penalty += 35
    elif 0 < age <= 30:
        anomalies.append(f"Very new domain ({age} days old) — elevated session risk")
        penalty += 25
    elif 0 < age <= 90:
        anomalies.append(f"Newly registered domain ({age} days old)")
        penalty += 12
    elif age < 0:
        # Unknown age — simulate based on URL characteristics
        entropy = url_features.get("url_entropy", 3.0)
        simulated_age = _stable_random(url + "age", 5, 3000)
        if entropy > 5.0 or url_features.get("has_suspicious_tld", 0):
            anomalies.append("Domain age unknown — suspicious characteristics detected")
            penalty += 18

    # ---- Device / Environment Mismatch Simulation ----
    # Heuristic: brand-impersonation + login form = device mismatch risk
    if (
        url_features.get("has_suspicious_words", 0)
        and content_features.get("has_login_form", 0)
        and not domain_features.get("ssl_valid", 0)
    ):
        anomalies.append("Simulated device mismatch: login page without valid SSL")
        penalty += 20

    # ---- Redirect Chain Anomaly ----
    if content_features.get("has_meta_redirect", 0):
        anomalies.append("Meta-redirect detected — potential redirect chain attack")
        penalty += 20

    # ---- Hidden iFrame Injection ----
    if content_features.get("has_iframe", 0):
        anomalies.append("Hidden iframe detected — possible clickjacking or content injection")
        penalty += 15

    # ---- Form Action Mismatch ----
    if content_features.get("form_action_external", 0):
        anomalies.append("Form submits data to external domain — credential harvesting risk")
        penalty += 30

    # ---- Credential Harvesting Pattern ----
    if content_features.get("has_password_field", 0) and not domain_features.get("ssl_valid", 0):
        anomalies.append("Password field on page without valid SSL certificate")
        penalty += 25

    # ---- Transaction Anomaly: Unusual request patterns ----
    # Simulated: high query parameter count suggests automation/bot-driven phishing
    query_len = url_features.get("query_length", 0)
    num_equals = url_features.get("num_equals", 0)
    if num_equals >= 5 and query_len > 100:
        anomalies.append("Unusual transaction pattern: excessive URL parameters detected")
        penalty += 15

    # ---- Geolocation Anomaly Simulation ----
    # Suspicious TLDs often hosted in non-standard regions
    if url_features.get("has_suspicious_tld", 0):
        anomalies.append("Geolocation anomaly: high-risk TLD associated with low-regulation jurisdiction")
        penalty += 10

    # ---- No Favicon (common in quickly deployed phishing pages) ----
    if content_features.get("fetch_success", 0) and not content_features.get("has_favicon", 0):
        anomalies.append("No favicon detected — typical of hastily deployed phishing pages")
        penalty += 8

    # ---- Script injection risk ----
    num_scripts = content_features.get("num_scripts", 0)
    if num_scripts > 15 and content_features.get("has_hidden_elements", 0):
        anomalies.append(f"High script count ({num_scripts}) with hidden elements — obfuscation risk")
        penalty += 15

    # ---- Behavioral velocity simulation ----
    # Simulate: multiple scan hits on same URL in short window = suspicious
    url_hash_val = int(hashlib.sha256(url.encode()).hexdigest()[:8], 16) % 100
    if url_hash_val < 15 and url_features.get("has_suspicious_words", 0):
        anomalies.append("Simulated velocity anomaly: high-frequency scan pattern for this URL")
        penalty += 10

    score = min(max(penalty, 0.0), 100.0)

    return {
        "score": round(score, 2),
        "anomalies": anomalies,
        "num_anomalies": len(anomalies),
        "session_risk": _classify_risk(score),
    }


def _classify_risk(score: float) -> str:
    if score >= 65:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"
