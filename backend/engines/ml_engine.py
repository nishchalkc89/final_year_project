"""
Machine Learning Detection Engine.
Primary: Loads pre-trained RF + XGBoost ensemble if available.
Fallback: Built-in weighted feature scorer (no training required).
The fallback gives realistic phishing probabilities from raw features.
"""

import joblib
import numpy as np
from pathlib import Path
from config import MODEL_DIR

_rf_model = None
_xgb_model = None
_scaler = None
_models_loaded = False

ML_FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_underscores",
    "num_slashes", "num_at_sign", "num_question_marks", "num_equals",
    "num_percent", "num_ampersands", "num_digits_in_url",
    "has_ip_address", "has_https", "url_entropy",
    "num_subdomains", "domain_length", "has_suspicious_tld",
    "path_length", "query_length", "has_suspicious_words",
    "suspicious_word_count", "num_hex_encoding",
    "has_double_slash_in_path", "has_at_in_netloc", "domain_has_digits",
    "has_login_form", "has_password_field", "has_iframe",
    "has_meta_redirect", "num_external_links", "form_action_external",
    "num_scripts", "has_hidden_elements",
    "domain_age_days", "has_ssl", "ssl_valid", "domain_resolves",
]


def _load_models():
    global _rf_model, _xgb_model, _scaler, _models_loaded
    if _models_loaded:
        return _models_loaded
    rf_path = Path(MODEL_DIR) / "rf_model.pkl"
    xgb_path = Path(MODEL_DIR) / "xgb_model.pkl"
    scaler_path = Path(MODEL_DIR) / "scaler.pkl"
    try:
        if rf_path.exists():
            _rf_model = joblib.load(rf_path)
        if xgb_path.exists():
            _xgb_model = joblib.load(xgb_path)
        if scaler_path.exists():
            _scaler = joblib.load(scaler_path)
        _models_loaded = bool(_rf_model or _xgb_model)
    except Exception as e:
        print(f"[ML Engine] Model loading failed: {e}")
        _models_loaded = False
    return _models_loaded


# ── Built-in Fallback Scorer ──────────────────────────────────────────────────
# Weighted feature scoring derived from domain knowledge + typical RF importances.
# Calibrated to produce probabilities that correlate well with real phishing signals.

_FEATURE_WEIGHTS = {
    # High-signal binary features
    "has_ip_address":          45.0,
    "num_at_sign":             30.0,   # > 0 means suspicious
    "has_suspicious_tld":      22.0,
    "form_action_external":    28.0,
    "has_at_in_netloc":        25.0,
    "domain_has_digits":       14.0,
    "has_double_slash_in_path": 14.0,
    # Content indicators
    "has_meta_redirect":       18.0,
    "has_hidden_elements":     12.0,
    "has_iframe":              10.0,
    # Credential harvesting
    "form_action_external_pwd": 0.0,   # handled below in combo
    # Negative signals (reduce score)
    "has_https":              -12.0,
    "ssl_valid":              -18.0,
    "domain_resolves":         -6.0,
    "has_favicon":             -5.0,
}


def _builtin_score(feats: dict) -> float:
    """Algorithmic phishing probability 0–100 using weighted features."""
    score = 15.0  # base prior (most URLs are not phishing)

    # ── Binary / categorical signals ──
    score += feats.get("has_ip_address", 0) * 45
    score += min(feats.get("num_at_sign", 0), 1) * 30
    score += feats.get("has_suspicious_tld", 0) * 22
    score += feats.get("form_action_external", 0) * 28
    score += feats.get("has_at_in_netloc", 0) * 25
    score += feats.get("domain_has_digits", 0) * 14
    score += feats.get("has_double_slash_in_path", 0) * 14
    score += feats.get("has_meta_redirect", 0) * 18
    score += feats.get("has_hidden_elements", 0) * 12
    score += feats.get("has_iframe", 0) * 10

    # ── Negative (legitimacy) signals ──
    score += feats.get("has_https", 0) * -12
    score += feats.get("ssl_valid", 0) * -18
    score += feats.get("domain_resolves", 0) * -6

    # ── Continuous features (non-linear) ──
    url_len = feats.get("url_length", 0)
    if url_len > 100:
        score += 18
    elif url_len > 75:
        score += 10
    elif url_len > 50:
        score += 4

    sus_words = feats.get("suspicious_word_count", 0)
    score += min(sus_words * 8, 30)

    subdomains = feats.get("num_subdomains", 0)
    if subdomains >= 4:
        score += 20
    elif subdomains == 3:
        score += 10
    elif subdomains == 2:
        score += 4

    entropy = feats.get("url_entropy", 0)
    if entropy > 5.5:
        score += 15
    elif entropy > 4.8:
        score += 7

    hex_enc = feats.get("num_hex_encoding", 0)
    score += min(hex_enc * 3, 18)

    age = feats.get("domain_age_days", -1)
    if age == 0:
        score += 30
    elif 0 < age <= 14:
        score += 22
    elif 0 < age <= 30:
        score += 14
    elif 0 < age <= 90:
        score += 7
    elif age > 365:
        score -= 10

    # ── Combo signals ──
    # Password field without SSL = very suspicious
    if feats.get("has_password_field", 0) and not feats.get("ssl_valid", 0):
        score += 22
    elif feats.get("has_password_field", 0) and feats.get("ssl_valid", 0):
        score += 2  # normal login page

    # Login form + external form action = credential harvesting
    if feats.get("has_login_form", 0) and feats.get("form_action_external", 0):
        score += 15

    # Query string complexity
    if feats.get("num_equals", 0) >= 5 and feats.get("query_length", 0) > 80:
        score += 10

    return min(max(score, 0.0), 100.0)


# ── Public Interface ──────────────────────────────────────────────────────────

def _build_feature_vector(url_feats: dict, content_feats: dict, domain_feats: dict) -> np.ndarray:
    merged = {**url_feats, **content_feats, **domain_feats}
    vec = []
    for name in ML_FEATURE_NAMES:
        val = merged.get(name, 0)
        if val is None or (isinstance(val, float) and np.isnan(val)):
            val = 0
        if name == "domain_age_days" and val < 0:
            val = 0
        vec.append(float(val))
    return np.array(vec).reshape(1, -1)


def run_ml_engine(url_features: dict, content_features: dict, domain_features: dict) -> dict:
    loaded = _load_models()

    all_feats = {**url_features, **content_features, **domain_features}

    if not loaded:
        # Use built-in scorer — no pkl files needed
        prob = _builtin_score(all_feats)
        return {
            "score": round(prob, 2),
            "rf_probability": round(prob, 2),
            "xgb_probability": round(prob, 2),
            "ensemble_probability": round(prob, 2),
            "model_available": False,
            "model_mode": "builtin_fallback",
            "prediction": "phishing" if prob >= 50 else "legitimate",
            "top_features": _top_features_builtin(all_feats),
        }

    # Trained models available — use them
    X = _build_feature_vector(url_features, content_features, domain_features)
    if _scaler is not None:
        try:
            X = _scaler.transform(X)
        except Exception:
            pass

    rf_prob, xgb_prob = 50.0, 50.0
    rf_weight, xgb_weight = 0.5, 0.5

    if _rf_model is not None:
        try:
            rf_prob = float(_rf_model.predict_proba(X)[0][1]) * 100
        except Exception:
            rf_weight = 0.0

    if _xgb_model is not None:
        try:
            xgb_prob = float(_xgb_model.predict_proba(X)[0][1]) * 100
        except Exception:
            xgb_weight = 0.0

    if rf_weight + xgb_weight == 0:
        ensemble = 50.0
    elif rf_weight == 0:
        ensemble = xgb_prob
    elif xgb_weight == 0:
        ensemble = rf_prob
    else:
        ensemble = (rf_prob * rf_weight + xgb_prob * xgb_weight) / (rf_weight + xgb_weight)

    top_features = []
    if _rf_model is not None and hasattr(_rf_model, "feature_importances_"):
        importances = _rf_model.feature_importances_
        indices = np.argsort(importances)[::-1][:5]
        top_features = [
            {"feature": ML_FEATURE_NAMES[i], "importance": round(float(importances[i]), 4)}
            for i in indices if i < len(ML_FEATURE_NAMES)
        ]

    return {
        "score": round(ensemble, 2),
        "rf_probability": round(rf_prob, 2),
        "xgb_probability": round(xgb_prob, 2),
        "ensemble_probability": round(ensemble, 2),
        "model_available": True,
        "model_mode": "trained",
        "prediction": "phishing" if ensemble >= 50 else "legitimate",
        "top_features": top_features,
    }


def _top_features_builtin(feats: dict) -> list:
    ranked = [
        ("has_ip_address", feats.get("has_ip_address", 0) * 0.45),
        ("form_action_external", feats.get("form_action_external", 0) * 0.28),
        ("num_at_sign", min(feats.get("num_at_sign", 0), 1) * 0.30),
        ("has_suspicious_tld", feats.get("has_suspicious_tld", 0) * 0.22),
        ("suspicious_word_count", min(feats.get("suspicious_word_count", 0) * 0.08, 0.30)),
        ("domain_age_days", 0.22 if 0 <= feats.get("domain_age_days", -1) <= 14 else 0),
        ("url_length", 0.18 if feats.get("url_length", 0) > 100 else 0),
        ("url_entropy", 0.15 if feats.get("url_entropy", 0) > 5.5 else 0),
    ]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return [{"feature": f, "importance": round(imp, 4)} for f, imp in ranked[:5] if imp > 0]
