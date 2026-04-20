"""
Decision Fusion Layer.
Combines outputs from Heuristic, ML, and Behavioral engines using
weighted scoring and produces a final classification with explanation.
"""

from config import (
    HEURISTIC_WEIGHT,
    ML_WEIGHT,
    BEHAVIORAL_WEIGHT,
    PHISHING_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
)


def fuse_decisions(
    heuristic_result: dict,
    ml_result: dict,
    behavioral_result: dict,
) -> dict:
    """
    Weighted fusion of all three engine outputs.

    Weights: Heuristic 35% | ML 45% | Behavioral 20%
    Thresholds: Phishing ≥ 65 | Suspicious 35–64 | Legitimate < 35
    """
    h_score = float(heuristic_result.get("score", 0))
    m_score = float(ml_result.get("score", 50))
    b_score = float(behavioral_result.get("score", 0))

    # If blacklisted, override to Phishing immediately
    if heuristic_result.get("is_blacklisted", False):
        final_score = 98.0
        label = "Phishing"
        explanation = [
            "URL is present in the local phishing blacklist — immediate Phishing classification.",
            *_build_explanation(heuristic_result, ml_result, behavioral_result),
        ]
        return _build_output(final_score, label, explanation, h_score, m_score, b_score)

    # Weighted composite score
    final_score = (
        h_score * HEURISTIC_WEIGHT
        + m_score * ML_WEIGHT
        + b_score * BEHAVIORAL_WEIGHT
    )
    final_score = min(max(final_score, 0.0), 100.0)

    # Classification
    if final_score >= PHISHING_THRESHOLD:
        label = "Phishing"
    elif final_score >= SUSPICIOUS_THRESHOLD:
        label = "Suspicious"
    else:
        label = "Legitimate"

    explanation = _build_explanation(heuristic_result, ml_result, behavioral_result)

    return _build_output(final_score, label, explanation, h_score, m_score, b_score)


def _build_explanation(
    heuristic_result: dict,
    ml_result: dict,
    behavioral_result: dict,
) -> list[str]:
    reasons = []

    h_score = heuristic_result.get("score", 0)
    m_score = ml_result.get("score", 50)
    b_score = behavioral_result.get("score", 0)

    # Heuristic reasons
    flags = heuristic_result.get("flags", [])
    if flags:
        reasons.extend(flags[:5])
    elif h_score < 10:
        reasons.append("No heuristic rule violations detected.")

    # ML reasons
    if not ml_result.get("model_available", False):
        reasons.append("ML model not yet trained — using neutral probability.")
    else:
        top = ml_result.get("top_features", [])
        if top:
            top_feat_str = ", ".join(f["feature"] for f in top[:3])
            reasons.append(
                f"ML model ({m_score:.0f}% phishing probability). "
                f"Key features: {top_feat_str}."
            )

    # Behavioral reasons
    anomalies = behavioral_result.get("anomalies", [])
    if anomalies:
        reasons.extend(anomalies[:4])
    elif b_score < 10:
        reasons.append("No behavioral anomalies detected.")

    return reasons


def _build_output(
    final_score: float,
    label: str,
    explanation: list[str],
    h_score: float,
    m_score: float,
    b_score: float,
) -> dict:
    confidence = _compute_confidence(final_score, label)
    return {
        "final_score": round(final_score, 2),
        "final_label": label,
        "confidence": confidence,
        "explanation": explanation,
        "score_breakdown": {
            "heuristic": round(h_score, 2),
            "ml": round(m_score, 2),
            "behavioral": round(b_score, 2),
            "weights": {
                "heuristic": HEURISTIC_WEIGHT,
                "ml": ML_WEIGHT,
                "behavioral": BEHAVIORAL_WEIGHT,
            },
        },
    }


def _compute_confidence(score: float, label: str) -> str:
    if label == "Phishing":
        if score >= 85:
            return "Very High"
        elif score >= 70:
            return "High"
        return "Medium"
    elif label == "Suspicious":
        return "Medium"
    else:
        if score <= 15:
            return "Very High"
        elif score <= 25:
            return "High"
        return "Medium"
