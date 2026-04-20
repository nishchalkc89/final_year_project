"""
PhishGuard ML Training Script
Trains Random Forest + XGBoost ensemble on dataset.csv.
Run: python train.py
Output: models/rf_model.pkl, models/xgb_model.pkl, models/scaler.pkl
"""

import sys
import json
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score,
)

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("WARNING XGBoost not installed — skipping XGBoost model")

DATASET_FILE = Path(__file__).parent / "dataset.csv"
MODELS_DIR = Path(__file__).parent / "models"
MODELS_DIR.mkdir(exist_ok=True)

FEATURE_COLUMNS = [
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


def load_data() -> tuple[np.ndarray, np.ndarray]:
    if not DATASET_FILE.exists():
        print("Dataset not found. Generating now...")
        from generate_dataset import generate_dataset, save_csv
        data = generate_dataset(500, 500)
        save_csv(data, DATASET_FILE)

    df = pd.read_csv(DATASET_FILE)
    print(f"OK Loaded {len(df)} samples | "
          f"Phishing: {df['label'].sum()} | "
          f"Legitimate: {(df['label'] == 0).sum()}")

    available = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f"WARNING Missing columns (will use 0): {missing}")
        for col in missing:
            df[col] = 0

    X = df[FEATURE_COLUMNS].fillna(0).values
    y = df["label"].values
    return X, y


def train_models():
    X, y = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features (beneficial for SVM; RF/XGB don't strictly need it
    # but we scale anyway so the scaler is used consistently in inference)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    results = {}

    # ── Random Forest ─────────────────────────────────────────────────────────
    print("\n[RF] Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train_s, y_train)
    rf_pred = rf.predict(X_test_s)
    rf_prob = rf.predict_proba(X_test_s)[:, 1]
    rf_acc = accuracy_score(y_test, rf_pred)
    rf_auc = roc_auc_score(y_test, rf_prob)
    print(f"   Accuracy: {rf_acc:.4f} | AUC-ROC: {rf_auc:.4f}")
    print(classification_report(y_test, rf_pred, target_names=["Legitimate", "Phishing"]))
    joblib.dump(rf, MODELS_DIR / "rf_model.pkl")
    print("   OK Saved rf_model.pkl")
    results["random_forest"] = {"accuracy": rf_acc, "auc": rf_auc}

    # ── XGBoost ───────────────────────────────────────────────────────────────
    if HAS_XGB:
        print("\n[XGB] Training XGBoost...")
        xgb = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
        xgb.fit(
            X_train_s, y_train,
            eval_set=[(X_test_s, y_test)],
            verbose=False,
        )
        xgb_pred = xgb.predict(X_test_s)
        xgb_prob = xgb.predict_proba(X_test_s)[:, 1]
        xgb_acc = accuracy_score(y_test, xgb_pred)
        xgb_auc = roc_auc_score(y_test, xgb_prob)
        print(f"   Accuracy: {xgb_acc:.4f} | AUC-ROC: {xgb_auc:.4f}")
        print(classification_report(y_test, xgb_pred, target_names=["Legitimate", "Phishing"]))
        joblib.dump(xgb, MODELS_DIR / "xgb_model.pkl")
        print("   OK Saved xgb_model.pkl")
        results["xgboost"] = {"accuracy": xgb_acc, "auc": xgb_auc}

    # ── Scaler ────────────────────────────────────────────────────────────────
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    print("\n   OK Saved scaler.pkl")

    # ── Feature Importance ────────────────────────────────────────────────────
    importances = rf.feature_importances_
    feat_imp = sorted(
        zip(FEATURE_COLUMNS, importances),
        key=lambda x: x[1], reverse=True
    )
    print("\n[CHART] Top 10 Feature Importances (Random Forest):")
    for feat, imp in feat_imp[:10]:
        bar = "#" * int(imp * 50)
        print(f"   {feat:<35} {imp:.4f} {bar}")

    # Save feature metadata
    with open(MODELS_DIR / "feature_names.json", "w") as f:
        json.dump({"features": FEATURE_COLUMNS, "results": results}, f, indent=2)

    print("\nOK Training complete!")
    print(f"   Models saved to: {MODELS_DIR}")
    return results


if __name__ == "__main__":
    train_models()
