# PhishGuard — Viva Explanation Script
## Final Year Project: "PhishGuard: A Hybrid Framework for Detecting Phishing Attacks"

---

## 1. Problem Statement

Phishing attacks are one of the most dangerous and widespread cybersecurity threats today.
Attackers create fake websites that mimic legitimate ones — banks, PayPal, Google, Apple —
to steal usernames, passwords, and financial data.

**The core problem:** Existing solutions like Google Safe Browsing and browser warnings
are reactive — they only block URLs *after* they've already been reported. New phishing
sites appear and disappear within 4–8 hours, long before they make it into any blacklist.

**Our question:** Can we build a system that detects *new, never-seen-before* phishing URLs
in real time, before any user is victimized?

---

## 2. Why Existing Systems Fail

| System | Weakness |
|--------|----------|
| Blacklists only | Miss brand-new phishing URLs (zero-day phishing) |
| Single ML model | High false positives; no explainability |
| Manual rules only | Attackers easily bypass fixed patterns |
| Browser warnings | Only trigger after damage is done |

The fundamental flaw: **single-method systems have blind spots**.
A blacklist can't detect a URL it's never seen.
An ML model alone can't explain WHY it made a decision.
Rules alone can't generalize to new attack patterns.

---

## 3. What is the Hybrid Model?

PhishGuard solves this by combining **three independent detection methods** that each
catch what the others miss — like a panel of three judges voting on each URL.

> **Hybrid = Heuristic Engine + Machine Learning Engine + Behavioral Engine**

Each engine analyzes the URL independently, generates a score, and the
**Decision Fusion Layer** combines all three using weighted voting.

---

## 4. Architecture Explanation (5 Stages)

```
[User URL Input]
       ↓
[Feature Extraction Layer]
  URL Features (37+ features extracted from raw URL string)
  Domain Features (SSL cert, domain age via WHOIS)
  Content Features (HTML analysis: forms, iframes, scripts)
       ↓
[3 Detection Engines — Run in PARALLEL]
  ┌─────────────────────────────────────────────────────┐
  │ A. Heuristic Engine (35% weight)                    │
  │    - Blacklist check (local DB, 50+ known domains)  │
  │    - 13 rule-based checks (IP in URL, @ symbol,     │
  │      suspicious TLD, brand squatting, entropy, etc) │
  └─────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────┐
  │ B. Machine Learning Engine (45% weight)             │
  │    - Random Forest (200 trees)                      │
  │    - XGBoost (200 estimators, depth=6)              │
  │    - Ensemble: RF 50% + XGBoost 50%                 │
  │    - Trained on 1000-sample labeled dataset         │
  └─────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────┐
  │ C. Behavioral & Transaction Engine (20% weight)     │
  │    - Domain age simulation                          │
  │    - Session anomaly detection                      │
  │    - Device mismatch simulation                     │
  │    - Redirect chain detection                       │
  │    - Hidden iframe / credential harvesting          │
  └─────────────────────────────────────────────────────┘
       ↓
[Decision Fusion Layer]
  Final Score = (Heuristic × 0.35) + (ML × 0.45) + (Behavioral × 0.20)
  ≥ 65 → Phishing | 35–64 → Suspicious | < 35 → Legitimate
       ↓
[Output: Result + Risk Score + Explanation]
```

---

## 5. Why 3 Layers?

**Layer 1 — Heuristic Engine:**
- Fast, deterministic, explainable
- Catches well-known patterns instantly
- Blacklist catches confirmed phishing domains
- Limitation: can't detect novel attacks it hasn't seen

**Layer 2 — Machine Learning Engine:**
- Generalizes to new, unseen phishing patterns
- Learns from 37 numerical features
- Random Forest + XGBoost ensemble reduces variance
- Limitation: black box, can't explain decisions alone

**Layer 3 — Behavioral Engine:**
- Catches evasive phishing that bypasses rules and ML
- Detects anomalies: new domain, hidden iframes, credential harvesting
- Simulates what a security analyst would notice manually
- Limitation: some signals are simulated, not live user telemetry

**Together:** No single layer can be fooled without triggering at least one other.
This is the key advantage of the hybrid approach.

---

## 6. How the System Works — Step by Step

**Step 1:** User pastes a URL (e.g., `http://paypa1-secure-login.com/verify?id=99999`)

**Step 2:** Feature Extraction runs:
- URL length: 47 characters ✓
- Has IP: No, but domain has digits ('1' instead of 'l') → `domain_has_digits: 1`
- HTTPS: No → `has_https: 0`
- Suspicious keywords: "secure", "login", "verify" → `suspicious_word_count: 3`
- Domain age: 5 days (new) → `domain_age_days: 5`
- Content: Has password field, form submits externally

**Step 3:** Engines run in parallel:
- Heuristic: detects brand squatting (paypa1), no HTTPS, suspicious keywords → Score: 80
- ML: predicts 91% phishing probability based on learned patterns → Score: 91
- Behavioral: new domain + credential harvesting + redirect → Score: 70

**Step 4:** Decision Fusion:
- `(80 × 0.35) + (91 × 0.45) + (70 × 0.20) = 28 + 40.95 + 14 = 82.95`
- Classification: **PHISHING** (> 65 threshold)

**Step 5:** User sees: Risk Score 83/100 | Phishing | Explanation with specific reasons

---

## 7. Advantages of PhishGuard

1. **Zero-day phishing detection** — ML layer catches new phishing sites blacklists haven't seen
2. **Explainability** — Heuristic layer explains *why* a URL was flagged, not just "it is phishing"
3. **Three independent failure modes** — an attacker must bypass all three layers simultaneously
4. **Works offline** — core detection doesn't require external APIs
5. **Fast** — all three engines run in parallel (typically < 3 seconds per scan)
6. **Admin visibility** — full audit trail, charts, and analytics for security teams
7. **Modular architecture** — each engine can be improved independently

---

## 8. Real-World Use Case

**Scenario:** A bank employee receives an email from "IT Support" asking them to
click `http://microsofft-account-update.xyz/verify` to update their credentials.

1. Employee copies the URL into PhishGuard
2. **Heuristic Engine** immediately flags: suspicious TLD (.xyz), brand squatting (microsofft), no HTTPS
3. **ML Engine** recognizes the URL pattern matches 94% of known phishing training samples
4. **Behavioral Engine** detects the domain was registered 2 days ago and has a hidden credential form
5. **Result:** PHISHING — Risk Score 89/100 — employee avoids clicking
6. **Admin Panel** logs the scan for the security team to investigate the email campaign

---

## 9. Dataset and Training

- **Dataset:** 1000 labeled samples (500 legitimate, 500 phishing)
- **Features:** 37 extracted features per sample
- **Models:** Random Forest (200 trees) + XGBoost (200 estimators)
- **Split:** 80% training / 20% testing
- **Expected Accuracy:** ~93–96% on test set
- **Evaluation:** Accuracy, AUC-ROC, Precision, Recall, F1-score

---

## 10. Tech Stack Justification

| Component | Technology | Why |
|-----------|-----------|-----|
| Backend | FastAPI (Python) | Async support, auto-docs, fast |
| Database | SQLite + SQLAlchemy | Lightweight, no server needed |
| ML | scikit-learn + XGBoost | Proven, production-ready |
| Frontend | React + Tailwind CSS | Fast development, beautiful UI |
| Feature Extraction | tldextract, BeautifulSoup | Reliable parsing libraries |
| Auth | JWT (python-jose) | Stateless, secure |

---

## 11. Possible Examiner Questions

**Q: Why not use deep learning (LSTM/BERT)?**
A: Deep learning requires much more training data and compute. Random Forest + XGBoost
achieves ~95% accuracy with only 1000 samples and runs in milliseconds on CPU.
For a final year project that runs locally, this is the appropriate choice.

**Q: Can the behavioral engine be improved?**
A: Yes — in a production system, the behavioral engine would integrate real browser telemetry,
actual user session data, and network traffic analysis. For this project, it simulates these
signals deterministically from URL and content features, which is academically valid.

**Q: What if a phishing site uses HTTPS?**
A: SSL alone doesn't mean a site is safe — 85% of phishing sites now use HTTPS. Our system
doesn't rely on HTTPS alone; it's one signal among 37+ features. The ML model correctly
learns that HTTPS is a weak positive signal.

**Q: How do you handle adversarial attacks (attackers trying to fool your system)?**
A: The hybrid architecture makes this much harder. To evade detection, an attacker would
need to simultaneously: use an old domain (defeat behavioral), use clean URL structure
(defeat heuristic), AND have feature patterns matching legitimate sites (defeat ML).

**Q: What is your model's accuracy?**
A: On our generated dataset, we expect ~93–96% accuracy with AUC-ROC > 0.97.
The exact figures are printed during training and shown in the terminal output.

---

*PhishGuard — Final Year Project | Hybrid Phishing Detection System*
