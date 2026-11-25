# 🛡️ ShieldGuard — Real-Time Phishing URL Detector

ShieldGuard is a low-latency, end-to-end real-time phishing detection system built with a **27-feature XGBoost classifier**, a **FastAPI inference backend** (with an in-memory TTL cache and trusted domain allowlist), and a **Chrome Extension (Manifest V3)** that scans active browser tabs on the fly.

---

## 🏗️ System Architecture

    [Chrome Extension (Manifest V3)]
      ├── background.js / popup.js  ──▶ Captures active tab URL & updates visual badge (OK / !)
      └── POST /predict { "url" }
            │
            ▼
    [FastAPI Inference Server (backend/app/main.py)]
      ├── 1. In-Memory TTL Cache (600s expiry)
      ├── 2. Trusted Domain Allowlist
      └── 3. 27-Feature URL Extractor (backend/app/features.py) ──▶ [XGBoost Model (.joblib)]

---

## 📊 Model Performance & Dataset

Trained on **40,000 real-world URLs** (`80/20` stratified train/test split, evaluated on **8,000** held-out URLs) using **27 lexical, structural, and entropy features**—including URL/hostname/path/query lengths, symbol counts (`.`, `-`, `@`, `/`, `?`, `=`, `&`, `_`, `%`), digit & letter counts, digit-to-URL and hostname-to-URL ratios, subdomain count, path depth, punycode (`xn--`) detection, risky TLD checks, suspicious keyword hits, and Shannon entropy of the hostname and path, with safe fallback handling for malformed URLs.

| Metric | Score |
| :--- | :---: |
| **Overall Accuracy** | **90.26%** |
| **Phishing Precision** | **85.21%** |
| **Phishing Recall** | **68.72%** |
| **Safe Recall** | **97.00%** |

---

## 📁 Project Structure

    shieldguard/
    ├── backend/
    │   ├── app/
    │   │   ├── __init__.py
    │   │   ├── features.py          # 27 lexical, structural & entropy feature extractor
    │   │   └── main.py              # FastAPI server, TTL cache, allowlist & /predict endpoint
    │   ├── model/
    │   │   └── phishing_model.joblib
    │   ├── train.py                 # Model training & evaluation script
    │   └── requirements.txt
    ├── extension/
    │   ├── manifest.json            # Chrome Manifest V3 configuration
    │   ├── background.js            # Tab monitoring & badge updates
    │   ├── popup.html               # Extension popup UI
    │   └── popup.js                 # Live prediction display & telemetry
    ├── .gitignore
    └── README.md

---

## 🚀 Setup & Local Execution

### 1. Run the FastAPI Backend

    cd backend
    python -m venv venv
    venv\Scripts\activate          # On Windows (use `source venv/bin/activate` on macOS/Linux)
    pip install -r requirements.txt
    python train.py               # Optional: retrain and save model/phishing_model.joblib
    uvicorn app.main:app --reload

The API runs at `http://127.0.0.1:8000` (interactive docs at `http://127.0.0.1:8000/docs`).

### 2. Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** ON (top-right corner).
3. Click **Load unpacked** and select the `extension/` folder.
4. Browse any website or test URL to see real-time phishing status, confidence score, and latency (`ms`).