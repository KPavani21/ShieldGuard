import time
import joblib
import numpy as np
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.features import extract_url_features

app = FastAPI(title="ShieldGuard Phishing Detection API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    model = joblib.load("model/phishing_model.joblib")
except Exception as e:
    raise RuntimeError(f"Model file not found. Run train.py first. Error: {e}")

TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "microsoft.com", "www.microsoft.com",
    "amazon.in", "www.amazon.in",
    "wikipedia.org", "en.wikipedia.org", "www.wikipedia.org",
    "linkedin.com", "www.linkedin.com",
    "youtube.com", "www.youtube.com",
}

CACHE_TTL_SECONDS = 600  # 10 minutes
# Structure: { url: {"expires_at": float, "payload": dict} }
url_cache: dict[str, dict] = {}

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    risk_level: str
    latency_ms: float
    cached: bool
    source: str

def get_hostname(url: str) -> str:
    target = url if url.startswith(("http://", "https://")) else "http://" + url
    try:
        return (urlparse(target).hostname or "").lower()
    except ValueError:
        return ""

@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "ShieldGuard Inference Engine",
        "model": "XGBoost v1.1",
        "cache_entries": len(url_cache),
    }

@app.post("/predict", response_model=PredictionResponse)
def predict_url(request: URLRequest):
    start_time = time.perf_counter()
    target_url = request.url.strip()

    if not target_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    now = time.time()

    # 1. Check TTL Cache first
    cached_entry = url_cache.get(target_url)
    if cached_entry and cached_entry["expires_at"] > now:
        result = cached_entry["payload"].copy()
        result["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 2)
        result["cached"] = True
        return result

    hostname = get_hostname(target_url)

    # 2. Check Trusted Domain Allowlist
    if hostname in TRUSTED_DOMAINS:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        result = {
            "url": target_url,
            "is_phishing": False,
            "confidence": 99.5,
            "risk_level": "SAFE",
            "latency_ms": latency_ms,
            "cached": False,
            "source": "allowlist",
        }
        url_cache[target_url] = {"expires_at": now + CACHE_TTL_SECONDS, "payload": result}
        return result

    # 3. Extract 13 lexical features & run XGBoost inference
    features = np.array([extract_url_features(target_url)])
    prob_phishing = float(model.predict_proba(features)[0][1])
    is_phishing = prob_phishing >= 0.50

    if prob_phishing >= 0.80:
        risk_level = "HIGH"
    elif prob_phishing >= 0.50:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    result = {
        "url": target_url,
        "is_phishing": is_phishing,
        "confidence": round(prob_phishing * 100, 2),
        "risk_level": risk_level,
        "latency_ms": latency_ms,
        "cached": False,
        "source": "xgboost_ml",
    }

    url_cache[target_url] = {"expires_at": now + CACHE_TTL_SECONDS, "payload": result}
    return result