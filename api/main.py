from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from src.features import extract_features
from src.bloom_filter import BloomFilter
from src.url_parser import URLParser
import pandas as pd

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing URL detector",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Loading model...")
MODEL = joblib.load(os.path.join(BASE_DIR, "models", "ensemble_v1.pkl"))
FEATURE_NAMES = joblib.load(os.path.join(BASE_DIR, "models", "feature_names.pkl"))

print("Loading Bloom filter...")
BLOOM = BloomFilter(size=5_000_000, num_hashes=3)
tranco = pd.read_csv(
    os.path.join(BASE_DIR, "data", "tranco.csv"),
    header=None,
    names=["rank", "domain"]
)
BLOOM.load_from_list(tranco["domain"].head(100_000).tolist())

print("PhishGuard API ready.")


class URLRequest(BaseModel):
    url: str


class PredictionResponse(BaseModel):
    url: str
    score: float
    verdict: str
    bloom_cached: bool
    top_features: list


@app.get("/health")
def health():
    return {"status": "ok", "model": "ensemble_v1"}


@app.post("/predict", response_model=PredictionResponse)
def predict(request: URLRequest):
    url = request.url.strip()

    parser = URLParser(url)
    domain = parser.get_domain()
    bloom_hit = BLOOM.might_contain(domain)

    if bloom_hit:
        return PredictionResponse(
            url=url,
            score=0.05,
            verdict="safe",
            bloom_cached=True,
            top_features=[]
        )

    features = extract_features(url)
    feature_vector = pd.DataFrame([features])[FEATURE_NAMES]
    score = float(MODEL.predict_proba(feature_vector)[0][1])
    verdict = "phishing" if score >= 0.5 else "safe"

    suspicious_priority = [
        'is_suspicious_tld', 'has_brand_keyword', 'has_ip',
        'has_at_symbol', 'brand_similarity', 'url_entropy',
        'domain_entropy', 'num_subdomains', 'num_hyphens'
    ]
    sorted_features = sorted(
        features.items(),
        key=lambda x: (
            suspicious_priority.index(x[0])
            if x[0] in suspicious_priority else 999,
            -abs(x[1])
        )
    )
    top_features = [
        {"name": k, "value": round(float(v), 4)}
        for k, v in sorted_features[:3]
    ]

    return PredictionResponse(
        url=url,
        score=round(score, 4),
        verdict=verdict,
        bloom_cached=False,
        top_features=top_features
    )