from __future__ import annotations

import os
import pickle
import re
from urllib.parse import urlparse, urlunparse

from ml_models.feature_extractor import extract_feature_map, extract_features


MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml_models",
    "phishing_model_optimized.pkl",
)
# To switch model replace filename above with "phishing_model.pkl". which was huge size.

_MODEL = None
_PHISHING_THRESHOLD = 0.5


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    value = re.sub(r"\s+", "", value)
    value = value.rstrip(".,;:!?")
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or "/"

    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    host = (parsed.netloc or "").strip().lower()
    if not host:
        raise ValueError("Invalid URL: missing host.")
    if " " in host:
        raise ValueError("Invalid URL: host contains spaces.")
    if "." not in host:
        raise ValueError("Invalid URL: host must contain a domain.")
    if host.startswith(".") or host.endswith("."):
        raise ValueError("Invalid URL: malformed domain.")
    if not re.match(r"^[a-z0-9.-]+$", host):
        raise ValueError("Invalid URL: unsupported host characters.")


def _load_model():
    global _MODEL
    global _PHISHING_THRESHOLD
    if _MODEL is not None:
        return _MODEL, _PHISHING_THRESHOLD

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model file not found at {MODEL_PATH}. Run: python ml_models/train_phishing_model_optimized.py"
        )

    # Supports both pickle (.pkl) and joblib-compressed artifacts.
    try:
        with open(MODEL_PATH, "rb") as model_file:
            loaded = pickle.load(model_file)
    except Exception:
        try:
            import joblib

            loaded = joblib.load(MODEL_PATH)
        except Exception as exc:
            raise ValueError(f"Failed to load model artifact at {MODEL_PATH}: {exc}") from exc

    # Backward compatible: older file stores model directly.
    if isinstance(loaded, dict) and "model" in loaded:
        _MODEL = loaded["model"]
        _PHISHING_THRESHOLD = float(loaded.get("phishing_threshold", 0.5))
    else:
        _MODEL = loaded
        _PHISHING_THRESHOLD = 0.5
    return _MODEL, _PHISHING_THRESHOLD


def scan_url(url: str) -> dict:
    model, phishing_threshold = _load_model()
    normalized_url = _normalize_url(url)
    _validate_url(normalized_url)

    vector = extract_features(normalized_url)
    phishing_probability = float(model.predict_proba([vector])[0][1])
    prediction_num = 1 if phishing_probability >= phishing_threshold else 0
    confidence = float(phishing_probability if prediction_num == 1 else (1 - phishing_probability))

    feature_map = extract_feature_map(normalized_url)

    return {
        "prediction": "PHISHING" if prediction_num == 1 else "SAFE",
        "confidence": confidence,
        "phishing_probability": phishing_probability,
        "phishing_threshold": float(phishing_threshold),
        "normalized_url": normalized_url,
        "features": feature_map,
    }
