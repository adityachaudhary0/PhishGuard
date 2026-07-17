from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Annotated
import pickle
from .features import extract_features
import pandas as pd
from dotenv import load_dotenv
import os
from pathlib import Path
from .vt import analyze_url


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
API_KEY = os.getenv("API_KEY")
PHISHING_THRESHOLD = float(os.getenv("PHISHING_THRESHOLD", "0.3"))
# IMPORTANT: This must match your notebook labels.
# Example: if you trained with phishing=0, set PHISHING_CLASS=0 in `.env`.
PHISHING_CLASS = int(os.getenv("PHISHING_CLASS", "1"))

app = FastAPI()

# CORS for Streamlit Cloud → Render API calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model
MODEL_PATH = Path(__file__).resolve().parent / "Phish1_u.pkl"
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Prefer the exact training-time feature order when available (sklearn >= 1.0).
# This prevents column-name / ordering mismatches between training and inference.
FEATURE_ORDER = list(getattr(model, "feature_names_in_", [])) or [
    "url_length",
    "domain_length",
    "is_ip",
    "tld_length",
    "subdomains",
    "has_obfuscation",
    "obfuscated_chars",
    "obfuscation_ratio",
    "letters",
    "letter_ratio",
    "digits",
    "digit_ratio",
    "equals",
    "qmark",
    "ampersand",
    "special_chars",
    "special_ratio",
    "is_https",
    "tld_risk",
    "has_suspicious",
    "hyphen_count",
]

class InputData(BaseModel):
    url: Annotated[str, Field(..., description="The URL to be classified")]

# 🔐 Dependency-like header
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/")
def welcome(x_api_key: str = Header(...)):
    verify_api_key(x_api_key)
    return {"message": "Welcome to PhishGuard 🚀"}

@app.post("/predict")
def predict(data: InputData, x_api_key: str = Header(...)):
    verify_api_key(x_api_key)

    try:
        # -------------------------------------------------
        # Feature Extraction
        # -------------------------------------------------
        features = extract_features(data.url)
        features_df = pd.DataFrame([features], columns=FEATURE_ORDER)

        # -------------------------------------------------
        # Machine Learning Prediction
        # -------------------------------------------------
        proba = model.predict_proba(features_df)[0]
        classes = list(getattr(model, "classes_", []))

        proba_by_class = (
            {int(cls): float(p) for cls, p in zip(classes, proba)}
            if classes
            else {}
        )

        phishing_probability = proba_by_class.get(PHISHING_CLASS)

        if phishing_probability is None:
            raise HTTPException(
                status_code=500,
                detail="Unable to determine phishing probability."
            )

        pred_class = (
            PHISHING_CLASS
            if phishing_probability >= PHISHING_THRESHOLD
            else (1 - PHISHING_CLASS)
        )

        pred_label = (
            "phishing"
            if pred_class == PHISHING_CLASS
            else "legitimate"
        )

        confidence = proba_by_class.get(pred_class)

        # -------------------------------------------------
        # VirusTotal Lookup
        # -------------------------------------------------
        vt_result = analyze_url(data.url)

        # -------------------------------------------------
        # Response
        # -------------------------------------------------
        return {
            "url": data.url,

            "machine_learning": {
                "prediction": pred_label,
                "predicted_class": pred_class,
                "phishing_class": PHISHING_CLASS,
                "threshold": PHISHING_THRESHOLD,
                "confidence": round(confidence, 6) if confidence is not None else None,
                "phishing_probability": round(phishing_probability, 6),
                "class_probabilities": {
                    str(k): round(v, 6)
                    for k, v in proba_by_class.items()
                },
            },

            "virustotal": vt_result,
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )