from __future__ import annotations

from dataclasses import dataclass
import importlib
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

import pickle
import pandas as pd


@dataclass(frozen=True)
class LocalModelConfig:
    model_path: Path
    phishing_class: int = 1


class LocalModelError(RuntimeError):
    pass


def _default_feature_order() -> List[str]:
    return [
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


def _load_model(model_path: Path) -> Any:
    try:
        with open(model_path, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        raise LocalModelError(f"Failed to load model: {e}") from e


def _repo_root() -> Path:
    # frontend/streamlit_app/local_model.py -> repo root is 2 levels up
    return Path(__file__).resolve().parents[2]


def _extract_features(url: str) -> List[float]:
    try:
        # Your FastAPI code uses local imports (e.g. `from utils import ...`).
        # Import `features.py` with `fastAPI/` on sys.path to match uvicorn runtime.
        fastapi_dir = _repo_root() / "fastAPI"
        sys.path.insert(0, str(fastapi_dir))
        features_mod = importlib.import_module("features")
        extract_features = getattr(features_mod, "extract_features")
    except Exception as e:
        raise LocalModelError(
            "Could not import `fastAPI/features.py` feature extractor. "
            "Make sure `fastAPI/` exists at the repo root."
        ) from e

    try:
        return list(extract_features(url))
    except Exception as e:
        raise LocalModelError(f"Feature extraction failed: {e}") from e


def predict_locally(cfg: LocalModelConfig, url: str) -> Dict[str, Any]:
    model = _load_model(cfg.model_path)

    feature_order = list(getattr(model, "feature_names_in_", [])) or _default_feature_order()
    features = _extract_features(url)
    features_df = pd.DataFrame([features], columns=feature_order)

    try:
        proba = model.predict_proba(features_df)[0]
        classes = list(getattr(model, "classes_", []))
        proba_by_class = (
            {int(cls): float(p) for cls, p in zip(classes, proba)} if classes else {}
        )

        pred_class = int(model.predict(features_df)[0])
    except Exception as e:
        raise LocalModelError(f"Local prediction failed: {e}") from e

    pred_label = "phishing" if pred_class == cfg.phishing_class else "legitimate"
    confidence: Optional[float] = proba_by_class.get(pred_class)
    phishing_probability: Optional[float] = proba_by_class.get(cfg.phishing_class)

    return {
        "url": url,
        "prediction": pred_label,
        "predicted_class": pred_class,
        "phishing_class": cfg.phishing_class,
        "confidence": round(float(confidence), 6) if confidence is not None else None,
        "phishing_probability": round(float(phishing_probability), 6)
        if phishing_probability is not None
        else None,
        "class_probabilities": {str(k): round(v, 6) for k, v in proba_by_class.items()}
        or None,
        "source": "local_model",
    }

