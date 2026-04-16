from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass(frozen=True)
class ApiConfig:
    base_url: str
    api_key: str
    timeout_s: float = 15.0

    def predict_url(self) -> str:
        return self.base_url.rstrip("/") + "/predict"


class ApiError(RuntimeError):
    pass


def predict_via_api(cfg: ApiConfig, url: str) -> Dict[str, Any]:
    if not cfg.api_key:
        raise ApiError("Missing API key. Provide `x-api-key`.")

    try:
        r = requests.post(
            cfg.predict_url(),
            json={"url": url},
            headers={"x-api-key": cfg.api_key},
            timeout=cfg.timeout_s,
        )
    except requests.RequestException as e:
        raise ApiError(f"API request failed: {e}") from e

    if r.status_code == 401:
        raise ApiError("Unauthorized (bad API key).")
    if r.status_code >= 400:
        detail: Optional[str] = None
        try:
            payload = r.json()
            if isinstance(payload, dict):
                detail = payload.get("detail") or payload.get("error")
        except Exception:
            detail = None
        raise ApiError(f"API error {r.status_code}" + (f": {detail}" if detail else "."))

    try:
        payload = r.json()
    except ValueError as e:
        raise ApiError("API returned non-JSON response.") from e

    if not isinstance(payload, dict):
        raise ApiError("API returned unexpected response format.")

    if "error" in payload and payload.get("error"):
        raise ApiError(str(payload["error"]))

    return payload

