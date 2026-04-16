from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import pandas as pd
import streamlit as st


@dataclass(frozen=True)
class PredictionView:
    label: str
    badge: str
    badge_kind: str  # "error" | "warning" | "success" | "info"
    phishing_probability: Optional[float]
    confidence: Optional[float]
    source: str


def normalize_probability(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        v = float(x)
        if v < 0 or v > 1:
            return None
        return v
    except Exception:
        return None


def prediction_to_view(payload: Dict[str, Any]) -> PredictionView:
    pred = str(payload.get("prediction", "")).strip().lower()
    phishing_prob = normalize_probability(payload.get("phishing_probability"))
    confidence = normalize_probability(payload.get("confidence"))
    source = str(payload.get("source") or "api")

    if pred == "phishing":
        badge = "PHISHING"
        badge_kind = "error"
        label = "High risk"
    elif pred == "legitimate":
        badge = "LEGIT"
        badge_kind = "success"
        label = "Looks legitimate"
    else:
        badge = "UNKNOWN"
        badge_kind = "warning"
        label = "Could not classify"

    return PredictionView(
        label=label,
        badge=badge,
        badge_kind=badge_kind,
        phishing_probability=phishing_prob,
        confidence=confidence,
        source=source,
    )


def render_header() -> None:
    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:4px;">
          <div style="font-size:28px; font-weight:800; letter-spacing:-0.5px;">PhishGuard</div>
          <div style="padding:4px 10px; border-radius:999px; background:#1B2550; border:1px solid rgba(255,255,255,0.08); font-size:12px;">
            URL phishing detection
          </div>
        </div>
        <div style="color: rgba(232,236,245,0.75); margin-bottom: 18px;">
          Paste a URL, get an instant risk score, and export batch results.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_badge(view: PredictionView) -> None:
    colors = {
        "success": ("#16A34A", "rgba(22,163,74,0.18)"),
        "error": ("#EF4444", "rgba(239,68,68,0.18)"),
        "warning": ("#F59E0B", "rgba(245,158,11,0.18)"),
        "info": ("#60A5FA", "rgba(96,165,250,0.18)"),
    }
    border, bg = colors.get(view.badge_kind, colors["info"])
    st.markdown(
        f"""
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px 14px;
                    border-radius:14px; background:{bg}; border:1px solid {border};">
          <div>
            <div style="font-size:12px; opacity:0.9; margin-bottom:2px;">Result</div>
            <div style="font-size:18px; font-weight:800;">{view.label}</div>
          </div>
          <div style="font-size:12px; padding:8px 12px; border-radius:999px; border:1px solid {border}; font-weight:800;">
            {view.badge}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics(view: PredictionView) -> None:
    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric(
            "Phishing probability",
            "—"
            if view.phishing_probability is None
            else f"{view.phishing_probability*100:.1f}%",
        )
    with c2:
        st.metric(
            "Confidence",
            "—" if view.confidence is None else f"{view.confidence*100:.1f}%",
        )
    with c3:
        st.metric("Source", view.source)

    if view.phishing_probability is not None:
        st.progress(min(max(view.phishing_probability, 0.0), 1.0), text="Risk score")


def ensure_url_column(df: pd.DataFrame) -> Tuple[pd.DataFrame, str]:
    lowered = {c.lower(): c for c in df.columns}
    if "url" in lowered:
        col = lowered["url"]
        out = df.copy()
        out["url"] = out[col].astype(str)
        return out, "url"
    first = df.columns[0]
    out = df.copy()
    out["url"] = out[first].astype(str)
    return out, str(first)

