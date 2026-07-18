from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, Tuple

import pandas as pd
import streamlit as st


Source = Literal["virustotal", "machine_learning"]


@dataclass(frozen=True)
class VirusTotalView:
    available: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    failure: int = 0
    total_engines: int = 0
    analysis_date: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class FinalResultView:
    label: str
    badge: str
    badge_kind: str  # "error" | "warning" | "success" | "info"
    verdict: str  # "phishing" | "suspicious" | "legitimate" | "unknown"
    source: Source
    source_note: str
    phishing_probability: Optional[float] = None
    confidence: Optional[float] = None
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_undetected: Optional[int] = None
    vt_total_engines: Optional[int] = None
    vt_analysis_date: Optional[str] = None


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


def _ml_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    ml = payload.get("machine_learning")
    return ml if isinstance(ml, dict) else payload


def virustotal_to_view(payload: Dict[str, Any]) -> VirusTotalView:
    vt = payload.get("virustotal")
    if not isinstance(vt, dict):
        return VirusTotalView(available=False, message="No VirusTotal report available.")
    # If VirusTotal indicates it's unavailable, propagate that.
    if not vt.get("available"):
        return VirusTotalView(
            available=False,
            message=vt.get("message"),
            error=vt.get("error"),
        )

    # Treat reports with zero engines as effectively "no report" so the
    # frontend falls back to the local ML model. Some VT lookups return
    # an empty stats object even when `available` is true.
    total_engines = int(vt.get("total_engines", 0) or 0)
    if total_engines <= 0:
        return VirusTotalView(available=False, message="No VirusTotal report available.")

    return VirusTotalView(
        available=True,
        malicious=int(vt.get("malicious", 0) or 0),
        suspicious=int(vt.get("suspicious", 0) or 0),
        harmless=int(vt.get("harmless", 0) or 0),
        undetected=int(vt.get("undetected", 0) or 0),
        timeout=int(vt.get("timeout", 0) or 0),
        failure=int(vt.get("failure", 0) or 0),
        total_engines=total_engines,
        analysis_date=vt.get("analysis_date"),
    )


def _ml_result_view(ml: Dict[str, Any]) -> FinalResultView:
    pred = str(ml.get("prediction", "")).strip().lower()
    phishing_prob = normalize_probability(ml.get("phishing_probability"))
    confidence = normalize_probability(ml.get("confidence"))

    if pred == "phishing":
        return FinalResultView(
            label="High risk",
            badge="PHISHING",
            badge_kind="error",
            verdict="phishing",
            source="machine_learning",
            source_note="No VirusTotal report found — result based on machine learning.",
            phishing_probability=phishing_prob,
            confidence=confidence,
        )

    if pred == "legitimate":
        return FinalResultView(
            label="Looks legitimate",
            badge="SAFE",
            badge_kind="success",
            verdict="legitimate",
            source="machine_learning",
            source_note="No VirusTotal report found — result based on machine learning.",
            phishing_probability=phishing_prob,
            confidence=confidence,
        )

    return FinalResultView(
        label="Could not classify",
        badge="UNKNOWN",
        badge_kind="warning",
        verdict="unknown",
        source="machine_learning",
        source_note="No VirusTotal report found — result based on machine learning.",
        phishing_probability=phishing_prob,
        confidence=confidence,
    )


def final_result_from_payload(payload: Dict[str, Any]) -> FinalResultView:
    vt = virustotal_to_view(payload)

    if vt.available:
        flagged = vt.malicious + vt.suspicious
        if vt.malicious > 0:
            return FinalResultView(
                label="This URL was flagged as malicious",
                badge="PHISHING",
                badge_kind="error",
                verdict="phishing",
                source="virustotal",
                source_note="Verified by VirusTotal community scan.",
                vt_malicious=vt.malicious,
                vt_suspicious=vt.suspicious,
                vt_harmless=vt.harmless,
                vt_undetected=vt.undetected,
                vt_total_engines=vt.total_engines,
                vt_analysis_date=vt.analysis_date,
            )

        if vt.suspicious > 0:
            return FinalResultView(
                label="Some security engines reported suspicion",
                badge="SUSPICIOUS",
                badge_kind="warning",
                verdict="suspicious",
                source="virustotal",
                source_note="Verified by VirusTotal community scan.",
                vt_malicious=vt.malicious,
                vt_suspicious=vt.suspicious,
                vt_harmless=vt.harmless,
                vt_undetected=vt.undetected,
                vt_total_engines=vt.total_engines,
                vt_analysis_date=vt.analysis_date,
            )

        return FinalResultView(
            label="No security engines flagged this URL",
            badge="SAFE",
            badge_kind="success",
            verdict="legitimate",
            source="virustotal",
            source_note="Verified by VirusTotal community scan.",
            vt_malicious=vt.malicious,
            vt_suspicious=vt.suspicious,
            vt_harmless=vt.harmless,
            vt_undetected=vt.undetected,
            vt_total_engines=vt.total_engines,
            vt_analysis_date=vt.analysis_date,
        )

    return _ml_result_view(_ml_payload(payload))


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
          Paste a URL to check whether it is safe. Results prioritize VirusTotal scans.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_final_result(view: FinalResultView) -> None:
    colors = {
        "success": ("#16A34A", "rgba(22,163,74,0.18)"),
        "error": ("#EF4444", "rgba(239,68,68,0.18)"),
        "warning": ("#F59E0B", "rgba(245,158,11,0.18)"),
        "info": ("#60A5FA", "rgba(96,165,250,0.18)"),
    }
    border, bg = colors.get(view.badge_kind, colors["info"])

    st.subheader("Result")
    st.markdown(
        f"""
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px 14px;
                    border-radius:14px; background:{bg}; border:1px solid {border};">
          <div>
            <div style="font-size:12px; opacity:0.9; margin-bottom:2px;">Final verdict</div>
            <div style="font-size:18px; font-weight:800;">{view.label}</div>
          </div>
          <div style="font-size:12px; padding:8px 12px; border-radius:999px; border:1px solid {border}; font-weight:800;">
            {view.badge}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption(view.source_note)

    if view.source == "virustotal":
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Malicious", view.vt_malicious or 0)
        with c2:
            st.metric("Suspicious", view.vt_suspicious or 0)
        with c3:
            st.metric("Harmless", view.vt_harmless or 0)
        with c4:
            st.metric("Undetected", view.vt_undetected or 0)

        total = view.vt_total_engines or 0
        flagged = (view.vt_malicious or 0) + (view.vt_suspicious or 0)
        if total > 0:
            st.progress(
                min(max(flagged / total, 0.0), 1.0),
                text=f"{flagged}/{total} security engines flagged",
            )

        if view.vt_analysis_date:
            st.caption(f"Last scanned: {view.vt_analysis_date}")
        return

    c1, c2 = st.columns(2)
    with c1:
        st.metric(
            "Risk score",
            "—"
            if view.phishing_probability is None
            else f"{view.phishing_probability * 100:.1f}%",
        )
    with c2:
        st.metric(
            "Confidence",
            "—" if view.confidence is None else f"{view.confidence * 100:.1f}%",
        )

    if view.phishing_probability is not None:
        st.progress(
            min(max(view.phishing_probability, 0.0), 1.0),
            text="Estimated risk",
        )


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


def batch_row_from_payload(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    result = final_result_from_payload(payload)

    row: Dict[str, Any] = {
        "url": payload.get("url", url),
        "verdict": result.verdict,
        "result": result.badge,
        "source": result.source,
        "error": None,
    }

    if result.source == "virustotal":
        row.update(
            {
                "vt_malicious": result.vt_malicious,
                "vt_suspicious": result.vt_suspicious,
                "vt_harmless": result.vt_harmless,
                "vt_undetected": result.vt_undetected,
                "vt_total_engines": result.vt_total_engines,
                "vt_analysis_date": result.vt_analysis_date,
                "ml_phishing_probability": None,
                "ml_confidence": None,
            }
        )
    else:
        row.update(
            {
                "vt_malicious": None,
                "vt_suspicious": None,
                "vt_harmless": None,
                "vt_undetected": None,
                "vt_total_engines": None,
                "vt_analysis_date": None,
                "ml_phishing_probability": result.phishing_probability,
                "ml_confidence": result.confidence,
            }
        )

    return row
