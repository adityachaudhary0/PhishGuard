from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from streamlit_app.api import ApiConfig, ApiError, predict_via_api
from streamlit_app.ui import (
    batch_row_from_payload,
    ensure_url_column,
    final_result_from_payload,
    render_final_result,
    render_header,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / "fastAPI" / ".env")
load_dotenv(REPO_ROOT / "frontend" / ".streamlit" / "secrets.env")


def _secret(name: str, default: str = "") -> str:
    try:
        value = st.secrets.get(name, default)
        if value:
            return str(value)
    except Exception:
        pass
    return os.getenv(name, default)


def _get_api_config() -> ApiConfig:
    return ApiConfig(
        base_url=_secret("API_BASE_URL", "http://127.0.0.1:8000"),
        api_key=_secret("API_KEY"),
        timeout_s=float(_secret("API_TIMEOUT", "30")),
    )


def _download_csv(df: pd.DataFrame) -> bytes:
    buf = BytesIO()
    df.to_csv(buf, index=False)
    return buf.getvalue()


def main() -> None:
    st.set_page_config(
        page_title="PhishGuard — URL phishing detection",
        page_icon="🛡️",
        layout="wide",
    )

    render_header()

    try:
        api_cfg = _get_api_config()
    except Exception as e:
        st.error(f"Could not load service configuration: {e}")
        return

    if not api_cfg.api_key:
        st.error("Service is not configured. Contact the administrator.")
        return

    tab1, tab2 = st.tabs(["Single URL", "Batch scan (CSV)"])

    with tab1:
        st.subheader("Single URL check")
        url = st.text_input("URL", placeholder="example.com/login or https://example.com")

        cols = st.columns([1, 1, 2])
        with cols[0]:
            run = st.button("Analyze", use_container_width=True, type="primary")
        with cols[1]:
            clear = st.button("Clear", use_container_width=True)
        if clear:
            st.session_state.pop("last_single_payload", None)
            st.rerun()

        if run:
            if not url.strip():
                st.warning("Please enter a URL.")
            else:
                with st.spinner("Analyzing URL…"):
                    try:
                        payload = predict_via_api(api_cfg, url.strip())
                        st.session_state["last_single_payload"] = payload
                    except ApiError as e:
                        st.error(str(e))

        payload = st.session_state.get("last_single_payload")
        if isinstance(payload, dict):
            render_final_result(final_result_from_payload(payload))

    with tab2:
        st.subheader("Batch scan")
        st.write("Upload a CSV with a `url` column (or the first column will be used).")
        file = st.file_uploader("CSV file", type=["csv"])

        colA, colB, colC = st.columns([1, 1, 2])
        with colA:
            max_rows = st.number_input("Max rows", value=200, min_value=1, step=50)
        with colB:
            stop_on_error = st.toggle("Stop on first error", value=False)
        with colC:
            st.caption("Batch scans run one URL at a time.")

        if file is not None:
            try:
                df = pd.read_csv(file)
            except Exception as e:
                st.error(f"Could not read CSV: {e}")
                return

            df, used_col = ensure_url_column(df)
            st.caption(f"Using column: `{used_col}` → `url`")

            st.dataframe(df[["url"]].head(10), use_container_width=True, hide_index=True)

            run_batch = st.button("Run batch scan", type="primary")
            if run_batch:
                urls = [u for u in df["url"].astype(str).tolist()[: int(max_rows)]]
                results: List[Dict[str, Any]] = []

                prog = st.progress(0, text="Starting…")
                status = st.empty()

                for i, u in enumerate(urls, start=1):
                    status.write(f"Analyzing {i}/{len(urls)}")
                    try:
                        payload = predict_via_api(api_cfg, u)
                        results.append(batch_row_from_payload(u, payload))
                    except ApiError as e:
                        results.append(
                            {
                                "url": u,
                                "verdict": None,
                                "result": None,
                                "source": None,
                                "vt_malicious": None,
                                "vt_suspicious": None,
                                "vt_harmless": None,
                                "vt_undetected": None,
                                "vt_total_engines": None,
                                "vt_analysis_date": None,
                                "ml_phishing_probability": None,
                                "ml_confidence": None,
                                "error": str(e),
                            }
                        )
                        if stop_on_error:
                            break

                    prog.progress(i / len(urls), text="Running…")

                status.write("Done.")
                out = pd.DataFrame(results)

                st.write("")
                st.subheader("Results")
                st.dataframe(out, use_container_width=True, hide_index=True)

                safe = (out["verdict"].astype(str).str.lower() == "legitimate").sum()
                suspicious = (out["verdict"].astype(str).str.lower() == "suspicious").sum()
                phish = (out["verdict"].astype(str).str.lower() == "phishing").sum()
                errs = out["error"].notna().sum()
                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    st.metric("Safe", int(safe))
                with m2:
                    st.metric("Suspicious", int(suspicious))
                with m3:
                    st.metric("Phishing", int(phish))
                with m4:
                    st.metric("Errors", int(errs))

                st.download_button(
                    "Download results CSV",
                    data=_download_csv(out),
                    file_name="phishguard_results.csv",
                    mime="text/csv",
                    use_container_width=True,
                )


if __name__ == "__main__":
    main()
