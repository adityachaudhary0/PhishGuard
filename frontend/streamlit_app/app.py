from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from streamlit_app.api import ApiConfig, ApiError, predict_via_api
from streamlit_app.local_model import LocalModelConfig, LocalModelError, predict_locally
from streamlit_app.ui import (
    ensure_url_column,
    prediction_to_view,
    render_badge,
    render_header,
    render_metrics,
)


REPO_ROOT = Path(__file__).resolve().parents[2]  # frontend/streamlit_app/app.py -> repo root
DEFAULT_MODEL_PATH = REPO_ROOT / "fastAPI" / "Phish1_u.pkl"


def _get_default_api_base_url() -> str:
    try:
        return st.secrets.get("API_BASE_URL", "")
    except Exception:
        return ""


def _get_default_api_key() -> str:
    try:
        return st.secrets.get("API_KEY", "")
    except Exception:
        return ""


def _download_csv(df: pd.DataFrame) -> bytes:
    buf = BytesIO()
    df.to_csv(buf, index=False)
    return buf.getvalue()


def _predict_one(
    url: str,
    use_api: bool,
    api_cfg: ApiConfig,
    local_cfg: LocalModelConfig,
    fallback_to_local: bool,
) -> Dict[str, Any]:
    if use_api:
        try:
            payload = predict_via_api(api_cfg, url)
            payload.setdefault("source", "api")
            return payload
        except ApiError:
            if not fallback_to_local:
                raise
    return predict_locally(local_cfg, url)


def main() -> None:
    st.set_page_config(
        page_title="PhishGuard — URL phishing detection",
        page_icon="🛡️",
        layout="wide",
    )

    render_header()

    with st.sidebar:
        st.subheader("Connection")

        api_base_url = st.text_input(
            "API base URL",
            value=_get_default_api_base_url() or "http://127.0.0.1:8000",
            help="Your FastAPI server URL (example: http://127.0.0.1:8000).",
        )
        api_key = st.text_input(
            "API key (`x-api-key`)",
            value=_get_default_api_key(),
            type="password",
            help="Stored in `fastAPI/.env` as `API_KEY=...`.",
        )
        timeout_s = st.slider("API timeout (seconds)", 3, 60, 15)

        st.divider()
        st.subheader("Inference mode")
        mode = st.radio(
            "Use",
            options=["FastAPI (recommended)", "Local model (offline)"],
            index=0,
        )
        fallback_to_local = st.toggle(
            "Fallback to local model if API fails",
            value=True,
        )

        st.divider()
        st.subheader("Local model")
        model_path = st.text_input("Model path", value=str(DEFAULT_MODEL_PATH))
        phishing_class = st.number_input(
            "Phishing class label",
            value=1,
            step=1,
            help="Must match training labels. If your notebook used phishing=0, set this to 0.",
        )

        st.caption("Tip: for Streamlit Cloud, set `API_BASE_URL` + `API_KEY` in Secrets.")

    api_cfg = ApiConfig(base_url=api_base_url, api_key=api_key, timeout_s=float(timeout_s))
    local_cfg = LocalModelConfig(model_path=Path(model_path), phishing_class=int(phishing_class))
    use_api = mode.startswith("FastAPI")

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
                        payload = _predict_one(
                            url=url.strip(),
                            use_api=use_api,
                            api_cfg=api_cfg,
                            local_cfg=local_cfg,
                            fallback_to_local=fallback_to_local,
                        )
                        st.session_state["last_single_payload"] = payload
                    except (ApiError, LocalModelError) as e:
                        st.error(str(e))

        payload = st.session_state.get("last_single_payload")
        if isinstance(payload, dict):
            view = prediction_to_view(payload)
            render_badge(view)
            st.write("")
            render_metrics(view)

            with st.expander("Raw response", expanded=False):
                st.json(payload, expanded=False)

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
            st.caption("Batch runs sequentially to avoid hammering your API.")

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
                        payload = _predict_one(
                            url=u,
                            use_api=use_api,
                            api_cfg=api_cfg,
                            local_cfg=local_cfg,
                            fallback_to_local=fallback_to_local,
                        )
                        results.append(
                            {
                                "url": payload.get("url", u),
                                "prediction": payload.get("prediction"),
                                "phishing_probability": payload.get("phishing_probability"),
                                "confidence": payload.get("confidence"),
                                "source": payload.get("source", "api"),
                                "error": None,
                            }
                        )
                    except (ApiError, LocalModelError) as e:
                        results.append(
                            {
                                "url": u,
                                "prediction": None,
                                "phishing_probability": None,
                                "confidence": None,
                                "source": "api" if use_api else "local_model",
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

                legit = (out["prediction"].astype(str).str.lower() == "legitimate").sum()
                phish = (out["prediction"].astype(str).str.lower() == "phishing").sum()
                errs = out["error"].notna().sum()
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("Legitimate", int(legit))
                with m2:
                    st.metric("Phishing", int(phish))
                with m3:
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

