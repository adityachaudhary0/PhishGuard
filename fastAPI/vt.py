import os
import base64
import requests
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# -------------------------------------------------------------------
# Load Environment Variables
# -------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

VT_API_KEY = os.getenv("VT_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"


# -------------------------------------------------------------------
# Convert URL -> VirusTotal URL ID
# -------------------------------------------------------------------

def _url_to_id(url: str) -> str:
    """
    VirusTotal expects the URL encoded using URL-safe Base64
    without '=' padding.
    """
    return (
        base64.urlsafe_b64encode(url.encode())
        .decode()
        .strip("=")
    )


# -------------------------------------------------------------------
# VirusTotal Lookup
# -------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """
    Look up a URL in VirusTotal.

    Returns a normalized dictionary that the frontend/backend
    can easily consume.
    """

    if not VT_API_KEY:
        return {
            "available": False,
            "error": "VirusTotal API key not configured."
        }

    url_id = _url_to_id(url)

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.get(
            f"{VT_URL}/{url_id}",
            headers=headers,
            timeout=15
        )

        # URL has never been analyzed
        if response.status_code == 404:
            return {
                "available": False,
                "message": "No VirusTotal report available."
            }

        response.raise_for_status()

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )
        stats = attributes.get("last_analysis_stats", {})
        analysis_timestamp = attributes.get("last_analysis_date")
        analysis_date = (
            datetime.utcfromtimestamp(analysis_timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
            if analysis_timestamp
            else None
        )
        total_engines = sum(stats.values())

        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "failure": stats.get("failure", 0),
            "analysis_date": analysis_date,
            "total_engines": total_engines,
        }

    except requests.exceptions.Timeout:
        return {
            "available": False,
            "error": "VirusTotal request timed out."
        }

    except requests.exceptions.RequestException as e:
        return {
            "available": False,
            "error": str(e)
        }