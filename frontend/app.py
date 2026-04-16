from __future__ import annotations

import sys
from pathlib import Path


# Ensure `frontend/` is importable as the project root for Streamlit.
FRONTEND_DIR = Path(__file__).resolve().parent
if str(FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(FRONTEND_DIR))


from streamlit_app.app import main  # noqa: E402


if __name__ == "__main__":
    main()

