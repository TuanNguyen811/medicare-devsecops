import os
import secrets
import sys
from pathlib import Path

DAST = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DAST))
# The app package (medicare) for export_routes; tests run with the app's uv environment.
sys.path.insert(0, str(DAST.parent.parent / "app"))

# create_app() needs settings; the engine is lazy, so nothing connects to this database.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://dast:dast@127.0.0.1:1/dast")
os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(32))
