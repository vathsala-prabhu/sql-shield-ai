import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_env_file(path):
    """Load environment variables from a .env file without requiring external packages."""
    if not path.exists():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip())


# Optional .env loader without requiring external library.
# Prefer a real .env file, but also allow a checked-in .env.example template
# to act as a fallback for local/dev environments where the file is not copied.
_load_env_file(BASE_DIR / ".env")
_load_env_file(BASE_DIR / ".env.example")


class Config:
    BASE_DIR = BASE_DIR
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "sql-shield-dev-secret-key-change-in-production")
    DB_PATH = Path(os.environ.get("SHIELD_DB_PATH", str(BASE_DIR / "database" / "shield.db")))
    MODELS_DIR = BASE_DIR / "models"
    DEFAULT_THRESHOLD = float(os.environ.get("SHIELD_THRESHOLD", 0.5))
    ACTIVE_MODEL = os.environ.get("SHIELD_ACTIVE_MODEL", "selected_model")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
    MAX_QUERY_LEN = int(os.environ.get("SHIELD_MAX_QUERY_LEN", 5000))
    DEBUG = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")

config = Config()
