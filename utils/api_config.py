"""
API Configuration — Optional external API integration.
All API features are DISABLED by default (privacy-first).
Enable via .env file or environment variables.
"""

import os
from pathlib import Path


def _clean_env_value(value: str) -> str:
    """Normalize env values from .env/system sources."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    # Strip one matching quote pair.
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
        cleaned = cleaned[1:-1].strip()
    return cleaned


# Load .env file directly (no dependency on python-dotenv)
def _load_env_file():
    """Load .env file manually without external dependencies."""
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = _clean_env_value(value)
                    if key:
                        os.environ[key] = value
    except Exception:
        pass

# Load on import
_load_env_file()


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable."""
    return _clean_env_value(os.environ.get(key, default))


def get_virustotal_key() -> str:
    """Get VirusTotal API key."""
    return _get_env("VIRUSTOTAL_API_KEY", "")


def get_abuseipdb_key() -> str:
    """Get AbuseIPDB API key."""
    return _get_env("ABUSEIPDB_API_KEY", "")


def get_safebrowsing_key() -> str:
    """Get Google Safe Browsing API key."""
    return _get_env("GOOGLE_SAFEBROWSING_API_KEY", "")


def is_api_enabled() -> bool:
    """Check if API features are enabled (auto-enable if keys present)."""
    explicit = os.environ.get("SOCENG_API_ENABLED", "").lower()
    if explicit == "false":
        return False
    if get_virustotal_key() or get_abuseipdb_key() or get_safebrowsing_key():
        return True
    return explicit == "true"


# Legacy compatibility (reads at import time)
API_ENABLED = is_api_enabled()
VIRUSTOTAL_API_KEY = get_virustotal_key()
ABUSEIPDB_API_KEY = get_abuseipdb_key()
GOOGLE_SAFEBROWSING_API_KEY = get_safebrowsing_key()
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY) and API_ENABLED
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY) and API_ENABLED
GOOGLE_SAFEBROWSING_ENABLED = bool(GOOGLE_SAFEBROWSING_API_KEY) and API_ENABLED

# Rate limits
VIRUSTOTAL_RATE_LIMIT = 4
ABUSEIPDB_RATE_LIMIT = 15
GOOGLE_RATE_LIMIT = 100

# Cache
API_CACHE_ENABLED = True
API_CACHE_TTL_SECONDS = 3600


def get_api_status() -> dict:
    """Get current API configuration status (reloads .env on each call)."""
    # Reload every call so Streamlit reflects .env edits without requiring module reload.
    _load_env_file()

    vt_key = get_virustotal_key()
    aip_key = get_abuseipdb_key()
    gsb_key = get_safebrowsing_key()
    enabled = is_api_enabled()
    
    return {
        "api_enabled": enabled,
        "virustotal": {
            "enabled": bool(vt_key) and enabled,
            "configured": bool(vt_key),
        },
        "abuseipdb": {
            "enabled": bool(aip_key) and enabled,
            "configured": bool(aip_key),
        },
        "google_safebrowsing": {
            "enabled": bool(gsb_key) and enabled,
            "configured": bool(gsb_key),
        },
    }
