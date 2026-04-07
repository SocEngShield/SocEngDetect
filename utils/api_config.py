"""
API Configuration — Optional external API integration.
All API features are DISABLED by default (privacy-first).
Enable via .env file or environment variables.
"""

import os
from pathlib import Path

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
                    value = value.strip()
                    if key and value:
                        os.environ[key] = value
    except Exception:
        pass

# Load on import
_load_env_file()


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable."""
    return os.environ.get(key, default)


def get_virustotal_key() -> str:
    """Get VirusTotal API key."""
    return _get_env("VIRUSTOTAL_API_KEY", "")


def get_abuseipdb_key() -> str:
    """Get AbuseIPDB API key."""
    return _get_env("ABUSEIPDB_API_KEY", "")


def get_safebrowsing_key() -> str:
    """Get Google Safe Browsing API key."""
    return _get_env("GOOGLE_SAFEBROWSING_API_KEY", "")


def get_urlhaus_key() -> str:
    """Get URLhaus API key."""
    return _get_env("URLHAUS_API_KEY", "")


def is_api_enabled() -> bool:
    """Check if API features are enabled (auto-enable if keys present)."""
    explicit = os.environ.get("SOCENG_API_ENABLED", "").lower()
    if explicit == "false":
        return False
    if get_virustotal_key() or get_abuseipdb_key() or get_safebrowsing_key() or get_urlhaus_key():
        return True
    return explicit == "true"


# Legacy compatibility (reads at import time)
API_ENABLED = is_api_enabled()
VIRUSTOTAL_API_KEY = get_virustotal_key()
ABUSEIPDB_API_KEY = get_abuseipdb_key()
GOOGLE_SAFEBROWSING_API_KEY = get_safebrowsing_key()
URLHAUS_API_KEY = get_urlhaus_key()
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY) and API_ENABLED
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY) and API_ENABLED
GOOGLE_SAFEBROWSING_ENABLED = bool(GOOGLE_SAFEBROWSING_API_KEY) and API_ENABLED
URLHAUS_ENABLED = bool(URLHAUS_API_KEY) and API_ENABLED

# Rate limits
VIRUSTOTAL_RATE_LIMIT = 4
ABUSEIPDB_RATE_LIMIT = 15
GOOGLE_RATE_LIMIT = 100
URLHAUS_RATE_LIMIT = 100

# Cache
API_CACHE_ENABLED = True
API_CACHE_TTL_SECONDS = 3600


def get_api_status() -> dict:
    """Get current API configuration status (reads fresh)."""
    vt_key = get_virustotal_key()
    aip_key = get_abuseipdb_key()
    gsb_key = get_safebrowsing_key()
    uh_key = get_urlhaus_key()
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
        "urlhaus": {
            "enabled": bool(uh_key) and enabled,
            "configured": bool(uh_key),
        },
    }
