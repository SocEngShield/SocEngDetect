"""
API Configuration — Optional external API integration.
All API features are DISABLED by default (privacy-first).
Enable via .env file or environment variables.
"""

import os
from pathlib import Path


_KEY_ALIASES = {
    "VIRUSTOTAL_API_KEY": ["VIRUSTOTAL_KEY", "VT_API_KEY"],
    "ABUSEIPDB_API_KEY": ["ABUSEIPDB_KEY"],
    "GOOGLE_SAFEBROWSING_API_KEY": [
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "GOOGLE_SAFEBROWSING_KEY",
        "SAFE_BROWSING_API_KEY",
    ],
    "SOCENG_API_ENABLED": ["API_ENABLED", "EXTERNAL_API_ENABLED"],
}


def _key_candidates(key: str) -> list:
    """Return canonical key and accepted aliases."""
    return [key, *_KEY_ALIASES.get(key, [])]


def _clean_env_value(value: str) -> str:
    """Normalize env values from .env/system sources."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    # Strip one matching quote pair.
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def _clean_dotenv_value(value: str) -> str:
    """Normalize .env values and strip inline comments for unquoted values."""
    raw = str(value).strip()
    if raw and raw[0] not in ('"', "'"):
        # Support values like KEY=value # note
        raw = raw.split(" #", 1)[0].strip()
    return _clean_env_value(raw)


def _env_file_candidates() -> list:
    """Return possible .env locations in priority order."""
    return [
        Path(__file__).resolve().parent.parent / ".env",  # project root via module path
        Path.cwd() / ".env",  # current process working directory
    ]


def _read_env_file_values() -> dict:
    """Read key/value pairs from the first available .env file."""
    seen_paths = set()
    for env_path in _env_file_candidates():
        try:
            resolved = str(env_path.resolve()).lower()
        except Exception:
            resolved = str(env_path).lower()

        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)

        if not env_path.exists():
            continue

        values = {}
        try:
            # utf-8-sig handles BOM safely (common from Windows editors)
            with open(env_path, 'r', encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key, _, value = line.partition('=')
                        key = key.strip()
                        value = _clean_dotenv_value(value)
                        if key:
                            values[key] = value
        except Exception:
            continue

        if values:
            return values

    return {}


def _from_mapping(mapping, key: str):
    """Best-effort mapping lookup across dict-like objects."""
    try:
        if hasattr(mapping, "get"):
            value = mapping.get(key)
            if value is not None:
                return value
    except Exception:
        pass

    try:
        if key in mapping:
            return mapping[key]
    except Exception:
        pass

    return None


def _read_streamlit_secret(key: str) -> str:
    """Read a key from Streamlit Secrets (root or common nested sections)."""
    try:
        import streamlit as st
        secrets = st.secrets
    except Exception:
        return ""

    for candidate in _key_candidates(key):
        root_val = _from_mapping(secrets, candidate)
        cleaned = _clean_env_value(root_val)
        if cleaned:
            return cleaned

    for section_name in ("api", "apis", "keys", "secrets"):
        section = _from_mapping(secrets, section_name)
        if section is None:
            continue
        for candidate in _key_candidates(key):
            nested_val = _from_mapping(section, candidate)
            cleaned = _clean_env_value(nested_val)
            if cleaned:
                return cleaned

    return ""


# Load .env file directly (no dependency on python-dotenv)
def _load_env_file():
    """Load .env file manually without external dependencies."""
    values = _read_env_file_values()
    if not values:
        return
    try:
        for key, value in values.items():
            if key and value:
                os.environ[key] = value
            elif key and key not in os.environ:
                os.environ[key] = ""
    except Exception:
        pass

# Load on import
_load_env_file()


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable."""
    for candidate in _key_candidates(key):
        value = _clean_env_value(os.environ.get(candidate, ""))
        if value:
            return value

    # Fallback to direct .env parsing so UI status remains stable
    # even if process environment became stale.
    values = _read_env_file_values()
    for candidate in _key_candidates(key):
        if candidate in values:
            cleaned = _clean_env_value(values.get(candidate, ""))
            if cleaned:
                return cleaned

    # Deployment fallback: Streamlit Secrets (when .env is unavailable).
    secret_value = _read_streamlit_secret(key)
    if secret_value:
        return secret_value

    return _clean_env_value(default)


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
