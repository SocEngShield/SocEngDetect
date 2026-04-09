"""
API Configuration — Optional external API integration.
All API features are DISABLED by default (privacy-first).
Enable via .env file or environment variables.
"""

import os
import re
from pathlib import Path

try:
    import tomllib
except Exception:
    tomllib = None


_KEY_ALIASES = {
    "VIRUSTOTAL_API_KEY": ["VIRUSTOTAL_KEY", "VT_API_KEY", "VIRUSTOTAL", "VT_KEY"],
    "ABUSEIPDB_API_KEY": ["ABUSEIPDB_KEY", "ABUSEIPDB"],
    "GOOGLE_SAFEBROWSING_API_KEY": [
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "GOOGLE_SAFEBROWSING_KEY",
        "SAFE_BROWSING_API_KEY",
        "GOOGLE_SAFEBROWSING",
        "GOOGLE_SAFE_BROWSING",
        "SAFE_BROWSING",
    ],
    "SOCENG_API_ENABLED": ["API_ENABLED", "EXTERNAL_API_ENABLED"],
}


def _key_candidates(key: str) -> list:
    """Return canonical key and accepted aliases."""
    return [key, *_KEY_ALIASES.get(key, [])]


def _normalize_key(name: str) -> str:
    """Normalize key strings for case-insensitive alias matching."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


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


def _secrets_file_candidates() -> list:
    """Return possible Streamlit secrets.toml locations."""
    return [
        Path(__file__).resolve().parent.parent / ".streamlit" / "secrets.toml",
        Path.cwd() / ".streamlit" / "secrets.toml",
        Path.home() / ".streamlit" / "secrets.toml",
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


def _iter_mapping_scalars(mapping, prefix: str = "", depth: int = 0):
    """Yield scalar key/value pairs from nested mapping-like objects."""
    if depth > 5 or mapping is None:
        return

    try:
        items = mapping.items()
    except Exception:
        return

    for key, value in items:
        key_str = str(key)
        full_key = f"{prefix}.{key_str}" if prefix else key_str
        if isinstance(value, (str, int, float, bool)):
            # Yield both full path and leaf key to support nested secret schemas.
            yield full_key, value
            if full_key != key_str:
                yield key_str, value
        elif value is not None:
            yield from _iter_mapping_scalars(value, full_key, depth + 1)


def _resolve_value_from_mapping(mapping, key: str) -> str:
    """Resolve value from mapping using exact and normalized key matching."""
    if mapping is None:
        return ""

    # Exact lookup on canonical + aliases.
    for candidate in _key_candidates(key):
        value = _from_mapping(mapping, candidate)
        cleaned = _clean_env_value(value)
        if cleaned:
            return cleaned

    # Case-insensitive / punctuation-insensitive lookup.
    normalized_targets = {_normalize_key(c) for c in _key_candidates(key)}
    for found_key, value in _iter_mapping_scalars(mapping):
        if _normalize_key(found_key) in normalized_targets:
            cleaned = _clean_env_value(value)
            if cleaned:
                return cleaned

    return ""


def _read_streamlit_secret(key: str) -> str:
    """Read a key from Streamlit Secrets (root or common nested sections)."""
    try:
        import streamlit as st
        secrets = st.secrets
    except Exception:
        return ""

    root_value = _resolve_value_from_mapping(secrets, key)
    if root_value:
        return root_value

    for section_name in ("api", "apis", "keys", "secrets"):
        section = _from_mapping(secrets, section_name)
        if section is None:
            continue
        nested_value = _resolve_value_from_mapping(section, key)
        if nested_value:
            return nested_value

    return ""


def _read_streamlit_secrets_toml(key: str) -> str:
    """Read key from local/deployed Streamlit secrets.toml when available."""
    if tomllib is None:
        return ""

    seen_paths = set()
    for path in _secrets_file_candidates():
        try:
            resolved = str(path.resolve()).lower()
        except Exception:
            resolved = str(path).lower()

        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)

        if not path.exists():
            continue

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            continue

        value = _resolve_value_from_mapping(data, key)
        if value:
            return value

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
    file_value = _resolve_value_from_mapping(values, key)
    if file_value:
        return file_value

    # Deployment fallback: Streamlit Secrets (when .env is unavailable).
    secret_value = _read_streamlit_secret(key)
    if secret_value:
        return secret_value

    # Additional fallback for secrets.toml-based deployments.
    toml_secret_value = _read_streamlit_secrets_toml(key)
    if toml_secret_value:
        return toml_secret_value

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
