"""
API Configuration — Optional external API integration.
All API features are DISABLED by default (privacy-first).
Enable via environment variables only.
"""

import os

# ---------------------------
# MASTER API TOGGLE
# ---------------------------
# Set SOCENG_API_ENABLED=true in environment to enable API features
API_ENABLED = os.getenv("SOCENG_API_ENABLED", "false").lower() == "true"

# ---------------------------
# VIRUSTOTAL API
# ---------------------------
# Free tier: 4 requests/minute, 500/day
# Get key: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY) and API_ENABLED

# ---------------------------
# ABUSEIPDB API
# ---------------------------
# Free tier: 1000 checks/day
# Get key: https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY) and API_ENABLED

# ---------------------------
# GOOGLE SAFE BROWSING API
# ---------------------------
# Free tier: 10,000 requests/day
# Get key: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
GOOGLE_SAFEBROWSING_API_KEY = os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "")
GOOGLE_SAFEBROWSING_ENABLED = bool(GOOGLE_SAFEBROWSING_API_KEY) and API_ENABLED

# ---------------------------
# RATE LIMITING
# ---------------------------
VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute
ABUSEIPDB_RATE_LIMIT = 15  # requests per minute
GOOGLE_RATE_LIMIT = 100    # requests per minute

# ---------------------------
# CACHE SETTINGS
# ---------------------------
API_CACHE_ENABLED = True
API_CACHE_TTL_SECONDS = 3600  # 1 hour


def get_api_status() -> dict:
    """Get current API configuration status."""
    return {
        "api_enabled": API_ENABLED,
        "virustotal": {
            "enabled": VIRUSTOTAL_ENABLED,
            "configured": bool(VIRUSTOTAL_API_KEY),
        },
        "abuseipdb": {
            "enabled": ABUSEIPDB_ENABLED,
            "configured": bool(ABUSEIPDB_API_KEY),
        },
        "google_safebrowsing": {
            "enabled": GOOGLE_SAFEBROWSING_ENABLED,
            "configured": bool(GOOGLE_SAFEBROWSING_API_KEY),
        },
    }
