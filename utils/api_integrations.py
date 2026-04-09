"""
External API Integrations — Optional URL/threat intelligence lookups.
All functions return gracefully when APIs are disabled or unavailable.
No data is sent externally without explicit user opt-in.
"""

import time
import hashlib
import base64
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from . import api_config

# Simple in-memory cache
_cache: Dict[str, Tuple[float, dict]] = {}


def _get_cached(key: str) -> Optional[dict]:
    """Get cached result if valid."""
    if not api_config.API_CACHE_ENABLED:
        return None
    if key in _cache:
        timestamp, data = _cache[key]
        if time.time() - timestamp < api_config.API_CACHE_TTL_SECONDS:
            return data
    return None


def _set_cache(key: str, data: dict):
    """Store result in cache."""
    if api_config.API_CACHE_ENABLED:
        _cache[key] = (time.time(), data)


def _get_runtime_api_state() -> Dict[str, object]:
    """Read API status/keys at runtime to avoid stale import-time state."""
    status = api_config.get_api_status()
    return {
        "virustotal_enabled": bool(status.get("virustotal", {}).get("enabled")),
        "abuseipdb_enabled": bool(status.get("abuseipdb", {}).get("enabled")),
        "google_safebrowsing_enabled": bool(status.get("google_safebrowsing", {}).get("enabled")),
        "virustotal_key": api_config.get_virustotal_key(),
        "abuseipdb_key": api_config.get_abuseipdb_key(),
        "google_safebrowsing_key": api_config.get_safebrowsing_key(),
    }


# ---------------------------
# VIRUSTOTAL API
# ---------------------------

def check_url_virustotal(url: str) -> dict:
    """
    Check URL against VirusTotal database.
    
    Returns:
        dict with keys:
            - enabled: bool
            - malicious: bool (if any vendor flagged it)
            - suspicious: bool
            - positives: int (number of vendors flagging)
            - total: int (total vendors)
            - error: str (if any)
    """
    result = {"enabled": False, "source": "virustotal"}
    runtime = _get_runtime_api_state()
    
    if not runtime["virustotal_enabled"] or not REQUESTS_AVAILABLE:
        return result
    
    result["enabled"] = True
    
    # Check cache
    cache_key = f"vt:{hashlib.md5(url.encode()).hexdigest()}"
    cached = _get_cached(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    
    try:
        # VirusTotal URL lookup (requires URL ID)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": runtime["virustotal_key"]}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 404:
            # URL not in database - submit for scan
            result["in_database"] = False
            result["malicious"] = False
            result["positives"] = 0
            _set_cache(cache_key, result)
            return result
        
        if response.status_code != 200:
            result["error"] = f"API error: {response.status_code}"
            return result
        
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        
        result.update({
            "in_database": True,
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "positives": malicious + suspicious,
            "total": total,
            "categories": data.get("data", {}).get("attributes", {}).get("categories", {}),
        })
        
        _set_cache(cache_key, result)
        return result
        
    except requests.Timeout:
        result["error"] = "Request timeout"
        return result
    except requests.RequestException as e:
        result["error"] = str(e)
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        return result


# ---------------------------
# GOOGLE SAFE BROWSING API
# ---------------------------

def check_url_safebrowsing(url: str) -> dict:
    """
    Check URL against Google Safe Browsing.
    
    Returns:
        dict with keys:
            - enabled: bool
            - safe: bool
            - threats: list of threat types found
            - error: str (if any)
    """
    result = {"enabled": False, "source": "google_safebrowsing"}
    runtime = _get_runtime_api_state()
    
    if not runtime["google_safebrowsing_enabled"] or not REQUESTS_AVAILABLE:
        return result
    
    result["enabled"] = True
    
    # Check cache
    cache_key = f"gsb:{hashlib.md5(url.encode()).hexdigest()}"
    cached = _get_cached(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    
    try:
        api_url = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={runtime['google_safebrowsing_key']}"
        )
        
        payload = {
            "client": {
                "clientId": "soceng-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        
        if response.status_code != 200:
            result["error"] = f"API error: {response.status_code}"
            return result
        
        data = response.json()
        matches = data.get("matches", [])
        
        result.update({
            "safe": len(matches) == 0,
            "threats": [m.get("threatType") for m in matches],
        })
        
        _set_cache(cache_key, result)
        return result
        
    except requests.Timeout:
        result["error"] = "Request timeout"
        return result
    except requests.RequestException as e:
        result["error"] = str(e)
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        return result


# ---------------------------
# ABUSEIPDB API
# ---------------------------

def check_ip_abuseipdb(ip: str) -> dict:
    """
    Check IP address against AbuseIPDB.
    
    Returns:
        dict with keys:
            - enabled: bool
            - is_whitelisted: bool
            - abuse_confidence_score: int (0-100)
            - total_reports: int
            - error: str (if any)
    """
    result = {"enabled": False, "source": "abuseipdb"}
    runtime = _get_runtime_api_state()
    
    if not runtime["abuseipdb_enabled"] or not REQUESTS_AVAILABLE:
        return result
    
    result["enabled"] = True
    
    # Check cache
    cache_key = f"aipdb:{ip}"
    cached = _get_cached(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    
    try:
        headers = {
            "Key": runtime["abuseipdb_key"],
            "Accept": "application/json"
        }
        
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers=headers,
            timeout=10
        )
        
        if response.status_code != 200:
            result["error"] = f"API error: {response.status_code}"
            return result
        
        data = response.json().get("data", {})
        
        result.update({
            "is_whitelisted": data.get("isWhitelisted", False),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
        })
        
        _set_cache(cache_key, result)
        return result
        
    except requests.Timeout:
        result["error"] = "Request timeout"
        return result
    except requests.RequestException as e:
        result["error"] = str(e)
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        return result


# ---------------------------
# COMBINED URL CHECK
# ---------------------------

def check_url_external(url: str) -> dict:
    """
    Check URL against all enabled external APIs.
    Aggregates results into a single threat score.
    
    Returns:
        dict with keys:
            - enabled: bool (any API enabled)
            - threat_score: float (0-1)
            - sources: list of source results
            - summary: str
    """
    result = {
        "enabled": False,
        "threat_score": 0.0,
        "sources": [],
        "summary": "No external APIs enabled",
    }
    
    if not REQUESTS_AVAILABLE:
        result["summary"] = "requests library not installed"
        return result

    runtime = _get_runtime_api_state()
    
    threat_signals = 0
    total_sources = 0
    
    # VirusTotal check
    if runtime["virustotal_enabled"]:
        vt_result = check_url_virustotal(url)
        result["sources"].append(vt_result)
        if vt_result.get("enabled"):
            result["enabled"] = True
            total_sources += 1
            if vt_result.get("malicious"):
                threat_signals += 2
            elif vt_result.get("suspicious"):
                threat_signals += 1
    
    # Google Safe Browsing check
    if runtime["google_safebrowsing_enabled"]:
        gsb_result = check_url_safebrowsing(url)
        result["sources"].append(gsb_result)
        if gsb_result.get("enabled"):
            result["enabled"] = True
            total_sources += 1
            if not gsb_result.get("safe", True):
                threat_signals += 2
    
    # Extract IP from URL and check AbuseIPDB
    if runtime["abuseipdb_enabled"]:
        try:
            import socket
            domain = urlparse(url).netloc.split(":")[0]
            ip = socket.gethostbyname(domain)
            aip_result = check_ip_abuseipdb(ip)
            result["sources"].append(aip_result)
            if aip_result.get("enabled"):
                result["enabled"] = True
                total_sources += 1
                score = aip_result.get("abuse_confidence_score", 0)
                if score >= 50:
                    threat_signals += 2
                elif score >= 25:
                    threat_signals += 1
        except:
            pass  # IP lookup failed, skip
    
    # Calculate aggregate threat score
    if total_sources > 0:
        result["threat_score"] = min(1.0, threat_signals / (total_sources * 2))
        
        if result["threat_score"] >= 0.5:
            result["summary"] = "High threat detected by external APIs"
        elif result["threat_score"] >= 0.25:
            result["summary"] = "Moderate threat indicators from external APIs"
        else:
            result["summary"] = "No significant threats detected by external APIs"
    
    return result
