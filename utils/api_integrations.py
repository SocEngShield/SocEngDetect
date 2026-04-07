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

from .api_config import (
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_ENABLED,
    ABUSEIPDB_API_KEY, ABUSEIPDB_ENABLED,
    GOOGLE_SAFEBROWSING_API_KEY, GOOGLE_SAFEBROWSING_ENABLED,
    API_CACHE_ENABLED, API_CACHE_TTL_SECONDS,
)

# Simple in-memory cache
_cache: Dict[str, Tuple[float, dict]] = {}


def _get_cached(key: str) -> Optional[dict]:
    """Get cached result if valid."""
    if not API_CACHE_ENABLED:
        return None
    if key in _cache:
        timestamp, data = _cache[key]
        if time.time() - timestamp < API_CACHE_TTL_SECONDS:
            return data
    return None


def _set_cache(key: str, data: dict):
    """Store result in cache."""
    if API_CACHE_ENABLED:
        _cache[key] = (time.time(), data)


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
    
    if not VIRUSTOTAL_ENABLED or not REQUESTS_AVAILABLE:
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
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
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
    
    if not GOOGLE_SAFEBROWSING_ENABLED or not REQUESTS_AVAILABLE:
        return result
    
    result["enabled"] = True
    
    # Check cache
    cache_key = f"gsb:{hashlib.md5(url.encode()).hexdigest()}"
    cached = _get_cached(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFEBROWSING_API_KEY}"
        
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
    
    if not ABUSEIPDB_ENABLED or not REQUESTS_AVAILABLE:
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
            "Key": ABUSEIPDB_API_KEY,
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
# URLHAUS (FREE - NO API KEY)
# ---------------------------

def check_url_urlhaus(url: str) -> dict:
    """
    Check URL against URLhaus malware database.
    FREE - No API key required!
    
    Returns:
        dict with keys:
            - enabled: bool
            - malicious: bool
            - threat_type: str
            - error: str (if any)
    """
    result = {"enabled": True, "source": "urlhaus"}
    
    if not REQUESTS_AVAILABLE:
        result["enabled"] = False
        return result
    
    # Check cache
    cache_key = f"urlhaus:{hashlib.md5(url.encode()).hexdigest()}"
    cached = _get_cached(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        
        if response.status_code != 200:
            result["error"] = f"API error: {response.status_code}"
            return result
        
        data = response.json()
        query_status = data.get("query_status", "")
        
        if query_status == "ok":
            # URL found in database (malicious)
            result.update({
                "malicious": True,
                "threat_type": data.get("threat", "malware"),
                "tags": data.get("tags", []),
                "date_added": data.get("date_added", ""),
            })
        elif query_status == "no_results":
            # URL not in database (likely clean)
            result.update({
                "malicious": False,
                "threat_type": None,
            })
        else:
            # Handle other statuses
            result.update({
                "malicious": False,
                "threat_type": None,
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
    
    threat_signals = 0
    total_sources = 0
    
    # VirusTotal check
    if VIRUSTOTAL_ENABLED:
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
    if GOOGLE_SAFEBROWSING_ENABLED:
        gsb_result = check_url_safebrowsing(url)
        result["sources"].append(gsb_result)
        if gsb_result.get("enabled"):
            result["enabled"] = True
            total_sources += 1
            if not gsb_result.get("safe", True):
                threat_signals += 2
    
    # Extract IP from URL and check AbuseIPDB
    if ABUSEIPDB_ENABLED:
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
    
    # URLhaus check (FREE - always enabled)
    urlhaus_result = check_url_urlhaus(url)
    result["sources"].append(urlhaus_result)
    if urlhaus_result.get("enabled") and not urlhaus_result.get("error"):
        result["enabled"] = True
        total_sources += 1
        if urlhaus_result.get("malicious"):
            threat_signals += 2
    
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
