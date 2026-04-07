"""
URL Knowledge Base for Social Engineering Detection.
Pattern-based, lightweight, no external dependencies.
Comprehensive offline URL analysis for phishing detection.
"""

from typing import List, Tuple, Dict
import re
from datetime import datetime

# ---------------------------
# TRUSTED DOMAINS
# ---------------------------

TRUSTED_DOMAINS = [
    # Tech giants
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "meta.com", "twitter.com", "x.com",
    # Financial
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "capitalone.com", "americanexpress.com",
    # Productivity
    "github.com", "gitlab.com", "dropbox.com", "slack.com",
    "zoom.us", "notion.so", "atlassian.com", "trello.com",
    # Social
    "linkedin.com", "instagram.com", "reddit.com", "pinterest.com",
    # Media
    "netflix.com", "spotify.com", "youtube.com", "twitch.tv",
    # Email
    "outlook.com", "live.com", "gmail.com", "yahoo.com", "proton.me",
    # E-commerce
    "ebay.com", "walmart.com", "target.com", "bestbuy.com",
    # Government (select)
    "irs.gov", "ssa.gov", "usa.gov",
]

# ---------------------------
# SUSPICIOUS TLDs (expanded)
# ---------------------------

SUSPICIOUS_TLDS = [
    # High-risk free TLDs
    ".xyz", ".tk", ".ml", ".cf", ".ga", ".gq",
    # Known phishing TLDs
    ".top", ".buzz", ".work", ".click", ".link", ".support",
    ".online", ".site", ".website", ".space", ".fun",
    # Country codes often abused
    ".ru", ".cn", ".su", ".pw", ".cc",
    # Newer suspicious TLDs
    ".icu", ".rest", ".monster", ".cyou", ".cfd",
]

# ---------------------------
# SUSPICIOUS URL KEYWORDS
# ---------------------------

SUSPICIOUS_KEYWORDS = [
    # Auth-related compound terms
    "secure-login", "verify-account", "update-info", "confirm-identity",
    "account-verify", "signin-secure", "login-verify", "auth-required",
    # Action urgency
    "click-here", "urgent-action", "immediate-response", "act-now",
    # Credential harvesting
    "password-reset", "credential-update", "security-alert",
    "suspended-account", "locked-account", "unusual-activity",
    # Financial lures
    "claim-reward", "prize-winner", "refund-process", "payment-failed",
]

SENSITIVE_PATH_KEYWORDS = [
    "login", "verify", "secure", "account", "confirm", "update",
    "signin", "auth", "password", "credential", "validate",
    "billing", "payment", "invoice", "refund", "suspend",
]

# ---------------------------
# URL SHORTENERS
# ---------------------------

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly",
    "rebrand.ly", "bl.ink", "short.io", "tiny.cc", "v.gd",
]

# ---------------------------
# LOOKALIKE PATTERNS (expanded)
# ---------------------------

LOOKALIKE_PATTERNS = [
    # Number substitutions
    ("paypa1", "paypal"), ("amaz0n", "amazon"), ("g00gle", "google"),
    ("micr0soft", "microsoft"), ("app1e", "apple"), ("faceb00k", "facebook"),
    ("netf1ix", "netflix"), ("1inkedin", "linkedin"), ("tw1tter", "twitter"),
    ("chasebank1", "chase"), ("we11sfargo", "wellsfargo"),
    # Letter substitutions (rn→m, l→I)
    ("paypai", "paypal"), ("arnazon", "amazon"), ("googie", "google"),
    ("rnicrosoft", "microsoft"), ("faceboook", "facebook"),
    # Typosquatting
    ("gooogle", "google"), ("amazom", "amazon"), ("paypaI", "paypal"),
    ("microsfot", "microsoft"), ("applle", "apple"), ("facebok", "facebook"),
    ("linkdin", "linkedin"), ("netfilx", "netflix"),
    # Homograph attacks (visual similarity)
    ("аpple", "apple"),  # Cyrillic 'a'
    ("gооgle", "google"),  # Cyrillic 'o'
    ("miсrosoft", "microsoft"),  # Cyrillic 'c'
]

# ---------------------------
# BRAND IMPERSONATION PATTERNS
# ---------------------------

BRAND_PATTERNS = {
    "paypal": ["paypal", "paypa1", "paypai", "pay-pal", "paypaI"],
    "amazon": ["amazon", "amaz0n", "arnazon", "amazom", "anazon"],
    "google": ["google", "g00gle", "googie", "gooogle", "goog1e"],
    "microsoft": ["microsoft", "micr0soft", "rnicrosoft", "microsfot"],
    "apple": ["apple", "app1e", "applle", "aple", "аpple"],
    "netflix": ["netflix", "netf1ix", "netfilx", "netfliix"],
    "facebook": ["facebook", "faceb00k", "facebok", "faceboook"],
    "chase": ["chase", "chasebank", "chase-bank", "chaseonline"],
    "wellsfargo": ["wellsfargo", "we11sfargo", "wells-fargo"],
    "bankofamerica": ["bankofamerica", "bofa", "boa-secure"],
}

# ---------------------------
# URL STRUCTURE TRICKS
# ---------------------------

def check_at_symbol(url: str) -> Tuple[bool, str]:
    """Check for @ symbol trick (user:pass@domain)."""
    if '@' in url and '://' in url:
        # Pattern like http://trusted.com@malicious.com
        return True, "URL contains @ symbol (credential trick)"
    return False, ""


def check_double_extension(url: str) -> Tuple[bool, str]:
    """Check for double file extension tricks."""
    patterns = [".pdf.exe", ".doc.exe", ".jpg.exe", ".html.exe", ".pdf.html"]
    for pattern in patterns:
        if pattern in url.lower():
            return True, f"Double extension detected ({pattern})"
    return False, ""


def check_unicode_tricks(url: str) -> Tuple[bool, str]:
    """Check for Unicode/IDN homograph attacks."""
    # Check for non-ASCII characters in domain
    try:
        domain_match = re.search(r"https?://([^/]+)", url)
        if domain_match:
            domain = domain_match.group(1)
            if not domain.isascii():
                return True, "Non-ASCII characters in domain (homograph attack)"
    except:
        pass
    return False, ""


def check_data_uri(url: str) -> Tuple[bool, str]:
    """Check for data URI schemes."""
    if url.lower().startswith("data:"):
        return True, "Data URI detected (potential XSS/phishing)"
    return False, ""


def check_javascript_uri(url: str) -> Tuple[bool, str]:
    """Check for javascript: URI schemes."""
    if "javascript:" in url.lower():
        return True, "JavaScript URI detected"
    return False, ""


def check_port_number(url: str) -> Tuple[bool, str]:
    """Check for unusual port numbers."""
    port_match = re.search(r":(\d+)", url)
    if port_match:
        port = int(port_match.group(1))
        # Normal ports: 80, 443, 8080, 8443
        if port not in [80, 443, 8080, 8443]:
            return True, f"Unusual port number ({port})"
    return False, ""


def check_long_subdomain(url: str) -> Tuple[bool, str]:
    """Check for suspiciously long subdomains."""
    domain_match = re.search(r"https?://([^/]+)", url.lower())
    if domain_match:
        domain = domain_match.group(1)
        parts = domain.split('.')
        for part in parts[:-2]:  # Exclude main domain and TLD
            if len(part) > 20:
                return True, "Unusually long subdomain"
    return False, ""


def check_brand_in_subdomain(url: str) -> Tuple[bool, str]:
    """Check if trusted brand appears in subdomain (not main domain)."""
    domain_match = re.search(r"https?://([^/]+)", url.lower())
    if domain_match:
        full_domain = domain_match.group(1)
        parts = full_domain.split('.')
        
        if len(parts) >= 3:
            subdomain = '.'.join(parts[:-2])
            main_domain = '.'.join(parts[-2:])
            
            for brand, variants in BRAND_PATTERNS.items():
                for variant in variants:
                    if variant in subdomain and variant not in main_domain:
                        return True, f"Brand '{brand}' in subdomain (not main domain)"
    return False, ""

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------

def is_trusted(url: str) -> bool:
    """
    Check if URL belongs to a trusted domain.
    Uses strict matching to avoid false positives.
    """
    url_lower = url.lower()
    
    # Extract domain from URL
    domain_match = re.search(r"https?://([^/]+)", url_lower)
    if not domain_match:
        domain_match = re.search(r"www\.([^/]+)", url_lower)
    
    if not domain_match:
        return False
    
    domain = domain_match.group(1).lstrip("www.")
    
    # Check exact match or subdomain match
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith(f".{trusted}"):
            return True
    
    return False


def check_suspicious_tld(url: str) -> Tuple[bool, str]:
    """Check if URL has a suspicious TLD."""
    url_lower = url.lower()
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            return True, f"Suspicious TLD ({tld})"
    return False, ""


def check_shortener(url: str) -> Tuple[bool, str]:
    """Check if URL is from a shortener service."""
    url_lower = url.lower()
    for shortener in SHORTENERS:
        if shortener in url_lower:
            return True, "Shortened URL"
    return False, ""


def check_suspicious_keywords(url: str) -> Tuple[bool, str]:
    """Check for suspicious keywords in URL."""
    url_lower = url.lower()
    
    # Check compound suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            return True, f"Suspicious pattern ({keyword})"
    
    # Check sensitive path keywords
    for keyword in SENSITIVE_PATH_KEYWORDS:
        if keyword in url_lower:
            return True, "Sensitive keyword in URL"
    
    return False, ""


def check_lookalike(url: str) -> Tuple[bool, str]:
    """Check for lookalike/homograph domain patterns."""
    url_lower = url.lower()
    for fake, real in LOOKALIKE_PATTERNS:
        if fake in url_lower:
            return True, f"Lookalike domain (mimics {real})"
    return False, ""


def check_ip_address(url: str) -> Tuple[bool, str]:
    """Check if URL uses IP address instead of domain."""
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url.lower()):
        return True, "IP address URL"
    return False, ""


def check_excessive_subdomains(url: str) -> Tuple[bool, str]:
    """Check for excessive subdomain nesting."""
    if url.count('.') > 3:
        return True, "Excessive subdomains"
    return False, ""


def analyze_url_kb(url: str) -> Tuple[float, List[str]]:
    """
    Comprehensive URL analysis using Knowledge Base patterns.
    Works entirely offline - no API calls needed.
    Returns (risk_score, list_of_reasons).
    """
    score = 0.0
    reasons = []
    
    # If URL is from trusted domain, reduce suspicion significantly
    if is_trusted(url):
        return 0.0, ["Trusted domain"]
    
    # Check each pattern category with weights
    checks = [
        # High-risk indicators (0.4-0.5)
        (check_lookalike(url), 0.5),
        (check_brand_in_subdomain(url), 0.45),
        (check_at_symbol(url), 0.4),
        (check_suspicious_tld(url), 0.4),
        
        # Medium-risk indicators (0.25-0.35)
        (check_ip_address(url), 0.35),
        (check_double_extension(url), 0.35),
        (check_unicode_tricks(url), 0.35),
        (check_javascript_uri(url), 0.35),
        (check_data_uri(url), 0.3),
        
        # Lower-risk but suspicious (0.15-0.25)
        (check_shortener(url), 0.25),
        (check_suspicious_keywords(url), 0.2),
        (check_excessive_subdomains(url), 0.2),
        (check_port_number(url), 0.2),
        (check_long_subdomain(url), 0.15),
    ]
    
    for (found, reason), weight in checks:
        if found:
            score += weight
            reasons.append(reason)
    
    return min(score, 1.0), reasons


def get_url_risk_summary(url: str) -> Dict:
    """
    Get comprehensive URL risk analysis.
    Returns dict with score, reasons, and recommendation.
    """
    score, reasons = analyze_url_kb(url)
    trusted = is_trusted(url)
    
    if trusted:
        risk_level = "SAFE"
        recommendation = "URL appears to be from a legitimate source"
    elif score >= 0.6:
        risk_level = "HIGH"
        recommendation = "DO NOT click this link - multiple red flags detected"
    elif score >= 0.35:
        risk_level = "POTENTIAL"
        recommendation = "Exercise caution - suspicious indicators present"
    elif score >= 0.15:
        risk_level = "LOW"
        recommendation = "Minor concerns - verify before proceeding"
    else:
        risk_level = "SAFE"
        recommendation = "No significant issues detected"
    
    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "trusted": trusted,
        "reasons": reasons,
        "recommendation": recommendation,
        "checks_performed": len(reasons) if reasons else 0,
    }
