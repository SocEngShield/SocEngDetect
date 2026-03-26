"""
URL Knowledge Base for Social Engineering Detection.
Pattern-based, lightweight, no external dependencies.
"""

from typing import List, Tuple
import re

# ---------------------------
# TRUSTED DOMAINS
# ---------------------------

TRUSTED_DOMAINS = [
    # Tech giants
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "meta.com",
    # Financial
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    # Productivity
    "github.com",
    "gitlab.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "notion.so",
    # Social
    "twitter.com",
    "x.com",
    "linkedin.com",
    "instagram.com",
    # Media
    "netflix.com",
    "spotify.com",
    "youtube.com",
    # Email
    "outlook.com",
    "live.com",
    "gmail.com",
    "yahoo.com",
]

# ---------------------------
# SUSPICIOUS PATTERNS
# ---------------------------

SUSPICIOUS_TLDS = [
    ".xyz", ".ru", ".tk", ".top", ".buzz",
    ".gq", ".ml", ".cf", ".ga", ".pw",
    ".cc", ".su", ".cn", ".work", ".click",
]

SUSPICIOUS_KEYWORDS = [
    # Auth-related
    "secure-login",
    "verify-account",
    "update-info",
    "confirm-identity",
    "account-verify",
    "signin-secure",
    "login-verify",
    # Action-related
    "click-here",
    "urgent-action",
    "immediate-response",
    # Credential harvesting
    "password-reset",
    "credential-update",
    "security-alert",
]

SENSITIVE_PATH_KEYWORDS = [
    "login", "verify", "secure", "account",
    "confirm", "update", "signin", "auth",
    "password", "credential", "validate",
]

# ---------------------------
# URL SHORTENERS
# ---------------------------

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorte.st",
    "cutt.ly",
    "rebrand.ly",
]

# ---------------------------
# LOOKALIKE PATTERNS
# ---------------------------

LOOKALIKE_PATTERNS = [
    # Number substitutions
    ("paypa1", "paypal"),
    ("amaz0n", "amazon"),
    ("g00gle", "google"),
    ("micr0soft", "microsoft"),
    ("app1e", "apple"),
    ("faceb00k", "facebook"),
    ("netf1ix", "netflix"),
    # Letter substitutions
    ("paypai", "paypal"),
    ("arnazon", "amazon"),
    ("googie", "google"),
    ("rnicrosoft", "microsoft"),
    # Typosquatting
    ("gooogle", "google"),
    ("amazom", "amazon"),
    ("paypaI", "paypal"),
    ("microsfot", "microsoft"),
]

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
    Analyze URL using Knowledge Base patterns.
    Returns (risk_score, list_of_reasons).
    """
    score = 0.0
    reasons = []
    
    # Check each pattern category
    checks = [
        (check_suspicious_tld(url), 0.4),
        (check_shortener(url), 0.2),
        (check_suspicious_keywords(url), 0.2),
        (check_lookalike(url), 0.5),
        (check_ip_address(url), 0.3),
        (check_excessive_subdomains(url), 0.2),
    ]
    
    for (found, reason), weight in checks:
        if found:
            score += weight
            reasons.append(reason)
    
    return min(score, 1.0), reasons
