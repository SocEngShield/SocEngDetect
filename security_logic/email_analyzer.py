"""
Email Header Analyzer — Lightweight sender verification for phishing detection.
Analyzes sender email addresses for common spoofing patterns.
No external APIs — fully offline.
"""

import re
from typing import Dict, List, Tuple

# Known trusted domains (for comparison)
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com", "amazon.com", "paypal.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citibank.com", "usbank.com",
    "facebook.com", "meta.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "github.com", "dropbox.com", "adobe.com", "zoom.us",
    "netflix.com", "spotify.com", "fedex.com", "ups.com", "usps.com",
    "dhl.com", "irs.gov", "ssa.gov", "state.gov",
}

# Brand keywords that should match sender domain
BRAND_KEYWORDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com", "hotmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "social security": ["ssa.gov"],
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".info", ".click", ".link", ".work", ".date",
    ".review", ".download", ".bid", ".stream", ".win", ".loan",
    ".racing", ".party", ".science", ".trade", ".webcam", ".gq",
    ".ml", ".cf", ".tk", ".ga", ".pw", ".cc", ".ru", ".cn",
}

# Suspicious patterns in sender email
SUSPICIOUS_SENDER_PATTERNS = [
    re.compile(r"noreply.*[0-9]{3,}", re.IGNORECASE),  # noreply with numbers
    re.compile(r"support.*[0-9]{3,}", re.IGNORECASE),  # support123
    re.compile(r"[a-z]{20,}@", re.IGNORECASE),  # Very long username
    re.compile(r"[0-9]{8,}@"),  # Long number string
    re.compile(r"^[a-z]{2,3}\d{3,}@", re.IGNORECASE),  # ab123@
    re.compile(r"[\.\-_]{3,}"),  # Multiple separators
]

# Typosquatting patterns (common brand misspellings)
TYPOSQUAT_PATTERNS = {
    "paypal": ["paypai", "paypa1", "paypaI", "paypall", "paypa-l", "pay-pal"],
    "google": ["googIe", "g00gle", "gooogle", "goog1e", "go0gle"],
    "microsoft": ["micr0soft", "micosoft", "mircosoft", "microsft"],
    "amazon": ["amaz0n", "arnazon", "amazom", "amazonn", "amazn"],
    "apple": ["app1e", "appIe", "aple", "applle"],
    "netflix": ["netf1ix", "netfIix", "netiflix", "netfliix"],
    "chase": ["chaise", "chas3", "chas-e"],
    "facebook": ["faceb00k", "facebok", "faceboook"],
}


def extract_email_domain(email: str) -> str:
    """Extract domain from email address."""
    if "@" in email:
        return email.split("@")[-1].lower().strip()
    return ""


def extract_display_name(sender: str) -> str:
    """Extract display name from sender field (e.g., 'John Doe <john@example.com>')."""
    if "<" in sender:
        return sender.split("<")[0].strip().strip('"').strip("'")
    return ""


def analyze_sender(sender: str, message_text: str = "") -> Tuple[float, List[str], Dict]:
    """
    Analyze email sender for spoofing indicators.
    
    Args:
        sender: Full sender field (e.g., "PayPal <security@paypal.com>" or just "email@domain.com")
        message_text: Optional message body for brand consistency check
        
    Returns:
        tuple: (suspicion_score 0-1, reasons list, parsed_info dict)
    """
    score = 0.0
    reasons = []
    
    # Parse sender components
    display_name = extract_display_name(sender)
    
    # Extract email from sender field
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender)
    email = email_match.group(0).lower() if email_match else sender.lower()
    
    domain = extract_email_domain(email)
    
    parsed = {
        "display_name": display_name,
        "email": email,
        "domain": domain,
        "trusted": domain in TRUSTED_DOMAINS,
    }
    
    if not domain:
        return 0.0, [], parsed
    
    # Check 1: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 0.3
            reasons.append(f"suspicious TLD: {tld}")
            break
    
    # Check 2: Display name / email mismatch
    if display_name:
        display_lower = display_name.lower()
        for brand, valid_domains in BRAND_KEYWORDS.items():
            if brand in display_lower:
                if not any(vd in domain for vd in valid_domains):
                    score += 0.4
                    reasons.append(f"display name '{display_name}' doesn't match domain '{domain}'")
                break
    
    # Check 3: Typosquatting detection
    for brand, typos in TYPOSQUAT_PATTERNS.items():
        for typo in typos:
            if typo in domain:
                score += 0.5
                reasons.append(f"possible typosquatting: {typo}")
                break
    
    # Check 4: Suspicious sender patterns
    for pattern in SUSPICIOUS_SENDER_PATTERNS:
        if pattern.search(email):
            score += 0.2
            reasons.append("suspicious email pattern")
            break
    
    # Check 5: Brand in message but sender domain mismatch
    if message_text:
        msg_lower = message_text.lower()
        for brand, valid_domains in BRAND_KEYWORDS.items():
            if brand in msg_lower:
                if not any(vd in domain for vd in valid_domains) and domain not in TRUSTED_DOMAINS:
                    score += 0.3
                    reasons.append(f"message mentions '{brand}' but sender is '{domain}'")
                break
    
    # Check 6: Very long domain (subdomain stacking)
    if domain.count(".") >= 3:
        score += 0.2
        reasons.append("excessive subdomain depth")
    
    # Check 7: Numbers in domain name (suspicious)
    if re.search(r'\d{3,}', domain.split(".")[0]):
        score += 0.2
        reasons.append("numbers in domain name")
    
    # Cap score at 1.0
    score = min(score, 1.0)
    
    return score, reasons, parsed


def analyze_email_headers(headers: Dict, message_text: str = "") -> Tuple[float, List[str], Dict]:
    """
    Analyze full email headers for spoofing indicators.
    
    Args:
        headers: Dict with keys like 'from', 'reply-to', 'return-path', etc.
        message_text: Optional message body for consistency check
        
    Returns:
        tuple: (suspicion_score 0-1, reasons list, analysis_dict)
    """
    score = 0.0
    reasons = []
    analysis = {}
    
    sender = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
    
    # Analyze sender
    sender_score, sender_reasons, sender_parsed = analyze_sender(sender, message_text)
    analysis["from"] = sender_parsed
    score += sender_score * 0.6  # 60% weight on sender
    reasons.extend(sender_reasons)
    
    # Check reply-to mismatch
    if reply_to:
        reply_domain = extract_email_domain(reply_to)
        sender_domain = sender_parsed.get("domain", "")
        if reply_domain and sender_domain and reply_domain != sender_domain:
            score += 0.3
            reasons.append(f"reply-to ({reply_domain}) differs from sender ({sender_domain})")
            analysis["reply_to_mismatch"] = True
    
    # Check return-path mismatch
    if return_path:
        return_domain = extract_email_domain(return_path)
        sender_domain = sender_parsed.get("domain", "")
        if return_domain and sender_domain and return_domain != sender_domain:
            score += 0.2
            reasons.append(f"return-path ({return_domain}) differs from sender ({sender_domain})")
            analysis["return_path_mismatch"] = True
    
    score = min(score, 1.0)
    
    return score, reasons, analysis
