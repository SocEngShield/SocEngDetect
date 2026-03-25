import re
from typing import List
from ..base import SignalResult

# Known company/service names commonly impersonated
KNOWN_COMPANIES = [
    r'microsoft', r'apple', r'google', r'amazon', r'paypal', r'netflix',
    r'facebook', r'instagram', r'whatsapp', r'linkedin', r'twitter',
    r'chase', r'wells\s*fargo', r'bank\s*of\s*america', r'citibank',
    r'usps', r'fedex', r'ups', r'dhl',
    r'irs', r'ssa', r'social\s*security',
    r'norton', r'mcafee', r'geek\s*squad',
]

# Government/official entities
OFFICIAL_ENTITIES = [
    r'(?:irs|internal\s+revenue\s+service)',
    r'(?:ssa|social\s+security\s+administration)',
    r'(?:fbi|federal\s+bureau)',
    r'(?:dhs|homeland\s+security)',
    r'(?:dmv|department\s+of\s+motor\s+vehicles)',
    r'(?:state|federal|government)\s+(?:agency|department|office)',
    r'(?:police|sheriff|law\s+enforcement)',
    r'(?:tax|revenue)\s+(?:agency|authority|department)',
]


def analyze(text: str) -> SignalResult:
    """
    Detect identity impersonation claims in text.

    Identifies attempts to assume a false identity such as:
    - Pretending to be a known individual (colleague, manager, support agent)
    - Pretending to represent an organization or service
    - Impersonating known companies (Microsoft, Apple, banks, etc.)
    - Government/official entity impersonation

    Args:
        text: The input text to analyze

    Returns:
        SignalResult with impersonation detection findings
    """
    if not text or not isinstance(text, str):
        return SignalResult(signal_name="impersonation", score=0.0, confidence=0.5, evidence=[])

    text_lower = text.lower()
    evidence: List[str] = []
    score = 0.0

    # Pattern 1: Direct identity assertion ("I am", "this is", "I'm from")
    identity_patterns = [
        r'\bi\s+am\s+(?:a\s+)?(?:your\s+)?(\w+\s+)?(?:manager|admin|support|agent|representative|officer|staff|technician)',
        r'\bthis\s+is\s+(\w+\s+)?(?:from|with)\s+(?:the\s+)?(\w+)',
        r'\bi\s+(?:work\s+)?(?:for|with|am\s+from)\s+(?:the\s+)?(\w+)',
        r'\bcalling\s+(?:from|on\s+behalf\s+of)',
        r'\bcontacting\s+you\s+(?:from|regarding)',
    ]

    for pattern in identity_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Direct identity assertion detected")
            score += 0.2
            break

    # Pattern 2: Known company impersonation
    company_pattern = r'\b(?:' + '|'.join(KNOWN_COMPANIES) + r')\b'
    company_context_patterns = [
        company_pattern + r'\s+(?:support|security|team|account|service|customer\s+service)',
        r'(?:from|with|at)\s+' + company_pattern,
        company_pattern + r'\s+(?:has|detected|noticed|found)',
        r'(?:your\s+)?' + company_pattern + r'\s+account',
    ]

    for pattern in company_context_patterns:
        if re.search(pattern, text_lower):
            # Find which company was mentioned
            company_match = re.search(company_pattern, text_lower)
            if company_match:
                evidence.append(f"Known company impersonation: {company_match.group()}")
                score += 0.25
                break

    # Pattern 3: Official/government entity impersonation
    for pattern in OFFICIAL_ENTITIES:
        if re.search(pattern, text_lower):
            evidence.append("Government or official entity impersonation detected")
            score += 0.3
            break

    # Pattern 4: Role/position claims ("I'm your", "acting as", "behalf of")
    role_patterns = [
        r'\b(?:your|the)\s+(?:manager|supervisor|admin|support|representative|it\s+staff|technician)',
        r'\b(?:acting\s+)?as\s+(?:your\s+)?(?:manager|admin|support|agent|representative)',
        r'\bon\s+behalf\s+of\s+(?:the\s+)?(\w+)',
        r'\bauthorized\s+(?:by|representative|agent)',
    ]

    for pattern in role_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Role or position impersonation claim detected")
            score += 0.15
            break

    # Pattern 5: Tech support scam patterns
    tech_support_patterns = [
        r'(?:your\s+)?(?:computer|device|system)\s+(?:has\s+been\s+)?(?:infected|hacked|compromised)',
        r'(?:virus|malware|threat)\s+(?:detected|found|alert)',
        r'call\s+(?:this\s+number|us|immediately)\s+(?:to|for)\s+(?:fix|resolve|help)',
        r'(?:tech|technical)\s+support\s+(?:team|specialist|expert)',
        r'remote\s+(?:access|connection|session)',
    ]

    for pattern in tech_support_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Tech support scam pattern detected")
            score += 0.2
            break

    # Pattern 6: Delivery/shipping impersonation
    delivery_patterns = [
        r'(?:package|parcel|shipment|delivery)\s+(?:could\s+not\s+be|failed|pending|waiting)',
        r'(?:reschedule|confirm)\s+(?:your\s+)?(?:delivery|shipment)',
        r'(?:tracking|reference)\s+(?:number|id)[\s:]+[\w\-]+',
        r'(?:customs|import)\s+(?:fee|duty|charge)',
    ]

    for pattern in delivery_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Delivery service impersonation pattern detected")
            score += 0.15
            break

    # Boost score if multiple impersonation types detected
    if len(evidence) >= 3:
        score *= 1.2
        evidence.append(f"Multiple impersonation tactics ({len(evidence)} types)")

    score = min(score, 0.85)

    # Bucketed confidence logic based on score
    if score == 0.0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.6
    elif score < 0.5:
        confidence = 0.75
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="impersonation",
        score=round(score, 3),
        confidence=confidence,
        evidence=evidence[:5]
    )