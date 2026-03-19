import re
from typing import List
from ..base import SignalResult

def analyze(text: str) -> SignalResult:

    if not text or not isinstance(text, str):
        return SignalResult(signal_name="impersonation", score=0.0, confidence=0.5, evidence=[])

    text_lower = text.lower()
    evidence: List[str] = []
    cue_count = 0

    # -----------------------------
    # Pattern 1: Direct identity assertion
    # -----------------------------
    identity_patterns = [
        r'\bi\s+am\s+(?:a\s+)?(?:your\s+)?(\w+\s+)?(?:manager|admin|support|agent|representative|officer|staff)',
        r'\bthis\s+is\s+(\w+\s+)?(?:from|with)\s+(?:the\s+)?(\w+)',
        r'\bi\s+(?:work\s+)?(?:for|with|am\s+from)\s+(?:the\s+)?(\w+)',
        r'\bthis\s+is\s+your\s+(?:bank|support|team)',
        r'\bwe\s+(?:are\s+)?from\s+(?:your\s+)?(?:bank|company|service)',
    ]

    for pattern in identity_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Direct identity assertion detected")
            cue_count += 1
            break

    # -----------------------------
    # Pattern 2: Role/position claims
    # -----------------------------
    role_patterns = [
        r'\b(?:your|the)\s+(?:manager|supervisor|admin|support|representative|it\s+staff)',
        r'\b(?:acting\s+)?as\s+(?:your\s+)?(?:manager|admin|support|agent|representative)',
        r'\bon\s+behalf\s+of\s+(?:the\s+)?(\w+)',
        r'\b(?:your\s+)?(?:bank|account|service)\s+(?:team|support|department)',
        r'\b(?:security|support|customer)\s+(?:team|department)',
    ]

    for pattern in role_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Role or position impersonation claim detected")
            cue_count += 1
            break

    # -----------------------------
    # Pattern 3: Organization/service claims
    # -----------------------------
    org_patterns = [
        r'\b(?:from|representing|with)\s+(?:the\s+)?(?:company|organization|bank|service|department|team)\b',
        r'\b(?:company|bank|service|organization|department)\s+(?:name|id|account|ticket)[\s:]*[\w\-]+',
        r'\b(?:your\s+)?(?:bank|company|service)\b',
    ]

    for pattern in org_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Organization or service representation claim detected")
            cue_count += 1
            break

    # -----------------------------
    # Pattern 4: Named individual impersonation
    # -----------------------------
    individual_patterns = [
        r'\b(?:i\'m|i\s+am)\s+(\w+)\s+(?:from|with|your)',
        r'\bcall\s+me\s+(\w+)',
    ]

    for pattern in individual_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Named individual impersonation claim detected")
            cue_count += 1
            break

    # -----------------------------
    # SCORING
    # -----------------------------
    score = 0.0
    if cue_count > 0:
        score = 0.3 + (min(cue_count - 1, 2) * 0.05)

    if score == 0.0:
        confidence = 0.5
    elif score < 0.4:
        confidence = 0.6
    elif score < 0.6:
        confidence = 0.75
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="impersonation",
        score=score,
        confidence=confidence,
        evidence=evidence[:5]
    )