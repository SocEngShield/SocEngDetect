import re
from ..base import SignalResult

def analyze(text: str) -> SignalResult:

    if not isinstance(text, str) or not text.strip():
        return SignalResult("fear_threat", 0.0, 0.5, [])

    text_lower = text.lower()
    evidence = []
    score = 0.0

    # -----------------------------
    # FINANCIAL / TRANSACTION THREATS (NEW FIX)
    # -----------------------------
    financial_threats = [
        r"issue\s+processing\s+(?:your\s+)?transaction",
        r"problem\s+with\s+(?:your\s+)?payment",
        r"payment\s+(?:failed|declined|blocked)",
        r"transaction\s+(?:failed|declined|flagged)",
        r"billing\s+(?:issue|problem|error)",
        r"unusual\s+transaction",
        r"suspicious\s+transaction",
    ]

    for pattern in financial_threats:
        if re.search(pattern, text_lower):
            evidence.append("Financial/transaction threat detected")
            score += 0.2
            break

    # -----------------------------
    # EXISTING DETECTION
    # -----------------------------
    account_threats = [
        r"account\s+(?:has\s+been\s+)?(?:compromised|hacked|breached|suspended)",
        r"unauthorized\s+(?:access|activity|login)",
        r"suspicious\s+(?:activity|login|access)",
        r"security\s+(?:breach|alert|threat)",
    ]

    legal_threats = [
        r"(?:legal|law\s+enforcement|police|court|lawsuit|prosecution)",
        r"(?:illegal|unlawful|violat(?:e|ion)\s+of\s+law)",
        r"criminal\s+(?:charges|liability|action)",
    ]

    access_threats = [
        r"(?:account|service|access)\s+(?:will\s+be\s+)?(?:suspended|terminated|closed|disabled|revoked)",
        r"(?:suspend|terminate|close|disable)\s+(?:your\s+)?(?:account|service|access)",
        r"lose\s+(?:access|your\s+account)",
    ]

    compliance_threats = [
        r"(?:failure|refusal)\s+to\s+(?:comply|respond|verify|confirm)",
        r"fail(?:ure)?\s+to\s+\w+\s+will\s+result\s+in",
    ]

    for patterns, message, increment in [
        (account_threats, "Account threat detected", 0.15),
        (legal_threats, "Legal threat detected", 0.15),
        (access_threats, "Access loss threat detected", 0.15),
        (compliance_threats, "Non-compliance consequences", 0.10),
    ]:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                evidence.append(message)
                score += increment
                break

    score = min(score, 0.7)

    if score == 0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.65
    elif score < 0.6:
        confidence = 0.8
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="fear_threat",
        score=round(score, 3),
        confidence=confidence,
        evidence=evidence[:6]
    )