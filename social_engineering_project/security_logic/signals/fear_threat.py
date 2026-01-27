import re
from ..base import SignalResult

def analyze(text: str) -> SignalResult:
    # Handle empty or non-string input
    if not isinstance(text, str) or not text.strip():
        return SignalResult(
            signal_name="fear_threat",
            score=0.0,
            confidence=0.5,
            evidence=[]
        )

    text_lower = text.lower()
    evidence = []
    score = 0.0

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
        r"ban(?:ned)?\s+from\s+(?:the\s+)?(?:platform|service|system)",
    ]

    compliance_threats = [
        r"(?:failure|refusal)\s+to\s+(?:comply|respond|verify|confirm)",
        r"fail(?:ure)?\s+to\s+\w+\s+will\s+result\s+in",
        r"otherwise\s+(?:your|we\s+will)",
    ]

    for patterns, message, increment in [
        (account_threats, "Account compromise or security threat detected", 0.15),
        (legal_threats, "Legal or enforcement threat detected", 0.15),
        (access_threats, "Threat of suspension or loss of access detected", 0.15),
        (compliance_threats, "Threat of consequences for non-compliance detected", 0.10),
    ]:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                evidence.append(message)
                score += increment
                break

    score = min(score, 0.6)

    if score == 0.0:
        confidence = 0.5
    elif score < 0.4:
        confidence = 0.6
    elif score < 0.6:
        confidence = 0.75
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="fear_threat",
        score=round(score, 3),
        confidence=confidence,
        evidence=evidence[:5]
    )
