import re
from ..base import SignalResult

def analyze(text: str) -> SignalResult:
    if not isinstance(text, str) or not text.strip():
        return SignalResult("fear_threat", 0.0, 0.5, [])

    text_lower = text.lower()
    evidence = []
    score = 0.0

    # -----------------------------
    # CORE DETECTION (implicit threats)
    # -----------------------------
    DETECTION_PATTERNS = [
        r"detected\s+(?:unusual|suspicious)\s+activity",
        r"we\s+detected\s+(?:unusual|suspicious)",
        r"unusual\s+activity\s+on\s+your\s+account",
        r"suspicious\s+activity\s+on\s+your\s+account",

        # real-world phrasing
        r"immediate\s+action\s+required",
        r"your\s+account\s+is\s+at\s+risk",
    ]

    for pattern in DETECTION_PATTERNS:
        if re.search(pattern, text_lower):
            evidence.append("Threat or suspicious activity detected")
            score += 0.2
            break

    # -----------------------------
    # ACCOUNT / SECURITY THREATS
    # -----------------------------
    account_threats = [
        r"account\s+(?:has\s+been\s+)?(?:compromised|hacked|breached|suspended)",
        r"unauthorized\s+(?:access|activity|login)",
        r"suspicious\s+(?:activity|login|access)",
        r"security\s+(?:breach|alert|threat)",
        r"account\s+(?:will\s+be\s+)?(?:locked|restricted|disabled)",
        r"we\s+will\s+(?:suspend|disable|lock)\s+(?:your\s+)?account",
    ]

    # -----------------------------
    # LEGAL THREATS
    # -----------------------------
    legal_threats = [
        r"(?:legal|law\s+enforcement|police|court|lawsuit|prosecution)",
        r"(?:illegal|unlawful|violat(?:e|ion)\s+of\s+law)",
        r"criminal\s+(?:charges|liability|action)",
    ]

    # -----------------------------
    # ACCESS / SERVICE LOSS
    # -----------------------------
    access_threats = [
        r"(?:account|service|access)\s+(?:will\s+be\s+)?(?:suspended|terminated|closed|disabled|revoked)",
        r"(?:suspend|terminate|close|disable)\s+(?:your\s+)?(?:account|service|access)",
        r"lose\s+(?:access|your\s+account)",
        r"ban(?:ned)?\s+from\s+(?:the\s+)?(?:platform|service|system)",
    ]

    # -----------------------------
    # COMPLIANCE THREATS
    # -----------------------------
    compliance_threats = [
        r"(?:failure|refusal)\s+to\s+(?:comply|respond|verify|confirm)",
        r"fail(?:ure)?\s+to\s+\w+\s+will\s+result\s+in",
        r"otherwise\s+(?:your|we\s+will)",
    ]

    for patterns, message, increment in [
        (account_threats, "Account/security threat detected", 0.15),
        (legal_threats, "Legal or enforcement threat detected", 0.15),
        (access_threats, "Loss of access or service threat detected", 0.15),
        (compliance_threats, "Threat of consequences for non-compliance detected", 0.10),
    ]:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                evidence.append(message)
                score += increment
                break

    # -----------------------------
    # FINAL SCORING
    # -----------------------------
    score = min(score, 0.7)

    if score == 0.0:
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