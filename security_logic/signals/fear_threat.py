import re
from ..base import SignalResult

# Benign patterns that indicate legitimate notifications
BENIGN_FEAR_PATTERNS = [
    r'\bpassword\s+(?:changed|updated|reset)\s+successfully\b',
    r'\bif\s+you\s+didn\'?t\s+(?:make|request)\s+this\s+change\b',
    r'\b(?:appointment|reservation|booking)\s+(?:is\s+)?confirmed\b',
    r'\bconfirmed\s+for\s+(?:\d{1,2}(?::\d{2})?\s*(?:am|pm)?|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b',
    r'\bthank\s+you\s+for\s+(?:your\s+)?(?:order|purchase|booking|payment)\b',
]

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

    # Check for benign context first
    is_benign_context = any(re.search(p, text_lower) for p in BENIGN_FEAR_PATTERNS)

    account_threats = [
        r"account\s+(?:has\s+been\s+)?(?:compromised|hacked|breached|suspended|frozen|locked)",
        r"unauthorized\s+(?:access|activity|login|transaction)",
        r"suspicious\s+(?:activity|login|access|transaction|sign[\s-]?in)",
        r"security\s+(?:breach|alert|threat|issue|concern)",
        r"(?:detected|noticed|found)\s+(?:unusual|suspicious|unauthorized)\s+(?:activity|access|login)",
        r"your\s+(?:account|data|information)\s+(?:is|may\s+be)\s+(?:at\s+risk|compromised|in\s+danger)",
        r"we\s+(?:detected|noticed|found)\s+(?:a\s+)?(?:problem|issue|concern)",
        r"someone\s+(?:tried|attempted|is\s+trying)\s+to\s+(?:access|log\s*in|hack)",
    ]

    legal_threats = [
        r"(?:legal|law\s+enforcement|police|court|lawsuit|prosecution)\s+(?:action|proceeding)",
        r"(?:illegal|unlawful|violat(?:e|ion)\s+of\s+(?:law|terms|policy))",
        r"criminal\s+(?:charges|liability|action|prosecution)",
        r"(?:authorities|law\s+enforcement)\s+(?:will\s+be\s+)?(?:notified|contacted|involved)",
        r"face\s+(?:legal|criminal|serious)\s+consequences",
    ]

    access_threats = [
        r"(?:account|service|access)\s+(?:will\s+be\s+)?(?:suspended|terminated|closed|disabled|revoked|frozen|locked)",
        r"(?:suspend|terminate|close|disable|freeze|lock)\s+(?:your\s+)?(?:account|service|access)",
        r"lose\s+(?:access|your\s+account|all\s+data)",
        r"ban(?:ned)?\s+from\s+(?:the\s+)?(?:platform|service|system)",
        r"(?:permanent(?:ly)?|immediate(?:ly)?)\s+(?:delete|remove|suspend|disable)",
        r"no\s+longer\s+(?:have\s+)?access",
    ]

    compliance_threats = [
        r"(?:failure|refusal)\s+to\s+(?:comply|respond|verify|confirm|act)",
        r"fail(?:ure)?\s+to\s+\w+\s+will\s+result\s+in",
        r"otherwise\s+(?:your|we\s+will)",
        r"(?:if|unless)\s+(?:you\s+)?(?:don't|do\s+not|fail\s+to)",
        r"(?:must|need\s+to)\s+(?:verify|confirm|update)\s+(?:immediately|now|within)",
    ]

    data_threats = [
        r"(?:data|files?|information|documents?)\s+(?:will\s+be\s+)?(?:deleted|lost|destroyed|encrypted)",
        r"(?:ransom|encrypt(?:ed)?|locked)\s+(?:your\s+)?(?:files?|data|system)",
        r"(?:recovery|restore)\s+(?:is\s+)?(?:not|no\s+longer)\s+possible",
        r"permanent(?:ly)?\s+(?:lose|delete|remove)",
    ]

    financial_threats = [
        r"(?:funds?|money|payment|charges?)\s+(?:will\s+be\s+)?(?:deducted|charged|withdrawn|lost)",
        r"(?:fee|penalty|fine)\s+(?:will\s+be\s+)?(?:applied|charged|assessed)",
        r"(?:fraudulent|unauthorized)\s+(?:transaction|charge|payment)",
        r"(?:your\s+)?(?:bank|card|payment)\s+(?:has\s+been\s+)?(?:flagged|blocked|frozen)",
    ]

    for patterns, message, increment in [
        (account_threats, "Account compromise or security threat detected", 0.18),
        (legal_threats, "Legal or enforcement threat detected", 0.18),
        (access_threats, "Threat of suspension or loss of access detected", 0.18),
        (compliance_threats, "Threat of consequences for non-compliance detected", 0.12),
        (data_threats, "Threat to data or files detected", 0.15),
        (financial_threats, "Financial threat or penalty detected", 0.15),
    ]:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                evidence.append(message)
                score += increment
                break

    # Boost score if multiple threat types detected
    if len(evidence) >= 3:
        score *= 1.2
        evidence.append(f"Multiple threat tactics ({len(evidence)} types)")

    # Suppress score if benign context detected
    if is_benign_context:
        score = min(score, 0.1)
        evidence.append("Benign notification context detected - score suppressed")

    score = min(score, 0.85)

    if score == 0.0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.6
    elif score < 0.5:
        confidence = 0.75
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="fear_threat",
        score=round(score, 3),
        confidence=confidence,
        evidence=evidence[:5]
    )
