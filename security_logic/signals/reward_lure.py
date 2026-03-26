import re
from ..base import SignalResult

# Benign context patterns - suppress false positives
BENIGN_CONTEXT_PATTERNS = [
    r'\bthank\s+you\s+for\s+(?:being|your)\b',  # "Thank you for being a loyal customer"
    r'\bhappy\s+(?:birthday|anniversary|holidays)\b',  # Greetings
    r'\bcustomer\s+appreciation\b',
    r'\bloyalty\s+(?:program|reward|discount)\b',  # Legitimate loyalty programs
    r'\bstore\s+(?:is\s+)?having\s+a\s+sale\b',  # Store sales
    r'\bvisit\s+(?:us|our\s+store)\b',  # Store invitations
    r'\boffice\s+hours\b',  # Educational context
    r'\bfeel\s+free\s+to\b',  # Casual invitations
    r'\b(?:10|15|20|25)%\s+(?:off|discount)\b',  # Reasonable discount percentages
    r'\bnewsletter\b',  # Newsletter context
    r'\bblog\s+post\b',  # Blog content
    r'\bwebinar\b',  # Educational webinars
]

def analyze(text: str) -> SignalResult:
    # Handle empty or non-string input
    if not isinstance(text, str) or not text.strip():
        return SignalResult(
            signal_name="reward_lure",
            score=0.0,
            confidence=0.5,
            evidence=[]
        )

    text_lower = text.lower()

    # Check for benign context first
    is_benign_context = any(re.search(p, text_lower) for p in BENIGN_CONTEXT_PATTERNS)

    # Category 1: Reward/prize language (+0.2)
    reward_patterns = [
        r'\bprizes?\b',
        r'\bwinnings?\b',
        r'\bbonuses?\b',
        r'\bgift\s+cards?\b',
        r'\bexclusive\s+offers?\b',
        r'\bspecial\s+selection\b',
        r'\bfree\b',
        r'\bdiscounted\b',
        r'\bbenefits?\b',
        r'\brewards?\b',
    ]

    # Category 2: Monetary/financial language (+0.2)
    monetary_patterns = [
        r'\$\d+',
        r'\bcompensation\b',
        r'\bpayout\b',
        r'\bsettlement\b',
        r'\brefund\b',
        r'\breimbursement\b',
        r'\bpayment\b',
        r'\bcash\s+bonus\b',
        r'\bmonetary\b',
        r'\bfunds\b',
    ]

    # Category 3: Claim/action language (+0.15)
    claim_patterns = [
        r'\bclaim\b',
        r'\breceive\s+(?:your\s+)?(?:payment|reward|prize)\b',
        r'\bcredited\s+to\s+your\s+account\b',
        r'\bfunds\s+will\s+be\s+credited\b',
        r'\beligible\s+for\s+(?:payment|reward)\b',
        r'\bcollect\s+(?:your\s+)?(?:reward|prize|winnings)\b',
        r'\bredeem\b',
    ]

    # Category 4: Scam-specific patterns (+0.25) - investment/work-from-home scams
    scam_patterns = [
        r'\bguaranteed\s+(?:\d+%?\s+)?returns?\b',  # "Guaranteed 500% returns"
        r'\b(?:earn|make)\s+\$?\d+[,\d]*(?:k|K)?\s*/?\s*(?:week|month|day)\b',  # "Earn $5000/week"
        r'\bwork(?:ing)?\s+from\s+home\b.*\bno\s+experience\b',  # Work from home scams
        r'\bno\s+experience\s+(?:needed|required)\b',
        r'\bsecret\s+(?:strategy|method|system)\b',  # "Secret Bitcoin strategy"
        r'\b(?:bitcoin|crypto)\s+(?:investment|strategy|opportunity)\b',
        r'\bmade\s+(?:me\s+)?\$?\d+[,\d]*(?:k|K)?\b',  # "Made me $100,000"
        r'\bgovernment\s+(?:stimulus|grant|payment)\b',  # Fake government payments
        r'\bpre[\s-]?approved\s+(?:for\s+)?(?:a\s+)?\$?\d+',  # "Pre-approved for $50,000"
        r'\bbad\s+credit\s+(?:ok|okay|accepted)\b',  # Loan scam indicators
        r'\b(?:lottery|sweepstakes)\s+(?:winner|winning)\b',
        r'\brandomly\s+selected\b',
        r'\b(?:nigerian|foreign)\s+prince\b',
        r'\btransfer(?:ring)?\s+\$?\d+[,\d]*\s*(?:million|m)\b',  # Money transfer scams
        r'\b(?:you\'?ll|you\s+will)\s+receive\s+\d+%\b',  # "You'll receive 30%"
    ]

    # Category 5: Too-good-to-be-true indicators (+0.2)
    tgtbt_patterns = [
        r'\b(?:100|200|300|400|500|1000)\s*%\s+(?:returns?|profit|roi)\b',
        r'\b\$\d{4,}\s+(?:per|a|every)\s+(?:day|week)\b',  # High daily/weekly amounts
        r'\bfree\s+(?:iphone|ipad|macbook|laptop|vacation|trip)\b',
        r'\b(?:million|m)\s+(?:dollar|usd|\$)\b',
        r'\bno\s+(?:risk|obligation|catch)\b',
    ]

    evidence = []
    score = 0.0

    # Check reward patterns
    reward_match = any(re.search(p, text, re.IGNORECASE) for p in reward_patterns)
    if reward_match:
        score += 0.2
        evidence.append("Reward or prize-based language detected")

    # Check monetary patterns
    monetary_match = any(re.search(p, text, re.IGNORECASE) for p in monetary_patterns)
    if monetary_match:
        score += 0.2
        evidence.append("Financial/monetary language detected")

    # Check claim patterns
    claim_match = any(re.search(p, text, re.IGNORECASE) for p in claim_patterns)
    if claim_match:
        score += 0.15
        evidence.append("Claim or redemption language detected")

    # Check scam-specific patterns (high weight)
    scam_match = any(re.search(p, text, re.IGNORECASE) for p in scam_patterns)
    if scam_match:
        score += 0.3
        evidence.append("Scam-specific pattern detected (investment/work-from-home)")

    # Check too-good-to-be-true patterns
    tgtbt_match = any(re.search(p, text, re.IGNORECASE) for p in tgtbt_patterns)
    if tgtbt_match:
        score += 0.25
        evidence.append("Too-good-to-be-true indicator detected")

    # Suppress score if benign context detected and no scam patterns
    if is_benign_context and not scam_match and not tgtbt_match:
        score = min(score, 0.1)  # Cap at low score for benign promotional content
        if evidence:
            evidence.append("Benign promotional context detected - score suppressed")

    # Cap score at 0.85
    score = min(score, 0.85)

    if score == 0.0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.6
    elif score < 0.6:
        confidence = 0.75
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="reward_lure",
        score=round(score, 3),
        confidence=confidence,
        evidence=evidence[:5]
    )
