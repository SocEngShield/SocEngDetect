import re
from ..base import SignalResult

def analyze(text: str) -> SignalResult:
    # Handle empty or non-string input
    if not isinstance(text, str) or not text.strip():
        return SignalResult(
            signal_name="reward_lure",
            score=0.0,
            confidence=0.5,
            evidence=[]
        )

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

    # Cap score at 0.75
    score = min(score, 0.75)

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
