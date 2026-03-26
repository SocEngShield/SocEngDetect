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
        # Financial compensation patterns
        r'\bcompensation\b',
        r'\bpayout\b',
        r'\bsettlement\b',
        r'\brefund\b',
        r'\breimbursement\b',
        r'\bcredited\s+to\s+your\s+account\b',
        r'\breceive\s+(?:your\s+)?payment\b',
        r'\bfunds\s+will\s+be\s+credited\b',
        r'\beligible\s+for\s+payment\b',
        r'\bmonetary\s+reward\b',
        r'\bcash\s+bonus\b',
        r'\$\d+',
    ]

    evidence = []
    match_count = 0

    for pattern in reward_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            match_count += 1

    if match_count > 0:
        evidence.append("Reward or prize-based language detected")

    score = min(0.25 + (0.05 * match_count), 0.5) if match_count > 0 else 0.0

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
