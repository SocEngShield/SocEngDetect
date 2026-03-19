import re
from ..base import SignalResult

def analyze(text: str) -> SignalResult:

    if not isinstance(text, str) or not text.strip():
        return SignalResult("reward_lure", 0.0, 0.5, [])

    text_lower = text.lower()
    evidence = []
    score = 0.0

    # -----------------------------
    # CORE REWARD / PRIZE DETECTION
    # -----------------------------
    reward_patterns = [
        r"congratulations",
        r"you(?:'ve| have)\s+been\s+selected",
        r"you\s+(?:are|have\s+been)\s+(?:chosen|selected|picked)",
        r"eligible\s+for\s+(?:a\s+)?reward",
        r"receive\s+(?:a\s+)?(?:reward|prize|gift)",
        r"won\s+(?:a\s+)?(?:prize|reward|gift)",
        r"free\s+(?:gift|reward|offer)",
        r"exclusive\s+offer",
        r"limited\s+offer",

        # standalone reward words (important)
        r"\breward\b",
        r"\bprize\b",
        r"\bgift\b",
    ]

    for pattern in reward_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Reward or selection language detected")
            score += 0.2
            break

    # -----------------------------
    # CLAIM / ACTION FOR REWARD
    # -----------------------------
    claim_patterns = [
        r"claim\s+(?:your|the)?\s*(?:reward|prize|gift)",
        r"click\s+(?:here)?\s*to\s+claim",
        r"redeem\s+(?:your|the)?\s*(?:reward|offer)",
        r"collect\s+(?:your|the)?\s*(?:reward|gift)",

        # NEW generic claim triggers
        r"claim\s+now",
        r"claim\s+today",
    ]

    for pattern in claim_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Claim action required for reward")
            score += 0.2
            break

    # -----------------------------
    # EXPIRY / SCARCITY
    # -----------------------------
    urgency_patterns = [
        r"expires?\s+(?:today|soon|shortly)",
        r"limited\s+time",
        r"before\s+it'?s\s+too\s+late",
    ]

    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            evidence.append("Reward tied to urgency/expiry")
            score += 0.15
            break

    # -----------------------------
    # MULTI-SIGNAL BOOST
    # -----------------------------
    if score >= 0.35:
        score *= 1.15

    score = min(score, 0.75)

    # -----------------------------
    # CONFIDENCE
    # -----------------------------
    if score == 0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.65
    elif score < 0.6:
        confidence = 0.8
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="reward_lure",
        score=round(score, 3),
        confidence=confidence,
        evidence=evidence[:5]
    )