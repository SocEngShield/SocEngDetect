from .signals.urgency import analyze as analyze_urgency
from .signals.authority import analyze as analyze_authority
from .signals.impersonation import analyze as analyze_impersonation
from .signals.reward_lure import analyze as analyze_reward_lure
from .signals.fear_threat import analyze as analyze_fear_threat


def analyze_text(text: str) -> dict:
    """
    Run all signal analyzers and apply aggregation rules for social engineering detection.

    Returns:
        {
            verdict: str,
            total_score: float,
            active_signals: list[str],
            strong_signals: list[str],
            per_signal_breakdown: dict,
            combined_evidence: list[str]
        }
    """

    # --- Activation thresholds (calibrated to actual signal behavior) ---
    ACTIVATION_THRESHOLDS = {
        "urgency": 0.2,
        "authority": 0.25,
        "impersonation": 0.4,   # intentionally higher to prevent dominance
        "reward_lure": 0.15,
        "fear_threat": 0.2,
    }

    def strength_tier(score: float) -> str:
        """Convert score to qualitative strength."""
        if score >= 0.6:
            return "high"
        elif score >= 0.35:
            return "medium"
        else:
            return "low"

    # --- Run all signal analyzers ---
    signal_results = [
        analyze_urgency(text),
        analyze_authority(text),
        analyze_impersonation(text),
        analyze_reward_lure(text),
        analyze_fear_threat(text),
    ]

    active_signals = []
    strong_signals = []
    per_signal_breakdown = {}

    # --- Process signals ---
    for result in signal_results:
        name = result.signal_name
        score = result.score
        confidence = result.confidence
        evidence = result.evidence

        threshold = ACTIVATION_THRESHOLDS.get(name, 0.25)
        is_active = score >= threshold
        strength = strength_tier(score)

        if is_active:
            active_signals.append(name)
            if strength == "high":
                strong_signals.append(name)

        per_signal_breakdown[name] = {
            "score": round(score, 3),
            "confidence": round(confidence, 3),
            "strength": strength,
            "is_active": is_active,
            "evidence": evidence,
        }

    # --- Aggregate total score (bounded) ---
    total_score = min(sum(r.score for r in signal_results), 1.0)

    # --- Escalation logic (pressure-based, not naive counting) ---
    escalated = False

    # Identity pressure
    if "impersonation" in strong_signals and "authority" in strong_signals:
        escalated = True

    # Time + fear pressure
    if "fear_threat" in strong_signals and "urgency" in strong_signals:
        escalated = True

    # Multiple strong signals
    if len(strong_signals) >= 3:
        escalated = True

    # --- Verdict determination ---
    if escalated:
        verdict = "critical"
    elif total_score >= 0.7:
        verdict = "high"
    elif total_score >= 0.4:
        verdict = "medium"
    else:
        verdict = "low"

    # --- Evidence aggregation (only from active signals) ---
    combined_evidence = []
    for name in active_signals:
        combined_evidence.extend(per_signal_breakdown[name]["evidence"])

    combined_evidence = combined_evidence[:20]

    return {
        "verdict": verdict,
        "total_score": round(total_score, 3),
        "active_signals": active_signals,
        "strong_signals": strong_signals,
        "per_signal_breakdown": per_signal_breakdown,
        "combined_evidence": combined_evidence,
    }
