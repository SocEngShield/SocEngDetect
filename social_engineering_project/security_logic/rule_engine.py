from math import pow
from .signals.urgency import analyze as analyze_urgency
from .signals.authority import analyze as analyze_authority
from .signals.impersonation import analyze as analyze_impersonation
from .signals.reward_lure import analyze as analyze_reward_lure
from .signals.fear_threat import analyze as analyze_fear_threat


def analyze_text(text: str) -> dict:
    """
    Advanced rule-based aggregation engine.
    """

    ACTIVATION_THRESHOLDS = {
        "urgency": 0.2,
        "authority": 0.25,
        "impersonation": 0.4,
        "reward_lure": 0.15,
        "fear_threat": 0.2,
    }

    WEIGHTS = {
        "urgency": 1.0,
        "authority": 1.1,
        "impersonation": 1.4,
        "reward_lure": 0.8,
        "fear_threat": 1.2,
    }

    def strength_tier(score: float) -> str:
        if score >= 0.6:
            return "high"
        elif score >= 0.35:
            return "medium"
        else:
            return "low"

    # -----------------------------
    # Run analyzers
    # -----------------------------
    signal_results = [
        analyze_urgency(text),
        analyze_authority(text),
        analyze_impersonation(text),
        analyze_reward_lure(text),
        analyze_fear_threat(text),
    ]

    per_signal_breakdown = {}
    active_signals = []
    strong_signals = []

    weighted_sum = 0.0

    # -----------------------------
    # Process signals
    # -----------------------------
    for result in signal_results:
        name = result.signal_name
        score = float(result.score)
        confidence = float(result.confidence)
        evidence = result.evidence

        threshold = ACTIVATION_THRESHOLDS.get(name, 0.25)
        is_active = score >= threshold
        strength = strength_tier(score)

        if is_active:
            active_signals.append(name)
            weighted_sum += score * WEIGHTS.get(name, 1.0)

            if strength == "high":
                strong_signals.append(name)

        per_signal_breakdown[name] = {
            "score": round(score, 3),
            "confidence": round(confidence, 3),
            "strength": strength,
            "is_active": is_active,
            "evidence": evidence,
        }

    # -----------------------------
    # Nonlinear Severity Scaling
    # -----------------------------
    weighted_sum = min(weighted_sum, 1.5)
    total_score = 1 - pow((1 - min(weighted_sum, 1.0)), 1.3)
    total_score = round(min(total_score, 1.0), 3)

    # -----------------------------
    # Primary Category
    # -----------------------------
    primary_category = None
    if active_signals:
        primary_category = max(
            [r for r in signal_results if r.signal_name in active_signals],
            key=lambda r: r.score,
        ).signal_name

    # -----------------------------
    # Escalation Logic
    # -----------------------------
    escalated = False

    if "impersonation" in strong_signals and "authority" in strong_signals:
        escalated = True

    if "fear_threat" in strong_signals and "urgency" in strong_signals:
        escalated = True

    if len(strong_signals) >= 3:
        escalated = True

    # -----------------------------
    # Verdict
    # -----------------------------
    if escalated:
        verdict = "critical"
    elif total_score >= 0.75:
        verdict = "high"
    elif total_score >= 0.45:
        verdict = "medium"
    else:
        verdict = "low"

    # -----------------------------
    # Confidence
    # -----------------------------
    if not active_signals:
        rule_confidence = 0.5
    else:
        avg_conf = sum(
            r.confidence for r in signal_results if r.signal_name in active_signals
        ) / len(active_signals)

        signal_factor = min(len(active_signals) / 3, 1.0)

        rule_confidence = (avg_conf * 0.7) + (signal_factor * 0.3)
        rule_confidence = round(min(rule_confidence, 0.95), 3)

    # -----------------------------
    # Evidence
    # -----------------------------
    combined_evidence = []
    for name in active_signals:
        combined_evidence.extend(per_signal_breakdown[name]["evidence"])

    combined_evidence = combined_evidence[:20]

    # -----------------------------
    # RADAR NORMALIZATION (NEW)
    # -----------------------------
    raw_scores = {
        name: per_signal_breakdown[name]["score"]
        for name in per_signal_breakdown
    }

    max_score = max(raw_scores.values()) if raw_scores else 0.0

    radar_data = {}
    for name, score in raw_scores.items():
        if max_score == 0:
            radar_data[name] = 0.0
        else:
            radar_data[name] = round(score / max_score, 3)

    # -----------------------------
    # Final Output
    # -----------------------------
    return {
        "verdict": verdict,
        "total_score": total_score,
        "rule_confidence": rule_confidence,
        "primary_category": primary_category,
        "active_signals": active_signals,
        "strong_signals": strong_signals,
        "per_signal_breakdown": per_signal_breakdown,
        "radar_data": radar_data, 
        "combined_evidence": combined_evidence,
    }