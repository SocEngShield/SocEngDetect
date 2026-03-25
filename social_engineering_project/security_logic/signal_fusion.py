"""
Signal Fusion Module for Social Engineering Detection.

Combines rule-based per-signal scores with ML (RAG) detection
to produce unified signal strength breakdown for visualization.

Bidirectional fusion: When rules and ML agree on a signal,
confidence is boosted (agreement reinforcement).
"""

import copy
from typing import Dict, List


# Activation thresholds (mirrored from rule_engine.py)
ACTIVATION_THRESHOLDS = {
    "urgency": 0.2,
    "authority": 0.25,
    "impersonation": 0.4,
    "reward_lure": 0.15,
    "fear_threat": 0.2,
}

# Valid signal names for fusion
VALID_SIGNALS = frozenset({
    "urgency",
    "authority",
    "impersonation",
    "reward_lure",
    "fear_threat",
})

# Map display category names to internal signal names
DISPLAY_TO_SIGNAL = {
    "Fear/Threat": "fear_threat",
    "Impersonation": "impersonation",
    "Authority": "authority",
    "Urgency": "urgency",
    "Reward/Lure": "reward_lure",
}

# Scaling factors for ML confidence to signal score conversion
# Primary category gets full scaling, secondary gets reduced
PRIMARY_SCALING_FACTOR = 0.9
SECONDARY_SCALING_FACTOR = 0.65

# Agreement boost: when both ML and rules detect the same signal
AGREEMENT_BOOST = 1.15  # 15% boost for agreement
RULE_AGREEMENT_THRESHOLD = 0.25  # Rule score must be >= this to count as "detected"


def _strength_tier(score: float) -> str:
    """Map score to strength tier."""
    if score >= 0.6:
        return "high"
    elif score >= 0.35:
        return "medium"
    return "low"


def fuse_signals(
    rule_output: Dict,
    rag_confidence: float,
    categories: List[str]
) -> Dict:
    """
    Fuse rule-based signals with ML detection (bidirectional).

    Fusion strategy:
    - For each signal: fused_score = max(rule_score, ml_inferred_score)
    - Primary category: ml_inferred_score = (rag_confidence / 100) * 0.9
    - Secondary categories: ml_inferred_score = (rag_confidence / 100) * 0.65
    - Agreement boost: +15% when both ML and rules detect same signal
    - Non-detected categories: ml_inferred_score = 0 (no artificial inflation)

    Args:
        rule_output: Output from rule_engine.analyze_text()
        rag_confidence: RAG detector confidence (0-100)
        categories: List of detected categories in display format (e.g., ["Fear/Threat", "Urgency"])

    Returns:
        Tuple of (fused_output, fusion_metadata)
        - fused_output: Deep copy of rule_output with fused scores
        - fusion_metadata: Dict with fusion details (agreements, boosts, etc.)
    """
    fused_output = copy.deepcopy(rule_output)

    # Track fusion metadata
    fusion_meta = {
        "agreements": [],  # Signals where ML and rules agree
        "ml_only": [],     # Signals boosted by ML only
        "rule_only": [],   # Signals detected by rules only (no ML)
    }

    # Convert display categories to internal signal names with priority
    # First category is primary, rest are secondary
    signal_priorities = {}  # signal_name -> is_primary
    for i, cat in enumerate(categories):
        signal = DISPLAY_TO_SIGNAL.get(cat)
        if signal and signal in VALID_SIGNALS:
            signal_priorities[signal] = (i == 0)  # True if primary

    # Fuse each signal in breakdown
    for signal_name, signal_data in fused_output["per_signal_breakdown"].items():
        original_score = signal_data["score"]
        rule_detected = original_score >= RULE_AGREEMENT_THRESHOLD

        # Compute ML-inferred score based on priority
        ml_inferred = 0.0
        ml_detected = False
        if signal_name in signal_priorities and rag_confidence > 0:
            ml_detected = True
            is_primary = signal_priorities[signal_name]
            scale = PRIMARY_SCALING_FACTOR if is_primary else SECONDARY_SCALING_FACTOR
            ml_inferred = min((rag_confidence / 100.0) * scale, 1.0)

        # Take maximum (core fusion rule)
        fused_score = max(original_score, ml_inferred)

        # Apply agreement boost when both ML and rules detect same signal
        agreement = False
        if ml_detected and rule_detected:
            fused_score = min(fused_score * AGREEMENT_BOOST, 1.0)
            agreement = True
            fusion_meta["agreements"].append(signal_name)
        elif ml_detected and ml_inferred > original_score:
            fusion_meta["ml_only"].append(signal_name)
        elif rule_detected and not ml_detected:
            fusion_meta["rule_only"].append(signal_name)

        # Update all dependent fields
        signal_data["score"] = round(fused_score, 3)
        signal_data["strength"] = _strength_tier(fused_score)

        threshold = ACTIVATION_THRESHOLDS.get(signal_name, 0.25)
        signal_data["is_active"] = fused_score >= threshold

        # Track ML contribution for transparency
        if ml_inferred > original_score or agreement:
            if agreement:
                signal_data["evidence"].append(
                    f"ML + Rule agreement: {signal_name} (boosted)"
                )
            else:
                priority_label = "primary" if signal_priorities.get(signal_name) else "secondary"
                signal_data["evidence"].append(
                    f"ML detection ({priority_label}): {signal_name} @ {rag_confidence:.1f}%"
                )
            signal_data["ml_boosted"] = True
            signal_data["agreement"] = agreement
        else:
            signal_data["ml_boosted"] = False
            signal_data["agreement"] = False

    # Recalculate aggregate fields
    breakdown = fused_output["per_signal_breakdown"]

    fused_output["active_signals"] = [
        name for name, data in breakdown.items() if data["is_active"]
    ]

    fused_output["strong_signals"] = [
        name for name, data in breakdown.items() if data["strength"] == "high"
    ]

    # Add fusion metadata to output
    fused_output["fusion_meta"] = fusion_meta

    return fused_output
