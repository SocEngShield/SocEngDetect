"""
Rule-based engine for evaluating social engineering threats.
"""


def assess_risk(signal_results: dict) -> dict:
    """Evaluate social engineering threat level based on triggered signals.

    Risk assessment relies on signal count alone (no weights or statistics).
    Higher counts indicate compounding behavioral indicators of manipulation.

    Args:
        signal_results: dict mapping signal names (str) to boolean values.
                       Example: {"urgency": True, "authority_claim": False, ...}

    Returns:
        dict with keys:
            - risk_level (str): "LOW", "MEDIUM", or "HIGH"
            - triggered_signals (list): names of all signals that evaluated to True

    Risk Logic:
        0–1 signals  → LOW risk (isolated indicators are weak)
        2–3 signals  → MEDIUM risk (combination suggests targeted social engineering)
        4+ signals   → HIGH risk (multiple concurrent tactics indicate sophisticated attack)
    """
    if not isinstance(signal_results, dict):
        return {"risk_level": "LOW", "triggered_signals": []}

    # Collect all signals that are explicitly True.
    triggered_signals = [name for name, result in signal_results.items() if result is True]

    # Count and classify by simple threshold.
    signal_count = len(triggered_signals)

    if signal_count <= 1:
        risk_level = "LOW"
    elif signal_count <= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "risk_level": risk_level,
        "triggered_signals": triggered_signals,
    }
