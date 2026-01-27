from .signals.urgency import analyze as analyze_urgency
from .signals.authority import analyze as analyze_authority
from .signals.impersonation import analyze as analyze_impersonation
from .signals.reward_lure import analyze as analyze_reward_lure
from .signals.fear_threat import analyze as analyze_fear_threat


def analyze_text(text: str) -> dict:
    """
    Run all signal analyzers and apply aggregation rules for social engineering detection.
    
    Args:
        text: Input text to analyze
        
    Returns:
        Dictionary with verdict, score, active signals, and evidence
    """
    
    # Run all signal analyzers
    signal_results = [
        analyze_urgency(text),
        analyze_authority(text),
        analyze_impersonation(text),
        analyze_reward_lure(text),
        analyze_fear_threat(text),
    ]
    
    # Compute active signals and total score
    active_signals = [
        result.signal_name
        for result in signal_results
        if result.score > 0
    ]
    
    total_score = min(sum(result.score for result in signal_results), 1.0)
    
    # Extract signal-specific results for easy lookup
    signal_map = {result.signal_name: result for result in signal_results}
    
    # Apply escalation rules
    escalated = False
    
    # Rule 1: Impersonation + Authority
    if "impersonation" in active_signals and "authority" in active_signals:
        escalated = True
    
    # Rule 2: Fear/Threat + Urgency
    if "fear_threat" in active_signals and "urgency" in active_signals:
        escalated = True
    
    # Rule 3: 3+ active signals
    if len(active_signals) >= 3:
        escalated = True
    
    # Determine verdict
    if escalated:
        verdict = "critical"
    elif total_score >= 0.7:
        verdict = "high"
    elif total_score >= 0.4:
        verdict = "medium"
    else:
        verdict = "low"
    
    # Collect combined evidence (capped at 20 items)
    combined_evidence = []
    for result in signal_results:
        combined_evidence.extend(result.evidence)
    combined_evidence = combined_evidence[:20]
    
    return {
        "verdict": verdict,
        "total_score": total_score,
        "active_signals": active_signals,
        "per_signal_results": signal_results,
        "combined_evidence": combined_evidence,
    }
