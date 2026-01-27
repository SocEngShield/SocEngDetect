import re
from typing import List, Tuple
from ..base import SignalResult

# Phrase-based patterns for urgency detection
DEADLINE_PATTERNS = [
    r'\b(?:expires?|expiring)\s+(?:in\s+)?\d+\s*(?:hours?|minutes?|days?|hrs?|mins?)\b',
    r'\b(?:only|just)\s+\d+\s*(?:hours?|minutes?|days?|hrs?|mins?)\s+(?:left|remaining)\b',
    r'\bdeadline\s+(?:is\s+)?(?:today|tomorrow|tonight|now)\b',
    r'\b(?:by|before)\s+(?:end\s+of\s+)?(?:today|tomorrow|tonight|business\s+day)\b',
    r'\b(?:within|in)\s+(?:the\s+)?(?:next\s+)?\d+\s*(?:hours?|minutes?|days?)\b',
    r'\blast\s+(?:chance|opportunity|day|warning)\b',
    r'\bfinal\s+(?:notice|warning|reminder|deadline)\b',
    r'\btime\s+(?:is\s+)?running\s+out\b',
    r'\bclock\s+is\s+ticking\b',
    r'\b(?:offer|deal|discount)\s+(?:expires?|ends?)\s+(?:soon|today|tonight|tomorrow)\b',
]

IMMEDIACY_PATTERNS = [
    r'\b(?:act|respond|reply|call|click)\s+(?:now|immediately|right\s+away|asap|today)\b',
    r'\bimmediately\s+(?:contact|call|respond|verify|confirm)\b',
    r'\burgent(?:ly)?\s+(?:need|require|request|action)\b',
    r'\b(?:don\'?t|do\s+not)\s+(?:wait|delay|hesitate)\b',
    r'\bas\s+soon\s+as\s+possible\b',
    r'\bright\s+(?:now|away)\b',
    r'\bwithout\s+(?:delay|hesitation)\b',
    r'\btime[\s-]?sensitive\b',
    r'\brequires?\s+immediate\s+(?:attention|action|response)\b',
    r'\b(?:must|need\s+to)\s+(?:act|respond|verify|confirm)\s+(?:now|immediately|today)\b',
]

TIME_PRESSURE_PATTERNS = [
    r'\b(?:limited[\s-]?time)\s+(?:offer|only|deal)\b',
    r'\bwhile\s+(?:supplies|stocks?|seats?|spots?)\s+last\b',
    r'\b(?:hurry|quick|rush)\b.*\b(?:before|limited|running\s+out)\b',
    r'\b(?:only|just)\s+\d+\s*(?:left|remaining|available)\b',
    r'\bbefore\s+(?:it\'?s?\s+)?too\s+late\b',
    r'\b(?:miss|lose)\s+(?:out|this|your)\b',
    r'\bwon\'?t\s+(?:last|wait|be\s+available)\b',
    r'\b(?:today|now)\s+only\b',
    r'\bone[\s-]?time\s+(?:offer|opportunity|chance)\b',
    r'\b(?:slots?|seats?|spots?)\s+(?:are\s+)?(?:filling|limited)\b',
]

ACTION_REQUEST_PATTERNS = [
    r'\b(?:click|tap)\s+(?:here|below|the\s+link|this\s+button)\b',
    r'\b(?:call|contact)\s+(?:us|this\s+number|immediately)\b',
    r'\bverify\s+(?:your|account|identity|now)\b',
    r'\bconfirm\s+(?:your|account|details|identity)\b',
    r'\b(?:update|provide)\s+(?:your|account)\s+(?:information|details|credentials)\b',
    r'\blog\s*in\s+(?:now|immediately|here)\b',
    r'\b(?:enter|submit)\s+(?:your|the)\s+(?:password|credentials|details)\b',
    r'\btake\s+action\s+(?:now|immediately|today)\b',
]

URGENCY_KEYWORDS_IN_CONTEXT = [
    r'\burgent\b',
    r'\bemergency\b',
    r'\bcritical\b',
    r'\bimportant\s*[!:]\b',
    r'\balert\s*[!:]\b',
    r'\bwarning\s*[!:]\b',
    r'\battention\s+required\b',
    r'\baction\s+required\b',
    r'\bimmediate\s+action\b',
]


def _find_matches(text: str, patterns: List[str]) -> List[str]:
    """Find all matches for a list of patterns in the text."""
    matches = []
    for pattern in patterns:
        found = re.findall(pattern, text, re.IGNORECASE)
        matches.extend(found)
    return matches


def _count_exclamation_urgency(text: str) -> Tuple[int, List[str]]:
    """Detect urgency emphasized with exclamation marks."""
    evidence = []
    # Look for repeated exclamation marks or urgency words followed by exclamation
    urgent_exclaim_pattern = r'\b(?:urgent|now|hurry|quick|fast|immediately|asap|warning|alert|important)[!]{1,3}'
    matches = re.findall(urgent_exclaim_pattern, text, re.IGNORECASE)
    if matches:
        evidence.extend(matches)
    
    # Multiple exclamation marks in short text suggest urgency
    multi_exclaim = re.findall(r'[!]{2,}', text)
    if multi_exclaim:
        evidence.append(f"Multiple exclamation marks ({len(multi_exclaim)} instances)")
    
    return len(matches) + len(multi_exclaim), evidence


def _has_caps_urgency(text: str) -> Tuple[bool, List[str]]:
    """Detect urgency words in ALL CAPS."""
    evidence = []
    caps_urgency_pattern = r'\b(URGENT|NOW|IMMEDIATELY|ASAP|WARNING|ALERT|CRITICAL|EMERGENCY|ACT NOW|HURRY|LIMITED TIME)\b'
    matches = re.findall(caps_urgency_pattern, text)
    if matches:
        evidence = [f"CAPS emphasis: {match}" for match in matches]
    return bool(matches), evidence


def analyze(text: str) -> SignalResult:
    """
    Detect urgency-based social engineering signals in text.
    
    Args:
        text: The text to analyze
        
    Returns:
        SignalResult with urgency detection results
    """
    if not text or not isinstance(text, str):
        return SignalResult(
            signal_name="urgency",
            score=0.0,
            confidence=0.5,
            evidence=[]
        )
    
    text = text.strip()
    if not text:
        return SignalResult(
            signal_name="urgency",
            score=0.0,
            confidence=0.5,
            evidence=[]
        )
    
    evidence = []
    category_scores = {}
    
    # Check deadline patterns
    deadline_matches = _find_matches(text, DEADLINE_PATTERNS)
    if deadline_matches:
        evidence.extend([f"Deadline language: {m}" for m in deadline_matches[:5]])
        category_scores['deadline'] = min(len(deadline_matches) * 0.15, 0.3)
    
    # Check immediacy patterns
    immediacy_matches = _find_matches(text, IMMEDIACY_PATTERNS)
    if immediacy_matches:
        evidence.extend([f"Immediacy marker: {m}" for m in immediacy_matches[:5]])
        category_scores['immediacy'] = min(len(immediacy_matches) * 0.15, 0.3)
    
    # Check time pressure patterns
    pressure_matches = _find_matches(text, TIME_PRESSURE_PATTERNS)
    if pressure_matches:
        evidence.extend([f"Time pressure: {m}" for m in pressure_matches[:5]])
        category_scores['time_pressure'] = min(len(pressure_matches) * 0.12, 0.25)
    
    # Check action request patterns (amplifies urgency when combined with above)
    action_matches = _find_matches(text, ACTION_REQUEST_PATTERNS)
    if action_matches:
        evidence.extend([f"Action request: {m}" for m in action_matches[:5]])
        category_scores['action_request'] = min(len(action_matches) * 0.1, 0.2)
    
    # Check contextual urgency keywords
    keyword_matches = _find_matches(text, URGENCY_KEYWORDS_IN_CONTEXT)
    if keyword_matches:
        evidence.extend([f"Urgency keyword: {m}" for m in keyword_matches[:3]])
        category_scores['keywords'] = min(len(keyword_matches) * 0.08, 0.15)
    
    # Check exclamation-based urgency
    exclaim_count, exclaim_evidence = _count_exclamation_urgency(text)
    if exclaim_evidence:
        evidence.append(exclaim_evidence[0])  # Cap to single item
        category_scores['exclamation'] = min(exclaim_count * 0.05, 0.1)
    
    # Check CAPS-based urgency
    has_caps, caps_evidence = _has_caps_urgency(text)
    if has_caps:
        evidence.extend(caps_evidence[:2])
        category_scores['caps_emphasis'] = 0.1
    
    # Calculate base score from category scores
    base_score = sum(category_scores.values())
    
    # Apply multiplier if action requests are combined with other urgency cues
    multiplier = 1.0
    non_action_categories = {k: v for k, v in category_scores.items() 
                           if k not in ('action_request', 'exclamation', 'caps_emphasis')}
    
    if category_scores.get('action_request', 0) > 0 and sum(non_action_categories.values()) > 0:
        multiplier = 1.25
        evidence.append("Urgency combined with action request (amplified)")
    
    # Multiple urgency categories increase severity
    active_categories = len([v for v in category_scores.values() if v > 0])
    if active_categories >= 3:
        multiplier *= 1.15
        evidence.append(f"Multiple urgency tactics detected ({active_categories} categories)")
    
    final_score = min(base_score * multiplier, 1.0)
    
    # Calculate confidence based on evidence strength
    if not evidence:
        confidence = 0.5
    elif final_score < 0.2:
        confidence = 0.6
    elif final_score < 0.5:
        confidence = 0.75
    else:
        confidence = 0.9
    
    return SignalResult(
        signal_name="urgency",
        score=round(final_score, 3),
        confidence=confidence,
        evidence=evidence[:10]  # Limit evidence to top 10 items
    )
