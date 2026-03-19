import re
from typing import List, Tuple
from ..base import SignalResult

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
    r"before\s+it\s+expires?",
    r"expires?\s+today",
    r"before\s+it'?s\s+too\s+late",
    r"claim\s+before\s+it\s+expires?",
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
]

TIME_PRESSURE_PATTERNS = [
    r'\blimited[\s-]?time\b',
    r'\bbefore\s+(?:it\'?s?\s+)?too\s+late\b',
    r'\b(?:only|just)\s+\d+\s*(?:left|remaining)\b',
]

ACTION_REQUEST_PATTERNS = [
    r'\bclick\s+(?:here|below)\b',
    r'\bverify\s+(?:your|account|identity)\b',
    r'\bconfirm\s+(?:your|account|details)\b',
]

URGENCY_KEYWORDS_IN_CONTEXT = [
    r'\burgent\b',
    r'\bimportant\b',
    r'\balert\b',
    r'\bwarning\b',
    r'\baction\s+required\b',
]

BASIC_URGENCY_PATTERNS = [
    r"\bimmediately\b",
    r"\burgent\b",
    r"\bact now\b",
    r"\bconfirm immediately\b",
    r"\brespond immediately\b",
]

def _find_matches(text: str, patterns: List[str]) -> List[str]:
    matches = []
    for pattern in patterns:
        found = re.findall(pattern, text, re.IGNORECASE)
        matches.extend(found)
    return matches

def analyze(text: str) -> SignalResult:

    if not text or not isinstance(text, str):
        return SignalResult("urgency", 0.0, 0.5, [])

    text = text.strip()
    if not text:
        return SignalResult("urgency", 0.0, 0.5, [])

    evidence = []
    category_scores = {}

    basic_matches = _find_matches(text, BASIC_URGENCY_PATTERNS)
    if basic_matches:
        evidence.extend([f"Basic urgency: {m}" for m in basic_matches[:3]])
        category_scores['basic'] = min(len(basic_matches) * 0.15, 0.3)

    deadline_matches = _find_matches(text, DEADLINE_PATTERNS)
    if deadline_matches:
        evidence.extend(deadline_matches[:3])
        category_scores['deadline'] = min(len(deadline_matches) * 0.15, 0.3)

    immediacy_matches = _find_matches(text, IMMEDIACY_PATTERNS)
    if immediacy_matches:
        evidence.extend(immediacy_matches[:3])
        category_scores['immediacy'] = min(len(immediacy_matches) * 0.15, 0.3)

    pressure_matches = _find_matches(text, TIME_PRESSURE_PATTERNS)
    if pressure_matches:
        evidence.extend(pressure_matches[:3])
        category_scores['pressure'] = min(len(pressure_matches) * 0.12, 0.25)

    action_matches = _find_matches(text, ACTION_REQUEST_PATTERNS)
    if action_matches:
        evidence.extend(action_matches[:2])
        category_scores['action'] = min(len(action_matches) * 0.1, 0.2)

    keyword_matches = _find_matches(text, URGENCY_KEYWORDS_IN_CONTEXT)
    if keyword_matches:
        evidence.extend(keyword_matches[:2])
        category_scores['keywords'] = min(len(keyword_matches) * 0.08, 0.15)

    base_score = sum(category_scores.values())

    if len(category_scores) >= 2:
        base_score *= 1.2

    final_score = min(base_score, 1.0)

    if final_score == 0:
        confidence = 0.5
    elif final_score < 0.3:
        confidence = 0.65
    elif final_score < 0.6:
        confidence = 0.8
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="urgency",
        score=round(final_score, 3),
        confidence=confidence,
        evidence=evidence[:8]
    )