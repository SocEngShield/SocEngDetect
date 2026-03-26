import re
from typing import List
from ..base import SignalResult

"""Authority-based social engineering detection signal."""

# Phase 1: Authority claim patterns
AUTHORITY_TITLES = [
    r'\b(ceo|cfo|cto|cio|coo|ciso)\b',
    r'\b(chief\s+(executive|financial|technology|information|operating|security)\s+officer)\b',
    r'\b(president|vice\s+president|vp)\b',
    r'\b(director|manager|supervisor|administrator)\b',
    r'\b(head\s+of\s+\w+)\b',
    r'\b(senior\s+(manager|director|executive|administrator))\b',
]

AUTHORITY_DEPARTMENTS = [
    r'\b(hr|human\s+resources)\b',
    r'\b(it\s+department|it\s+support|tech\s+support|helpdesk)\b',
    r'\b(legal\s+(department|team|counsel))\b',
    r'\b(compliance\s+(department|team|office))\b',
    r'\b(security\s+(department|team|office))\b',
    r'\b(finance\s+(department|team))\b',
    r'\b(accounting\s+(department|team))\b',
    r'\b(executive\s+office)\b',
]

AUTHORITY_ORGANIZATIONS = [
    r'\b(irs|fbi|cia|nsa|dhs)\b',
    r'\b(police|law\s+enforcement)\b',
    r'\b(federal\s+(agency|government|bureau))\b',
    r'\b(bank|financial\s+institution)\b',
    r'\b(microsoft|google|apple|amazon)\s+(support|security|team)\b',
]

# Phase 2: Directive/compliance language patterns
DIRECTIVE_PATTERNS = [
    r'\b(you\s+must)\b',
    r'\b(you\s+are\s+required\s+to)\b',
    r'\b(must\s+comply)\b',
    r'\b(required\s+by\s+(law|policy|regulation))\b',
    r'\b(instructed\s+to)\b',
    r'\b(directed\s+to)\b',
    r'\b(mandatory)\b',
    r'\b(failure\s+to\s+comply)\b',
    r'\b(non-compliance)\b',
    r'\b(do\s+not\s+share\s+this)\b',
    r'\b(keep\s+this\s+confidential)\b',
    r'\b(authorized\s+by)\b',
    r'\b(on\s+behalf\s+of)\b',
    r'\b(acting\s+under\s+authority)\b',
]


def _find_matches(text: str, patterns: List[str]) -> List[str]:
    """Find all matches for a list of regex patterns in text."""
    matches = []
    text_lower = text.lower()
    for pattern in patterns:
        found = re.findall(pattern, text_lower, re.IGNORECASE)
        for match in found:
            if isinstance(match, tuple):
                match = match[0]
            if match and match not in matches:
                matches.append(match)
    return matches


def analyze(text: str) -> SignalResult:
    """
    Analyze text for authority-based social engineering indicators.
    
    Two-phase detection:
    1. Detect authority claims (titles, departments, organizations)
    2. Detect directive/compliance language
    
    Scoring:
    - Authority claims alone: low score (0.2-0.3)
    - Directive language alone: minimal score (0.1)
    - Authority + directive language: higher score (0.5-0.7)
    """
    evidence = []
    
    # Phase 1: Detect authority claims
    title_matches = _find_matches(text, AUTHORITY_TITLES)
    department_matches = _find_matches(text, AUTHORITY_DEPARTMENTS)
    organization_matches = _find_matches(text, AUTHORITY_ORGANIZATIONS)
    
    authority_found = False
    
    if title_matches:
        authority_found = True
        evidence.append(f"Authority title detected: {', '.join(title_matches)}")
    
    if department_matches:
        authority_found = True
        evidence.append(f"Authority department detected: {', '.join(department_matches)}")
    
    if organization_matches:
        authority_found = True
        evidence.append(f"Authority organization detected: {', '.join(organization_matches)}")
    
    # Phase 2: Detect directive/compliance language
    directive_matches = _find_matches(text, DIRECTIVE_PATTERNS)
    directive_found = len(directive_matches) > 0
    
    if directive_found:
        evidence.append(f"Directive language detected: {', '.join(directive_matches)}")
    
    # Scoring logic (explicit and readable)
    score = 0.0
    
    if authority_found and directive_found:
        # Combined authority + directive: high concern
        base_score = 0.5
        
        # Add 0.1 for each additional authority category (max 0.2 extra)
        authority_category_count = sum([
            1 if title_matches else 0,
            1 if department_matches else 0,
            1 if organization_matches else 0,
        ])
        authority_bonus = min((authority_category_count - 1) * 0.1, 0.2)
        
        # Add 0.05 for each additional directive match (max 0.1 extra)
        directive_bonus = min((len(directive_matches) - 1) * 0.05, 0.1)
        
        score = base_score + authority_bonus + directive_bonus
        evidence.append("Authority claim combined with directive language increases risk")
        
    elif authority_found:
        # Authority alone: low concern
        base_score = 0.2
        
        # Add 0.05 for each additional authority category (max 0.1 extra)
        authority_category_count = sum([
            1 if title_matches else 0,
            1 if department_matches else 0,
            1 if organization_matches else 0,
        ])
        authority_bonus = min((authority_category_count - 1) * 0.05, 0.1)
        
        score = base_score + authority_bonus
        evidence.append("Authority claim without directive language (lower risk)")
        
    elif directive_found:
        # Directive alone: minimal concern
        score = 0.1
        evidence.append("Directive language without authority claim (minimal risk)")
    
    # No matches: score remains 0.0
    
    # Map score to confidence
    if score == 0.0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.6
    elif score < 0.6:
        confidence = 0.75
    else:
        confidence = 0.9
    
    # Cap evidence to avoid UI clutter
    max_evidence_items = 5
    capped_evidence = evidence[:max_evidence_items]
    
    return SignalResult(
        signal_name="authority",
        score=round(score, 2),
        confidence=confidence,
        evidence=capped_evidence,
    )