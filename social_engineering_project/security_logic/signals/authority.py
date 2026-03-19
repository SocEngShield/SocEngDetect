import re
from typing import List
from ..base import SignalResult

"""Authority-based social engineering detection signal."""

# -----------------------------
# AUTHORITY CLAIM PATTERNS
# -----------------------------

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

    #  realistic patterns
    r'\b(account\s+(department|team))\b',
    r'\b(customer\s+support\s+team)\b',
    r'\b(security\s+team)\b',
    r'\b(support\s+team)\b',
]

AUTHORITY_ORGANIZATIONS = [
    r'\b(irs|fbi|cia|nsa|dhs)\b',
    r'\b(police|law\s+enforcement)\b',
    r'\b(federal\s+(agency|government|bureau))\b',
    r'\b(bank|financial\s+institution)\b',
    r'\b(microsoft|google|apple|amazon)\s+(support|security|team)\b',

    # implicit authority
    r'\byour\s+(bank|account|service)\b',
]

# -----------------------------
# DIRECTIVE / COMPLIANCE PATTERNS
# -----------------------------

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

    # natural directives
    r'\bverify\s+(?:your|account|details)\b',
    r'\bupdate\s+(?:your|account|information)\b',
]

# -----------------------------
# HELPER
# -----------------------------

def _find_matches(text: str, patterns: List[str]) -> List[str]:
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


# -----------------------------
# MAIN ANALYZER
# -----------------------------

def analyze(text: str) -> SignalResult:

    evidence = []

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

    directive_matches = _find_matches(text, DIRECTIVE_PATTERNS)
    directive_found = len(directive_matches) > 0

    if directive_found:
        evidence.append(f"Directive language detected: {', '.join(directive_matches)}")

    score = 0.0

    if authority_found and directive_found:
        base_score = 0.5

        authority_category_count = sum([
            1 if title_matches else 0,
            1 if department_matches else 0,
            1 if organization_matches else 0,
        ])
        authority_bonus = min((authority_category_count - 1) * 0.1, 0.2)
        directive_bonus = min((len(directive_matches) - 1) * 0.05, 0.1)

        score = base_score + authority_bonus + directive_bonus
        evidence.append("Authority claim combined with directive language increases risk")

    elif authority_found:
        base_score = 0.2

        authority_category_count = sum([
            1 if title_matches else 0,
            1 if department_matches else 0,
            1 if organization_matches else 0,
        ])
        authority_bonus = min((authority_category_count - 1) * 0.05, 0.1)

        score = base_score + authority_bonus
        evidence.append("Authority claim without directive language (lower risk)")

    elif directive_found:
        score = 0.1
        evidence.append("Directive language without authority claim (minimal risk)")

    if score == 0.0:
        confidence = 0.5
    elif score < 0.3:
        confidence = 0.6
    elif score < 0.6:
        confidence = 0.75
    else:
        confidence = 0.9

    return SignalResult(
        signal_name="authority",
        score=round(score, 2),
        confidence=confidence,
        evidence=evidence[:5],
    )