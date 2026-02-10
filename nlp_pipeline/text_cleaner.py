"""
Text cleaning and preprocessing module for social engineering detection.

Two modes:
  - clean_text()          -> for NLP / embedding input (strips URLs, emails, noise)
  - extract_raw_urls()    -> captures URLs BEFORE stripping (needed by structural rules)
  - extract_raw_emails()  -> captures emails BEFORE stripping
"""

import re
import string
from typing import List


# Pre-compiled patterns
_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_WHITESPACE_RE = re.compile(r"\s+")

# Punctuation to strip — keep !, ?, @, # (carry intent / tone signals)
_ALLOWED_PUNCT = {"@", "#", "!", "?"}
_STRIP_PUNCT = "".join(ch for ch in string.punctuation if ch not in _ALLOWED_PUNCT)
_PUNCT_TABLE = str.maketrans("", "", _STRIP_PUNCT)


def extract_raw_urls(text: str) -> List[str]:
    """Return all URLs found in the raw text (before cleaning)."""
    if not text:
        return []
    return _URL_RE.findall(text)


def extract_raw_emails(text: str) -> List[str]:
    """Return all email addresses found in the raw text (before cleaning)."""
    if not text:
        return []
    return _EMAIL_RE.findall(text)


def clean_text(text: str) -> str:
    """Normalize text for downstream NLP / embedding analysis.

    Preserves psychologically meaningful cues (urgency, intent, tone)
    while stripping noise (URLs, emails, non-informative punctuation).
    """
    if not text:
        return ""

    normalized = text.strip().lower()

    # Strip URLs and email addresses
    normalized = _URL_RE.sub(" ", normalized)
    normalized = _EMAIL_RE.sub(" ", normalized)

    # Strip noisy punctuation (keep ! ? @ #)
    normalized = normalized.translate(_PUNCT_TABLE)

    # Collapse whitespace and remove non-printable chars
    normalized = _WHITESPACE_RE.sub(" ", normalized)
    normalized = "".join(ch for ch in normalized if ch.isprintable())

    return normalized.strip()