"""
Module for detecting and analyzing threat signals in communications.
"""

from typing import Iterable


_URGENCY_TERMS: tuple[str, ...] = (
	"urgent",
	"immediately",
	"asap",
	"now",
	"action required",
)


def _contains_phrase(text: str, phrases: Iterable[str]) -> bool:
	"""Return True if any full phrase from `phrases` appears in `text`."""
	lowered = text.lower()
	return any(phrase in lowered for phrase in phrases)


def has_urgency_words(text: str) -> bool:
	"""Check if the message contains common urgency-related terms."""
	if not text:
		return False

	# Direct phrase lookup keeps this lightweight and readable.
	return _contains_phrase(text, _URGENCY_TERMS)
