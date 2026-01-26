"""
Text cleaning and preprocessing module for social engineering detection.
"""

import re
import string


def clean_text(text: str) -> str:
	"""Normalize email or chat text for downstream security analysis.
	Keeps psychologically meaningful cues (urgency, intent, tone) while removing
	obvious noise such as URLs, emails, and non-informative punctuation.
	"""
	if text is None:
		return ""

	# Normalize whitespace and casing early for consistent parsing
	normalized = text.strip().lower()

	# Remove URLs and email addresses to reduce noisy tokens
	url_pattern = r"https?://\S+|www\.\S+"
	email_pattern = r"[\w.+-]+@[\w-]+\.[\w.-]+"
	normalized = re.sub(url_pattern, " ", normalized)
	normalized = re.sub(email_pattern, " ", normalized)

	# Remove punctuation, but preserve markers that signal intent/tone
	# (e.g., "!" or "?" for urgency/uncertainty, "@"/"#" for mentions/tags).
	allowed = {"@", "#", "!", "?"}
	punctuation = "".join(ch for ch in string.punctuation if ch not in allowed)
	normalized = normalized.translate(str.maketrans("", "", punctuation))

	# Collapse repeated whitespace and remove lingering control characters
	normalized = re.sub(r"\s+", " ", normalized)
	normalized = "".join(ch for ch in normalized if ch.isprintable())

	return normalized.strip()
