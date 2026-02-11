"""
Combined detector integrating RAG, NLP, Regex, and security rules
v2.0 — Fear_threat dominance, false-negative floors, improved risk mapping
"""

from typing import Dict
import re

# Import RAG detector
try:
    from .rag_detector import get_detector
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nlp_pipeline.rag_detector import get_detector


class IntegratedSocialEngineeringDetector:
    """
    Multi-layer detection system combining:
    1. RAG-based semantic detection
    2. Context-aware rule-based detection with threat severity
    3. Weighted ensemble with fear_threat dominance and explainability
    """

    # ── High-severity threat keywords (aligned with rag_detector) ──
    THREAT_KEYWORDS_SEVERE = [
        "legal action", "court", "police", "fir", "arrest",
        "investigation", "permanently closed", "terminated",
        "account frozen", "service termination", "aadhaar",
        "pan blocked", "pan card", "sim deactivated",
        "bank account frozen", "money laundering", "prosecution",
        "seized", "non-bailable", "blacklisted", "cyber cell",
        "suspended", "hacked", "compromised", "ransomware",
        "encrypted", "dark web", "webcam", "leaked", "breach",
    ]

    DEADLINE_KEYWORDS = [
        "immediately", "within 24 hours", "within 48 hours", "today",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
    ]

    FEAR_OVERRIDE_KEYWORDS = [
        "legal action", "permanently closed", "terminated", "court",
        "police", "fir", "investigation", "account frozen",
        "service termination", "aadhaar", "pan blocked", "pan card",
        "sim deactivated", "arrest", "prosecution", "seized",
        "money laundering", "non-bailable", "suspended", "hacked",
        "compromised", "ransomware", "encrypted", "webcam",
        "dark web", "leaked",
    ]

    def __init__(self):
        self.rag_detector = get_detector()

        # Ensemble weights
        self.weights = {
            "rag": 0.65,
            "rules": 0.35
        }

        # ── Whitelist for known safe informational messages ──
        self._whitelist_patterns = [
            r"(ceo|director|manager|president|executive)\s+(announced|said|reported|mentioned|shared|presented)",
            r"scheduled\s+(meeting|maintenance)",
            r"product\s+launch",
            r"press\s+release",
            r"no\s+action\s+(required|needed|is needed)",
            r"confirm\s+(your\s+)?(appointment|meeting|booking|reservation)",
            r"verify\s+(your\s+)?email\s+(address\s+)?to\s+complete\s+(your\s+)?registration",
        ]
        self._compiled_whitelist = [
            re.compile(p, re.IGNORECASE) for p in self._whitelist_patterns
        ]

        # Authority benign context
        self._authority_benign = re.compile(
            r"(announced|said|reported|mentioned|shared|presented|discussed|confirmed\s+that)",
            re.IGNORECASE,
        )

        # Verify benign context
        self._verify_benign = re.compile(
            r"(appointment|meeting|booking|reservation|schedule|calendar|tomorrow|today|registration|sign.?up)",
            re.IGNORECASE,
        )

    # ───────────────────────────────────────────────────────────
    # Whitelist handling
    # ───────────────────────────────────────────────────────────

    def _is_whitelisted(self, message: str) -> bool:
        """Return True only if message matches safe pattern AND has no threat keywords."""
        msg_lower = message.lower()
        has_threat = any(kw in msg_lower for kw in self.THREAT_KEYWORDS_SEVERE)
        if has_threat:
            return False

        for pattern in self._compiled_whitelist:
            if pattern.search(message):
                return True
        return False

    def _safe_result(self) -> Dict:
        return {
            "is_social_engineering": False,
            "confidence_score": 0.0,
            "category": "safe",
            "details": {
                "rag_confidence": 0.0,
                "rule_confidence": 0.0,
                "rag_similarity": 0.0,
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rule_weight": self.weights["rules"],
                    "formula": "final = 0.65 × RAG + 0.35 × Rules",
                },
            },
            "risk_level": "SAFE",
            "explanation": "Message is informational and matches known safe patterns.",
        }

    # ───────────────────────────────────────────────────────────
    # Public API
    # ───────────────────────────────────────────────────────────

    def analyze_message(self, message: str) -> Dict:
        if self._is_whitelisted(message):
            return self._safe_result()

        rag_result = self.rag_detector.detect(message)
        rule_result = self._run_rule_based_detection(message)

        return self._ensemble_detection(message, rag_result, rule_result)

    # ───────────────────────────────────────────────────────────
    # Rule-based detection (v2: threat severity multiplier)
    # ───────────────────────────────────────────────────────────

    def _run_rule_based_detection(self, message: str) -> Dict:
        score = self._basic_rule_detection(message)
        return {
            "is_social_engineering": score > 0.55,
            "confidence_score": score,
            "category": self._detect_category_from_rules(message),
        }

    def _basic_rule_detection(self, message: str) -> float:
        msg = message.lower()
        score = 0.0

        # Urgency
        urgency_keywords = [
            "urgent", "immediately", "act now", "expires", "final warning",
        ]
        if any(k in msg for k in urgency_keywords):
            score += 0.30

        # Threat / fear (expanded)
        fear_keywords = [
            "suspended", "terminated", "legal action", "compromised",
            "hacked", "court", "police", "fir", "arrest", "investigation",
            "account frozen", "service termination", "aadhaar",
            "pan blocked", "sim deactivated", "prosecution", "seized",
            "ransomware", "encrypted", "dark web", "webcam", "leaked",
            "breach", "money laundering", "blacklisted",
        ]
        fear_count = sum(1 for k in fear_keywords if k in msg)
        if fear_count >= 1:
            score += 0.35
        if fear_count >= 2:
            score += 0.20  # additional boost for multi-threat

        # Threat severity multiplier
        if fear_count >= 1:
            score *= 1.25

        # Reward lure
        reward_keywords = ["won", "prize", "reward", "claim", "free"]
        if any(k in msg for k in reward_keywords):
            score += 0.30

        # Authority abuse (non-informational)
        authority_keywords = ["ceo", "manager", "director", "boss"]
        for k in authority_keywords:
            if k in msg and not self._authority_benign.search(msg):
                score += 0.20

        # Impersonation via verify/confirm (not appointments/registration)
        if "verify" in msg or "confirm" in msg:
            if not self._verify_benign.search(msg):
                score += 0.25

        return min(score, 1.0)

    def _detect_category_from_rules(self, message: str) -> str:
        msg = message.lower()

        # ── Fear_threat dominance: check threat keywords FIRST ──
        fear_keywords = [
            "suspended", "terminated", "legal action", "compromised",
            "hacked", "court", "police", "fir", "arrest", "investigation",
            "account frozen", "service termination", "aadhaar",
            "pan blocked", "sim deactivated", "prosecution", "seized",
            "ransomware", "encrypted", "dark web", "webcam", "leaked",
            "breach", "money laundering", "blacklisted",
        ]
        if any(k in msg for k in fear_keywords):
            return "fear_threat"

        if any(k in msg for k in ["urgent", "act now", "expires"]):
            return "urgency"
        if any(k in msg for k in ["won", "reward", "prize", "free"]):
            return "reward_lure"
        if any(
            k in msg for k in ["ceo", "director", "manager"]
        ) and not self._authority_benign.search(msg):
            return "authority"
        if any(
            k in msg for k in ["verify", "confirm"]
        ) and not self._verify_benign.search(msg):
            return "impersonation"

        return "unknown"

    # ───────────────────────────────────────────────────────────
    # Ensemble logic (v2: fear_threat floor, dominance logic)
    # ───────────────────────────────────────────────────────────

    def _ensemble_detection(
        self, message: str, rag: Dict, rules: Dict
    ) -> Dict:
        rag_conf = rag["confidence_score"]
        rule_conf = rules["confidence_score"]

        final_conf = (
            self.weights["rag"] * rag_conf
            + self.weights["rules"] * rule_conf
        )

        final_conf = max(0.0, min(1.0, final_conf))

        # ── Category selection with fear_threat dominance ──
        msg_lower = message.lower()
        has_fear_override = any(
            kw in msg_lower for kw in self.FEAR_OVERRIDE_KEYWORDS
        )

        if has_fear_override:
            category = "fear_threat"
        elif rag_conf >= rule_conf:
            category = rag["category"]
        else:
            category = rules["category"]

        if category == "psychological_coercion":
            category = "fear_threat"

        # ── Fear_threat impersonation dominance ──
        # If both impersonation and threat keywords exist, fear_threat wins
        impersonation_keywords = [
            "netflix", "amazon", "paypal", "apple", "microsoft",
            "google", "instagram", "linkedin", "dropbox", "spotify",
            "fedex", "your bank",
        ]
        has_impersonation = any(k in msg_lower for k in impersonation_keywords)
        if has_impersonation and has_fear_override:
            category = "fear_threat"

        # ── Ensemble confidence floors (false-negative reduction) ──
        if rule_conf > 0.7 and category == "fear_threat":
            final_conf = max(final_conf, 0.65)

        threat_count = sum(
            1 for kw in self.THREAT_KEYWORDS_SEVERE if kw in msg_lower
        )
        has_deadline = any(kw in msg_lower for kw in self.DEADLINE_KEYWORDS)

        if threat_count >= 2 and has_deadline:
            final_conf = max(final_conf, 0.75)
        elif threat_count >= 2:
            final_conf = max(final_conf, 0.65)
        elif threat_count >= 1 and has_deadline:
            final_conf = max(final_conf, 0.60)

        final_conf = max(0.0, min(1.0, final_conf))
        is_attack = final_conf > 0.50

        return {
            "is_social_engineering": is_attack,
            "confidence_score": round(final_conf, 4),
            "category": category,
            "details": {
                "rag_confidence": round(rag_conf, 4),
                "rule_confidence": round(rule_conf, 4),
                "rag_similarity": rag.get("raw_similarity", 0.0),
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rag_contribution": round(
                        self.weights["rag"] * rag_conf, 4
                    ),
                    "rule_weight": self.weights["rules"],
                    "rule_contribution": round(
                        self.weights["rules"] * rule_conf, 4
                    ),
                    "formula": "final = 0.65 × RAG + 0.35 × Rules",
                },
                "similar_patterns": rag.get("similar_patterns", []),
            },
            "risk_level": self._get_risk_level(final_conf, category),
            "explanation": self._final_explanation(
                is_attack, category, final_conf
            ),
        }

    # ───────────────────────────────────────────────────────────
    # Risk level (v2: category-aware)
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _get_risk_level(confidence: float, category: str = "unknown") -> str:
        if confidence >= 0.85:
            return "CRITICAL"
        if confidence >= 0.70:
            return "HIGH"
        if confidence >= 0.60 and category in ("fear_threat", "authority"):
            return "HIGH"
        if confidence >= 0.50:
            return "MEDIUM"
        if confidence >= 0.30:
            return "LOW"
        return "SAFE"

    # ───────────────────────────────────────────────────────────
    # Explanation
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _final_explanation(
        is_attack: bool, category: str, confidence: float
    ) -> str:
        if not is_attack:
            return (
                f"Message appears legitimate.\n"
                f"Confidence: {(1 - confidence) * 100:.1f}%"
            )
        return (
            f"Social Engineering Attack Detected\n"
            f"Category: {category.replace('_', ' ').title()}\n"
            f"Confidence: {confidence * 100:.1f}%\n"
            f"Risk Level: {IntegratedSocialEngineeringDetector._get_risk_level(confidence, category)}"
        )