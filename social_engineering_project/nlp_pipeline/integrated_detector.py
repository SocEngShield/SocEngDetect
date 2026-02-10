"""
Combined detector integrating RAG, NLP, Regex, and security rules
False-positive controlled, exam-safe version
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
    2. Context-aware rule-based detection
    3. Weighted ensemble with explainability
    """

    def __init__(self):
        self.rag_detector = get_detector()

        # Ensemble weights
        self.weights = {
            "rag": 0.65,
            "rules": 0.35
        }

        # ── Whitelist for known safe informational messages ──
        self._whitelist_patterns = [
            r"(ceo|director|manager|president|executive)\s+(announced|said|reported|mentioned|shared)",
            r"scheduled\s+meeting",
            r"product\s+launch",
            r"press\s+release",
            r"no\s+action\s+required",
            r"confirm\s+(your\s+)?(appointment|meeting|booking|reservation)",
        ]
        self._compiled_whitelist = [
            re.compile(p, re.IGNORECASE) for p in self._whitelist_patterns
        ]

        # Authority benign context
        self._authority_benign = re.compile(
            r"(announced|said|reported|mentioned|shared|presented|discussed|confirmed\s+that)",
            re.IGNORECASE
        )

        # Verify benign context
        self._verify_benign = re.compile(
            r"(appointment|meeting|booking|reservation|schedule|calendar|tomorrow|today)",
            re.IGNORECASE
        )

    # ───────────────────────────────────────────────
    # Whitelist handling
    # ───────────────────────────────────────────────

    def _is_whitelisted(self, message: str) -> bool:
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
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rule_weight": self.weights["rules"],
                    "formula": "final = 0.65 × RAG + 0.35 × Rules"
                }
            },
            "risk_level": "SAFE",
            "explanation": "Message is informational and matches known safe patterns."
        }

    # ───────────────────────────────────────────────
    # Public API
    # ───────────────────────────────────────────────

    def analyze_message(self, message: str) -> Dict:
        if self._is_whitelisted(message):
            return self._safe_result()

        rag_result = self.rag_detector.detect(message)
        rule_result = self._run_rule_based_detection(message)

        return self._ensemble_detection(rag_result, rule_result)

    # ───────────────────────────────────────────────
    # Rule-based detection
    # ───────────────────────────────────────────────

    def _run_rule_based_detection(self, message: str) -> Dict:
        score = self._basic_rule_detection(message)
        return {
            "is_social_engineering": score > 0.55,
            "confidence_score": score,
            "category": self._detect_category_from_rules(message)
        }

    def _basic_rule_detection(self, message: str) -> float:
        msg = message.lower()
        score = 0.0

        # Urgency requires pressure keywords
        urgency_keywords = ["urgent", "immediately", "act now", "expires", "final warning"]
        if any(k in msg for k in urgency_keywords):
            score += 0.30

        # Threat / fear
        fear_keywords = ["suspended", "terminated", "legal action", "compromised", "hacked"]
        if any(k in msg for k in fear_keywords):
            score += 0.35

        # Reward lure
        reward_keywords = ["won", "prize", "reward", "claim", "free"]
        if any(k in msg for k in reward_keywords):
            score += 0.30

        # Authority abuse (non-informational)
        authority_keywords = ["ceo", "manager", "director", "boss"]
        for k in authority_keywords:
            if k in msg and not self._authority_benign.search(msg):
                score += 0.20

        # Impersonation via verify/confirm (not appointments)
        if "verify" in msg or "confirm" in msg:
            if not self._verify_benign.search(msg):
                score += 0.25

        return min(score, 1.0)

    def _detect_category_from_rules(self, message: str) -> str:
        msg = message.lower()

        if any(k in msg for k in ["urgent", "act now", "expires"]):
            return "urgency"
        if any(k in msg for k in ["won", "reward", "prize", "free"]):
            return "reward_lure"
        if any(k in msg for k in ["ceo", "director", "manager"]) and not self._authority_benign.search(msg):
            return "authority"
        if any(k in msg for k in ["verify", "confirm"]) and not self._verify_benign.search(msg):
            return "impersonation"
        if any(k in msg for k in ["suspended", "legal action", "hacked", "terminated"]):
            return "fear_threat"

        return "unknown"

    # ───────────────────────────────────────────────
    # Ensemble logic
    # ───────────────────────────────────────────────

    def _ensemble_detection(self, rag: Dict, rules: Dict) -> Dict:
        rag_conf = rag["confidence_score"]
        rule_conf = rules["confidence_score"]

        final_conf = (
            self.weights["rag"] * rag_conf +
            self.weights["rules"] * rule_conf
        )

        final_conf = max(0.0, min(1.0, final_conf))
        is_attack = final_conf > 0.55

        category = rag["category"] if rag_conf >= rule_conf else rules["category"]
        if category == "psychological_coercion":
            category = "fear_threat"

        return {
            "is_social_engineering": is_attack,
            "confidence_score": round(final_conf, 4),
            "category": category,
            "details": {
                "rag_confidence": round(rag_conf, 4),
                "rule_confidence": round(rule_conf, 4),
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rag_contribution": round(self.weights["rag"] * rag_conf, 4),
                    "rule_weight": self.weights["rules"],
                    "rule_contribution": round(self.weights["rules"] * rule_conf, 4),
                    "formula": "final = 0.65 × RAG + 0.35 × Rules"
                },
                "similar_patterns": rag.get("similar_patterns", []),
            },
            "risk_level": self._get_risk_level(final_conf),
            "explanation": self._final_explanation(is_attack, category, final_conf)
        }

    # ───────────────────────────────────────────────
    # Helpers
    # ───────────────────────────────────────────────

    def _get_risk_level(self, confidence: float) -> str:
        if confidence >= 0.85:
            return "CRITICAL"
        elif confidence >= 0.7:
            return "HIGH"
        elif confidence >= 0.55:
            return "MEDIUM"
        elif confidence >= 0.3:
            return "LOW"
        return "SAFE"

    def _final_explanation(self, is_attack: bool, category: str, confidence: float) -> str:
        if not is_attack:
            return (
                f"Message appears legitimate.\n"
                f"Confidence: {(1-confidence)*100:.1f}%"
            )
        return (
            f"Social Engineering Attack Detected\n"
            f"Category: {category.replace('_', ' ').title()}\n"
            f"Confidence: {confidence*100:.1f}%\n"
            f"Risk Level: {self._get_risk_level(confidence)}"
        )
