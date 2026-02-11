"""
Combined detector integrating RAG, NLP, Regex, and security rules
v3.0 — Multi-label categories, false-negative floors, improved risk mapping,
       government authority floor, confidence display restructure
"""

from typing import Dict, List
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
    1. RAG-based semantic detection (multi-label)
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
        "income tax", "deactivated", "frozen", "permanently",
        "action will be taken",
    ]

    DEADLINE_KEYWORDS = [
        "immediately", "within 24 hours", "within 48 hours", "today",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "30 minutes", "in 10 minutes",
        "in 30 minutes", "expires", "last warning", "last chance",
    ]

    FEAR_OVERRIDE_KEYWORDS = [
        "legal action", "permanently closed", "terminated", "court",
        "police", "fir", "investigation", "account frozen",
        "service termination", "aadhaar", "pan blocked", "pan card",
        "sim deactivated", "arrest", "prosecution", "seized",
        "money laundering", "non-bailable", "suspended", "hacked",
        "compromised", "ransomware", "encrypted", "webcam",
        "dark web", "leaked", "income tax", "deactivated",
        "frozen", "permanently", "action will be taken",
    ]

    GOVERNMENT_KEYWORDS = [
        "income tax", "aadhaar", "court", "police", "fir",
        "prosecution", "arrest", "non-bailable", "cyber cell",
        "irs", "tax department", "government",
    ]

    SENSITIVE_INFO_KEYWORDS = [
        "password", "credential", "login", "card detail", "bank detail",
        "ssn", "social security", "otp", "pin", "cvv",
        "account number", "routing number", "financial detail",
        "share your", "send your", "provide your", "submit your",
        "confirm your", "verify your identity",
    ]

    IMPERSONATION_IDENTITY_KEYWORDS = [
        "this is", "from it department", "from it", "customer support",
        "bank team", "support team", "help desk", "helpdesk",
        "technical support", "tech support",
    ]

    BRAND_KEYWORDS = [
        "netflix", "amazon", "paypal", "apple", "microsoft",
        "google", "instagram", "linkedin", "dropbox", "spotify",
        "fedex", "your bank", "irs", "income tax department",
    ]

    AUTHORITY_KEYWORDS = [
        "ceo", "cfo", "cto", "manager", "director", "supervisor",
        "president", "chairman", "head of", "department head",
        "team lead", "executive", "boss", "vp of",
    ]

    REWARD_KEYWORDS = [
        "discount", "90%", "winner", "gift", "won", "prize",
        "reward", "claim", "free", "cashback", "lottery",
        "selected", "chosen", "bonus",
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
            r"(appointment|meeting|booking|reservation|schedule|calendar|tomorrow|registration|sign.?up)",
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
            "categories": ["safe"],
            "details": {
                "rag_confidence": 0.0,
                "rule_confidence": 0.0,
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rag_contribution": 0.0,
                    "rule_weight": self.weights["rules"],
                    "rule_contribution": 0.0,
                    "formula": "final = 0.65 × RAG + 0.35 × Rules",
                },
                "similar_patterns": [],
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
    # Rule-based detection (v3: multi-label + expanded keywords)
    # ───────────────────────────────────────────────────────────

    def _run_rule_based_detection(self, message: str) -> Dict:
        score = self._basic_rule_detection(message)
        categories = self._detect_categories_from_rules(message)
        return {
            "is_social_engineering": score > 0.50,
            "confidence_score": score,
            "category": categories[0] if categories else "unknown",
            "categories": categories,
        }

    def _basic_rule_detection(self, message: str) -> float:
        msg = message.lower()
        score = 0.0

        # Urgency
        if any(k in msg for k in self.DEADLINE_KEYWORDS):
            score += 0.30

        # Threat / fear
        fear_count = sum(1 for k in self.THREAT_KEYWORDS_SEVERE if k in msg)
        if fear_count >= 1:
            score += 0.35
        if fear_count >= 2:
            score += 0.20

        # Threat severity multiplier
        if fear_count >= 1:
            score *= 1.25

        # Reward lure
        if any(k in msg for k in self.REWARD_KEYWORDS):
            score += 0.30

        # Authority abuse (non-informational)
        for k in self.AUTHORITY_KEYWORDS:
            if k in msg and not self._authority_benign.search(msg):
                score += 0.20
                break  # count authority once

        # Impersonation (identity or brand)
        if any(k in msg for k in self.IMPERSONATION_IDENTITY_KEYWORDS):
            if not self._verify_benign.search(msg):
                score += 0.25
        if any(k in msg for k in self.BRAND_KEYWORDS):
            score += 0.20

        # Sensitive info request
        if any(k in msg for k in self.SENSITIVE_INFO_KEYWORDS):
            score += 0.20

        # Verify/confirm (not appointments/registration)
        if ("verify" in msg or "confirm" in msg):
            if not self._verify_benign.search(msg):
                score += 0.15

        return min(score, 1.0)

    def _detect_categories_from_rules(self, message: str) -> List[str]:
        """Detect up to 2 categories, priority-ordered."""
        msg = message.lower()
        candidates = []

        # Fear_threat — highest priority
        if any(k in msg for k in self.FEAR_OVERRIDE_KEYWORDS):
            candidates.append("fear_threat")

        # Impersonation
        has_identity = any(k in msg for k in self.IMPERSONATION_IDENTITY_KEYWORDS)
        has_brand = any(k in msg for k in self.BRAND_KEYWORDS)
        if (has_identity or has_brand) and not self._verify_benign.search(msg):
            if "impersonation" not in candidates:
                candidates.append("impersonation")

        # Authority
        if any(k in msg for k in self.AUTHORITY_KEYWORDS) and not self._authority_benign.search(msg):
            if "authority" not in candidates:
                candidates.append("authority")

        # Urgency
        if any(k in msg for k in self.DEADLINE_KEYWORDS):
            if "urgency" not in candidates:
                candidates.append("urgency")

        # Reward lure
        if any(k in msg for k in self.REWARD_KEYWORDS):
            if "reward_lure" not in candidates:
                candidates.append("reward_lure")

        if not candidates:
            # Fallback: verify/confirm without benign context
            if ("verify" in msg or "confirm" in msg) and not self._verify_benign.search(msg):
                candidates.append("impersonation")
            else:
                candidates.append("unknown")

        return candidates[:2]

    # ───────────────────────────────────────────────────────────
    # Ensemble logic (v3: multi-label, confidence floors)
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

        msg_lower = message.lower()

        # ── Merge categories from RAG and rules ──
        rag_categories = rag.get("categories", [rag.get("category", "unknown")])
        rule_categories = rules.get("categories", [rules.get("category", "unknown")])

        # Build merged priority list
        merged = []
        for cat in rag_categories + rule_categories:
            if cat not in merged and cat != "unknown":
                merged.append(cat)

        # Fear_threat dominance override
        has_fear_override = any(
            kw in msg_lower for kw in self.FEAR_OVERRIDE_KEYWORDS
        )
        if has_fear_override and "fear_threat" not in merged:
            merged.insert(0, "fear_threat")
        elif has_fear_override and "fear_threat" in merged:
            merged.remove("fear_threat")
            merged.insert(0, "fear_threat")

        # Normalize legacy
        merged = [
            "fear_threat" if c in ("psychological_coercion", "fear_threat_severe") else c
            for c in merged
        ]

        # Deduplicate, max 2
        seen = []
        for c in merged:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break

        if not seen:
            seen = ["unknown"]

        categories = seen
        primary_category = categories[0]

        # ── Confidence floors (false-negative reduction) ──
        threat_count = sum(
            1 for kw in self.THREAT_KEYWORDS_SEVERE if kw in msg_lower
        )
        has_deadline = any(kw in msg_lower for kw in self.DEADLINE_KEYWORDS)
        has_government = any(kw in msg_lower for kw in self.GOVERNMENT_KEYWORDS)
        has_sensitive = any(kw in msg_lower for kw in self.SENSITIVE_INFO_KEYWORDS)
        has_impersonation = (
            any(k in msg_lower for k in self.IMPERSONATION_IDENTITY_KEYWORDS)
            or any(k in msg_lower for k in self.BRAND_KEYWORDS)
        )

        # Government authority floor: 0.70
        if has_government:
            final_conf = max(final_conf, 0.70)

        # Financial + urgency floor: 0.65
        if has_sensitive and has_deadline:
            final_conf = max(final_conf, 0.65)

        # Impersonation + sensitive info floor: 0.65
        if has_impersonation and has_sensitive:
            final_conf = max(final_conf, 0.65)

        # Threat count floors
        if threat_count >= 2 and has_deadline:
            final_conf = max(final_conf, 0.75)
        elif threat_count >= 2:
            final_conf = max(final_conf, 0.65)
        elif threat_count >= 1 and has_deadline:
            final_conf = max(final_conf, 0.60)

        # Rule confidence fear_threat floor
        if rule_conf > 0.7 and "fear_threat" in categories:
            final_conf = max(final_conf, 0.65)

        # At least 1 strong threat keyword = minimum "Potential Threat"
        if threat_count >= 1:
            final_conf = max(final_conf, 0.40)

        final_conf = max(0.0, min(1.0, final_conf))
        is_attack = final_conf > 0.35

        # ── Compute display values ──
        rag_contribution = round(self.weights["rag"] * rag_conf, 4)
        rule_contribution = round(self.weights["rules"] * rule_conf, 4)

        return {
            "is_social_engineering": is_attack,
            "confidence_score": round(final_conf, 4),
            "category": primary_category,
            "categories": categories,
            "details": {
                "rag_confidence": round(rag_conf, 4),
                "rule_confidence": round(rule_conf, 4),
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rag_contribution": rag_contribution,
                    "rule_weight": self.weights["rules"],
                    "rule_contribution": rule_contribution,
                    "formula": "final = 0.65 × RAG + 0.35 × Rules",
                },
                "similar_patterns": rag.get("similar_patterns", []),
            },
            "risk_level": self._get_risk_level(round(final_conf, 4), categories),
            "explanation": self._final_explanation(
                is_attack, categories, round(final_conf, 4),
                round(rag_conf, 4), round(rule_conf, 4),
            ),
        }

    # ───────────────────────────────────────────────────────────
    # Risk level (v3: updated thresholds + fear_threat floor)
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _get_risk_level(confidence: float, categories: List[str] = None) -> str:
        if categories is None:
            categories = []

        # fear_threat with confidence >= 0.60 → minimum HIGH
        if "fear_threat" in categories and confidence >= 0.60:
            if confidence >= 0.85:
                return "CRITICAL"
            return "HIGH"

        if confidence >= 0.85:
            return "CRITICAL"
        if confidence >= 0.70:
            return "HIGH"
        if confidence >= 0.55:
            return "MEDIUM"
        if confidence >= 0.35:
            return "LOW"
        return "SAFE"

    # ───────────────────────────────────────────────────────────
    # Explanation (v3: shows ensemble calculation)
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _final_explanation(
        is_attack: bool, categories: List[str], confidence: float,
        rag_conf: float = 0.0, rule_conf: float = 0.0,
    ) -> str:
        if not is_attack:
            return (
                f"Message appears legitimate.\n"
                f"Confidence: {(1 - confidence) * 100:.1f}%"
            )

        cat_display = " + ".join(
            c.replace("_", " ").title() for c in categories
        )
        risk = IntegratedSocialEngineeringDetector._get_risk_level(confidence, categories)

        rag_contrib = round(0.65 * rag_conf, 4)
        rule_contrib = round(0.35 * rule_conf, 4)

        return (
            f"Social Engineering Attack Detected\n"
            f"Category: {cat_display}\n"
            f"Confidence: {confidence * 100:.1f}%\n"
            f"Risk Level: {risk}\n"
            f"Calculation: (0.65 × {rag_conf:.2f}) + (0.35 × {rule_conf:.2f}) = "
            f"{rag_contrib:.4f} + {rule_contrib:.4f}\n"
            f"Final score is weighted ensemble of semantic similarity and rule-based signals."
        )