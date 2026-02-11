"""
Combined detector integrating RAG + Rule Engine
v3.0 — Clear separation: RAG owns confidence, Rules own category.
       Multi-label (max 2), severity floors, fear_threat dominance.
"""

from typing import Dict, List
import re

try:
    from .rag_detector import get_detector
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nlp_pipeline.rag_detector import get_detector


class IntegratedSocialEngineeringDetector:
    """
    Responsibilities:
      • RAG  → attack probability (confidence score)
      • Rules → category classification (multi-label, max 2)
      • This class → ensemble confidence, severity floors, risk level
    """

    # ══════════════════════════════════════════════════════════════
    #  KEYWORD LISTS — single source of truth
    # ══════════════════════════════════════════════════════════════

    # High-severity fear/threat keywords
    FEAR_KEYWORDS = [
        "legal action", "court", "police", "fir", "arrest",
        "investigation", "permanently closed", "terminated",
        "account frozen", "frozen account", "service termination",
        "aadhaar", "pan blocked", "pan card", "sim deactivated",
        "bank account frozen", "money laundering", "prosecution",
        "seized", "non-bailable", "blacklisted", "cyber cell",
        "suspended", "hacked", "compromised", "ransomware",
        "encrypted", "dark web", "webcam", "leaked", "breach",
        "income tax", "deactivated", "permanently", "frozen",
        "action will be taken",
    ]

    # Deadline / immediacy
    DEADLINE_KEYWORDS = [
        "immediately", "within 24 hours", "within 48 hours", "today",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "in 10 minutes", "30 minutes",
        "in 30 minutes", "last warning", "last chance", "expires",
    ]

    # Government / legal authority (triggers 0.70 floor)
    GOVERNMENT_KEYWORDS = [
        "income tax", "aadhaar", "court", "police", "fir",
        "prosecution", "arrest", "non-bailable", "cyber cell",
        "irs", "tax department", "income tax department",
    ]

    # Impersonation: identity claims
    IDENTITY_PHRASES = [
        "this is", "i am", "i'm", "we are", "from it department",
        "from it", "customer support", "bank team", "support team",
        "help desk", "helpdesk", "technical support", "tech support",
        "amazon support", "amazon customer support",
    ]

    # Impersonation: brand names
    BRAND_KEYWORDS = [
        "netflix", "amazon", "paypal", "apple", "microsoft",
        "google", "instagram", "linkedin", "dropbox", "spotify",
        "fedex", "irs", "income tax department",
    ]

    # Authority titles (non-brand)
    AUTHORITY_KEYWORDS = [
        "ceo", "cfo", "cto", "manager", "director", "supervisor",
        "president", "chairman", "head of", "department head",
        "team lead", "executive", "boss", "vp of",
    ]

    # Sensitive info requests
    SENSITIVE_KEYWORDS = [
        "password", "credential", "login", "card detail",
        "bank detail", "ssn", "social security", "otp", "pin",
        "cvv", "account number", "routing number",
        "financial detail", "submit financial",
        "share your", "send your", "provide your", "submit your",
        "confirm your card", "confirm card",
    ]

    # Reward / lure
    REWARD_KEYWORDS = [
        "won", "winner", "prize", "reward", "free", "gift",
        "discount", "cashback", "lottery", "selected", "chosen",
        "bonus", "90%",
    ]

    # ══════════════════════════════════════════════════════════════

    def __init__(self):
        self.rag_detector = get_detector()

        self.weights = {"rag": 0.65, "rules": 0.35}

        # Whitelist for genuinely safe messages
        self._whitelist_patterns = [
            re.compile(p, re.IGNORECASE) for p in [
                r"(ceo|director|manager|president|executive)\s+(announced|said|reported|mentioned|shared|presented)",
                r"scheduled\s+(meeting|maintenance)",
                r"product\s+launch",
                r"press\s+release",
                r"no\s+action\s+(required|needed|is needed)",
                r"confirm\s+(your\s+)?(appointment|meeting|booking|reservation)",
                r"verify\s+(your\s+)?email\s+(address\s+)?to\s+complete\s+(your\s+)?registration",
            ]
        ]

        self._authority_benign = re.compile(
            r"(announced|said|reported|mentioned|shared|presented|discussed|confirmed\s+that)",
            re.IGNORECASE,
        )

        self._verify_benign = re.compile(
            r"(appointment|meeting|booking|reservation|schedule|calendar|registration|sign.?up)",
            re.IGNORECASE,
        )

    # ───────────────────────────────────────────────────────────
    # Keyword matchers
    # ───────────────────────────────────────────────────────────

    @staticmethod
    def _match_any(msg: str, keywords: list) -> bool:
        return any(kw in msg for kw in keywords)

    @staticmethod
    def _match_count(msg: str, keywords: list) -> int:
        return sum(1 for kw in keywords if kw in msg)

    # ───────────────────────────────────────────────────────────
    # Whitelist
    # ───────────────────────────────────────────────────────────

    def _is_whitelisted(self, message: str) -> bool:
        msg_lower = message.lower()
        if self._match_any(msg_lower, self.FEAR_KEYWORDS):
            return False
        if self._match_any(msg_lower, self.SENSITIVE_KEYWORDS):
            return False
        return any(p.search(message) for p in self._whitelist_patterns)

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
                    "rag_weight": 0.65,
                    "rag_contribution": 0.0,
                    "rule_weight": 0.35,
                    "rule_contribution": 0.0,
                    "formula": "final = (0.65 × RAG) + (0.35 × Rules)",
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
        rule_result = self._rule_based_detection(message)

        return self._ensemble(message, rag_result, rule_result)

    # ═══════════════════════════════════════════════════════════
    #  RULE ENGINE — owns category classification
    # ═══════════════════════════════════════════════════════════

    def _rule_based_detection(self, message: str) -> Dict:
        msg = message.lower()
        score = self._rule_score(msg)
        categories = self._rule_categories(msg)
        return {
            "confidence_score": score,
            "category": categories[0] if categories else "unknown",
            "categories": categories,
        }

    def _rule_score(self, msg: str) -> float:
        """Additive score from keyword signals. Returns 0.0–1.0."""
        score = 0.0

        # ── Fear / threat ──
        fear_count = self._match_count(msg, self.FEAR_KEYWORDS)
        if fear_count >= 1:
            score += 0.35
        if fear_count >= 2:
            score += 0.20

        # ── Urgency / deadline ──
        if self._match_any(msg, self.DEADLINE_KEYWORDS):
            score += 0.25

        # ── Impersonation: identity claim ──
        has_identity = self._match_any(msg, self.IDENTITY_PHRASES)
        has_brand = self._match_any(msg, self.BRAND_KEYWORDS)
        if has_identity or has_brand:
            score += 0.25

        # ── Authority abuse (non-informational context only) ──
        if self._match_any(msg, self.AUTHORITY_KEYWORDS):
            if not self._authority_benign.search(msg):
                score += 0.20

        # ── Sensitive info request ──
        if self._match_any(msg, self.SENSITIVE_KEYWORDS):
            score += 0.25

        # ── Reward lure ──
        if self._match_any(msg, self.REWARD_KEYWORDS):
            score += 0.25

        # ── Verify/confirm in suspicious context ──
        if ("verify" in msg or "confirm" in msg):
            if not self._verify_benign.search(msg):
                score += 0.10

        return min(score, 1.0)

    def _rule_categories(self, msg: str) -> List[str]:
        """
        Detect up to 2 categories, priority-ordered:
        fear_threat > impersonation > authority > urgency > reward_lure

        Key rule: urgency alone NEVER overrides fear_threat.
        """
        detected: List[str] = []

        has_fear = self._match_any(msg, self.FEAR_KEYWORDS)
        has_identity = self._match_any(msg, self.IDENTITY_PHRASES)
        has_brand = self._match_any(msg, self.BRAND_KEYWORDS)
        has_authority = (
            self._match_any(msg, self.AUTHORITY_KEYWORDS)
            and not self._authority_benign.search(msg)
        )
        has_deadline = self._match_any(msg, self.DEADLINE_KEYWORDS)
        has_reward = self._match_any(msg, self.REWARD_KEYWORDS)
        has_sensitive = self._match_any(msg, self.SENSITIVE_KEYWORDS)

        # Priority 1: fear_threat
        if has_fear:
            detected.append("fear_threat")

        # Priority 2: impersonation (identity claim OR brand name)
        if has_identity or has_brand:
            if "impersonation" not in detected:
                detected.append("impersonation")

        # Priority 3: authority
        if has_authority:
            if "authority" not in detected:
                detected.append("authority")

        # Priority 4: urgency  (only if fear_threat is NOT already primary)
        if has_deadline:
            if "urgency" not in detected:
                detected.append("urgency")

        # Priority 5: reward_lure
        if has_reward:
            if "reward_lure" not in detected:
                detected.append("reward_lure")

        # ── OVERRIDE: impersonation + sensitive info → include fear_threat ──
        if ("impersonation" in detected) and has_sensitive:
            if "fear_threat" not in detected:
                detected.insert(0, "fear_threat")

        # ── OVERRIDE: identity claim + sensitive info but no fear yet ──
        if (has_identity or has_brand) and has_sensitive:
            if "fear_threat" not in detected:
                detected.insert(0, "fear_threat")

        # If nothing matched, check verify/confirm
        if not detected:
            if ("verify" in msg or "confirm" in msg):
                if not self._verify_benign.search(msg):
                    detected.append("impersonation")

        if not detected:
            detected.append("unknown")

        # Return max 2, deduplicated
        seen = []
        for c in detected:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break
        return seen

    # ═══════════════════════════════════════════════════════════
    #  ENSEMBLE — merges RAG confidence + Rule category
    # ═══════════════════════════════════════════════════════════

    def _ensemble(self, message: str, rag: Dict, rules: Dict) -> Dict:
        msg = message.lower()

        rag_conf = rag["confidence_score"]
        rule_conf = rules["confidence_score"]

        # ── Step 1: weighted ensemble ──
        final_conf = (self.weights["rag"] * rag_conf) + (self.weights["rules"] * rule_conf)
        final_conf = max(0.0, min(1.0, final_conf))

        # ── Step 2: RULES own category (not RAG) ──
        # RAG category is used ONLY as a tie-breaking signal
        rule_cats = rules.get("categories", ["unknown"])
        rag_cat = rag.get("category", "unknown")

        # Merge: rule categories are authoritative; add RAG if unique
        categories = list(rule_cats)
        if rag_cat not in categories and rag_cat != "unknown":
            categories.append(rag_cat)

        # Normalize
        categories = [
            "fear_threat" if c in ("psychological_coercion", "fear_threat_severe") else c
            for c in categories
        ]

        # Deduplicate, max 2
        seen = []
        for c in categories:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break
        categories = seen if seen else ["unknown"]

        # ── Step 3: Category override — fear_threat dominance ──
        #    If rule engine detected fear_threat with conf >= 0.5, force it primary
        if "fear_threat" in rule_cats and rule_conf >= 0.50:
            if "fear_threat" in categories:
                categories.remove("fear_threat")
            categories.insert(0, "fear_threat")

        # If ANY high-severity keyword exists, fear_threat MUST be present
        fear_count = self._match_count(msg, self.FEAR_KEYWORDS)
        if fear_count >= 1 and "fear_threat" not in categories:
            categories.insert(0, "fear_threat")
            if len(categories) > 2:
                categories = categories[:2]

        primary_category = categories[0]

        # ── Step 4: Severity confidence floors ──

        has_deadline = self._match_any(msg, self.DEADLINE_KEYWORDS)
        has_government = self._match_any(msg, self.GOVERNMENT_KEYWORDS)
        has_sensitive = self._match_any(msg, self.SENSITIVE_KEYWORDS)
        has_identity = self._match_any(msg, self.IDENTITY_PHRASES)
        has_brand = self._match_any(msg, self.BRAND_KEYWORDS)

        # Government / legal authority reference → 0.70 minimum
        if has_government:
            final_conf = max(final_conf, 0.70)

        # Financial info + urgency → 0.65 minimum
        if has_sensitive and has_deadline:
            final_conf = max(final_conf, 0.65)

        # Impersonation + sensitive info → 0.65 minimum
        if (has_identity or has_brand) and has_sensitive:
            final_conf = max(final_conf, 0.65)

        # 2+ high-severity keywords → 0.60 minimum
        if fear_count >= 2:
            final_conf = max(final_conf, 0.60)

        # 1 high-severity keyword + deadline → 0.60 minimum
        if fear_count >= 1 and has_deadline:
            final_conf = max(final_conf, 0.60)

        # Any fear keyword → never SAFE (minimum 0.40)
        if fear_count >= 1:
            final_conf = max(final_conf, 0.40)

        # Rule engine strong signal floor
        if rule_conf > 0.70 and "fear_threat" in categories:
            final_conf = max(final_conf, 0.65)

        final_conf = round(max(0.0, min(1.0, final_conf)), 4)

        # ── Step 5: Attack determination ──
        is_attack = final_conf > 0.35

        # ── Step 6: Risk level ──
        risk_level = self._get_risk_level(final_conf, categories)

        # ── Step 7: Build response ──
        rag_contrib = round(self.weights["rag"] * rag_conf, 4)
        rule_contrib = round(self.weights["rules"] * rule_conf, 4)

        return {
            "is_social_engineering": is_attack,
            "confidence_score": final_conf,
            "category": primary_category,
            "categories": categories,
            "details": {
                "rag_confidence": round(rag_conf, 4),
                "rule_confidence": round(rule_conf, 4),
                "confidence_breakdown": {
                    "rag_weight": self.weights["rag"],
                    "rag_contribution": rag_contrib,
                    "rule_weight": self.weights["rules"],
                    "rule_contribution": rule_contrib,
                    "formula": "final = (0.65 × RAG) + (0.35 × Rules)",
                },
                "similar_patterns": rag.get("similar_patterns", []),
            },
            "risk_level": risk_level,
            "explanation": self._build_explanation(
                is_attack, categories, final_conf,
                round(rag_conf, 4), round(rule_conf, 4),
            ),
        }

    # ═══════════════════════════════════════════════════════════
    #  RISK LEVEL
    # ══════════════��════════════════════════════════════════════

    @staticmethod
    def _get_risk_level(confidence: float, categories: List[str]) -> str:
        # Special rule: fear_threat + conf >= 0.60 → minimum HIGH
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

    # ═══════════════════════════════════════════════════════════
    #  EXPLANATION
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _build_explanation(
        is_attack: bool, categories: List[str], confidence: float,
        rag_conf: float, rule_conf: float,
    ) -> str:
        if not is_attack:
            return (
                f"Message appears legitimate.\n"
                f"Confidence: {(1 - confidence) * 100:.1f}%"
            )

        cat_display = " + ".join(c.replace("_", " ").title() for c in categories)
        risk = IntegratedSocialEngineeringDetector._get_risk_level(confidence, categories)
        rag_c = round(0.65 * rag_conf, 4)
        rule_c = round(0.35 * rule_conf, 4)

        return (
            f"Social Engineering Attack Detected\n"
            f"Category: {cat_display}\n"
            f"Confidence: {confidence * 100:.1f}%\n"
            f"Risk Level: {risk}\n\n"
            f"Calculation: (0.65 × {rag_conf:.2f}) + (0.35 × {rule_conf:.2f})"
            f" = {rag_c:.4f} + {rule_c:.4f}\n"
            f"Final score is weighted ensemble of semantic similarity "
            f"and rule-based signals."
        )