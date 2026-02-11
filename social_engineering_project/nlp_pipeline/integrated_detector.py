"""
Integrated Social Engineering Detector — Production v4.0.

Separation of concerns:
  • RAG   → attack probability (confidence score)
  • Rules → category classification (multi-label, max 2)
  • This  → ensemble, severity floors, explainability, risk levels
"""

from typing import Dict, List, Tuple
import re

try:
    from .rag_detector import get_detector
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nlp_pipeline.rag_detector import get_detector


class IntegratedSocialEngineeringDetector:

    # ══════════════════════════════════════════════════════
    #  KEYWORD REGISTRIES  (single source of truth)
    # ══════════════════════════════════════════════════════

    FEAR_KW = [
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

    DEADLINE_KW = [
        "immediately", "within 24 hours", "within 48 hours",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "in 10 minutes", "in 30 minutes",
        "30 minutes", "last warning", "last chance", "expires",
    ]

    GOV_KW = [
        "income tax", "aadhaar", "court", "police", "fir",
        "prosecution", "arrest", "non-bailable", "cyber cell",
        "irs", "tax department", "income tax department",
    ]

    # Word-boundary aware patterns for identity impersonation
    _IDENTITY_PATTERNS = [
        r"\bthis is\b", r"\bi am\b", r"\bi'm\b", r"\bwe are\b",
        r"\bfrom it department\b", r"\bfrom it\b", r"\bcustomer support\b",
        r"\bbank team\b", r"\bsupport team\b", r"\bhelp\s?desk\b",
        r"\btechnical support\b", r"\btech support\b",
        r"\bamazon support\b", r"\bamazon customer support\b",
    ]
    _IDENTITY_RX = [re.compile(p, re.IGNORECASE) for p in _IDENTITY_PATTERNS]

    BRAND_KW = [
        "netflix", "amazon", "paypal", "apple", "microsoft",
        "google", "instagram", "linkedin", "dropbox", "spotify",
        "fedex", "irs", "income tax department",
    ]

    AUTHORITY_KW = [
        "ceo", "cfo", "cto", "manager", "director", "supervisor",
        "president", "chairman", "head of", "department head",
        "team lead", "executive", "boss", "vp of",
    ]

    # Word-boundary aware patterns for sensitive info to avoid
    # "pin" matching inside "opinion", "spinning", etc.
    _SENSITIVE_PATTERNS = [
        r"\bpassword\b", r"\bcredential", r"\blogin\b",
        r"\bcard detail", r"\bbank detail", r"\bfinancial detail",
        r"\bsubmit financial\b",
        r"\bssn\b", r"\bsocial security\b", r"\b(?:otp)\b",
        r"\bpin\b", r"\bcvv\b", r"\baccount number\b",
        r"\brouting number\b",
        r"\bshare your\b", r"\bsend your\b",
        r"\bprovide your\b", r"\bsubmit your\b",
        r"\bconfirm your card\b", r"\bconfirm card\b",
        r"\blogin credential",
    ]
    _SENSITIVE_RX = [re.compile(p, re.IGNORECASE) for p in _SENSITIVE_PATTERNS]

    REWARD_KW = [
        "won", "winner", "prize", "reward", "free", "gift",
        "discount", "cashback", "lottery", "selected", "chosen",
        "bonus", "90%",
    ]

    # ══════════════════════════════════════════════════════

    def __init__(self):
        self.rag_detector = get_detector()
        self.w_rag = 0.65
        self.w_rule = 0.35

        self._whitelist_rx = [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"(ceo|director|manager|president|executive)\s+"
                r"(announced|said|reported|mentioned|shared|presented)",
                r"scheduled\s+(meeting|maintenance)",
                r"product\s+launch",
                r"press\s+release",
                r"no\s+action\s+(required|needed|is needed)",
                r"confirm\s+(your\s+)?(appointment|meeting|booking|reservation)",
                r"verify\s+(your\s+)?email\s+(address\s+)?to\s+complete\s+(your\s+)?registration",
            ]
        ]
        self._auth_benign_rx = re.compile(
            r"\b(announced|said|reported|mentioned|shared|presented|discussed)\b",
            re.IGNORECASE,
        )
        self._verify_benign_rx = re.compile(
            r"\b(appointment|meeting|booking|reservation|schedule|"
            r"calendar|registration|sign.?up)\b",
            re.IGNORECASE,
        )

    # ──────────────────────────────────────────────────────
    # Keyword matchers
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _any_kw(msg: str, kws: list) -> bool:
        return any(kw in msg for kw in kws)

    @staticmethod
    def _count_kw(msg: str, kws: list) -> int:
        return sum(1 for kw in kws if kw in msg)

    @classmethod
    def _any_rx(cls, msg: str, rxs: list) -> bool:
        return any(rx.search(msg) for rx in rxs)

    @classmethod
    def _matched_rx(cls, msg: str, rxs: list) -> List[str]:
        """Return the actual patterns that matched (for explainability)."""
        return [rx.pattern for rx in rxs if rx.search(msg)]

    # ──────────────────────────────────────────────────────
    # Signal detection  (returns what matched, not just bool)
    # ──────────────────────────────────────────────────────

    def _detect_signals(self, msg: str) -> Dict:
        """Detect all keyword/pattern signals. Used by rules AND explainer."""
        return {
            "fear_kw": [kw for kw in self.FEAR_KW if kw in msg],
            "deadline_kw": [kw for kw in self.DEADLINE_KW if kw in msg],
            "gov_kw": [kw for kw in self.GOV_KW if kw in msg],
            "identity_rx": self._matched_rx(msg, self._IDENTITY_RX),
            "brand_kw": [kw for kw in self.BRAND_KW if kw in msg],
            "authority_kw": [
                kw for kw in self.AUTHORITY_KW
                if kw in msg and not self._auth_benign_rx.search(msg)
            ],
            "sensitive_rx": self._matched_rx(msg, self._SENSITIVE_RX),
            "reward_kw": [kw for kw in self.REWARD_KW if kw in msg],
            "has_verify_confirm": (
                ("verify" in msg or "confirm" in msg)
                and not self._verify_benign_rx.search(msg)
            ),
        }

    # ──────────────────────────────────────────────────────
    # Whitelist
    # ──────────────────────────────────────────────────────

    def _is_whitelisted(self, msg: str, signals: Dict) -> bool:
        if signals["fear_kw"] or signals["sensitive_rx"]:
            return False
        return any(rx.search(msg) for rx in self._whitelist_rx)

    # ──────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────

    def analyze_message(self, message: str) -> Dict:
        msg = message.lower()
        signals = self._detect_signals(msg)

        if self._is_whitelisted(msg, signals):
            return self._safe_result()

        rag = self.rag_detector.detect(message)
        rule_conf, rule_cats = self._rule_engine(signals)

        return self._ensemble(message, rag, rule_conf, rule_cats, signals)

    # ══════════════════════════════════════════════════════
    #  RULE ENGINE — owns category classification
    # ══════════════════════════════════════════════════════

    def _rule_engine(self, sig: Dict) -> Tuple[float, List[str]]:
        score = 0.0

        # Fear/threat
        n_fear = len(sig["fear_kw"])
        if n_fear >= 1:
            score += 0.35
        if n_fear >= 2:
            score += 0.15

        # Deadline/urgency
        if sig["deadline_kw"]:
            score += 0.25

        # Impersonation (identity or brand)
        if sig["identity_rx"] or sig["brand_kw"]:
            score += 0.20

        # Authority
        if sig["authority_kw"]:
            score += 0.20

        # Sensitive info request
        if sig["sensitive_rx"]:
            score += 0.25

        # Reward lure
        if sig["reward_kw"]:
            score += 0.20

        # Verify/confirm suspicious
        if sig["has_verify_confirm"]:
            score += 0.10

        score = min(score, 1.0)

        # Category detection (priority ordered, max 2)
        cats: List[str] = []

        if sig["fear_kw"]:
            cats.append("fear_threat")

        if sig["identity_rx"] or sig["brand_kw"]:
            cats.append("impersonation")

        if sig["authority_kw"]:
            cats.append("authority")

        if sig["deadline_kw"]:
            cats.append("urgency")

        if sig["reward_kw"]:
            cats.append("reward_lure")

        # OVERRIDE: impersonation + sensitive info → inject fear_threat
        if "impersonation" in cats and sig["sensitive_rx"]:
            if "fear_threat" not in cats:
                cats.insert(0, "fear_threat")

        if sig["has_verify_confirm"] and not cats:
            cats.append("impersonation")

        if not cats:
            cats.append("unknown")

        # Deduplicate, max 2
        seen: List[str] = []
        for c in cats:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break

        return score, seen

    # ══════════════════════════════════════════════════════
    #  ENSEMBLE
    # ══════════════════════════════════════════════════════

    def _ensemble(
        self,
        message: str,
        rag: Dict,
        rule_conf: float,
        rule_cats: List[str],
        signals: Dict,
    ) -> Dict:

        rag_conf = rag["confidence_score"]

        # Step 1: weighted combination
        raw_final = (self.w_rag * rag_conf) + (self.w_rule * rule_conf)

        # Step 2: merge categories — rules authoritative, RAG supplementary
        rag_cat = rag.get("category", "unknown")
        cats = list(rule_cats)
        if rag_cat not in cats and rag_cat != "unknown":
            cats.append(rag_cat)

        cats = [
            "fear_threat" if c in ("psychological_coercion", "fear_threat_severe") else c
            for c in cats
        ]
        seen: List[str] = []
        for c in cats:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break
        cats = seen or ["unknown"]

        # Ensure fear_threat is primary when fear keywords exist
        n_fear = len(signals["fear_kw"])
        if n_fear >= 1 and "fear_threat" not in cats:
            cats.insert(0, "fear_threat")
            cats = cats[:2]
        elif n_fear >= 1 and cats[0] != "fear_threat":
            cats.remove("fear_threat")
            cats.insert(0, "fear_threat")
            cats = cats[:2]

        # Step 3: severity floors
        final = raw_final
        has_gov = bool(signals["gov_kw"])
        has_sens = bool(signals["sensitive_rx"])
        has_dl = bool(signals["deadline_kw"])

        if has_gov:
            final = max(final, 0.70)
        if has_sens and has_dl:
            final = max(final, 0.65)
        if has_sens and (signals["identity_rx"] or signals["brand_kw"]):
            final = max(final, 0.65)
        if n_fear >= 2:
            final = max(final, 0.60)
        if n_fear >= 1 and has_dl:
            final = max(final, 0.60)
        if n_fear >= 1:
            final = max(final, 0.40)
        if rule_conf > 0.70 and "fear_threat" in cats:
            final = max(final, 0.65)

        final = round(max(0.0, min(1.0, final)), 4)
        is_attack = final > 0.35

        risk = self._risk_level(final, cats)

        # Compute display values
        rag_c = round(self.w_rag * rag_conf, 4)
        rule_c = round(self.w_rule * rule_conf, 4)

        return {
            "is_social_engineering": is_attack,
            "confidence_score": final,
            "category": cats[0],
            "categories": cats,
            "details": {
                "rag_confidence": round(rag_conf, 4),
                "rule_confidence": round(rule_conf, 4),
                "confidence_breakdown": {
                    "rag_weight": self.w_rag,
                    "rag_contribution": rag_c,
                    "rule_weight": self.w_rule,
                    "rule_contribution": rule_c,
                    "raw_ensemble": round(rag_c + rule_c, 4),
                    "formula": f"(0.65 × {rag_conf:.4f}) + (0.35 × {rule_conf:.4f})"
                               f" = {rag_c:.4f} + {rule_c:.4f}"
                               f" = {round(rag_c + rule_c, 4):.4f}",
                },
                "similar_patterns": rag.get("similar_patterns", []),
            },
            "risk_level": risk,
            "explanation": self._explain(cats, signals, final, risk),
            "signals": signals,  # exposed for evaluation
        }

    # ══════════════════════════════════════════════════════
    #  RISK LEVEL
    # ══════════════════════════════════════════════════════

    @staticmethod
    def _risk_level(conf: float, cats: List[str]) -> str:
        if "fear_threat" in cats and conf >= 0.60:
            return "CRITICAL" if conf >= 0.85 else "HIGH"
        if conf >= 0.85:
            return "CRITICAL"
        if conf >= 0.70:
            return "HIGH"
        if conf >= 0.55:
            return "MEDIUM"
        if conf >= 0.35:
            return "LOW"
        return "SAFE"

    # ══════════════════════════════════════════════════════
    #  EXPLAINABILITY ENGINE
    # ══════════════════════════════════════════════════════

    @staticmethod
    def _explain(cats: List[str], sig: Dict, conf: float, risk: str) -> str:
        if conf <= 0.35 and not any([sig["fear_kw"], sig["sensitive_rx"]]):
            return "Message appears legitimate. No significant attack signals detected."

        lines = ["**Why this was flagged:**", ""]

        if "fear_threat" in cats:
            if sig["fear_kw"]:
                lines.append(
                    f"• Contains threat/fear language: "
                    f"_{', '.join(sig['fear_kw'][:5])}_"
                )
            if sig["gov_kw"]:
                lines.append(
                    f"• References government/legal authority: "
                    f"_{', '.join(sig['gov_kw'][:3])}_"
                )

        if "impersonation" in cats:
            parts = []
            if sig["identity_rx"]:
                parts.append("identity claim detected")
            if sig["brand_kw"]:
                parts.append(f"brand name: {', '.join(sig['brand_kw'][:3])}")
            if parts:
                lines.append(f"• Impersonation signals: _{'; '.join(parts)}_")

        if "authority" in cats and sig["authority_kw"]:
            lines.append(
                f"• Abuses authority title: "
                f"_{', '.join(sig['authority_kw'][:3])}_"
            )

        if "urgency" in cats and sig["deadline_kw"]:
            lines.append(
                f"• Creates urgency pressure: "
                f"_{', '.join(sig['deadline_kw'][:3])}_"
            )

        if "reward_lure" in cats and sig["reward_kw"]:
            lines.append(
                f"• Uses reward-based lure: "
                f"_{', '.join(sig['reward_kw'][:3])}_"
            )

        if sig["sensitive_rx"]:
            lines.append("• Requests sensitive information (credentials/financial)")

        if len(lines) == 2:  # only header + blank
            lines.append("• Semantic similarity to known attack patterns is high.")

        return "\n".join(lines)

    # ══════════════════════════════════════════════════════
    #  SAFE RESULT
    # ══════════════════════════════════════════════════════

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
                    "rag_weight": self.w_rag,
                    "rag_contribution": 0.0,
                    "rule_weight": self.w_rule,
                    "rule_contribution": 0.0,
                    "raw_ensemble": 0.0,
                    "formula": "(0.65 × 0.0000) + (0.35 × 0.0000) = 0.0000",
                },
                "similar_patterns": [],
            },
            "risk_level": "SAFE",
            "explanation": "Message is informational and matches known safe patterns.",
            "signals": {},
        }