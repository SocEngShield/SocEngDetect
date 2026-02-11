"""
Integrated Social Engineering Detector — v5.0 STRICT.
Output contains ONLY the 7 required keys. No extras.
Weights: 0.6 RAG + 0.4 Rules. Risk: SAFE/LOW/POTENTIAL/HIGH.
"""

import re
from typing import Dict, List, Tuple

try:
    from .rag_detector import get_detector
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nlp_pipeline.rag_detector import get_detector


class IntegratedSocialEngineeringDetector:

    # ═══════════════════════════════════════════════════
    #  KEYWORD REGISTRIES
    # ═══════════════════════════════════════════════════

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
        "action will be taken","credentials","share info",
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

    _IDENTITY_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bthis is\b", r"\bi am\b", r"\bi'm\b", r"\bwe are\b",
            r"\bfrom it department\b", r"\bfrom it\b",
            r"\bcustomer support\b", r"\bbank team\b",
            r"\bsupport team\b", r"\bhelp\s?desk\b",
            r"\btechnical support\b", r"\btech support\b",
            r"\bamazon support\b", r"\bamazon customer support\b",
        ]
    ]

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

    _SENSITIVE_RX = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bpassword\b", r"\bcredential", r"\blogin\b",
            r"\bcard detail", r"\bbank detail", r"\bfinancial detail",
            r"\bsubmit financial\b", r"\bssn\b", r"\bsocial security\b",
            r"\botp\b", r"\bpin\b", r"\bcvv\b", r"\baccount number\b",
            r"\brouting number\b", r"\bshare your\b", r"\bsend your\b",
            r"\bprovide your\b", r"\bsubmit your\b",
            r"\bconfirm your card\b", r"\bconfirm card\b",
            r"\blogin credential", r"\bverify your identity\b",
        ]
    ]

    REWARD_KW = [
        "won", "winner", "prize", "reward", "free", "gift",
        "discount", "cashback", "lottery", "selected", "chosen",
        "bonus", "90%",
    ]

    # ═══════════════════════════════════════════════════

    def __init__(self):
        self.rag = get_detector()

        self._whitelist_rx = [
            re.compile(p, re.IGNORECASE) for p in [
                r"(ceo|director|manager|president|executive)\s+"
                r"(announced|said|reported|mentioned|shared|presented)",
                r"scheduled\s+(meeting|maintenance)",
                r"product\s+launch", r"press\s+release",
                r"no\s+action\s+(required|needed|is needed)",
                r"confirm\s+(your\s+)?(appointment|meeting|booking|reservation)",
                r"verify\s+(your\s+)?email\s+(address\s+)?to\s+complete",
            ]
        ]
        self._auth_benign = re.compile(
            r"\b(announced|said|reported|mentioned|shared|presented|discussed)\b",
            re.IGNORECASE,
        )
        self._verify_benign = re.compile(
            r"\b(appointment|meeting|booking|reservation|schedule|"
            r"calendar|registration|sign.?up)\b",
            re.IGNORECASE,
        )

    # ───────────────────────────────────────────────
    # Helpers
    # ───────────────────────────────────────────────

    @staticmethod
    def _any(msg: str, kws: list) -> bool:
        return any(kw in msg for kw in kws)

    @staticmethod
    def _count(msg: str, kws: list) -> int:
        return sum(1 for kw in kws if kw in msg)

    @classmethod
    def _any_rx(cls, msg: str, rxs: list) -> bool:
        return any(rx.search(msg) for rx in rxs)

    # ───────────────────────────────────────────────
    # Signal extraction
    # ───────────────────────────────────────────────

    def _signals(self, msg: str) -> Dict:
        return {
            "fear": [kw for kw in self.FEAR_KW if kw in msg],
            "deadline": [kw for kw in self.DEADLINE_KW if kw in msg],
            "gov": [kw for kw in self.GOV_KW if kw in msg],
            "identity": any(rx.search(msg) for rx in self._IDENTITY_RX),
            "brand": [kw for kw in self.BRAND_KW if kw in msg],
            "authority": [
                kw for kw in self.AUTHORITY_KW
                if kw in msg and not self._auth_benign.search(msg)
            ],
            "sensitive": any(rx.search(msg) for rx in self._SENSITIVE_RX),
            "reward": [kw for kw in self.REWARD_KW if kw in msg],
            "verify_suspicious": (
                ("verify" in msg or "confirm" in msg)
                and not self._verify_benign.search(msg)
            ),
        }

    # ───────────────────────────────────────────────
    # Whitelist
    # ───────────────────────────────────────────────

    def _whitelisted(self, msg: str, sig: Dict) -> bool:
        if sig["fear"] or sig["sensitive"]:
            return False
        return any(rx.search(msg) for rx in self._whitelist_rx)

    # ───────────────────────────────────────────────
    # Public API  → returns ONLY 7 keys
    # ───────────────────────────────────────────────

    def analyze_message(self, message: str) -> Dict:
        msg = message.lower()
        sig = self._signals(msg)

        if self._whitelisted(msg, sig):
            return {
                "attack_detected": False,
                "categories": [],
                "risk_level": "SAFE",
                "rag_confidence": 0.0,
                "rule_confidence": 0.0,
                "overall_confidence": 0.0,
                "confidence_calculation": (
                    "Overall Confidence = (0.6 × 0.00) + (0.4 × 0.00)\n"
                    "= 0.00 + 0.00\n"
                    "= 0.00%"
                ),
            }

        rag_conf, rag_cat = self.rag.detect(message)
        rule_conf, rule_cats = self._rule_engine(sig)

        return self._combine(msg, rag_conf, rag_cat, rule_conf, rule_cats, sig)

    # ═══════════════════════════════════════════════
    #  RULE ENGINE → rule_confidence (0-100), categories
    # ═══════════════════════════════════════════════

    def _rule_engine(self, sig: Dict) -> Tuple[float, List[str]]:
        score = 0.0

        n_fear = len(sig["fear"])
        if n_fear >= 1:
            score += 35.0
        if n_fear >= 2:
            score += 15.0

        if sig["deadline"]:
            score += 25.0

        if sig["identity"] or sig["brand"]:
            score += 20.0

        if sig["authority"]:
            score += 20.0

        if sig["sensitive"]:
            score += 25.0

        if sig["reward"]:
            score += 20.0

        if sig["verify_suspicious"]:
            score += 10.0

        score = min(score, 100.0)

        # Category detection (priority: fear > impersonation > authority > urgency > reward)
        cats: List[str] = []

        if sig["fear"]:
            cats.append("Fear/Threat")

        if sig["identity"] or sig["brand"]:
            cats.append("Impersonation")

        if sig["authority"]:
            cats.append("Authority")

        if sig["deadline"]:
            cats.append("Urgency")

        if sig["reward"]:
            cats.append("Reward/Lure")

        # Override: impersonation + sensitive → inject Fear/Threat
        if "Impersonation" in cats and sig["sensitive"]:
            if "Fear/Threat" not in cats:
                cats.insert(0, "Fear/Threat")

        if sig["verify_suspicious"] and not cats:
            cats.append("Impersonation")

        # Deduplicate, max 2
        seen: List[str] = []
        for c in cats:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break

        return score, seen

    # ═══════════════════════════════════════════════
    #  COMBINE → strict 7-key output
    # ═══════════════════════════════════════════════

    def _combine(
        self,
        msg: str,
        rag_conf: float,
        rag_cat: str,
        rule_conf: float,
        rule_cats: List[str],
        sig: Dict,
    ) -> Dict:

        # ── Merge categories: rules authoritative, RAG supplementary ──
        CAT_MAP = {
            "fear_threat": "Fear/Threat",
            "impersonation": "Impersonation",
            "authority": "Authority",
            "urgency": "Urgency",
            "reward_lure": "Reward/Lure",
        }
        rag_cat_display = CAT_MAP.get(rag_cat, None)

        cats = list(rule_cats)
        if rag_cat_display and rag_cat_display not in cats:
            cats.append(rag_cat_display)

        # Ensure Fear/Threat is primary when fear keywords exist
        n_fear = len(sig["fear"])
        if n_fear >= 1 and "Fear/Threat" not in cats:
            cats.insert(0, "Fear/Threat")
        elif n_fear >= 1 and cats and cats[0] != "Fear/Threat":
            if "Fear/Threat" in cats:
                cats.remove("Fear/Threat")
            cats.insert(0, "Fear/Threat")

        cats = list(dict.fromkeys(cats))[:2]

        # ── Weighted fusion: 0.6 RAG + 0.4 Rules ──
        rag_part = round(0.6 * rag_conf, 2)
        rule_part = round(0.4 * rule_conf, 2)
        overall = round(rag_part + rule_part, 2)

        # ── Severity floors ──
        has_gov = bool(sig["gov"])
        has_sens = sig["sensitive"]
        has_dl = bool(sig["deadline"])

        if has_gov:
            overall = max(overall, 70.0)
        if has_sens and has_dl:
            overall = max(overall, 65.0)
        if has_sens and (sig["identity"] or sig["brand"]):
            overall = max(overall, 65.0)
        if n_fear >= 2:
            overall = max(overall, 60.0)
        if n_fear >= 1 and has_dl:
            overall = max(overall, 60.0)
        if n_fear >= 1:
            overall = max(overall, 40.0)
        if rule_conf > 70.0 and "Fear/Threat" in cats:
            overall = max(overall, 65.0)

        overall = round(max(0.0, min(100.0, overall)), 2)

        # ── Risk level (strict mapping) ──
        if overall >= 76:
            risk = "HIGH"
        elif overall >= 56:
            risk = "POTENTIAL"
        elif overall >= 31:
            risk = "LOW"
        else:
            risk = "SAFE"

        # Fear/Threat override: conf >= 60 → minimum POTENTIAL
        if "Fear/Threat" in cats and overall >= 60 and risk == "LOW":
            risk = "POTENTIAL"

        attack = overall > 30.0

        # ── Build calculation string ──
        calc = (
            f"Overall Confidence = (0.6 × {rag_conf:.2f}) + (0.4 × {rule_conf:.2f})\n"
            f"= {rag_part:.2f} + {rule_part:.2f}\n"
            f"= {round(rag_part + rule_part, 2):.2f}%"
        )
        if overall != round(rag_part + rule_part, 2):
            calc += f"\nAfter severity floors: {overall:.2f}%"

        return {
            "attack_detected": attack,
            "categories": cats if attack else [],
            "risk_level": risk,
            "rag_confidence": round(rag_conf, 2),
            "rule_confidence": round(rule_conf, 2),
            "overall_confidence": overall,
            "confidence_calculation": calc,
        }