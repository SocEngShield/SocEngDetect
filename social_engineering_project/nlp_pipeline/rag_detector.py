"""
RAG-based Social Engineering Detection using Embeddings
v3.0 — Multi-label categories, improved calibration, reduced false negatives,
       fear_threat dominance, government authority floors
"""

import math
import re
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import Dict, List, Tuple
from sklearn.metrics.pairwise import cosine_similarity


class RAGSocialEngineeringDetector:
    """
    Uses Retrieval Augmented Generation (RAG) approach for detecting social engineering.
    v3.0: Multi-label (up to 2 categories), gentler sigmoid, stronger neighbor
    agreement, government authority confidence floor, impersonation identity detection.
    """

    # ── High-severity threat keywords (used for false-negative reduction) ──
    THREAT_KEYWORDS_SEVERE = [
        "legal action", "court", "police", "fir filed", "fir has been filed",
        "arrest", "investigation", "permanently closed", "terminated",
        "account frozen", "account has been frozen", "service termination",
        "aadhaar misuse", "aadhaar", "pan blocked", "pan card",
        "sim deactivated", "sim card", "bank account frozen",
        "money laundering", "prosecution", "seized", "non-bailable",
        "blacklisted", "look-out notice", "cyber cell",
        "suspended", "hacked", "compromised", "ransomware",
        "encrypted", "dark web", "webcam", "browsing activity",
        "leaked", "breach", "income tax", "deactivated", "frozen",
        "action will be taken", "permanently",
    ]

    # ── Deadline / immediacy words ──
    DEADLINE_KEYWORDS = [
        "immediately", "within 24 hours", "within 48 hours", "today",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "30 minutes", "in 10 minutes",
        "in 30 minutes", "expires", "last warning", "last chance",
    ]

    # ── Fear_threat override keywords (force category regardless of RAG) ──
    FEAR_OVERRIDE_KEYWORDS = [
        "legal action", "permanently closed", "terminated", "court",
        "police", "fir", "investigation", "account frozen",
        "service termination", "aadhaar misuse", "aadhaar",
        "pan blocked", "pan card", "sim deactivated", "arrest",
        "prosecution", "seized", "money laundering", "non-bailable",
        "suspended", "hacked", "compromised", "ransomware",
        "encrypted", "webcam", "dark web", "leaked",
        "income tax", "deactivated", "frozen", "permanently",
        "action will be taken",
    ]

    # ── Impersonation identity keywords ──
    IMPERSONATION_KEYWORDS = [
        "this is", "from it department", "from it", "customer support",
        "bank team", "support team", "help desk", "helpdesk",
        "technical support", "tech support",
    ]

    # ── Brand impersonation keywords ──
    BRAND_KEYWORDS = [
        "netflix", "amazon", "paypal", "apple", "microsoft",
        "google", "instagram", "linkedin", "dropbox", "spotify",
        "fedex", "your bank", "irs", "income tax department",
    ]

    # ── Authority keywords ──
    AUTHORITY_KEYWORDS = [
        "ceo", "cfo", "cto", "manager", "director", "supervisor",
        "president", "chairman", "head of", "department head",
        "team lead", "executive", "boss", "vp of",
    ]

    # ── Government authority keywords (higher confidence floor) ──
    GOVERNMENT_KEYWORDS = [
        "income tax", "aadhaar", "court", "police", "fir",
        "prosecution", "arrest", "non-bailable", "cyber cell",
        "irs", "tax department", "government",
    ]

    # ── Sensitive info request keywords ──
    SENSITIVE_INFO_KEYWORDS = [
        "password", "credential", "login", "card detail", "bank detail",
        "ssn", "social security", "otp", "pin", "cvv",
        "account number", "routing number", "financial detail",
        "share your", "send your", "provide your", "submit your",
        "confirm your", "verify your identity",
    ]

    # ── Reward keywords ──
    REWARD_KEYWORDS = [
        "discount", "90%", "winner", "gift", "won", "prize",
        "reward", "claim", "free", "cashback", "lottery",
        "selected", "chosen", "bonus",
    ]

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        print(f"Loading embedding model: {model_name}")
        self.embedding_model = SentenceTransformer(model_name)

        self.patterns: List[str] = []
        self.embeddings = None
        self.metadatas: List[Dict] = []

        print("RAG Detector initialized successfully!")

    def add_patterns_to_knowledge_base(self, patterns: List[Dict]):
        texts = [p["text"] for p in patterns]

        embeddings = self.embedding_model.encode(
            texts, convert_to_tensor=False, show_progress_bar=False
        )

        self.patterns = texts
        self.embeddings = np.array(embeddings)
        self.metadatas = [
            {
                "label": p["label"],
                "category": (
                    p["category"]
                    if p["category"] not in ("psychological_coercion", "fear_threat_severe")
                    else "fear_threat"
                ),
                "base_confidence": p["confidence"],
            }
            for p in patterns
        ]

        print(f"Added {len(patterns)} patterns to knowledge base")

    # ─────────────────────────────────────────────────────────────
    # Keyword helpers
    # ─────────────────────────────────────────────────────────────

    def _count_threat_keywords(self, msg_lower: str) -> int:
        return sum(1 for kw in self.THREAT_KEYWORDS_SEVERE if kw in msg_lower)

    def _has_deadline(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.DEADLINE_KEYWORDS)

    def _should_override_fear_threat(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.FEAR_OVERRIDE_KEYWORDS)

    def _has_impersonation(self, msg_lower: str) -> bool:
        return (
            any(kw in msg_lower for kw in self.IMPERSONATION_KEYWORDS)
            or any(kw in msg_lower for kw in self.BRAND_KEYWORDS)
        )

    def _has_authority(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.AUTHORITY_KEYWORDS)

    def _has_government(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.GOVERNMENT_KEYWORDS)

    def _has_sensitive_info_request(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.SENSITIVE_INFO_KEYWORDS)

    def _has_reward(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.REWARD_KEYWORDS)

    # ─────────────────────────────────────────────────────────────
    # Multi-label category detection (max 2)
    # ─────────────────────────────────────────────────────────────

    def _detect_categories(self, msg_lower: str, rag_category: str) -> List[str]:
        """
        Detect up to 2 categories using priority:
        fear_threat > impersonation > authority > urgency > reward_lure
        """
        candidates = []

        has_fear = self._should_override_fear_threat(msg_lower)
        has_impersonation = self._has_impersonation(msg_lower)
        has_authority = self._has_authority(msg_lower)
        has_deadline = self._has_deadline(msg_lower)
        has_reward = self._has_reward(msg_lower)

        # Priority-ordered detection
        if has_fear:
            candidates.append("fear_threat")
        if has_impersonation:
            candidates.append("impersonation")
        if has_authority and "impersonation" not in candidates:
            candidates.append("authority")
        elif has_authority and "authority" not in candidates:
            candidates.append("authority")
        if has_deadline and "urgency" not in candidates:
            candidates.append("urgency")
        if has_reward and "reward_lure" not in candidates:
            candidates.append("reward_lure")

        # If no keyword-based categories, use RAG category
        if not candidates:
            if rag_category and rag_category != "unknown":
                candidates.append(rag_category)
            else:
                candidates.append("unknown")

        # Return max 2, deduplicated, priority-ordered
        seen = []
        for c in candidates:
            if c not in seen:
                seen.append(c)
            if len(seen) == 2:
                break

        return seen

    # ─────────────────────────────────────────────────────────────
    # Main detect
    # ─────────────────────────────────────────────────────────────

    def detect(self, message: str, top_k: int = 5) -> Dict:
        message_embedding = self.embedding_model.encode(
            [message], show_progress_bar=False
        )[0].reshape(1, -1)

        similarities = cosine_similarity(message_embedding, self.embeddings)[0]
        top_indices = np.argsort(similarities)[::-1][:top_k]

        best_sim = float(similarities[top_indices[0]]) if top_indices.size else 0.0
        raw_similarity = round(best_sim, 4)

        msg_lower = message.lower()

        # ── Informational / safe context suppression ──
        informational_phrases = [
            "announced", "reported", "mentioned", "shared",
            "during today", "presentation", "product launch",
            "press release", "scheduled maintenance",
            "no action required", "no action is needed",
        ]
        is_informational = any(p in msg_lower for p in informational_phrases)

        # If message also has threat keywords, it is NOT informational
        threat_count = self._count_threat_keywords(msg_lower)
        if threat_count >= 1:
            is_informational = False

        # ── Sigmoid calibration (v3: gentler slope, lower midpoint) ──
        #    steepness=8 (was 10), midpoint=0.40 (was 0.42)
        if best_sim <= 0:
            calibrated = 0.0
        else:
            calibrated = 1 / (1 + math.exp(-8 * (best_sim - 0.40)))
            calibrated *= 0.92

        # ── Minimum similarity threshold (v3: lowered to 0.30) ──
        if best_sim < 0.30:
            calibrated = min(calibrated, 0.15)

        if is_informational:
            calibrated = min(calibrated, 0.35)

        calibrated_confidence = round(calibrated, 4)

        # ── Build results structure ──
        results = {
            "documents": [[self.patterns[i] for i in top_indices]],
            "distances": [[1 - similarities[i] for i in top_indices]],
            "metadatas": [[self.metadatas[i] for i in top_indices]],
        }

        vote_conf, is_attack, rag_category = self._calculate_confidence(results)

        # ── Normalize legacy category ──
        if rag_category in ("psychological_coercion", "fear_threat_severe"):
            rag_category = "fear_threat"

        # ── Multi-label category detection ──
        categories = self._detect_categories(msg_lower, rag_category)
        primary_category = categories[0]

        # ── Neighbor agreement boost (v3: stronger — 1.20×) ──
        attack_neighbors = sum(
            1 for m in results["metadatas"][0]
            if m["label"] == "social_engineering"
        )
        agreement_ratio = attack_neighbors / max(len(results["metadatas"][0]), 1)

        if agreement_ratio >= 0.7 and calibrated_confidence > 0.25:
            calibrated_confidence = min(
                round(calibrated_confidence * 1.20, 4), 0.95
            )

        # ── Threat keyword confidence floor (false-negative reduction) ──
        has_deadline = self._has_deadline(msg_lower)
        has_government = self._has_government(msg_lower)
        has_sensitive = self._has_sensitive_info_request(msg_lower)
        has_impersonation = self._has_impersonation(msg_lower)

        # Government authority floor: 0.70
        if has_government:
            calibrated_confidence = max(calibrated_confidence, 0.70)
            is_attack = True

        # Financial + urgency floor: 0.65
        if has_sensitive and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.65)
            is_attack = True

        # Impersonation + sensitive info floor: 0.65
        if has_impersonation and has_sensitive:
            calibrated_confidence = max(calibrated_confidence, 0.65)
            is_attack = True

        # 2+ threat keywords + deadline: 0.75
        if threat_count >= 2 and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.75)
            is_attack = True
        elif threat_count >= 2:
            calibrated_confidence = max(calibrated_confidence, 0.65)
            is_attack = True
        elif threat_count >= 1 and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.60)
            is_attack = True

        # ── At least 1 strong threat keyword = minimum "Potential Threat" ──
        if threat_count >= 1:
            is_attack = True

        # ── Threat severity multiplier ──
        if threat_count >= 1:
            calibrated_confidence = min(
                round(calibrated_confidence * 1.25, 4), 0.98
            )
            if "fear_threat" not in categories:
                categories.insert(0, "fear_threat")
                if len(categories) > 2:
                    categories = categories[:2]
                primary_category = "fear_threat"

        similar_patterns = results["documents"][0]
        distances = results["distances"][0]

        return {
            "is_social_engineering": is_attack and not is_informational,
            "confidence_score": calibrated_confidence,
            "raw_similarity": raw_similarity,
            "calibrated_confidence": calibrated_confidence,
            "category": primary_category,
            "categories": categories,
            "similar_patterns": [
                {"pattern": p, "similarity": round(1 - d, 4)}
                for p, d in zip(similar_patterns[:3], distances[:3])
            ],
            "explanation": self._generate_explanation(
                is_attack and not is_informational,
                categories,
                calibrated_confidence,
            ),
        }

    # ─────────────────────────────────────────────────────────────
    # Confidence calculation (neighbor voting)
    # ─────────────────────────────────────────────────────────────

    def _calculate_confidence(self, results: Dict) -> Tuple[float, bool, str]:
        if not results["distances"]:
            return 0.0, False, "unknown"

        similarities = [1 - d for d in results["distances"][0]]
        metadatas = results["metadatas"][0]

        attack_score = 0.0
        legit_score = 0.0
        category_scores: Dict[str, float] = {}

        for sim, meta in zip(similarities, metadatas):
            weight = sim * float(meta["base_confidence"])
            cat = meta["category"]

            if cat in ("psychological_coercion", "fear_threat_severe"):
                cat = "fear_threat"

            if meta["label"] == "social_engineering":
                attack_score += weight
                category_scores[cat] = category_scores.get(cat, 0) + weight
            else:
                legit_score += weight

        total = attack_score + legit_score
        attack_conf = attack_score / total if total > 0 else 0.0

        is_attack = attack_conf > 0.55
        category = (
            max(category_scores, key=category_scores.get)
            if category_scores
            else "unknown"
        )

        return attack_conf, is_attack, category

    # ─────────────────────────────────────────────────────────────
    # Explanation
    # ─────────────────────────────────────────────────────────────

    def _generate_explanation(
        self, is_attack: bool, categories: List[str], confidence: float
    ) -> str:
        if not is_attack:
            return (
                f"Message appears legitimate with "
                f"{(1 - confidence) * 100:.1f}% confidence"
            )

        explanations = {
            "urgency": "pressures immediate action using urgency",
            "reward_lure": "promises rewards to manipulate the user",
            "authority": "abuses authority to force compliance",
            "impersonation": "pretends to be from a trusted source",
            "fear_threat": "uses fear, threats, or coercion to force action",
        }

        parts = []
        for cat in categories:
            desc = explanations.get(cat, "uses suspicious social engineering tactics")
            parts.append(desc)

        combined = " and ".join(parts)
        return (
            f"The message {combined}. "
            f"Confidence: {confidence * 100:.1f}%"
        )


# ─────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────

_detector_instance = None


def get_detector() -> RAGSocialEngineeringDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = RAGSocialEngineeringDetector()
    return _detector_instance