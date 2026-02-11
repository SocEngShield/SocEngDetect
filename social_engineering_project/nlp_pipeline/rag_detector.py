"""
RAG-based Social Engineering Detection using Embeddings
v2.0 — Improved calibration, reduced false negatives, fear_threat dominance
"""

import math
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import Dict, List, Tuple
from sklearn.metrics.pairwise import cosine_similarity


class RAGSocialEngineeringDetector:
    """
    Uses Retrieval Augmented Generation (RAG) approach for detecting social engineering.
    v2.0: Better sigmoid calibration, neighbor agreement boost, minimum
    similarity threshold, fear_threat dominance logic.
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
        "leaked", "breach",
    ]

    # ── Deadline / immediacy words ──
    DEADLINE_KEYWORDS = [
        "immediately", "within 24 hours", "within 48 hours", "today",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
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
                "category": p["category"] if p["category"] != "psychological_coercion" else "fear_threat",
                "base_confidence": p["confidence"],
            }
            for p in patterns
        ]

        print(f"Added {len(patterns)} patterns to knowledge base")

    # ─────────────────────────────────────────────────────────────
    # Threat keyword helpers
    # ─────────────────────────────────────────────────────────────

    def _count_threat_keywords(self, msg_lower: str) -> int:
        """Count how many severe threat keywords appear in the message."""
        return sum(1 for kw in self.THREAT_KEYWORDS_SEVERE if kw in msg_lower)

    def _has_deadline(self, msg_lower: str) -> bool:
        """Check if message contains deadline / immediacy words."""
        return any(kw in msg_lower for kw in self.DEADLINE_KEYWORDS)

    def _should_override_fear_threat(self, msg_lower: str) -> bool:
        """Check if fear_threat should dominate category regardless of RAG."""
        return any(kw in msg_lower for kw in self.FEAR_OVERRIDE_KEYWORDS)

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

        # ── Sigmoid calibration (v2: gentler slope, lower midpoint) ──
        #    steepness=10 (was 12), midpoint=0.42 (was 0.45)
        if best_sim <= 0:
            calibrated = 0.0
        else:
            calibrated = 1 / (1 + math.exp(-10 * (best_sim - 0.42)))
            calibrated *= 0.92

        # ── Minimum similarity threshold ──
        if best_sim < 0.35:
            calibrated = min(calibrated, 0.20)

        if is_informational:
            calibrated = min(calibrated, 0.35)

        calibrated_confidence = round(calibrated, 4)

        # ── Build results structure ──
        results = {
            "documents": [[self.patterns[i] for i in top_indices]],
            "distances": [[1 - similarities[i] for i in top_indices]],
            "metadatas": [[self.metadatas[i] for i in top_indices]],
        }

        vote_conf, is_attack, category = self._calculate_confidence(results)

        # ── Normalize legacy category ──
        if category == "psychological_coercion":
            category = "fear_threat"

        # ── FEAR_THREAT dominance: override category if threat keywords present ──
        if self._should_override_fear_threat(msg_lower) and category in (
            "impersonation", "urgency", "unknown"
        ):
            category = "fear_threat"

        # ── Neighbor agreement boost ──
        attack_neighbors = sum(
            1 for m in results["metadatas"][0]
            if m["label"] == "social_engineering"
        )
        agreement_ratio = attack_neighbors / max(len(results["metadatas"][0]), 1)

        if agreement_ratio >= 0.7 and calibrated_confidence > 0.3:
            calibrated_confidence = min(
                round(calibrated_confidence * 1.15, 4), 0.95
            )

        # ── Threat keyword confidence floor (false-negative reduction) ──
        has_deadline = self._has_deadline(msg_lower)

        if threat_count >= 2 and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.75)
            is_attack = True
        elif threat_count >= 2:
            calibrated_confidence = max(calibrated_confidence, 0.65)
            is_attack = True
        elif threat_count >= 1 and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.60)
            is_attack = True

        # ── Threat severity multiplier ──
        if threat_count >= 1:
            calibrated_confidence = min(
                round(calibrated_confidence * 1.25, 4), 0.98
            )
            if category not in ("fear_threat",):
                category = "fear_threat"

        similar_patterns = results["documents"][0]
        distances = results["distances"][0]

        return {
            "is_social_engineering": is_attack and not is_informational,
            "confidence_score": calibrated_confidence,
            "raw_similarity": raw_similarity,
            "calibrated_confidence": calibrated_confidence,
            "category": category,
            "similar_patterns": [
                {"pattern": p, "similarity": round(1 - d, 4)}
                for p, d in zip(similar_patterns[:3], distances[:3])
            ],
            "explanation": self._generate_explanation(
                is_attack and not is_informational,
                category,
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

            if cat == "psychological_coercion":
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
        self, is_attack: bool, category: str, confidence: float
    ) -> str:
        if not is_attack:
            return (
                f"Message appears legitimate with "
                f"{(1 - confidence) * 100:.1f}% confidence"
            )

        explanations = {
            "urgency": "The message pressures immediate action using urgency",
            "reward_lure": "The message promises rewards to manipulate the user",
            "authority": "The message abuses authority to force compliance",
            "impersonation": "The message pretends to be from a trusted source",
            "fear_threat": "The message uses fear, threats, or coercion to force action",
        }

        return (
            f"{explanations.get(category, 'Suspicious social engineering detected')}. "
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