"""
RAG-based Social Engineering Detection using Embeddings
v2.1 — RAG focuses on CONFIDENCE ESTIMATION; category resolution
       is delegated to integrated_detector.
"""

import math
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import Dict, List, Tuple
from sklearn.metrics.pairwise import cosine_similarity


class RAGSocialEngineeringDetector:
    """
    RAG detector responsibilities (v2.1):
      • Encode message → retrieve top-K neighbors
      • Produce calibrated confidence (sigmoid + floors)
      • Return neighbor-voted category as a SIGNAL (not final)
      • Apply threat-keyword floors to prevent false negatives

    Category resolution is handled by IntegratedDetector.
    """

    # ── Threat keywords (confidence floors only, NOT category override) ──
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
        "leaked", "breach", "income tax", "frozen",
        "permanently", "deactivated",
    ]

    DEADLINE_KEYWORDS = [
        "immediately", "within 24 hours", "within 48 hours", "today",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "in 10 minutes", "30 minutes",
        "in 30 minutes", "last warning", "last chance", "expires",
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
                    "fear_threat"
                    if p["category"] in ("psychological_coercion", "fear_threat_severe")
                    else p["category"]
                ),
                "base_confidence": p["confidence"],
            }
            for p in patterns
        ]

        print(f"Added {len(patterns)} patterns to knowledge base")

    # ─────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────

    def _count_threat_keywords(self, msg_lower: str) -> int:
        return sum(1 for kw in self.THREAT_KEYWORDS_SEVERE if kw in msg_lower)

    def _has_deadline(self, msg_lower: str) -> bool:
        return any(kw in msg_lower for kw in self.DEADLINE_KEYWORDS)

    # ─────────────────────────────────────────────────────────────
    # Main detect — returns confidence + neighbor-voted category
    # ─────────────────────────────────────────────────────────────

    def detect(self, message: str, top_k: int = 5) -> Dict:
        message_embedding = self.embedding_model.encode(
            [message], show_progress_bar=False
        )[0].reshape(1, -1)

        similarities = cosine_similarity(message_embedding, self.embeddings)[0]
        top_indices = np.argsort(similarities)[::-1][:top_k]

        best_sim = float(similarities[top_indices[0]]) if top_indices.size else 0.0

        msg_lower = message.lower()

        # ── Informational suppression ──
        informational_phrases = [
            "announced", "reported", "mentioned",
            "during today", "presentation", "product launch",
            "press release", "scheduled maintenance",
            "no action required", "no action is needed",
        ]
        is_informational = any(p in msg_lower for p in informational_phrases)

        threat_count = self._count_threat_keywords(msg_lower)
        if threat_count >= 1:
            is_informational = False

        # ── Sigmoid calibration (v2.1: steepness=9, midpoint=0.40) ──
        if best_sim <= 0:
            calibrated = 0.0
        else:
            calibrated = 1 / (1 + math.exp(-9 * (best_sim - 0.40)))
            calibrated *= 0.92

        # ── Low-similarity cap ──
        if best_sim < 0.30:
            calibrated = min(calibrated, 0.15)

        if is_informational:
            calibrated = min(calibrated, 0.35)

        calibrated_confidence = round(calibrated, 4)

        # ── Build neighbor results ──
        results = {
            "documents": [[self.patterns[i] for i in top_indices]],
            "distances": [[1 - similarities[i] for i in top_indices]],
            "metadatas": [[self.metadatas[i] for i in top_indices]],
        }

        vote_conf, is_attack, voted_category = self._calculate_confidence(results)

        if voted_category in ("psychological_coercion", "fear_threat_severe"):
            voted_category = "fear_threat"

        # ── Neighbor agreement boost (v2.1: 1.18x, threshold 0.25) ──
        attack_neighbors = sum(
            1 for m in results["metadatas"][0]
            if m["label"] == "social_engineering"
        )
        agreement_ratio = attack_neighbors / max(len(results["metadatas"][0]), 1)

        if agreement_ratio >= 0.7 and calibrated_confidence > 0.25:
            calibrated_confidence = min(
                round(calibrated_confidence * 1.18, 4), 0.95
            )

        # ── Threat-keyword confidence floors (NOT category override) ──
        has_deadline = self._has_deadline(msg_lower)

        if threat_count >= 2 and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.75)
            is_attack = True
        elif threat_count >= 2:
            calibrated_confidence = max(calibrated_confidence, 0.60)
            is_attack = True
        elif threat_count >= 1 and has_deadline:
            calibrated_confidence = max(calibrated_confidence, 0.55)
            is_attack = True
        elif threat_count >= 1:
            calibrated_confidence = max(calibrated_confidence, 0.40)
            is_attack = True

        similar_patterns = results["documents"][0]
        distances = results["distances"][0]

        return {
            "is_social_engineering": is_attack and not is_informational,
            "confidence_score": calibrated_confidence,
            "calibrated_confidence": calibrated_confidence,
            # Neighbor-voted category — a SIGNAL for integrated_detector
            "category": voted_category,
            "similar_patterns": [
                {"pattern": p, "similarity": round(1 - d, 4)}
                for p, d in zip(similar_patterns[:3], distances[:3])
            ],
            "explanation": self._generate_explanation(
                is_attack and not is_informational,
                voted_category,
                calibrated_confidence,
            ),
        }

    # ─────────────────────────────────────────────────────────────
    # Neighbor voting
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