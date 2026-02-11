"""
RAG-based Social Engineering Detection using Embeddings
False-positive controlled version (exam-safe)
"""

import math
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import Dict, List, Tuple
from sklearn.metrics.pairwise import cosine_similarity


class RAGSocialEngineeringDetector:
    """
    Uses Retrieval Augmented Generation (RAG) approach for detecting social engineering.
    Optimized to reduce false positives and resolve urgency / impersonation confusion.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        print(f"Loading embedding model: {model_name}")
        self.embedding_model = SentenceTransformer(model_name)

        self.patterns = []
        self.embeddings = None
        self.metadatas = []

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
                "category": p["category"],
                "base_confidence": p["confidence"],
            }
            for p in patterns
        ]

        print(f"Added {len(patterns)} patterns to knowledge base")

    def detect(self, message: str, top_k: int = 5) -> Dict:
        message_embedding = self.embedding_model.encode(
            [message], show_progress_bar=False
        )[0].reshape(1, -1)

        similarities = cosine_similarity(message_embedding, self.embeddings)[0]
        top_indices = np.argsort(similarities)[::-1][:top_k]

        best_sim = float(similarities[top_indices[0]]) if top_indices.size else 0.0
        raw_similarity = round(best_sim, 4)

        # ── FIX 1: Suppress informational / reporting messages ──
        msg_lower = message.lower()
        informational_phrases = [
            "announced",
            "reported",
            "mentioned",
            "shared",
            "during today",
            "meeting",
            "presentation",
            "product launch",
            "press release",
        ]

        is_informational = any(p in msg_lower for p in informational_phrases)

        # Sigmoid calibration
        if best_sim <= 0:
            calibrated = 0.0
        else:
            calibrated = 1 / (1 + math.exp(-12 * (best_sim - 0.45)))
            calibrated *= 0.90

        if is_informational:
            calibrated = min(calibrated, 0.35)

        calibrated_confidence = round(calibrated, 4)

        results = {
            "documents": [[self.patterns[i] for i in top_indices]],
            "distances": [[1 - similarities[i] for i in top_indices]],
            "metadatas": [[self.metadatas[i] for i in top_indices]],
        }

        vote_conf, is_attack, category = self._calculate_confidence(results)

        if category == "psychological_coercion":
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

    def _calculate_confidence(self, results: Dict) -> Tuple[float, bool, str]:
        if not results["distances"]:
            return 0.0, False, "unknown"

        similarities = [1 - d for d in results["distances"][0]]
        metadatas = results["metadatas"][0]

        attack_score = 0.0
        legit_score = 0.0
        category_scores = {}

        for sim, meta in zip(similarities, metadatas):
            weight = sim * float(meta["base_confidence"])
            category = meta["category"]

            if category == "psychological_coercion":
                category = "fear_threat"

            if meta["label"] == "social_engineering":
                attack_score += weight
                category_scores[category] = category_scores.get(category, 0) + weight
            else:
                legit_score += weight

        total = attack_score + legit_score
        attack_conf = attack_score / total if total > 0 else 0.0

        is_attack = attack_conf > 0.55
        category = max(category_scores, key=category_scores.get) if category_scores else "unknown"

        return attack_conf, is_attack, category

    def _generate_explanation(self, is_attack: bool, category: str, confidence: float) -> str:
        if not is_attack:
            return f"Message appears legitimate with {(1-confidence)*100:.1f}% confidence"

        explanations = {
            "urgency": "The message pressures immediate action using urgency",
            "reward_lure": "The message promises rewards to manipulate the user",
            "authority": "The message abuses authority to force compliance",
            "impersonation": "The message pretends to be from a trusted source",
            "fear_threat": "The message uses fear or threats to coerce action",
        }

        return f"{explanations.get(category, 'Suspicious social engineering detected')}. Confidence: {confidence*100:.1f}%"


_detector_instance = None

def get_detector() -> RAGSocialEngineeringDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = RAGSocialEngineeringDetector()
    return _detector_instance
