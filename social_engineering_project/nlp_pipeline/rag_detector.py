"""
RAG-based Social Engineering Detection using Embeddings.
v4.0 — Production-grade. RAG owns CONFIDENCE. Category is a signal only.
"""

import math
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import Dict, List, Tuple
from sklearn.metrics.pairwise import cosine_similarity


class RAGSocialEngineeringDetector:
    """
    Responsibilities:
      1. Encode input → retrieve top-K nearest neighbors from knowledge base
      2. Produce calibrated confidence (sigmoid + floors)
      3. Return neighbor-voted category as a SIGNAL (not authoritative)

    This class does NOT make final category decisions.
    IntegratedDetector owns that.
    """

    THREAT_KEYWORDS = [
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
        "immediately", "within 24 hours", "within 48 hours",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "in 10 minutes", "in 30 minutes",
        "30 minutes", "last warning", "last chance", "expires",
    ]

    INFORMATIONAL_PHRASES = [
        "announced", "reported", "mentioned",
        "during today", "presentation", "product launch",
        "press release", "scheduled maintenance",
        "no action required", "no action is needed",
    ]

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        print(f"Loading embedding model: {model_name}")
        self.embedding_model = SentenceTransformer(model_name)
        self.patterns: List[str] = []
        self.embeddings = None
        self.metadatas: List[Dict] = []
        print("RAG Detector initialized.")

    def add_patterns_to_knowledge_base(self, patterns: List[Dict]):
        texts = [p["text"] for p in patterns]
        embeddings = self.embedding_model.encode(
            texts, convert_to_tensor=False, show_progress_bar=False,
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
        print(f"Knowledge base loaded: {len(patterns)} patterns.")

    # ───────────────────────────────────────────────────────
    # Helpers
    # ───────────────────────────────────────────────────────

    def _count_threat_kw(self, msg: str) -> int:
        return sum(1 for kw in self.THREAT_KEYWORDS if kw in msg)

    def _has_deadline(self, msg: str) -> bool:
        return any(kw in msg for kw in self.DEADLINE_KEYWORDS)

    def _is_informational(self, msg: str) -> bool:
        return any(p in msg for p in self.INFORMATIONAL_PHRASES)

    # ───────────────────────────────────────────────────────
    # Core detection
    # ───────────────────────────────────────────────────────

    def detect(self, message: str, top_k: int = 5) -> Dict:
        msg_embedding = self.embedding_model.encode(
            [message], show_progress_bar=False,
        )[0].reshape(1, -1)

        sims = cosine_similarity(msg_embedding, self.embeddings)[0]
        top_idx = np.argsort(sims)[::-1][:top_k]
        best_sim = float(sims[top_idx[0]]) if top_idx.size else 0.0

        msg_lower = message.lower()
        threat_count = self._count_threat_kw(msg_lower)
        informational = self._is_informational(msg_lower) and threat_count == 0

        # Sigmoid calibration: steepness=9, midpoint=0.40
        if best_sim <= 0:
            cal = 0.0
        else:
            cal = 1.0 / (1.0 + math.exp(-9.0 * (best_sim - 0.40)))
            cal *= 0.92

        # Low-similarity cap
        if best_sim < 0.30:
            cal = min(cal, 0.15)
        if informational:
            cal = min(cal, 0.30)

        # Neighbor voting
        results = {
            "documents": [[self.patterns[i] for i in top_idx]],
            "distances": [[1.0 - sims[i] for i in top_idx]],
            "metadatas": [[self.metadatas[i] for i in top_idx]],
        }
        _vote_conf, is_attack, voted_cat = self._neighbor_vote(results)

        if voted_cat in ("psychological_coercion", "fear_threat_severe"):
            voted_cat = "fear_threat"

        # Neighbor agreement boost
        n_attack = sum(
            1 for m in results["metadatas"][0]
            if m["label"] == "social_engineering"
        )
        agreement = n_attack / max(len(results["metadatas"][0]), 1)
        if agreement >= 0.7 and cal > 0.25:
            cal = min(cal * 1.18, 0.95)

        # Threat-keyword confidence floors (NOT category override)
        has_dl = self._has_deadline(msg_lower)
        if threat_count >= 2 and has_dl:
            cal = max(cal, 0.75)
            is_attack = True
        elif threat_count >= 2:
            cal = max(cal, 0.60)
            is_attack = True
        elif threat_count >= 1 and has_dl:
            cal = max(cal, 0.55)
            is_attack = True
        elif threat_count >= 1:
            cal = max(cal, 0.40)
            is_attack = True

        cal = round(cal, 4)

        return {
            "is_social_engineering": is_attack and not informational,
            "confidence_score": cal,
            "category": voted_cat,
            "similar_patterns": [
                {"pattern": self.patterns[i], "similarity": round(float(sims[i]), 4)}
                for i in top_idx[:3]
            ],
        }

    def _neighbor_vote(self, results: Dict) -> Tuple[float, bool, str]:
        if not results["distances"]:
            return 0.0, False, "unknown"

        similarities = [1.0 - d for d in results["distances"][0]]
        metadatas = results["metadatas"][0]

        attack_s, legit_s = 0.0, 0.0
        cat_scores: Dict[str, float] = {}

        for sim, meta in zip(similarities, metadatas):
            w = sim * float(meta["base_confidence"])
            cat = meta["category"]
            if cat in ("psychological_coercion", "fear_threat_severe"):
                cat = "fear_threat"

            if meta["label"] == "social_engineering":
                attack_s += w
                cat_scores[cat] = cat_scores.get(cat, 0.0) + w
            else:
                legit_s += w

        total = attack_s + legit_s
        conf = attack_s / total if total > 0 else 0.0
        cat = max(cat_scores, key=cat_scores.get) if cat_scores else "unknown"
        return conf, conf > 0.55, cat


# ── Singleton ──
_instance = None

def get_detector() -> RAGSocialEngineeringDetector:
    global _instance
    if _instance is None:
        _instance = RAGSocialEngineeringDetector()
    return _instance