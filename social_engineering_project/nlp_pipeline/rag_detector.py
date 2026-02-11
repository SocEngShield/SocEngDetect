"""
RAG-based Social Engineering Detection — v5.0 STRICT.
Returns ONLY: rag_confidence (0-100) and voted_category.
No similarity scores, no calibrated values, no intermediate metrics.
"""

import math
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity as _cos_sim
from typing import Dict, List, Tuple


class RAGSocialEngineeringDetector:

    THREAT_KW = [
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
        "permanently", "deactivated","share","credentials","login details","financial",
    ]

    DEADLINE_KW = [
        "immediately", "within 24 hours", "within 48 hours",
        "right now", "act now", "in 1 hour", "in 2 hours",
        "within the next", "before authorities", "final warning",
        "within 10 minutes", "in 10 minutes", "in 30 minutes",
        "30 minutes", "last warning", "last chance", "expires",
    ]

    SAFE_CONTEXT = [
        "announced", "reported", "mentioned",
        "during today", "presentation", "product launch",
        "press release", "scheduled maintenance",
        "no action required", "no action is needed",
    ]

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        print(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.patterns: List[str] = []
        self.embeddings = None
        self.metadatas: List[Dict] = []
        print("RAG Detector ready.")

    def add_patterns(self, patterns: List[Dict]):
        texts = [p["text"] for p in patterns]
        self.embeddings = np.array(
            self.model.encode(texts, convert_to_tensor=False, show_progress_bar=False)
        )
        self.patterns = texts
        self.metadatas = [
            {
                "label": p["label"],
                "category": (
                    "fear_threat"
                    if p["category"] in ("psychological_coercion", "fear_threat_severe")
                    else p["category"]
                ),
                "base_conf": p["confidence"],
            }
            for p in patterns
        ]
        print(f"Knowledge base: {len(patterns)} patterns loaded.")

    # ──────────────────────────────────────────────────
    # Core detection → returns rag_confidence (0-100)
    # ──────────────────────────────────────────────────

    def detect(self, message: str) -> Tuple[float, str]:
        """
        Returns:
            rag_confidence: float 0-100 (probability message is malicious)
            voted_category: str (neighbor-voted category signal)
        """
        emb = self.model.encode([message], show_progress_bar=False)[0].reshape(1, -1)
        scores = _cos_sim(emb, self.embeddings)[0]
        top_idx = np.argsort(scores)[::-1][:5]
        top_score = float(scores[top_idx[0]]) if top_idx.size else 0.0

        msg = message.lower()
        n_threat = sum(1 for kw in self.THREAT_KW if kw in msg)
        has_deadline = any(kw in msg for kw in self.DEADLINE_KW)
        is_safe_ctx = any(p in msg for p in self.SAFE_CONTEXT) and n_threat == 0

        # ── Convert top embedding score to malicious probability ──
        if top_score <= 0:
            prob = 0.0
        else:
            prob = 1.0 / (1.0 + math.exp(-9.0 * (top_score - 0.40)))
            prob *= 0.92

        if top_score < 0.30:
            prob = min(prob, 0.15)
        if is_safe_ctx:
            prob = min(prob, 0.25)

        # ── Neighbor agreement ──
        metas = [self.metadatas[i] for i in top_idx]
        n_attack = sum(1 for m in metas if m["label"] == "social_engineering")
        agreement = n_attack / max(len(metas), 1)
        if agreement >= 0.7 and prob > 0.20:
            prob = min(prob * 1.18, 0.95)

        # ── Threat keyword floors ──
        if n_threat >= 2 and has_deadline:
            prob = max(prob, 0.75)
        elif n_threat >= 2:
            prob = max(prob, 0.60)
        elif n_threat >= 1 and has_deadline:
            prob = max(prob, 0.55)
        elif n_threat >= 1:
            prob = max(prob, 0.40)

        # ── Neighbor vote for category ──
        cat_scores: Dict[str, float] = {}
        for i in top_idx:
            m = self.metadatas[i]
            s = float(scores[i])
            cat = m["category"]
            if cat in ("psychological_coercion", "fear_threat_severe"):
                cat = "fear_threat"
            if m["label"] == "social_engineering":
                cat_scores[cat] = cat_scores.get(cat, 0.0) + s * m["base_conf"]

        voted_cat = max(cat_scores, key=cat_scores.get) if cat_scores else "unknown"

        rag_confidence = round(max(0.0, min(100.0, prob * 100)), 2)

        return rag_confidence, voted_cat


# ── Singleton ──
_instance = None

def get_detector() -> RAGSocialEngineeringDetector:
    global _instance
    if _instance is None:
        _instance = RAGSocialEngineeringDetector()
    return _instance