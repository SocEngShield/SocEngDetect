"""
External category-labeled phishing dataset loader.

Loads phishing_dataset_with_category.csv and prepares CATEGORY_DATASET
for RAG pattern expansion without modifying the original knowledge base.
"""

import os
from typing import Dict, List, Optional

import pandas as pd


_ALLOWED_CATEGORIES = {
    "urgency",
    "authority",
    "impersonation",
    "reward_lure",
    "fear_threat",
}


def _find_column(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    normalized = {str(col).strip().lower(): col for col in df.columns}
    for name in candidates:
        if name in normalized:
            return normalized[name]
    return None


def _normalize_category(raw_value: object) -> str:
    val = str(raw_value).strip().lower()

    # Direct match first.
    if val in _ALLOWED_CATEGORIES:
        return val

    # Common aliases/synonyms mapped to system signal categories.
    alias_map = {
        "urgent": "urgency",
        "time_pressure": "urgency",
        "pressure": "urgency",
        "official": "authority",
        "government": "authority",
        "bank": "authority",
        "spoofing": "impersonation",
        "brand_impersonation": "impersonation",
        "prize": "reward_lure",
        "lottery": "reward_lure",
        "reward": "reward_lure",
        "threat": "fear_threat",
        "fear": "fear_threat",
        "coercion": "fear_threat",
    }
    return alias_map.get(val, "generic_phishing")


def _load_and_preprocess_category_dataset(max_samples: int = 700) -> List[Dict]:
    """
    Load, clean, deduplicate and cap the category dataset.

    Output format:
        [{"text": "...", "label": "urgency|authority|...|generic_phishing"}, ...]
    """
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base_dir, "phishing_dataset_with_category.csv")

        if not os.path.exists(csv_path):
            print(f"[!] Category dataset not found at {csv_path}. Skipping category expansion.")
            return []

        try:
            df = pd.read_csv(csv_path)
        except UnicodeDecodeError:
            df = pd.read_csv(csv_path, encoding="latin-1")

        if df.empty:
            print("[!] Category dataset is empty. Skipping category expansion.")
            return []

        text_col = _find_column(df, ["text", "message", "content", "body", "v2"])
        category_col = _find_column(df, ["category", "class", "attack_type", "type", "label"])

        if text_col is None:
            print("[!] No text/message column found in category dataset. Skipping category expansion.")
            return []

        if category_col is None:
            print("[!] No category column found in category dataset. Using generic_phishing labels.")

        # Keep phishing rows where possible.
        selected = df.copy()
        label_col = _find_column(df, ["label", "target", "is_phishing", "phishing"])
        if label_col is not None:
            labels = selected[label_col].astype(str).str.strip().str.lower()
            phishing_mask = labels.isin({"phishing", "spam", "1", "true", "yes", "malicious", "scam"})
            if phishing_mask.any():
                selected = selected[phishing_mask].copy()

        # Clean text and normalize categories.
        cleaned = selected[[text_col]].copy()
        cleaned[text_col] = cleaned[text_col].astype(str).str.lower().str.strip()
        cleaned = cleaned[cleaned[text_col].notna()]
        cleaned = cleaned[cleaned[text_col] != ""]

        if category_col is not None:
            cleaned["_mapped_category"] = selected.loc[cleaned.index, category_col].apply(_normalize_category)
        else:
            cleaned["_mapped_category"] = "generic_phishing"

        # Drop duplicate texts, keep first occurrence.
        cleaned = cleaned.drop_duplicates(subset=[text_col], keep="first")

        # Cap dataset size for stable runtime.
        cleaned = cleaned.head(max_samples)

        patterns: List[Dict] = []
        for _, row in cleaned.iterrows():
            patterns.append(
                {
                    "text": row[text_col],
                    "label": row["_mapped_category"],
                }
            )

        print(f"[+] Category dataset loaded: {len(patterns)} samples")
        return patterns

    except Exception as exc:
        print(f"[!] Error loading category dataset: {exc}")
        return []


CATEGORY_DATASET = _load_and_preprocess_category_dataset()
