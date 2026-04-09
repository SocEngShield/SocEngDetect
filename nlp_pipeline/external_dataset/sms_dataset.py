"""
External SMS/Text Spam Dataset - Expanded RAG Pattern Coverage
Loaded from: nlp_pipeline/external_dataset/spam.csv

Source: UCI SMS Spam Collection Dataset
Format: v1 (label), v2 (message)

This dataset is used ONLY to expand RAG pattern coverage and does NOT modify
the original SOCIAL_ENGINEERING_DATASET or system scoring logic.
"""

import os
import pandas as pd
import warnings
from typing import List, Dict

warnings.filterwarnings("ignore")


def _load_and_preprocess_sms() -> List[Dict]:
    """
    Load spam.csv, preprocess, and convert to RAG format.
    
    Returns:
        List of patterns in RAG format: [{"text": ..., "label": ..., "category": ..., "confidence": ...}, ...]
    """
    try:
        # Get the absolute path to spam.csv
        current_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(current_dir, "spam.csv")
        
        if not os.path.exists(csv_path):
            print(f"[!] SMS Dataset not found at {csv_path}. Skipping SMS pattern expansion.")
            return []
        
        # Load with latin-1 encoding (required for this dataset)
        df = pd.read_csv(csv_path, encoding="latin-1")
        
        # Filter for spam rows only
        spam_df = df[df["v1"] == "spam"].copy()
        
        if len(spam_df) == 0:
            print("[!] No spam messages found in dataset. Skipping SMS pattern expansion.")
            return []
        
        # Extract message text
        messages = spam_df["v2"].tolist()
        
        # Preprocess: clean text
        cleaned_messages = []
        for msg in messages:
            if pd.isna(msg):
                continue
            # Convert to lowercase and strip whitespace
            msg_clean = str(msg).lower().strip()
            if msg_clean:  # Only add non-empty messages
                cleaned_messages.append(msg_clean)
        
        # Remove duplicates while preserving order
        unique_messages = []
        seen = set()
        for msg in cleaned_messages:
            if msg not in seen:
                unique_messages.append(msg)
                seen.add(msg)
        
        print(f"[+] Loaded {len(unique_messages)} unique spam messages from SMS dataset")
        
        # Limit size to reasonable amount (keep 700-800 for balanced expansion)
        # This prevents the dataset from dominating RAG embeddings
        max_samples = min(750, len(unique_messages))
        unique_messages = unique_messages[:max_samples]
        
        print(f"[+] Using {len(unique_messages)} SMS patterns for RAG expansion")
        
        # Convert to RAG format
        # All SMS spam is labeled as "generic_phishing" category with confidence 0.85
        # This is deliberate: SMS phishing patterns are diverse and may not fit existing categories
        sms_patterns = []
        for msg in unique_messages:
            sms_patterns.append({
                "text": msg,
                "label": "social_engineering",
                "category": "generic_phishing",
                "confidence": 0.85
            })
        
        return sms_patterns
    
    except Exception as e:
        print(f"[!] Error loading SMS dataset: {str(e)}")
        return []


# Load SMS dataset at module import time
SMS_DATASET = _load_and_preprocess_sms()

if SMS_DATASET:
    print(f"[+] SMS_DATASET initialized with {len(SMS_DATASET)} patterns")
else:
    print("[*] SMS_DATASET empty or unavailable - system will use original patterns only")
