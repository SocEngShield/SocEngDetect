"""
Evaluation module — Computes accuracy, precision, recall, F1 on labeled test sets.
Uses sklearn.metrics as required. Binary classification: attack=1, safe=0.
"""

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from typing import Dict, List


# ── Built-in labeled test suite (20 cases) ──
EVAL_DATASET = [
    # --- ATTACKS (13) ---
    {"text": "Hi this is Rahul from IT. Share login credentials.",
     "label": 1, "expected_cat": "Impersonation"},
    {"text": "This is Amazon Customer Support. Confirm card details.",
     "label": 1, "expected_cat": "Impersonation"},
    {"text": "Your account will expire in 30 minutes! Click here now.",
     "label": 1, "expected_cat": "Urgency"},
    {"text": "Last warning! Update details within 10 minutes.",
     "label": 1, "expected_cat": "Urgency"},
    {"text": "Get 90% discount. Login using special link.",
     "label": 1, "expected_cat": "Reward/Lure"},
    {"text": "Income Tax Department. Submit financial details immediately.",
     "label": 1, "expected_cat": "Fear/Threat"},
    {"text": "Your Aadhaar has been misused. Call this number immediately.",
     "label": 1, "expected_cat": "Fear/Threat"},
    {"text": "Congratulations! You've won $1,000,000. Send bank details.",
     "label": 1, "expected_cat": "Reward/Lure"},
    {"text": "I'm the CEO. Wire $50,000 to this account immediately.",
     "label": 1, "expected_cat": "Authority"},
    {"text": "An FIR has been filed against you for fraud.",
     "label": 1, "expected_cat": "Fear/Threat"},
    {"text": "Your bank account has been frozen. Contact us now.",
     "label": 1, "expected_cat": "Fear/Threat"},
    {"text": "We have your webcam footage. Pay $2000 in Bitcoin.",
     "label": 1, "expected_cat": "Fear/Threat"},
    {"text": "Your bank account has been suspended. Verify immediately.",
     "label": 1, "expected_cat": "Fear/Threat"},
    # --- SAFE (7) ---
    {"text": "Hey, can we schedule a meeting for Tuesday at 2 PM?",
     "label": 0, "expected_cat": "safe"},
    {"text": "Here are the quarterly reports you requested.",
     "label": 0, "expected_cat": "safe"},
    {"text": "Happy birthday! Wishing you a wonderful year ahead.",
     "label": 0, "expected_cat": "safe"},
    {"text": "Reminder: Team standup meeting at 10 AM tomorrow.",
     "label": 0, "expected_cat": "safe"},
    {"text": "Please confirm tomorrow's meeting.",
     "label": 0, "expected_cat": "safe"},
    {"text": "The production server is down. Engineers join the bridge call.",
     "label": 0, "expected_cat": "safe"},
    {"text": "Could you review the pull request I submitted this morning?",
     "label": 0, "expected_cat": "safe"},
]


def evaluate_predictions(
    true_labels: List[int],
    predicted_labels: List[int],
) -> Dict:
    """
    Compute binary classification metrics using sklearn.
    Labels: 1 = attack, 0 = safe.
    """
    acc = accuracy_score(true_labels, predicted_labels)
    prec = precision_score(true_labels, predicted_labels, zero_division=0)
    rec = recall_score(true_labels, predicted_labels, zero_division=0)
    f1 = f1_score(true_labels, predicted_labels, zero_division=0)
    cm = confusion_matrix(true_labels, predicted_labels, labels=[1, 0])
    # cm layout with labels=[1,0]:
    #   [[TP, FN],
    #    [FP, TN]]
    tp = int(cm[0][0])
    fn = int(cm[0][1])
    fp = int(cm[1][0])
    tn = int(cm[1][1])

    return {
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "total": len(true_labels),
        "correct": tp + tn,
    }


def run_evaluation(detector) -> Dict:
    """
    Run detector against the built-in test suite.
    Returns metrics dict + per-case results.
    """
    true_labels = []
    pred_labels = []
    per_case = []

    for case in EVAL_DATASET:
        result = detector.analyze_message(case["text"])
        predicted = 1 if result["attack_detected"] else 0

        true_labels.append(case["label"])
        pred_labels.append(predicted)

        per_case.append({
            "text": case["text"],
            "expected": "ATTACK" if case["label"] == 1 else "SAFE",
            "predicted": "ATTACK" if predicted else "SAFE",
            "correct": predicted == case["label"],
            "overall_confidence": result["overall_confidence"],
            "risk_level": result["risk_level"],
            "categories": result["categories"],
        })

    metrics = evaluate_predictions(true_labels, pred_labels)
    metrics["per_case"] = per_case

    return metrics