"""
Evaluation module for Social Engineering Detection System.
Computes accuracy, precision, recall, F1 on labeled test sets.
v4.0 — Production-grade metrics with per-category breakdown.
"""

from typing import Dict, List, Tuple


class DetectionEvaluator:
    """
    Evaluates detector performance against labeled ground truth.

    Each test case:
        {
            "text": "...",
            "expected_attack": True/False,
            "expected_categories": ["fear_threat", "impersonation"],  # optional
        }
    """

    # ── Built-in test suite (20 cases) ──
    BUILT_IN_TESTS = [
        {
            "text": "Hi this is Rahul from IT. Share login credentials.",
            "expected_attack": True,
            "expected_categories": ["impersonation"],
        },
        {
            "text": "This is Amazon Customer Support. Confirm card details.",
            "expected_attack": True,
            "expected_categories": ["impersonation", "fear_threat"],
        },
        {
            "text": "Your account will expire in 30 minutes! Click here now.",
            "expected_attack": True,
            "expected_categories": ["urgency"],
        },
        {
            "text": "Limited-time security update required.",
            "expected_attack": True,
            "expected_categories": ["urgency"],
        },
        {
            "text": "Last warning! Update details within 10 minutes.",
            "expected_attack": True,
            "expected_categories": ["urgency"],
        },
        {
            "text": "Get 90% discount. Login using special link.",
            "expected_attack": True,
            "expected_categories": ["reward_lure"],
        },
        {
            "text": "Income Tax Department. Submit financial details immediately.",
            "expected_attack": True,
            "expected_categories": ["fear_threat"],
        },
        {
            "text": "Your Aadhaar has been misused. Call this number immediately.",
            "expected_attack": True,
            "expected_categories": ["fear_threat"],
        },
        {
            "text": "Congratulations! You've won $1,000,000. Send bank details.",
            "expected_attack": True,
            "expected_categories": ["reward_lure"],
        },
        {
            "text": "I'm the CEO. Wire $50,000 to this account immediately.",
            "expected_attack": True,
            "expected_categories": ["authority"],
        },
        {
            "text": "An FIR has been filed against you for fraud.",
            "expected_attack": True,
            "expected_categories": ["fear_threat"],
        },
        {
            "text": "Your bank account has been frozen. Contact us now.",
            "expected_attack": True,
            "expected_categories": ["fear_threat"],
        },
        {
            "text": "We have your webcam footage. Pay $2000 in Bitcoin.",
            "expected_attack": True,
            "expected_categories": ["fear_threat"],
        },
        {
            "text": "Hey, can we schedule a meeting for Tuesday at 2 PM?",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
        {
            "text": "Here are the quarterly reports you requested.",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
        {
            "text": "Happy birthday! Wishing you a wonderful year ahead.",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
        {
            "text": "Reminder: Team standup meeting at 10 AM tomorrow.",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
        {
            "text": "Your Amazon order #112 has shipped! Track at amazon.com.",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
        {
            "text": "The production server is down. Engineers join the bridge call.",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
        {
            "text": "Could you review the pull request I submitted this morning?",
            "expected_attack": False,
            "expected_categories": ["safe"],
        },
    ]

    def __init__(self, detector):
        """
        Args:
            detector: IntegratedSocialEngineeringDetector instance
        """
        self.detector = detector

    def evaluate(
        self, test_cases: List[Dict] = None
    ) -> Dict:
        """
        Run evaluation on test cases.
        Returns metrics dict with accuracy, precision, recall, F1,
        per-case results, and confusion counts.
        """
        cases = test_cases or self.BUILT_IN_TESTS

        tp = 0  # true positive: predicted attack, was attack
        fp = 0  # false positive: predicted attack, was safe
        tn = 0  # true negative: predicted safe, was safe
        fn = 0  # false negative: predicted safe, was attack

        results_list = []

        for case in cases:
            result = self.detector.analyze_message(case["text"])
            predicted_attack = result["is_social_engineering"]
            expected_attack = case["expected_attack"]

            predicted_cats = result.get("categories", [result.get("category", "unknown")])
            expected_cats = case.get("expected_categories", [])

            # Binary classification metrics
            if expected_attack and predicted_attack:
                tp += 1
                correct = True
            elif not expected_attack and not predicted_attack:
                tn += 1
                correct = True
            elif not expected_attack and predicted_attack:
                fp += 1
                correct = False
            else:
                fn += 1
                correct = False

            # Category overlap check
            cat_overlap = bool(
                set(predicted_cats) & set(expected_cats)
            ) if expected_cats else None

            results_list.append({
                "text": case["text"][:80] + ("..." if len(case["text"]) > 80 else ""),
                "expected_attack": expected_attack,
                "predicted_attack": predicted_attack,
                "correct": correct,
                "confidence": result["confidence_score"],
                "risk_level": result["risk_level"],
                "predicted_categories": predicted_cats,
                "expected_categories": expected_cats,
                "category_match": cat_overlap,
            })

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "total_samples": total,
            "correct": tp + tn,
            "accuracy": round(accuracy * 100, 1),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "confusion": {
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn,
            },
            "per_case": results_list,
        }

    def format_report(self, metrics: Dict = None) -> str:
        """Generate a human-readable evaluation report."""
        if metrics is None:
            metrics = self.evaluate()

        lines = [
            "═" * 56,
            "  DETECTION SYSTEM EVALUATION REPORT",
            "═" * 56,
            "",
            f"  Total Samples:  {metrics['total_samples']}",
            f"  Correct:        {metrics['correct']}",
            f"  Accuracy:       {metrics['accuracy']}%",
            "",
            f"  Precision:      {metrics['precision']:.4f}",
            f"  Recall:         {metrics['recall']:.4f}",
            f"  F1 Score:       {metrics['f1_score']:.4f}",
            "",
            "  Confusion Matrix:",
            f"    TP={metrics['confusion']['true_positive']}  "
            f"FP={metrics['confusion']['false_positive']}",
            f"    FN={metrics['confusion']['false_negative']}  "
            f"TN={metrics['confusion']['true_negative']}",
            "",
            "─" * 56,
            "  PER-CASE RESULTS:",
            "─" * 56,
        ]

        for i, r in enumerate(metrics["per_case"], 1):
            mark = "✓" if r["correct"] else "✗"
            lines.append(
                f"  {mark} [{i:2d}] {r['text']}"
            )
            lines.append(
                f"        Expected: {'ATTACK' if r['expected_attack'] else 'SAFE'}  |  "
                f"Got: {'ATTACK' if r['predicted_attack'] else 'SAFE'}  |  "
                f"Conf: {r['confidence']:.2f}  |  "
                f"Risk: {r['risk_level']}"
            )
            if r["predicted_attack"]:
                lines.append(
                    f"        Categories: {' + '.join(r['predicted_categories'])}"
                )
            lines.append("")

        lines.append("═" * 56)
        return "\n".join(lines)