#!/usr/bin/env python3
"""
Evaluation script for Social Engineering Detection System.

Computes Precision, Recall, and F1 Score for attack detection.
Runs independently without modifying any existing system files.

Usage:
    python evaluate.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_dataset import TEST_SAMPLES
from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.rag_detector import get_detector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET


def evaluate_system():
    """
    Run evaluation on the test dataset and compute metrics.
    """
    print("=" * 60)
    print("SOCIAL ENGINEERING DETECTION SYSTEM - EVALUATION")
    print("=" * 60)
    print()
    
    # Initialize detector
    print("[*] Initializing detector...")
    
    # Load RAG knowledge base (required before detection)
    rag = get_detector()
    rag.add_patterns(SOCIAL_ENGINEERING_DATASET)
    
    detector = IntegratedSocialEngineeringDetector()
    print("[+] Detector ready.")
    print()
    
    # Counters
    tp = 0  # True Positives: Actual attack, predicted attack
    fp = 0  # False Positives: Actual benign, predicted attack
    tn = 0  # True Negatives: Actual benign, predicted benign
    fn = 0  # False Negatives: Actual attack, predicted benign
    
    # Track misclassifications for analysis
    false_positives_list = []
    false_negatives_list = []
    
    total = len(TEST_SAMPLES)
    print(f"[*] Running evaluation on {total} samples...")
    print("-" * 60)
    
    for i, sample in enumerate(TEST_SAMPLES, 1):
        text = sample["text"]
        actual_attack = sample["attack"]
        
        # Get prediction
        result = detector.analyze_message(text)
        predicted_attack = result["attack_detected"]
        
        # Update counters
        if actual_attack and predicted_attack:
            tp += 1
        elif actual_attack and not predicted_attack:
            fn += 1
            false_negatives_list.append({
                "text": text[:80] + "..." if len(text) > 80 else text,
                "expected_labels": sample["labels"],
                "confidence": result["overall_confidence"],
            })
        elif not actual_attack and predicted_attack:
            fp += 1
            false_positives_list.append({
                "text": text[:80] + "..." if len(text) > 80 else text,
                "detected_categories": result["categories"],
                "confidence": result["overall_confidence"],
            })
        else:
            tn += 1
        
        # Progress indicator
        if i % 20 == 0:
            print(f"    Processed {i}/{total} samples...")
    
    print("-" * 60)
    print()
    
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    
    # Print results
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print()
    print("CONFUSION MATRIX:")
    print("-" * 40)
    print(f"                  Predicted")
    print(f"                  Attack    Benign")
    print(f"  Actual Attack    {tp:4d}      {fn:4d}")
    print(f"  Actual Benign    {fp:4d}      {tn:4d}")
    print("-" * 40)
    print()
    print("METRICS:")
    print("-" * 40)
    print(f"  True Positives (TP):   {tp:4d}")
    print(f"  False Positives (FP):  {fp:4d}")
    print(f"  True Negatives (TN):   {tn:4d}")
    print(f"  False Negatives (FN):  {fn:4d}")
    print()
    print(f"  Precision:  {precision:.4f}  ({precision*100:.1f}%)")
    print(f"  Recall:     {recall:.4f}  ({recall*100:.1f}%)")
    print(f"  F1 Score:   {f1:.4f}  ({f1*100:.1f}%)")
    print(f"  Accuracy:   {accuracy:.4f}  ({accuracy*100:.1f}%)")
    print("-" * 40)
    print()
    
    # Print misclassification details
    if false_negatives_list:
        print("FALSE NEGATIVES (Missed Attacks):")
        print("-" * 40)
        for i, fn_item in enumerate(false_negatives_list, 1):
            print(f"  {i}. \"{fn_item['text']}\"")
            print(f"     Expected: {fn_item['expected_labels']}")
            print(f"     Confidence: {fn_item['confidence']:.1f}%")
            print()
    
    if false_positives_list:
        print("FALSE POSITIVES (Benign flagged as Attack):")
        print("-" * 40)
        for i, fp_item in enumerate(false_positives_list, 1):
            print(f"  {i}. \"{fp_item['text']}\"")
            print(f"     Detected: {fp_item['detected_categories']}")
            print(f"     Confidence: {fp_item['confidence']:.1f}%")
            print()
    
    print("=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    
    # Return metrics for programmatic use
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "total_samples": total,
        "false_positives": false_positives_list,
        "false_negatives": false_negatives_list,
    }


def print_summary(metrics):
    """Print a compact summary suitable for reports."""
    print()
    print("SUMMARY FOR REVIEW:")
    print(f"  Dataset: {metrics['total_samples']} samples (50 attacks, 50 benign)")
    print(f"  Precision: {metrics['precision']*100:.1f}%")
    print(f"  Recall: {metrics['recall']*100:.1f}%")
    print(f"  F1 Score: {metrics['f1']*100:.1f}%")
    print(f"  Accuracy: {metrics['accuracy']*100:.1f}%")
    print()


if __name__ == "__main__":
    metrics = evaluate_system()
    print_summary(metrics)
