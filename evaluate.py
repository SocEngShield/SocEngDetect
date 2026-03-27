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
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_dataset import TEST_SAMPLES, get_stats, get_url_attack_samples
from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.rag_detector import get_detector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET


def evaluate_system(verbose=True):
    """
    Run evaluation on the test dataset and compute metrics.
    """
    if verbose:
        print("=" * 60)
        print("SOCIAL ENGINEERING DETECTION SYSTEM - EVALUATION")
        print("=" * 60)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    # Initialize detector
    if verbose:
        print("[*] Initializing detector...")
    
    # Load RAG knowledge base (required before detection)
    rag = get_detector()
    rag.add_patterns(SOCIAL_ENGINEERING_DATASET)
    
    detector = IntegratedSocialEngineeringDetector()
    if verbose:
        print("[+] Detector ready.")
        print()
    
    # Get dataset stats
    stats = get_stats()
    
    # Counters
    tp = 0  # True Positives: Actual attack, predicted attack
    fp = 0  # False Positives: Actual benign, predicted attack
    tn = 0  # True Negatives: Actual benign, predicted benign
    fn = 0  # False Negatives: Actual attack, predicted benign
    
    # Track misclassifications for analysis
    false_positives_list = []
    false_negatives_list = []
    
    # Track attack type classification (F2)
    attack_type_counts = {}
    
    # Track URL-based attack detection (F1)
    url_attacks_detected = 0
    url_attacks_missed = 0
    
    total = len(TEST_SAMPLES)
    if verbose:
        print(f"[*] Running evaluation on {total} samples...")
        print(f"    ({stats['attacks']} attacks, {stats['benign']} benign, {stats['url_attacks']} URL-based)")
        print("-" * 60)
    
    for i, sample in enumerate(TEST_SAMPLES, 1):
        text = sample["text"]
        actual_attack = sample["attack"]
        
        # Get prediction
        result = detector.analyze_message(text)
        predicted_attack = result["attack_detected"]
        
        # Track attack types (F2)
        attack_type = result.get("attack_type")
        if attack_type and predicted_attack:
            main_type = attack_type.split(" → ")[0] if " → " in attack_type else attack_type
            attack_type_counts[main_type] = attack_type_counts.get(main_type, 0) + 1
        
        # Check if URL-based attack
        is_url_attack = any(p in text.lower() for p in ["http://", "https://", ".xyz", ".tk", ".ru", "bit.ly"])
        
        # Update counters
        if actual_attack and predicted_attack:
            tp += 1
            if is_url_attack:
                url_attacks_detected += 1
        elif actual_attack and not predicted_attack:
            fn += 1
            if is_url_attack:
                url_attacks_missed += 1
            false_negatives_list.append({
                "text": text[:80] + "..." if len(text) > 80 else text,
                "expected_labels": sample["labels"],
                "confidence": result["overall_confidence"],
                "has_url": is_url_attack,
            })
        elif not actual_attack and predicted_attack:
            fp += 1
            false_positives_list.append({
                "text": text[:80] + "..." if len(text) > 80 else text,
                "detected_categories": result["categories"],
                "confidence": result["overall_confidence"],
                "attack_type": attack_type,
            })
        else:
            tn += 1
        
        # Progress indicator
        if verbose and i % 25 == 0:
            print(f"    Processed {i}/{total} samples...")
    
    if verbose:
        print("-" * 60)
        print()
    
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    
    # URL attack metrics (F1 evaluation)
    url_attack_recall = url_attacks_detected / (url_attacks_detected + url_attacks_missed) if (url_attacks_detected + url_attacks_missed) > 0 else 0.0
    
    if verbose:
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
        
        # F1 URL attack evaluation
        print("URL-BASED ATTACK DETECTION (F1):")
        print("-" * 40)
        print(f"  URL Attacks Detected:  {url_attacks_detected}")
        print(f"  URL Attacks Missed:    {url_attacks_missed}")
        print(f"  URL Attack Recall:     {url_attack_recall:.1%}")
        print("-" * 40)
        print()
        
        # F2 Attack Type Distribution
        if attack_type_counts:
            print("ATTACK TYPE DISTRIBUTION (F2):")
            print("-" * 40)
            for attack_type, count in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
                print(f"  {attack_type}: {count}")
            print("-" * 40)
            print()
        
        # Print misclassification details
        if false_negatives_list:
            print("FALSE NEGATIVES (Missed Attacks):")
            print("-" * 40)
            for i, fn_item in enumerate(false_negatives_list[:15], 1):  # Limit to 15
                url_tag = " [URL]" if fn_item.get("has_url") else ""
                print(f"  {i}. \"{fn_item['text']}\"{url_tag}")
                print(f"     Expected: {fn_item['expected_labels']}")
                print(f"     Confidence: {fn_item['confidence']:.1f}%")
                print()
            if len(false_negatives_list) > 15:
                print(f"  ... and {len(false_negatives_list) - 15} more")
                print()
        
        if false_positives_list:
            print("FALSE POSITIVES (Benign flagged as Attack):")
            print("-" * 40)
            for i, fp_item in enumerate(false_positives_list[:10], 1):  # Limit to 10
                print(f"  {i}. \"{fp_item['text']}\"")
                print(f"     Detected: {fp_item['detected_categories']}")
                print(f"     Confidence: {fp_item['confidence']:.1f}%")
                if fp_item.get("attack_type"):
                    print(f"     Type: {fp_item['attack_type']}")
                print()
            if len(false_positives_list) > 10:
                print(f"  ... and {len(false_positives_list) - 10} more")
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
        "attack_samples": stats["attacks"],
        "benign_samples": stats["benign"],
        "url_attack_recall": url_attack_recall,
        "attack_type_distribution": attack_type_counts,
        "false_positives": false_positives_list,
        "false_negatives": false_negatives_list,
    }


def print_summary(metrics):
    """Print a compact summary suitable for reports."""
    print()
    print("SUMMARY FOR REVIEW:")
    print(f"  Dataset: {metrics['total_samples']} samples ({metrics['attack_samples']} attacks, {metrics['benign_samples']} benign)")
    print(f"  Precision: {metrics['precision']*100:.1f}%")
    print(f"  Recall: {metrics['recall']*100:.1f}%")
    print(f"  F1 Score: {metrics['f1']*100:.1f}%")
    print(f"  Accuracy: {metrics['accuracy']*100:.1f}%")
    print(f"  URL Attack Recall: {metrics['url_attack_recall']*100:.1f}%")
    print()


def compare_results(current, previous_f1=None):
    """Compare current results with a previous baseline."""
    print()
    print("COMPARISON:")
    print("-" * 40)
    if previous_f1:
        delta = current["f1"] - previous_f1
        direction = "↑" if delta > 0 else "↓" if delta < 0 else "→"
        print(f"  F1 Score: {current['f1']*100:.1f}% {direction} (was {previous_f1*100:.1f}%)")
        print(f"  Change: {delta*100:+.1f}%")
    else:
        print(f"  Current F1: {current['f1']*100:.1f}%")
        print("  (No baseline provided for comparison)")
    print()


if __name__ == "__main__":
    metrics = evaluate_system()
    print_summary(metrics)
    
    # Optional: Compare with previous baseline
    # Uncomment and set previous F1 score to track progress
    # compare_results(metrics, previous_f1=0.826)
