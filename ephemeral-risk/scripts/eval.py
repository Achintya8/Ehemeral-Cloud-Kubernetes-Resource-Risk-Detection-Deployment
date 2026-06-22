"""
eval.py
=======
Evaluation script for the Ephemeral Cloud Risk Detection system.
Compares anomalies detected by IsolationForest against the generated ground truth.

Features
--------
1. Standard metrics: Precision, Recall, F1-Score, Confusion Matrix.
2. Scenario-specific recall breakdown (e.g. Crypto-mining, Debug pod, Identity leak).
3. Hyperparameter sweep: evaluates contamination rates from 1% to 25% to find the F1-optimal rate.

Usage
-----
    # Run evaluation with default contamination
    python eval.py

    # Run hyperparameter sweep
    python eval.py --sweep
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from model.features import calculate_behavioral_features  # noqa: E402
from model.detector import detect_anomalies               # noqa: E402

DB_PATH = PROJECT_ROOT  / "data" / "events.db"
GT_PATH = PROJECT_ROOT / "data" / "ground_truth.json"


def load_ground_truth(gt_path: Path) -> dict:
    if not gt_path.exists():
        print(f"[ERROR] Ground truth file not found: {gt_path}")
        print("Please run `python generate_events.py` first.")
        sys.exit(1)
    with open(gt_path, "r", encoding="utf-8") as f:
        return json.load(f)


def calculate_metrics(detected: set[str], ground_truth: set[str], all_ids: set[str]) -> dict:
    tp = detected.intersection(ground_truth)
    fp = detected.difference(ground_truth)
    fn = ground_truth.difference(detected)
    tn = all_ids.difference(detected.union(ground_truth))

    precision = len(tp) / len(detected) if len(detected) > 0 else 0.0
    recall = len(tp) / len(ground_truth) if len(ground_truth) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "tn": len(tn),
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


def evaluate_single(
    features_df: pd.DataFrame,
    all_true_ids: set[str],
    scenarios: dict[str, list[str]],
    contamination: float
) -> None:
    from model import detector
    detector._MODEL = None  # Reset global model cache to ensure we fit with specified contamination
    all_ids = set(features_df["event_id"].unique())
    anomalies_df = detect_anomalies(features_df, contamination=contamination)
    detected_ids = set(anomalies_df["event_id"].unique())

    metrics = calculate_metrics(detected_ids, all_true_ids, all_ids)

    print("\n" + "=" * 70)
    print(f"  DETECTION EVALUATION REPORT (contamination = {contamination:.3f})")
    print("=" * 70)

    print(f"\n  Dataset Size   : {len(all_ids):,} events")
    print(f"  True Anomalies : {len(all_true_ids):,}")
    print(f"  Detected       : {len(detected_ids):,}")

    print("\n  CONFUSION MATRIX")
    print("  " + "-" * 30)
    print(f"  True Positives  (TP) : {metrics['tp']:>5}")
    print(f"  False Positives (FP) : {metrics['fp']:>5}")
    print(f"  False Negatives (FN) : {metrics['fn']:>5}")
    print(f"  True Negatives  (TN) : {metrics['tn']:>5}")
    print("  " + "-" * 30)

    print("\n  CORE METRICS")
    print("  " + "-" * 30)
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    print(f"  F1 Score  : {metrics['f1']:.4f}")
    print("  " + "-" * 30)

    print("\n  SCENARIO-SPECIFIC RECALL BREAKDOWN")
    print("  " + "-" * 55)
    print(f"  {'Scenario Name':<30} | {'True':>5} | {'Detected':>8} | {'Recall':>6}")
    print("  " + "-" * 55)
    for name, ids in scenarios.items():
        scenario_true = set(ids)
        scenario_detected = detected_ids.intersection(scenario_true)
        scen_recall = len(scenario_detected) / len(scenario_true) if len(scenario_true) > 0 else 0.0
        print(f"  {name:<30} | {len(scenario_true):>5} | {len(scenario_detected):>8} | {scen_recall:.4f}")
    print("  " + "-" * 55 + "\n")


def run_sweep(
    features_df: pd.DataFrame,
    all_true_ids: set[str],
    scenarios: dict[str, list[str]]
) -> None:
    from model import detector
    
    all_ids = set(features_df["event_id"].unique())
    contamination_rates = [
        0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08,
        0.10, 0.12, 0.15, 0.17, 0.18, 0.20, 0.22, 0.25,
    ]

    results = []
    best_f1 = -1.0
    best_rate = 0.17

    for rate in contamination_rates:
        scored = detector.score_events(features_df, contamination=rate)
        detected_ids = set(scored.loc[scored["anomaly_label"] == -1, "event_id"].unique())
        metrics = calculate_metrics(detected_ids, all_true_ids, all_ids)
        results.append((rate, len(detected_ids), metrics))
        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_rate = rate

    print("\n" + "=" * 80)
    print("  HYPERPARAMETER SWEEP: CONTAMINATION RATE VS. DETECTION METRICS")
    print("=" * 80)
    print(f"\n  {'Rate':<6} | {'Detected':>8} | {'TP':>5} | {'FP':>5} | {'FN':>5} | {'Precision':<9} | {'Recall':<6} | {'F1 Score':<8}")
    print("  " + "-" * 76)
    for rate, det_len, m in results:
        marker = " <-- (Best)" if rate == best_rate else ""
        print(f"  {rate:<6.2f} | {det_len:>8} | {m['tp']:>5} | {m['fp']:>5} | {m['fn']:>5} | {m['precision']:.4f}    | {m['recall']:.4f} | {m['f1']:.4f}{marker}")
    print("  " + "-" * 76 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Ephemeral Cloud Risk Detection anomalies.")
    parser.add_argument("--db-path", type=str, default=str(DB_PATH), help="Path to events.db")
    parser.add_argument("--gt-path", type=str, default=str(GT_PATH), help="Path to ground_truth.json")
    parser.add_argument("--contamination", type=float, default=0.17, help="Single contamination rate to evaluate (default=0.17, matches true anomaly rate of the 5k dataset)")
    parser.add_argument("--sweep", action="store_true", help="Perform contamination sweep")
    args = parser.parse_args()

    db_path = Path(args.db_path)
    gt_path = Path(args.gt_path)

    if not db_path.exists():
        print(f"[ERROR] Database not found: {db_path}")
        print("Please run `python generate_events.py` first.")
        sys.exit(1)

    print("[1/2] Loading ground truth and telemetry data...")
    gt = load_ground_truth(gt_path)
    all_true_ids = set(gt.get("all_true_anomaly_ids", []))
    scenarios = gt.get("anomaly_scenarios", {})

    features_df = calculate_behavioral_features(db_path=str(db_path))

    print("[2/2] Evaluating detection performance...")
    if args.sweep:
        run_sweep(features_df, all_true_ids, scenarios)
    else:
        evaluate_single(features_df, all_true_ids, scenarios, args.contamination)


if __name__ == "__main__":
    main()
