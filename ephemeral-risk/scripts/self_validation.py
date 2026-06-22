import sqlite3
import pandas as pd
import json
from pathlib import Path
from sklearn.metrics import precision_score, recall_score, f1_score
from model.features import calculate_behavioral_features
from model.detector import score_with_global_model

def main():
    events_db_path = Path(__file__).parent.parent / "data" / "events.db"
    gt_path = Path(__file__).parent.parent / "data" / "ground_truth.json"
    
    if not events_db_path.exists():
        print(f"Database not found at {events_db_path}")
        return

    # 1. Load the official Ground Truth
    with open(gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)
    true_anomaly_ids = set(gt_data.get("all_true_anomaly_ids", []))
    
    print("==================================================")
    print("  EPHEMERAL RISK DETECTION - HACKATHON VALIDATION")
    print("==================================================")
    
    # 2. Extract Features directly from the raw events.db
    print("Extracting features from raw telemetry in events.db...")
    features_df = calculate_behavioral_features(db_path=str(events_db_path))
    
    if features_df.empty:
        print("No events found in database.")
        return
        
    print(f"Total events analyzed: {len(features_df)}")
    
    # 3. Generate Ground Truth labels
    y_true = features_df['event_id'].isin(true_anomaly_ids).astype(int)
    
    # 4. Score with the Tuned ML Pipeline
    print("Scoring events with tuned Isolation Forest (contamination=0.14)...")
    scored_df = score_with_global_model(features_df)
    y_pred = (scored_df['anomaly_label'] == -1).astype(int)
    
    # 5. Output ML Metrics
    print(f"Actual attacks (Ground Truth): {y_true.sum()}")
    print(f"Predicted attacks (Alerts): {y_pred.sum()}\n")

    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.2%}")
    print(f"Recall:    {recall_score(y_true, y_pred, zero_division=0):.2%}")
    print(f"F1 Score:  {f1_score(y_true, y_pred, zero_division=0):.2f}\n")

    # 6. Simulate Alert Clustering (Grouping by Principal & Time Window)
    raw_alerts = y_pred.sum()
    if raw_alerts > 0:
        alert_df = features_df[y_pred == 1].copy()
        alert_df['timestamp'] = pd.to_datetime(alert_df['timestamp'])
        # Cluster into 30-min campaigns per identity
        alert_df['time_window'] = alert_df['timestamp'].dt.floor('30min')
        clustered_incidents = alert_df.groupby(['principal_id', 'time_window']).ngroups
        
        reduction = (1 - clustered_incidents / raw_alerts) * 100
        print(f"Alert reduction: {raw_alerts} isolated alerts -> {clustered_incidents} correlated incidents ({reduction:.0f}% reduction)")
    else:
        print("Alert reduction: 0 alerts -> 0 incidents (0% reduction)")

    print("\n# Target: Precision > 75%, Recall > 70%, Alert reduction >= 40%")
    print("==================================================")

if __name__ == "__main__":
    main()
