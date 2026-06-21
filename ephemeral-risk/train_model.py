import joblib
import os
import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from features import calculate_behavioral_features, FEATURE_COLS

DB_PATH = BASE_DIR / "data" / "events.db"

def main():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH} does not exist. Cannot train.")
        return

    print("Loading historical data...")
    features_df = calculate_behavioral_features(db_path=str(DB_PATH))
    if features_df.empty:
        print("No features extracted. Aborting.")
        return

    active_cols = [c for c in FEATURE_COLS if c in features_df.columns]
    X = features_df[active_cols].fillna(0).to_numpy(dtype=float)

    print(f"Fitting IsolationForest on {X.shape[0]} samples...")
    model = IsolationForest(
        n_estimators=300,
        contamination=0.01,
        max_samples=512,
        bootstrap=True,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    print("Fitting MinMaxScaler to decision function scores...")
    raw_scores = model.decision_function(X)
    inverted_scores = raw_scores * -1
    scaler = MinMaxScaler()
    scaler.fit(inverted_scores.reshape(-1, 1))

    # Save to disk
    joblib.dump(model, 'iso_forest.joblib')
    joblib.dump(scaler, 'scaler.joblib')

    print("Saved iso_forest.joblib and scaler.joblib successfully!")

if __name__ == '__main__':
    main()
