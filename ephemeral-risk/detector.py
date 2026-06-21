"""
detector.py
===========
Unsupervised anomaly detection using scikit-learn IsolationForest.

Public API
----------
    detect_anomalies(
        features_df   : pd.DataFrame,
    contamination : float = 0.01,
        n_estimators  : int   = 300,
        random_state  : int   = 42,
    ) -> pd.DataFrame

    Trains IsolationForest on FEATURE_COLS (StandardScaler-normalised),
    appends anomaly_label and anomaly_score columns, then returns only the
    rows labelled -1 (anomalies).

    Improvements over v1
    --------------------
    * hybrid rules catch high-confidence cloud/K8s/network risk indicators.
    * StandardScaler applied so rolling_burst_count (0-100+) does not
      dominate the binary features (0/1).
    * n_estimators raised 200 → 300 for better tree coverage.
    * Two new high-signal features: vpc_bytes_log, is_unknown_identity.

Requires: numpy, pandas, scikit-learn
"""

from __future__ import annotations

import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score

from features import KNOWN_BAD_IPS, MODEL_FEATURE_COLS as FEATURE_COLS

warnings.filterwarnings("ignore", category=UserWarning)

# ──────────────────────────────────────────────────────────────────────────────
# PATHS
# ──────────────────────────────────────────────────────────────────────────────

_ROOT = Path(__file__).resolve().parent
_CACHE_DIR = _ROOT / "data" / "model_cache"

# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL MODEL CACHE (for warm-up / incremental scoring)
# ──────────────────────────────────────────────────────────────────────────────

_MODEL: IsolationForest | None = None
_SCALER: StandardScaler | None = None
_MODEL_CONTAMINATION: float = 0.10

# Score distribution from training data — used by ml_pipeline._risk_score()
# to map raw anomaly scores into calibrated 0-100 risk scores.
_SCORE_DISTRIBUTION: dict = {
    "min": -0.70,
    "max": 0.0,
    "p5": -0.60,
    "p25": -0.50,
    "median": -0.45,
    "p75": -0.40,
    "p95": -0.37,
    "threshold": -0.50,   # score at which the model labels anomalies
    "normal_mean": -0.42,
    "normal_std": 0.05,
}


def _hybrid_rule_mask(df: pd.DataFrame) -> pd.Series:
    """
    High-confidence security rules layered on top of IsolationForest.

    These are intentionally narrow: they catch obvious production signals
    while leaving valid autoscale/CI bursts alone.
    """
    result = pd.Series(False, index=df.index)

    log_type = df.get("log_type", pd.Series("", index=df.index)).fillna("")
    event_name = df.get("event_name", pd.Series("", index=df.index)).fillna("").astype(str)
    source_ip = df.get("source_ip", pd.Series("", index=df.index)).fillna("").astype(str)
    dst_addr = df.get("dst_addr", pd.Series("", index=df.index)).fillna("").astype(str)
    src_addr = df.get("src_addr", pd.Series("", index=df.index)).fillna("").astype(str)
    namespace = df.get("namespace", pd.Series("", index=df.index)).fillna("").astype(str)

    is_unknown = pd.to_numeric(df.get("is_unknown_identity", 0), errors="coerce").fillna(0).astype(int)
    is_night = pd.to_numeric(df.get("is_night_time", 0), errors="coerce").fillna(0).astype(int)
    weak_tags = pd.to_numeric(df.get("weak_tag_score", 0), errors="coerce").fillna(0)
    missing_tags = pd.to_numeric(df.get("missing_tags_score", 0), errors="coerce").fillna(0)
    untrusted = pd.to_numeric(df.get("untrusted_network_hit", 0), errors="coerce").fillna(0).astype(int)
    privileged = pd.to_numeric(df.get("is_privileged_pod", 0), errors="coerce").fillna(0).astype(int)
    vpc_bytes_log = pd.to_numeric(df.get("vpc_bytes_log", 0), errors="coerce").fillna(0)
    suspicious_session = pd.to_numeric(df.get("suspicious_session", 0), errors="coerce").fillna(0).astype(int)
    long_ttl = pd.to_numeric(df.get("long_token_ttl", 0), errors="coerce").fillna(0).astype(int)

    known_bad_egress = (
        (log_type == "vpc_flow")
        & (dst_addr.isin(KNOWN_BAD_IPS) | src_addr.isin(KNOWN_BAD_IPS))
    )
    tagless_external_compute = (
        (log_type == "cloudtrail")
        & event_name.isin({"RunInstances", "RequestSpotInstances"})
        & (is_unknown.eq(1) | weak_tags.ge(3) | missing_tags.ge(2))
        & (is_night.eq(1) | source_ip.str.startswith(("198.51.100.", "203.0.113.")))
    )
    # Tightened: require privileged AND (untrusted network OR suspicious namespace)
    # AND at least one more signal (unknown identity, night time, or missing tags)
    # to avoid over-flagging normal CI/CD pods in default namespace.
    exposed_privileged_pod = (
        (log_type == "k8s_audit")
        & privileged.eq(1)
        & untrusted.eq(1)
        & (is_unknown.eq(1) | is_night.eq(1) | missing_tags.ge(2))
    )
    identity_or_pii_abuse = (
        (log_type == "cloudtrail")
        & event_name.isin({"AssumeRole", "AssumeRoleWithWebIdentity", "GetObject"})
        & (is_unknown.eq(1) | suspicious_session.eq(1) | long_ttl.eq(1))
        & (untrusted.eq(1) | source_ip.str.startswith(("192.168.", "198.51.100.", "203.0.113.")))
    )
    large_external_transfer = (
        (log_type == "vpc_flow")
        & untrusted.eq(1)
        & vpc_bytes_log.ge(6.0)
    )

    result |= known_bad_egress
    result |= tagless_external_compute
    result |= exposed_privileged_pod
    result |= identity_or_pii_abuse
    result |= large_external_transfer
    return result


def _apply_hybrid_rules(df: pd.DataFrame, labels: np.ndarray, scores: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    rule_mask = _hybrid_rule_mask(df).to_numpy()
    labels = labels.copy()
    scores = scores.copy()
    labels[rule_mask] = -1
    if rule_mask.any():
        floor = scores.min(initial=-0.6) - 0.05
        scores[rule_mask] = np.minimum(scores[rule_mask], floor)
    return labels, scores


# ──────────────────────────────────────────────────────────────────────────────
# K-FOLD CROSS-VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def kfold_evaluate(
    features_df: pd.DataFrame,
    labels: "pd.Series | np.ndarray",
    contamination: float = 0.10,
    n_estimators: int = 400,
    k: int = 5,
    random_state: int = 42,
) -> dict:
    """
    Stratified K-Fold cross-validation for IsolationForest.

    Since IsolationForest is unsupervised, `labels` are NOT used during
    training — they are only used for post-hoc evaluation of each fold's
    predictions. This gives honest out-of-sample Precision / Recall / F1.

    Parameters
    ----------
    features_df  : Feature-engineered DataFrame (output of features.py).
    labels       : Binary array/Series — 1 = true anomaly, 0 = normal.
    contamination: Expected anomaly fraction (should equal true_rate from GT).
    n_estimators : Number of isolation trees.
    k            : Number of folds.
    random_state : Seed for reproducibility.

    Returns
    -------
    dict with keys: mean_precision, mean_recall, mean_f1, per_fold.
    """
    active_cols = [c for c in FEATURE_COLS if c in features_df.columns]
    X_raw = features_df[active_cols].fillna(0).to_numpy(dtype=np.float64)
    y = np.asarray(labels, dtype=int)

    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=random_state)

    fold_results = []
    print("\n" + "=" * 65)
    print(f"  K-FOLD CROSS-VALIDATION  (k={k}, contamination={contamination:.3f})")
    print("=" * 65)
    print(f"  {'Fold':<6} {'Precision':>9} {'Recall':>9} {'F1':>9} {'TP':>5} {'FP':>5} {'FN':>5}")
    print("  " + "-" * 55)

    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X_raw, y), start=1):
        X_train, X_test = X_raw[train_idx], X_raw[test_idx]
        y_test = y[test_idx]

        # Normalise on training split only — prevent data leakage
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s  = scaler.transform(X_test)

        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples="auto",
            max_features=1.0,
            bootstrap=True,
            random_state=random_state,
            n_jobs=-1,
        )
        model.fit(X_train_s)
        preds = model.predict(X_test_s)          # +1 = normal, -1 = anomaly
        y_pred = (preds == -1).astype(int)        # convert to 0/1 label

        # Apply hybrid rules to test rows (rule-based overrides, no leakage)
        test_df = features_df.iloc[test_idx].reset_index(drop=True)
        rule_mask = _hybrid_rule_mask(test_df).to_numpy()
        y_pred[rule_mask] = 1

        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test, y_pred, zero_division=0)
        f1   = f1_score(y_test, y_pred, zero_division=0)
        tp = int(((y_pred == 1) & (y_test == 1)).sum())
        fp = int(((y_pred == 1) & (y_test == 0)).sum())
        fn = int(((y_pred == 0) & (y_test == 1)).sum())

        fold_results.append({"precision": prec, "recall": rec, "f1": f1,
                              "tp": tp, "fp": fp, "fn": fn})
        print(f"  {fold_idx:<6} {prec:>9.4f} {rec:>9.4f} {f1:>9.4f} {tp:>5} {fp:>5} {fn:>5}")

    print("  " + "-" * 55)
    mean_p  = float(np.mean([r["precision"] for r in fold_results]))
    mean_r  = float(np.mean([r["recall"]    for r in fold_results]))
    mean_f1 = float(np.mean([r["f1"]        for r in fold_results]))
    print(f"  {'Mean':<6} {mean_p:>9.4f} {mean_r:>9.4f} {mean_f1:>9.4f}")
    print("=" * 65 + "\n")

    return {"mean_precision": mean_p, "mean_recall": mean_r,
            "mean_f1": mean_f1, "per_fold": fold_results}


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def detect_anomalies(
    features_df:   pd.DataFrame,
    contamination: float = 0.10,
    n_estimators:  int   = 400,
    random_state:  int   = 42,
) -> pd.DataFrame:
    """
    Fit IsolationForest on FEATURE_COLS (after StandardScaler normalisation)
    and return only the anomalous events (those scored with label == -1).

    Three columns are appended to the returned DataFrame:

        anomaly_label : int    — IsolationForest prediction (+1 normal, -1 anomaly)
        anomaly_score : float  — raw score_samples() output; lower ↔ more anomalous
        anomaly_rank  : int    — 1-based rank among anomalies (1 = most suspicious)

    Parameters
    ----------
    features_df   : Output of features.calculate_behavioral_features()
        contamination : Expected fraction of statistical outliers in the dataset.
                    Default 0.01 matches the current hybrid detector sweep:
                    high-confidence rules carry the obvious security cases.
    n_estimators  : Number of isolation trees (300 for better coverage).
    random_state  : Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Subset of *features_df* containing only anomalous rows, sorted by
        anomaly_score ascending (most anomalous first). Returns an empty
        DataFrame (same schema) if no anomalies are found.
    """
    if features_df.empty:
        return features_df.copy()

    missing = [c for c in FEATURE_COLS if c not in features_df.columns]
    if missing:
        raise ValueError(
            f"detect_anomalies(): missing feature column(s): {missing}. "
            "Run calculate_behavioral_features() first."
        )

    # Use only the columns that actually exist (graceful degradation if a new
    # feature column is missing from an older database schema).
    active_cols = [c for c in FEATURE_COLS if c in features_df.columns]
    X_raw = features_df[active_cols].fillna(0).to_numpy(dtype=np.float64)

    # Normalise so high-magnitude features (rolling_burst_count, vpc_bytes_log)
    # don't dominate the binary 0/1 features during tree splitting.
    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=512,
        bootstrap=True,
        random_state=random_state,
        n_jobs=-1,
    )
    labels = model.fit_predict(X)
    scores = model.score_samples(X)
    labels, scores = _apply_hybrid_rules(features_df, labels, scores)

    df = features_df.copy()
    df["anomaly_label"] = labels
    df["anomaly_score"] = scores

    anomalies = df[df["anomaly_label"] == -1].copy()

    if anomalies.empty:
        return anomalies

    anomalies["anomaly_rank"] = (
        anomalies["anomaly_score"]
        .rank(method="min", ascending=True)
        .astype(int)
    )

    return anomalies.sort_values("anomaly_score").reset_index(drop=True)

def score_events(
    features_df: pd.DataFrame,
    contamination: float = 0.10,
    n_estimators: int = 400,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Fit IsolationForest and return the FULL dataframe with anomaly_label 
    and anomaly_score appended to all rows.
    """
    if features_df.empty:
        return features_df.copy()

    active_cols = [c for c in FEATURE_COLS if c in features_df.columns]
    X_raw = features_df[active_cols].fillna(0).to_numpy(dtype=np.float64)

    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=512,
        bootstrap=True,
        random_state=random_state,
        n_jobs=-1,
    )
    labels = model.fit_predict(X)
    scores = model.score_samples(X)
    labels, scores = _apply_hybrid_rules(features_df, labels, scores)

    df = features_df.copy()
    df["anomaly_label"] = labels
    df["anomaly_score"] = scores
    
    return df


# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL MODEL API (warm-up + cached scoring)
# ──────────────────────────────────────────────────────────────────────────────

def fit_global_model(
    features_df: pd.DataFrame,
    contamination: float = 0.10,
    n_estimators: int = 400,
    random_state: int = 42,
) -> None:
    """
    Fit and cache a global IsolationForest + StandardScaler on *features_df*.

    Subsequent calls to ``score_with_global_model`` will reuse this cached
    model instead of re-fitting from scratch every time.

    Also computes the score distribution of the training data so that
    risk scores can be calibrated relative to the training distribution.
    """
    global _MODEL, _SCALER, _MODEL_CONTAMINATION, _SCORE_DISTRIBUTION

    if features_df.empty:
        return

    active_cols = [c for c in FEATURE_COLS if c in features_df.columns]
    X_raw = features_df[active_cols].fillna(0).to_numpy(dtype=np.float64)

    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    print(f"  [fit_global_model] Training IsolationForest: n_estimators={n_estimators}, "
          f"contamination={contamination:.4f}, n_samples={len(X)}")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        max_features=1.0,
        bootstrap=True,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)

    # Compute score distribution from training data for risk calibration
    training_scores = model.score_samples(X)
    training_labels = model.predict(X)
    normal_scores = training_scores[training_labels == 1]

    _SCORE_DISTRIBUTION = {
        "min": float(np.min(training_scores)),
        "max": float(np.max(training_scores)),
        "p5": float(np.percentile(training_scores, 5)),
        "p25": float(np.percentile(training_scores, 25)),
        "median": float(np.median(training_scores)),
        "p75": float(np.percentile(training_scores, 75)),
        "p95": float(np.percentile(training_scores, 95)),
        "threshold": float(model.offset_),  # decision boundary
        "normal_mean": float(np.mean(normal_scores)) if len(normal_scores) > 0 else -0.42,
        "normal_std": float(np.std(normal_scores)) if len(normal_scores) > 0 else 0.05,
    }

    print(f"  Score distribution: min={_SCORE_DISTRIBUTION['min']:.4f}, "
          f"p5={_SCORE_DISTRIBUTION['p5']:.4f}, "
          f"median={_SCORE_DISTRIBUTION['median']:.4f}, "
          f"p95={_SCORE_DISTRIBUTION['p95']:.4f}, "
          f"max={_SCORE_DISTRIBUTION['max']:.4f}, "
          f"threshold(offset)={_SCORE_DISTRIBUTION['threshold']:.4f}")

    _MODEL = model
    _SCALER = scaler
    _MODEL_CONTAMINATION = contamination


def score_with_global_model(
    features_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Score *features_df* using the cached global model.

    Falls back to ``score_events`` (fresh fit) if no global model has been
    fitted yet via ``fit_global_model``.
    """
    if _MODEL is None or _SCALER is None:
        return score_events(features_df, contamination=_MODEL_CONTAMINATION)

    if features_df.empty:
        return features_df.copy()

    active_cols = [c for c in FEATURE_COLS if c in features_df.columns]
    X_raw = features_df[active_cols].fillna(0).to_numpy(dtype=np.float64)
    X = _SCALER.transform(X_raw)

    labels = _MODEL.predict(X)
    scores = _MODEL.score_samples(X)
    labels, scores = _apply_hybrid_rules(features_df, labels, scores)

    df = features_df.copy()
    df["anomaly_label"] = labels
    df["anomaly_score"] = scores

    return df


# ──────────────────────────────────────────────────────────────────────────────
# MODEL PERSISTENCE (joblib)
# ──────────────────────────────────────────────────────────────────────────────

def save_global_model() -> None:
    """Persist the global model, scaler, and score distribution to disk."""
    if _MODEL is None or _SCALER is None:
        print("  [save_global_model] No model fitted yet — nothing to save.")
        return

    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(_MODEL, _CACHE_DIR / "isolation_forest.joblib")
    joblib.dump(_SCALER, _CACHE_DIR / "scaler.joblib")
    joblib.dump({"contamination": _MODEL_CONTAMINATION, "score_distribution": _SCORE_DISTRIBUTION},
                _CACHE_DIR / "metadata.joblib")
    print(f"  [save_global_model] Model persisted to {_CACHE_DIR}")


def load_global_model() -> bool:
    """
    Try to load a previously persisted model from disk.

    Returns True if a valid model was loaded, False otherwise.
    """
    global _MODEL, _SCALER, _MODEL_CONTAMINATION, _SCORE_DISTRIBUTION

    model_path = _CACHE_DIR / "isolation_forest.joblib"
    scaler_path = _CACHE_DIR / "scaler.joblib"
    meta_path = _CACHE_DIR / "metadata.joblib"

    if not (model_path.exists() and scaler_path.exists() and meta_path.exists()):
        return False

    try:
        _MODEL = joblib.load(model_path)
        _SCALER = joblib.load(scaler_path)
        meta = joblib.load(meta_path)
        _MODEL_CONTAMINATION = meta.get("contamination", 0.01)
        _SCORE_DISTRIBUTION = meta.get("score_distribution", _SCORE_DISTRIBUTION)
        print(f"  [load_global_model] Loaded persisted model from {_CACHE_DIR}")
        print(f"  Score distribution: min={_SCORE_DISTRIBUTION['min']:.4f}, "
              f"threshold={_SCORE_DISTRIBUTION['threshold']:.4f}, "
              f"normal_mean={_SCORE_DISTRIBUTION['normal_mean']:.4f}")
        return True
    except Exception as e:
        print(f"  [load_global_model] Failed to load persisted model: {e}")
        _MODEL = None
        _SCALER = None
        return False


def get_score_distribution() -> dict:
    """Return the training score distribution for risk score calibration."""
    return _SCORE_DISTRIBUTION.copy()
