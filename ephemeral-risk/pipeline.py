"""
pipeline.py
===========
Master orchestration script for the Ephemeral Cloud Risk Detection system.

Data flow
---------
    features.calculate_behavioral_features()
        ↓  feature-enriched DataFrame
    detector.detect_anomalies()
        ↓  anomaly-only DataFrame
    correlator.group_anomalies_into_incidents()
        ↓  list of incident campaign dicts
    correlator.run_local_llm_triage()  (per incident)
        ↓  IncidentTriageReport (Pydantic)
    → terminal summary + returned result dict

Public API
----------
    execute_security_pipeline(
        contamination_rate : float = 0.01,
        db_path            : str   = "data/events.db",
        run_llm_triage     : bool  = True,
        window_min         : int   = 5,
    ) -> dict

Usage
-----
    python pipeline.py
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from features   import calculate_behavioral_features        # noqa: E402
from detector   import detect_anomalies                     # noqa: E402
from correlator import (                                    # noqa: E402
    group_anomalies_into_incidents,
    run_local_llm_triage,
    IncidentTriageReport,
)

DB_PATH = str(ROOT / "data" / "events.db")


# ──────────────────────────────────────────────────────────────────────────────
# CORE PIPELINE
# ──────────────────────────────────────────────────────────────────────────────

def execute_security_pipeline(
    contamination_rate: float = 0.01,
    db_path:            str   = DB_PATH,
    run_llm_triage:     bool  = True,
    window_min:         int   = 5,
    gemini_api_key:     str | None = None,
) -> dict:
    """
    Run the full detection pipeline end-to-end and return results.

    Returns
    -------
    dict with keys: features_df, anomalies_df, incidents, triage_reports
    """
    SEP = "=" * 70
    BAR = "-" * 70

    print(f"\n{SEP}")
    print("  EPHEMERAL CLOUD RISK DETECTION  —  SECURITY PIPELINE")
    print(f"{SEP}\n")

    print("[1/4] FEATURE ENGINEERING")
    print(BAR)
    features_df = calculate_behavioral_features(db_path=db_path)
    n_events = len(features_df)
    print(f"\n  Feature matrix : {n_events:,} events × {features_df.shape[1]} columns")
    for lt, cnt in features_df["log_type"].value_counts().items():
        print(f"    {lt:<20} : {cnt:>5,} events")

    print(f"\n[2/4] ANOMALY DETECTION  (contamination={contamination_rate})")
    print(BAR)
    anomalies_df = detect_anomalies(features_df, contamination=contamination_rate)
    n_anomalies  = len(anomalies_df)

    print(f"  Total events   : {n_events:,}")
    print(f"  Normal         : {n_events - n_anomalies:,}  ({(n_events-n_anomalies)/n_events*100:.1f}%)")
    print(f"  Anomalies      : {n_anomalies:,}  ({n_anomalies/n_events*100:.1f}%)")

    if not anomalies_df.empty:
        print(f"\n  Anomalies by log_type:")
        for lt, cnt in anomalies_df["log_type"].value_counts().items():
            print(f"    {lt:<20} : {cnt:>4}")
        print(f"\n  Anomalies by raw severity:")
        for sv, cnt in anomalies_df["severity"].value_counts().items():
            print(f"    {sv:<12} : {cnt:>4}")

    if anomalies_df.empty:
        print("\n  [INFO] No anomalies detected. Pipeline halted.")
        return {"features_df": features_df, "anomalies_df": anomalies_df,
                "incidents": [], "triage_reports": []}

    print(f"\n[3/4] INCIDENT CORRELATION  (window={window_min} min)")
    print(BAR)
    incidents    = group_anomalies_into_incidents(anomalies_df, db_path=db_path, window_min=window_min)
    n_incidents  = len(incidents)
    total_alerts = sum(len(i["raw_telemetry_events"]) for i in incidents)

    print(f"  Raw anomaly alerts   : {total_alerts}")
    print(f"  Incident campaigns   : {n_incidents}")
    print(f"  Alert fatigue relief : {total_alerts/max(n_incidents,1):.1f}× reduction\n")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = sum(1 for i in incidents if i["severity"] == sev)
        if cnt:
            print(f"    {sev:<12} : {cnt} campaign(s)")

    print(f"\n[4/4] LLM TRIAGE  ({'enabled' if run_llm_triage else 'disabled'})")
    print(BAR)

    triage_reports: list[IncidentTriageReport] = []

    if run_llm_triage:
        for idx, incident in enumerate(incidents, 1):
            inc_id = incident["incident_id"]
            print(f"  Triaging incident {idx}/{n_incidents}  [{incident['severity']}]  {inc_id[:16]}…")
            report = run_local_llm_triage(incident_logs=incident["raw_telemetry_events"], incident_id=inc_id, api_key=gemini_api_key)
            triage_reports.append(report)
            incident["triage"] = report.model_dump()
    else:
        print("  LLM triage skipped (run_llm_triage=False).")

    return {
        "features_df":    features_df,
        "anomalies_df":   anomalies_df,
        "incidents":      incidents,
        "triage_reports": triage_reports,
    }


# ──────────────────────────────────────────────────────────────────────────────
# TERMINAL SUMMARY
# ──────────────────────────────────────────────────────────────────────────────

def _print_summary(result: dict) -> None:
    SEP  = "=" * 70
    BAR  = "-" * 70
    THIN = "·" * 70

    incidents      = result["incidents"]
    triage_reports = result["triage_reports"]

    if not incidents:
        print(f"\n{SEP}\n  [ALL CLEAR] No active incidents.\n{SEP}\n")
        return

    total_alerts = sum(len(i["raw_telemetry_events"]) for i in incidents)

    print(f"\n{SEP}")
    print("  ACTIVE INCIDENT PORTFOLIO")
    print(f"{SEP}")
    print(f"\n  {'#':<4} {'Incident ID':<38} {'Severity':<10} {'Nodes':>6} {'Alerts':>7}  Lead Entity")
    print(BAR)

    for idx, inc in enumerate(incidents, 1):
        lead = next((n for n in inc["affected_nodes"] if n.startswith("id:")), inc["affected_nodes"][0] if inc["affected_nodes"] else "—")
        print(f"  {idx:<4} {inc['incident_id'][:36]:<38} {inc['severity']:<10} {len(inc['affected_nodes']):>6} {len(inc['raw_telemetry_events']):>7}  {lead}")

    print(BAR)
    print(f"\n  Raw alerts → {total_alerts}  |  Campaigns → {len(incidents)}  |  {total_alerts/max(len(incidents),1):.1f}× reduction\n")

    print(f"{SEP}")
    print("  INCIDENT DETAIL")
    print(f"{SEP}")

    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", 200)
    pd.set_option("display.float_format", "{:.4f}".format)
    pd.set_option("display.max_colwidth", 36)

    DETAIL_COLS = [
        "event_id", "timestamp", "log_type", "severity", "identity",
        "is_night_time", "rolling_burst_count", "is_privileged_pod",
        "untrusted_network_hit", "missing_tags_score", "anomaly_score", "anomaly_rank",
    ]

    for idx, inc in enumerate(incidents, 1):
        print(f"\n  ── Campaign #{idx}  [{inc['severity']}]  ID: {inc['incident_id']}")

        groups: dict[str, list[str]] = {}
        for node in sorted(inc["affected_nodes"]):
            pre, _, val = node.partition(":")
            groups.setdefault(pre, []).append(val)
        labels = {"id":"Identities","arn":"ARNs","ip":"IPs","res":"Resources","ns":"Namespaces"}
        for pre, vals in groups.items():
            print(f"  {labels.get(pre,pre):<12}: {', '.join(vals[:5])}" + (" …" if len(vals)>5 else ""))

        events_df = pd.DataFrame(inc["raw_telemetry_events"])
        if "anomaly_rank" in events_df.columns:
            events_df = events_df.sort_values("anomaly_rank")
        avail = [c for c in DETAIL_COLS if c in events_df.columns]
        print(f"\n  Top events ({min(5, len(events_df))}/{len(events_df)}):")
        print(THIN)
        print(events_df[avail].head(5).to_string(index=False))
        print(THIN)

        if idx - 1 < len(triage_reports):
            tr = triage_reports[idx - 1]
            print(f"\n  ╔══ TRIAGE REPORT ══════════════════════════════════════════")
            print(f"  ║  Title    : {tr.incident_title}")
            print(f"  ║  Severity : {tr.severity}")
            print(f"  ║  Tactics  : {', '.join(tr.mitre_tactics)}")
            print(f"  ║  Summary  : {tr.executive_summary[:180]}{'…' if len(tr.executive_summary)>180 else ''}")
            print(f"  ║  Timeline :")
            for step in tr.attack_timeline:
                print(f"  ║    {step.time:<10} {step.action}")
            print(f"  ╚{'═'*60}")

    print(f"\n{SEP}\n  [OK] Pipeline complete.\n{SEP}\n")


# ──────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    db = Path(DB_PATH)
    if not db.exists():
        print(f"\n[ERROR] Database not found: {db}\nRun  python generate_events.py  first.\n")
        sys.exit(1)

    result = execute_security_pipeline(contamination_rate=0.01, db_path=DB_PATH,
                                       run_llm_triage=True, window_min=5)
    _print_summary(result)
