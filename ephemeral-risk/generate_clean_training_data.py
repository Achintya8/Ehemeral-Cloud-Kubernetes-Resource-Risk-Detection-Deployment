"""
generate_clean_training_data.py
================================

Builds a clean, labeled synthetic dataset for model training/evaluation.

Outputs:
  data/events.db                         SQLite database compatible with features.py
  data/ground_truth.json                 anomaly labels grouped by scenario
  data/exports/telemetry_raw.csv         flattened raw telemetry
  data/exports/features_with_labels.csv  model features plus labels
  data/exports/anomalies_only.csv        labeled anomalous events only
  data/exports/dataset_summary.json      counts and expected mix checks

The database keeps the existing normalized tables used by the model and adds
sidecar tables for fields the original schema did not store directly:
  cloudtrail_event_metadata: tags, request parameters, user agent
  k8s_event_metadata: labels, controller owner, service exposure, RBAC fields
  identity_session_events: assumed-role, service-account token, federation events
"""

from __future__ import annotations

import datetime as dt
import json
import random
import sqlite3
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from features import calculate_behavioral_features


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
EXPORT_DIR = DATA_DIR / "exports"
DB_PATH = DATA_DIR / "events.db"
GT_PATH = DATA_DIR / "ground_truth.json"
SUMMARY_PATH = EXPORT_DIR / "dataset_summary.json"
SCHEMA = ROOT / "schema.sql"

AWS_ACCOUNT_ID = "123456789012"
BASE_DATE = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
SIM_START = BASE_DATE
SIM_END = BASE_DATE + dt.timedelta(hours=24)   # full day → realistic is_night_time distribution

RANDOM_SEED = 20260620

# ── Event-type split that sums to ~5 000 total timeline rows ─────────────────
# cloudtrail + identity_session share the same rows (identity events are
# implemented as CloudTrail calls), so the true row count is:
#   cloudtrail + k8s_audit + identity_session  ≈ 5 000
TARGET_COUNTS = {
    "cloudtrail":        1_600,   # ~32%
    "k8s_audit":         2_100,   # ~42%
    "identity_session":  1_300,   # ~26%
}

# ── Scenario mix (must sum to TARGET_TOTAL) ───────────────────────────────────
# Constraints (of 5 000 total):
#   Resource hijacking / crypto mining       : 5-8%  →  325  (6.5%)
#   Public exposure of ephemeral compute     : 3-5%  →  200  (4.0%)
#   Unexpected identity/session activity     : 5-8%  →  325  (6.5%)
#   Legitimate autoscaling / CI/CD bursts    : 40-50%→ 2250  (45.0%)
#   Routine ephemeral lifecycle (normal)     : 30-40%→ 1900  (38.0%)
SCENARIO_TARGETS = {
    "scenario_1_crypto_mining":  325,    # resource hijacking,             6.5 %
    "scenario_2_debug_pod":      200,    # public exposure,                4.0 %
    "scenario_3_identity_leak":  325,    # unexpected identity/session,    6.5 %
    "scenario_4_false_positive": 2_250,  # legitimate autoscaling/CI/CD,  45.0 %
    "baseline":                  1_900,  # routine ephemeral lifecycle,   38.0 %
}

VALID_CI_CD_USERS = ["ci-runner-svc", "github-actions-svc", "jenkins-deployer"]
VALID_DEVOPS_USERS = ["devops-pipeline", "argocd-svc", "flux-controller"]
VALID_IDENTITIES = VALID_CI_CD_USERS + VALID_DEVOPS_USERS + [
    "hpa-controller",
    "kube-scheduler",
    "metrics-server",
    "svc-metrics",
    "dev-alice",
]
VALID_NAMESPACES = ["production", "staging", "monitoring", "kube-system", "infra"]
WORKLOADS = [
    "api-gateway",
    "auth-service",
    "payment-processor",
    "recommendation-engine",
    "notification-svc",
    "metrics-adapter",
]
AWS_SOURCES = {
    "RunInstances": "ec2.amazonaws.com",
    "TerminateInstances": "ec2.amazonaws.com",
    "DescribeInstances": "ec2.amazonaws.com",
    "CreateTags": "ec2.amazonaws.com",
    "AssumeRole": "sts.amazonaws.com",
    "AssumeRoleWithWebIdentity": "sts.amazonaws.com",
    "GetCallerIdentity": "sts.amazonaws.com",
    "CreateBucket": "s3.amazonaws.com",
    "PutBucketTagging": "s3.amazonaws.com",
    "PutObject": "s3.amazonaws.com",
    "GetObject": "s3.amazonaws.com",
    "AccessKubernetesApi": "eks.amazonaws.com",
    "CreateService": "eks.amazonaws.com",
    "CreateRoleBinding": "eks.amazonaws.com",
}
CORP_NAT_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.55"]
KNOWN_BAD_IPS = ["185.220.101.47", "45.142.212.100", "91.108.4.200", "198.51.100.77"]


timeline_rows: list[dict[str, Any]] = []
cloudtrail_rows: list[dict[str, Any]] = []
k8s_rows: list[dict[str, Any]] = []
cloudtrail_metadata_rows: list[dict[str, Any]] = []
k8s_metadata_rows: list[dict[str, Any]] = []
identity_session_rows: list[dict[str, Any]] = []
ground_truth: dict[str, list[str]] = defaultdict(list)


def _uid() -> str:
    return str(uuid.uuid4())


def _ts_for_scenario(scenario: str) -> dt.datetime:
    if scenario == "scenario_1_crypto_mining":
        # Two distinct crypto bursts: one at night (01:30) and one at midday (13:00)
        burst = random.choice([
            BASE_DATE + dt.timedelta(hours=1, minutes=30),   # night-time burst
            BASE_DATE + dt.timedelta(hours=13, minutes=0),   # daytime burst
        ])
        start = burst
        end = burst + dt.timedelta(minutes=40)
    elif scenario == "scenario_2_debug_pod":
        # Debug pod exposure during business hours
        start = BASE_DATE + dt.timedelta(hours=9, minutes=5)
        end = start + dt.timedelta(minutes=35)
    elif scenario == "scenario_3_identity_leak":
        # Two identity-leak windows: early morning and afternoon
        burst = random.choice([
            BASE_DATE + dt.timedelta(hours=3, minutes=10),   # off-hours
            BASE_DATE + dt.timedelta(hours=14, minutes=20),  # business hours
        ])
        start = burst
        end = burst + dt.timedelta(minutes=55)
    elif scenario == "scenario_4_false_positive":
        # Multiple CI/CD burst windows spread across the business day
        burst = random.choice([
            BASE_DATE + dt.timedelta(hours=7,  minutes=30),
            BASE_DATE + dt.timedelta(hours=9,  minutes=0),
            BASE_DATE + dt.timedelta(hours=11, minutes=15),
            BASE_DATE + dt.timedelta(hours=13, minutes=30),
            BASE_DATE + dt.timedelta(hours=15, minutes=45),
            BASE_DATE + dt.timedelta(hours=18, minutes=0),
        ])
        start = burst
        end = burst + dt.timedelta(minutes=15)
    else:
        # Baseline: spread uniformly across the full 24-hour window
        start = SIM_START
        end = SIM_END
    seconds = random.uniform(0, (end - start).total_seconds())
    return start + dt.timedelta(seconds=seconds)



def _internal_ip() -> str:
    return random.choice([
        f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}",
        f"192.168.{random.randint(0, 4)}.{random.randint(1, 254)}",
        f"172.19.{random.randint(0, 5)}.{random.randint(1, 254)}",
    ])


def _external_ip() -> str:
    return random.choice([
        f"198.51.100.{random.randint(1, 254)}",
        f"203.0.113.{random.randint(1, 254)}",
        f"52.94.{random.randint(0, 255)}.{random.randint(1, 254)}",
    ])


def _arn(principal: str, assumed: bool = False) -> str:
    if assumed:
        role = random.choice(["ProdDeployRole", "CICDRole"])
        return f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/{role}/{principal}-{uuid.uuid4().hex[:8]}"
    if principal in VALID_CI_CD_USERS:
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/CICDRole"
    if principal in VALID_DEVOPS_USERS:
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/ProdDeployRole"
    if principal == "svc-metrics":
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/svc-metrics"
    if principal == "dev-alice":
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/dev-alice"
    return f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{principal}"


def _tags(owner: str, env: str, app: str, clean: bool = True) -> dict[str, str]:
    if not clean:
        return {"Name": f"untagged-{app}-{uuid.uuid4().hex[:5]}"}
    return {
        "Owner": owner,
        "Environment": env,
        "Application": app,
        "ManagedBy": "ephemeral-risk-sim",
        "CostCenter": random.choice(["cc-1042", "cc-2030", "cc-3110"]),
    }


def _labels(app: str, clean: bool = True) -> dict[str, str]:
    if not clean:
        return {"app": app}
    return {
        "app": app,
        "managed-by": random.choice(["hpa", "argocd", "github-actions"]),
        "owner": random.choice(["platform", "payments", "identity"]),
        "env": random.choice(["prod", "stage", "infra"]),
    }


def _track_truth(scenario: str, event_id: str) -> None:
    if scenario in {"scenario_1_crypto_mining", "scenario_2_debug_pod", "scenario_3_identity_leak"}:
        ground_truth[scenario].append(event_id)


def _add_timeline(event_id: str, timestamp: dt.datetime, log_type: str, scenario: str) -> None:
    severity = "INFO"
    if scenario in {"scenario_1_crypto_mining", "scenario_3_identity_leak"}:
        severity = "CRITICAL"
    elif scenario == "scenario_2_debug_pod":
        severity = "HIGH"
    timeline_rows.append({
        "event_id": event_id,
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "log_type": log_type,
        "severity": severity,
        "scenario": scenario,
    })
    _track_truth(scenario, event_id)


def _add_cloudtrail(
    scenario: str,
    event_name: str,
    principal: str,
    source_ip: str,
    timestamp: dt.datetime | None = None,
    tags: dict[str, str] | None = None,
    request: dict[str, Any] | None = None,
) -> str:
    event_id = _uid()
    ts = timestamp or _ts_for_scenario(scenario)
    _add_timeline(event_id, ts, "cloudtrail", scenario)
    cloudtrail_rows.append({
        "event_id": event_id,
        "event_source": AWS_SOURCES[event_name],
        "event_name": event_name,
        "principal_id": principal,
        "arn": _arn(principal, assumed=event_name in {"AssumeRole", "AssumeRoleWithWebIdentity"}),
        "source_ip": source_ip,
    })
    cloudtrail_metadata_rows.append({
        "event_id": event_id,
        "tags_json": json.dumps(tags or {}, sort_keys=True),
        "request_parameters_json": json.dumps(request or {}, sort_keys=True),
        "user_agent": random.choice(["aws-cli/2", "botocore/1", "terraform/1.8", "github-actions-runner"]),
    })
    return event_id


def _add_k8s(
    scenario: str,
    verb: str,
    resource_name: str,
    namespace: str,
    username: str,
    pod_ip: str,
    is_privileged: int = 0,
    timestamp: dt.datetime | None = None,
    labels: dict[str, str] | None = None,
    controller_owner: str = "",
    service_type: str = "",
    rbac_change: str = "",
) -> str:
    event_id = _uid()
    ts = timestamp or _ts_for_scenario(scenario)
    _add_timeline(event_id, ts, "k8s_audit", scenario)
    k8s_rows.append({
        "event_id": event_id,
        "verb": verb,
        "resource_name": resource_name,
        "namespace": namespace,
        "username": username,
        "pod_ip": pod_ip,
        "is_privileged": is_privileged,
    })
    k8s_metadata_rows.append({
        "event_id": event_id,
        "labels_json": json.dumps(labels or {}, sort_keys=True),
        "controller_owner": controller_owner,
        "service_type": service_type,
        "rbac_change": rbac_change,
    })
    return event_id


def _add_identity_session(
    scenario: str,
    session_type: str,
    principal: str,
    source_ip: str,
    timestamp: dt.datetime | None = None,
) -> str:
    event_name_by_type = {
        "assumed_role": "AssumeRole",
        "service_account_token": "AssumeRoleWithWebIdentity",
        "federation": "GetCallerIdentity",
    }
    event_name = event_name_by_type[session_type]
    event_id = _add_cloudtrail(
        scenario=scenario,
        event_name=event_name,
        principal=principal,
        source_ip=source_ip,
        timestamp=timestamp,
        tags=_tags("identity-platform", "prod", "session-broker", clean=scenario != "scenario_3_identity_leak"),
        request={
            "sessionName": f"{principal}-{uuid.uuid4().hex[:8]}",
            "durationSeconds": random.choice([900, 1800, 3600]),
            "provider": random.choice(["oidc.eks.amazonaws.com", "saml.corp.example", "github-oidc"]),
        },
    )
    identity_session_rows.append({
        "event_id": event_id,
        "session_type": session_type,
        "principal_id": principal,
        "session_name": f"{principal}-{uuid.uuid4().hex[:10]}",
        "issuer": random.choice(["eks-oidc", "github-oidc", "corp-saml"]),
        "source_ip": source_ip,
        "token_ttl_seconds": random.choice([600, 900, 1800, 3600]),
    })
    return event_id


def _scenario_for_bucket(bucket: str) -> str:
    cumulative = 0
    roll = random.randint(1, sum(SCENARIO_TARGETS.values()))
    for scenario, count in SCENARIO_TARGETS.items():
        cumulative += count
        if roll <= cumulative:
            return scenario
    return "baseline"


def _cloudtrail_event_for_scenario(scenario: str) -> None:
    if scenario == "scenario_1_crypto_mining":
        principal = random.choice(["svc-datapipeline-legacy", "build-cache-temp"])
        app = "miner"
        name = random.choices(["RunInstances", "CreateTags", "TerminateInstances"], weights=[8, 1, 1])[0]
        clean_tags = False
        source_ip = random.choice(KNOWN_BAD_IPS + [_external_ip()])
    elif scenario == "scenario_2_debug_pod":
        principal = random.choice(["dev-alice", "devops-pipeline"])
        app = "debug-nodeport"
        name = random.choice(["AccessKubernetesApi", "CreateService"])
        clean_tags = True
        source_ip = random.choice(CORP_NAT_IPS)
    elif scenario == "scenario_3_identity_leak":
        principal = random.choice(["svc-datapipeline-legacy", "DataAnalyticsRole:stolen-session"])
        app = "pii-reader"
        name = random.choices(["AssumeRole", "AssumeRoleWithWebIdentity", "GetObject"], weights=[2, 3, 7])[0]
        clean_tags = False
        source_ip = random.choice([_external_ip(), _internal_ip()])
    elif scenario == "scenario_4_false_positive":
        principal = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS)
        app = random.choice(WORKLOADS)
        name = random.choices(
            ["RunInstances", "AssumeRole", "CreateBucket", "PutBucketTagging", "AccessKubernetesApi"],
            weights=[3, 4, 1, 2, 5],
        )[0]
        clean_tags = True
        source_ip = random.choice(CORP_NAT_IPS)
    else:
        principal = random.choice(VALID_IDENTITIES)
        app = random.choice(WORKLOADS)
        name = random.choice([
            "DescribeInstances", "GetCallerIdentity", "AssumeRole", "CreateBucket",
            "PutBucketTagging", "PutObject", "AccessKubernetesApi",
        ])
        clean_tags = True
        source_ip = random.choice(CORP_NAT_IPS + [_internal_ip()])

    _add_cloudtrail(
        scenario=scenario,
        event_name=name,
        principal=principal,
        source_ip=source_ip,
        tags=_tags(principal, random.choice(["prod", "stage", "infra"]), app, clean=clean_tags),
        request={
            "resource": f"{app}-{uuid.uuid4().hex[:8]}",
            "region": random.choice(["us-east-1", "us-west-2", "ap-south-1"]),
            "ephemeral": True,
        },
    )


def _k8s_event_for_scenario(scenario: str) -> None:
    app = random.choice(WORKLOADS)
    pod = f"{app}-{uuid.uuid4().hex[:8]}"
    if scenario == "scenario_1_crypto_mining":
        namespace = random.choice(["default", "ci-build"])
        username = random.choice(["svc-datapipeline-legacy", "unknown-builder"])
        verb = random.choices(["create", "delete"], weights=[8, 2])[0]
        is_privileged = random.choice([0, 1])
        labels = _labels("miner", clean=False)
        owner = ""
        service_type = ""
        rbac = ""
    elif scenario == "scenario_2_debug_pod":
        namespace = "default"
        username = random.choice(["dev-alice", "temporary-admin"])
        verb = random.choice(["create", "patch", "delete"])
        is_privileged = 1
        labels = _labels("debug-shell", clean=False)
        owner = ""
        service_type = random.choice(["NodePort", "LoadBalancer"])
        rbac = random.choice(["create-rolebinding", "bind-cluster-admin", ""])
    elif scenario == "scenario_3_identity_leak":
        namespace = random.choice(["production", "default"])
        username = random.choice(["compromised-svc", "svc-datapipeline-legacy"])
        verb = random.choice(["get", "create", "create-token"])
        is_privileged = 0
        labels = _labels("token-reader", clean=False)
        owner = "job/pii-export"
        service_type = ""
        rbac = random.choice(["service-account-token", "impersonate-user", ""])
    elif scenario == "scenario_4_false_positive":
        namespace = random.choice(["production", "staging", "infra"])
        username = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS + ["hpa-controller"])
        verb = random.choice(["create", "delete", "scale-up", "scale-down"])
        is_privileged = 0
        labels = _labels(app, clean=True)
        owner = random.choice([f"deployment/{app}", f"job/{app}-build", f"replicaset/{app}-rs"])
        service_type = random.choice(["", "ClusterIP"])
        rbac = ""
    else:
        namespace = random.choice(VALID_NAMESPACES)
        username = random.choice(VALID_IDENTITIES)
        verb = random.choice(["create", "delete", "get", "scale-up", "scale-down"])
        is_privileged = 0
        labels = _labels(app, clean=True)
        owner = random.choice([f"deployment/{app}", f"job/{app}-cleanup", f"replicaset/{app}-rs"])
        service_type = random.choice(["", "ClusterIP"])
        rbac = random.choice(["", "read-only-rolebinding"])

    _add_k8s(
        scenario=scenario,
        verb=verb,
        resource_name=pod,
        namespace=namespace,
        username=username,
        pod_ip=_internal_ip(),
        is_privileged=is_privileged,
        labels=labels,
        controller_owner=owner,
        service_type=service_type,
        rbac_change=rbac,
    )


def _identity_event_for_scenario(scenario: str) -> None:
    if scenario == "scenario_3_identity_leak":
        principal = random.choice(["svc-datapipeline-legacy", "compromised-svc", "DataAnalyticsRole:stolen-session"])
        source_ip = random.choice([_external_ip(), _internal_ip()])
        session_type = random.choice(["assumed_role", "service_account_token", "federation"])
    elif scenario == "scenario_2_debug_pod":
        principal = random.choice(["temporary-admin", "dev-alice"])
        source_ip = random.choice(CORP_NAT_IPS + [_external_ip()])
        session_type = random.choice(["service_account_token", "assumed_role"])
    elif scenario == "scenario_1_crypto_mining":
        principal = random.choice(["svc-datapipeline-legacy", "unknown-builder"])
        source_ip = random.choice(KNOWN_BAD_IPS + [_external_ip()])
        session_type = random.choice(["assumed_role", "federation"])
    elif scenario == "scenario_4_false_positive":
        principal = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS)
        source_ip = random.choice(CORP_NAT_IPS)
        session_type = random.choice(["assumed_role", "service_account_token", "federation"])
    else:
        principal = random.choice(VALID_IDENTITIES)
        source_ip = random.choice(CORP_NAT_IPS + [_internal_ip()])
        session_type = random.choice(["assumed_role", "service_account_token", "federation"])
    _add_identity_session(scenario, session_type, principal, source_ip)


def _weighted_scenarios(total: int) -> list[str]:
    scenarios: list[str] = []
    for scenario, target in SCENARIO_TARGETS.items():
        scenarios.extend([scenario] * round(total * target / sum(SCENARIO_TARGETS.values())))
    while len(scenarios) < total:
        scenarios.append(_scenario_for_bucket("event"))
    scenarios = scenarios[:total]
    random.shuffle(scenarios)
    return scenarios


def _generate_events() -> None:
    for scenario in _weighted_scenarios(TARGET_COUNTS["cloudtrail"]):
        _cloudtrail_event_for_scenario(scenario)
    for scenario in _weighted_scenarios(TARGET_COUNTS["k8s_audit"]):
        _k8s_event_for_scenario(scenario)
    for scenario in _weighted_scenarios(TARGET_COUNTS["identity_session"]):
        _identity_event_for_scenario(scenario)


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cloudtrail_event_metadata (
            event_id TEXT PRIMARY KEY,
            tags_json TEXT NOT NULL,
            request_parameters_json TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );

        CREATE TABLE IF NOT EXISTS k8s_event_metadata (
            event_id TEXT PRIMARY KEY,
            labels_json TEXT NOT NULL,
            controller_owner TEXT NOT NULL,
            service_type TEXT NOT NULL,
            rbac_change TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        """
    )
    # identity_session_events is created by schema.sql without principal_id / source_ip.
    # Add them via ALTER TABLE (no-op if they already exist).
    existing_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(identity_session_events)").fetchall()
    }
    if "principal_id" not in existing_cols:
        conn.execute("ALTER TABLE identity_session_events ADD COLUMN principal_id TEXT NOT NULL DEFAULT ''")
    if "source_ip" not in existing_cols:
        conn.execute("ALTER TABLE identity_session_events ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''")
    conn.commit()



def _to_sql(conn: sqlite3.Connection, table: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    pd.DataFrame(rows).to_sql(table, conn, if_exists="append", index=False, method="multi", chunksize=500)


def _write_database() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    for wal_path in (DB_PATH.with_suffix(".db-wal"), DB_PATH.with_suffix(".db-shm")):
        if wal_path.exists():
            wal_path.unlink()

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        _init_db(conn)
        timeline = sorted(timeline_rows, key=lambda row: row["timestamp"])
        _to_sql(conn, "telemetry_timeline", timeline)
        _to_sql(conn, "cloudtrail_events", cloudtrail_rows)
        _to_sql(conn, "k8s_audit_events", k8s_rows)
        _to_sql(conn, "cloudtrail_event_metadata", cloudtrail_metadata_rows)
        _to_sql(conn, "k8s_event_metadata", k8s_metadata_rows)
        _to_sql(conn, "identity_session_events", identity_session_rows)
        conn.commit()
    finally:
        conn.close()


def _write_ground_truth() -> None:
    all_true = [event_id for ids in ground_truth.values() for event_id in ids]
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "description": "Clean synthetic dataset with cloud audit, Kubernetes, and identity/session telemetry.",
        "anomaly_scenarios": dict(sorted(ground_truth.items())),
        "false_positive_scenario": {
            "scenario_4_false_positive": [
                row["event_id"] for row in timeline_rows if row["scenario"] == "scenario_4_false_positive"
            ]
        },
        "all_true_anomaly_ids": all_true,
    }
    GT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _export_flattened() -> dict[str, Any]:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        raw = pd.read_sql_query(
            """
            SELECT
                t.event_id, t.timestamp, t.log_type, t.severity, t.scenario,
                c.event_source, c.event_name, c.principal_id, c.arn, c.source_ip AS cloud_source_ip,
                cm.tags_json, cm.request_parameters_json, cm.user_agent,
                k.verb, k.resource_name, k.namespace, k.username, k.pod_ip, k.is_privileged,
                km.labels_json, km.controller_owner, km.service_type, km.rbac_change,
                i.session_type, i.session_name, i.issuer, i.token_ttl_seconds
            FROM telemetry_timeline t
            LEFT JOIN cloudtrail_events c ON c.event_id = t.event_id
            LEFT JOIN cloudtrail_event_metadata cm ON cm.event_id = t.event_id
            LEFT JOIN k8s_audit_events k ON k.event_id = t.event_id
            LEFT JOIN k8s_event_metadata km ON km.event_id = t.event_id
            LEFT JOIN identity_session_events i ON i.event_id = t.event_id
            ORDER BY t.timestamp ASC
            """,
            conn,
        )
    finally:
        conn.close()

    raw["is_true_anomaly"] = raw["scenario"].isin({
        "scenario_1_crypto_mining",
        "scenario_2_debug_pod",
        "scenario_3_identity_leak",
    }).astype(int)
    raw.to_csv(EXPORT_DIR / "telemetry_raw.csv", index=False)

    features_df = calculate_behavioral_features(str(DB_PATH))
    features_df["is_true_anomaly"] = features_df["scenario"].isin({
        "scenario_1_crypto_mining",
        "scenario_2_debug_pod",
        "scenario_3_identity_leak",
    }).astype(int)
    features_df.to_csv(EXPORT_DIR / "features_with_labels.csv", index=False)
    features_df[features_df["is_true_anomaly"] == 1].to_csv(EXPORT_DIR / "anomalies_only.csv", index=False)

    scenario_counts = Counter(row["scenario"] for row in timeline_rows)
    log_counts = Counter(row["log_type"] for row in timeline_rows)
    event_total = len(timeline_rows)
    summary = {
        "seed": RANDOM_SEED,
        "simulation_window": {
            "start": SIM_START.isoformat(timespec="seconds"),
            "end": SIM_END.isoformat(timespec="seconds"),
        },
        "row_counts": {
            "timeline_events": event_total,
            "cloudtrail_events": len(cloudtrail_rows),
            "k8s_audit_events": len(k8s_rows),
            "identity_session_events": len(identity_session_rows),
        },
        "log_type_counts": dict(sorted(log_counts.items())),
        "scenario_counts": dict(sorted(scenario_counts.items())),
        "scenario_percentages": {
            scenario: round(count * 100 / event_total, 2)
            for scenario, count in sorted(scenario_counts.items())
        },
        "true_anomaly_events": int(features_df["is_true_anomaly"].sum()),
        "exports": {
            "telemetry_raw": str(EXPORT_DIR / "telemetry_raw.csv"),
            "features_with_labels": str(EXPORT_DIR / "features_with_labels.csv"),
            "anomalies_only": str(EXPORT_DIR / "anomalies_only.csv"),
        },
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    random.seed(RANDOM_SEED)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    _generate_events()
    _write_database()
    _write_ground_truth()
    summary = _export_flattened()

    print("Clean training dataset generated.")
    print(f"  SQLite DB: {DB_PATH}")
    print(f"  Ground truth: {GT_PATH}")
    print(f"  Total timeline events: {summary['row_counts']['timeline_events']}")
    print(f"  Cloud audit logs: {summary['row_counts']['cloudtrail_events']}")
    print(f"  Kubernetes events: {summary['row_counts']['k8s_audit_events']}")
    print(f"  Identity/session logs: {summary['row_counts']['identity_session_events']}")
    print("  Scenario mix:")
    for scenario, pct in summary["scenario_percentages"].items():
        print(f"    {scenario}: {summary['scenario_counts'][scenario]} ({pct}%)")


if __name__ == "__main__":
    main()
