"""
generate_test_data.py
=====================

Generates a HOLDOUT test dataset — never used for training.

The model is trained on data/events.db (5 000 rows, seed 20260620).
This script produces data/test_events.db + data/test_ground_truth.json
(1 500 rows, seed 20261201) with the same scenario mix and schema.

Usage
-----
    python generate_test_data.py          # generate holdout set
    python eval.py \\
        --db-path  data/test_events.db \\
        --gt-path  data/test_ground_truth.json   # evaluate on holdout
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


ROOT       = Path(__file__).resolve().parent
DATA_DIR   = ROOT / "data"
EXPORT_DIR = DATA_DIR / "exports"
DB_PATH    = DATA_DIR / "test_events.db"          # ← separate from training DB
GT_PATH    = DATA_DIR / "test_ground_truth.json"
SCHEMA     = ROOT / "schema.sql"

AWS_ACCOUNT_ID = "123456789012"
BASE_DATE  = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
SIM_START  = BASE_DATE
SIM_END    = BASE_DATE + dt.timedelta(hours=24)

# ── Different seed from training (20260620) so the data is truly unseen ────────
RANDOM_SEED = 20261201

# ── 1 500 events — same scenario proportions as training ──────────────────────
TARGET_COUNTS = {
    "cloudtrail":       480,
    "k8s_audit":        630,
    "identity_session": 390,
}

SCENARIO_TARGETS = {
    "scenario_1_crypto_mining":  97,    # 6.5 %
    "scenario_2_debug_pod":      60,    # 4.0 %
    "scenario_3_identity_leak":  97,    # 6.5 %
    "scenario_4_false_positive": 675,   # 45.0 %
    "baseline":                  571,   # 38.1 %
}

VALID_CI_CD_USERS  = ["ci-runner-svc", "github-actions-svc", "jenkins-deployer"]
VALID_DEVOPS_USERS = ["devops-pipeline", "argocd-svc", "flux-controller"]
VALID_IDENTITIES   = VALID_CI_CD_USERS + VALID_DEVOPS_USERS + [
    "hpa-controller", "kube-scheduler", "metrics-server", "svc-metrics", "dev-alice",
]
VALID_NAMESPACES = ["production", "staging", "monitoring", "kube-system", "infra"]
WORKLOADS = [
    "api-gateway", "auth-service", "payment-processor",
    "recommendation-engine", "notification-svc", "metrics-adapter",
]
AWS_SOURCES = {
    "RunInstances":             "ec2.amazonaws.com",
    "TerminateInstances":       "ec2.amazonaws.com",
    "DescribeInstances":        "ec2.amazonaws.com",
    "CreateTags":               "ec2.amazonaws.com",
    "AssumeRole":               "sts.amazonaws.com",
    "AssumeRoleWithWebIdentity":"sts.amazonaws.com",
    "GetCallerIdentity":        "sts.amazonaws.com",
    "CreateBucket":             "s3.amazonaws.com",
    "PutBucketTagging":         "s3.amazonaws.com",
    "PutObject":                "s3.amazonaws.com",
    "GetObject":                "s3.amazonaws.com",
    "AccessKubernetesApi":      "eks.amazonaws.com",
    "CreateService":            "eks.amazonaws.com",
    "CreateRoleBinding":        "eks.amazonaws.com",
}
CORP_NAT_IPS  = ["203.0.113.10", "203.0.113.11", "203.0.113.55"]
KNOWN_BAD_IPS = ["185.220.101.47", "45.142.212.100", "91.108.4.200", "198.51.100.77"]


timeline_rows:           list[dict[str, Any]] = []
cloudtrail_rows:         list[dict[str, Any]] = []
k8s_rows:                list[dict[str, Any]] = []
cloudtrail_metadata_rows:list[dict[str, Any]] = []
k8s_metadata_rows:       list[dict[str, Any]] = []
identity_session_rows:   list[dict[str, Any]] = []
ground_truth: dict[str, list[str]] = defaultdict(list)


def _uid() -> str:
    return str(uuid.uuid4())


def _ts_for_scenario(scenario: str) -> dt.datetime:
    if scenario == "scenario_1_crypto_mining":
        burst = random.choice([
            BASE_DATE + dt.timedelta(hours=2, minutes=10),
            BASE_DATE + dt.timedelta(hours=14, minutes=30),
        ])
        start, end = burst, burst + dt.timedelta(minutes=40)
    elif scenario == "scenario_2_debug_pod":
        start = BASE_DATE + dt.timedelta(hours=10, minutes=0)
        end   = start + dt.timedelta(minutes=30)
    elif scenario == "scenario_3_identity_leak":
        burst = random.choice([
            BASE_DATE + dt.timedelta(hours=4, minutes=5),
            BASE_DATE + dt.timedelta(hours=15, minutes=45),
        ])
        start, end = burst, burst + dt.timedelta(minutes=50)
    elif scenario == "scenario_4_false_positive":
        burst = random.choice([
            BASE_DATE + dt.timedelta(hours=8,  minutes=0),
            BASE_DATE + dt.timedelta(hours=10, minutes=30),
            BASE_DATE + dt.timedelta(hours=12, minutes=0),
            BASE_DATE + dt.timedelta(hours=14, minutes=45),
            BASE_DATE + dt.timedelta(hours=17, minutes=0),
        ])
        start, end = burst, burst + dt.timedelta(minutes=15)
    else:
        start, end = SIM_START, SIM_END
    return start + dt.timedelta(seconds=random.uniform(0, (end - start).total_seconds()))


def _internal_ip() -> str:
    return random.choice([
        f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
        f"192.168.{random.randint(0,4)}.{random.randint(1,254)}",
        f"172.19.{random.randint(0,5)}.{random.randint(1,254)}",
    ])


def _external_ip() -> str:
    return random.choice([
        f"198.51.100.{random.randint(1,254)}",
        f"203.0.113.{random.randint(1,254)}",
        f"52.94.{random.randint(0,255)}.{random.randint(1,254)}",
    ])


def _arn(principal: str, assumed: bool = False) -> str:
    if assumed:
        role = random.choice(["ProdDeployRole", "CICDRole"])
        return f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/{role}/{principal}-{uuid.uuid4().hex[:8]}"
    if principal in VALID_CI_CD_USERS:
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/CICDRole"
    if principal in VALID_DEVOPS_USERS:
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/ProdDeployRole"
    return f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{principal}"


def _tags(owner: str, env: str, app: str, clean: bool = True) -> dict[str, str]:
    if not clean:
        return {"Name": f"untagged-{app}-{uuid.uuid4().hex[:5]}"}
    return {
        "Owner": owner, "Environment": env, "Application": app,
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
        "event_id":  event_id,
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "log_type":  log_type,
        "severity":  severity,
        "scenario":  scenario,
    })
    _track_truth(scenario, event_id)


def _add_cloudtrail(
    scenario: str, event_name: str, principal: str, source_ip: str,
    timestamp: dt.datetime | None = None,
    tags: dict[str, str] | None = None,
    request: dict[str, Any] | None = None,
) -> str:
    event_id = _uid()
    ts = timestamp or _ts_for_scenario(scenario)
    _add_timeline(event_id, ts, "cloudtrail", scenario)
    cloudtrail_rows.append({
        "event_id":     event_id,
        "event_source": AWS_SOURCES[event_name],
        "event_name":   event_name,
        "principal_id": principal,
        "arn":          _arn(principal, assumed=event_name in {"AssumeRole", "AssumeRoleWithWebIdentity"}),
        "source_ip":    source_ip,
    })
    cloudtrail_metadata_rows.append({
        "event_id":                 event_id,
        "tags_json":                json.dumps(tags or {}, sort_keys=True),
        "request_parameters_json":  json.dumps(request or {}, sort_keys=True),
        "user_agent":               random.choice(["aws-cli/2", "botocore/1", "terraform/1.8", "github-actions-runner"]),
    })
    return event_id


def _add_k8s(
    scenario: str, verb: str, resource_name: str, namespace: str,
    username: str, pod_ip: str, is_privileged: int = 0,
    timestamp: dt.datetime | None = None,
    labels: dict[str, str] | None = None,
    controller_owner: str = "", service_type: str = "", rbac_change: str = "",
) -> str:
    event_id = _uid()
    ts = timestamp or _ts_for_scenario(scenario)
    _add_timeline(event_id, ts, "k8s_audit", scenario)
    k8s_rows.append({
        "event_id":     event_id,
        "verb":         verb,
        "resource_name":resource_name,
        "namespace":    namespace,
        "username":     username,
        "pod_ip":       pod_ip,
        "is_privileged":is_privileged,
    })
    k8s_metadata_rows.append({
        "event_id":        event_id,
        "labels_json":     json.dumps(labels or {}, sort_keys=True),
        "controller_owner":controller_owner,
        "service_type":    service_type,
        "rbac_change":     rbac_change,
    })
    return event_id


def _add_identity_session(
    scenario: str, session_type: str, principal: str, source_ip: str,
    timestamp: dt.datetime | None = None,
    token_ttl: int | None = None,
) -> str:
    event_name_by_type = {
        "assumed_role":         "AssumeRole",
        "service_account_token":"AssumeRoleWithWebIdentity",
        "federation":           "GetCallerIdentity",
    }
    event_name = event_name_by_type[session_type]
    event_id = _add_cloudtrail(
        scenario=scenario, event_name=event_name, principal=principal,
        source_ip=source_ip, timestamp=timestamp,
        tags=_tags("identity-platform", "prod", "session-broker",
                   clean=scenario != "scenario_3_identity_leak"),
        request={
            "sessionName":     f"{principal}-{uuid.uuid4().hex[:8]}",
            "durationSeconds": random.choice([900, 1800, 3600]),
            "provider":        random.choice(["oidc.eks.amazonaws.com", "saml.corp.example", "github-oidc"]),
        },
    )
    identity_session_rows.append({
        "event_id":         event_id,
        "session_type":     session_type,
        "principal_id":     principal,
        "session_name":     f"{principal}-{uuid.uuid4().hex[:10]}",
        "issuer":           random.choice(["eks-oidc", "github-oidc", "corp-saml"]),
        "source_ip":        source_ip,
        "token_ttl_seconds":token_ttl or random.choice([600, 900, 1800, 3600]),
    })
    return event_id


# ──────────────────────────────────────────────────────────────────────────────
# SCENARIO EVENT GENERATORS  (strong, distinctive feature signals)
# ──────────────────────────────────────────────────────────────────────────────

def _cloudtrail_event_for_scenario(scenario: str) -> None:
    if scenario == "scenario_1_crypto_mining":
        # Untrusted identity + known-bad IPs + missing tags → all 3 detectors fire
        principal = random.choice(["svc-datapipeline-legacy", "build-cache-temp", "unknown-miner"])
        name      = random.choices(["RunInstances", "CreateTags", "TerminateInstances"], weights=[8, 1, 1])[0]
        source_ip = random.choices(KNOWN_BAD_IPS, weights=[3,3,2,2])[0]  # always bad IPs
        tags      = _tags(principal, "prod", "miner", clean=False)        # always missing tags
    elif scenario == "scenario_2_debug_pod":
        principal = random.choice(["dev-alice", "temporary-admin"])
        name      = random.choice(["AccessKubernetesApi", "CreateService", "CreateRoleBinding"])
        source_ip = random.choice(CORP_NAT_IPS)
        tags      = _tags(principal, "prod", "debug-nodeport", clean=True)
    elif scenario == "scenario_3_identity_leak":
        # Unknown principal + external IP → untrusted_network_hit + is_unknown_identity
        principal = random.choice(["svc-datapipeline-legacy", "DataAnalyticsRole:stolen-session", "compromised-svc"])
        name      = random.choices(["AssumeRole", "AssumeRoleWithWebIdentity", "GetObject"], weights=[3, 5, 2])[0]
        source_ip = random.choice(KNOWN_BAD_IPS + [_external_ip()])       # mostly external
        tags      = _tags(principal, "prod", "pii-reader", clean=False)
    elif scenario == "scenario_4_false_positive":
        principal = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS)
        name      = random.choices(
            ["RunInstances", "AssumeRole", "CreateBucket", "PutBucketTagging", "AccessKubernetesApi"],
            weights=[3, 4, 1, 2, 5])[0]
        source_ip = random.choice(CORP_NAT_IPS)
        tags      = _tags(principal, "prod", random.choice(WORKLOADS), clean=True)
    else:
        principal = random.choice(VALID_IDENTITIES)
        name      = random.choice([
            "DescribeInstances", "GetCallerIdentity", "AssumeRole",
            "PutObject", "AccessKubernetesApi",
        ])
        source_ip = random.choice(CORP_NAT_IPS + [_internal_ip()])
        tags      = _tags(principal, "prod", random.choice(WORKLOADS), clean=True)

    _add_cloudtrail(
        scenario=scenario, event_name=name, principal=principal, source_ip=source_ip,
        tags=tags,
        request={"resource": f"{scenario}-{uuid.uuid4().hex[:8]}", "ephemeral": True},
    )


def _k8s_event_for_scenario(scenario: str) -> None:
    app = random.choice(WORKLOADS)
    pod = f"{app}-{uuid.uuid4().hex[:8]}"
    if scenario == "scenario_1_crypto_mining":
        namespace     = random.choice(["default", "ci-build"])
        username      = random.choice(["svc-datapipeline-legacy", "unknown-builder", "unknown-miner"])
        verb          = random.choices(["create", "delete"], weights=[9, 1])[0]
        is_privileged = 1                           # always privileged
        labels        = _labels("miner", clean=False)
        owner         = ""                          # no controller = missing_controller_owner
        service_type  = ""
        rbac          = ""
    elif scenario == "scenario_2_debug_pod":
        namespace     = "debug-shell"               # untrusted namespace
        username      = random.choice(["temporary-admin", "dev-alice"])
        verb          = random.choice(["create", "patch"])
        is_privileged = 1                           # always privileged
        labels        = _labels("debug-shell", clean=False)
        owner         = ""                          # no controller
        service_type  = random.choice(["NodePort", "LoadBalancer"])  # always public
        rbac          = random.choice(["bind-cluster-admin", "create-rolebinding"])  # always RBAC escalation
    elif scenario == "scenario_3_identity_leak":
        namespace     = random.choice(["production", "default"])
        username      = random.choice(["compromised-svc", "svc-datapipeline-legacy"])
        verb          = random.choice(["create-token", "get", "create"])
        is_privileged = 0
        labels        = _labels("token-reader", clean=False)
        owner         = "job/pii-export"
        service_type  = ""
        rbac          = random.choice(["service-account-token", "impersonate-user"])  # always RBAC
    elif scenario == "scenario_4_false_positive":
        namespace     = random.choice(["production", "staging", "infra"])
        username      = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS + ["hpa-controller"])
        verb          = random.choice(["create", "delete", "scale-up", "scale-down"])
        is_privileged = 0
        labels        = _labels(app, clean=True)
        owner         = random.choice([f"deployment/{app}", f"job/{app}-build", f"replicaset/{app}-rs"])
        service_type  = random.choice(["", "ClusterIP"])
        rbac          = ""
    else:
        namespace     = random.choice(VALID_NAMESPACES)
        username      = random.choice(VALID_IDENTITIES)
        verb          = random.choice(["create", "delete", "get", "scale-up", "scale-down"])
        is_privileged = 0
        labels        = _labels(app, clean=True)
        owner         = random.choice([f"deployment/{app}", f"job/{app}-cleanup"])
        service_type  = random.choice(["", "ClusterIP"])
        rbac          = random.choice(["", "read-only-rolebinding"])

    _add_k8s(
        scenario=scenario, verb=verb, resource_name=pod, namespace=namespace,
        username=username, pod_ip=_internal_ip(), is_privileged=is_privileged,
        labels=labels, controller_owner=owner, service_type=service_type, rbac_change=rbac,
    )


def _identity_event_for_scenario(scenario: str) -> None:
    if scenario == "scenario_3_identity_leak":
        principal    = random.choice(["svc-datapipeline-legacy", "compromised-svc", "DataAnalyticsRole:stolen-session"])
        source_ip    = random.choice(KNOWN_BAD_IPS + [_external_ip()])
        session_type = random.choice(["service_account_token", "federation"])
        token_ttl    = random.choice([3600, 7200, 43200])  # always long TTL
    elif scenario == "scenario_2_debug_pod":
        principal    = random.choice(["temporary-admin", "dev-alice"])
        source_ip    = random.choice(CORP_NAT_IPS + [_external_ip()])
        session_type = "service_account_token"
        token_ttl    = random.choice([3600, 7200])
    elif scenario == "scenario_1_crypto_mining":
        principal    = random.choice(["svc-datapipeline-legacy", "unknown-builder", "unknown-miner"])
        source_ip    = random.choices(KNOWN_BAD_IPS, weights=[3,3,2,2])[0]
        session_type = random.choice(["assumed_role", "federation"])
        token_ttl    = random.choice([3600, 7200])
    elif scenario == "scenario_4_false_positive":
        principal    = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS)
        source_ip    = random.choice(CORP_NAT_IPS)
        session_type = random.choice(["assumed_role", "service_account_token", "federation"])
        token_ttl    = random.choice([600, 900, 1800])
    else:
        principal    = random.choice(VALID_IDENTITIES)
        source_ip    = random.choice(CORP_NAT_IPS + [_internal_ip()])
        session_type = random.choice(["assumed_role", "service_account_token", "federation"])
        token_ttl    = random.choice([600, 900, 1800])

    _add_identity_session(scenario, session_type, principal, source_ip, token_ttl=token_ttl)


# ──────────────────────────────────────────────────────────────────────────────
# ORCHESTRATION
# ──────────────────────────────────────────────────────────────────────────────

def _weighted_scenarios(total: int) -> list[str]:
    scenarios: list[str] = []
    for scenario, target in SCENARIO_TARGETS.items():
        scenarios.extend([scenario] * round(total * target / sum(SCENARIO_TARGETS.values())))
    while len(scenarios) < total:
        scenarios.append("baseline")
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
    conn.executescript("""
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
    """)
    existing_cols = {
        row[1] for row in
        conn.execute("PRAGMA table_info(identity_session_events)").fetchall()
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
    for p in (DB_PATH.with_suffix(".db-wal"), DB_PATH.with_suffix(".db-shm")):
        if p.exists():
            p.unlink()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        _init_db(conn)
        timeline = sorted(timeline_rows, key=lambda r: r["timestamp"])
        _to_sql(conn, "telemetry_timeline",         timeline)
        _to_sql(conn, "cloudtrail_events",           cloudtrail_rows)
        _to_sql(conn, "k8s_audit_events",            k8s_rows)
        _to_sql(conn, "cloudtrail_event_metadata",   cloudtrail_metadata_rows)
        _to_sql(conn, "k8s_event_metadata",          k8s_metadata_rows)
        _to_sql(conn, "identity_session_events",     identity_session_rows)
        conn.commit()
    finally:
        conn.close()


def _write_ground_truth() -> None:
    all_true = [eid for ids in ground_truth.values() for eid in ids]
    payload = {
        "generated_at":     dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "description":      "HOLDOUT test set — not used for training. Seed=20261201.",
        "anomaly_scenarios":dict(sorted(ground_truth.items())),
        "false_positive_scenario": {
            "scenario_4_false_positive": [
                r["event_id"] for r in timeline_rows if r["scenario"] == "scenario_4_false_positive"
            ]
        },
        "all_true_anomaly_ids": all_true,
    }
    GT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    random.seed(RANDOM_SEED)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Generating holdout test dataset (seed={RANDOM_SEED})...")
    _generate_events()
    _write_database()
    _write_ground_truth()

    total     = len(timeline_rows)
    n_anomaly = sum(len(v) for v in ground_truth.values())
    scenario_counts = Counter(r["scenario"] for r in timeline_rows)

    print(f"\nHoldout test dataset written.")
    print(f"  DB          : {DB_PATH}")
    print(f"  Ground truth: {GT_PATH}")
    print(f"  Total events: {total:,}")
    print(f"  True anomalies: {n_anomaly} ({n_anomaly/total*100:.1f}%)")
    print(f"\n  Scenario mix:")
    for sc, cnt in sorted(scenario_counts.items()):
        print(f"    {sc:<35} : {cnt:>4}  ({cnt/total*100:.1f}%)")
    print(f"\nEvaluate on holdout set:")
    print(f"  py eval.py --db-path data/test_events.db --gt-path data/test_ground_truth.json")


if __name__ == "__main__":
    main()
