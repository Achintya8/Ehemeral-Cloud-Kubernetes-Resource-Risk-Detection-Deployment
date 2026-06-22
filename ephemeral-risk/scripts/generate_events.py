"""
generate_events.py
==================
Synthetic security-event stream generator.

Reads schema.sql, initialises data/events.db, and populates four log tables
with a realistic 6-hour dataset anchored to today's midnight UTC:

  95 % baseline  — HPA autoscaler bursts, 2-min CI/CD transient pods,
                   normal CloudTrail API calls, normal VPC flows.
   5 % malicious — 4 attack scenarios (3 true positives + 1 false-positive):
                   Scenario 1  03:00 AM tagless crypto-mining EC2 burst
                   Scenario 2  11-min privileged debug pod exposing NodePort
                   Scenario 3  15-min stolen AWS AssumeRole token reading PII S3
                   Scenario 4  40-pod valid burst (false-positive control)

Output
------
  data/events.db          — SQLite database
  data/ground_truth.json  — maps every generated anomalous event_id to its
                            scenario so eval.py can compute P/R/F1 accurately.

Usage
-----
    python generate_events.py
"""

from __future__ import annotations

import json
import random
import sqlite3
import sys
import uuid
import datetime
import io
from collections import defaultdict
from pathlib import Path

import pandas as pd

# ──────────────────────────────────────────────────────────────────────────────
# PATHS
# ──────────────────────────────────────────────────────────────────────────────

ROOT      = Path(__file__).resolve().parent
DATA_DIR  = ROOT / "data"
DB_PATH   = DATA_DIR / "events.db"
GT_PATH   = DATA_DIR / "ground_truth.json"
SCHEMA    = ROOT / "schema.sql"

# ──────────────────────────────────────────────────────────────────────────────
# SIMULATION WINDOW
# ──────────────────────────────────────────────────────────────────────────────

# Simulation anchored to today's midnight UTC (relative, not hard-coded).
BASE_DATE = datetime.datetime.now(datetime.timezone.utc).replace(
    hour=0, minute=0, second=0, microsecond=0
)
SIM_START = BASE_DATE
SIM_END   = BASE_DATE + datetime.timedelta(hours=6)

# ──────────────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

AWS_ACCOUNT_ID = "123456789012"

CORPORATE_CIDRS      = [f"10.0.{b}.{c}"   for b in range(0, 5)  for c in range(1, 255)]
CLUSTER_POD_CIDRS    = [f"192.168.{b}.{c}" for b in range(0, 4) for c in range(1, 255)]
CORP_NAT_IPS         = ["203.0.113.10", "203.0.113.11", "203.0.113.55"]
KNOWN_MINING_POOL    = ["185.220.101.47", "45.142.212.100", "91.108.4.200"]
INTERNAL_DNS_IPS     = ["10.0.0.2", "10.0.1.2"]

VALID_CI_CD_USERS    = ["ci-runner-svc", "github-actions-svc", "jenkins-deployer"]
VALID_DEVOPS_USERS   = ["devops-pipeline", "argocd-svc", "flux-controller"]
VALID_ARN_PREFIXES   = [
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/ProdDeployRole",
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/CICDRole",
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/svc-metrics",
]

COMPROMISED_PRINCIPAL   = "svc-datapipeline-legacy"
COMPROMISED_ARN         = f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/svc-datapipeline-legacy"

S3_OBJECT_KEYS = [
    "customers/2026/Q1/pii_export.csv.gz",
    "customers/2026/Q2/pii_export.csv.gz",
    "audit/gdpr_data_requests.jsonl",
    "finance/salaries_h1_2026.xlsx",
]

# ──────────────────────────────────────────────────────────────────────────────
# IN-MEMORY EVENT BUFFERS
# ──────────────────────────────────────────────────────────────────────────────

_timeline_rows:    list[dict] = []
_cloudtrail_rows:  list[dict] = []
_k8s_rows:         list[dict] = []
_vpc_rows:         list[dict] = []

# Ground-truth tracking: scenario_name → [event_id, ...]
_ground_truth: dict[str, list[str]] = defaultdict(list)


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _uid() -> str:
    return str(uuid.uuid4())


def _rand_ip(pool: list[str]) -> str:
    return random.choice(pool)


def _rand_ts(start: datetime.datetime, end: datetime.datetime) -> datetime.datetime:
    return start + datetime.timedelta(seconds=random.uniform(0, (end - start).total_seconds()))


def _offset(base: datetime.datetime, seconds: float) -> datetime.datetime:
    return base + datetime.timedelta(seconds=seconds)


def _push_cloudtrail(
    eid: str, ts: datetime.datetime,
    event_source: str, event_name: str,
    principal_id: str, arn: str, source_ip: str,
    severity: str = "INFO", scenario: str = "baseline",
) -> None:
    _timeline_rows.append({
        "event_id": eid, "timestamp": ts.isoformat(),
        "log_type": "cloudtrail", "severity": severity, "scenario": scenario,
    })
    _cloudtrail_rows.append({
        "event_id": eid, "event_source": event_source, "event_name": event_name,
        "principal_id": principal_id, "arn": arn, "source_ip": source_ip,
    })
    if scenario not in ("baseline", "scenario_4_false_positive"):
        _ground_truth[scenario].append(eid)


def _push_k8s(
    eid: str, ts: datetime.datetime,
    verb: str, resource_name: str, namespace: str, username: str,
    pod_ip: str, is_privileged: int = 0,
    severity: str = "INFO", scenario: str = "baseline",
) -> None:
    _timeline_rows.append({
        "event_id": eid, "timestamp": ts.isoformat(),
        "log_type": "k8s_audit", "severity": severity, "scenario": scenario,
    })
    _k8s_rows.append({
        "event_id": eid, "verb": verb, "resource_name": resource_name,
        "namespace": namespace, "username": username,
        "pod_ip": pod_ip, "is_privileged": is_privileged,
    })
    if scenario not in ("baseline", "scenario_4_false_positive"):
        _ground_truth[scenario].append(eid)


def _push_vpc(
    eid: str, ts: datetime.datetime,
    src_addr: str, dst_addr: str, src_port: int, dst_port: int,
    nbytes: int, action: str = "ACCEPT",
    severity: str = "INFO", scenario: str = "baseline",
) -> None:
    _timeline_rows.append({
        "event_id": eid, "timestamp": ts.isoformat(),
        "log_type": "vpc_flow", "severity": severity, "scenario": scenario,
    })
    _vpc_rows.append({
        "event_id": eid, "src_addr": src_addr, "dst_addr": dst_addr,
        "src_port": src_port, "dst_port": dst_port,
        "bytes": nbytes, "action": action,
    })
    if scenario not in ("baseline", "scenario_4_false_positive"):
        _ground_truth[scenario].append(eid)


# ──────────────────────────────────────────────────────────────────────────────
# BASELINE GENERATORS
# ──────────────────────────────────────────────────────────────────────────────

def _hpa_scaling_event(ts: datetime.datetime) -> None:
    """HPA scales a deployment up or down."""
    direction  = random.choice(["scale-up", "scale-down"])
    namespace  = random.choice(["production", "staging"])
    deployment = random.choice([
        "api-gateway", "auth-service", "recommendation-engine",
        "payment-processor", "notification-svc",
    ])
    pod_name = f"{deployment}-{uuid.uuid4().hex[:6]}"
    pod_ip   = _rand_ip(CLUSTER_POD_CIDRS)

    _push_k8s(_uid(), ts, verb=direction, resource_name=pod_name,
              namespace=namespace, username="hpa-controller", pod_ip=pod_ip)

    _push_vpc(_uid(), _offset(ts, random.uniform(0.2, 1.0)),
              src_addr=pod_ip, dst_addr=_rand_ip(INTERNAL_DNS_IPS),
              src_port=random.randint(30_000, 65_535), dst_port=443,
              nbytes=random.randint(1_024, 8_192))


def _cicd_pod_event(ts: datetime.datetime) -> None:
    """CI/CD pipeline: transient build pod lives for 90-120 s."""
    namespace = random.choice(["infra", "staging"])
    job_id    = uuid.uuid4().hex[:8]
    pod_name  = f"build-job-{job_id}"
    pod_ip    = _rand_ip(CLUSTER_POD_CIDRS)
    runner_ip = _rand_ip(CORP_NAT_IPS)
    username  = random.choice(VALID_CI_CD_USERS)

    _push_k8s(_uid(), ts, "create", pod_name, namespace, username, pod_ip)
    _push_cloudtrail(
        _uid(), _offset(ts, random.uniform(1, 5)),
        "ecr.amazonaws.com", "GetAuthorizationToken",
        username, random.choice(VALID_ARN_PREFIXES), runner_ip,
    )
    _push_vpc(_uid(), _offset(ts, random.uniform(5, 15)),
              pod_ip, f"52.94.{random.randint(0,255)}.{random.randint(1,254)}",
              random.randint(30_000, 65_535), 443,
              random.randint(50_000, 500_000))
    _push_k8s(_uid(), _offset(ts, random.uniform(90, 120)),
              "delete", pod_name, namespace, username, pod_ip)


def _normal_cloudtrail(ts: datetime.datetime) -> None:
    svc, name = random.choice([
        ("ec2.amazonaws.com",  "DescribeInstances"),
        ("ec2.amazonaws.com",  "DescribeSecurityGroups"),
        ("s3.amazonaws.com",   "ListBuckets"),
        ("iam.amazonaws.com",  "ListRoles"),
        ("eks.amazonaws.com",  "DescribeCluster"),
        ("sts.amazonaws.com",  "GetCallerIdentity"),
        ("logs.amazonaws.com", "DescribeLogGroups"),
        ("ecr.amazonaws.com",  "DescribeRepositories"),
    ])
    user = random.choice(VALID_CI_CD_USERS + VALID_DEVOPS_USERS)
    _push_cloudtrail(_uid(), ts, svc, name, user,
                     random.choice(VALID_ARN_PREFIXES), _rand_ip(CORP_NAT_IPS))


def _normal_vpc_flow(ts: datetime.datetime) -> None:
    src = _rand_ip(CLUSTER_POD_CIDRS + CORPORATE_CIDRS)
    dst = _rand_ip(CLUSTER_POD_CIDRS + CORPORATE_CIDRS + INTERNAL_DNS_IPS)
    _push_vpc(_uid(), ts, src, dst,
              random.randint(1_024, 65_535),
              random.choice([80, 443, 8_080, 8_443, 5_432, 6_379, 9_092]),
              random.randint(256, 65_536))


# ──────────────────────────────────────────────────────────────────────────────
# SCENARIO 1 — 03:00 AM CRYPTO-MINING BURST
# ──────────────────────────────────────────────────────────────────────────────

def _scenario_1_crypto_mining() -> None:
    burst_start  = BASE_DATE + datetime.timedelta(hours=3)
    burst_end    = BASE_DATE + datetime.timedelta(hours=3, minutes=2)
    cleanup_time = BASE_DATE + datetime.timedelta(hours=4, minutes=30)
    scenario     = "scenario_1_crypto_mining"

    instance_ips = [f"10.0.{random.randint(100,199)}.{random.randint(2,254)}"
                    for _ in range(20)]

    print(f"  [Scenario 1] Crypto-mining burst (03:00–04:30) …")

    for inst_ip in instance_ips:
        launch_ts = _rand_ts(burst_start, burst_end)

        _push_cloudtrail(
            _uid(), launch_ts,
            "ec2.amazonaws.com", "RunInstances",
            COMPROMISED_PRINCIPAL, COMPROMISED_ARN,
            f"198.51.100.{random.randint(50, 99)}",
            severity="CRITICAL", scenario=scenario,
        )

        for _ in range(random.randint(15, 25)):
            _push_vpc(
                _uid(), _rand_ts(launch_ts, cleanup_time - datetime.timedelta(minutes=2)),
                src_addr=inst_ip, dst_addr=_rand_ip(KNOWN_MINING_POOL),
                src_port=random.randint(1_024, 65_535),
                dst_port=random.choice([3_333, 4_444, 8_080, 14_444]),
                nbytes=random.randint(50_000, 250_000),
                severity="CRITICAL", scenario=scenario,
            )

    for _ in range(20):
        _push_cloudtrail(
            _uid(), _offset(cleanup_time, random.uniform(0, 30)),
            "ec2.amazonaws.com", "TerminateInstances",
            COMPROMISED_PRINCIPAL, COMPROMISED_ARN,
            f"198.51.100.{random.randint(50, 99)}",
            severity="HIGH", scenario=scenario,
        )


# ──────────────────────────────────────────────────────────────────────────────
# SCENARIO 2 — 11-MINUTE PRIVILEGED DEBUG POD
# ──────────────────────────────────────────────────────────────────────────────

def _scenario_2_debug_pod() -> None:
    t0         = BASE_DATE + datetime.timedelta(hours=1, minutes=22)
    node_port  = random.randint(30_000, 32_767)
    pod_ip     = f"192.168.2.{random.randint(10, 250)}"
    node_ip    = f"10.0.3.{random.randint(10, 250)}"
    attacker   = "198.51.100.77"
    exfil_dst  = f"203.0.113.{random.randint(50, 200)}"
    scenario   = "scenario_2_debug_pod"

    print("  [Scenario 2] Debug pod exploit (T+0 → T+11 min) …")

    _push_k8s(_uid(), t0, "create", "debug-tool-xyz", "default",
              "dev-alice", pod_ip, is_privileged=1,
              severity="HIGH", scenario=scenario)

    _push_cloudtrail(
        _uid(), _offset(t0, 5),
        "eks.amazonaws.com", "AccessKubernetesApi",
        "dev-alice", f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/dev-alice",
        _rand_ip(CORP_NAT_IPS), severity="INFO", scenario=scenario,
    )

    t2 = _offset(t0, 120)
    _push_vpc(_uid(), t2, attacker, node_ip,
              random.randint(40_000, 65_535), node_port,
              random.randint(512, 2_048),
              severity="HIGH", scenario=scenario)

    _push_vpc(_uid(), _offset(t2, 3), node_ip, exfil_dst,
              node_port, 443, random.randint(10_000_000, 50_000_000),
              severity="CRITICAL", scenario=scenario)

    for _ in range(4):
        _push_vpc(_uid(), _offset(t2, random.uniform(10, 90)),
                  attacker, node_ip,
                  random.randint(40_000, 65_535), node_port,
                  random.randint(1_024, 65_536),
                  severity="HIGH", scenario=scenario)

    t11 = _offset(t0, 660)
    _push_k8s(_uid(), t11, "delete", "debug-tool-xyz", "default",
              "dev-alice", pod_ip, is_privileged=0,
              severity="HIGH", scenario=scenario)

    _push_cloudtrail(
        _uid(), _offset(t11, 1),
        "eks.amazonaws.com", "AccessKubernetesApi",
        "dev-alice", f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/dev-alice",
        _rand_ip(CORP_NAT_IPS), severity="INFO", scenario=scenario,
    )


# ──────────────────────────────────────────────────────────────────────────────
# SCENARIO 3 — 15-MINUTE STOLEN ASSUMED-ROLE SESSION TOKEN
# ──────────────────────────────────────────────────────────────────────────────

def _scenario_3_identity_leak() -> None:
    t0         = BASE_DATE + datetime.timedelta(hours=2, minutes=5)
    pod_ip     = f"192.168.1.{random.randint(10, 250)}"
    session_id = uuid.uuid4().hex[:12]
    session_arn = (
        f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/"
        f"DataAnalyticsRole/stolen-{session_id}"
    )
    scenario = "scenario_3_identity_leak"

    print("  [Scenario 3] Identity leak / token abuse (T+0 → T+15 min) …")

    _push_cloudtrail(
        _uid(), t0,
        "sts.amazonaws.com", "AssumeRoleWithWebIdentity",
        COMPROMISED_PRINCIPAL, COMPROMISED_ARN,
        pod_ip, severity="HIGH", scenario=scenario,
    )

    _push_k8s(_uid(), _offset(t0, 1), "get",
              f"compromised-analytics-{session_id[:6]}",
              "production", "compromised-svc", pod_ip,
              severity="HIGH", scenario=scenario)

    for _ in range(random.randint(80, 120)):
        get_ts = _offset(t0, random.uniform(5, 895))
        _push_cloudtrail(
            _uid(), get_ts,
            "s3.amazonaws.com", "GetObject",
            f"DataAnalyticsRole:stolen-{session_id}", session_arn,
            pod_ip, severity="HIGH", scenario=scenario,
        )
        _push_vpc(
            _uid(), _offset(get_ts, random.uniform(0.05, 0.5)),
            src_addr=pod_ip,
            dst_addr=f"52.217.{random.randint(0,255)}.{random.randint(1,254)}",
            src_port=random.randint(32_768, 65_535), dst_port=443,
            nbytes=random.randint(100_000, 5_000_000),
            severity="HIGH", scenario=scenario,
        )

    _push_cloudtrail(
        _uid(), _offset(t0, 900),
        "s3.amazonaws.com", "GetObject",
        f"DataAnalyticsRole:stolen-{session_id}", session_arn,
        pod_ip, severity="CRITICAL", scenario=scenario,
    )


# ──────────────────────────────────────────────────────────────────────────────
# SCENARIO 4 — 40-POD VALID BURST (FALSE-POSITIVE CONTROL)
# ──────────────────────────────────────────────────────────────────────────────

def _scenario_4_false_positive() -> None:
    burst_start = BASE_DATE + datetime.timedelta(hours=4, minutes=15)
    burst_end   = burst_start + datetime.timedelta(minutes=2)
    namespaces  = ["production", "staging", "infra"]
    scenario    = "scenario_4_false_positive"

    print("  [Scenario 4] False-positive valid burst (40 pods, 3 namespaces) …")

    for p in range(40):
        ns        = namespaces[p % 3]
        pod_name  = f"valid-burst-{ns}-{uuid.uuid4().hex[:8]}"
        pod_ip    = _rand_ip(CLUSTER_POD_CIDRS)
        create_ts = _rand_ts(burst_start, burst_end)
        user      = random.choice(VALID_DEVOPS_USERS)

        _push_k8s(_uid(), create_ts, "create", pod_name, ns, user, pod_ip,
                  scenario=scenario)
        _push_cloudtrail(
            _uid(), _offset(create_ts, random.uniform(0.5, 3)),
            "eks.amazonaws.com", "AccessKubernetesApi", user,
            random.choice(VALID_ARN_PREFIXES), _rand_ip(CORP_NAT_IPS),
            scenario=scenario,
        )
        _push_vpc(
            _uid(), _offset(create_ts, random.uniform(1, 5)),
            pod_ip, _rand_ip(CLUSTER_POD_CIDRS),
            random.randint(30_000, 65_535),
            random.choice([8_080, 8_443, 9_090]),
            random.randint(1_024, 16_384),
            scenario=scenario,
        )


# ──────────────────────────────────────────────────────────────────────────────
# BASELINE GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def _generate_baseline() -> None:
    print("  [Baseline] Normal traffic (~95 % of dataset) …")

    t = SIM_START
    while t < SIM_END:
        _hpa_scaling_event(t)
        t += datetime.timedelta(seconds=random.uniform(45, 90))

    t = SIM_START
    while t < SIM_END:
        _cicd_pod_event(t)
        t += datetime.timedelta(seconds=random.uniform(180, 360))

    t = SIM_START
    while t < SIM_END:
        _normal_cloudtrail(t)
        t += datetime.timedelta(seconds=random.uniform(20, 40))

    t = SIM_START
    while t < SIM_END:
        _normal_vpc_flow(t)
        t += datetime.timedelta(seconds=random.uniform(5, 12))


# ──────────────────────────────────────────────────────────────────────────────
# DATABASE INITIALISATION
# ──────────────────────────────────────────────────────────────────────────────

def _init_db(conn: sqlite3.Connection) -> None:
    ddl = SCHEMA.read_text(encoding="utf-8")
    conn.executescript(ddl)
    conn.commit()
    print("  [DB] Schema applied from schema.sql.")


def _bulk_insert(conn: sqlite3.Connection) -> None:
    print("\n  [DB] Sorting events chronologically …")

    df_tt  = pd.DataFrame(_timeline_rows).sort_values("timestamp").reset_index(drop=True)
    df_ct  = pd.DataFrame(_cloudtrail_rows)
    df_k8s = pd.DataFrame(_k8s_rows)
    df_vpc = pd.DataFrame(_vpc_rows)

    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.executescript("""
        DELETE FROM vpc_flow_logs;
        DELETE FROM k8s_audit_events;
        DELETE FROM cloudtrail_events;
        DELETE FROM telemetry_timeline;
    """)
    conn.commit()

    print(f"  [DB] Inserting {len(df_tt):,} rows into telemetry_timeline …")
    df_tt.to_sql("telemetry_timeline", conn, if_exists="append",
                 index=False, method="multi", chunksize=500)

    print(f"  [DB] Inserting {len(df_ct):,} rows into cloudtrail_events …")
    df_ct.to_sql("cloudtrail_events", conn, if_exists="append",
                 index=False, method="multi", chunksize=500)

    print(f"  [DB] Inserting {len(df_k8s):,} rows into k8s_audit_events …")
    df_k8s.to_sql("k8s_audit_events", conn, if_exists="append",
                  index=False, method="multi", chunksize=500)

    print(f"  [DB] Inserting {len(df_vpc):,} rows into vpc_flow_logs …")
    df_vpc.to_sql("vpc_flow_logs", conn, if_exists="append",
                  index=False, method="multi", chunksize=500)

    conn.commit()
    conn.execute("PRAGMA foreign_keys = ON;")

    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_tt_timestamp  ON telemetry_timeline (timestamp);
        CREATE INDEX IF NOT EXISTS idx_tt_log_type   ON telemetry_timeline (log_type);
        CREATE INDEX IF NOT EXISTS idx_tt_severity   ON telemetry_timeline (severity);
        CREATE INDEX IF NOT EXISTS idx_tt_scenario   ON telemetry_timeline (scenario);
        CREATE INDEX IF NOT EXISTS idx_ct_event_name ON cloudtrail_events  (event_name);
        CREATE INDEX IF NOT EXISTS idx_ct_principal  ON cloudtrail_events  (principal_id);
        CREATE INDEX IF NOT EXISTS idx_k8s_namespace ON k8s_audit_events   (namespace);
        CREATE INDEX IF NOT EXISTS idx_k8s_priv      ON k8s_audit_events   (is_privileged);
        CREATE INDEX IF NOT EXISTS idx_vpc_dst_addr  ON vpc_flow_logs      (dst_addr);
        CREATE INDEX IF NOT EXISTS idx_vpc_src_addr  ON vpc_flow_logs      (src_addr);
    """)
    conn.commit()
    print("  [DB] Indexes rebuilt.")


def _save_ground_truth() -> None:
    anomaly_scenarios = {
        k: v for k, v in _ground_truth.items()
        if k != "scenario_4_false_positive"
    }
    false_positive = {
        k: v for k, v in _ground_truth.items()
        if k == "scenario_4_false_positive"
    }
    all_true_ids = [eid for ids in anomaly_scenarios.values() for eid in ids]

    payload = {
        "generated_at":            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "anomaly_scenarios":       anomaly_scenarios,
        "false_positive_scenario": false_positive,
        "all_true_anomaly_ids":    all_true_ids,
    }
    GT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"  [GT] Ground truth saved → {GT_PATH}")
    print(f"       True anomaly event IDs  : {len(all_true_ids):,}")
    for sc, ids in anomaly_scenarios.items():
        print(f"         {sc:<38}: {len(ids):>4} events")


# ──────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    random.seed(42)
    SEP = "=" * 70

    print(f"\n{SEP}")
    print("  SYNTHETIC SECURITY EVENT STREAM GENERATOR")
    print(f"  Window : {SIM_START.isoformat()}  →  {SIM_END.isoformat()}")
    print(f"  Output : {DB_PATH}")
    print(f"{SEP}\n")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if DB_PATH.exists():
        DB_PATH.unlink()

    print("[1/3] GENERATING EVENTS\n")
    _generate_baseline()
    print()
    _scenario_1_crypto_mining()
    print()
    _scenario_2_debug_pod()
    print()
    _scenario_3_identity_leak()
    print()
    _scenario_4_false_positive()

    print(f"\n  In-memory totals:")
    print(f"    Timeline events  : {len(_timeline_rows):,}")
    print(f"    CloudTrail rows  : {len(_cloudtrail_rows):,}")
    print(f"    K8s Audit rows   : {len(_k8s_rows):,}")
    print(f"    VPC Flow rows    : {len(_vpc_rows):,}")

    print("\n[2/3] PERSISTING TO SQLITE\n")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA cache_size=-65536;")
    _init_db(conn)
    _bulk_insert(conn)
    conn.close()

    print("\n[3/3] SAVING GROUND TRUTH\n")
    _save_ground_truth()

    print(f"\n{SEP}")
    print("  [OK] Generation complete.  Ready to run pipeline.py")
    print(f"{SEP}\n")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    main()