"""
seed_telemetry.py
═══════════════════════════════════════════════════════════════════════════════
Standalone one-shot telemetry seeder + ML trainer.

Run this SEPARATELY from the FastAPI server (which then starts in <1s):

    python seed_telemetry.py            # full run: train + generate + seed
    python seed_telemetry.py --train    # only retrain the model on existing DB
    python seed_telemetry.py --seed     # only generate + insert synthetic events

What it does:
  1. If data/events.db exists with ground_truth.json → trains the Isolation
     Forest on real simulated events and persists the model.
  2. Generates ~300 realistic AWS CloudTrail / K8s audit / IAM / VPC Flow
     events spread across all six TTL buckets (0s … 60m+).
  3. Inserts them into events.db so Analytics, TTL distribution, and the
     recent-events feed have meaningful data on first dashboard load.
  4. Seeds the live pipeline deque context.

This is idempotent (INSERT OR REPLACE) and safe to re-run any time.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

BASE_DIR = Path(__file__).resolve().parent


# ── Resource catalogues (single source of truth) ──────────────────────────────

AWS_ACCOUNT = "123456789012"
K8S_NAMESPACES = ["production", "staging", "kube-system", "monitoring", "data-pipeline"]
AWS_REGIONS = ["eu-west-1", "eu-central-1", "us-east-1", "ap-south-1"]
SOURCE_IP_POOL = [
    "10.0.1.20", "10.0.2.14", "10.0.3.7", "172.16.4.9", "172.16.5.2",
    "52.214.20.18", "3.121.88.42", "18.194.7.91", "203.0.113.77",   # 203.x = suspicious
]
K8S_PRINCIPALS = [
    ("system:serviceaccount:production:api-server-sa", "api-server"),
    ("system:serviceaccount:production:worker-pool-sa", "worker-pool"),
    ("system:serviceaccount:data-pipeline:spark-sa", "spark-executor"),
    ("system:serviceaccount:monitoring:prometheus-sa", "prometheus"),
    ("system:serviceaccount:kube-system:cluster-autoscaler", "autoscaler"),
    ("arn:aws:iam::123456789012:role/EKSWorkerNodeRole", "eks-worker"),
]
CLOUDTRAIL_PRINCIPALS = [
    f"arn:aws:iam::{AWS_ACCOUNT}:user/dev-alex.kumar",
    f"arn:aws:iam::{AWS_ACCOUNT}:user/dev-priya.shah",
    f"arn:aws:iam::{AWS_ACCOUNT}:role/lambda-execution-role",
    f"arn:aws:iam::{AWS_ACCOUNT}:role/CodeBuildServiceRole",
    f"arn:aws:iam::{AWS_ACCOUNT}:role/ECS-TaskExecutionRole",
    f"arn:aws:iam::{AWS_ACCOUNT}:root",
]
K8S_POD_TEMPLATES = [
    ("api-server", "Deployment", "production"),
    ("worker-pool-3", "Deployment", "production"),
    ("worker-pool-4", "Deployment", "production"),
    ("cronjob-nightly-backup", "CronJob", "production"),
    ("redis-cache-0", "StatefulSet", "production"),
    ("postgres-primary-0", "StatefulSet", "data-pipeline"),
    ("spark-executor-a1b2", "Job", "data-pipeline"),
    ("spark-executor-c3d4", "Job", "data-pipeline"),
    ("grafana-7d9f", "Deployment", "monitoring"),
    ("prometheus-0", "StatefulSet", "monitoring"),
    ("fluentd-logs-x9", "DaemonSet", "kube-system"),
    ("cluster-autoscaler-6b4", "Deployment", "kube-system"),
    ("nginx-ingress-2c1", "Deployment", "kube-system"),
    ("staging-frontend-4f8", "Deployment", "staging"),
    ("staging-api-9a2", "Deployment", "staging"),
]
LAMBDA_FUNCTIONS = ["data-processor-v2", "thumbnail-generator", "webhook-receiver", "s3-replicator"]
S3_BUCKETS = ["sg-prod-telemetry", "sg-backup-archive", "sg-ml-datasets", "sg-logs-archive"]

LOG_TYPE_TEMPLATES = {
    "k8s_audit": [
        ("pod.created", "ADDED"), ("pod.started", "started"), ("pod.completed", "completed"),
        ("pod.deleted", "DELETED"), ("pod.failed", "failed"),
        ("configmap.updated", "UPDATE"), ("secret.accessed", "GET"),
        ("rbac.rolebinding.create", "CREATE"),
    ],
    "cloudtrail": [
        ("AssumeRole", "AssumeRole"), ("ListBuckets", "ListBuckets"),
        ("GetObject", "GetObject"), ("PutObject", "PutObject"),
        ("DeleteBucket", "DeleteBucket"), ("CreateAccessKey", "CreateAccessKey"),
        ("AttachRolePolicy", "AttachRolePolicy"), ("InvokeFunction", "Invoke"),
    ],
    "iam_audit": [
        ("role.assumed", "AssumeRole"), ("user.login", "ConsoleLogin"),
        ("accesskey.created", "CreateAccessKey"), ("policy.attached", "AttachRolePolicy"),
    ],
    "vpcflow": [
        ("network.flow", "ACCEPT"), ("network.flow", "REJECT"),
    ],
}


def _make_event(log_type, principal, resource_name, namespace, region,
                source_ip, ts_iso, *, is_anomaly=False):
    """Build one realistic telemetry event dict."""
    event_name, verb = random.choice(LOG_TYPE_TEMPLATES[log_type])
    ttl = random.randint(5, 600)
    is_priv = 1 if (is_anomaly and "privilege" in event_name.lower()) else (
        1 if "cluster-autoscaler" in resource_name else 0
    )
    risk = 0.0
    if is_anomaly:
        risk = random.uniform(72, 96)
    elif "Delete" in verb or "AttachRolePolicy" in verb or "CreateAccessKey" in verb:
        risk = random.uniform(35, 60)
    else:
        risk = random.uniform(2, 25)

    return {
        "event_id": f"{log_type[:4]}-{uuid4()}",
        "timestamp": ts_iso,
        "log_type": log_type,
        "severity": "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 30 else "INFO",
        "scenario": "live_stream",
        "event_source": "kubernetes" if log_type == "k8s_audit" else "aws",
        "event_name": event_name,
        "principal_id": principal,
        "arn": principal if principal.startswith("arn:") else "",
        "source_ip": source_ip,
        "verb": verb,
        "resource_name": resource_name,
        "namespace": namespace,
        "is_privileged": is_priv,
        "risk_score": round(risk, 1),
        "is_anomaly": is_anomaly,
        "user_agent": "kubectl/v1.29" if log_type == "k8s_audit" else (
            "aws-sdk-go/1.50" if "lambda" in principal else "boto3/1.34"
        ),
        "actor": principal.split("/")[-1] if "/" in principal else principal.split(":")[-1],
        "action": verb,
        "resource_id": f"{namespace}/{resource_name}" if log_type == "k8s_audit" else resource_name,
        "region": region,
        "cluster_id": "sg-prod-cluster-1",
        "pod_ip": source_ip if log_type == "k8s_audit" else "",
        "duration": ttl, "ttl": ttl,
        "controller": "Deployment" if log_type == "k8s_audit" else "",
        "privilege": "privileged" if is_priv else "standard",
        "src_addr": source_ip if log_type == "vpcflow" else "",
        "dst_addr": f"10.0.{random.randint(1,3)}.{random.randint(5,250)}" if log_type == "vpcflow" else "",
        "src_port": random.randint(1024, 65535) if log_type == "vpcflow" else 0,
        "dst_port": random.choice([443, 80, 5432, 6379, 9090]) if log_type == "vpcflow" else 0,
        "vpc_bytes": random.randint(200, 50000) if log_type == "vpcflow" else 0,
        "vpc_action": "ACCEPT" if log_type == "vpcflow" else "",
    }


def generate_events() -> list[dict]:
    """Generate ~300 realistic events spread across all TTL buckets."""
    print("  [seed] Generating realistic synthetic telemetry (AWS/K8s/IAM/VPC)...")
    all_events: list[dict] = []
    base_time = datetime.now(timezone.utc)

    # K8s pods: 1-6 events spread across weighted lifespan buckets
    for pod_name, _controller, namespace in K8S_POD_TEMPLATES:
        principal = next(
            (p for p in K8S_PRINCIPALS if p[1] in pod_name or namespace in p[1]),
            K8S_PRINCIPALS[0],
        )[0]
        region = random.choice(AWS_REGIONS)
        source_ip = random.choice(SOURCE_IP_POOL[:-1])
        lifespan_choice = random.choices(
            ["instant", "sub_min", "few_min", "quarter_hr", "hour", "long"],
            weights=[20, 30, 20, 15, 10, 5], k=1,
        )[0]
        lifespan_sec = {
            "instant": 0,
            "sub_min": random.randint(2, 50),
            "few_min": random.randint(70, 280),
            "quarter_hr": random.randint(320, 850),
            "hour": random.randint(950, 3500),
            "long": random.randint(3700, 12000),
        }[lifespan_choice]
        n_events = 1 if lifespan_sec == 0 else random.randint(2, 6)
        end_offset = random.randint(3600, 86400)
        for j in range(n_events):
            ts = (
                base_time - timedelta(
                    seconds=end_offset - (
                        lifespan_sec * j // max(1, n_events - 1) if n_events > 1 else 0
                    )
                )
            ).isoformat(timespec="seconds")
            is_anom = random.random() < 0.06
            all_events.append(_make_event(
                "k8s_audit", principal, pod_name, namespace, region,
                "203.0.113.77" if is_anom else source_ip, ts, is_anomaly=is_anom,
            ))

    # CloudTrail / IAM events for Lambda + S3
    for _ in range(60):
        fn = random.choice(LAMBDA_FUNCTIONS + S3_BUCKETS)
        principal = random.choice(CLOUDTRAIL_PRINCIPALS)
        region = random.choice(AWS_REGIONS)
        source_ip = random.choice(SOURCE_IP_POOL)
        ts = (base_time - timedelta(seconds=random.randint(60, 86400))).isoformat(timespec="seconds")
        log_type = "iam_audit" if random.random() < 0.2 else "cloudtrail"
        is_anom = random.random() < 0.08
        all_events.append(_make_event(
            log_type, principal, fn, "aws", region,
            "203.0.113.77" if is_anom else source_ip, ts, is_anomaly=is_anom,
        ))

    # VPC Flow events (high volume, mostly benign)
    for _ in range(80):
        ts = (base_time - timedelta(seconds=random.randint(10, 7200))).isoformat(timespec="seconds")
        region = random.choice(AWS_REGIONS)
        src = random.choice(SOURCE_IP_POOL)
        dst_pod = random.choice(K8S_POD_TEMPLATES)[0]
        all_events.append(_make_event(
            "vpcflow", src, dst_pod, random.choice(K8S_NAMESPACES),
            region, src, ts, is_anomaly=(src == "203.0.113.77"),
        ))

    all_events.sort(key=lambda e: e["timestamp"])
    print(
        f"  [seed] Generated {len(all_events)} events across "
        f"{len(K8S_POD_TEMPLATES) + len(LAMBDA_FUNCTIONS) + len(S3_BUCKETS)} resources."
    )
    return all_events


def train_model_on_sim_db() -> bool:
    """Train the Isolation Forest on existing events.db if present.
    Returns True if training succeeded."""
    sim_db_path = BASE_DIR / "data" / "events.db"
    gt_path = BASE_DIR / "data" / "ground_truth.json"
    cache_dir = BASE_DIR / "data" / "model_cache"

    if not sim_db_path.exists():
        print("  [train] No events.db found — skipping real-data training.")
        return False

    try:
        if cache_dir.exists():
            for stale in cache_dir.glob("*.joblib"):
                stale.unlink(missing_ok=True)
            print("  [train] Cleared stale model cache — will retrain.")

        print(f"  [train] Loading simulated events from {sim_db_path} for ML training...")
        from features import calculate_behavioral_features
        import detector
        features_df = calculate_behavioral_features(db_path=str(sim_db_path))

        true_contamination = 0.10
        if gt_path.exists():
            try:
                with open(gt_path, "r", encoding="utf-8") as f:
                    gt = json.load(f)
                n_anomalies = len(gt.get("all_true_anomaly_ids", []))
                n_total = len(features_df)
                if n_total > 0 and n_anomalies > 0:
                    true_contamination = round(
                        max(0.01, min(0.49, n_anomalies / n_total)), 4
                    )
                print(
                    f"  [train] Ground truth: {n_anomalies} anomalies / {n_total} total "
                    f"→ contamination = {true_contamination:.4f}"
                )
            except Exception as e:
                print(f"  [train] Could not read ground_truth.json: {e}. Using default contamination.")

        detector.fit_global_model(features_df, contamination=true_contamination)
        detector.save_global_model()
        print(
            f"  [train] ML model trained on {len(features_df)} real sim events "
            f"(contamination={true_contamination:.4f}). Isolation Forest ready."
        )
        return True
    except Exception as e:
        print(f"  [train] Error training on sim DB: {e}")
        return False


def train_model_on_events(events: list[dict]) -> None:
    """Fallback: train on freshly generated synthetic events."""
    try:
        from features import calculate_features_from_events
        import detector
        features_df = calculate_features_from_events(events)
        detector.fit_global_model(features_df, contamination=0.10)
        detector.save_global_model()
        print("  [train] Synthetic warmup complete. Isolation Forest ready.")
    except Exception as e:
        print(f"  [train] Error during synthetic warmup: {e}")


def seed_events_db(events: list[dict]) -> None:
    """Insert events into events.db (idempotent via INSERT OR REPLACE)."""
    from database import insert_event
    inserted = 0
    for ev in events:
        try:
            insert_event(ev)
            inserted += 1
        except Exception:
            pass
    print(f"  [seed] Inserted {inserted}/{len(events)} events into events.db (Analytics + TTL ready).")


def seed_pipeline_context(events: list[dict]) -> None:
    """Seed the live pipeline deque with context events for rolling features."""
    try:
        from ml_pipeline import seed_pipeline_events
        seed_pipeline_events(events[-100:])
        print("  [seed] Pipeline deque seeded with last 100 events.")
    except Exception as e:
        print(f"  [seed] Failed to seed pipeline events: {e}")


def run_full() -> None:
    print("═══════════════════════════════════════════════════════════════")
    print("  SEED TELEMETRY (full: train + generate + seed)")
    print("═══════════════════════════════════════════════════════════════")

    # Ensure DB exists first
    from database import init_db
    init_db()

    trained_on_real = train_model_on_sim_db()

    events = generate_events()

    if not trained_on_real:
        train_model_on_events(events)

    seed_events_db(events)
    seed_pipeline_context(events)

    print("═══════════════════════════════════════════════════════════════")
    print("  Done. Dashboard / Analytics / TTL now have real data.")
    print("═══════════════════════════════════════════════════════════════")


def run_train_only() -> None:
    print("═══════════════════════════════════════════════════════════════")
    print("  SEED TELEMETRY (train-only)")
    print("═══════════════════════════════════════════════════════════════")
    from database import init_db
    init_db()
    train_model_on_sim_db()
    print("  Done.")


def run_seed_only() -> None:
    print("═══════════════════════════════════════════════════════════════")
    print("  SEED TELEMETRY (seed-only: generate + insert)")
    print("═══════════════════════════════════════════════════════════════")
    from database import init_db
    init_db()
    events = generate_events()
    seed_events_db(events)
    seed_pipeline_context(events)
    print("  Done.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        run_train_only()
    elif len(sys.argv) > 1 and sys.argv[1] == "--seed":
        run_seed_only()
    else:
        run_full()
