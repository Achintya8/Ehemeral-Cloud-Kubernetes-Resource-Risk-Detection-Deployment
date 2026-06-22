"""
backend/simulator.py
====================
Integrated event simulator that runs inside the FastAPI server (no separate
process / terminal needed — works on Render, Railway, etc.).

It replaces the old demo_traffic_loop() with a much richer dataset: ~500
realistic events per cycle covering all six event types, then clears the DB
and repeats.

Lifecycle (run as an asyncio background task on startup):
  1. Clear the DB so the dashboard starts fresh.
  2. Generate ~500 events with the distribution below.
  3. Feed them onto the same `k8s_event_queue` that the live ingest path
     uses, so every event goes through the full ML pipeline (features →
     IsolationForest → correlator → narrative → DB + SSE).
  4. After all events are processed, wait a "display window" so users can
     see the populated dashboard, then clear and repeat.

This guarantees the dashboard always shows a realistic, fully-correlated
picture that proves the model works.
"""

from __future__ import annotations

import asyncio
import json
import random
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


# ─── DISTRIBUTION (≈500 events per cycle) ─────────────────────────────────────
DISTRIBUTION = {
    "resource_hijacking":    35,   # ~7%  crypto-mining bursts   — CRITICAL
    "public_exposure":        20,   # ~4%  public exposure        — HIGH
    "identity_anomaly":      30,   # ~6%  identity / session      — HIGH
    "legitimate_autoscale": 220,   # ~44% HPA bursts (noise)
    "legitimate_cicd":       120,  # ~24% CI/CD jobs (noise)
    "routine_ephemeral":      75,  # ~15% routine lifecycle
}
TOTAL_EVENTS = sum(DISTRIBUTION.values())  # 500

# ─── REALISTIC DATA POOLS ─────────────────────────────────────────────────────
NAMESPACES = ["production", "staging", "dev", "cicd", "monitoring", "data-pipeline"]
TEAMS = ["platform", "data-engineering", "frontend", "backend", "security", "ml-team"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
SERVICES = ["web-api", "data-processor", "ml-inference", "cache-layer", "auth-service",
            "payment-svc", "user-svc", "order-svc", "search-svc", "gateway"]
USERS = ["dev-sarah", "dev-mike", "dev-alex", "svc-cicd", "svc-autoscaler",
         "svc-backup", "admin-deploy"]
ROLES = ["admin", "editor", "viewer", "cluster-admin", "pod-reader"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ts(base: datetime, offset: int) -> str:
    jitter = random.randint(-30, 30)
    return (base + timedelta(seconds=offset + jitter)).astimezone(timezone.utc).isoformat(timespec="seconds")


def _internal_ip() -> str:
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _external_ip() -> str:
    return f"185.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _suspicious_ip() -> str:
    # Ranges flagged by features.py (KNOWN_BAD_IPS / non-internal)
    prefixes = ["185.220.101", "203.0.113", "198.51.100", "45.142.212", "91.108.4"]
    return f"{random.choice(prefixes)}.{random.randint(1,254)}"


# ─── EVENT BUILDERS ───────────────────────────────────────────────────────────
# Each returns a dict in the canonical telemetry schema so the normalizer +
# feature engineering + IsolationForest all see the right signals.

def _cloudtrail(event_type: str, ts: str) -> Dict[str, Any]:
    principal = random.choice(USERS)
    region = random.choice(REGIONS)
    rid = f"i-{uuid.uuid4().hex[:17]}"
    e: Dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "log_type": "cloudtrail",
        "severity": "INFO",
        "scenario": "live_cloudtrail",
        "event_source": "ec2.amazonaws.com",
        "event_name": "DescribeInstances",
        "principal_id": principal,
        "arn": f"arn:aws:iam::123456789012:user/{principal}",
        "source_ip": _internal_ip(),
        "resource_name": rid,
        "resource_id": rid,
        "region": region,
        "user_agent": "aws-cli/2.0",
        "tags_json": json.dumps({"Environment": "dev", "Team": random.choice(TEAMS)}),
        "verb": "describe",
        "namespace": "default",
        "is_privileged": 0,
        "actor": principal,
        "action": "DescribeInstances",
    }

    if event_type == "resource_hijacking":
        e.update(
            severity="CRITICAL", event_name="RunInstances", action="RunInstances",
            event_source="ec2.amazonaws.com",
            resource_name=f"temp-miner-{uuid.uuid4().hex[:6]}",
            resource_id=f"i-{uuid.uuid4().hex[:17]}",
            source_ip=_suspicious_ip(), user_agent="boto3/1.26",
            tags_json=json.dumps({"Name": "temp-worker", "auto": "true"}),
            request_parameters_json=json.dumps({"InstanceType": "c5.4xlarge", "MinCount": 5, "MaxCount": 15}),
        )
    elif event_type == "public_exposure":
        e.update(
            severity="HIGH", event_name="AuthorizeSecurityGroupIngress",
            action="AuthorizeSecurityGroupIngress", event_source="ec2.amazonaws.com",
            resource_name=f"sg-debug-{uuid.uuid4().hex[:6]}",
            resource_id=f"sg-{uuid.uuid4().hex[:12]}",
            source_ip=_external_ip(),
            tags_json=json.dumps({"debug": "true", "ttl": "15m"}),
            request_parameters_json=json.dumps({
                "GroupId": f"sg-{uuid.uuid4().hex[:12]}",
                "IpPermissions": [{"IpProtocol": "-1", "FromPort": 0, "ToPort": 65535,
                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            }),
        )
    elif event_type == "identity_anomaly":
        role = random.choice(ROLES)
        e.update(
            severity="HIGH", event_name="AssumeRole", action="AssumeRole",
            event_source="sts.amazonaws.com",
            resource_name=role,
            resource_id=f"arn:aws:iam::123456789012:role/{role}",
            principal_id=random.choice(["unknown-service", "svc-lambda", "svc-backup"]),
            arn=f"arn:aws:sts::123456789012:assumed-role/{role}/{uuid.uuid4().hex[:8]}",
            source_ip=_suspicious_ip(), user_agent="Boto3/1.26.0",
            token_ttl_seconds=random.choice([900, 1800]),
            tags_json=json.dumps({}),
            session_type="AssumedRole", session_name=uuid.uuid4().hex[:8],
        )
    elif event_type == "legitimate_autoscale":
        e.update(
            event_name="RunInstances", action="RunInstances",
            resource_name=f"hpa-{random.choice(SERVICES)}-{random.randint(100,999)}",
            resource_id=f"i-{uuid.uuid4().hex[:17]}",
            tags_json=json.dumps({
                "Name": f"hpa-{random.choice(SERVICES)}", "auto": "true",
                "team": random.choice(TEAMS), "cost-center": "cc-12345",
                "environment": random.choice(["prod", "staging"]),
            }),
            request_parameters_json=json.dumps({"InstanceType": random.choice(["t3.medium","t3.large"]), "MinCount": 2, "MaxCount": 8}),
        )
    elif event_type == "legitimate_cicd":
        e.update(
            principal_id="svc-cicd",
            arn="arn:aws:iam::123456789012:user/svc-cicd",
            event_name="RunInstances", action="RunInstances",
            resource_name=f"build-{random.randint(1000,9999)}",
            resource_id=f"i-{uuid.uuid4().hex[:17]}",
            tags_json=json.dumps({
                "pipeline": f"build-{random.randint(1000,9999)}",
                "commit": uuid.uuid4().hex[:8],
                "team": random.choice(TEAMS), "ttl": "30m",
            }),
        )
    else:  # routine_ephemeral
        en = random.choice(["CreateBucket", "DeleteInstances", "RunInstances"])
        e.update(
            event_name=en, action=en,
            resource_name=f"temp-{uuid.uuid4().hex[:8]}",
            tags_json=json.dumps({"environment": random.choice(["dev","test"]),
                                  "owner": random.choice(USERS), "ttl": f"{random.randint(5,60)}m"}),
        )
    return e


def _k8s(event_type: str, ts: str) -> Dict[str, Any]:
    ns = random.choice(NAMESPACES)
    principal = random.choice(USERS)
    rname = f"{random.choice(SERVICES)}-{uuid.uuid4().hex[:8]}"
    e: Dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "log_type": "k8s_audit",
        "severity": "INFO",
        "scenario": "live_kubernetes",
        "event_source": "k8s-api-server",
        "event_name": "PodCreated",
        "principal_id": principal,
        "source_ip": _internal_ip(),
        "verb": "create",
        "resource_name": rname,
        "namespace": ns,
        "is_privileged": 0,
        "actor": principal,
        "action": "create",
        "user_agent": "k8s-client",
        "region": "local",
        "labels_json": json.dumps({"app": random.choice(SERVICES)}),
        "controller_owner": f"deployment/{random.choice(SERVICES)}-deployment",
        "service_type": "",
        "rbac_change": "",
    }

    if event_type == "resource_hijacking":
        e.update(
            severity="CRITICAL", verb="create", action="create",
            resource_name=f"miner-{uuid.uuid4().hex[:6]}",
            principal_id=random.choice(["unknown", "system:anonymous", "svc-backup"]),
            source_ip=_suspicious_ip(), is_privileged=1,
            namespace=random.choice(["production", "default"]),
            controller_owner="",  # orphaned
            labels_json=json.dumps({"app":"worker","temp":"true",
                                    "image": random.choice(["crypto-miner:latest","xmrig:6.12"])}),
        )
    elif event_type == "public_exposure":
        e.update(
            severity="HIGH", verb="create", action="create",
            event_name="ServiceExposed",
            resource_name=f"debug-svc-{uuid.uuid4().hex[:6]}",
            namespace=random.choice(["production","staging"]),
            service_type="NodePort",
            labels_json=json.dumps({"debug":"true","ttl":"15m"}),
            controller_owner="",
        )
    elif event_type == "identity_anomaly":
        e.update(
            severity="HIGH", verb="bind", action="bind",
            event_name="RoleBindingCreated",
            resource_name=f"temp-binding-{uuid.uuid4().hex[:6]}",
            principal_id=random.choice(["unknown","system:anonymous"]),
            source_ip=_suspicious_ip(),
            rbac_change="bind:clusterrolebindings",
            labels_json=json.dumps({"role":"cluster-admin","subject":"temp-sa"}),
            controller_owner="",
        )
    elif event_type == "legitimate_autoscale":
        e.update(
            resource_name=f"{random.choice(SERVICES)}-{uuid.uuid4().hex[:8]}",
            labels_json=json.dumps({"app": random.choice(SERVICES),
                                    "managed-by":"horizontal-pod-autoscaler",
                                    "team": random.choice(TEAMS)}),
            controller_owner=f"deployment/{random.choice(SERVICES)}-deployment",
        )
    elif event_type == "legitimate_cicd":
        e.update(
            principal_id="svc-cicd",
            resource_name=f"build-{random.randint(1000,9999)}-{uuid.uuid4().hex[:4]}",
            labels_json=json.dumps({"job-name": f"build-{random.randint(1000,9999)}",
                                    "tekton.dev/pipeline":"ci-pipeline","team": random.choice(TEAMS)}),
            controller_owner=f"job/build-job-{random.randint(1000,9999)}",
        )
    else:  # routine_ephemeral
        v = random.choice(["create","delete"])
        e.update(verb=v, action=v, resource_name=f"temp-{uuid.uuid4().hex[:8]}",
                 labels_json=json.dumps({"app": random.choice(SERVICES),
                                         "environment": random.choice(["dev","test"]),
                                         "ttl": f"{random.randint(5,60)}m"}))
    return e


def _vpc(event_type: str, ts: str) -> Dict[str, Any]:
    src = _internal_ip()
    dst = _internal_ip()
    e: Dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "log_type": "vpc_flow",
        "severity": "INFO",
        "scenario": "live_network",
        "event_source": "vpc-flow-logs",
        "event_name": "vpc_flow",
        "principal_id": "network-flow",
        "source_ip": src, "src_addr": src, "dst_addr": dst,
        "src_port": random.randint(1024,65535),
        "dst_port": random.choice([80,443,8080,5432,6379,9090]),
        "vpc_bytes": random.randint(100,5000),
        "vpc_action": "ACCEPT",
        "resource_name": f"{src}->{dst}", "resource_id": f"{src}->{dst}",
        "region": random.choice(REGIONS), "namespace": "default",
        "is_privileged": 0, "actor": "network-flow", "action": "ACCEPT",
        "user_agent": "", "tags_json": "", "labels_json": "",
    }
    if event_type == "resource_hijacking":
        e.update(severity="HIGH", dst_addr=_suspicious_ip(),
                 dst_port=random.choice([3333,4444,5555,14444]),
                 vpc_bytes=random.randint(500_000,5_000_000))
    elif event_type == "public_exposure":
        e.update(severity="HIGH", src_addr=_suspicious_ip(), source_ip=_suspicious_ip(),
                 vpc_bytes=random.randint(100_000,1_000_000),
                 dst_port=random.choice([22,3389,8080]))
    elif event_type == "identity_anomaly":
        e.update(severity="MEDIUM", dst_port=random.choice([22,3389,445]),
                 vpc_bytes=random.randint(50_000,500_000))
    return e


def _identity(event_type: str, ts: str) -> Dict[str, Any]:
    principal = random.choice(USERS)
    e: Dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "log_type": "cloudtrail",
        "severity": "INFO",
        "scenario": "live_cloudtrail",
        "event_source": "sts.amazonaws.com",
        "event_name": "GetSessionToken",
        "principal_id": principal,
        "arn": f"arn:aws:iam::123456789012:user/{principal}",
        "source_ip": _internal_ip(),
        "resource_name": principal,
        "resource_id": f"arn:aws:sts::123456789012:assumed-role/{random.choice(ROLES)}/{principal}",
        "region": "us-east-1",
        "user_agent": "aws-sdk-go/1.44",
        "tags_json": json.dumps({}),
        "verb": "create", "namespace": "default", "is_privileged": 0,
        "actor": principal, "action": "GetSessionToken",
        "token_ttl_seconds": 3600, "session_type": "Standard",
        "session_name": principal, "issuer": "",
    }
    if event_type == "identity_anomaly":
        e.update(severity="HIGH", event_name="AssumeRole", action="AssumeRole",
                 principal_id=random.choice(["unknown-service","svc-lambda"]),
                 source_ip=_suspicious_ip(),
                 token_ttl_seconds=random.choice([900,1800]),
                 session_type="AssumedRole", session_name=uuid.uuid4().hex[:8],
                 issuer="federated-user")
    elif event_type == "resource_hijacking":
        e.update(severity="CRITICAL", event_name="CreateAccessKey", action="CreateAccessKey",
                 principal_id=random.choice(["svc-cicd","unknown-service"]),
                 source_ip=_suspicious_ip(), token_ttl_seconds=7200)
    elif event_type in ("legitimate_autoscale", "legitimate_cicd"):
        e.update(event_name="AssumeRole", action="AssumeRole",
                 principal_id="svc-autoscaler" if event_type == "legitimate_autoscale" else "svc-cicd",
                 source_ip=_internal_ip(), token_ttl_seconds=3600,
                 session_type="AssumedRole", session_name=uuid.uuid4().hex[:8])
    else:  # routine_ephemeral
        en = random.choice(["GetSessionToken", "AssumeRole"])
        e.update(event_name=en, action=en, token_ttl_seconds=random.choice([3600,7200,14400]))
    return e


# ─── ASSEMBLE ONE CYCLE ───────────────────────────────────────────────────────
_SOURCE_WEIGHTS = {"cloudtrail": 0.40, "k8s_audit": 0.40, "vpc_flow": 0.15, "identity": 0.05}


def generate_cycle_events() -> List[Dict[str, Any]]:
    """Generate one full cycle of ~500 events, sorted chronologically."""
    events: List[Dict[str, Any]] = []
    base = datetime.now(timezone.utc) - timedelta(hours=2)

    for event_type, count in DISTRIBUTION.items():
        for _ in range(count):
            # Burst events cluster in 2-minute windows
            if event_type in ("legitimate_autoscale", "resource_hijacking"):
                window = random.randint(0, 59)
                offset = window * 120 + random.randint(0, 120)
            else:
                offset = random.randint(0, 7200)
            ts = _ts(base, offset)
            source = random.choices(list(_SOURCE_WEIGHTS.keys()),
                                    weights=list(_SOURCE_WEIGHTS.values()))[0]
            if source == "cloudtrail":
                ev = _cloudtrail(event_type, ts)
            elif source == "k8s_audit":
                ev = _k8s(event_type, ts)
            elif source == "vpc_flow":
                ev = _vpc(event_type, ts)
            else:
                ev = _identity(event_type, ts)
            ev["classification"] = event_type
            ev["ephemeral"] = True
            events.append(ev)

    events.sort(key=lambda x: x["timestamp"])
    return events


# ─── ASYNC LOOP ───────────────────────────────────────────────────────────────
async def simulator_loop(queue: asyncio.Queue) -> None:
    """Background task: clear DB → feed 500 events → wait → repeat.

    Puts events onto the same `k8s_event_queue` that /api/ingest uses, so
    every event goes through the full ML pipeline (k8s_queue_processor).
    """
    from backend.database import clear_all_events

    print("  [simulator] Starting integrated event simulator (500 events/cycle)")
    # Brief delay so the queue processor + model are ready
    await asyncio.sleep(8)

    cycle = 1
    while True:
        try:
            print(f"\n{'='*70}\n  [simulator] CYCLE {cycle} — generating {TOTAL_EVENTS} events\n{'='*70}")

            # 1. Clear DB for a fresh dashboard
            try:
                clear_all_events()
                print("  [simulator] ✅ Database cleared")
            except Exception as e:
                print(f"  [simulator] ⚠️  Clear failed: {e}")

            # 2. Generate events
            events = generate_cycle_events()
            dist = Counter(e.get("classification", "?") for e in events)
            print(f"  [simulator] Distribution: {dict(dist)}")

            # 3. Feed events into the queue at a realistic rate.
            #    Small delay between events so the SSE stream feels live and
            #    the rolling burst chart shows movement.
            for i, event in enumerate(events):
                await queue.put(event)
                # Pace: ~10 events/sec → 500 events in ~50s
                if i % 10 == 0:
                    print(f"  [simulator] Fed {i+1}/{len(events)} events")
                await asyncio.sleep(0.1)

            print(f"  [simulator] ✅ All {len(events)} events queued. Waiting 120s display window...")

            # 4. Display window — let users see the populated dashboard
            await asyncio.sleep(120)

            cycle += 1

        except asyncio.CancelledError:
            print("  [simulator] Loop cancelled, exiting.")
            raise
        except Exception as e:
            print(f"  [simulator] ❌ Cycle error: {e}")
            await asyncio.sleep(10)
