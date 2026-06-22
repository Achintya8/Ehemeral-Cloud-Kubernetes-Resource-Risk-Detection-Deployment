#!/usr/bin/env python3
"""
Ephemeral Cloud & Kubernetes Event Simulator
============================================
Generates ~500 realistic security events per cycle, sends them to the
FastAPI backend via POST /api/ingest, then clears the database and repeats.

This is the ONLY event source when the server's built-in demo_traffic_loop
is disabled (see instructions below).

Usage:
    pip install requests
    python event_simulator.py

Before running, disable the server's built-in demo generator so events
don't compete:
    In backend/main.py startup_event(), comment out:
        asyncio.create_task(demo_traffic_loop())
"""

import requests
import random
import json
import time
import uuid
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from collections import Counter


# ─── CONFIG ──────────────────────────────────────────────────────────────────
BASE_URL = "http://localhost:8000"       # FastAPI dev server
LOGIN_URL = f"{BASE_URL}/login"          # Auth endpoint
INGEST_URL = f"{BASE_URL}/api/ingest"   # Single-event ingestion (no auth)
CLEAR_URL = f"{BASE_URL}/api/admin/clear"  # We'll add this endpoint

USERNAME = "analyst1"
PASSWORD = "hackathon"

# Event distribution (out of 500 events)
DISTRIBUTION = {
    "resource_hijacking":    35,   # ~7%  crypto mining bursts — CRITICAL
    "public_exposure":        20,   # ~4%  public exposure — HIGH
    "identity_anomaly":      30,   # ~6%  unexpected identity/session — HIGH
    "legitimate_autoscale": 220,   # ~44% legitimate bursts (noise)
    "legitimate_cicd":       120,  # ~24% CI/CD (noise)
    "routine_ephemeral":      75,  # ~15% normal lifecycle
}

TOTAL_EVENTS = sum(DISTRIBUTION.values())  # 500

# Realistic data pools
NAMESPACES = ["production", "staging", "dev", "cicd", "monitoring", "data-pipeline"]
TEAMS = ["platform", "data-engineering", "frontend", "backend", "security", "ml-team"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
INSTANCE_TYPES = ["t3.medium", "t3.large", "m5.xlarge", "c5.2xlarge", "spot-fleet"]
POD_IMAGES = [
    "nginx:1.21", "python:3.9-slim", "node:16-alpine",
    "ubuntu:20.04", "alpine:latest", "busybox:latest",
    "crypto-miner:latest", "xmrig:6.12", "jenkins-agent:2.3",
    "gitlab-runner:latest", "argo-workflow:3.2",
]
SERVICES = ["web-api", "data-processor", "ml-inference", "cache-layer", "auth-service",
            "payment-svc", "user-svc", "order-svc", "search-svc", "gateway"]
USERS = ["dev-sarah", "dev-mike", "dev-alex", "svc-cicd", "svc-autoscaler", "svc-backup",
         "admin-deploy", "system:anonymous"]
ROLES = ["admin", "editor", "viewer", "cluster-admin", "pod-reader"]
MITRE_ATTACK = {
    "resource_hijacking": ("T1496", "Resource Hijacking", "Impact"),
    "public_exposure":    ("T1133", "External Remote Services", "Initial Access"),
    "identity_anomaly":    ("T1078.004", "Valid Accounts:Cloud Accounts", "Initial Access"),
}


# ─── AUTHENTICATION ────────────────────────────────────────────────────────────
def get_auth_token() -> str | None:
    """Login via POST /login and get JWT access_token."""
    try:
        resp = requests.post(LOGIN_URL, json={"username": USERNAME, "password": PASSWORD}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if token:
            print(f"[AUTH] ✅ Logged in as {USERNAME} (role={data.get('user', {}).get('role', '?')})")
            return token
        print(f"[AUTH] ⚠️  Token not found in response: {data}")
        return None
    except Exception as e:
        print(f"[AUTH] ❌ Login failed: {e}")
        return None


# ─── EVENT GENERATION HELPERS ────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_timestamp(base_time: datetime, offset_seconds: int) -> str:
    """ISO timestamp with ±30s jitter."""
    jitter = random.randint(-30, 30)
    t = base_time + timedelta(seconds=offset_seconds + jitter)
    return t.astimezone(timezone.utc).isoformat(timespec="seconds")


def _random_internal_ip() -> str:
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    return f"185.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_suspicious_external_ip() -> str:
    """External IPs from known suspicious ranges."""
    prefixes = ["185.220.101", "203.0.113", "198.51.100", "45.155", "91.240", "194.165"]
    return f"{random.choice(prefixes)}.{random.randint(1, 254)}"


# ─── CLOUD AUDIT (CloudTrail) EVENTS ────────────────────────────────────────
def generate_cloudtrail_event(event_type: str, timestamp: str, event_id: str) -> Dict[str, Any]:
    """Generate a CloudTrail-style event matching CANONICAL_DEFAULTS."""
    principal = random.choice(USERS)
    region = random.choice(REGIONS)
    resource_name = f"i-{uuid.uuid4().hex[:17]}"
    source_ip = _random_internal_ip()

    # Base event (canonical schema for telemetry_normalizer)
    event: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "log_type": "cloudtrail",
        "severity": "INFO",
        "scenario": "live_cloudtrail",
        "event_source": "ec2.amazonaws.com",
        "event_name": "DescribeInstances",
        "principal_id": principal,
        "arn": f"arn:aws:iam::123456789012:user/{principal}",
        "source_ip": source_ip,
        "resource_name": resource_name,
        "resource_id": resource_name,
        "region": region,
        "user_agent": "aws-cli/2.0",
        "tags_json": json.dumps({"Environment": "dev", "Team": random.choice(TEAMS)}),
        "labels_json": "",
        "verb": "describe",
        "namespace": "default",
        "is_privileged": 0,
        "risk_score": 5.0,
        "actor": principal,
        "action": "DescribeInstances",
    }

    if event_type == "resource_hijacking":
        # Crypto mining: high-CPU instances, sparse tags, external IP, off-hours
        event["severity"] = "CRITICAL"
        event["event_name"] = "RunInstances"
        event["action"] = "RunInstances"
        event["event_source"] = "ec2.amazonaws.com"
        event["resource_name"] = f"temp-miner-{uuid.uuid4().hex[:6]}"
        event["resource_id"] = f"i-{uuid.uuid4().hex[:17]}"
        event["source_ip"] = _random_suspicious_external_ip()
        event["user_agent"] = "boto3/1.26"
        event["region"] = random.choice(["us-east-1", "eu-west-1"])
        event["tags_json"] = json.dumps({"Name": "temp-worker", "auto": "true"})
        event["request_parameters_json"] = json.dumps({
            "InstanceType": "c5.4xlarge",
            "MinCount": 5,
            "MaxCount": 15,
        })
        event["risk_score"] = random.uniform(85, 98)
        event["is_anomaly"] = True

    elif event_type == "public_exposure":
        # Security group opened to 0.0.0.0/0, debug context
        event["severity"] = "HIGH"
        event["event_name"] = "AuthorizeSecurityGroupIngress"
        event["action"] = "AuthorizeSecurityGroupIngress"
        event["event_source"] = "ec2.amazonaws.com"
        event["resource_name"] = f"sg-debug-{uuid.uuid4().hex[:6]}"
        event["resource_id"] = f"sg-{uuid.uuid4().hex[:12]}"
        event["source_ip"] = _random_external_ip()
        event["tags_json"] = json.dumps({"debug": "true", "ttl": "15m"})
        event["request_parameters_json"] = json.dumps({
            "GroupId": f"sg-{uuid.uuid4().hex[:12]}",
            "IpPermissions": [{"IpProtocol": "-1", "FromPort": 0, "ToPort": 65535,
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        })
        event["risk_score"] = random.uniform(75, 90)
        event["is_anomaly"] = True

    elif event_type == "identity_anomaly":
        # AssumeRole off-hours, short session, external IP
        event["severity"] = "HIGH"
        event["event_name"] = "AssumeRole"
        event["action"] = "AssumeRole"
        event["event_source"] = "sts.amazonaws.com"
        event["resource_name"] = random.choice(ROLES)
        event["resource_id"] = f"arn:aws:iam::123456789012:role/{event['resource_name']}"
        event["principal_id"] = random.choice(["unknown-service", "svc-lambda", "svc-backup"])
        event["arn"] = f"arn:aws:sts::123456789012:assumed-role/{event['resource_name']}/{uuid.uuid4().hex[:8]}"
        event["source_ip"] = _random_suspicious_external_ip()
        event["user_agent"] = "Boto3/1.26.0"
        event["token_ttl_seconds"] = random.choice([900, 1800])
        event["tags_json"] = json.dumps({})
        event["session_type"] = "AssumedRole"
        event["session_name"] = uuid.uuid4().hex[:8]
        event["risk_score"] = random.uniform(70, 88)
        event["is_anomaly"] = True

    elif event_type == "legitimate_autoscale":
        event["event_name"] = "RunInstances"
        event["action"] = "RunInstances"
        event["resource_name"] = f"hpa-{random.choice(SERVICES)}-{random.randint(100,999)}"
        event["resource_id"] = f"i-{uuid.uuid4().hex[:17]}"
        event["tags_json"] = json.dumps({
            "Name": f"hpa-{random.choice(SERVICES)}",
            "auto": "true",
            "team": random.choice(TEAMS),
            "cost-center": "cc-12345",
            "environment": random.choice(["prod", "staging"]),
        })
        event["request_parameters_json"] = json.dumps({
            "InstanceType": random.choice(["t3.medium", "t3.large"]),
            "MinCount": 2,
            "MaxCount": 8,
        })
        event["risk_score"] = random.uniform(5, 20)

    elif event_type == "legitimate_cicd":
        event["principal_id"] = "svc-cicd"
        event["arn"] = "arn:aws:iam::123456789012:user/svc-cicd"
        event["event_name"] = "RunInstances"
        event["action"] = "RunInstances"
        event["resource_name"] = f"build-{random.randint(1000, 9999)}"
        event["resource_id"] = f"i-{uuid.uuid4().hex[:17]}"
        event["tags_json"] = json.dumps({
            "pipeline": f"build-{random.randint(1000, 9999)}",
            "commit": uuid.uuid4().hex[:8],
            "team": random.choice(TEAMS),
            "ttl": "30m",
        })
        event["risk_score"] = random.uniform(3, 15)

    else:  # routine_ephemeral
        event["event_name"] = random.choice(["CreateBucket", "DeleteInstances", "RunInstances"])
        event["action"] = event["event_name"]
        event["resource_name"] = f"temp-{uuid.uuid4().hex[:8]}"
        event["tags_json"] = json.dumps({
            "environment": random.choice(["dev", "test"]),
            "owner": random.choice(USERS),
            "ttl": f"{random.randint(5, 60)}m",
        })
        event["risk_score"] = random.uniform(1, 10)

    return event


# ─── KUBERNETES AUDIT EVENTS ────────────────────────────────────────────────
def generate_k8s_audit_event(event_type: str, timestamp: str, event_id: str) -> Dict[str, Any]:
    """Generate a Kubernetes audit event matching CANONICAL_DEFAULTS."""
    namespace = random.choice(NAMESPACES)
    principal = random.choice(USERS)
    resource_name = f"{random.choice(SERVICES)}-{uuid.uuid4().hex[:8]}"
    source_ip = _random_internal_ip()

    event: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "log_type": "k8s_audit",
        "severity": "INFO",
        "scenario": "live_kubernetes",
        "event_source": "k8s-api-server",
        "event_name": "PodCreated",
        "principal_id": principal,
        "source_ip": source_ip,
        "verb": "create",
        "resource_name": resource_name,
        "namespace": namespace,
        "is_privileged": 0,
        "risk_score": 5.0,
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
        # Crypto mining pod: privileged, high resources, suspicious image
        event["severity"] = "CRITICAL"
        event["verb"] = "create"
        event["action"] = "create"
        event["resource_name"] = f"miner-{uuid.uuid4().hex[:6]}"
        event["principal_id"] = random.choice(["unknown", "system:anonymous", "svc-backup"])
        event["source_ip"] = _random_suspicious_external_ip()
        event["is_privileged"] = 1
        event["labels_json"] = json.dumps({"app": "worker", "temp": "true"})
        event["controller_owner"] = ""  # orphaned — no controller
        event["namespace"] = random.choice(["production", "default"])
        event["risk_score"] = random.uniform(90, 99)
        event["is_anomaly"] = True
        # Add image info in labels for visibility
        event["labels_json"] = json.dumps({
            "app": "worker",
            "temp": "true",
            "image": random.choice(["crypto-miner:latest", "xmrig:6.12"]),
        })

    elif event_type == "public_exposure":
        # NodePort service exposed
        event["severity"] = "HIGH"
        event["verb"] = "create"
        event["action"] = "create"
        event["event_name"] = "ServiceExposed"
        event["resource_name"] = f"debug-svc-{uuid.uuid4().hex[:6]}"
        event["namespace"] = random.choice(["production", "staging"])
        event["service_type"] = "NodePort"
        event["labels_json"] = json.dumps({"debug": "true", "ttl": "15m"})
        event["controller_owner"] = ""
        event["risk_score"] = random.uniform(78, 92)
        event["is_anomaly"] = True

    elif event_type == "identity_anomaly":
        # RBAC escalation: bind cluster-admin to temp service account
        event["severity"] = "HIGH"
        event["verb"] = "bind"
        event["action"] = "bind"
        event["event_name"] = "RoleBindingCreated"
        event["resource_name"] = f"temp-binding-{uuid.uuid4().hex[:6]}"
        event["namespace"] = namespace
        event["principal_id"] = random.choice(["unknown", "system:anonymous"])
        event["source_ip"] = _random_suspicious_external_ip()
        event["rbac_change"] = "bind:clusterrolebindings"
        event["labels_json"] = json.dumps({"role": "cluster-admin", "subject": "temp-sa"})
        event["controller_owner"] = ""
        event["risk_score"] = random.uniform(72, 89)
        event["is_anomaly"] = True

    elif event_type == "legitimate_autoscale":
        event["resource_name"] = f"{random.choice(SERVICES)}-{uuid.uuid4().hex[:8]}"
        event["labels_json"] = json.dumps({
            "app": random.choice(SERVICES),
            "managed-by": "horizontal-pod-autoscaler",
            "team": random.choice(TEAMS),
        })
        event["controller_owner"] = f"deployment/{random.choice(SERVICES)}-deployment"
        event["risk_score"] = random.uniform(5, 18)

    elif event_type == "legitimate_cicd":
        event["principal_id"] = "svc-cicd"
        event["resource_name"] = f"build-{random.randint(1000, 9999)}-{uuid.uuid4().hex[:4]}"
        event["labels_json"] = json.dumps({
            "job-name": f"build-{random.randint(1000, 9999)}",
            "tekton.dev/pipeline": "ci-pipeline",
            "team": random.choice(TEAMS),
        })
        event["controller_owner"] = f"job/build-job-{random.randint(1000, 9999)}"
        event["risk_score"] = random.uniform(3, 12)

    else:  # routine_ephemeral
        event["verb"] = random.choice(["create", "delete"])
        event["action"] = event["verb"]
        event["resource_name"] = f"temp-{uuid.uuid4().hex[:8]}"
        event["labels_json"] = json.dumps({
            "app": random.choice(SERVICES),
            "environment": random.choice(["dev", "test"]),
            "ttl": f"{random.randint(5, 60)}m",
        })
        event["risk_score"] = random.uniform(1, 10)

    return event


# ─── VPC FLOW EVENTS ────────────────────────────────────────────────────────
def generate_vpc_flow_event(event_type: str, timestamp: str, event_id: str) -> Dict[str, Any]:
    """Generate a VPC Flow Log event matching CANONICAL_DEFAULTS."""
    src_addr = _random_internal_ip()
    dst_addr = _random_internal_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 8080, 5432, 6379, 9090])

    event: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "log_type": "vpc_flow",
        "severity": "INFO",
        "scenario": "live_network",
        "event_source": "vpc-flow-logs",
        "event_name": "vpc_flow",
        "principal_id": "network-flow",
        "source_ip": src_addr,
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "src_port": src_port,
        "dst_port": dst_port,
        "vpc_bytes": random.randint(100, 5000),
        "vpc_action": "ACCEPT",
        "resource_name": f"{src_addr}->{dst_addr}",
        "resource_id": f"{src_addr}->{dst_addr}",
        "region": random.choice(REGIONS),
        "namespace": "default",
        "is_privileged": 0,
        "risk_score": 3.0,
        "actor": "network-flow",
        "action": "ACCEPT",
        "user_agent": "",
        "tags_json": "",
        "labels_json": "",
    }

    if event_type == "resource_hijacking":
        # High-volume traffic to mining pool ports (3333, 4444, 5555)
        event["severity"] = "HIGH"
        event["dst_addr"] = _random_suspicious_external_ip()
        event["dst_port"] = random.choice([3333, 4444, 5555, 14444])
        event["vpc_bytes"] = random.randint(500_000, 5_000_000)
        event["vpc_action"] = "ACCEPT"
        event["risk_score"] = random.uniform(80, 95)
        event["is_anomaly"] = True

    elif event_type == "public_exposure":
        # Large inbound from external IPs
        event["severity"] = "HIGH"
        event["src_addr"] = _random_suspicious_external_ip()
        event["source_ip"] = event["src_addr"]
        event["vpc_bytes"] = random.randint(100_000, 1_000_000)
        event["dst_port"] = random.choice([22, 3389, 8080])
        event["risk_score"] = random.uniform(70, 85)
        event["is_anomaly"] = True

    elif event_type == "identity_anomaly":
        # Suspicious lateral movement patterns
        event["severity"] = "MEDIUM"
        event["dst_addr"] = _random_internal_ip()
        event["dst_port"] = random.choice([22, 3389, 445])
        event["vpc_bytes"] = random.randint(50_000, 500_000)
        event["risk_score"] = random.uniform(55, 75)
        event["is_anomaly"] = True

    elif event_type in ("legitimate_autoscale", "legitimate_cicd", "routine_ephemeral"):
        event["risk_score"] = random.uniform(1, 10)

    return event


# ─── IDENTITY / SESSION EVENTS (CloudTrail STS) ─────────────────────────────
def generate_identity_event(event_type: str, timestamp: str, event_id: str) -> Dict[str, Any]:
    """Generate an STS identity/session event (subset of CloudTrail)."""
    principal = random.choice(USERS)
    source_ip = _random_internal_ip()

    event: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "log_type": "cloudtrail",
        "severity": "INFO",
        "scenario": "live_cloudtrail",
        "event_source": "sts.amazonaws.com",
        "event_name": "GetSessionToken",
        "principal_id": principal,
        "arn": f"arn:aws:iam::123456789012:user/{principal}",
        "source_ip": source_ip,
        "resource_name": principal,
        "resource_id": f"arn:aws:sts::123456789012:assumed-role/{random.choice(ROLES)}/{principal}",
        "region": "us-east-1",
        "user_agent": "aws-sdk-go/1.44",
        "tags_json": json.dumps({}),
        "labels_json": "",
        "verb": "create",
        "namespace": "default",
        "is_privileged": 0,
        "risk_score": 5.0,
        "actor": principal,
        "action": "GetSessionToken",
        "token_ttl_seconds": 3600,
        "session_type": "Standard",
        "session_name": principal,
        "issuer": "",
    }

    if event_type == "identity_anomaly":
        event["severity"] = "HIGH"
        event["event_name"] = "AssumeRole"
        event["action"] = "AssumeRole"
        event["principal_id"] = random.choice(["unknown-service", "svc-lambda"])
        event["source_ip"] = _random_suspicious_external_ip()
        event["token_ttl_seconds"] = random.choice([900, 1800])
        event["session_type"] = "AssumedRole"
        event["session_name"] = uuid.uuid4().hex[:8]
        event["issuer"] = "federated-user"
        event["risk_score"] = random.uniform(75, 92)
        event["is_anomaly"] = True

    elif event_type == "resource_hijacking":
        event["severity"] = "CRITICAL"
        event["event_name"] = "CreateAccessKey"
        event["action"] = "CreateAccessKey"
        event["principal_id"] = random.choice(["svc-cicd", "unknown-service"])
        event["source_ip"] = _random_suspicious_external_ip()
        event["token_ttl_seconds"] = 7200
        event["risk_score"] = random.uniform(88, 97)
        event["is_anomaly"] = True

    elif event_type in ("legitimate_autoscale", "legitimate_cicd"):
        event["event_name"] = "AssumeRole"
        event["action"] = "AssumeRole"
        event["principal_id"] = "svc-autoscaler" if event_type == "legitimate_autoscale" else "svc-cicd"
        event["source_ip"] = _random_internal_ip()
        event["token_ttl_seconds"] = 3600
        event["session_type"] = "AssumedRole"
        event["session_name"] = uuid.uuid4().hex[:8]
        event["risk_score"] = random.uniform(5, 15)

    else:  # routine_ephemeral
        event["event_name"] = random.choice(["GetSessionToken", "AssumeRole"])
        event["action"] = event["event_name"]
        event["token_ttl_seconds"] = random.choice([3600, 7200, 14400])
        event["risk_score"] = random.uniform(1, 10)

    return event


# ─── ASSEMBLE ALL EVENTS ──────────────────────────────────────────────────
def generate_all_events() -> List[Dict[str, Any]]:
    """Generate the full set of ~500 events with realistic timestamps."""
    events: List[Dict[str, Any]] = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    # Source type weights: 40% CloudTrail, 40% K8s, 15% VPC Flow, 5% Identity
    source_weights = {
        "cloudtrail": 0.40,
        "k8s_audit": 0.40,
        "vpc_flow": 0.15,
        "identity": 0.05,
    }

    for event_type, count in DISTRIBUTION.items():
        for _ in range(count):
            event_id = str(uuid.uuid4())

            # Burst clustering: hijacking and autoscale events cluster in 2-min windows
            if event_type in ("legitimate_autoscale", "resource_hijacking"):
                window = random.randint(0, 59)
                offset = window * 120 + random.randint(0, 120)
            else:
                offset = random.randint(0, 7200)

            timestamp = generate_timestamp(base_time, offset)

            # Pick source type based on weights
            source = random.choices(
                list(source_weights.keys()),
                weights=list(source_weights.values())
            )[0]

            if source == "cloudtrail":
                event = generate_cloudtrail_event(event_type, timestamp, event_id)
            elif source == "k8s_audit":
                event = generate_k8s_audit_event(event_type, timestamp, event_id)
            elif source == "vpc_flow":
                event = generate_vpc_flow_event(event_type, timestamp, event_id)
            else:
                event = generate_identity_event(event_type, timestamp, event_id)

            # Tag with classification for ground-truth tracking
            event["classification"] = event_type
            event["ephemeral"] = True
            event["ttl_minutes"] = random.choice([5, 10, 15, 30, 60, 120])

            events.append(event)

    # Sort by timestamp for realistic ingestion order
    events.sort(key=lambda x: x["timestamp"])

    print(f"[GEN] ✅ Generated {len(events)} events")
    return events


# ─── API INTERACTION ──────────────────────────────────────────────────────────
def send_events(events: List[Dict[str, Any]], token: str | None) -> int:
    """Send events one-by-one via POST /api/ingest. Returns count sent."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    total_sent = 0
    failed = 0
    batch_size = 10  # Send in small rapid-fire batches

    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        for event in batch:
            try:
                resp = requests.post(INGEST_URL, headers=headers, json=event, timeout=15)
                if resp.status_code in (200, 202):
                    total_sent += 1
                else:
                    failed += 1
                    if failed <= 5:
                        print(f"[SEND] ⚠️  {resp.status_code} for event {event.get('event_id')}: {resp.text[:100]}")
            except Exception as e:
                failed += 1
                if failed <= 5:
                    print(f"[SEND] ❌ Error: {e}")

        # Progress indicator
        pct = min(100, ((i + batch_size) / len(events)) * 100)
        print(f"[SEND] 📊 {pct:5.1f}% — Sent {total_sent}, Failed {failed}")
        time.sleep(0.2)  # Small delay between batches

    print(f"[SEND] ✅ Complete: {total_sent} sent, {failed} failed")
    return total_sent


def clear_database(token: str | None) -> bool:
    """Clear the database via the admin API endpoint."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Try multiple approaches
    clear_endpoints = [
        ("DELETE", f"{BASE_URL}/api/admin/clear"),
        ("POST",  f"{BASE_URL}/api/admin/clear"),
        ("DELETE", f"{BASE_URL}/api/clear"),
        ("POST",  f"{BASE_URL}/api/clear"),
        ("POST",  f"{BASE_URL}/api/reset"),
    ]

    for method, url in clear_endpoints:
        try:
            resp = requests.request(method, url, headers=headers, timeout=10)
            if resp.status_code in (200, 204):
                print(f"[CLEAR] ✅ Database cleared via {method} {url}")
                return True
        except Exception:
            pass

    print("[CLEAR] ⚠️  No clear endpoint found — DB will accumulate events")
    return False


# ─── MAIN LOOP ───────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  🔴 Ephemeral Cloud & K8s Event Simulator")
    print(f"  Target: {BASE_URL}")
    print(f"  Distribution: {json.dumps(DISTRIBUTION, indent=4)}")
    print("=" * 70)

    # Authenticate (optional — /api/ingest doesn't require auth, but clear might)
    token = get_auth_token()

    cycle = 1
    try:
        while True:
            print(f"\n{'─' * 70}")
            print(f"  🔄 CYCLE {cycle}")
            print(f"{'─' * 70}")

            # Step 1: Generate events
            print(f"\n[STEP 1] Generating {TOTAL_EVENTS} events...")
            events = generate_all_events()

            # Show distribution
            dist = Counter(e.get("classification", "unknown") for e in events)
            print(f"[STATS] Event type distribution:")
            for k, v in sorted(dist.items(), key=lambda x: -x[1]):
                pct = (v / TOTAL_EVENTS) * 100
                bar = "█" * int(pct / 2) + "░" * (25 - int(pct / 2))
                print(f"        {k:25s} {v:4d} ({pct:5.1f}%) {bar}")

            # Show severity distribution
            sev_dist = Counter(e.get("severity", "INFO") for e in events)
            print(f"\n[STATS] Severity distribution:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
                v = sev_dist.get(sev, 0)
                if v:
                    print(f"        {sev:10s} {v:4d}")

            # Show source distribution
            src_dist = Counter(e.get("log_type", "unknown") for e in events)
            print(f"\n[STATS] Source distribution:")
            for src, v in src_dist.most_common():
                print(f"        {src:15s} {v:4d}")

            # Step 2: Send to API
            print(f"\n[STEP 2] Sending events to {INGEST_URL}...")
            sent = send_events(events, token)

            # Step 3: Wait for ML pipeline to process
            print(f"\n[STEP 3] Waiting 45 seconds for ML processing...")
            for i in range(45, 0, -5):
                print(f"        ...{i}s remaining")
                time.sleep(5)

            # Step 4: Clear database
            print(f"\n[STEP 4] Clearing database for next cycle...")
            clear_database(token)

            # Step 5: Brief pause before next cycle
            wait_time = 10
            print(f"\n[STEP 5] Next cycle in {wait_time}s — Press Ctrl+C to stop")
            time.sleep(wait_time)

            cycle += 1

    except KeyboardInterrupt:
        print(f"\n\n[EXIT] 👋 Simulator stopped after {cycle - 1} cycles")
    except Exception as e:
        print(f"\n[EXIT] 💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
