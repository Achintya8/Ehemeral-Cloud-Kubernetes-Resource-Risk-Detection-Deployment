
# Generate the fixed ingestion script


"""
live_ingestor.py
═══════════════════════════════════════════════════════════════════════════════
Bridges live AWS (CloudTrail, Lambda) and Kubernetes events into the
Ephemeral Risk Detection SQLite database.

Run alongside your pipeline:
    python live_ingestor.py

Or run in background:
    nohup python live_ingestor.py > ingestor.log 2>&1 &
"""

import asyncio
import hashlib
import json
import sqlite3
import subprocess
import sys
import time
import uuid
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from model.telemetry_normalizer import normalize_telemetry_event

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
ROOT = PROJECT_ROOT
DB_PATH = ROOT / "data" / "events.db"
SCHEMA_PATH = ROOT / "schema.sql"
POLL_INTERVAL = 5
K8S_POLL_INTERVAL = 3
LAMBDA_POLL_INTERVAL = 10

AWS_REGION = "us-east-1"
CLOUDTRAIL_BUCKET = "ephemeral-ct-logs-726092964715"
LAMBDA_FUNCTION = "ephemeral-event-generator"
K8S_NAMESPACE = "ephemeral-test"

# ─── DATABASE HELPERS ──────────────────────────────────────────────────────────


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

PROCESSED_EVENT_IDS = set()
import os
FASTAPI_INGEST_URL = os.environ.get("FASTAPI_INGEST_URL", "http://127.0.0.1:8000/api/ingest")


def init_ingestor_tables() -> None:
    pass


def _stable_event_id(event: Dict[str, Any], extra: str = "") -> str:
    """Deterministic ID from event content so the same real event always hashes to the same key."""
    raw = f"{event.get('eventName','')}{event.get('eventSource','')}{event.get('sourceIPAddress','')}{event.get('eventTime','')}{extra}"
    return hashlib.sha1(raw.encode()).hexdigest()


def insert_normalized_event(event: Dict[str, Any]) -> None:
    normalized = normalize_telemetry_event(event)
    event_id = normalized.get("event_id")

    if event_id in PROCESSED_EVENT_IDS:
        return
    PROCESSED_EVENT_IDS.add(event_id)

    try:
        response = requests.post(FASTAPI_INGEST_URL, json=event, timeout=10)
        if response.status_code == 200:
            print(
                f"[INGEST] {normalized['log_type']} "
                f"{normalized['action'] or normalized['event_name'] or normalized['verb']} "
                f"-> {normalized['severity']} (sent to FastAPI)"
            )
        else:
            # One retry after a short pause
            time.sleep(2)
            try:
                response = requests.post(FASTAPI_INGEST_URL, json=event, timeout=10)
                if response.status_code != 200:
                    print(f"[INGEST] Retry failed (HTTP {response.status_code}): {response.text}")
            except requests.exceptions.RequestException as retry_err:
                print(f"[INGEST] Retry exception: {retry_err}")
    except requests.exceptions.RequestException as e:
        print(f"[INGEST] Failed to send to FastAPI: {e}")


def insert_cloudtrail_event(event: Dict[str, Any]) -> None:
    insert_normalized_event(event)


def insert_k8s_event(event: Dict[str, Any]) -> None:
    insert_normalized_event(event)


def insert_vpc_flow_event(event: Dict[str, Any]) -> None:
    insert_normalized_event(event)


# ─── AWS LAMBDA LOG INGESTION ────────────────────────────────────────────────


def get_lambda_logs() -> List[Dict[str, Any]]:
    """Fetch recent Lambda execution logs and parse events."""
    try:
        # Use get-log-events instead of tail for reliable JSON extraction
        result = subprocess.run(
            [
                "aws", "logs", "describe-log-streams",
                "--log-group-name", f"/aws/lambda/{LAMBDA_FUNCTION}",
                "--order-by", "LastEventTime",
                "--descending",
                "--limit", "1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"[DEBUG] describe-log-streams failed: {result.stderr}")
            return []

        streams = json.loads(result.stdout).get("logStreams", [])
        if not streams:
            print("[DEBUG] No log streams found")
            return []

        stream_name = streams[0]["logStreamName"]

        # Get events from the stream
        result = subprocess.run(
            [
                "aws", "logs", "get-log-events",
                "--log-group-name", f"/aws/lambda/{LAMBDA_FUNCTION}",
                "--log-stream-name", stream_name,
                "--limit", "50",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"[DEBUG] get-log-events failed: {result.stderr}")
            return []

        events_data = json.loads(result.stdout)
        events = []

        for event in events_data.get("events", []):
            message = event.get("message", "")
            # Look for JSON in the message
            if "{" not in message:
                continue
            # Find the JSON part
            json_start = message.find("{")
            if json_start == -1:
                continue
            # Try to find the matching closing brace
            try:
                data = json.loads(message[json_start:])
                if "eventName" in data:
                    events.append(data)
                    print(f"[DEBUG] Parsed Lambda event: {data.get('eventName')}")
            except json.JSONDecodeError:
                # Try with brace counting
                brace_count = 0
                json_end = json_start
                for i, char in enumerate(message[json_start:], start=json_start):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
                try:
                    data = json.loads(message[json_start:json_end])
                    if "eventName" in data:
                        events.append(data)
                        print(f"[DEBUG] Parsed Lambda event: {data.get('eventName')}")
                except json.JSONDecodeError:
                    continue

        print(f"[DEBUG] Total Lambda events parsed: {len(events)}")
        return events
    except Exception as e:
        print(f"[ERROR] Lambda log fetch failed: {e}")
        import traceback
        traceback.print_exc()
        return []


# ─── KUBERNETES EVENT INGESTION ──────────────────────────────────────────────


def get_k8s_events() -> List[Dict[str, Any]]:
    """Fetch recent Kubernetes events from ephemeral-test namespace."""
    try:
        result = subprocess.run(
            [
                "kubectl", "get", "events",
                "-n", K8S_NAMESPACE,
                "--sort-by=.lastTimestamp",
                "-o", "json",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"[DEBUG] kubectl failed: {result.stderr}")
            return []

        data = json.loads(result.stdout)
        events = []

        for item in data.get("items", [])[-15:]:
            event_type = item.get("type", "Normal")
            reason = item.get("reason", "")
            message = item.get("message", "")
            involved = item.get("involvedObject", {})
            name = involved.get("name", "unknown")
            kind = involved.get("kind", "Unknown")

            # FIXED: Better verb mapping
            verb = "unknown"
            reason_lower = reason.lower()
            
            if any(r in reason_lower for r in ["created", "creating", "successfulcreate"]):
                verb = "create"
            elif any(r in reason_lower for r in ["deleted", "deleting", "killing"]):
                verb = "delete"
            elif any(r in reason_lower for r in ["scaling", "scaled"]):
                verb = "scale-up"
            elif any(r in reason_lower for r in ["completed", "sawcompletedjob"]):
                verb = "complete"
            elif any(r in reason_lower for r in ["scheduled", "pulling", "pulled", "started"]):
                verb = "create"
            elif "back-off" in reason_lower or "failed" in reason_lower:
                verb = "failed"

            is_privileged = "privileged" in message.lower()

            events.append({
                "verb": verb,
                "resource_name": name,
                "namespace": K8S_NAMESPACE,
                "username": f"system:serviceaccount:{K8S_NAMESPACE}:event-generator",
                "pod_ip": "10.0.0.1",
                "is_privileged": is_privileged,
                "raw": f"{reason}: {message}",
            })

        return events
    except Exception as e:
        print(f"[ERROR] K8s event fetch failed: {e}")
        import traceback
        traceback.print_exc()
        return []


# ─── CLOUDTRAIL S3 INGESTION ─────────────────────────────────────────────────


def get_cloudtrail_s3_events() -> List[Dict[str, Any]]:
    try:
        today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        result = subprocess.run(
            [
                "aws", "s3", "ls",
                f"s3://{CLOUDTRAIL_BUCKET}/AWSLogs/726092964715/CloudTrail/{AWS_REGION}/{today}/",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        events = []
        lines = result.stdout.strip().split("\\n")
        if not lines:
            return []

        latest = lines[-1].split()[-1]
        local_path = f"/tmp/cloudtrail_{latest}"

        subprocess.run(
            [
                "aws", "s3", "cp",
                f"s3://{CLOUDTRAIL_BUCKET}/AWSLogs/726092964715/CloudTrail/{AWS_REGION}/{today}/{latest}",
                local_path,
            ],
            capture_output=True,
            timeout=30,
        )

        import gzip
        with gzip.open(local_path, "rt") as f:
            data = json.load(f)

        for record in data.get("Records", []):
            events.append({
                "eventID": record.get("eventID"),
                "eventTime": record.get("eventTime"),
                "eventSource": record.get("eventSource", "unknown"),
                "eventName": record.get("eventName", "Unknown"),
                "sourceIPAddress": record.get("sourceIPAddress", "0.0.0.0"),
                "userAgent": record.get("userAgent", "unknown"),
                "userIdentity": record.get("userIdentity", {}),
                "requestParameters": record.get("requestParameters", {}),
                "resources": record.get("resources", []),
                "awsRegion": record.get("awsRegion", AWS_REGION),
            })

        return events
    except Exception as e:
        print(f"[ERROR] CloudTrail S3 fetch failed: {e}")
        return []


# ─── MAIN LOOP ────────────────────────────────────────────────────────────────


async def ingest_loop() -> None:
    print("═══════════════════════════════════════════════════════════════")
    print("  LIVE EVENT INGESTOR")
    print("  Sources: Lambda logs | K8s events | CloudTrail S3")
    print("  Database:", DB_PATH)
    print("═══════════════════════════════════════════════════════════════")
    print()

    init_ingestor_tables()

    last_lambda_check = 0
    last_k8s_check = 0
    last_s3_check = 0

    while True:
        now = time.time()

        if now - last_lambda_check >= LAMBDA_POLL_INTERVAL:
            print("[POLL] Checking Lambda logs...")
            lambda_events = get_lambda_logs()
            for event in lambda_events:
                insert_cloudtrail_event(event)
            last_lambda_check = now

        if now - last_k8s_check >= K8S_POLL_INTERVAL:
            print("[POLL] Checking K8s events...")
            k8s_events = get_k8s_events()
            for event in k8s_events:
                insert_k8s_event(event)
            last_k8s_check = now

        if now - last_s3_check >= POLL_INTERVAL:
            print("[POLL] Checking CloudTrail S3...")
            s3_events = get_cloudtrail_s3_events()
            for event in s3_events:
                insert_cloudtrail_event(event)
            last_s3_check = now

        await asyncio.sleep(1)


# ─── MANUAL INGESTION ────────────────────────────────────────────────────────


def ingest_lambda_now(count: int = 10) -> None:
    print(f"Invoking Lambda {count} times...")
    for i in range(count):
        try:
            subprocess.run(
                [
                    "aws", "lambda", "invoke",
                    "--function-name", LAMBDA_FUNCTION,
                    "--payload", json.dumps({"manual": True, "index": i}),
                    "/dev/null",
                ],
                capture_output=True,
            )
        except Exception as e:
            print(f"[ERROR] Failed to invoke lambda: {e}")
            break
        time.sleep(0.5)

    print("Waiting for logs to propagate...")
    time.sleep(5)

    events = get_lambda_logs()
    print(f"Found {len(events)} events in logs")
    for event in events:
        insert_cloudtrail_event(event)


def ingest_k8s_now() -> None:
    events = get_k8s_events()
    print(f"Found {len(events)} K8s events")
    for event in events:
        insert_k8s_event(event)


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        print("One-shot ingestion mode")
        init_ingestor_tables()
        ingest_lambda_now(5)
        ingest_k8s_now()
        print("Done.")
    else:
        try:
            asyncio.run(ingest_loop())
        except KeyboardInterrupt:
            print("\\n[INGESTOR] Shutting down gracefully.")
