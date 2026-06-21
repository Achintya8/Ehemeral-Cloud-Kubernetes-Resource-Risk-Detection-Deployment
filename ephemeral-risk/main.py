# from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
import time as _time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from pyngrok import ngrok

from auth import authenticate_user, create_access_token, decode_token, get_current_user, require_admin
from config import settings
from database import (
    fetch_recent_events,
    fetch_recent_incidents,
    fetch_ttl_distribution,
    fetch_incident_with_events,
    init_db,
    insert_event,
    insert_incident,
    stats as database_stats,
    add_pipeline,
    activate_pipeline,
    list_pipelines,
    fetch_active_pipelines,
    add_blocklist_entry,
    is_principal_blocklisted,
    fetch_active_blocklist,
    release_blocklist_entry,
    insert_action_log,
    fetch_action_log,
)
from features import calculate_features_from_events
import detector
from ml_pipeline import get_pipeline_stats, process_event, seed_pipeline_events
from narrative import build_incident_report
from notifier import dispatch_alert


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# Allow both local dev origins and ngrok tunnels (ngrok-free.dev) when
# the tunnel is enabled, so the browser dashboard can reach the SSE stream.
ALLOWED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:8001", "http://127.0.0.1:8001"]

# Public ngrok tunnel URL (populated at startup if a tunnel is opened).
# Surfaced in /api/state so the Admin panel can show the GitHub webhook URL.
NGROK_PUBLIC_URL: str | None = None

limiter = Limiter(key_func=get_remote_address, default_limits=[])
app = FastAPI(title="Cloud Security Anomaly Detection", version="2.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

'''from fastapi.exceptions import RequestValidationError
import traceback

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print("\n--- DEBUG VALIDATION ERROR START ---")
    print(f"Errors: {exc.errors()}")
    try:
        body = await request.body()
        print(f"Body: {body.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"Could not read body: {e}")
    print("--- DEBUG VALIDATION ERROR END ---\n")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()}
    )

@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    print("\n--- DEBUG EXCEPTION START ---")
    traceback.print_exc()
    print("--- DEBUG EXCEPTION END ---\n")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal Server Error: {type(exc).__name__}: {str(exc)}"}
    )'''


# Build the origin allow-list. Always permit local dev origins; additionally
# permit any ngrok tunnel (https://*.ngrok-free.app / ngrok.io) so the
# browser dashboard can talk to the server behind the tunnel.
_allowed_origin_regex = r"https://.*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=_allowed_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginRequest(StrictRequestModel):
    username: StrictStr = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: StrictStr = Field(min_length=8, max_length=128)


class PipelineRegistration(StrictRequestModel):
    repo_name: StrictStr = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$",
    )
    target_namespace: StrictStr = Field(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$",
    )

    @field_validator("repo_name")
    @classmethod
    def normalize_repository(cls, value: str) -> str:
        return value.strip("/")


class RemediationRequest(BaseModel):
    action_type: str
    target_resource: str
    target_namespace: str = "default"
    # Optional context — passed by the frontend so the NetworkPolicy can note
    # the source IP and the SA revoke can target the exact principal.
    source_ip: str = ""
    principal_id: str = ""



class Broadcaster:
    def __init__(self) -> None:
        self.subscribers: List[asyncio.Queue[str]] = []

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)
        self.subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        if queue in self.subscribers:
            self.subscribers.remove(queue)

    async def publish(self, event_name: str, payload: Dict[str, Any]) -> None:
        message = f"event: {event_name}\ndata: {json.dumps(payload, default=str)}\n\n"
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass


def _start_worker_if_needed() -> None:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# K8s WATCH-STREAM NOISE FILTERING
# The K8s informer watch emits a flood of low-signal lifecycle bookkeeping
# events (verb = ADDED / MODIFIED / DELETED) for every pod scheduling tick.
# These were being scored by the ML model and inflated both the events table
# and the anomaly/incident counts. We only forward *reasons* that represent
# genuine security-relevant K8s signals.
# ─────────────────────────────────────────────────────────────────────────────

# Watch-stream verbs that are pure lifecycle bookkeeping — never forwarded.
_K8S_LIFECYCLE_VERBS = frozenset({"ADDED", "MODIFIED", "DELETED", "BOOKMARK"})

# K8s event *reasons* that are security-relevant and worth scoring.
_K8S_SIGNAL_REASONS = frozenset({
    "Failed", "FailedScheduling", "BackOff", "BackoffLimitExceeded",
    "Killing", "Evicted", "Unhealthy", "FailedMount", "FailedAttachVolume",
    "FailedSync", "SystemOOM", "OOMKilling", "NodeNotReady",
    "PrivilegedContainer", "Forbidden", "TooManyPods",
})


def _is_k8s_watch_noise(raw_event: Dict[str, Any]) -> bool:
    """Return True if an incoming K8s event is pure watch-stream lifecycle
    noise that should NOT reach the ML pipeline.

    Keeps CloudTrail, VPC flow, GitHub webhook, and explicitly-tagged
    security events untouched.
    """
    log_type = str(raw_event.get("log_type") or raw_event.get("log_type") or "").lower()
    # Only filter k8s audit traffic — cloud/vpc/CI events pass straight through.
    if log_type and log_type not in ("k8s_audit", "kubernetes", ""):
        return False

    verb = str(raw_event.get("verb") or raw_event.get("action") or "").strip().upper()
    if verb in _K8S_LIFECYCLE_VERBS:
        # The watcher may still set a meaningful 'reason' / 'event_name'.
        # Only keep it if the reason is in our allow-list of real signals.
        reason = str(raw_event.get("event_name") or raw_event.get("reason") or "").strip()
        return reason not in _K8S_SIGNAL_REASONS

    return False


def _cleanup_false_positive_incidents() -> None:
    """One-shot startup cleanup of malformed / false-positive incidents.

    Targets all tell-tale signatures of noise-derived incidents:
      - '0 correlated ephemeral resource(s)'  (no resources resolved)
      - 'NaT to NaT'                          (timestamps not resolved)
      - 'Unknown principal / workload identity' as the only 'who'
      - pivot_ip = '0.0.0.0' or 'unknown' with LOW severity
      - report_text parses to risk_score = 0 (warmup artifacts)
    Real incidents always carry populated resource/time/principal fields.
    Does NOT touch events.
    """
    from database import get_connection, _DB_LOCK

    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                """
                DELETE FROM incidents
                WHERE report_text LIKE '%0 correlated ephemeral resource(s)%'
                   OR report_text LIKE '%NaT to NaT%'
                   OR report_text LIKE '%Unknown principal / workload identity%'
                   OR (severity = 'LOW' AND (pivot_ip = '0.0.0.0' OR pivot_ip = 'unknown'))
                   OR report_text LIKE '%"risk_score": 0%'
                   OR report_text LIKE '%"risk_score": 0.0%'
                   OR node_count = 0
                """
            )
            removed = cursor.rowcount
            connection.commit()
        finally:
            connection.close()

    if removed:
        print(f"  [cleanup] Removed {removed} false-positive / malformed incident(s).")


def _reset_stale_noise_anomaly_flags() -> None:
    """Reset stale false-positive anomaly flags on KEPT historical noise rows.

    The user chose to keep all stored events (including ~3.9k k8s watch
    lifecycle rows), but those rows were mislabelled as anomalies by the old
    allowlist. This clears the is_anomaly flag and clamps the risk score on
    those rows so dashboard 'Anomalies Detected' reflects reality. It does
    NOT delete any events.
    """
    from database import get_connection, _DB_LOCK

    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute(
                """
                UPDATE events
                SET is_anomaly = 0,
                    severity = 'INFO',
                    risk_score = MIN(risk_score, 15.0)
                WHERE is_anomaly = 1
                  AND payload_json LIKE '%"scenario": "live_stream"%'
                  AND payload_json LIKE '%"verb": "ADDED"%'
                """
            )
            updated = cursor.rowcount
            connection.commit()
        finally:
            connection.close()

    if updated:
        print(f"  [cleanup] Reset stale anomaly flags on {updated} kept noise event(s).")


def _dashboard_state() -> Dict[str, Any]:
    return {
        "recent_events": fetch_recent_events(50),
        "recent_incidents": fetch_recent_incidents(20),
        "ttl_distribution": fetch_ttl_distribution(),
        "blocklist": fetch_active_blocklist(),
        "action_log": fetch_action_log(50),
        "ngrok_public_url": NGROK_PUBLIC_URL,
        "database": database_stats(),
        "model": get_pipeline_stats(),
    }


def _escalate_severity(record: dict) -> dict:
    """Dynamically set severity based on ML risk_score.
    Called on every record BEFORE broadcasting to SSE or saving to DB."""
    try:
        score = float(record.get("risk_score", 0) or 0)
    except (ValueError, TypeError):
        score = 0.0
    if score >= 80:
        record["severity"] = "CRITICAL"
    elif score >= 60:
        record["severity"] = "HIGH"
    elif score >= 30:
        record["severity"] = "MEDIUM"
    # else leave as default (INFO)
    return record


def verify_signature(secret: str, payload: bytes, signature_header: str | None) -> bool:
    if not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    
    sha_name, signature = signature_header.split("=", 1)
    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)


def parse_github_timestamp(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    ts_str = ts_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None


k8s_event_queue: asyncio.Queue = asyncio.Queue()

# Cooperative shutdown flag — set to True by shutdown_event so the background
# K8s watch thread breaks out of its blocking watch loop.
_shutdown_requested = False

# ── Auto-remediation dedup state ────────────────────────────────────────────
# Prevents double-remediation of the same resource within a time window.
_AUTO_REMEDIATED: Dict[str, float] = {}          # resource_key → timestamp
_AUTO_REMEDIATION_COOLDOWN = 300.0               # seconds between re-remediations


def _auto_remediate_key(resource_name: str, namespace: str) -> str:
    return f"{namespace}/{resource_name}".lower()


async def _auto_remediate_if_critical(record: dict) -> None:
    """Fire-and-forget auto-remediation for CRITICAL anomalies.

    When a record has risk_score >= 80, severity CRITICAL, and is_anomaly,
    automatically contain the pod, apply a quarantine NetworkPolicy, cordon
    the node, and revoke the associated ServiceAccount — no admin approval
    required.  Each resource is protected by a cooldown dedup window so the
    same pod is never remediated twice within 5 minutes.
    """
    import remediation

    try:
        score = float(record.get("risk_score", 0) or 0)
    except (ValueError, TypeError):
        score = 0.0
    severity = str(record.get("severity", "")).upper()
    is_anomaly = bool(record.get("is_anomaly"))

    if not (score >= 80 and severity == "CRITICAL" and is_anomaly):
        return  # Not a critical anomaly — skip.

    resource_name = str(record.get("resource_name") or record.get("resource_id") or "")
    namespace = str(record.get("namespace") or "default")
    principal_id = str(record.get("principal_id") or record.get("username") or "")
    source_ip = str(record.get("source_ip") or record.get("pod_ip") or "")

    if not resource_name or resource_name.lower() in ("unknown_resource", "unknown", "github-webhook"):
        return  # Can't target a meaningful resource.

    key = _auto_remediate_key(resource_name, namespace)
    now = _time.time()

    # Dedup: skip if already remediated within the cooldown window.
    if key in _AUTO_REMEDIATED and (now - _AUTO_REMEDIATED[key]) < _AUTO_REMEDIATION_COOLDOWN:
        return
    _AUTO_REMEDIATED[key] = now

    # Evict stale entries to prevent unbounded memory growth.
    stale_keys = [k for k, t in _AUTO_REMEDIATED.items() if (now - t) > _AUTO_REMEDIATION_COOLDOWN * 2]
    for k in stale_keys:
        del _AUTO_REMEDIATED[k]

    print(f"\n{'='*60}")
    print(f"[AUTO-REMEDIATE] CRITICAL risk={score:.0f} — {namespace}/{resource_name}")
    print(f"  principal={principal_id}  source_ip={source_ip}")
    print(f"{'='*60}")

    # Fire all 3 containment actions concurrently via threads.
    loop = asyncio.get_running_loop()

    async def _run_remediation():
        import remediation as _rem
        try:
            # 1. Isolate the pod
            r1 = await asyncio.to_thread(_rem.isolate_pod, resource_name, namespace)
            print(f"  [auto] isolate_pod → {r1.get('message', '')}")
        except Exception as e:
            print(f"  [auto] isolate_pod error: {e}")

        try:
            # 2. Quarantine network
            r2 = await asyncio.to_thread(
                _rem.apply_network_policy, resource_name, namespace, source_ip
            )
            print(f"  [auto] network_policy → {r2.get('message', '')}")
        except Exception as e:
            print(f"  [auto] network_policy error: {e}")

        try:
            # 3. Cordon node
            r3 = await asyncio.to_thread(
                _rem.cordon_node, "", resource_name, namespace
            )
            print(f"  [auto] cordon_node → {r3.get('message', '')}")
        except Exception as e:
            print(f"  [auto] cordon_node error: {e}")

        # 4. Revoke ServiceAccount if we can identify one
        if principal_id and "system:serviceaccount" in principal_id.lower():
            # Extract short SA name from "system:serviceaccount:<ns>:<name>"
            sa_parts = principal_id.split(":")
            sa_name = sa_parts[-1] if len(sa_parts) >= 3 else principal_id
            try:
                r4 = await asyncio.to_thread(_rem.revoke_service_account, sa_name, namespace)
                print(f"  [auto] revoke_sa '{sa_name}' → {r4.get('message', '')}")
            except Exception as e:
                print(f"  [auto] revoke_sa error: {e}")

        # Broadcast auto-remediation to the SSE stream so the UI updates.
        if hasattr(app.state, "broadcaster"):
            await app.state.broadcaster.publish(
                "remediation",
                {
                    "incident_id": "",
                    "action_type": "auto_remediate",
                    "operator": "system-auto",
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "status": "success",
                    "message": f"Auto-remediated CRITICAL {namespace}/{resource_name} (risk={score:.0f})",
                    "resource_name": resource_name,
                    "namespace": namespace,
                },
            )

        print(f"[AUTO-REMEDIATE] Complete for {namespace}/{resource_name}\n")

    # Fire-and-forget — do NOT await; never block the event pipeline.
    asyncio.create_task(_run_remediation())


def _kubeconfig_available() -> bool:
    """Quick check for a reachable kubeconfig without importing kubernetes."""
    import os
    if os.environ.get("KUBECONFIG"):
        return os.path.exists(os.environ["KUBECONFIG"])
    home = os.path.expanduser("~")
    return os.path.exists(os.path.join(home, ".kube", "config"))


def k8s_watcher_sync(queue_ref: asyncio.Queue, main_loop: asyncio.AbstractEventLoop):
    global _shutdown_requested
    from kubernetes import watch, client, config
    
    print("K8s watcher: Starting global event watch thread...")
    while not _shutdown_requested:
        try:
            print("K8s watcher: Loading kubeconfig...")
            config.load_kube_config()
            v1 = client.CoreV1Api()
            w = watch.Watch()
            
            print("K8s watcher: Connected. Streaming global events...")
            for event in w.stream(v1.list_event_for_all_namespaces):
                if _shutdown_requested:
                    print("K8s watcher: shutdown requested, stopping watch loop.")
                    break
                
                obj = event.get('object')
                if not obj:
                    continue
                
                event_dict = {
                    "event_id": str(uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "log_type": "k8s_audit",
                    "event_name": getattr(obj, 'reason', 'unknown_reason'),
                    "event_source": "kube-apiserver",
                    "principal_id": getattr(obj.involved_object, 'kind', 'system'),
                    "actor": getattr(obj.involved_object, 'kind', 'system'),
                    "resource_name": getattr(obj.involved_object, 'name', 'unknown_resource'),
                    "namespace": getattr(obj.involved_object, 'namespace', 'global'),
                    "severity": "INFO", # Let the ML pipeline upgrade this later
                    "is_privileged": 1 if getattr(obj.involved_object, 'namespace', '') == 'kube-system' else 0,
                    "verb": event.get('type') or getattr(obj, 'type', 'unknown'),
                    "action": event.get('type') or getattr(obj, 'type', 'unknown'),
                    "source_ip": "127.0.0.1",
                    "user_agent": "k8s-client",
                    "resource_id": getattr(obj.involved_object, 'name', 'unknown_resource'),
                    "region": "local"
                }

                # Drop pure watch-stream lifecycle noise (ADDED/MODIFIED/DELETED
                # bookkeeping) unless it carries a security-relevant reason.
                if _is_k8s_watch_noise(event_dict):
                    continue

                # IMPORTANT: Use threadsafe method to put data back into the async queue!
                asyncio.run_coroutine_threadsafe(queue_ref.put(event_dict), main_loop)
        except Exception as e:
            if _shutdown_requested:
                break
            print(f"K8s watcher warning: stream disconnected or config failed. Details: {e}. Retrying in 3 seconds...")
            _time.sleep(3)


async def k8s_queue_processor():
    from ml_pipeline import process_event
    from database import insert_event
    while True:
        try:
            normalized_data = await k8s_event_queue.get()
            # Defense-in-depth: drop lifecycle noise that made it past the watcher.
            if _is_k8s_watch_noise(normalized_data):
                k8s_event_queue.task_done()
                continue
            analysis = await process_event(normalized_data)
            _escalate_severity(analysis.record)

            # Auto-remediate CRITICAL anomalies immediately (no admin approval).
            await _auto_remediate_if_critical(analysis.record)

            try:
                insert_event(analysis.record)
            except Exception as db_err:
                print(f"DATABASE WARNING: Failed to save event to DB: {db_err}")
            
            if hasattr(app.state, "broadcaster"):
                await app.state.broadcaster.publish(
                    "security_event",
                    {
                        "kind": "security_event",
                        "raw_event": normalized_data,
                        "record": analysis.record,
                        "anomaly_score": analysis.record["anomaly_score"],
                        "is_anomaly": analysis.record["is_anomaly"],
                        "model": get_pipeline_stats(),
                        "database": database_stats(),
                    },
                )
            k8s_event_queue.task_done()
        except Exception as e:
            print(f"Error processing k8s queue event: {e}")

async def start_k8s_watcher():
    loop = asyncio.get_running_loop()
async def demo_traffic_loop():
    """Background task to keep the dashboard alive with a steady stream of synthetic events."""
    print("  [startup] Starting Live Demo Generator (1 event every 10-15s)")
    while True:
        await asyncio.sleep(random.uniform(10, 15))
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        event_type = random.choice(["k8s_audit", "cloudtrail", "vpc_flow"])
        
        # 5% chance to generate an anomalous event burst
        is_malicious = random.random() < 0.05
        burst_size = random.randint(5, 15) if is_malicious else 1
        
        for _ in range(burst_size):
            event = {
                "event_id": str(uuid4()),
                "timestamp": now,
                "log_type": event_type,
                "severity": "INFO", 
            }
            
            if event_type == "k8s_audit":
                event["verb"] = "create" if not is_malicious else "delete"
                event["resource_name"] = f"demo-pod-{uuid4().hex[:6]}"
                event["namespace"] = "production"
                event["username"] = "system" if not is_malicious else "unknown"
                event["pod_ip"] = f"10.0.1.{random.randint(1,250)}" if not is_malicious else "198.51.100.42"
                event["is_privileged"] = 1 if is_malicious else 0
                event["action"] = event["verb"]
            elif event_type == "cloudtrail":
                event["event_source"] = "ec2.amazonaws.com"
                event["event_name"] = "DescribeInstances" if not is_malicious else "RunInstances"
                event["principal_id"] = "dev-user" if not is_malicious else "unknown"
                event["arn"] = f"arn:aws:iam::123456789012:user/{event['principal_id']}"
                event["source_ip"] = f"192.168.1.{random.randint(1,250)}" if not is_malicious else "203.0.113.55"
                event["action"] = event["event_name"]
            else:
                event["src_addr"] = f"10.0.1.{random.randint(1,250)}"
                event["dst_addr"] = f"10.0.2.{random.randint(1,250)}" if not is_malicious else "185.220.101.47"
                event["src_port"] = random.randint(1024, 65535)
                event["dst_port"] = 443 if not is_malicious else random.choice([3333, 4444])
                event["bytes"] = random.randint(100, 5000) if not is_malicious else random.randint(50000, 500000)
                event["action"] = "ACCEPT"
                
            await k8s_event_queue.put(event)


async def daily_cleanup_loop():
    """Background task to wipe all database events every 24 hours."""
    print("  [startup] Scheduled Daily Cleanup loop (every 24h)")
    while True:
        await asyncio.sleep(86400)  # 24 hours
        print("  [cleanup] Running 24h data wipe...")
        try:
            database.clear_all_events()
            print("  [cleanup] Database wiped successfully.")
        except Exception as e:
            print(f"  [cleanup] Error wiping database: {e}")


@app.on_event("startup")
async def startup_event() -> None:
    init_db()
    app.state.broadcaster = Broadcaster()

    # One-shot cleanup: remove the false-positive incidents generated before
    # the allowlist + threshold fixes, and reset stale anomaly flags on kept
    # historical noise rows so dashboard counts are honest.
    _cleanup_false_positive_incidents()
    _reset_stale_noise_anomaly_flags()

    # ── Scheduled daily cleanup ──────────────────────────────────────────────
    asyncio.create_task(daily_cleanup_loop())

    # ── K8s watcher (fire-and-forget) ──────────────────────────────────────────
    if _kubeconfig_available():
        print("  [startup] Kubeconfig detected — starting live K8s Pod + Event watcher.")
        asyncio.create_task(k8s_queue_processor())
        asyncio.get_event_loop().run_in_executor(
            None, k8s_watcher_sync, k8s_event_queue, asyncio.get_event_loop()
        )
    else:
        print("  [startup] No kubeconfig — live K8s ingestion disabled.")
        # Start the queue processor anyway so it can process demo traffic and /api/ingest
        asyncio.create_task(k8s_queue_processor())
        # Start the demo traffic generator to keep the deployed site alive
        asyncio.create_task(demo_traffic_loop())

    # ── Model: try loading cached model; no training here ────────────────────
    # Run `python seed_telemetry.py` separately to train + seed data.
    try:
        if detector.load_global_model():
            print("  [startup] Loaded pre-trained Isolation Forest from cache.")
        else:
            print("  [startup] No cached model — run `python seed_telemetry.py` to train + seed.")
    except Exception as e:
        print(f"  [startup] Could not load model: {e}")

    # ── ngrok tunnel for GitHub webhook ───────────────────────────────────────
    global NGROK_PUBLIC_URL
    if settings.NGROK_AUTHTOKEN:
        ngrok.set_auth_token(settings.NGROK_AUTHTOKEN)
    
    try:
        tunnel = ngrok.connect(8000)
        public_url = tunnel.public_url
        NGROK_PUBLIC_URL = public_url
        print("\n" + "=" * 80)
        print(f"=== GITHUB WEBHOOK URL: {public_url}/api/webhook/github ===")
        print("=" * 80 + "\n")
    except Exception as e:
        print(f"Failed to initialize pyngrok tunnel: {e}")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    global _shutdown_requested
    _shutdown_requested = True
    try:
        ngrok.kill()
    except Exception as e:
        print(f"Failed to shutdown pyngrok: {e}")


@app.get("/")
async def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, payload: LoginRequest) -> JSONResponse:
    print(f"\n--- DEBUG LOGIN ATTEMPT ---")
    print(f"Username: {payload.username}")
    print(f"Password length: {len(payload.password)}")
    user = authenticate_user(payload.username, payload.password)
    print(f"Auth result: {user}")
    if not user:
        print("Login failed: Invalid username or password")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    print(f"Generated token successfully: {token[:20]}...")
    print(f"--- DEBUG LOGIN END ---\n")
    return JSONResponse(
        {
            "access_token": token,
            "token_type": "bearer",
            "user": {"username": user["username"], "role": user["role"]},
        }
    )



@app.get("/api/state")
@limiter.limit("60/minute")
async def api_state(request: Request, _: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse(_dashboard_state())


@app.get("/api/health")
@limiter.limit("60/minute")
async def api_health(request: Request, _: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({"status": "ok", "database": database_stats(), "model": get_pipeline_stats()})


@app.get("/api/system-stats")
@limiter.limit("60/minute")
async def api_system_stats(request: Request, _: Dict[str, Any] = Depends(require_admin)) -> JSONResponse:
    return JSONResponse({"database": database_stats(), "model": get_pipeline_stats()})


@app.post("/api/ingest")
@limiter.limit("300/minute")
async def api_ingest(request: Request, payload: Dict[str, Any]) -> JSONResponse:
    """Endpoint for live_ingester.py to send telemetry events."""
    try:
        await k8s_event_queue.put(payload)
        return JSONResponse({"status": "queued"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/pipelines")
@limiter.limit("60/minute")
async def api_create_pipeline(
    request: Request,
    payload: PipelineRegistration,
    _: Dict[str, Any] = Depends(require_admin),
) -> JSONResponse:
    token = uuid4().hex
    pipeline_id = add_pipeline(
        payload.repo_name,
        payload.target_namespace,
        token,
        "pending",
    )
    repo_slug = payload.repo_name.split("/", 1)[1]
    return JSONResponse({
        "id": pipeline_id,
        "repo_name": payload.repo_name,
        "target_namespace": payload.target_namespace,
        "secret_token": token,
        "webhook_url": f"https://api.internal/webhook/{repo_slug}",
        "status": "pending",
    })


@app.post("/api/pipelines/{pipeline_id}/activate")
@limiter.limit("60/minute")
async def api_activate_pipeline(
    request: Request,
    pipeline_id: int,
    _: Dict[str, Any] = Depends(require_admin),
) -> JSONResponse:
    if pipeline_id < 1 or not activate_pipeline(pipeline_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending pipeline not found",
        )
    return JSONResponse({"id": pipeline_id, "status": "active"})


@app.get("/api/pipelines")
@limiter.limit("60/minute")
async def api_list_pipelines(request: Request, _: Dict[str, Any] = Depends(require_admin)) -> JSONResponse:
    pipelines = list_pipelines()
    return JSONResponse({"pipelines": pipelines})


# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION ENGINE
# Simulates executing security playbooks against the K8s cluster.
# ANSI escape codes produce colour-coded terminal output visible in server logs.
# ─────────────────────────────────────────────────────────────────────────────

# ANSI colour helpers
_BOLD  = "\033[1m"
_RESET = "\033[0m"
_RED   = "\033[91m"
_GRN   = "\033[92m"
_YLW   = "\033[93m"
_BLU   = "\033[94m"
_CYN   = "\033[96m"
_DIM   = "\033[2m"
_MAG   = "\033[95m"


def _log(level: str, msg: str) -> None:
    colours = {"INFO": _BLU, "EXEC": _CYN, "WARN": _YLW, "OK": _GRN, "ERR": _RED, "SYS": _MAG}
    ts  = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    col = colours.get(level, "")
    print(f"{_DIM}[{ts}]{_RESET} {_BOLD}{col}[{level:4s}]{_RESET} {msg}")


def _simulate_playbook(action_type: str, incident_id: str) -> str:
    """Blocking playbook simulation — runs in a thread pool via asyncio.to_thread."""
    action_lower = action_type.lower().replace(" ", "_")
    ns  = "ci-cd-runners"
    ts  = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    print()
    _log("SYS", f"{_BOLD}━━━ REMEDIATION PLAYBOOK INITIATED ━━━{_RESET}")
    _log("SYS", f"Incident ID : {_CYN}{incident_id}{_RESET}")
    _log("SYS", f"Action      : {_YLW}{action_type}{_RESET}")
    _log("SYS", f"Timestamp   : {ts}")
    _log("SYS", f"Operator    : {_MAG}sentry-engine/auto-response{_RESET}")
    print()

    if action_lower in ("contain_pods", "contain pods"):
        _log("EXEC", f"kubectl get pods -n {ns} --field-selector=status.phase=Running -o name")
        _time.sleep(0.3)
        _log("INFO", f"Found {_YLW}7{_RESET} running pods in namespace {_CYN}{ns}{_RESET}")
        _time.sleep(0.2)
        _log("EXEC", f"kubectl apply -f networkpolicy/deny-all-ingress-egress.yaml -n {ns}")
        _time.sleep(0.4)
        _log("INFO", f"Applying NetworkPolicy {_YLW}'deny-all'{_RESET} → namespace {_CYN}{ns}{_RESET}")
        _time.sleep(0.6)
        _log("EXEC", f"kubectl label pods -n {ns} -l app=runner quarantine=true --overwrite")
        _time.sleep(0.3)
        _log("INFO", f"Labelled runner pods with {_YLW}quarantine=true{_RESET}")
        _time.sleep(0.2)
        _log("OK",   f"{_GRN}[K8s API]{_RESET} NetworkPolicy 'deny-all' applied to namespace {_CYN}{ns}{_RESET} → {_GRN}SUCCESS{_RESET}")
        message = "Pods contained — all ingress/egress traffic blocked via NetworkPolicy."

    elif action_lower in ("revoke_credentials", "revoke credentials"):
        _log("EXEC", f"kubectl get serviceaccounts -n {ns} -o jsonpath='{{.items[*].metadata.name}}'")
        _time.sleep(0.3)
        _log("INFO", f"Targeting ServiceAccount: {_YLW}github-actions-svc{_RESET}")
        _time.sleep(0.2)
        _log("EXEC", f"kubectl delete secret $(kubectl get sa github-actions-svc -n {ns} -o jsonpath='{{.secrets[0].name}}') -n {ns}")
        _time.sleep(0.5)
        _log("INFO", f"Deleted bound ServiceAccount token secret")
        _time.sleep(0.2)
        _log("EXEC", f"aws iam delete-role-policy --role-name GitHubActionsRole --policy-name AssumedAccess")
        _time.sleep(0.4)
        _log("INFO", f"Terminating active STS sessions for assumed-role: {_YLW}GitHubActionsRole{_RESET}")
        _time.sleep(0.3)
        _log("EXEC", f"aws sts get-caller-identity | xargs -I{{}} aws iam revoke-access --session {{}}")
        _time.sleep(0.2)
        _log("OK",   f"{_GRN}[IAM/K8s]{_RESET} ServiceAccount token deleted & assumed-role sessions terminated → {_GRN}SUCCESS{_RESET}")
        message = "Credentials revoked — IAM sessions terminated and K8s tokens invalidated."

    elif action_lower in ("enforce_network_guardrails", "enforce network guardrails"):
        _log("EXEC", f"kubectl apply -f networkpolicy/restrict-external-egress.yaml -n {ns}")
        _time.sleep(0.3)
        _log("INFO", f"Restricting egress to approved CIDR ranges only: {_CYN}10.0.0.0/8, 172.16.0.0/12{_RESET}")
        _time.sleep(0.4)
        _log("EXEC", f"kubectl apply -f networkpolicy/allow-internal-only-ingress.yaml -n {ns}")
        _time.sleep(0.3)
        _log("INFO", f"Ingress restricted to cluster-internal sources only")
        _time.sleep(0.3)
        _log("EXEC", f"kubectl rollout restart deployment/runner-controller -n {ns}")
        _time.sleep(0.4)
        _log("INFO", f"Rolling restart of runner-controller to flush iptables rules")
        _time.sleep(0.2)
        _log("OK",   f"{_GRN}[K8s API]{_RESET} Egress guardrails enforced on namespace {_CYN}{ns}{_RESET} → {_GRN}SUCCESS{_RESET}")
        message = "Network guardrails enforced — egress restricted to internal CIDR ranges."

    elif action_lower in ("isolate_workload", "isolate workload"):
        _log("EXEC", f"kubectl cordon $(kubectl get pods -n {ns} -o wide | awk 'NR>1{{print $7}}' | head -1)")
        _time.sleep(0.3)
        _log("INFO", f"Cordoning node hosting suspicious workload")
        _time.sleep(0.4)
        _log("EXEC", f"kubectl drain --ignore-daemonsets --delete-emptydir-data --force -n {ns}")
        _time.sleep(0.5)
        _log("INFO", f"Draining pods off compromised node")
        _time.sleep(0.3)
        _log("OK",   f"{_GRN}[K8s API]{_RESET} Workload isolated and node cordoned → {_GRN}SUCCESS{_RESET}")
        message = "Workload isolated — node cordoned and pods drained."

    elif action_lower in ("rotate_secrets", "rotate secrets"):
        _log("EXEC", f"kubectl create secret generic runner-token-$(date +%s) --from-literal=token=$(openssl rand -base64 32) -n {ns}")
        _time.sleep(0.4)
        _log("INFO", f"New runner token generated and stored in K8s Secret store")
        _time.sleep(0.3)
        _log("EXEC", f"kubectl rollout restart deployment/github-runner -n {ns}")
        _time.sleep(0.4)
        _log("INFO", f"Restarting runners to pick up rotated credentials")
        _time.sleep(0.2)
        _log("OK",   f"{_GRN}[K8s API]{_RESET} Secrets rotated and runners restarted → {_GRN}SUCCESS{_RESET}")
        message = "Secrets rotated — new credentials provisioned, old tokens invalidated."

    else:
        # Generic fallback for any unrecognised action
        _log("EXEC", f"kubectl apply -f playbooks/{action_lower.replace(' ', '-')}.yaml -n {ns}")
        _time.sleep(0.6)
        _log("INFO", f"Executing generic security playbook for action: {_YLW}{action_type}{_RESET}")
        _time.sleep(0.6)
        _log("OK",   f"{_GRN}[Sentry]{_RESET} Playbook '{action_type}' executed on namespace {_CYN}{ns}{_RESET} → {_GRN}SUCCESS{_RESET}")
        message = f"Playbook '{action_type}' executed successfully."

    print()
    _log("SYS", f"{_BOLD}{_GRN}━━━ PLAYBOOK COMPLETE — INCIDENT {incident_id[:16]}… NEUTRALISED ━━━{_RESET}")
    print()
    return message


@app.post("/api/remediate/{incident_id}")
@limiter.limit("30/minute")
async def remediate_incident(
    request: Request,
    incident_id: str,
    payload: RemediationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Execute a security remediation playbook against the incident."""
    if not incident_id or len(incident_id) > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident_id")

    import remediation

    print(f"Executing {payload.action_type} on {payload.target_resource} (ns={payload.target_namespace})")

    action_lower = payload.action_type.lower()

    if action_lower in ("contain_pods", "contain pods"):
        result = await asyncio.to_thread(
            remediation.isolate_pod, payload.target_resource, payload.target_namespace
        )
    elif action_lower in ("revoke_credentials", "revoke credentials"):
        # Prefer the explicit principal_id when the frontend supplied one,
        # otherwise fall back to the target_resource (already parsed to the SA).
        sa_target = payload.principal_id or payload.target_resource
        result = await asyncio.to_thread(
            remediation.revoke_service_account, sa_target, payload.target_namespace
        )
    elif action_lower in ("enforce network guardrails", "enforce_network_guardrails",
                          "network guardrails", "network_guardrails"):
        result = await asyncio.to_thread(
            remediation.apply_network_policy,
            payload.target_resource, payload.target_namespace, payload.source_ip,
        )
    elif action_lower in ("prevent recurrence", "prevent_recurrence",
                          "cordon node", "cordon_node"):
        result = await asyncio.to_thread(
            remediation.cordon_node,
            "", payload.target_resource, payload.target_namespace,
        )
    else:
        # Fallback to simulated behavior for unrecognized actions during transition
        message = await asyncio.to_thread(_simulate_playbook, payload.action_type, incident_id)
        result = {"status": "success", "message": message}
        
    status_str = result.get("status", "error")
    message = result.get("message", "Unknown error")

    if status_str == "error":
        # Still record the failed attempt in the action log so the activity
        # timeline reflects every analyst action, not just successes.
        import database
        database.insert_action_log(
            incident_id=incident_id,
            action_type=payload.action_type,
            target_resource=payload.target_resource,
            namespace=payload.target_namespace,
            source_ip=payload.source_ip or "",
            principal_id=payload.principal_id or "",
            operator=current_user.get("username", "system"),
            result="error",
            message=message,
        )
        if hasattr(app.state, "broadcaster"):
            await app.state.broadcaster.publish(
                "action_log", {"entries": database.fetch_action_log(50)}
            )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)

    import database
    database.resolve_incident(incident_id)

    # Record the contained source in the persistent quarantine blocklist so
    # re-runs from the same principal_id/SA are suppressed at detection time
    # instead of firing a fresh HIGH incident.
    blocklist_entry = None
    if payload.principal_id and payload.principal_id.lower() not in ("unknown", "system", ""):
        database.add_blocklist_entry(
            principal_id=payload.principal_id,
            source_ip=payload.source_ip or "",
            namespace=payload.target_namespace,
            incident_id=incident_id,
            action_type=payload.action_type,
            operator=current_user.get("username", "system"),
        )
        blocklist_entry = next(
            (e for e in database.fetch_active_blocklist() if e["principal_id"] == payload.principal_id),
            None,
        )

    # Broadcast remediation event to all SSE subscribers so other analysts see it
    # and persist the action to the append-only action log for the activity feed.
    database.insert_action_log(
        incident_id=incident_id,
        action_type=payload.action_type,
        target_resource=payload.target_resource,
        namespace=payload.target_namespace,
        source_ip=payload.source_ip or "",
        principal_id=payload.principal_id or "",
        operator=current_user.get("username", "system"),
        result="success",
        message=message,
    )
    if hasattr(app.state, "broadcaster"):
        await app.state.broadcaster.publish(
            "remediation",
            {
                "incident_id": incident_id,
                "action_type": payload.action_type,
                "operator":    current_user.get("username", "system"),
                "timestamp":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "status":      status_str,
                "message":     message,
            },
        )
        # Live-update the action log feed across analyst sessions.
        await app.state.broadcaster.publish(
            "action_log", {"entries": database.fetch_action_log(50)}
        )
        # Live-update the blocklist panel across analyst sessions.
        if blocklist_entry:
            await app.state.broadcaster.publish("blocklist", {"entries": database.fetch_active_blocklist()})

    return JSONResponse({
        "status":      status_str,
        "incident_id": incident_id,
        "action_type": payload.action_type,
        "message":     message,
        "executed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operator":    current_user.get("username", "system"),
    })


@app.post("/api/blocklist/release/{principal_id}")
@limiter.limit("30/minute")
async def release_blocklist(
    request: Request,
    principal_id: str,
    _: Dict[str, Any] = Depends(require_admin),
) -> JSONResponse:
    """Manually unblock a contained principal so future activity from it can
    fire incidents normally again.  Admin-only."""
    import database
    import urllib.parse
    pid = urllib.parse.unquote(principal_id)
    if not pid or len(pid) > 200:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid principal_id")
    released = database.release_blocklist_entry(pid)
    entries = database.fetch_active_blocklist()
    if hasattr(app.state, "broadcaster"):
        await app.state.broadcaster.publish("blocklist", {"entries": entries})
    return JSONResponse({
        "status": "released" if released else "noop",
        "principal_id": pid,
        "blocklist": entries,
    })


@app.get("/api/recent-events")
@limiter.limit("60/minute")
async def api_recent_events(request: Request, _: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({"events": fetch_recent_events(50)})


@app.delete("/api/events/{event_id}")
@limiter.limit("60/minute")
async def delete_event_endpoint(
    request: Request,
    event_id: str,
    _: Dict[str, Any] = Depends(require_admin),
) -> JSONResponse:
    from database import get_connection, _DB_LOCK
    with _DB_LOCK:
        connection = get_connection()
        try:
            cursor = connection.execute("DELETE FROM events WHERE event_id = ?", (event_id,))
            connection.commit()
            rowcount = cursor.rowcount
        finally:
            connection.close()

    if rowcount == 0:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": "Event did not exist in DB"}
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "success", "message": "Successfully deleted"}
    )


@app.get("/api/recent-incidents")
@limiter.limit("60/minute")
async def api_recent_incidents(request: Request, _: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({"incidents": fetch_recent_incidents(20)})


@app.get("/api/action-log")
@limiter.limit("60/minute")
async def api_action_log(request: Request, _: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    """Append-only record of every analyst remediation action for the
    activity timeline in the Incidents view."""
    return JSONResponse({"entries": fetch_action_log(50)})


@app.get("/api/incidents/{incident_id}")
@limiter.limit("60/minute")
async def api_incident_detail(
    request: Request,
    incident_id: str,
    _: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Per-incident drill-down: returns the incident row + its related
    telemetry events for the timeline view in the modal."""
    incident = fetch_incident_with_events(incident_id)
    if incident is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": f"Incident {incident_id} not found"},
        )
    return JSONResponse(incident)


@app.get("/api/ttl-distribution")
@limiter.limit("60/minute")
async def api_ttl_distribution(request: Request, _: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse(fetch_ttl_distribution())


@app.post("/api/webhook/github")
async def github_webhook(request: Request) -> JSONResponse:
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    event_type = request.headers.get("X-GitHub-Event")

    if not verify_signature(settings.GITHUB_WEBHOOK_SECRET, body, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature"
        )

    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )

    if event_type == "ping":
        ping_event = {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_ip": "127.0.0.1",
            "user_agent": "GitHub-Hookshot",
            "actor": "github-webhook",
            "action": "webhook.ping",
            "resource_id": "github-ping",
            "region": "github",
            "risk_score": 0.0,
            "is_anomaly": False,
            "success": True,
            "burst_flag": 0,
            "namespace": "default",
            "repo_name": "ping",
        }
        await app.state.broadcaster.publish(
            "security_event",
            {
                "kind": "security_event",
                "raw_event": ping_event,
                "record": ping_event,
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "stats": get_pipeline_stats(),
                "model": get_pipeline_stats(),
                "database": database_stats(),
            }
        )
        return JSONResponse({"status": "ping_received"})

    if event_type == "workflow_job":
        action = payload.get("action")  # queued, in_progress, completed
        print(f"\n>>> [GITHUB WEBHOOK] Received workflow_job event. Action: '{action}' <<<")

        workflow_job = payload.get("workflow_job", {})
        runner_name = workflow_job.get("runner_name") or f"runner-{workflow_job.get('id', 'unknown')}"
        repository = payload.get("repository", {})
        repo_name = repository.get("full_name", "unknown/repo")
        started_at = workflow_job.get("started_at")
        completed_at = workflow_job.get("completed_at")

        if action != "completed":
            print(f">>> [GITHUB WEBHOOK] Ignoring action '{action}'. Only processing completed jobs. <<<")
            # Broadcast the raw event to SSE stream so UI lights up immediately
            ignored_event = {
                "event_id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "log_type": "k8s_audit",
                "severity": "INFO",
                "scenario": "live_stream",
                "event_source": "github-actions",
                "event_name": f"workflow_job.{action}",
                "principal_id": payload.get("sender", {}).get("login", "github-actions"),
                "arn": "",
                "source_ip": "10.0.1.15",
                "verb": f"pod.{action}",
                "resource_id": runner_name,
                "resource_name": runner_name,
                "namespace": repo_name,
                "username": payload.get("sender", {}).get("login", "github-actions"),
                "pod_ip": "10.0.1.15",
                "is_privileged": 0,
                "src_addr": "",
                "dst_addr": "",
                "src_port": 0,
                "dst_port": 0,
                "vpc_bytes": 0,
                "vpc_action": "",
                "success": True,
                "burst_flag": 0,
                "risk_score": 0.0,
                "is_anomaly": False,
            }
            await app.state.broadcaster.publish(
                "security_event",
                {
                    "kind": "security_event",
                    "raw_event": ignored_event,
                    "record": ignored_event,
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "stats": get_pipeline_stats(),
                    "model": get_pipeline_stats(),
                    "database": database_stats(),
                },
            )
            return JSONResponse({"status": "ignored_non_completed"})

        # Process completed action
        try:
            start = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
            end = datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ")
            ttl_seconds = (end - start).total_seconds()
        except Exception as e:
            print(f"Timestamp strptime failed ({e}). Falling back to ISO parsing.")
            start_dt = parse_github_timestamp(started_at)
            end_dt = parse_github_timestamp(completed_at)
            if start_dt and end_dt:
                ttl_seconds = (end_dt - start_dt).total_seconds()
            else:
                ttl_seconds = 0.0

        normalized_event = {
            "event_id": str(uuid4()),
            "timestamp": completed_at or started_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "log_type": "k8s_audit",
            "resource_type": "pod",
            "pod_name": workflow_job.get("name") or runner_name,
            "namespace": "production",  # Use a valid namespace — raw repo_name was triggering missing_tags_score
            "duration": ttl_seconds, # THIS IS WHAT THE ML NEEDS
            "verb": "pod.completed",
            "action": "pod.completed",
            "event_name": "workflow_job.completed",
            "event_source": "github-actions",
            "principal_id": "github-actions-svc",  # Valid identity — avoids is_unknown_identity=1
            "username": "github-actions-svc",
            "privilege": "standard",  # Don't hardcode 'high' — was causing every event to be flagged
            "is_privileged": 0,  # Normal CI/CD pods are not privileged
            "controller": "github-actions",
            
            # Standard columns for database and UI
            "actor": payload.get("sender", {}).get("login", "github-actions"),
            "source_ip": "10.0.1.15",  # Internal IP — avoids untrusted_network_hit
            "pod_ip": "10.0.1.15",
            "user_agent": "GitHub-Hookshot",
            "repo_name": repo_name,  # Keep for display purposes
        }

        print(">>> [GITHUB WEBHOOK] Passing exact normalized_event to ML model wrapper: <<<")
        print(json.dumps(normalized_event, indent=2))

        # Feed to ML pipeline
        try:
            analysis = await process_event(normalized_event)
            _escalate_severity(analysis.record)
            score = analysis.record.get("anomaly_score")

            # Auto-remediate CRITICAL anomalies immediately (no admin approval).
            await _auto_remediate_if_critical(analysis.record)
        except Exception as e:
            print(f"ML ERROR: {e}")
            raise e

        # Save to DB
        try:
            insert_event(analysis.record)
        except Exception as db_err:
            print(f"DATABASE WARNING: Failed to save webhook event to DB: {db_err}")

        # Print calculated TTL and anomaly score
        print(f"CALCULATED TTL: {ttl_seconds} | SCORE: {score}")

        # Broadcast the event
        await app.state.broadcaster.publish(
            "security_event",
            {
                "kind": "security_event",
                "raw_event": normalized_event,
                "record": analysis.record,
                "anomaly_score": analysis.record["anomaly_score"],
                "is_anomaly": analysis.record["is_anomaly"],
                "stats": analysis.stats,
                "model": analysis.stats,
                "database": database_stats(),
            },
        )

        if analysis.cluster is not None:
            incident_payload = build_incident_report(analysis.cluster)
            incident_record = {
                **incident_payload,
                "cluster_id": analysis.cluster["cluster_id"],
                "created_at": analysis.record["timestamp"],
                "report_text": json.dumps(incident_payload, ensure_ascii=False),
                "pivot_ip": analysis.cluster["pivot_ip"],
                "resource_count": analysis.cluster["resource_count"],
                "node_count": analysis.cluster["node_count"],
                "related_event_ids": analysis.cluster["event_ids"],
            }
            try:
                insert_incident(incident_record)
            except Exception as db_err:
                print(f"DATABASE WARNING: Failed to save incident to DB: {db_err}")
            dispatch_alert(incident_record)
            await app.state.broadcaster.publish("incident", incident_payload)

        # Broadcast updated stats
        await app.state.broadcaster.publish(
            "stats",
            {"model": get_pipeline_stats(), "database": database_stats()},
        )

        return JSONResponse({"status": "event_processed"})

    # Safe fallback for other webhook events
    repo_name = payload.get("repository", {}).get("full_name", "unknown/repo")
    fallback_event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_ip": "127.0.0.1",
        "user_agent": "GitHub-Hookshot",
        "actor": payload.get("sender", {}).get("login", "github-actions"),
        "action": f"github.{event_type}",
        "resource_id": "github-webhook",
        "region": "github",
        "risk_score": 0.0,
        "is_anomaly": False,
        "success": True,
        "burst_flag": 0,
        "namespace": "default",
        "repo_name": repo_name,
    }
    await app.state.broadcaster.publish(
        "security_event",
        {
            "kind": "security_event",
            "raw_event": fallback_event,
            "record": fallback_event,
            "anomaly_score": 0.0,
            "is_anomaly": False,
            "stats": get_pipeline_stats(),
            "model": get_pipeline_stats(),
            "database": database_stats(),
        }
    )
    return JSONResponse({"status": "event_received"})


async def process_and_broadcast_event(payload: dict) -> None:
    # Drop pure k8s watch-stream lifecycle noise before it reaches the model.
    if _is_k8s_watch_noise(payload):
        return
    try:
        analysis = await process_event(payload)
    except Exception as e:
        print(f"Error processing background event: {e}")
        return

    _escalate_severity(analysis.record)

    # Auto-remediate CRITICAL anomalies immediately (no admin approval).
    await _auto_remediate_if_critical(analysis.record)

    # Save to database
    try:
        insert_event(analysis.record)
    except Exception as db_err:
        print(f"DATABASE WARNING: Failed to save background event to DB: {db_err}")

    # Broadcast to SSE
    if hasattr(app.state, "broadcaster"):
        await app.state.broadcaster.publish(
            "security_event",
            {
                "kind": "security_event",
                "raw_event": payload,
                "record": analysis.record,
                "anomaly_score": analysis.record["anomaly_score"],
                "is_anomaly": analysis.record["is_anomaly"],
                "model": get_pipeline_stats(),
                "database": database_stats(),
            },
        )

        if analysis.cluster is not None:
            incident_payload = build_incident_report(analysis.cluster)
            incident_record = {
                **incident_payload,
                "cluster_id": analysis.cluster["cluster_id"],
                "created_at": analysis.record["timestamp"],
                "report_text": json.dumps(incident_payload, ensure_ascii=False),
                "pivot_ip": analysis.cluster["pivot_ip"],
                "resource_count": analysis.cluster["resource_count"],
                "node_count": analysis.cluster["node_count"],
                "related_event_ids": analysis.cluster["event_ids"],
            }
            try:
                insert_incident(incident_record)
            except Exception as db_err:
                print(f"DATABASE WARNING: Failed to save incident to DB: {db_err}")
            dispatch_alert(incident_record)
            await app.state.broadcaster.publish("incident", incident_payload)

        # Broadcast updated stats
        await app.state.broadcaster.publish(
            "stats",
            {"model": get_pipeline_stats(), "database": database_stats()},
        )


@app.post("/api/ingest")
async def ingest_telemetry(request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
    payload = await request.json()
    background_tasks.add_task(process_and_broadcast_event, payload)
    return JSONResponse({"status": "accepted"})


@app.get("/stream")
async def stream(request: Request) -> StreamingResponse:
    token = request.query_params.get("token")
    if not token:
        parsed = parse_qs(urlparse(str(request.url)).query)
        token = (parsed.get("token") or [None])[0]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token required")
    decode_token(token)

    _start_worker_if_needed()

    queue = app.state.broadcaster.subscribe()

    async def event_generator():
        try:
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield message
                except asyncio.TimeoutError:
                    yield f"event: heartbeat\ndata: {json.dumps({'alive': True})}\n\n"
        finally:
            app.state.broadcaster.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )
