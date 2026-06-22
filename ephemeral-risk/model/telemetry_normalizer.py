"""
telemetry_normalizer.py
=======================
Canonical adapters for production and demo telemetry.

The ML feature code expects one normalized event shape. These helpers accept
raw-ish CloudTrail, Kubernetes audit, VPC flow, CI/CD job, autoscale, spot
instance, and local demo events and return that shape without hiding the native
log type.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


AWS_ACCOUNT_ID = "123456789012"
DEFAULT_REGION = "local"


CANONICAL_DEFAULTS: dict[str, Any] = {
    "event_id": "",
    "timestamp": "",
    "log_type": "k8s_audit",
    "severity": "INFO",
    "scenario": "live_stream",
    "event_source": "",
    "event_name": "",
    "principal_id": "",
    "arn": "",
    "source_ip": "",
    "verb": "",
    "resource_name": "",
    "namespace": "",
    "username": "",
    "pod_ip": "",
    "is_privileged": 0,
    "src_addr": "",
    "dst_addr": "",
    "src_port": 0,
    "dst_port": 0,
    "vpc_bytes": 0,
    "vpc_action": "",
    "tags_json": "",
    "request_parameters_json": "",
    "user_agent": "",
    "labels_json": "",
    "controller_owner": "",
    "service_type": "",
    "rbac_change": "",
    "session_type": "",
    "session_name": "",
    "issuer": "",
    "token_ttl_seconds": 0,
    "region": DEFAULT_REGION,
    "resource_id": "",
    "actor": "",
    "action": "",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return json.dumps(str(value))


def _stable_id(*parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _first(value: Any, fallback: str = "") -> str:
    if isinstance(value, list):
        return str(value[0]) if value else fallback
    if value is None:
        return fallback
    return str(value)


def _identity_from_cloudtrail_user(user_identity: dict[str, Any]) -> tuple[str, str, str, str, str]:
    if not isinstance(user_identity, dict):
        return "unknown", "", "", "", ""

    arn = str(user_identity.get("arn") or "")
    principal = str(
        user_identity.get("principalId")
        or user_identity.get("userName")
        or user_identity.get("accountId")
        or "unknown"
    )
    session_type = str(user_identity.get("type") or "")
    session_name = ""
    issuer = ""

    session_context = user_identity.get("sessionContext") or {}
    if isinstance(session_context, dict):
        issuer_obj = session_context.get("sessionIssuer") or {}
        if isinstance(issuer_obj, dict):
            issuer = str(issuer_obj.get("userName") or issuer_obj.get("arn") or "")
        attrs = session_context.get("attributes") or {}
        if isinstance(attrs, dict):
            session_name = str(attrs.get("creationDate") or "")

    if ":assumed-role/" in arn and "/" in arn.rsplit(":assumed-role/", 1)[-1]:
        session_name = arn.rsplit("/", 1)[-1]

    return principal, arn, session_type, session_name, issuer


def _cloudtrail_severity(event_name: str, source_ip: str) -> str:
    high = {
        "AssumeRole",
        "AssumeRoleWithWebIdentity",
        "CreateAccessKey",
        "RunInstances",
        "RequestSpotInstances",
        "CreateService",
        "CreateRoleBinding",
        "PutBucketPolicy",
    }
    critical = {
        "AttachRolePolicy",
        "PutRolePolicy",
        "DetachRolePolicy",
        "DeleteTrail",
        "StopLogging",
    }
    if event_name in critical:
        return "CRITICAL"
    if event_name in high or source_ip.startswith(("198.51.100.", "203.0.113.")):
        return "HIGH"
    return "INFO"


def normalize_cloudtrail_event(raw: dict[str, Any]) -> dict[str, Any]:
    user_identity = raw.get("userIdentity") or {}
    principal, arn, session_type, session_name, issuer = _identity_from_cloudtrail_user(user_identity)
    event_name = str(raw.get("eventName") or raw.get("event_name") or "UnknownEvent")
    event_source = str(raw.get("eventSource") or raw.get("event_source") or "unknown.amazonaws.com")
    event_time = str(raw.get("eventTime") or raw.get("timestamp") or _now())
    source_ip = str(raw.get("sourceIPAddress") or raw.get("source_ip") or "0.0.0.0")
    request = raw.get("requestParameters") or raw.get("request_parameters") or {}
    tags = raw.get("tags") or raw.get("tagSet") or raw.get("requestTags") or {}

    event_id = str(
        raw.get("eventID")
        or raw.get("event_id")
        or _stable_id(event_name, event_source, source_ip, event_time, principal)
    )
    resource = (
        raw.get("resource_id")
        or raw.get("resources")
        or raw.get("recipientAccountId")
        or event_name
    )

    normalized = {
        **CANONICAL_DEFAULTS,
        "event_id": event_id,
        "timestamp": event_time,
        "log_type": "cloudtrail",
        "severity": str(raw.get("severity") or _cloudtrail_severity(event_name, source_ip)),
        "scenario": str(raw.get("scenario") or "live_cloudtrail"),
        "event_source": event_source,
        "event_name": event_name,
        "principal_id": principal,
        "arn": arn or str(raw.get("arn") or f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{principal}"),
        "source_ip": source_ip,
        "tags_json": _json(tags),
        "request_parameters_json": _json(request),
        "user_agent": str(raw.get("userAgent") or raw.get("user_agent") or ""),
        "session_type": session_type,
        "session_name": session_name,
        "issuer": issuer,
        "region": str(raw.get("awsRegion") or raw.get("region") or DEFAULT_REGION),
        "resource_id": _first(resource, event_name),
        "actor": principal,
        "action": event_name,
    }

    if event_name in {"AssumeRole", "AssumeRoleWithWebIdentity", "GetSessionToken"}:
        normalized["token_ttl_seconds"] = int(raw.get("durationSeconds") or raw.get("token_ttl_seconds") or 3600)

    return normalized


def _extract_k8s_privileged(raw: dict[str, Any]) -> int:
    if raw.get("is_privileged") is not None:
        return int(bool(raw.get("is_privileged")))
    if raw.get("privilege") == "high":
        return 1
    payload = raw.get("requestObject") or raw.get("object") or {}
    try:
        containers = payload.get("spec", {}).get("containers", [])
        return int(any((c.get("securityContext") or {}).get("privileged") for c in containers))
    except AttributeError:
        return 0


def _extract_k8s_labels(raw: dict[str, Any]) -> dict[str, Any]:
    for key in ("labels", "pod_labels"):
        if isinstance(raw.get(key), dict):
            return raw[key]
    payload = raw.get("requestObject") or raw.get("object") or {}
    try:
        return payload.get("metadata", {}).get("labels", {}) or {}
    except AttributeError:
        return {}


def normalize_k8s_event(raw: dict[str, Any]) -> dict[str, Any]:
    object_ref = raw.get("objectRef") or {}
    user = raw.get("user") or {}
    event_time = str(
        raw.get("stageTimestamp")
        or raw.get("requestReceivedTimestamp")
        or raw.get("eventTime")
        or raw.get("timestamp")
        or _now()
    )
    verb = str(raw.get("verb") or raw.get("action") or "unknown")
    username = str(
        raw.get("username")
        or raw.get("actor")
        or (user.get("username") if isinstance(user, dict) else "")
        or "unknown"
    )
    namespace = str(raw.get("namespace") or object_ref.get("namespace") or "default")
    resource_name = str(
        raw.get("resource_name")
        or raw.get("resource_id")
        or raw.get("pod_name")
        or object_ref.get("name")
        or object_ref.get("resource")
        or "unknown"
    )
    source_ip = _first(raw.get("sourceIPs"), str(raw.get("source_ip") or raw.get("pod_ip") or "10.0.1.15"))
    is_privileged = _extract_k8s_privileged(raw)
    service_type = str(raw.get("service_type") or raw.get("serviceType") or "")
    rbac_change = str(raw.get("rbac_change") or "")
    if object_ref.get("resource") in {"rolebindings", "clusterrolebindings"} or verb in {"bind", "escalate"}:
        rbac_change = rbac_change or f"{verb}:{object_ref.get('resource', '')}"

    event_id = str(raw.get("auditID") or raw.get("eventID") or raw.get("event_id") or uuid4())
    severity = "CRITICAL" if is_privileged else ("HIGH" if verb.lower() in {"delete", "bind", "escalate"} else "INFO")

    return {
        **CANONICAL_DEFAULTS,
        "event_id": event_id,
        "timestamp": event_time,
        "log_type": "k8s_audit",
        "severity": str(raw.get("severity") or severity),
        "scenario": str(raw.get("scenario") or "live_kubernetes"),
        "principal_id": username,
        "source_ip": source_ip,
        "verb": verb,
        "resource_name": resource_name,
        "namespace": namespace,
        "username": username,
        "pod_ip": str(raw.get("pod_ip") or source_ip),
        "is_privileged": is_privileged,
        "labels_json": _json(_extract_k8s_labels(raw)),
        "controller_owner": str(raw.get("controller_owner") or raw.get("controller") or ""),
        "service_type": service_type,
        "rbac_change": rbac_change,
        "region": str(raw.get("region") or "local"),
        "resource_id": resource_name,
        "actor": username,
        "action": verb,
        "user_agent": str(raw.get("userAgent") or raw.get("user_agent") or "k8s-client"),
    }


def normalize_vpc_flow_event(raw: dict[str, Any]) -> dict[str, Any]:
    src = str(raw.get("srcaddr") or raw.get("src_addr") or raw.get("source_ip") or "")
    dst = str(raw.get("dstaddr") or raw.get("dst_addr") or raw.get("destination_ip") or "")
    event_time = str(raw.get("start") or raw.get("timestamp") or raw.get("eventTime") or _now())
    bytes_value = int(raw.get("bytes") or raw.get("vpc_bytes") or 0)
    event_id = str(raw.get("event_id") or raw.get("flow_id") or _stable_id(src, dst, event_time, bytes_value))
    severity = "HIGH" if bytes_value >= 10_000_000 else "INFO"
    action = str(raw.get("action") or raw.get("vpc_action") or "ACCEPT").upper()
    if action not in {"ACCEPT", "REJECT"}:
        action = "ACCEPT"

    return {
        **CANONICAL_DEFAULTS,
        "event_id": event_id,
        "timestamp": event_time,
        "log_type": "vpc_flow",
        "severity": str(raw.get("severity") or severity),
        "scenario": str(raw.get("scenario") or "live_network"),
        "source_ip": src,
        "src_addr": src,
        "dst_addr": dst,
        "src_port": int(raw.get("srcport") or raw.get("src_port") or 0),
        "dst_port": int(raw.get("dstport") or raw.get("dst_port") or 0),
        "vpc_bytes": bytes_value,
        "vpc_action": action,
        "region": str(raw.get("region") or DEFAULT_REGION),
        "resource_id": str(raw.get("resource_id") or f"{src}->{dst}"),
        "actor": str(raw.get("actor") or raw.get("principal_id") or "network-flow"),
        "action": str(raw.get("event_name") or raw.get("action") or "vpc_flow"),
    }


def normalize_telemetry_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical event shape for any supported telemetry source."""
    if not raw:
        return {**CANONICAL_DEFAULTS, "event_id": str(uuid4()), "timestamp": _now()}

    log_type = str(raw.get("log_type") or "").lower()
    
    # Prioritize explicit log_type to prevent collision on already-normalized events containing src_addr/dst_addr
    if log_type == "cloudtrail":
        return normalize_cloudtrail_event(raw)
    if log_type == "vpc_flow":
        return normalize_vpc_flow_event(raw)
    if log_type == "k8s_audit":
        return normalize_k8s_event(raw)

    if "eventSource" in raw or "userIdentity" in raw:
        return normalize_cloudtrail_event(raw)
    if {"srcaddr", "dstaddr"}.issubset(raw.keys()) or {"src_addr", "dst_addr"}.issubset(raw.keys()):
        return normalize_vpc_flow_event(raw)
    if (
        raw.get("apiVersion") == "audit.k8s.io/v1"
        or "objectRef" in raw
        or "pod_name" in raw
        or "namespace" in raw
    ):
        return normalize_k8s_event(raw)
    if raw.get("resource_type") in {"spot_instance", "ec2_instance", "ephemeral_compute"}:
        return normalize_cloudtrail_event({
            **raw,
            "eventSource": "ec2.amazonaws.com",
            "eventName": raw.get("action") or "RunInstances",
        })
    return normalize_k8s_event(raw)


def normalize_many(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_telemetry_event(event) for event in events]
