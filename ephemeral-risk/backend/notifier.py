from __future__ import annotations

import json
import smtplib
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Mapping

from backend.config import settings as _settings

ALERT_LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "critical_alerts.log"
# FIX 1: Ensure the parent directory exists so open('a') never throws FileNotFoundError
ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

_LOG_LOCK = threading.Lock()

# Severities that warrant an email notification.
_EMAIL_SEVERITIES = {"CRITICAL", "HIGH"}

_EMAILED_INCIDENTS: dict[str, float] = {}
_EMAIL_COOLDOWN = 3600.0


def _build_email_body(incident: Mapping[str, Any]) -> str:
    """Format an incident into a readable plain-text email body."""
    severity = incident.get("severity", "UNKNOWN").upper()
    risk_score = incident.get("risk_score", "N/A")
    inc_id = incident.get("incident_id", "unknown")
    cluster_id = incident.get("cluster_id", "unknown")
    pivot_ip = incident.get("pivot_ip", "unknown")
    resource_count = incident.get("resource_count", 0)
    node_count = incident.get("node_count", 0)
    scenario = incident.get("scenario", "N/A")
    intent = incident.get("intent_summary", "N/A")

    lines = [
        f"Security Incident Detected",
        f"{'─' * 40}",
        f"Severity:    {severity}",
        f"Risk Score:  {risk_score}",
        f"Incident ID: {inc_id}",
        f"Cluster ID:  {cluster_id}",
        f"Pivot IP:    {pivot_ip}",
        f"Resources:   {resource_count} pods affected",
        f"Nodes:       {node_count}",
        "",
        f"Scenario:    {scenario}",
        f"Intent:      {intent}",
    ]

    # Correlated evidence
    evidence = incident.get("correlated_evidence", [])
    if evidence:
        lines.append("")
        lines.append("Correlated Evidence:")
        if isinstance(evidence, dict):
            for k, v in evidence.items():
                lines.append(f"  - {str(k).capitalize()}: {v}")
        elif isinstance(evidence, list):
            for ev in evidence[:10]:
                ev_id = ev.get("event_id", "unknown") if isinstance(ev, dict) else str(ev)
                desc = (
                    ev.get("description", "")
                    if isinstance(ev, dict)
                    else str(ev)
                )
                lines.append(f"  - {ev_id}: {desc}")
        else:
            lines.append(f"  - {str(evidence)}")

    # Recommended actions
    actions = incident.get("clear_actions", [])
    if actions:
        lines.append("")
        lines.append("Recommended Actions:")
        for i, action in enumerate(actions[:10], 1):
            act_text = action if isinstance(action, str) else json.dumps(action, ensure_ascii=False)
            lines.append(f"  {i}. {act_text}")

    lines.append("")
    lines.append(
        f"Dispatched at: {datetime.now(timezone.utc).isoformat(timespec='seconds')} UTC"
    )
    return "\n".join(lines)


def _send_email(recipient: str, incident: Mapping[str, Any]) -> None:
    """Send an alert email via SMTP. Catches errors gracefully."""
    print(f"[DEBUG] _send_email called for recipient: {recipient}", flush=True)
    cfg = _settings
    if not getattr(cfg, "SMTP_HOST", None):
        print(f"[DEBUG] _send_email aborted: SMTP_HOST is empty or not configured.", flush=True)
        return

    severity = incident.get("severity", "UNKNOWN").upper()
    inc_id = incident.get("incident_id", "unknown")
    subject = f"[{severity}] Ephemeral Risk Alert — Incident {inc_id}"

    body = _build_email_body(incident)

    msg = MIMEMultipart()
    msg["From"] = cfg.SMTP_USER
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        # FIX 3: Check port to prevent hanging. 465 requires SMTP_SSL, 587 requires SMTP + starttls
        port = int(getattr(cfg, "SMTP_PORT", 587))
        
        if port == 465:
            with smtplib.SMTP_SSL(cfg.SMTP_HOST, port, timeout=15) as server:
                server.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg.SMTP_HOST, port, timeout=15) as server:
                server.starttls()
                server.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
                server.send_message(msg)
                
        print(
            f"\033[32m[EMAIL SENT] {subject} -> {recipient}\033[0m",
            flush=True,
        )
    except Exception as err:
        print(
            f"\033[33m[EMAIL ERROR] Failed to send alert {inc_id}: {err}\033[0m",
            flush=True,
        )


def dispatch_alert(incident_data: Mapping[str, Any]) -> None:
    """Persist a local alert and optionally send email for HIGH/CRITICAL."""
    dispatched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    
    # Safely handle None values from the dictionary
    raw_severity = incident_data.get("severity")
    severity = str(raw_severity).upper() if raw_severity else "INFO"

    # Safely handle missing ALERT_RECIPIENT
    raw_recipient = getattr(_settings, "ALERT_RECIPIENT", "") or ""

    alert = {
        "dispatched_at": dispatched_at,
        "channel": "Email",
        "recipient": raw_recipient,
        "incident_id": incident_data.get("incident_id", "unknown"),
        "cluster_id": incident_data.get("cluster_id", "unknown"),
        "severity": severity,
        "pivot_ip": incident_data.get("pivot_ip", "unknown"),
        "resource_count": incident_data.get("resource_count", 0),
        "node_count": incident_data.get("node_count", 0),
        "report_text": incident_data.get("report_text", ""),
    }

    # Always write to local log.
    formatted_alert = (
        f"\n=== {severity} SECURITY ALERT ===\n"
        f"{json.dumps(alert, indent=2, ensure_ascii=False, default=str)}\n"
        "=== END ALERT ===\n"
    )
    
    # The parent directory is now guaranteed to exist from Line 16
    with _LOG_LOCK:
        with ALERT_LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(formatted_alert)

    # Email only for HIGH and CRITICAL.
    print(f"[DEBUG] dispatch_alert evaluating severity: '{severity}' in {_EMAIL_SEVERITIES}?", flush=True)
    if severity in _EMAIL_SEVERITIES:
        now = datetime.now(timezone.utc).timestamp()
        inc_id = alert['incident_id']
        
        # Deduplication check
        if inc_id in _EMAILED_INCIDENTS and (now - _EMAILED_INCIDENTS[inc_id]) < _EMAIL_COOLDOWN:
            print(f"[DEBUG] Skipping email for {inc_id} (already sent within cooldown window)", flush=True)
            return

        _EMAILED_INCIDENTS[inc_id] = now

        print(f"[DEBUG] Raw ALERT_RECIPIENT from settings: '{raw_recipient}'", flush=True)
        
        # FIX 2: Safely parse recipients, preventing AttributeError if None
        recipients = [
            addr.strip()
            for addr in str(raw_recipient).split(",")
            if addr.strip()
        ]
        
        print(f"[DEBUG] Parsed recipients list: {recipients}", flush=True)
        for addr in recipients:
            _send_email(addr, incident_data)

        # Console output — flashing red for CRITICAL, bold yellow for HIGH.
        if severity == "CRITICAL":
            style = "\033[5;1;31m"  # flashing red bold
        else:
            style = "\033[1;33m"  # bold yellow
        reset = "\033[0m"
        print(
            f"{style}[{severity} ALERT DISPATCHED: Email -> {raw_recipient}]"
            f" Incident={alert['incident_id']} Pivot={alert['pivot_ip']}{reset}",
            flush=True,
        )
    else:
        print(
            f"[{severity}] Incident={alert['incident_id']} logged locally (no email)",
            flush=True,
        )