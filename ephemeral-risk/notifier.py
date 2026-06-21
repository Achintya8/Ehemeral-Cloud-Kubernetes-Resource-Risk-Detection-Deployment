from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


ALERT_RECIPIENT = "soc@company.com"
ALERT_LOG_PATH = Path(__file__).resolve().parent / "critical_alerts.log"
_LOG_LOCK = threading.Lock()


def dispatch_alert(incident_data: Mapping[str, Any]) -> None:
    """Persist and display a local critical-incident notification."""
    dispatched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    alert = {
        "dispatched_at": dispatched_at,
        "channel": "Email",
        "recipient": ALERT_RECIPIENT,
        "incident_id": incident_data.get("incident_id", "unknown"),
        "cluster_id": incident_data.get("cluster_id", "unknown"),
        "severity": incident_data.get("severity", "Critical"),
        "pivot_ip": incident_data.get("pivot_ip", "unknown"),
        "resource_count": incident_data.get("resource_count", 0),
        "node_count": incident_data.get("node_count", 0),
        "report_text": incident_data.get("report_text", ""),
    }

    formatted_alert = (
        "\n=== CRITICAL SECURITY ALERT ===\n"
        f"{json.dumps(alert, indent=2, ensure_ascii=False, default=str)}\n"
        "=== END ALERT ===\n"
    )
    with _LOG_LOCK:
        with ALERT_LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(formatted_alert)

    flashing_red = "\033[5;1;31m"
    reset = "\033[0m"
    print(
        f"{flashing_red}[CRITICAL ALERT DISPATCHED: Email -> {ALERT_RECIPIENT}]"
        f" Incident={alert['incident_id']} Pivot={alert['pivot_ip']}{reset}",
        flush=True,
    )
