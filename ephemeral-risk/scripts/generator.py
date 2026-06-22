from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List
from backend.database import fetch_active_pipelines


class MockEventGenerator:
    def __init__(self, seed: int = 11) -> None:
        self.rng = random.Random(seed)
        self.counter = 0
        self.attack_ip = self.rng.choice(["10.10.8.14", "10.10.8.21", "172.16.44.7"])
        self.attack_resources = ["aks-prod-01", "aks-prod-02", "aks-prod-03", "aks-prod-04"]

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _normal_event(self) -> Dict[str, Any]:
        return {
            "source_ip": self.rng.choice(["10.0.1.12", "10.0.2.24", "10.0.3.18", "192.168.1.23"]),
            "user_agent": self.rng.choice(["kubectl/v1.30", "terraform/1.8", "helm/3.15", "argo-cd/2.10"]),
            "actor": self.rng.choice(["dev-alice", "argocd-svc", "flux-controller", "ci-runner-svc"]),
            "action": self.rng.choice(["pod.list", "pod.get", "image.pull", "cluster.describe"]),
            "resource_id": self.rng.choice(["deploy/web", "deploy/api", "secret/db", "configmap/platform"]),
            "region": self.rng.choice(["eastus", "westus2", "westeurope"]),
            "request_weight": self.rng.randint(1, 6),
            "burst_flag": 0,
            "success": True,
        }

    def _burst_event(self) -> Dict[str, Any]:
        return {
            "source_ip": self.attack_ip,
            "user_agent": self.rng.choice(["curl/8.1", "python-requests/2.32", "sqlmap/1.7"]),
            "actor": self.rng.choice(["unknown", "unauthenticated", "system"]),
            "action": self.rng.choice(["secret.list", "role.bind", "pod.exec", "token.create"]),
            "resource_id": self.rng.choice(self.attack_resources),
            "region": self.rng.choice(["eastus", "centralus", "westeurope"]),
            "request_weight": self.rng.randint(8, 20),
            "burst_flag": 1,
            "success": False,
        }

    def next_event(self) -> Dict[str, Any]:
        self.counter += 1
        # Pick an active pipeline to contextualize this event; fallback to generic if none
        active = fetch_active_pipelines()
        pipeline = self.rng.choice(active) if active else None
        burst = self.counter % 9 in {0, 1, 2} or self.counter % 17 == 0
        payload = self._burst_event() if burst else self._normal_event()
        # attach pipeline context
        if pipeline:
            repo = pipeline.get("repo_name")
            namespace = pipeline.get("target_namespace")
            pod_name = f"{repo.split('/')[-1]}-build-{self.counter % 1000}"
            payload["resource_id"] = pod_name
            payload["namespace"] = namespace
            payload["repo_name"] = repo

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": self._now(),
            **payload,
        }
        if burst:
            event["burst_id"] = f"burst-{self.counter // 3}"
        return event

    async def stream_events(self) -> AsyncIterator[Dict[str, Any]]:
        while True:
            yield self.next_event()
            delay = 0.22 if self.counter % 9 in {0, 1, 2} else 0.9
            await asyncio.sleep(delay)
