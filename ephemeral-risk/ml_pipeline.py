from __future__ import annotations

import asyncio
import math
from collections import deque, OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pandas as pd

from correlator import group_anomalies_into_incidents
from detector import score_with_global_model, get_score_distribution
from features import FEATURE_COLS, MODEL_FEATURE_COLS, calculate_features_from_events
from telemetry_normalizer import normalize_telemetry_event


@dataclass
class ProcessingResult:
    """Result returned to the FastAPI live event loop."""

    record: Dict[str, Any]
    cluster: Optional[Dict[str, Any]]
    stats: Dict[str, Any]


def sanitize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    # Sanitize risk_score
    risk_score = record.get("risk_score")
    if risk_score is None:
        record["risk_score"] = 0.0
    else:
        try:
            if math.isnan(float(risk_score)):
                record["risk_score"] = 0.0
            else:
                record["risk_score"] = float(risk_score)
        except (ValueError, TypeError):
            record["risk_score"] = 0.0

    # Sanitize anomaly_score and model_score similarly just in case
    for k in ("anomaly_score", "model_score"):
        val = record.get(k)
        if val is None:
            record[k] = 0.0
        else:
            try:
                if math.isnan(float(val)):
                    record[k] = 0.0
                else:
                    record[k] = float(val)
            except (ValueError, TypeError):
                record[k] = 0.0

    # Fields to sanitize text
    text_fields = {
        "event_id": "unknown",
        "timestamp": "1970-01-01T00:00:00Z",
        "log_type": "k8s_audit",
        "severity": "INFO",
        "event_name": "unknown",
        "event_source": "unknown",
        "principal_id": "unknown",
        "source_ip": "0.0.0.0",
        "verb": "unknown",
        "resource_name": "unknown",
        "namespace": "default",
        "user_agent": "unknown",
        "actor": "unknown",
        "action": "unknown",
        "resource_id": "unknown",
        "region": "local"
    }

    for key, fallback in text_fields.items():
        val = record.get(key)
        if val is None or str(val).strip() == "" or str(val).lower() in ("nan", "none"):
            record[key] = fallback
        else:
            record[key] = str(val)

    # Sanitize features dictionary values
    if "features" in record and isinstance(record["features"], dict):
        for f_key, f_val in record["features"].items():
            if f_val is None:
                record["features"][f_key] = 0.0 if f_key == "vpc_bytes_log" else 0
            else:
                try:
                    if math.isnan(float(f_val)):
                        record["features"][f_key] = 0.0 if f_key == "vpc_bytes_log" else 0
                except (ValueError, TypeError):
                    record["features"][f_key] = 0.0 if f_key == "vpc_bytes_log" else 0

    return record


class _LiveMLPipeline:
    def __init__(
        self,
        contamination: float = 0.10,
        random_state: int = 42,
        max_events: int = 240,
        min_training_events: int = 20,
        min_cluster_events: int = 3,
        correlation_window_min: int = 5,
        min_incident_risk_score: float = 50.0,
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.max_events = max_events
        self.min_training_events = min_training_events
        self.min_cluster_events = min_cluster_events
        self.correlation_window_min = correlation_window_min
        # An incident is only emitted when the correlated cluster reaches this
        # minimum risk score. Prevents low-risk noise from becoming incidents.
        self.min_incident_risk_score = min_incident_risk_score
        self._events: deque[Dict[str, Any]] = deque(maxlen=max_events)
        # Bounded campaign severity cache (LRU eviction at 200 entries) so the
        # suppression map cannot grow unbounded and permanently suppress future
        # incidents that share an entity with old campaigns.
        self._reported_campaign_severity: OrderedDict[str, int] = OrderedDict()
        self._reported_campaign_ts: OrderedDict[str, datetime] = OrderedDict()
        self._campaign_cache_max = 200
        self._campaign_reemit_interval_min: int = 15
        self._processed = 0
        self._anomalies = 0
        self._clusters = 0
        self._last_average_score = 0.0
        self._lock = asyncio.Lock()

    @staticmethod
    def _normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Translate any supported raw event to the canonical ML schema."""
        return normalize_telemetry_event(raw_event)


    @staticmethod
    def _risk_score(raw_anomaly_score: float, is_anomaly: bool) -> float:
        """
        Map a raw IsolationForest score_samples() value to a 0-100 risk score
        using the training data's actual score distribution.

        Normal events (label=+1):  0 - 40  (higher = more unusual for a normal event)
        Anomalous events (label=-1): 50 - 100  (higher = more anomalous)
        """
        dist = get_score_distribution()
        threshold = dist["threshold"]    # model's decision boundary (offset_)
        normal_mean = dist["normal_mean"]
        score_min = dist["min"]

        if not is_anomaly:
            # Normal event: map from [normal_mean ... threshold] → [0 ... 40]
            # Scores closer to threshold are more suspicious normals.
            if raw_anomaly_score >= normal_mean:
                # Very normal, well above the mean → low risk
                scaled = 5.0
            else:
                # Between threshold and normal_mean — scale 0-40
                denom = normal_mean - threshold
                if denom == 0:
                    denom = 0.01
                ratio = (normal_mean - raw_anomaly_score) / denom
                scaled = min(40.0, max(0.0, ratio * 40.0))
        else:
            # Anomalous event: map from [threshold ... score_min] → [50 ... 100]
            denom = threshold - score_min
            if denom == 0:
                denom = 0.01
            ratio = (threshold - raw_anomaly_score) / denom
            scaled = 50.0 + min(50.0, max(0.0, ratio * 50.0))

        return round(max(0.0, min(100.0, scaled)), 2)

    @staticmethod
    def _campaign_key(incident: Dict[str, Any]) -> str:
        """Produce a stable campaign key from entity signatures.

        Uses sorted identity + namespace + resource_name values so genuinely
        distinct campaigns (different actor, namespace, or resource) always
        get distinct keys, even when a single event is shared across graph
        components.
        """
        events = incident.get("raw_telemetry_events", [])
        signatures: list[str] = []
        for event in events:
            for field in ("principal_id", "identity", "username", "actor"):
                val = str(event.get(field) or "").strip()
                if val and val.lower() not in ("", "unknown", "none", "nan"):
                    signatures.append(f"id:{val}")
                    break
            for field in ("namespace",):
                val = str(event.get(field) or "").strip()
                if val and val.lower() not in ("", "unknown", "none", "nan"):
                    signatures.append(f"ns:{val}")
                    break
            for field in ("resource_name", "resource_id", "pod_name"):
                val = str(event.get(field) or "").strip()
                if val and val.lower() not in ("", "unknown", "none", "nan"):
                    # Truncate long resource names to avoid pathological keys
                    signatures.append(f"res:{val[:64]}")
                    break
        signatures = sorted(set(signatures))
        return "|".join(signatures[:6]) if signatures else str(
            incident.get("incident_id", "unknown")
        )

    @staticmethod
    def _cluster_principals(incident: Dict[str, Any]) -> List[str]:
        """Distinct principal_ids present in a cluster's raw events.
        Mirrors the identity extraction in `_campaign_key` so suppression keys
        on the same notion of 'who'."""
        seen: list[str] = []
        for event in incident.get("raw_telemetry_events", []):
            for field in ("principal_id", "identity", "username", "actor"):
                val = str(event.get(field) or "").strip()
                if val and val.lower() not in ("", "unknown", "none", "nan", "system"):
                    if val not in seen:
                        seen.append(val)
                    break
        return seen

    @staticmethod
    def _blocked_principal_in(incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the active blocklist entry for the first principal in the
        cluster that has been contained, or None.  Lazy-imports database to
        avoid a circular import at module load."""
        principals = _LiveMLPipeline._cluster_principals(incident)
        if not principals:
            return None
        try:
            from database import is_principal_blocklisted
            for pid in principals:
                entry = is_principal_blocklisted(pid)
                if entry:
                    return entry
        except Exception as e:
            print(f"Blocklist lookup failed (non-fatal): {e}")
        return None

    @staticmethod
    def _safe_iso(value: Any) -> Optional[str]:
        """Coerce a timestamp value (incl. pandas NaT / Timestamp) to an ISO
        string. Returns None if the value is missing or not a real timestamp —
        previously these surfaced as the literal string 'NaT' in incidents."""
        if value is None:
            return None
        # pandas.Timestamp and numpy.datetime64 expose .isoformat()
        iso = getattr(value, "isoformat", None)
        if callable(iso):
            try:
                result = iso()
            except (ValueError, OverflowError):
                return None
            # pandas NaT.isoformat() returns 'NaT' — treat as missing
            return None if str(result).strip().lower() == "nat" else str(result)
        text = str(value).strip()
        if not text or text.lower() in ("nat", "none", "nan"):
            return None
        return text

    @classmethod
    def _cluster_payload(cls, incident: Dict[str, Any]) -> Dict[str, Any]:
        events = incident["raw_telemetry_events"]
        affected_nodes = incident.get("affected_nodes", [])
        source_ips = sorted({
            str(event.get("source_ip") or event.get("pod_ip"))
            for event in events
            if event.get("source_ip") or event.get("pod_ip")
        })
        # Resources: prefer resource_name, fall back to pod_name /
        # resource_id / principal_id so we never report "0 resources" when
        # the correlated events clearly reference live ephemeral assets.
        resources = sorted({
            str(event.get("resource_name") or event.get("pod_name")
                or event.get("resource_id") or event.get("principal_id"))
            for event in events
            if (event.get("resource_name") or event.get("pod_name")
                or event.get("resource_id") or event.get("principal_id"))
        })
        timestamps = [
            ts for ts in (cls._safe_iso(event.get("timestamp")) for event in events)
            if ts
        ]
        risk_scores = [float(event.get("risk_score", 0.0)) for event in events]
        pivot_ip = source_ips[0] if source_ips else "unknown"

        return {
            "cluster_id": incident["incident_id"],
            "pivot_ip": pivot_ip,
            "node_count": len(affected_nodes),
            "resource_count": len(resources),
            "source_ips": source_ips,
            "resource_ids": resources,
            "event_ids": [str(event["event_id"]) for event in events],
            "strongest_score": max(risk_scores, default=0.0),
            "average_score": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0,
            "time_window": {
                "start": min(timestamps) if timestamps else None,
                "end": max(timestamps) if timestamps else None,
            },
            "active_edges": max(0, len(affected_nodes) - 1),
            "correlator_severity": incident["severity"],
            "affected_nodes": affected_nodes,
            "events": events,
        }

    async def process(self, raw_event: Dict[str, Any]) -> ProcessingResult:
        async with self._lock:
            print(f"\n=========================================")
            print(f"=== ML PIPELINE: PROCESSING INCOMING EVENT ===")
            print(f"=========================================")
            print(
                "Incoming event source: "
                f"log_type={raw_event.get('log_type')}, "
                f"eventSource={raw_event.get('eventSource')}, "
                f"verb={raw_event.get('verb') or raw_event.get('action')}"
            )

            normalized = self._normalize_event(raw_event)
            self._events.append(normalized)
            self._processed += 1

            features_df = calculate_features_from_events(list(self._events))
            current_features = features_df.iloc[-1]
            raw_score = 0.0
            is_anomaly = False
            scored_df = features_df.copy()

            if len(features_df) >= self.min_training_events:
                scored_df = score_with_global_model(features_df)
                current_scored = scored_df[scored_df["event_id"] == normalized["event_id"]]
                if not current_scored.empty:
                    raw_score = float(current_scored.iloc[-1]["anomaly_score"])
                    is_anomaly = int(current_scored.iloc[-1]["anomaly_label"]) == -1
                self._last_average_score = round(
                    float(scored_df["anomaly_score"].mean()), 4
                )

            risk_score = self._risk_score(raw_score, is_anomaly)
            
            print(f"\n>>> Isolation Forest Raw Score: {raw_score}")
            print(f">>> Scaled Risk Score: {risk_score}")
            print(f">>> Is Anomaly: {is_anomaly}")
            print(f">>> Calculated Features: ")
            for feature_name in FEATURE_COLS:
                print(f"    - {feature_name}: {current_features[feature_name]}")
            print(f"=========================================\n")

            feature_payload = {
                feature_name: (
                    float(current_features[feature_name])
                    if feature_name == "vpc_bytes_log"
                    else int(current_features[feature_name])
                )
                for feature_name in FEATURE_COLS
            }

            record = {
                **normalized,
                **raw_event,
                "anomaly_score": round(raw_score, 6),
                "model_score": round(raw_score, 6),
                "risk_score": risk_score,
                "is_anomaly": is_anomaly,
                "cluster_id": None,
                "features": feature_payload,
            }

            # Overwrite the severity key based on risk_score
            if risk_score >= 80:
                record["severity"] = "CRITICAL"
            elif risk_score >= 60:
                record["severity"] = "HIGH"
            elif risk_score >= 30:
                record["severity"] = "MEDIUM"
            # Else leave it as its default (e.g. from normalized or raw event)

            # Map K8s pod_name or resource_name to the required DB column
            record["resource_id"] = record.get("resource_id") or record.get("pod_name") or record.get("resource_name") or "unknown-resource"
            record["region"] = record.get("region") or "local"
            record["user_agent"] = record.get("user_agent") or record.get("userAgent") or "telemetry-client"
            record["actor"] = record.get("actor") or record.get("username") or "unknown"
            record["action"] = record.get("action") or record.get("verb") or "unknown"


            cluster = None
            if is_anomaly:
                try:
                    self._anomalies += 1
                    anomalies_df = scored_df[scored_df["anomaly_label"] == -1].copy()
                    if not anomalies_df.empty:
                        risk_by_event = {
                            str(row["event_id"]): self._risk_score(
                                float(row["anomaly_score"]), True
                            )
                            for _, row in anomalies_df.iterrows()
                        }
                        anomalies_df["risk_score"] = anomalies_df["event_id"].map(risk_by_event)
                        incidents = group_anomalies_into_incidents(
                            anomalies_df,
                            window_min=self.correlation_window_min,
                        )
                        current_incident = next(
                            (
                                incident for incident in incidents
                                if any(
                                    str(event.get("event_id")) == normalized["event_id"]
                                    for event in incident["raw_telemetry_events"]
                                )
                            ),
                            None,
                        )
                        if (
                            current_incident
                            and len(current_incident["raw_telemetry_events"]) >= self.min_cluster_events
                        ):
                            # Pre-compute the cluster payload once so we can gate
                            # on the strongest risk score before reporting it.
                            candidate_cluster = self._cluster_payload(current_incident)
                            if candidate_cluster["strongest_score"] < self.min_incident_risk_score:
                                # Low-risk cluster — do not promote to an incident.
                                cluster = None
                            else:
                                # Quarantine-blocklist suppression: if any principal
                                # in this cluster has already been contained by an
                                # analyst, do NOT promote to a fresh incident.  The
                                # event is still scored + persisted (audit trail),
                                # but we clamp severity to INFO and flag it so the
                                # UI shows "suppressed — already contained".
                                blocked_entry = self._blocked_principal_in(current_incident)
                                if blocked_entry:
                                    cluster = None
                                    record["suppressed"] = True
                                    record["suppressed_principal"] = blocked_entry["principal_id"]
                                    record["suppressed_reason"] = (
                                        f"Source '{blocked_entry['principal_id']}' already contained "
                                        f"by {blocked_entry.get('operator', 'system')} "
                                        f"on {blocked_entry.get('created_at', '')}"
                                    )
                                    record["severity"] = "INFO"
                                else:
                                    severity_rank = {
                                        "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3
                                    }.get(current_incident["severity"], 0)
                                    campaign_key = self._campaign_key(current_incident)
                                    previous_rank = self._reported_campaign_severity.get(campaign_key, -1)
                                    previous_ts = self._reported_campaign_ts.get(campaign_key)
                                    now = datetime.now(timezone.utc)

                                    # Re-emit if: severity escalated, OR enough time
                                    # has passed since last report (escalation refresh).
                                    reemit = severity_rank > previous_rank
                                    if not reemit and previous_ts:
                                        elapsed_min = (now - previous_ts).total_seconds() / 60.0
                                        reemit = elapsed_min >= self._campaign_reemit_interval_min

                                    if reemit:
                                        cluster = candidate_cluster
                                        record["cluster_id"] = cluster["cluster_id"]
                                        # LRU eviction: bump to end, evict oldest if full
                                        self._reported_campaign_severity[campaign_key] = severity_rank
                                        self._reported_campaign_severity.move_to_end(campaign_key)
                                        self._reported_campaign_ts[campaign_key] = now
                                        self._reported_campaign_ts.move_to_end(campaign_key)
                                        while len(self._reported_campaign_severity) > self._campaign_cache_max:
                                            self._reported_campaign_severity.popitem(last=False)
                                            self._reported_campaign_ts.popitem(last=False)
                                        self._clusters += 1
                except Exception as e:
                    print(f"Narrative Engine Failed: {e}. Falling back to raw event.")
                    record['type'] = 'raw_anomaly'
                    # risk_score is already calculated and attached to record!

            record = sanitize_record(record)
            return ProcessingResult(record=record, cluster=cluster, stats=self.get_stats())

    def get_stats(self) -> Dict[str, Any]:
        return {
            "model": {
                "name": "IsolationForest",
                "contamination": self.contamination,
                "trained_features": len(MODEL_FEATURE_COLS),
                "events_in_window": len(self._events),
                "average_anomaly_score": self._last_average_score,
            },
            "correlation": {
                "engine": "NetworkX",
                "active_clusters_tracked": len(self._reported_campaign_severity),
                "graph_nodes": 0,
                "graph_edges": 0,
                "reported_clusters": self._clusters,
                "anomalous_events": self._anomalies,
            },
            "processed_events": self._processed,
        }


_PIPELINE = _LiveMLPipeline()


def seed_pipeline_events(events: list[Dict[str, Any]]) -> None:
    """
    Pre-populate the pipeline's event deque with normalised events
    so that rolling features (e.g. rolling_burst_count) have proper
    context from the very first live event.

    Should be called once at startup after the model is fitted.
    """
    for event in events:
        normalized = _PIPELINE._normalize_event(event)
        _PIPELINE._events.append(normalized)
    print(f"  [seed_pipeline_events] Seeded pipeline with {len(events)} context events.")


async def process_event(raw_event: Dict[str, Any]) -> ProcessingResult:
    """Process one raw live event through features, detection, and correlation."""
    try:
        return await _PIPELINE.process(raw_event)
    except Exception as e:
        print(f"ML ERROR: {e}")
        raise e


def get_pipeline_stats() -> Dict[str, Any]:
    return _PIPELINE.get_stats()


def get_pipeline() -> _LiveMLPipeline:
    """Return the singleton pipeline instance (e.g. for seeding)."""
    return _PIPELINE
