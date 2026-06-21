"""
correlator.py
=============
Two-stage alert correlation and AI triage module.

Public API
----------
    group_anomalies_into_incidents(
        anomalies_df : pd.DataFrame,
        db_path      : str = "data/events.db",
        window_min   : int = 5,
    ) -> list[dict]

    run_local_llm_triage(
        incident_logs : list[dict],
        incident_id   : str = "",
    ) -> IncidentTriageReport

Stage 1 — NetworkX Graph Correlation
    Builds an undirected entity-correlation graph from anomalous events.
    Nodes  = typed entity labels (identity, ARN, IP, resource, namespace).
    Edges  = entities that co-appear in the same event (intra-event),
             OR that appear in events within *window_min* of each other
             while sharing at least one common entity (inter-event).
    nx.connected_components() partitions the graph into distinct Incident
    Campaigns, collapsing hundreds of raw alert lines into a handful of
    actionable records.

Stage 2 — Local LLM Triage (Ollama / llama3.1:8b via instructor)
    Passes each incident's raw event logs to an air-gapped local LLM and
    extracts a structured IncidentTriageReport Pydantic object.
    If Ollama is unavailable, a rule-based fallback report is returned.

Requires: networkx, pandas, pydantic, instructor, openai (for ollama transport)
"""

from __future__ import annotations

import itertools
import uuid
from pathlib import Path
from typing import Any, Literal

import networkx as nx
import pandas as pd
from pydantic import BaseModel, Field

# ──────────────────────────────────────────────────────────────────────────────
# PYDANTIC SCHEMA — LLM OUTPUT CONTRACT
# ──────────────────────────────────────────────────────────────────────────────

class AttackTimelineEntry(BaseModel):
    """A single timestamped step in the reconstructed attack chain."""
    time:   str = Field(description="Approximate UTC time or relative offset, e.g. T+2min")
    action: str = Field(description="What happened at this step")


class IncidentTriageReport(BaseModel):
    """
    Structured triage report produced by the local LLM for one incident campaign.

    Fields
    ------
    incident_title     Short, human-readable name for the incident campaign.
    severity           CRITICAL | HIGH | MEDIUM | LOW
    mitre_tactics      List of MITRE ATT&CK for Cloud tactic names.
    executive_summary  2–4 sentence non-technical summary for leadership.
    attack_timeline    Ordered list of attack steps with timestamps.
    remediation_script Executable shell/CLI commands to contain and remediate.
    """
    incident_title:     str                           = Field(description="Short incident name")
    severity:           Literal["CRITICAL","HIGH","MEDIUM","LOW"]
    mitre_tactics:      list[str]                     = Field(description="MITRE ATT&CK Cloud tactics")
    executive_summary:  str                           = Field(description="2-4 sentence executive brief")
    attack_timeline:    list[AttackTimelineEntry]     = Field(description="Ordered attack steps")
    remediation_script: str                           = Field(description="Shell commands to remediate")


# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

ROOT    = Path(__file__).resolve().parent
DB_PATH = str(ROOT / "data" / "events.db")

_NODE_FIELDS: list[tuple[str, str]] = [
    ("identity",      "id"),
    ("arn",           "arn"),
    ("source_ip",     "ip"),
    ("pod_ip",        "ip"),
    ("src_addr",      "ip"),
    ("dst_addr",      "ip"),
    ("resource_name", "res"),
    ("namespace",     "ns"),
]

_NULL_SENTINELS = frozenset({"", "0", "0.0.0.0", "<unknown>", "nan", "None"})
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Entity-type edge weights: strong entities (identity, ARN, resource) link
# incidents firmly; weak entities (namespace, IP) only provide circumstantial
# links and should not collapse distinct campaigns on their own.
_STRONG_PREFIXES = frozenset({"id", "arn", "res"})
_DEFAULT_EDGE_WEIGHT = 1.0
_WEAK_EDGE_WEIGHT = 0.3
# Minimum combined edge weight between two nodes to keep them connected.
# At least one strong link is required for a meaningful merge.
_MIN_EDGE_WEIGHT_THRESHOLD = 0.5


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _node_label(prefix: str, value: str) -> str:
    return f"{prefix}:{value}"


def _node_prefix(node: str) -> str:
    """Return the prefix part of a node label, e.g. 'ns' from 'ns:default'."""
    return node.split(":", 1)[0]


def _edge_weight_for(n1: str, n2: str) -> float:
    """Compute edge weight based on the entity types being linked.

    Strong entity types (identity, ARN, resource) produce weight 1.0.
    If *both* endpoints are weak (namespace, IP), weight is 0.3.
    Mixed (one strong, one weak) gets weight 0.5.
    """
    p1, p2 = _node_prefix(n1), _node_prefix(n2)
    both_weak = (p1 not in _STRONG_PREFIXES) and (p2 not in _STRONG_PREFIXES)
    one_weak = (p1 not in _STRONG_PREFIXES) or (p2 not in _STRONG_PREFIXES)
    if both_weak:
        return _WEAK_EDGE_WEIGHT
    if one_weak:
        return 0.5
    return _DEFAULT_EDGE_WEIGHT


def _extract_nodes(row: dict[str, Any]) -> list[str]:
    seen: dict[str, None] = {}
    for field, prefix in _NODE_FIELDS:
        val = str(row.get(field) or "").strip()
        if val and val not in _NULL_SENTINELS:
            seen[_node_label(prefix, val)] = None
    return list(seen)


def _build_entity_graph(anomalies: pd.DataFrame, window_min: int) -> nx.Graph:
    G: nx.Graph = nx.Graph()
    rows = anomalies.to_dict(orient="records")

    for row in rows:
        nodes = _extract_nodes(row)
        eid   = row.get("event_id", "")
        ltype = row.get("log_type", "")

        for node in nodes:
            if not G.has_node(node):
                G.add_node(node, event_ids=[], log_types=set())
            G.nodes[node]["event_ids"].append(eid)
            G.nodes[node]["log_types"].add(ltype)

        # Intra-event edges: all entities in the same event are strongly linked.
        for n1, n2 in itertools.combinations(nodes, 2):
            w = _edge_weight_for(n1, n2)
            if G.has_edge(n1, n2):
                G[n1][n2]["weight"] += w
            else:
                G.add_edge(n1, n2, weight=w)

    valid = (
        anomalies.dropna(subset=["timestamp"])
        .sort_values("timestamp")
        .to_dict(orient="records")
    )
    window_td = pd.Timedelta(minutes=window_min)

    for i, row_i in enumerate(valid):
        ts_i    = row_i["timestamp"]
        nodes_i = set(_extract_nodes(row_i))
        if not nodes_i:
            continue

        for j in range(i + 1, len(valid)):
            row_j = valid[j]
            ts_j  = row_j["timestamp"]
            if ts_j - ts_i > window_td:
                break

            nodes_j = set(_extract_nodes(row_j))
            if not nodes_j or not (nodes_i & nodes_j):
                continue

            for n1, n2 in itertools.product(nodes_i, nodes_j):
                if n1 == n2:
                    continue
                w = _edge_weight_for(n1, n2)
                if G.has_edge(n1, n2):
                    G[n1][n2]["weight"] += w
                else:
                    G.add_edge(n1, n2, weight=w)

    return G


# ──────────────────────────────────────────────────────────────────────────────
# SEVERITY CALCULATOR
# ──────────────────────────────────────────────────────────────────────────────

def _cluster_severity(cluster_df: pd.DataFrame) -> str:
    if cluster_df.empty:
        return "LOW"

    priv      = bool(cluster_df["is_privileged_pod"].any())
    untrusted = bool(cluster_df["untrusted_network_hit"].any())
    burst     = int(cluster_df["rolling_burst_count"].max())
    missing   = int(cluster_df["missing_tags_score"].max())
    raw_sevs  = set(cluster_df["severity"].str.upper())

    if priv and untrusted:
        return "CRITICAL"
    if "CRITICAL" in raw_sevs and untrusted:
        return "CRITICAL"
    if burst >= 20 and untrusted and missing >= 2:
        return "CRITICAL"
    if "CRITICAL" in raw_sevs or "HIGH" in raw_sevs:
        return "HIGH"
    if untrusted and missing >= 2:
        return "HIGH"
    if burst >= 10 and untrusted:
        return "HIGH"
    if untrusted or missing >= 2 or burst >= 5:
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 1 — PUBLIC API: GROUP ANOMALIES INTO INCIDENTS
# ──────────────────────────────────────────────────────────────────────────────

def group_anomalies_into_incidents(
    anomalies_df: pd.DataFrame,
    db_path:      str = DB_PATH,
    window_min:   int = 5,
) -> list[dict]:
    """
    Build an entity-correlation graph from *anomalies_df* and partition it into
    incident campaigns using NetworkX connected components.

    Parameters
    ----------
    anomalies_df : Output of detector.detect_anomalies()
    db_path      : SQLite database path (reserved for future enrichment queries)
    window_min   : Sliding correlation window in minutes.

    Returns
    -------
    list[dict]  Sorted CRITICAL → LOW; each dict:
        {
            "incident_id"          : str
            "severity"             : str
            "affected_nodes"       : list[str]
            "raw_telemetry_events" : list[dict]
        }
    """
    if anomalies_df.empty:
        return []

    G = _build_entity_graph(anomalies_df, window_min)

    if G.number_of_nodes() == 0:
        return []

    # Prune weak edges (below threshold) so namespace/IP-only links don't
    # collapse distinct campaigns that happen to share `ns:default` or an
    # egress IP.  Edges that survive have at least one strong entity link.
    weak_edges = [
        (u, v) for u, v, data in G.edges(data=True)
        if data.get("weight", 0) < _MIN_EDGE_WEIGHT_THRESHOLD
    ]
    G.remove_edges_from(weak_edges)

    incidents: list[dict] = []

    for component in nx.connected_components(G):
        event_ids: set[str] = set()
        for node in component:
            event_ids.update(G.nodes[node].get("event_ids", []))

        cluster_df = anomalies_df[anomalies_df["event_id"].isin(event_ids)].copy()
        severity   = _cluster_severity(cluster_df)

        raw_events = (
            cluster_df
            .sort_values("anomaly_score")
            .where(cluster_df.notna(), other=None)
            .to_dict(orient="records")
        )

        incidents.append({
            "incident_id":           str(uuid.uuid4()),
            "severity":              severity,
            "affected_nodes":        sorted(component),
            "raw_telemetry_events":  raw_events,
        })

    incidents.sort(key=lambda x: (
        _SEVERITY_ORDER.get(x["severity"], 9),
        -len(x["raw_telemetry_events"]),
    ))

    return incidents


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 2 — LLM TRIAGE (Ollama / instructor)
# ──────────────────────────────────────────────────────────────────────────────

def _rule_based_fallback(
    incident_logs: list[dict],
    incident_id:   str,
) -> IncidentTriageReport:
    df = pd.DataFrame(incident_logs) if incident_logs else pd.DataFrame()

    def _col(c: str, default=0):
        return df[c].max() if not df.empty and c in df.columns else default

    priv      = bool(_col("is_privileged_pod"))
    untrusted = bool(_col("untrusted_network_hit"))
    burst     = int(_col("rolling_burst_count"))
    missing   = int(_col("missing_tags_score"))
    raw_sev   = df["severity"].str.upper().unique().tolist() if not df.empty and "severity" in df.columns else []

    if priv and untrusted:
        sev: Literal["CRITICAL","HIGH","MEDIUM","LOW"] = "CRITICAL"
    elif "CRITICAL" in raw_sev or (untrusted and missing >= 2):
        sev = "HIGH"
    elif untrusted or burst >= 10:
        sev = "MEDIUM"
    else:
        sev = "LOW"

    tactics: list[str] = []
    if "CRITICAL" in raw_sev or (not df.empty and "RunInstances" in df.get("event_name", pd.Series()).values):
        tactics.append("Resource Hijacking (T1496)")
    if untrusted:
        tactics.append("Exfiltration Over C2 Channel (T1041)")
    if priv:
        tactics.append("Escape to Host (T1611)")
    if not df.empty and "AssumeRoleWithWebIdentity" in df.get("event_name", pd.Series()).values:
        tactics.append("Valid Accounts — Cloud Accounts (T1078.004)")
    if not tactics:
        tactics = ["Discovery (TA0007)"]

    identities = df["identity"].dropna().unique().tolist() if not df.empty and "identity" in df.columns else []
    identity_str = ", ".join(identities[:3]) or "unknown"

    return IncidentTriageReport(
        incident_title=f"[Rule-Based] Incident {incident_id[:8]} — {sev} Anomaly Cluster",
        severity=sev,
        mitre_tactics=tactics,
        executive_summary=(
            f"An automated rule engine detected a {sev}-severity security event cluster "
            f"involving {len(incident_logs)} anomalous log entries attributed to "
            f"identit{'ies' if len(identities) > 1 else 'y'} [{identity_str}]. "
            f"Key risk signals: untrusted_network_hit={int(untrusted)}, "
            f"is_privileged_pod={int(priv)}, max_burst={burst}, "
            f"missing_tags_score={missing}. Immediate investigation is recommended."
        ),
        attack_timeline=[
            AttackTimelineEntry(time="T+0", action=f"First anomalous event detected"),
            AttackTimelineEntry(time="T+ongoing", action=f"{len(incident_logs)} total anomalous events in campaign"),
        ],
        remediation_script=(
            "#!/bin/bash\n# Auto-generated remediation\n\n"
            + ("aws iam delete-access-key --access-key-id <KEY_ID>\n" if sev in ("CRITICAL","HIGH") else "")
            + ("kubectl delete pod debug-tool-xyz -n default --force --grace-period=0\n" if priv else "")
            + "aws cloudtrail lookup-events --max-results 50\n"
        ),
    )


def run_local_llm_triage(
    incident_logs: list[dict],
    incident_id:   str = "",
    api_key:       str | None = None,
) -> IncidentTriageReport:
    """
    Send raw incident logs to a locally running Ollama model or the Gemini API
    via the instructor library and return a structured IncidentTriageReport.

    Falls back to rule-based triage if the model is unreachable or times out.

    Parameters
    ----------
    incident_logs : list[dict]  — raw_telemetry_events from an incident record
    incident_id   : str         — UUID of the parent incident (for logging)
    api_key       : str | None  — Gemini API Key. If not provided, checks GEMINI_API_KEY environment variable.

    Returns
    -------
    IncidentTriageReport  (Pydantic model, always non-None)
    """
    if not incident_logs:
        return _rule_based_fallback([], incident_id)

    sample = incident_logs[:30]
    log_lines = "\n".join(
        f"[{r.get('timestamp','?')}] {r.get('log_type','?').upper()} "
        f"severity={r.get('severity','?')} identity={r.get('identity','?')} "
        f"event={r.get('event_name') or r.get('verb','?')} "
        f"src={r.get('source_ip') or r.get('src_addr','?')} "
        f"dst={r.get('dst_addr','?')} "
        f"untrusted={r.get('untrusted_network_hit',0)} "
        f"burst={r.get('rolling_burst_count',1)} "
        f"privileged={r.get('is_privileged_pod',0)} "
        f"missing_tags={r.get('missing_tags_score',0)}"
        for r in sample
    )

    system_prompt = (
        "You are an expert cloud security incident responder. "
        "Analyse the provided security telemetry and produce a structured triage report. "
        "The remediation_script must be executable bash/kubectl/awscli commands."
    )

    user_prompt = (
        f"Incident ID: {incident_id}\n"
        f"Total anomalous events in this cluster: {len(incident_logs)}\n\n"
        f"Security event log sample:\n{'─'*70}\n{log_lines}\n{'─'*70}\n\n"
        "Produce a complete IncidentTriageReport JSON object."
    )

    try:
        import os
        import instructor
        from openai import OpenAI

        gemini_key = api_key or os.environ.get("GEMINI_API_KEY")

        if gemini_key:
            client = instructor.from_openai(
                OpenAI(
                    base_url="https://generativelanguage.googleapis.com/v1beta/",
                    api_key=gemini_key,
                    timeout=60.0
                ),
                mode=instructor.Mode.JSON,
            )
            model_name = "gemini-1.5-flash"
        else:
            client = instructor.from_openai(
                OpenAI(
                    base_url="http://localhost:11434/v1",
                    api_key="ollama",
                    timeout=60.0
                ),
                mode=instructor.Mode.JSON,
            )
            model_name = "llama3.1:8b"

        return client.chat.completions.create(
            model=model_name,
            temperature=0.0,
            response_model=IncidentTriageReport,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        )

    except ImportError:
        print("  [LLM] 'instructor'/'openai' not installed — using rule-based fallback.")
        return _rule_based_fallback(incident_logs, incident_id)

    except Exception as exc:
        lbl = "Gemini" if (api_key or os.environ.get("GEMINI_API_KEY")) else "Ollama"
        print(f"  [LLM] {lbl} unavailable ({type(exc).__name__}) — using rule-based fallback.")
        return _rule_based_fallback(incident_logs, incident_id)