# k8strl: Ephemeral Cloud Kubernetes Resource Risk Detection Platform
## Developer & Architect System Documentation

Welcome to the technical documentation for the **k8strl** platform. This document provides a deep dive into the system's architecture, ML anomaly detection pipeline, containment automation, compliance verification, and API reference.

---

## 1. System Architecture Overview

The platform uses a decoupled, event-driven architecture designed to process high-throughput cloud and container telemetry (Kubernetes Audit Logs, VPC Flow Logs, AWS CloudTrail) in real-time. It detects ephemeral infrastructure breakout attempts, executes zero-trust containment, and generates AI-driven triage reports.

```
+-------------------------------------------------------------------------------+
|                                 DATA SOURCES                                  |
|  [ K8s Audit Logs ]      [ VPC Flow Logs ]      [ AWS CloudTrail ]  [ Stress ]|
+---------------------------------------+---------------------------------------+
                                        | (HTTP POST /api/ingest)
                                        v
+-------------------------------------------------------------------------------+
|                               FASTAPI ENGINE                                  |
|  +--------------------+      +--------------------+      +-----------------+  |
|  | In-Memory Queue    | ---> | Telemetry          | ---> | Isolation       |  |
|  |                    |      | Normalizer         |      | Forest Anomaly  |  |
|  +--------------------+      +--------------------+      +-----------------+  |
|                                                                   |           |
|  +--------------------+      +--------------------+               v           |
|  | SSE Broadcast      | <--- | Connected Cluster  | <--- | NetworkX Graph  |  |
|  | & SSE Broadcaster  |      | Analysis (Campaign)|      | Linkage Engine  |  |
|  +---------+----------+      +---------+----------+      +-----------------+  |
+------------|---------------------------|--------------------------------------+
             |                           |
             | (SSE Event)               | (Triggers Engine)
             v                           v
+------------------------+   +-----------------------+   +----------------------+
| REACT Triages          |   | REMEDIATION ENGINE    |   | LLM COGNITIVE ENGINE |
| Analyst Dashboard      |   | [ Pod Isolation ]     |   | Groq Llama 3.3 70B   |
| (Interactive Feedback) |   | [ Network Blocklist ] |   | [ Intent / Mappings ]|
|                        |   | [ Node Cordoning ]    |   | [ NIST / MITRE / CIS]|
+------------------------+   +-----------------------+   +----------------------+
```

---

## 2. Telemetry Ingestion & Normalization

All events arrive at the `/api/ingest` endpoint. The `model/telemetry_normalizer.py` parses and maps various telemetry structures to a canonical schema:

### Canonical Event Schema
* `event_id` (UUID): Unique event identifier.
* `timestamp` (UTC ISO-8601): Event time.
* `log_type` (`k8s_audit` | `vpc_flow` | `cloudtrail`): Origin source.
* `severity` (`INFO` | `MEDIUM` | `HIGH` | `CRITICAL`): Calculated severity.
* `principal_id` (String): Username, ServiceAccount, or assumed role.
* `source_ip` (String): Originating IP address.
* `verb` (String): Action performed (e.g., `create`, `delete`, `AssumeRole`).
* `resource_name` (String): Kubernetes resource or AWS service identifier.
* `namespace` (String): Namespace context (for container events).
* `is_privileged` (Boolean/Int): Flag indicating privilege escalations or root-level actions.

---

## 3. Real-Time ML Anomaly Detection & Correlation

The Machine Learning engine in `model/ml_pipeline.py` runs as a singleton pipeline (`_LiveMLPipeline`):

### A. Anomaly Detection (Isolation Forest)
* Real-time events are evaluated using a pre-trained **Isolation Forest** model.
* The model computes an anomaly score based on features such as:
  * Rolling event counts per namespace
  * Privilege escalation attempts
  * Unknown principal identities
  * IP/CIDR deviations
* Scores are normalized to a `0-100` **Risk Score**:
  * Normal events scale between `0` and `40`.
  * Anomalous events scale between `50` and `100`.

### B. Graph-Based Incident Correlation (NetworkX)
* Normal and anomalous events are added to a rolling undirected graph.
* **Nodes**: Represent assets (Pods, IPs, Users).
* **Edges**: Built dynamically when events share identities, namespaces, or source IPs within a sliding time window.
* **Clustering**: Connected components identify coordinated campaign paths. If a component contains at least one anomalous event (Risk Score >= 80), it is clustered and emitted as an **Incident**.

---

## 4. Automated Response & Containment

When a clustered incident's overall risk score is classified as **CRITICAL** (Risk Score >= 80 and flagged as an anomaly), the `remediation.py` engine triggers immediate, concurrent containment protocols:

1. **Pod Isolation**: Modifies labels on target pods in Kubernetes to apply a zero-trust network policy and sever active ingress/egress connections.
2. **Network Quarantine**: Adds the offending principal's IP address to the active local blocklist (`quarantine_blocklist`).
3. **Node Cordoning**: Issues commands to mark the host Kubernetes node as unschedulable, stopping the threat from spawning replica containers.

---

## 5. Groq Llama-Powered AI Triage & Compliance Mapping

Upon incident generation, the backend dispatches raw telemetry events to the **Groq API** running `llama-3.3-70b-versatile` to perform deep analysis:

### A. Narrative Generation
The model builds a structured JSON triage report:
* **Intent Summary**: Clear narrative describing the attacker's likely objectives.
* **Evidence Correlation**: Explains why the behavioral pattern is anomalous.
* **Mitigation Recommendations**: Specific remediation playbooks.

### B. Regulatory Compliance Mappings
The LLM evaluates compliance violations and returns maps to:
* **NIST SP 800-53**: Control alignments (e.g., `CM-8` Component Inventory, `SI-4` System Monitoring, `IR-4` Incident Handling).
* **MITRE ATT&CK**: Technique IDs and Tactics (e.g., `T1578` Cloud Compute Infrastructure, `T1496` Resource Hijacking, `T1190` Exploits).
* **CIS Benchmarks**: Specific container and cloud benchmark references.

*Note: In the UI, these mappings render dynamically. If no controls are violated, the respective sections are completely hidden to avoid empty placeholders.*

---

## 6. Interactive Containment Feedback Loop

For critical incidents, a premium, zero-trust containment verification widget is displayed in the **Drill Down** modal. This establishes an analyst-in-the-loop control flow:

### ✔ Approve Containment
* Confirms the automated response was correct.
* Marks the incident as `resolved` in the database.
* Logs an `approve_containment` action to the Analyst Activity History log.
* Removes the incident card from active dashboards in real-time via Server-Sent Events (SSE).

### ✘ Disapprove & Rollback
* Analysts can reject the containment (e.g., due to a false-positive CI/CD workload) and input justification notes.
* Releases the blocklisted principal from the network quarantine.
* Logs a `rollback_containment` audit log entry with the analyst's justification notes.
* Marks the incident as `resolved` and filters it out of active dashboards.
* **Active Model Feedback Loop**: Updates the database `telemetry_timeline.scenario` to `scenario_4_false_positive` for the associated events, feeding directly back to correct future Isolation Forest training cycles.

---

## 7. API Reference

### A. Ingest Telemetry
* **Endpoint**: `POST /api/ingest`
* **Access**: Public
* **Payload**:
```json
{
  "source": "kubernetes",
  "timestamp": "2026-06-21T13:05:23Z",
  "action": "create",
  "resource_type": "Pod",
  "resource_name": "worker-29700735",
  "namespace": "ephemeral-test",
  "username": "system:serviceaccount:ephemeral-test:event-generator",
  "source_ip": "10.0.0.1"
}
```

### B. Submit Incident Feedback
* **Endpoint**: `POST /api/incidents/{incident_id}/feedback`
* **Access**: Authenticated (Analyst/Admin)
* **Payload**:
```json
{
  "feedback": "Remediation Approved" 
}
```
*or for disapprovals:*
```json
{
  "feedback": "Remediation Disapproved: Normal staging deployment script."
}
```

### C. Fetch Analyst Activity History
* **Endpoint**: `GET /api/action-logs`
* **Access**: Authenticated (Admin)
* **Response**: Returns a chronological audit log of approvals, rollbacks, and overrides.
