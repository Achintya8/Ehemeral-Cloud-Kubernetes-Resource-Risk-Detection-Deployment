-- schema.sql
-- ============================================================================
-- SQLite DDL for the Ephemeral Cloud / Kubernetes Risk Detection system.
-- Four normalised tables share a single timeline index (telemetry_timeline).
-- Run once at startup; every CREATE uses IF NOT EXISTS for idempotency.
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ─────────────────────────────────────────────────────────────────────────────
-- CORE TIMELINE INDEX
-- Every event in the system, regardless of log type, is registered here first.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS telemetry_timeline (
    event_id  TEXT    PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    log_type  TEXT    NOT NULL CHECK (log_type IN ('cloudtrail', 'k8s_audit', 'vpc_flow')),
    severity  TEXT    NOT NULL CHECK (severity  IN ('INFO', 'HIGH', 'CRITICAL')),
    scenario  TEXT    NOT NULL DEFAULT 'baseline'
        CHECK (scenario IN (
            'baseline',
            'scenario_1_crypto_mining',
            'scenario_2_debug_pod',
            'scenario_3_identity_leak',
            'scenario_4_false_positive',
            'live_stream',
            'live_cloudtrail',
            'live_kubernetes',
            'live_network',
            'live_cicd',
            'live_ephemeral_compute'
        ))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- AWS CLOUDTRAIL EVENTS
-- Records IAM / STS / EC2 / S3 / EKS API calls observed via CloudTrail.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cloudtrail_events (
    event_id     TEXT NOT NULL,
    event_source TEXT NOT NULL,     -- e.g. ec2.amazonaws.com
    event_name   TEXT NOT NULL,     -- e.g. RunInstances
    principal_id TEXT NOT NULL,     -- IAM user / role short name
    arn          TEXT NOT NULL,     -- full IAM ARN of the caller
    source_ip    TEXT NOT NULL,     -- originating IP address
    FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- KUBERNETES AUDIT EVENTS
-- Records kubectl / controller actions captured by the K8s audit log.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS k8s_audit_events (
    event_id      TEXT    NOT NULL,
    verb          TEXT    NOT NULL,     -- create | delete | get | scale-up | scale-down
    resource_name TEXT    NOT NULL,     -- pod / deployment name
    namespace     TEXT    NOT NULL,     -- K8s namespace
    username      TEXT    NOT NULL,     -- K8s subject (service-account or user)
    pod_ip        TEXT    NOT NULL,     -- pod IP at time of event
    is_privileged INTEGER NOT NULL DEFAULT 0 CHECK (is_privileged IN (0, 1)),
    FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- VPC FLOW LOGS
-- Network-level packet metadata from the AWS VPC flow log stream.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vpc_flow_logs (
    event_id TEXT    NOT NULL,
    src_addr TEXT    NOT NULL,
    dst_addr TEXT    NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    bytes    INTEGER NOT NULL,
    action   TEXT    NOT NULL CHECK (action IN ('ACCEPT', 'REJECT')),
    FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- OPTIONAL METADATA SIDECARS
-- These preserve production fields that do not fit the compact v1 tables.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cloudtrail_event_metadata (
    event_id TEXT PRIMARY KEY,
    tags_json TEXT NOT NULL DEFAULT '',
    request_parameters_json TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS k8s_event_metadata (
    event_id TEXT PRIMARY KEY,
    labels_json TEXT NOT NULL DEFAULT '',
    controller_owner TEXT NOT NULL DEFAULT '',
    service_type TEXT NOT NULL DEFAULT '',
    rbac_change TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS identity_session_events (
    event_id TEXT PRIMARY KEY,
    session_type TEXT NOT NULL DEFAULT '',
    session_name TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT '',
    token_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (event_id) REFERENCES telemetry_timeline (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- PERFORMANCE INDEXES
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tt_timestamp  ON telemetry_timeline (timestamp);
CREATE INDEX IF NOT EXISTS idx_tt_log_type   ON telemetry_timeline (log_type);
CREATE INDEX IF NOT EXISTS idx_tt_severity   ON telemetry_timeline (severity);
CREATE INDEX IF NOT EXISTS idx_tt_scenario   ON telemetry_timeline (scenario);

CREATE INDEX IF NOT EXISTS idx_ct_event_name ON cloudtrail_events  (event_name);
CREATE INDEX IF NOT EXISTS idx_ct_principal  ON cloudtrail_events  (principal_id);
CREATE INDEX IF NOT EXISTS idx_ct_source_ip  ON cloudtrail_events  (source_ip);

CREATE INDEX IF NOT EXISTS idx_k8s_namespace ON k8s_audit_events   (namespace);
CREATE INDEX IF NOT EXISTS idx_k8s_priv      ON k8s_audit_events   (is_privileged);
CREATE INDEX IF NOT EXISTS idx_k8s_username  ON k8s_audit_events   (username);

CREATE INDEX IF NOT EXISTS idx_vpc_dst_addr  ON vpc_flow_logs      (dst_addr);
CREATE INDEX IF NOT EXISTS idx_vpc_src_addr  ON vpc_flow_logs      (src_addr);
CREATE INDEX IF NOT EXISTS idx_vpc_action    ON vpc_flow_logs      (action);
