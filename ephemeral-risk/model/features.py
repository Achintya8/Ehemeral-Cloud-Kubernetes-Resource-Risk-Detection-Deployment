"""
features.py
===========
Behavioral feature engineering for the Ephemeral Cloud Risk Detection system.

Public API
----------
    calculate_behavioral_features(db_path="data/events.db") -> pd.DataFrame

    Returns one row per telemetry event, augmented with five numeric/binary
    ML-ready feature columns computed via 5-minute per-identity rolling windows:

        is_night_time          int8   [0,1]   Event in UTC 00:00–06:00
        rolling_burst_count    int    [1,∞)   # events by same identity in past 5 min
        is_privileged_pod      int8   [0,1]   K8s is_privileged = 1
        untrusted_network_hit  int8   [0,1]   Traffic to/from untrusted CIDRs or bad IPs
        missing_tags_score     int8   [0,3]   Governance deficit score

All structural NaN values (cross-table JOIN gaps) are filled with 0 / "".

Requires: sqlite3, pandas, numpy
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd
from model.telemetry_normalizer import normalize_many

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

ROOT    = Path(__file__).resolve().parent
DB_PATH = str(ROOT / "data" / "events.db")

AWS_ACCOUNT_ID = "123456789012"

INTERNAL_IP_PREFIXES: tuple[str, ...] = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.",
)

KNOWN_BAD_IPS = frozenset({
    "185.220.101.47", "45.142.212.100", "91.108.4.200",
    "198.51.100.77",  "203.0.113.200",  "192.0.2.99",
})

CORP_NAT_IPS = frozenset({"203.0.113.10", "203.0.113.11", "203.0.113.55"})

VALID_ARN_PREFIXES: tuple[str, ...] = (
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/ProdDeployRole",
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/CICDRole",
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/svc-metrics",
    f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/ProdDeployRole/",
    f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/CICDRole/",
    f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/dev-alice",
)

# Explicit, well-known CI/CD and control-plane service accounts. These are
# treated as trusted WITHOUT needing to match a pattern below.
VALID_IDENTITIES = frozenset({
    "ci-runner-svc", "github-actions-svc", "jenkins-deployer",
    "devops-pipeline", "argocd-svc", "flux-controller",
    "hpa-controller", "kube-scheduler", "metrics-server",
    "svc-metrics", "dev-alice",
    # Kubernetes control-plane / well-known system identities
    "kube-system", "system", "k8s-watcher",
    "system:anonymous",
})

# Suffix / prefix patterns that mark an identity as a legitimate cluster or
# automation principal. Any matching identity is considered trusted, so that
# ordinary-but-unfamiliar service accounts (e.g. a per-namespace event
# generator or a controller we haven't enumerated) are NOT auto-flagged as
# "unknown identity" — which was the main source of false-positive anomalies.
TRUSTED_IDENTITY_PATTERNS: tuple[str, ...] = (
    "system:",            # system:serviceaccount:..., system:kube-scheduler, ...
    "system-",            # system-controllers, etc.
    "-controller",
    "-scheduler",
    "-operator",
    "-autoscaler",
    "-agent",
    "serviceaccount",
    "service-account",
    "kube-",
)

# Namespaces that are considered legitimate. Expanded to include the system /
# infra namespaces real clusters run (previously only production/staging/etc.
# were whitelisted, which made every kube-system / ephemeral-test pod trip
# missing_tags_score).
VALID_NAMESPACES = frozenset({
    "production", "staging", "monitoring", "kube-system", "infra",
    "default", "ephemeral-test", "local-path-storage",
    "kube-public", "kube-node-lease",
})

# Namespace patterns that imply a system-managed workload, trusted by default.
TRUSTED_NAMESPACE_PATTERNS: tuple[str, ...] = (
    "kube-", "local-path-", "ephemeral-", "monitoring-", "ingress-",
)


def _is_trusted_identity(identity: str) -> bool:
    """An identity is trusted if it's explicitly whitelisted OR matches a
    controller / system / automation pattern. Unknown human-style identities
    still fall through and get scored normally."""
    if not identity:
        return False
    ident = str(identity).strip().lower()
    if ident in VALID_IDENTITIES:
        return True
    return any(pattern in ident for pattern in TRUSTED_IDENTITY_PATTERNS)


def _is_trusted_namespace(namespace: str) -> bool:
    """A namespace is trusted if explicitly whitelisted OR matches a system
    / infra pattern."""
    if not namespace:
        return False
    ns = str(namespace).strip().lower()
    if ns in VALID_NAMESPACES:
        return True
    return any(pattern in ns for pattern in TRUSTED_NAMESPACE_PATTERNS)

FEATURE_COLS = [
    "is_night_time",
    "rolling_burst_count",
    "is_privileged_pod",
    "untrusted_network_hit",
    "missing_tags_score",
    # v2 additions
    "vpc_bytes_log",       # log10(bytes+1) — flags large exfiltration volumes
    "is_unknown_identity", # 1 if principal not in known-good whitelist
    # v3 additions from original cloud/K8s/session metadata
    "public_service_exposure",
    "rbac_escalation",
    "missing_controller_owner",
    "weak_label_score",
    "weak_tag_score",
    "suspicious_session",
    "long_token_ttl",
]

MODEL_FEATURE_COLS = [
    "is_night_time",
    "rolling_burst_count",
    "is_privileged_pod",
    "untrusted_network_hit",
    "missing_tags_score",
    "vpc_bytes_log",
    "is_unknown_identity",
    "public_service_exposure",
    "rbac_escalation",
    "missing_controller_owner",
    "weak_label_score",
    "weak_tag_score",
    "suspicious_session",
    "long_token_ttl",
]

NIGHT_START  = 0
NIGHT_END    = 6
BURST_WINDOW = "5min"


# ──────────────────────────────────────────────────────────────────────────────
# DATA LOADING
# ──────────────────────────────────────────────────────────────────────────────

def _load_flat(db_path: str) -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        conn.close()

    cloud_meta_join = ""
    cloud_meta_cols = """
            '' AS tags_json,
            '' AS request_parameters_json,
            '' AS user_agent,
    """
    if "cloudtrail_event_metadata" in tables:
        cloud_meta_join = "LEFT JOIN cloudtrail_event_metadata cm ON cm.event_id = t.event_id"
        cloud_meta_cols = """
            cm.tags_json,
            cm.request_parameters_json,
            cm.user_agent,
        """

    k8s_meta_join = ""
    k8s_meta_cols = """
            '' AS labels_json,
            '' AS controller_owner,
            '' AS service_type,
            '' AS rbac_change,
    """
    if "k8s_event_metadata" in tables:
        k8s_meta_join = "LEFT JOIN k8s_event_metadata km ON km.event_id = t.event_id"
        k8s_meta_cols = """
            km.labels_json,
            km.controller_owner,
            km.service_type,
            km.rbac_change,
        """

    identity_join = ""
    identity_cols = """
            '' AS session_type,
            '' AS session_name,
            '' AS issuer,
            0 AS token_ttl_seconds
    """
    if "identity_session_events" in tables:
        identity_join = "LEFT JOIN identity_session_events i ON i.event_id = t.event_id"
        identity_cols = """
            i.session_type,
            i.session_name,
            i.issuer,
            i.token_ttl_seconds
        """

    sql = """
        SELECT
            t.event_id,
            t.timestamp,
            t.log_type,
            t.severity,
            t.scenario,
            c.event_source,
            c.event_name,
            c.principal_id,
            c.arn,
            c.source_ip,
            k.verb,
            k.resource_name,
            k.namespace,
            k.username,
            k.pod_ip,
            k.is_privileged,
            v.src_addr,
            v.dst_addr,
            v.src_port,
            v.dst_port,
            v.bytes    AS vpc_bytes,
            v.action   AS vpc_action,
{cloud_meta_cols}
{k8s_meta_cols}
{identity_cols}
        FROM  telemetry_timeline t
        LEFT JOIN cloudtrail_events c ON c.event_id = t.event_id
        LEFT JOIN k8s_audit_events  k ON k.event_id = t.event_id
        LEFT JOIN vpc_flow_logs     v ON v.event_id = t.event_id
        {cloud_meta_join}
        {k8s_meta_join}
        {identity_join}
        ORDER BY t.timestamp ASC
    """.format(
        cloud_meta_cols=cloud_meta_cols.rstrip(),
        k8s_meta_cols=k8s_meta_cols.rstrip(),
        identity_cols=identity_cols.rstrip(),
        cloud_meta_join=cloud_meta_join,
        k8s_meta_join=k8s_meta_join,
        identity_join=identity_join,
    )
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(sql, conn, parse_dates=["timestamp"])
    finally:
        conn.close()

    if df["timestamp"].dt.tz is None:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)

    return df


# ──────────────────────────────────────────────────────────────────────────────
# UNIFIED IDENTITY COLUMN
# ──────────────────────────────────────────────────────────────────────────────

def _build_identity(df: pd.DataFrame) -> pd.Series:
    principal = df["principal_id"] if "principal_id" in df.columns else pd.Series("", index=df.index)
    username = df["username"] if "username" in df.columns else pd.Series("", index=df.index)
    identity = principal.fillna("")
    identity = identity.mask(identity.astype(str).str.strip() == "", username.fillna(""))
    identity = identity.mask(identity.astype(str).str.strip() == "", "<unknown>")
    return identity.astype(str).str.strip()


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: is_night_time
# ──────────────────────────────────────────────────────────────────────────────

def _feature_is_night_time(df: pd.DataFrame) -> pd.Series:
    hour = df["timestamp"].dt.hour
    return ((hour >= NIGHT_START) & (hour < NIGHT_END)).astype(np.int8)


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: rolling_burst_count
# ──────────────────────────────────────────────────────────────────────────────

def _feature_rolling_burst_count(df: pd.DataFrame) -> pd.Series:
    work = df[["timestamp", "identity", "event_id"]].copy()
    work["_orig_idx"] = work.index

    valid = work.dropna(subset=["timestamp"]).copy()
    valid = valid.set_index("timestamp").sort_index()

    counts = (
        valid.groupby("identity", group_keys=False)["event_id"]
        .transform(lambda s: s.rolling(BURST_WINDOW, closed="right").count())
    )

    valid["_burst"] = counts.values
    orig_to_burst = valid.set_index("_orig_idx")["_burst"]
    return orig_to_burst.reindex(df.index).fillna(1).astype(int)


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: is_privileged_pod
# ──────────────────────────────────────────────────────────────────────────────

def _feature_is_privileged_pod(df: pd.DataFrame) -> pd.Series:
    return df["is_privileged"].fillna(0).astype(np.int8)


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: untrusted_network_hit
# ──────────────────────────────────────────────────────────────────────────────

def _ip_is_internal(ip: str) -> bool:
    if not ip or ip != ip:
        return True
    return ip.startswith(INTERNAL_IP_PREFIXES)


def _feature_untrusted_network_hit(df: pd.DataFrame) -> pd.Series:
    result = pd.Series(0, index=df.index, dtype=np.int8)

    m = df["log_type"] == "vpc_flow"
    if m.any():
        v = df.loc[m]
        result.loc[m] = (
            ~v["dst_addr"].apply(_ip_is_internal)
            | ~v["src_addr"].apply(_ip_is_internal)
            | v["dst_addr"].isin(KNOWN_BAD_IPS)
            | v["src_addr"].isin(KNOWN_BAD_IPS)
        ).astype(np.int8)

    m = df["log_type"] == "k8s_audit"
    if m.any():
        k = df.loc[m]
        # NOTE: previously `namespace == "default"` was treated as an untrusted
        # network hit. That is not a network-trust signal and it inflated the
        # anomaly score of every pod in the default namespace. We now only
        # flag genuine external pod IPs.
        result.loc[m] = (~k["pod_ip"].apply(_ip_is_internal)).astype(np.int8)

    m = df["log_type"] == "cloudtrail"
    if m.any():
        c = df.loc[m]
        result.loc[m] = (
            (
                ~c["source_ip"].apply(_ip_is_internal)
                & ~c["source_ip"].isin(CORP_NAT_IPS)
            )
            | c["source_ip"].isin(KNOWN_BAD_IPS)
        ).astype(np.int8)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: missing_tags_score
# ──────────────────────────────────────────────────────────────────────────────

def _feature_missing_tags_score(df: pd.DataFrame) -> pd.Series:
    score = pd.Series(0, index=df.index, dtype=np.int8)

    m_ct = df["log_type"] == "cloudtrail"
    if m_ct.any():
        arns = df.loc[m_ct, "arn"].fillna("")
        score.loc[m_ct] += (~arns.apply(
            lambda a: any(a.startswith(p) for p in VALID_ARN_PREFIXES)
        )).astype(np.int8)

    # Penalise genuinely unknown identities, but NOT recognised cluster /
    # automation principals (controllers, schedulers, system:* accounts).
    score += (~df["identity"].apply(_is_trusted_identity)).astype(np.int8)

    m_k8s = df["log_type"] == "k8s_audit"
    if m_k8s.any():
        ns = df.loc[m_k8s, "namespace"].fillna("")
        score.loc[m_k8s] += (~ns.apply(_is_trusted_namespace)).astype(np.int8)

    return score


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: vpc_bytes_log  (NEW v2)
# ──────────────────────────────────────────────────────────────────────────────

def _feature_vpc_bytes_log(df: pd.DataFrame) -> pd.Series:
    """
    Log10-scaled volume of VPC bytes transferred.

    Why: Scenario 2 (debug pod) exfiltrates 10-50 MB; Scenario 3 (identity
    leak) moves 100 KB–5 MB per S3 GET. Normal CI/CD traffic is <65 KB.
    A logarithmic scale keeps the feature well-behaved for IsolationForest.
    Non-VPC events get 0.
    """
    result = pd.Series(0.0, index=df.index, dtype=np.float64)
    m = df["log_type"] == "vpc_flow"
    if m.any():
        bytes_col = pd.to_numeric(df.loc[m, "vpc_bytes"], errors="coerce").fillna(0.0)
        result.loc[m] = np.log10(bytes_col + 1.0)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE: is_unknown_identity  (NEW v2)
# ──────────────────────────────────────────────────────────────────────────────

def _feature_is_unknown_identity(df: pd.DataFrame) -> pd.Series:
    """
    Binary flag: 1 if the acting identity is NOT recognised.

    An identity is recognised if it's explicitly whitelisted OR matches a
    trusted controller / system / automation pattern (system:*,
    *-controller, *-scheduler, *-operator, kube-*, serviceaccount, ...).
    This keeps genuinely foreign principals (e.g. `svc-datapipeline-legacy`
    from Scenario 1) flagged while no longer auto-flagging every real
    cluster service account.
    """
    return (~df["identity"].apply(_is_trusted_identity)).astype(np.int8)


def _parse_json_object(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if not value or value != value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _feature_public_service_exposure(df: pd.DataFrame) -> pd.Series:
    service = df.get("service_type", pd.Series("", index=df.index)).fillna("").str.lower()
    return service.isin({"nodeport", "loadbalancer"}).astype(np.int8)


def _feature_rbac_escalation(df: pd.DataFrame) -> pd.Series:
    rbac = df.get("rbac_change", pd.Series("", index=df.index)).fillna("").str.lower()
    verb = df.get("verb", pd.Series("", index=df.index)).fillna("").str.lower()
    risky = (
        rbac.str.contains("cluster-admin|impersonate|token|rolebinding", regex=True)
        | verb.isin({"create-token", "bind", "escalate"})
    )
    return risky.astype(np.int8)


def _feature_missing_controller_owner(df: pd.DataFrame) -> pd.Series:
    result = pd.Series(0, index=df.index, dtype=np.int8)
    m = df["log_type"] == "k8s_audit"
    if m.any():
        owner = df.loc[m].get("controller_owner", pd.Series("", index=df.loc[m].index))
        verb = df.loc[m, "verb"].fillna("").str.lower()
        result.loc[m] = ((owner.fillna("").str.strip() == "") & verb.isin({"create", "patch"})).astype(np.int8)
    return result


def _feature_weak_label_score(df: pd.DataFrame) -> pd.Series:
    result = pd.Series(0, index=df.index, dtype=np.int8)
    m = df["log_type"] == "k8s_audit"
    required = {"app", "managed-by", "owner", "env"}
    if m.any():
        values = df.loc[m].get("labels_json", pd.Series("", index=df.loc[m].index))
        result.loc[m] = values.apply(
            lambda raw: max(0, len(required - set(_parse_json_object(raw).keys())))
        ).clip(0, 4).astype(np.int8)
    return result


def _feature_weak_tag_score(df: pd.DataFrame) -> pd.Series:
    result = pd.Series(0, index=df.index, dtype=np.int8)
    m = df["log_type"] == "cloudtrail"
    required = {"Owner", "Environment", "Application", "ManagedBy"}
    if m.any():
        values = df.loc[m].get("tags_json", pd.Series("", index=df.loc[m].index))
        result.loc[m] = values.apply(
            lambda raw: max(0, len(required - set(_parse_json_object(raw).keys())))
        ).clip(0, 4).astype(np.int8)
    return result


def _feature_suspicious_session(df: pd.DataFrame) -> pd.Series:
    result = pd.Series(0, index=df.index, dtype=np.int8)
    session_type = df.get("session_type", pd.Series("", index=df.index)).fillna("").str.lower()
    issuer = df.get("issuer", pd.Series("", index=df.index)).fillna("").str.lower()
    event_name = df.get("event_name", pd.Series("", index=df.index)).fillna("").str.lower()
    result = (
        session_type.isin({"service_account_token", "federation"})
        & (
            ~df["identity"].apply(_is_trusted_identity)
            | issuer.str.contains("github|eks", regex=True)
            | event_name.isin({"assumerolewithwebidentity", "assumerole"})
        )
    ).astype(np.int8)
    return result


def _feature_long_token_ttl(df: pd.DataFrame) -> pd.Series:
    ttl = pd.to_numeric(
        df.get("token_ttl_seconds", pd.Series(0, index=df.index)),
        errors="coerce",
    ).fillna(0)
    return (ttl > 1800).astype(np.int8)


# ──────────────────────────────────────────────────────────────────────────────
# STRUCTURAL NULL FILL
# ──────────────────────────────────────────────────────────────────────────────

def _fill_structural_nulls(df: pd.DataFrame) -> pd.DataFrame:
    numeric = [
        "is_privileged", "src_port", "dst_port", "vpc_bytes",
        "token_ttl_seconds",
        *FEATURE_COLS,
    ]
    strings = [
        "event_source", "event_name", "principal_id", "arn", "source_ip",
        "verb", "resource_name", "namespace", "username", "pod_ip",
        "src_addr", "dst_addr", "vpc_action",
        "tags_json", "request_parameters_json", "user_agent",
        "labels_json", "controller_owner", "service_type", "rbac_change",
        "session_type", "session_name", "issuer",
    ]
    for col in numeric:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    for col in strings:
        if col in df.columns:
            df[col] = df[col].fillna("")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def calculate_behavioral_features(db_path: str = DB_PATH) -> pd.DataFrame:
    """
    Load all telemetry events from *db_path* and return a feature-enriched
    DataFrame suitable for ML.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database (default: data/events.db).

    Returns
    -------
    pd.DataFrame
        Chronologically sorted, one row per event, with columns:
        [raw event columns] + [identity] + FEATURE_COLS
    """
    db_path = str(Path(db_path).resolve())

    df = _load_flat(db_path)
    df["identity"] = _build_identity(df)

    df["is_night_time"]         = _feature_is_night_time(df)
    df["rolling_burst_count"]   = _feature_rolling_burst_count(df)
    df["is_privileged_pod"]     = _feature_is_privileged_pod(df)
    df["untrusted_network_hit"] = _feature_untrusted_network_hit(df)
    df["missing_tags_score"]    = _feature_missing_tags_score(df)
    # v2 additions
    df["vpc_bytes_log"]         = _feature_vpc_bytes_log(df)
    df["is_unknown_identity"]   = _feature_is_unknown_identity(df)
    df["public_service_exposure"] = _feature_public_service_exposure(df)
    df["rbac_escalation"]       = _feature_rbac_escalation(df)
    df["missing_controller_owner"] = _feature_missing_controller_owner(df)
    df["weak_label_score"]      = _feature_weak_label_score(df)
    df["weak_tag_score"]        = _feature_weak_tag_score(df)
    df["suspicious_session"]    = _feature_suspicious_session(df)
    df["long_token_ttl"]        = _feature_long_token_ttl(df)

    df = _fill_structural_nulls(df)
    return df.reset_index(drop=True)


# ──────────────────────────────────────────────────────────────────────────────
# IN-MEMORY EVENT PATH (for live streaming pipeline)
# ──────────────────────────────────────────────────────────────────────────────

def calculate_features_from_events(events: list[dict]) -> pd.DataFrame:
    """
    Compute behavioral features from a list of in-memory event dicts (the
    live-streaming schema produced by _LiveMLPipeline._normalize_event).

    This is the in-memory counterpart of ``calculate_behavioral_features``
    which reads from SQLite.

    Parameters
    ----------
    events : list[dict]
        Normalised event dictionaries, each containing at least:
        event_id, timestamp, log_type, identity (or principal_id/username),
        source_ip, pod_ip, namespace, is_privileged, resource_name, and
        any VPC / tag fields present in the offline schema.

    Returns
    -------
    pd.DataFrame
        Feature-enriched DataFrame with FEATURE_COLS + identity column.
    """
    if not events:
        return pd.DataFrame(columns=[
            "event_id", "timestamp", "log_type", "severity", "scenario",
            "event_source", "event_name", "principal_id", "arn", "source_ip",
            "verb", "resource_name", "namespace", "username", "pod_ip",
            "is_privileged", "src_addr", "dst_addr", "src_port", "dst_port",
            "vpc_bytes", "vpc_action", "tags_json", "request_parameters_json",
            "user_agent", "labels_json", "controller_owner", "service_type",
            "rbac_change", "session_type", "session_name", "issuer",
            "token_ttl_seconds", "identity",
            *FEATURE_COLS,
        ])

    df = pd.DataFrame(normalize_many(events))

    # ── Ensure the columns expected by downstream feature helpers exist ──
    # Map alternate field names that the live normaliser may produce
    for col in ("event_id", "timestamp", "log_type", "severity", "scenario",
                "event_source", "event_name", "principal_id", "arn", "source_ip",
                "verb", "resource_name", "namespace", "username", "pod_ip",
                "tags_json", "request_parameters_json", "user_agent",
                "labels_json", "controller_owner", "service_type", "rbac_change",
                "session_type", "session_name", "issuer"):
        if col not in df.columns:
            df[col] = ""

    for col in ("is_privileged", "src_port", "dst_port", "vpc_bytes", "token_ttl_seconds"):
        if col not in df.columns:
            df[col] = 0

    for col in ("src_addr", "dst_addr", "vpc_action"):
        if col not in df.columns:
            df[col] = ""

    if "identity" not in df.columns:
        df["identity"] = _build_identity(df)
    else:
        fallback_identity = _build_identity(df)
        df["identity"] = df["identity"].fillna(fallback_identity)
        df["identity"] = df["identity"].mask(df["identity"].astype(str).str.strip() == "", fallback_identity)

    # Parse timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Fill structural nulls first so feature helpers see clean data
    df = _fill_structural_nulls(df)

    # ── Compute all features using the same helpers as the DB path ──
    df["is_night_time"]         = _feature_is_night_time(df)
    df["rolling_burst_count"]   = _feature_rolling_burst_count(df)
    df["is_privileged_pod"]     = _feature_is_privileged_pod(df)
    df["untrusted_network_hit"] = _feature_untrusted_network_hit(df)
    df["missing_tags_score"]    = _feature_missing_tags_score(df)
    df["vpc_bytes_log"]         = _feature_vpc_bytes_log(df)
    df["is_unknown_identity"]   = _feature_is_unknown_identity(df)
    df["public_service_exposure"] = _feature_public_service_exposure(df)
    df["rbac_escalation"]       = _feature_rbac_escalation(df)
    df["missing_controller_owner"] = _feature_missing_controller_owner(df)
    df["weak_label_score"]      = _feature_weak_label_score(df)
    df["weak_tag_score"]        = _feature_weak_tag_score(df)
    df["suspicious_session"]    = _feature_suspicious_session(df)
    df["long_token_ttl"]        = _feature_long_token_ttl(df)

    return df.reset_index(drop=True)
