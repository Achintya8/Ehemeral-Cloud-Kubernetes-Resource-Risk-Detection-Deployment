export function fmt(ts) {
  const d = new Date(ts);
  return isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString([], { hour12: false });
}

export function decodeJWT(token) {
  try {
    const payload = token.split(".")[1];
    const norm = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = norm.padEnd(norm.length + ((4 - norm.length % 4) % 4), "=");
    return JSON.parse(atob(padded));
  } catch { return null; }
}

export function normaliseIncident(raw) {
  let inc = null;
  if (raw?.correlated_evidence && Array.isArray(raw?.clear_actions)) {
    inc = { ...raw };
  } else if (raw?.report_text) {
    try {
      const parsed = JSON.parse(raw.report_text);
      if (parsed?.correlated_evidence) {
        inc = { ...raw, ...parsed };
      }
    } catch {}
  }
  
  if (!inc) {
    inc = {
      incident_id:         raw?.incident_id || raw?.cluster_id || raw?.event_id || crypto.randomUUID(),
      severity:            String(raw?.severity || "MEDIUM").toUpperCase(),
      risk_score:          Number(raw?.risk_score || 50),
      correlated_evidence: {
        who:       raw?.actor || raw?.username || "Identity unavailable",
        what:      raw?.pod_name || raw?.resource_name || raw?.resource || `${raw?.resource_count || 0} correlated resource(s)`,
        when:      raw?.timestamp || raw?.created_at || "Unknown",
        where:     (raw?.namespace ? `Namespace: ${raw.namespace}` : "") + (raw?.source_ip ? ` | Source: ${raw.source_ip}` : "") || raw?.pivot_ip || "Unknown",
        why_risky: raw?.why_risky || "Raw anomaly detected. Downstream correlation unavailable.",
      },
      clear_actions: ["Contain Pods", "Revoke Credentials", "Enforce Network Guardrails"],
    };
  }

  inc.incident_id = inc.incident_id || inc.cluster_id || raw?.event_id || crypto.randomUUID();
  inc.risk_score = Number(inc.risk_score || 0);
  inc.severity = String(inc.severity || (inc.risk_score > 80 ? "CRITICAL" : "HIGH")).toUpperCase();
  inc.pod_name = inc.pod_name || raw?.pod_name || raw?.resource_name || raw?.resource || "unknown-pod";
  inc.namespace = inc.namespace || raw?.namespace || "default";

  return inc;
}

export function sevStyle(sev) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL") return { card: "sev-critical", badge: "badge-critical", score: "sev-critical" };
  if (s === "HIGH")     return { card: "sev-high",     badge: "badge-high",     score: "sev-high" };
  if (s === "MEDIUM")   return { card: "sev-medium",   badge: "badge-medium",   score: "sev-medium" };
  return                       { card: "sev-info",     badge: "badge-info",     score: "sev-info" };
}
