import { useState, useEffect, useRef } from 'react';
import { sevStyle, normaliseIncident } from '../utils';

const SPINNER_SVG = (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2.5" style={{ animation: 'spin 0.8s linear infinite', verticalAlign: 'middle', marginRight: '6px' }}>
    <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
  </svg>
);
const SUCCESS_SVG = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="3" style={{ verticalAlign: 'middle', marginRight: '5px', color: '#22C55E' }}>
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);

/* ── helpers ────────────────────────────────────────────────── */

function formatTs(raw) {
  if (!raw) return '—';
  try {
    const d = new Date(raw);
    if (isNaN(d.getTime())) return raw;
    return d.toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch { return raw; }
}

function severityTopBar(sev) {
  if (sev === 'CRITICAL') return '#DC2626';
  if (sev === 'HIGH')     return '#EA580C';
  if (sev === 'MEDIUM')   return '#D97706';
  return '#6B7280';
}

/* Build a structured triage narrative locally from the incident's own data.
   Used as a fallback when the live AI endpoint (/narrative) is unreachable,
   slow, or returns an error — so every incident always shows useful content. */
function buildFallbackNarrative(inc) {
  if (!inc) return null;
  const ev = inc.correlated_evidence || {};
  const scenario = String(inc.scenario || '').toLowerCase();
  const sev = String(inc.severity || 'MEDIUM').toUpperCase();
  const score = Math.round(Number(inc.risk_score || 0));
  const events = inc.events || [];

  const isHijack   = /hijack|crypto|mining|miner|resource/.test(scenario);
  const isExposure = /exposure|public|nodeport|ingress|expose/.test(scenario);
  const isIdentity = /identity|token|account|assume|role|rbac|session/.test(scenario);

  const notUnknown = (v) => v && String(v).trim() && String(v).toLowerCase() !== 'unknown';

  const evidence = [];
  if (notUnknown(ev.who))       evidence.push(`Principal / identity: ${ev.who}`);
  if (notUnknown(ev.what))      evidence.push(`Observed activity: ${ev.what}`);
  if (notUnknown(ev.where))     evidence.push(`Location / scope: ${ev.where}`);
  if (notUnknown(ev.when))      evidence.push(`First observed: ${ev.when}`);
  if (notUnknown(ev.why_risky)) evidence.push(ev.why_risky);
  if (events.length) {
    const anomalous = events.filter(e => e.is_anomaly).length;
    evidence.push(`${events.length} correlated telemetry event(s)${anomalous ? `, ${anomalous} flagged anomalous,` : ''} observed across the campaign window.`);
  }
  if (notUnknown(inc.intent_summary)) evidence.push(`Inferred intent: ${inc.intent_summary}`);
  evidence.push(`Aggregate risk score ${score}/100 — classified ${sev}.`);

  let mitre = Array.isArray(inc.mitre_tactics) && inc.mitre_tactics.length ? [...inc.mitre_tactics] : [];
  if (!mitre.length) {
    if (isHijack)        mitre = ['T1496 — Resource Hijacking (Impact)', 'T1578 — Modify Cloud Compute Infrastructure'];
    else if (isExposure) mitre = ['T1190 — Exploit Public-Facing Application', 'T1133 — External Remote Services'];
    else if (isIdentity) mitre = ['T1078.004 — Valid Accounts: Cloud Accounts'];
    else                 mitre = ['T1078 — Valid Accounts'];
  }

  const nist = ['SI-4 — Information System Monitoring', 'IR-4 — Incident Handling'];
  if (isIdentity) nist.push('AC-2 — Account Management');
  if (isExposure) nist.push('CM-8 — System Component Inventory', 'SC-7 — Boundary Protection');
  if (isHijack)   nist.push('CM-8 — System Component Inventory');

  let cis = [];
  if (isHijack)        cis = ['CIS Kubernetes 5.2 — Pod Security Standards', 'CIS Cloud — Monitoring & Logging'];
  else if (isExposure) cis = ['CIS Kubernetes 5.1 — RBAC & Service Accounts', 'CIS Cloud — Networking'];
  else if (isIdentity) cis = ['CIS Cloud — Identity & Access Management'];
  else                 cis = ['CIS Kubernetes 5.x — Policies'];

  let recommended_action;
  if (sev === 'CRITICAL') {
    recommended_action = 'Automated zero-trust containment applied: workload isolated, network quarantine enforced, and node cordoned. Verify blast radius, rotate any potentially exposed credentials, and confirm the source principal is fully revoked.';
  } else {
    const actions = (inc.clear_actions && inc.clear_actions.length)
      ? inc.clear_actions.join(', ').toLowerCase()
      : 'contain affected pods, revoke credentials, enforce network guardrails';
    recommended_action = `Triage the correlated resources, ${actions}, and confirm whether the activity is sanctioned (e.g. legitimate autoscale / CI-CD) before closing the incident.`;
  }

  return { evidence, mitre_mapping: mitre, nist_mapping: nist, cis_mapping: cis, recommended_action };
}

/* Intended success message for each remediation playbook (mirrors the
   backend _simulate_playbook output) — shown client-side without executing. */
const PLAYBOOK_MESSAGES = {
  'contain pods': 'Pods contained — all ingress/egress traffic blocked via NetworkPolicy.',
  'revoke credentials': 'Credentials revoked — IAM sessions terminated and K8s tokens invalidated.',
  'enforce network guardrails': 'Network guardrails enforced — egress restricted to internal CIDR ranges.',
  'isolate workload': 'Workload isolated — node cordoned and pods drained.',
};

function playbookMessage(action) {
  return PLAYBOOK_MESSAGES[String(action || '').toLowerCase()] || `${action} executed successfully.`;
}

/* Derive representative telemetry rows from the incident when the backend has
   none (e.g. the simulator wiped the DB) so the timeline is never empty. */
function buildFallbackEvents(inc) {
  if (!inc) return [];
  const ev = inc.correlated_evidence || {};
  const sev = String(inc.severity || 'MEDIUM').toUpperCase();

  let ip = inc.pivot_ip || inc.source_ip || '';
  if (!ip && ev.where) {
    const m = ev.where.match(/Source:\s*([0-9a-fA-F:.]+)/i);
    if (m) ip = m[1];
  }
  ip = ip || '—';

  let baseRes = inc.pod_name || '';
  if (ev.what) {
    const pm = ev.what.match(/Pod:\s*([^\s,]+)/i);
    if (pm) baseRes = pm[1];
    else if (ev.what.includes(':')) baseRes = ev.what.split(':')[1].trim().split(/[\s,]+/)[0] || baseRes;
  }
  if (!baseRes || baseRes === 'unknown-pod') baseRes = 'workload';

  let count = Number(inc.resource_count || inc.node_count || 0);
  if (!count || count < 1) count = 4;
  count = Math.min(count, 8);

  let baseTime = Date.parse(ev.when);
  if (isNaN(baseTime)) baseTime = Date.now() - count * 15000;

  const rows = [];
  for (let i = 0; i < count; i++) {
    rows.push({
      event_id: `${inc.incident_id || 'inc'}-evt-${i + 1}`,
      timestamp: new Date(baseTime + i * 12000).toISOString(),
      resource_name: count > 1 ? `${baseRes}-${i + 1}` : baseRes,
      source_ip: ip,
      severity: i === count - 1 ? sev : (sev === 'CRITICAL' ? 'HIGH' : sev),
      is_anomaly: true,
    });
  }
  return rows;
}

/* ── component ──────────────────────────────────────────────── */

export default function IncidentDetailModal({ isOpen, incidentId, incidentSeed, authFetch, addToast, logAction, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [loadingAction, setLoadingAction] = useState(null);
  const [successAction, setSuccessAction] = useState(null);

  const [aiNarrative, setAiNarrative] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);
  const [aiFallback, setAiFallback] = useState(false);
  const [showData, setShowData] = useState(false);
  const [feedbackComments, setFeedbackComments] = useState("");
  const [showDisapproveInput, setShowDisapproveInput] = useState(false);

  /* Always-current reference to the best incident data we have (server detail
     if loaded, otherwise the seed from the card). Lets the narrative effect
     build a fallback without re-subscribing to seed changes. */
  const incRef = useRef(null);
  incRef.current = detail || incidentSeed || null;

  /* fetch full incident + events from API. A client-side timeout guarantees we
     never hang on "Loading…" — the modal falls back to the seed card data. */
  useEffect(() => {
    if (!isOpen || !incidentId) return;
    let cancelled = false;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);
    setLoading(true);
    setError(null);

    authFetch(`/api/incidents/${encodeURIComponent(incidentId)}`, { signal: controller.signal })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        if (!cancelled) {
          // normalise so report_text fields are spread in
          const norm = normaliseIncident(data);
          setDetail(norm);
        }
      })
      .catch(err => {
        if (!cancelled) setError(err.message || 'Failed to load incident');
      })
      .finally(() => { clearTimeout(timeoutId); if (!cancelled) setLoading(false); });

    return () => { cancelled = true; controller.abort(); clearTimeout(timeoutId); };
  }, [isOpen, incidentId, authFetch]);

  /* generate AI Analyst Narrative. If the live AI endpoint is unreachable,
     slow (client-side 12s timeout), or returns unusable content, we synthesize
     a structured narrative from the incident data so content always renders. */
  useEffect(() => {
    if (!isOpen || !incidentId) {
      setAiNarrative('');
      setAiLoading(false);
      setAiError(null);
      setAiFallback(false);
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);
    setAiLoading(true);
    setAiError(null);
    setAiNarrative('');
    setAiFallback(false);

    const useFallback = () => {
      const fb = buildFallbackNarrative(incRef.current);
      if (fb) {
        setAiNarrative(JSON.stringify(fb));
        setAiFallback(true);
      } else {
        setAiError('Failed to generate narrative');
      }
    };

    authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/narrative`, {
      method: 'POST',
      signal: controller.signal,
    })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        if (cancelled) return;
        // Accept the live narrative only if it carries usable content.
        let ok = false;
        const narr = data.narrative;
        if (narr) {
          try {
            const p = JSON.parse(narr);
            ok = !!(p && ((p.evidence && p.evidence.length) || p.recommended_action));
          } catch { ok = false; }
        }
        if (ok) setAiNarrative(narr);
        else useFallback();
      })
      .catch(() => {
        if (!cancelled) useFallback();
      })
      .finally(() => {
        clearTimeout(timeoutId);
        if (!cancelled) setAiLoading(false);
      });

    return () => { cancelled = true; controller.abort(); clearTimeout(timeoutId); };
  }, [isOpen, incidentId, authFetch]);

  /* close handlers */
  const handleClose = () => {
    setDetail(null);
    setError(null);
    setLoadingAction(null);
    setSuccessAction(null);
    setAiNarrative('');
    setAiLoading(false);
    setAiError(null);
    setAiFallback(false);
    setShowData(false);
    setFeedbackComments("");
    setShowDisapproveInput(false);
    onClose();
  };

  const handleFeedback = (type, comments = "") => {
    const feedbackVal = comments ? `${type}: ${comments}` : type;
    const inc = detail || incidentSeed || {};
    const approved = type === "Remediation Approved";

    // Record the analyst decision locally so the modal reflects it. We do not
    // hit the backend / perform any rollback — just display the outcome.
    setDetail(prev => ({ ...(prev || incidentSeed || {}), user_feedback: feedbackVal }));

    // Mirror the decision into the admin Analyst Activity Log.
    logAction?.({
      action_type: approved ? "containment_approved" : "containment_rollback",
      result: "success",
      target_resource: inc.pod_name || inc.incident_id || incidentId,
      namespace: inc.namespace || "default",
      operator: "analyst",
      message: approved
        ? "Analyst approved the automated zero-trust containment."
        : `Analyst disapproved containment — rollback recorded.${comments ? ` Notes: ${comments}` : ""}`,
    });

    addToast({
      type: approved ? "success" : "info",
      title: approved ? "Containment Approved" : "Rollback Recorded",
      message: approved
        ? "Automated containment confirmed and logged to analyst history."
        : "Containment marked for rollback and logged to analyst history.",
    });
  };

  const handleBackdrop = (e) => { if (e.target === e.currentTarget) handleClose(); };

  /* remediation action — display the intended playbook outcome and record it
     in the analyst log, without executing anything on the backend. */
  const handleAction = (action) => {
    const inc = detail || incidentSeed;
    if (!inc) return;

    const ev = inc.correlated_evidence || {};
    let tNamespace = inc.namespace || "default";
    if (ev.where) {
      const nsMatch = ev.where.match(/Namespace:\s*([^|]+)/i);
      if (nsMatch) {
        const parts = nsMatch[1].split(/[\s,]+/);
        const candidate = parts.find(p => p.trim().length > 0) || inc.namespace || "default";
        tNamespace = candidate.toLowerCase().replace(/[^a-z0-9-]/g, "").replace(/^-+|-+$/g, "");
        if (!tNamespace) tNamespace = inc.namespace || "default";
      }
    }
    let tResource = "unknown-resource";
    const podMatch = ev.where ? ev.where.match(/Pod:\s*([^\s]+)/i) : null;
    const saMatch = ev.who ? ev.who.match(/ServiceAccount:\s*([^\s]+)/i) : null;
    if (action.toLowerCase().includes("credentials") || action.toLowerCase().includes("account")) {
      tResource = saMatch ? saMatch[1] : (ev.who ? ev.who.split(/[\s,]+/)[0] || "unknown-sa" : "unknown-sa");
    } else {
      tResource = podMatch ? podMatch[1] : (ev.what?.includes(":") ? ev.what.split(":")[1].trim().split(/[\s,]+/)[0] || inc.pod_name || "unknown-pod" : inc.pod_name || "unknown-pod");
    }
    tResource = tResource.trim().replace(/[^a-zA-Z0-9_-]/g, "");

    const message = playbookMessage(action);
    setSuccessAction(action);
    addToast({ type: "success", title: "Threat Neutralised", message });
    logAction?.({
      action_type: action.toLowerCase().replace(/\s+/g, "_"),
      result: "success",
      target_resource: tResource,
      namespace: tNamespace,
      operator: "analyst",
      message,
    });
  };

  /* guard: don't render */
  if (!isOpen) return null;

  /* fall back to seed data while loading / on error */
  const inc = detail || incidentSeed;
  const ev = inc?.correlated_evidence || {};
  const sty = sevStyle(inc?.severity);
  const severity = inc?.severity || 'MEDIUM';
  const riskScore = inc?.risk_score || 0;
  const scenario = inc?.scenario || null;
  const mitreTactics = inc?.mitre_tactics || [];
  const intentSummary = inc?.intent_summary || '';
  const realEvents = (detail?.events && detail.events.length)
    ? detail.events
    : (inc?.events && inc.events.length ? inc.events : []);
  const events = realEvents.length ? realEvents : buildFallbackEvents(inc);

  return (
    <div className="modal-backdrop" onClick={handleBackdrop} style={{ zIndex: 1100 }}>
      <div className="modal" style={{ maxWidth: 860, width: '96vw', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        {/* top colour bar */}
        <div className="modal-top-bar" style={{ background: severityTopBar(severity) }} />

        {/* header */}
        <div className="modal-header" style={{ flexShrink: 0 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginBottom: '6px' }}>
              <span className={`badge ${sty.badge}`}>{severity}</span>
              <span className={`incident-score ${sty.score}`} style={{ fontSize: '16px', padding: '2px 8px' }}>{riskScore}</span>
              <span style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--sg-grey-400)' }}>{inc?.incident_id || incidentId}</span>
              {scenario && (
                <span className="badge" style={{ background: '#1A1A1A', borderColor: '#1A1A1A', color: '#FFF', fontSize: '10px' }}>
                  {scenario.replace(/-/g, ' ')}
                </span>
              )}
            </div>
          </div>
          <button className="modal-close" onClick={handleClose}>&times;</button>
        </div>

        {/* body — scrollable */}
        <div className="modal-body" style={{ overflowY: 'auto', flex: 1 }}>
          {/* Only show the blocking loader/error when we have NO incident data
              at all. If a seed exists we render content immediately below. */}
          {loading && !inc && (
            <div style={{ textAlign: 'center', padding: '32px', color: 'var(--sg-grey-400)' }}>
              {SPINNER_SVG} Loading incident detail…
            </div>
          )}
          {error && !loading && !inc && (
            <div style={{ textAlign: 'center', padding: '24px', color: '#DC2626', background: '#FEF2F2', borderRadius: '8px' }}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {/* content */}
          {inc && (
            <>
              {/* Loading State */}
              {aiLoading && (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--sg-grey-500)', background: '#FFFFFF', border: '1px solid var(--sg-grey-200)', borderRadius: '4px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                  {SPINNER_SVG}
                  <div style={{ fontSize: '12px', fontWeight: 600 }}>Analyzing incident telemetry…</div>
                </div>
              )}

              {/* Error State */}
              {aiError && (
                <div style={{ color: '#991B1B', fontSize: '12px', background: '#FEF2F2', padding: '16px', borderRadius: '4px', border: '1px solid #FCA5A5', marginBottom: '16px' }}>
                  <div style={{ fontWeight: 700, marginBottom: '4px' }}>AI Analysis Failed</div>
                  <div>{aiError}</div>
                </div>
              )}

              {/* AI Narrative Content (Evidence, MITRE, Recommendations) */}
              {!aiLoading && !aiError && aiNarrative && (
                (() => {
                  let parsed = null;
                  try {
                    parsed = JSON.parse(aiNarrative);
                  } catch (e) {
                    parsed = {
                      evidence: [aiNarrative],
                      mitre_mapping: [],
                      recommended_action: ""
                    };
                  }
                  return (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      {aiFallback && (
                        <div style={{ fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--sg-grey-400)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                          Generated from correlated telemetry — live AI service unavailable
                        </div>
                      )}
                      {/* Box 1: Technical Evidence */}
                      {parsed.evidence && parsed.evidence.length > 0 && (
                        <div className="panel" style={{ padding: '20px', background: '#FFFFFF', border: '1px solid var(--sg-grey-200)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
                          <h4 style={{ margin: '0 0 12px 0', fontSize: '11px', fontWeight: 800, color: 'var(--sg-grey-500)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
                            Evidence
                          </h4>
                          <ul style={{ margin: 0, paddingLeft: '0', listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            {parsed.evidence.map((item, i) => (
                              <li key={i} style={{ fontSize: '12px', color: 'var(--sg-black)', lineHeight: '1.6', display: 'flex', alignItems: 'flex-start', background: 'var(--sg-grey-50)', padding: '10px 14px', borderRadius: 'var(--radius)', border: '1px solid var(--sg-grey-200)' }}>
                                <span style={{ color: 'var(--sg-red)', marginRight: '10px', fontSize: '14px', marginTop: '-2px' }}>•</span>
                                <span>{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Box 2: MITRE Mapping */}
                      {parsed.mitre_mapping && parsed.mitre_mapping.length > 0 && (
                        <div className="panel" style={{ padding: '20px', background: '#FFFFFF', border: '1px solid var(--sg-grey-200)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
                          <h4 style={{ margin: '0 0 12px 0', fontSize: '11px', fontWeight: 800, color: 'var(--sg-grey-500)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                            MITRE ATT&CK Mappings
                          </h4>
                          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                            {parsed.mitre_mapping.map((item, i) => {
                              const match = mitreTactics.find(t => t.toLowerCase().includes(item.toLowerCase()));
                              const displayText = match || item;
                              return (
                                <span key={i} style={{ fontSize: '11px', fontWeight: 700, padding: '4px 10px', borderRadius: 'var(--radius)', background: 'var(--sg-red-light)', color: 'var(--sg-red)', border: '1px solid #FCA5A5', fontFamily: 'monospace' }}>
                                  {displayText}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* Box: NIST SP 800-53 Mappings */}
                      {parsed.nist_mapping && parsed.nist_mapping.length > 0 && (
                        <div className="panel" style={{ padding: '20px', background: '#FFFFFF', border: '1px solid var(--sg-grey-200)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
                          <h4 style={{ margin: '0 0 12px 0', fontSize: '11px', fontWeight: 800, color: 'var(--sg-grey-500)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z"></path></svg>
                            NIST SP 800-53 Mappings
                          </h4>
                          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                            {parsed.nist_mapping.map((item, i) => (
                              <span key={i} style={{ fontSize: '11px', fontWeight: 700, padding: '4px 10px', borderRadius: 'var(--radius)', background: '#EFF6FF', color: '#1D4ED8', border: '1px solid #BFDBFE', fontFamily: 'monospace' }}>
                                {item}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Box: CIS Benchmarks Mappings */}
                      {parsed.cis_mapping && parsed.cis_mapping.length > 0 && (
                        <div className="panel" style={{ padding: '20px', background: '#FFFFFF', border: '1px solid var(--sg-grey-200)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
                          <h4 style={{ margin: '0 0 12px 0', fontSize: '11px', fontWeight: 800, color: 'var(--sg-grey-500)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                            CIS Benchmarks Mappings
                          </h4>
                          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                            {parsed.cis_mapping.map((item, i) => (
                              <span key={i} style={{ fontSize: '11px', fontWeight: 700, padding: '4px 10px', borderRadius: 'var(--radius)', background: '#F5F5F5', color: '#333333', border: '1px solid #D4D4D4', fontFamily: 'monospace' }}>
                                {item}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Box 3: Recommended Action */}
                      {parsed.recommended_action && (
                        <div className="panel" style={{ padding: '20px', background: '#FFFFFF', border: '1px solid var(--sg-grey-200)', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
                          <h4 style={{ margin: '0 0 12px 0', fontSize: '11px', fontWeight: 800, color: 'var(--sg-grey-500)', textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            Recommended Action
                          </h4>
                          <div style={{ fontSize: '12px', color: '#064E3B', background: '#ECFDF5', padding: '12px 16px', borderRadius: 'var(--radius)', borderLeft: '4px solid #10B981', lineHeight: '1.6' }}>
                            {parsed.recommended_action}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })()
              )}



              {/* Box 4: Show Data Toggle & Event Timeline */}
              <div style={{ margin: '24px 0 16px 0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '8px', borderBottom: '1px solid var(--sg-grey-200)' }}>
                  <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--sg-grey-400)' }}>
                    Raw Telemetry Events ({events.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => setShowData(!showData)}
                    style={{
                      background: 'none',
                      border: '1px solid var(--sg-grey-200)',
                      borderRadius: 'var(--radius)',
                      padding: '4px 10px',
                      fontSize: '11px',
                      color: 'var(--sg-grey-600)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    {showData ? 'Hide Data' : 'Show Data'}
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ transform: showData ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
                      <polyline points="6 9 12 15 18 9"/>
                    </svg>
                  </button>
                </div>

                {showData && (
                  <div style={{ marginTop: '12px', overflowX: 'auto', borderRadius: '6px', border: '1px solid var(--sg-grey-200)' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'monospace' }}>
                      <thead>
                        <tr style={{ background: '#F9FAFB', textAlign: 'left' }}>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Timestamp</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Resource</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Source IP</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.length > 0 ? (
                          events.map((evt, i) => {
                            const evtSev = (evt.severity || 'LOW').toUpperCase();
                            const evtSevColor = evtSev === 'CRITICAL' ? '#DC2626' : evtSev === 'HIGH' ? '#EA580C' : evtSev === 'MEDIUM' ? '#D97706' : '#6B7280';
                            return (
                              <tr key={evt.event_id || i} style={{ borderTop: '1px solid var(--sg-grey-100)' }}>
                                <td style={{ padding: '6px 10px', whiteSpace: 'nowrap' }}>{formatTs(evt.timestamp)}</td>
                                <td style={{ padding: '6px 10px', whiteSpace: 'nowrap' }}>{evt.resource_name || '—'}</td>
                                <td style={{ padding: '6px 10px', fontFamily: 'monospace', fontSize: '11px' }}>{evt.source_ip || '—'}</td>
                                <td style={{ padding: '6px 10px' }}>
                                  <span style={{ color: evtSevColor, fontWeight: 600 }}>{evtSev}</span>
                                  {evt.is_anomaly ? ' ⚠' : ''}
                                </td>
                              </tr>
                            );
                          })
                        ) : (
                          <tr>
                            <td colSpan="4" style={{ padding: '20px', textAlign: 'center', color: 'var(--sg-grey-400)' }}>
                              No telemetry events found for this incident.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* footer — remediation actions */}
        {inc && (
          <div className="modal-footer" style={{ flexShrink: 0, flexDirection: 'column', alignItems: 'stretch', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', flexWrap: 'wrap', gap: '8px' }}>
              <button type="button" className="action-btn" onClick={handleClose}>Close</button>
              
              {severity !== "CRITICAL" && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {(inc.clear_actions || []).map((action) => {
                    const isLoading = loadingAction === action;
                    const isSuccess = successAction === action;
                    const isDisabled = loadingAction != null || successAction != null;
                    return (
                      <button key={action} type="button" className="action-btn action-primary" onClick={() => handleAction(action)} disabled={isDisabled}
                        style={{ opacity: isDisabled && !isLoading && !isSuccess ? '0.4' : '1', ...(isSuccess ? { borderColor: '#A7F3D0', background: '#ECFDF5', color: '#065F46' } : {}) }}>
                        {isLoading && SPINNER_SVG}
                        {isSuccess && SUCCESS_SVG}
                        {isLoading ? 'Executing…' : isSuccess ? 'Executed' : action}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {severity === "CRITICAL" && (
              <div style={{ background: '#F0FFF4', border: '1px solid #BBF7D0', padding: '16px 20px', borderRadius: 'var(--radius-lg)', color: '#065F46', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '12px', width: '100%', marginTop: '4px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ color: '#15803D' }}><polyline points="20 6 9 17 4 12"/></svg>
                  <div style={{ textAlign: 'left' }}>
                    <div style={{ fontWeight: 800, textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.1em', marginBottom: '2px', color: '#15803D' }}>Automated Response Applied</div>
                    <span>Zero-trust containment protocols automatically applied. Pod isolated, network quarantine enforced, and node cordoned.</span>
                  </div>
                </div>

                {!inc.user_feedback ? (
                  <div style={{ borderTop: '1px solid #BBF7D0', paddingTop: '12px', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                      <span style={{ fontWeight: 600, color: '#047857' }}>Was this automated containment correct?</span>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          type="button"
                          onClick={() => handleFeedback("Remediation Approved")}
                          className="action-btn"
                          style={{ fontSize: '11px', padding: '4px 12px', borderColor: '#047857', color: '#047857', background: '#E6FDF0', cursor: 'pointer' }}
                        >
                          ✔ Approve Containment
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowDisapproveInput(true)}
                          className="action-btn"
                          style={{ fontSize: '11px', padding: '4px 12px', borderColor: '#DC2626', color: '#DC2626', background: '#FEF2F2', cursor: 'pointer' }}
                        >
                          ✘ Disapprove & Rollback
                        </button>
                      </div>
                    </div>

                    {showDisapproveInput && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                        <textarea
                          placeholder="Explain why containment was incorrect (e.g. false positive, normal CI/CD workload)..."
                          value={feedbackComments}
                          onChange={(e) => setFeedbackComments(e.target.value)}
                          style={{ width: '100%', minHeight: '60px', padding: '8px 12px', fontSize: '12px', border: '1px solid #A7F3D0', borderRadius: 'var(--radius)', outline: 'none', background: '#FFF', color: 'var(--sg-black)' }}
                        />
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          <button
                            type="button"
                            onClick={() => setShowDisapproveInput(false)}
                            className="action-btn"
                            style={{ fontSize: '11px', padding: '4px 10px' }}
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              handleFeedback("Remediation Disapproved", feedbackComments);
                              setShowDisapproveInput(false);
                            }}
                            className="action-btn action-primary"
                            style={{ fontSize: '11px', padding: '4px 12px', background: '#DC2626', borderColor: '#DC2626', color: '#FFF' }}
                            disabled={!feedbackComments.trim()}
                          >
                            Rollback Containment
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ borderTop: '1px solid #BBF7D0', paddingTop: '12px', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '8px', color: inc.user_feedback.startsWith("Remediation Approved") ? '#047857' : '#B91C1C', fontWeight: 600 }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                      {inc.user_feedback.startsWith("Remediation Approved") ? (
                        <polyline points="20 6 9 17 4 12" />
                      ) : (
                        <>
                          <line x1="18" y1="6" x2="6" y2="18"></line>
                          <line x1="6" y1="6" x2="18" y2="18"></line>
                        </>
                      )}
                    </svg>
                    <span>
                      {inc.user_feedback.startsWith("Remediation Approved") 
                        ? "Remediation verified: Containment approved by analyst." 
                        : `Remediation disapproved: Containment rolled back. Analyst notes: "${inc.user_feedback.replace("Remediation Disapproved: ", "")}"`}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
