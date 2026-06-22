import { useState, useEffect } from 'react';
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

/* ── component ──────────────────────────────────────────────── */

export default function IncidentDetailModal({ isOpen, incidentId, incidentSeed, authFetch, addToast, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [loadingAction, setLoadingAction] = useState(null);
  const [successAction, setSuccessAction] = useState(null);

  const [aiNarrative, setAiNarrative] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);
  const [showData, setShowData] = useState(false);
  const [feedbackComments, setFeedbackComments] = useState("");
  const [showDisapproveInput, setShowDisapproveInput] = useState(false);

  /* fetch full incident + events from API */
  useEffect(() => {
    if (!isOpen || !incidentId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    authFetch(`/api/incidents/${encodeURIComponent(incidentId)}`)
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
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [isOpen, incidentId, authFetch]);

  /* generate AI Analyst Narrative */
  useEffect(() => {
    if (!isOpen || !incidentId) {
      setAiNarrative('');
      setAiLoading(false);
      setAiError(null);
      return;
    }
    let cancelled = false;
    setAiLoading(true);
    setAiError(null);
    setAiNarrative('');

    authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/narrative`, {
      method: 'POST'
    })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        if (!cancelled) {
          setAiNarrative(data.narrative || 'No narrative generated.');
        }
      })
      .catch(err => {
        if (!cancelled) setAiError(err.message || 'Failed to generate narrative');
      })
      .finally(() => {
        if (!cancelled) setAiLoading(false);
      });

    return () => { cancelled = true; };
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
    setShowData(false);
    setFeedbackComments("");
    setShowDisapproveInput(false);
    onClose();
  };

  const handleFeedback = async (type, comments = "") => {
    const feedbackVal = comments ? `${type}: ${comments}` : type;
    try {
      const res = await authFetch(`/api/incidents/${encodeURIComponent(incidentId)}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ feedback: feedbackVal })
      });
      if (!res.ok) throw new Error("Failed to save feedback");
      
      setDetail(prev => prev ? { ...prev, user_feedback: feedbackVal } : null);
      
      addToast({
        type: "success",
        title: "Feedback Recorded",
        message: "Your feedback has been successfully recorded."
      });
    } catch (err) {
      addToast({
        type: "error",
        title: "Feedback Failed",
        message: err.message
      });
    }
  };

  const handleBackdrop = (e) => { if (e.target === e.currentTarget) handleClose(); };

  /* remediation action (same logic as IncidentCard) */
  const handleAction = async (action) => {
    const inc = detail || incidentSeed;
    if (!inc) return;

    setLoadingAction(action);
    try {
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

      // Extract context for backend targeting (SA name, source IP)
      const principalId = saMatch ? saMatch[1] : (inc.principal_id || "");
      const ipInWhere = ev.where ? ev.where.match(/Source:\s*([0-9a-fA-F:.]+)/i) : null;
      const sourceIp = ipInWhere ? ipInWhere[1] : (inc.pivot_ip || inc.source_ip || "");

      const res = await authFetch(`/api/remediate/${encodeURIComponent(inc.incident_id)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_type: action,
          target_resource: tResource,
          target_namespace: tNamespace,
          principal_id: principalId,
          source_ip: sourceIp,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        let errMsg = "Remediation failed";
        if (typeof data.detail === 'string') errMsg = data.detail;
        else if (Array.isArray(data.detail)) errMsg = data.detail.map(d => `${d.loc.join('.')}: ${d.msg}`).join('; ');
        else if (data.detail && typeof data.detail === 'object') errMsg = JSON.stringify(data.detail);
        else if (data.message) errMsg = data.message;
        throw new Error(errMsg);
      }
      setSuccessAction(action);
      addToast({ type: "success", title: "Threat Neutralised", message: data.message || `${action} executed successfully.` });
    } catch (err) {
      addToast({ type: "error", title: "Remediation Failed", message: err.message || "Unexpected error." });
      setLoadingAction(null);
    }
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
  const events = detail?.events || [];

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
          {/* loading / error states */}
          {loading && (
            <div style={{ textAlign: 'center', padding: '32px', color: 'var(--sg-grey-400)' }}>
              {SPINNER_SVG} Loading incident detail…
            </div>
          )}
          {error && !loading && (
            <div style={{ textAlign: 'center', padding: '24px', color: '#DC2626', background: '#FEF2F2', borderRadius: '8px' }}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {/* content */}
          {/* content */}
          {!loading && inc && (
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
        {!loading && inc && (
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
