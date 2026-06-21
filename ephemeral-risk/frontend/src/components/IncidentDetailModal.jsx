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

  /* close handlers */
  const handleClose = () => {
    setDetail(null);
    setError(null);
    setLoadingAction(null);
    setSuccessAction(null);
    onClose();
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
            {mitreTactics.length > 0 && (
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                {mitreTactics.map((t, i) => (
                  <span key={i} style={{ fontSize: '10px', fontFamily: 'monospace', padding: '2px 8px', borderRadius: '4px', background: '#FEF3C7', color: '#92400E', border: '1px solid #FDE68A' }}>
                    {t}
                  </span>
                ))}
              </div>
            )}
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
          {!loading && inc && (
            <>
              {/* evidence grid */}
              <div className="evidence-grid" style={{ marginBottom: '16px' }}>
                <div className="evidence-cell"><div className="evidence-label">WHO</div><div className="evidence-value">{ev.who || 'Identity unavailable'}</div></div>
                <div className="evidence-cell"><div className="evidence-label">WHAT</div><div className="evidence-value">{ev.what || 'Resource unavailable'}</div></div>
                <div className="evidence-cell"><div className="evidence-label">WHEN</div><div className="evidence-value">{ev.when || 'Time unavailable'}</div></div>
                <div className="evidence-cell"><div className="evidence-label">WHERE</div><div className="evidence-value">{ev.where || 'Location unavailable'}</div></div>
              </div>

              {/* intent + why_risky */}
              {intentSummary && (
                <div style={{ marginBottom: '16px', padding: '14px 16px', background: '#FFFBEB', border: '1px solid #FDE68A', borderRadius: '8px' }}>
                  <div style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.18em', textTransform: 'uppercase', color: '#92400E', marginBottom: '6px' }}>
                    Intent Analysis
                  </div>
                  <div style={{ fontSize: '13px', color: '#78350F', lineHeight: 1.5 }}>{intentSummary}</div>
                </div>
              )}

              <div className="threat-context" style={{ marginBottom: '20px' }}>
                <div className="threat-label">Threat context · Why this is risky</div>
                <div className="threat-text">{ev.why_risky || 'Raw anomaly detected.'}</div>
              </div>

              {/* per-event timeline */}
              {events.length > 0 && (
                <div style={{ marginTop: '4px' }}>
                  <div style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--sg-grey-400)', marginBottom: '10px' }}>
                    Event Timeline ({events.length} event{events.length !== 1 ? 's' : ''})
                  </div>
                  <div style={{ overflowX: 'auto', borderRadius: '6px', border: '1px solid var(--sg-grey-200)' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'monospace' }}>
                      <thead>
                        <tr style={{ background: '#F9FAFB', textAlign: 'left' }}>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Timestamp</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Event</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Severity</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Actor</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Resource</th>
                          <th style={{ padding: '8px 10px', borderBottom: '1px solid var(--sg-grey-200)', color: 'var(--sg-grey-500)', fontWeight: 600 }}>Source IP</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.map((evt, i) => {
                          const evtSev = (evt.severity || 'LOW').toUpperCase();
                          const evtSevColor = evtSev === 'CRITICAL' ? '#DC2626' : evtSev === 'HIGH' ? '#EA580C' : evtSev === 'MEDIUM' ? '#D97706' : '#6B7280';
                          return (
                            <tr key={evt.event_id || i} style={{ borderTop: '1px solid var(--sg-grey-100)' }}>
                              <td style={{ padding: '6px 10px', whiteSpace: 'nowrap' }}>{formatTs(evt.timestamp)}</td>
                              <td style={{ padding: '6px 10px' }}>{evt.event_name || evt.log_type || '—'}</td>
                              <td style={{ padding: '6px 10px' }}>
                                <span style={{ color: evtSevColor, fontWeight: 600 }}>{evtSev}</span>
                                {evt.is_anomaly ? ' ⚠' : ''}
                              </td>
                              <td style={{ padding: '6px 10px', whiteSpace: 'nowrap' }}>{evt.principal_id || evt.actor || '—'}</td>
                              <td style={{ padding: '6px 10px', whiteSpace: 'nowrap' }}>{evt.resource_name || '—'}</td>
                              <td style={{ padding: '6px 10px', fontFamily: 'monospace', fontSize: '11px' }}>{evt.source_ip || '—'}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {!loading && !error && events.length === 0 && (
                <div style={{ textAlign: 'center', padding: '20px', color: 'var(--sg-grey-400)', fontSize: '12px' }}>
                  No telemetry events found for this incident.
                </div>
              )}
            </>
          )}
        </div>

        {/* footer — remediation actions */}
        {!loading && inc && (
          <div className="modal-footer" style={{ flexShrink: 0 }}>
            <button type="button" className="action-btn" onClick={handleClose} style={{ marginRight: 'auto' }}>Close</button>
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
          </div>
        )}
      </div>
    </div>
  );
}
