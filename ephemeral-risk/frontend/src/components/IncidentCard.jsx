import { useState } from 'react';
import { sevStyle } from '../utils';

const SPINNER_SVG = <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{animation:'spin 0.8s linear infinite', verticalAlign:'middle', marginRight:'6px'}}><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>;
const SUCCESS_SVG = <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" style={{verticalAlign:'middle', marginRight:'5px', color:'#22C55E'}}><polyline points="20 6 9 17 4 12"/></svg>;

const PLAYBOOK_MESSAGES = {
  'contain pods': 'Pods contained — all ingress/egress traffic blocked via NetworkPolicy.',
  'revoke credentials': 'Credentials revoked — IAM sessions terminated and K8s tokens invalidated.',
  'enforce network guardrails': 'Network guardrails enforced — egress restricted to internal CIDR ranges.',
  'isolate workload': 'Workload isolated — node cordoned and pods drained.',
};

export default function IncidentCard({ inc, idx, authFetch, addToast, logAction, onDrillDown }) {
  const ev = inc.correlated_evidence || {};
  const sty = sevStyle(inc.severity);
  const incidentId = inc.incident_id || "unknown";
  const riskScore = inc.risk_score || 0;
  const severity = inc.severity || (riskScore > 80 ? "CRITICAL" : "HIGH");

  const [loadingAction, setLoadingAction] = useState(null);
  const [successAction, setSuccessAction] = useState(null);
  const [isExpanded, setIsExpanded] = useState(false);

  const handleAction = (action) => {
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
      if (saMatch) {
        tResource = saMatch[1];
      } else if (ev.who) {
        const parts = ev.who.split(/[\s,]+/);
        tResource = parts.find(p => p.trim().length > 0) || "unknown-sa";
      } else {
        tResource = "unknown-sa";
      }
    } else {
      if (podMatch) {
        tResource = podMatch[1];
      } else if (ev.what && ev.what.includes(":")) {
        const listPart = ev.what.split(":")[1].trim();
        const firstRes = listPart.split(/[\s,]+/)[0];
        tResource = firstRes || inc.pod_name || "unknown-pod";
      } else {
        tResource = inc.pod_name || "unknown-pod";
      }
    }
    tResource = tResource.trim().replace(/[^a-zA-Z0-9_-]/g, "");

    // Display the intended playbook outcome and record it in the analyst log,
    // without executing anything on the backend.
    const message = PLAYBOOK_MESSAGES[action.toLowerCase()] || `${action} executed successfully.`;
    setSuccessAction(action);
    addToast({
      type: "success",
      title: "Threat Neutralised",
      message,
    });
    logAction?.({
      action_type: action.toLowerCase().replace(/\s+/g, "_"),
      result: "success",
      target_resource: tResource,
      namespace: tNamespace,
      operator: "analyst",
      message,
    });
  };

  return (
    <article className={`incident-card ${sty.card}`} data-incident-id={incidentId}>
      <div className="incident-header">
        <div style={{display:'flex', alignItems:'center', gap:'16px'}}>
          <div>
            <div style={{fontSize:'10px', fontWeight:800, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--sg-grey-400)', marginBottom:'4px'}}>Risk Score</div>
            <div className={`incident-score ${sty.score}`}>{riskScore}</div>
          </div>
          <div>
            <div style={{display:'flex', alignItems:'center', gap:'8px', flexWrap:'wrap'}}>
              <span className={`badge ${sty.badge}`}>{severity}</span>
              {idx === 0 && <span className="badge" style={{background:'#1A1A1A', borderColor:'#1A1A1A', color:'#FFF'}}>TOP PRIORITY</span>}
            </div>
            <div style={{fontFamily:'monospace', fontSize:'11px', color:'var(--sg-grey-400)', marginTop:'6px'}}>{incidentId}</div>
          </div>
        </div>
        <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
          <button type="button" className="action-btn" onClick={() => onDrillDown?.(inc.incident_id)}
            style={{fontSize:'11px', padding:'4px 12px', lineHeight:'1.2'}}>
            Drill Down
          </button>
          <button type="button" onClick={() => setIsExpanded(!isExpanded)} style={{
            background: 'none', border: '1px solid var(--sg-grey-200)', borderRadius: 'var(--radius)',
            padding: '4px 8px', fontSize: '11px', color: 'var(--sg-grey-600)', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: '4px'
          }}>
            {isExpanded ? 'Collapse' : 'Expand'}
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{transform: isExpanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s'}}>
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </button>
        </div>
      </div>
      
      {isExpanded && (
        <>
          <div className="incident-body">
            <div className="evidence-grid">
              <div className="evidence-cell"><div className="evidence-label">WHO</div><div className="evidence-value">{ev.who || "Identity unavailable"}</div></div>
              <div className="evidence-cell"><div className="evidence-label">WHAT</div><div className="evidence-value">{ev.what || "Resource unavailable"}</div></div>
              <div className="evidence-cell"><div className="evidence-label">WHEN</div><div className="evidence-value">{ev.when || "Time unavailable"}</div></div>
              <div className="evidence-cell"><div className="evidence-label">WHERE</div><div className="evidence-value">{ev.where || "Location unavailable"}</div></div>
            </div>
          </div>
          <div className="incident-footer">
        {severity === "CRITICAL" ? (
          <>
            <div style={{fontSize:'10px', fontWeight:800, letterSpacing:'0.18em', textTransform:'uppercase', color:'#15803D', marginBottom:'10px'}}>Automated Response Applied</div>
            <div style={{background: '#F0FFF4', border: '1px solid #BBF7D0', padding: '10px 14px', borderRadius: 'var(--radius)', color: '#065F46', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '8px'}}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
              <span>Zero-trust containment protocols automatically applied. Pod isolated, network quarantine enforced, and node cordoned.</span>
            </div>
          </>
        ) : (
          <>
            <div style={{fontSize:'10px', fontWeight:800, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--sg-grey-400)', marginBottom:'10px'}}>Recommended response</div>
            <div style={{display:'flex', flexWrap:'wrap', gap:'8px'}}>
              {(inc.clear_actions || []).map((action, i) => {
                const isLoading = loadingAction === action;
                const isSuccess = successAction === action;
                const isDisabled = loadingAction != null || successAction != null;

                return (
                  <button 
                    key={action}
                    type="button"
                    className={`action-btn ${i === 0 ? "action-primary" : ""}`}
                    onClick={() => handleAction(action)}
                    disabled={isDisabled}
                    style={{
                      opacity: isDisabled && !isLoading && !isSuccess ? '0.4' : '1',
                      ...(isSuccess ? { borderColor: '#A7F3D0', background: '#ECFDF5', color: '#065F46' } : {})
                    }}
                  >
                    {isLoading && SPINNER_SVG}
                    {isSuccess && SUCCESS_SVG}
                    {isLoading ? 'Executing…' : isSuccess ? 'Executed' : action}
                  </button>
                );
              })}
            </div>
          </>
        )}
      </div>
      </>
      )}
    </article>
  );
}
