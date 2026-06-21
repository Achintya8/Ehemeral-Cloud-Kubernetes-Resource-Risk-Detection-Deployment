import { useState } from 'react';
import PipelineModal from '../components/PipelineModal';

export default function Admin({ appState }) {
  const { pipelines, health, dbStats, modelStats, refreshHealth, ngrokPublicUrl } = appState;
  const [modalOpen, setModalOpen] = useState(false);

  // Prefer the public ngrok tunnel URL (reachable from GitHub) when the
  // server has one open; otherwise fall back to the current browser origin.
  const baseUrl = ngrokPublicUrl || window.location.origin;
  const webhookEndpoint = `${baseUrl}/api/webhook/github`;

  const total = pipelines.length;
  const active = pipelines.filter(p => p.status === "active").length;
  const pending = pipelines.filter(p => p.status === "pending").length;

  const handleActivate = async (id) => {
    try {
      await appState.authFetch(`/api/pipelines/${id}/activate`, { method: "POST" });
      await appState.refreshPipelines();
    } catch {}
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(webhookEndpoint);
  };

  return (
    <div className="page-view" id="view-admin">
      <div className="page-header" style={{display:'flex', alignItems:'flex-end', justifyContent:'space-between', flexWrap:'wrap', gap:'12px'}}>
        <div>
          <div className="breadcrumb">Administration · Pipeline Integrations</div>
          <h2>Pipeline Admin</h2>
          <p>Register, manage and monitor CI/CD repositories feeding the detection engine</p>
        </div>
        <button id="open-pipeline-modal" className="btn-danger" onClick={() => setModalOpen(true)}>
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{width:'14px', height:'14px', display:'inline', marginRight:'6px'}}><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Register Pipeline
        </button>
      </div>

      <div className="admin-grid">
        <div className="metric-card t-red">
          <div className="metric-label">Total Pipelines <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#E2001A'}}><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg></div>
          <div className="metric-value">{total}</div>
          <div className="metric-sub">Registered integrations</div>
        </div>
        <div className="metric-card t-green">
          <div className="metric-label">Active <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#059669'}}><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
          <div className="metric-value">{active}</div>
          <div className="metric-sub">Streaming events</div>
        </div>
        <div className="metric-card t-amber">
          <div className="metric-label">Pending <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#D97706'}}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
          <div className="metric-value">{pending}</div>
          <div className="metric-sub">Awaiting webhook config</div>
        </div>
        <div className="metric-card t-blue">
          <div className="metric-label">DB Events <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#2563EB'}}><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div>
          <div className="metric-value">{dbStats?.events ?? "—"}</div>
          <div className="metric-sub">Total stored events</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Registered Pipelines</h3>
            <p>Repositories currently integrated into the detection fabric</p>
          </div>
          <span style={{fontSize:'12px', color:'var(--sg-grey-400)'}}>{total} total</span>
        </div>
        <div style={{overflowX:'auto'}}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Target Namespace</th>
                <th>Status</th>
                <th>Webhook URL</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pipelines.length === 0 ? (
                <tr><td colSpan="5" style={{textAlign:'center', padding:'40px', color:'var(--sg-grey-400)'}}>No pipelines registered. Click "Register Pipeline" to add one.</td></tr>
              ) : pipelines.map(p => (
                <tr key={p.id}>
                  <td className="td-name">{p.repo_name}</td>
                  <td style={{fontFamily:'monospace', fontSize:'11px'}}>{p.target_namespace}</td>
                  <td><span className={`badge ${p.status === 'active' ? 'badge-active' : p.status === 'pending' ? 'badge-pending' : 'badge-inactive'}`}>{p.status}</span></td>
                  <td style={{fontFamily:'monospace', fontSize:'11px', maxWidth:'180px', overflow:'hidden', textOverflow:'ellipsis'}}>{webhookEndpoint}</td>
                  <td>
                    {p.status === 'pending' && <button className="btn-danger" style={{fontSize:'11px', padding:'5px 10px'}} onClick={() => handleActivate(p.id)}>Activate</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>System Health</h3>
            <p>Model and database diagnostics</p>
          </div>
          <button className="btn-secondary" style={{fontSize:'12px', padding:'7px 14px'}} onClick={refreshHealth}>Refresh</button>
        </div>
        <div className="panel-body">
          <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))', gap:'12px'}}>
            <div className="evidence-cell"><div className="evidence-label">API Status</div><div className="evidence-value">{health.status === 'ok' ? '✓ OK' : health.status === 'error' ? 'Error' : 'Checking…'}</div></div>
            <div className="evidence-cell"><div className="evidence-label">DB Events</div><div className="evidence-value">{dbStats?.events ?? "—"}</div></div>
            <div className="evidence-cell"><div className="evidence-label">DB Incidents</div><div className="evidence-value">{dbStats?.incidents ?? "—"}</div></div>
            <div className="evidence-cell"><div className="evidence-label">ML Model</div><div className="evidence-value">{modelStats?.model_state || "—"}</div></div>
            <div className="evidence-cell"><div className="evidence-label">Events Scored</div><div className="evidence-value">{modelStats?.total_scored ?? "—"}</div></div>
            <div className="evidence-cell"><div className="evidence-label">Anomalies Found</div><div className="evidence-value">{modelStats?.total_anomalies ?? "—"}</div></div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Webhook Configuration</h3>
            <p>GitHub webhook endpoint details for pipeline setup</p>
          </div>
        </div>
        <div className="panel-body" style={{display:'grid', gap:'14px', maxWidth:'600px'}}>
          {/* Tunnel status banner */}
          <div style={{
            background: ngrokPublicUrl ? '#F0FFF4' : '#FFFBEB',
            border: `1px solid ${ngrokPublicUrl ? '#BBF7D0' : '#FDE68A'}`,
            borderRadius: '4px', padding: '10px 14px',
            display: 'flex', alignItems: 'center', gap: '10px',
          }}>
            <span className="pulse-dot" style={{
              width: '8px', height: '8px',
              background: ngrokPublicUrl ? '#15803D' : '#D97706',
            }}></span>
            <div style={{ minWidth: 0 }}>
              <div style={{
                fontSize: '11px', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase',
                color: ngrokPublicUrl ? '#15803D' : '#D97706',
              }}>
                {ngrokPublicUrl ? 'Public tunnel active' : 'Local mode'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--sg-grey-500)', marginTop: '2px' }}>
                {ngrokPublicUrl
                  ? 'GitHub can reach this endpoint over the public ngrok tunnel.'
                  : 'No public tunnel — webhook URL below is only reachable locally. Set NGROK_AUTHTOKEN to expose it publicly.'}
              </div>
            </div>
          </div>
          <div className="form-group">
            <label className="form-label">Webhook Endpoint URL</label>
            <div className="copy-field">
              <input className="form-input" readOnly value={webhookEndpoint} />
              <button className="copy-btn" onClick={copyToClipboard}>Copy</button>
            </div>
          </div>
          <div style={{background:'var(--sg-grey-50)', border:'1px solid var(--sg-grey-200)', borderRadius:'4px', padding:'14px'}}>
            <p style={{fontSize:'12px', fontWeight:700, marginBottom:'8px', color:'var(--sg-grey-500)'}}>CONFIGURATION INSTRUCTIONS</p>
            <ol style={{fontSize:'12px', color:'var(--sg-grey-600)', lineHeight:1.8, paddingLeft:'16px'}}>
              <li>Go to your GitHub repository → Settings → Webhooks</li>
              <li>Set Payload URL to the endpoint above</li>
              <li>Set Content type to <code style={{background:'white', border:'1px solid var(--sg-grey-200)', padding:'1px 5px', borderRadius:'2px'}}>application/json</code></li>
              <li>Paste the secret token from the pipeline registration wizard</li>
              <li>Select <strong>Workflow jobs</strong> events only</li>
              <li>Click Add webhook — your pipeline is live</li>
            </ol>
          </div>
        </div>
      </div>

      <PipelineModal appState={appState} isOpen={modalOpen} onClose={() => setModalOpen(false)} />
    </div>
  );
}
