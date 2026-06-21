import { useState } from 'react';

export default function PipelineModal({ appState, isOpen, onClose }) {
  const { authFetch } = appState;
  const [step, setStep] = useState(1);
  const [repo, setRepo] = useState('');
  const [namespace, setNamespace] = useState('');
  const [error, setError] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [secretToken, setSecretToken] = useState('');
  const [pendingPipelineId, setPendingPipelineId] = useState(null);

  if (!isOpen) return null;

  const handleRepoChange = (e) => {
    const val = e.target.value;
    setRepo(val);
    const ns = val.split("/").pop().toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
    setNamespace(ns);
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!repo.trim()) return;
    try {
      const res = await authFetch(`/api/pipelines`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_name: repo.trim(),
          target_namespace: namespace || repo.trim().split("/").pop().toLowerCase(),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Registration failed");

      setPendingPipelineId(data.id);
      setWebhookUrl(`${window.location.origin}/api/webhook/github`);
      setSecretToken(data.secret_token);
      setStep(2);
    } catch (err) {
      setError(err.message || "Registration failed");
    }
  };

  const handleActivate = async () => {
    if (pendingPipelineId) {
      try {
        await authFetch(`/api/pipelines/${pendingPipelineId}/activate`, { method: "POST" });
      } catch {}
      await appState.refreshPipelines();
    }
    handleClose();
  };

  const handleClose = () => {
    setStep(1);
    setRepo('');
    setNamespace('');
    setError('');
    onClose();
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div id="pipeline-modal" className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal">
        <div className="modal-top-bar"></div>
        <div className="modal-header">
          <div>
            <p style={{fontSize:'10px', fontWeight:800, letterSpacing:'0.2em', textTransform:'uppercase', color:'var(--sg-grey-400)', marginBottom:'4px'}}>Integration Wizard</p>
            <h2 id="modal-title">Register CI/CD Pipeline</h2>
          </div>
          <button className="modal-close" aria-label="Close" onClick={handleClose}>&times;</button>
        </div>

        <div className="wizard-tabs">
          <div className={`wizard-tab ${step === 1 ? 'active' : ''}`}>01 · Repository</div>
          <div className={`wizard-tab ${step === 2 ? 'active' : ''}`}>02 · Webhook</div>
          <div className={`wizard-tab ${step === 3 ? 'active' : ''}`}>03 · Activate</div>
        </div>

        {step === 1 && (
          <div className="modal-body">
            <h3 style={{fontSize:'15px', fontWeight:700, marginBottom:'6px'}}>Identify the source repository</h3>
            <p style={{fontSize:'13px', color:'var(--sg-grey-500)', marginBottom:'20px'}}>The canonical GitHub path — a Kubernetes-safe namespace will be derived automatically.</p>
            <form id="pipeline-form" autoComplete="off" onSubmit={handleRegister}>
              <div className="form-group">
                <label className="form-label" htmlFor="repo-input">Repository Path</label>
                <input 
                  id="repo-input" 
                  required 
                  maxLength="120" 
                  pattern="[A-Za-z0-9._-]+/[A-Za-z0-9._-]+" 
                  className="form-input" 
                  placeholder="socgen/payments-api"
                  value={repo}
                  onChange={handleRepoChange}
                />
                <p id="register-status" style={{marginTop:'8px', fontSize:'12px', color: error ? 'var(--sg-red)' : 'var(--sg-grey-400)'}}>
                  {error || (namespace ? `Namespace: ${namespace}` : "Format: organisation/repository")}
                </p>
              </div>
              <div className="modal-footer" style={{padding:'20px 0 0', borderTop:'none'}}>
                <button type="button" className="btn-secondary" onClick={handleClose}>Cancel</button>
                <button type="submit" className="btn-danger">Generate Webhook →</button>
              </div>
            </form>
          </div>
        )}

        {step === 2 && (
          <div className="modal-body">
            <h3 style={{fontSize:'15px', fontWeight:700, marginBottom:'6px'}}>Configure your webhook</h3>
            <p style={{fontSize:'13px', color:'var(--sg-grey-500)', marginBottom:'20px'}}>Paste these values into your GitHub repository webhook settings.</p>
            <div style={{display:'flex', flexDirection:'column', gap:'16px'}}>
              <div className="form-group">
                <label className="form-label">Payload URL</label>
                <div className="copy-field">
                  <input readOnly className="form-input" style={{fontFamily:'monospace', fontSize:'12px', background:'var(--sg-grey-50)'}} value={webhookUrl} />
                  <button className="copy-btn" onClick={() => copyToClipboard(webhookUrl)}>Copy</button>
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Secret Token</label>
                <div className="copy-field">
                  <input readOnly className="form-input" style={{fontFamily:'monospace', fontSize:'12px', background:'var(--sg-grey-50)'}} value={secretToken} />
                  <button className="copy-btn" onClick={() => copyToClipboard(secretToken)}>Copy</button>
                </div>
              </div>
              <div style={{background:'#FFFBEB', border:'1px solid #FDE68A', borderRadius:'4px', padding:'12px', fontSize:'12px', color:'#78350F'}}>
                <strong>Content-type:</strong> application/json &nbsp;|&nbsp; <strong>Events:</strong> Workflow jobs only
              </div>
            </div>
            <div style={{display:'flex', justifyContent:'flex-end', gap:'10px', marginTop:'24px'}}>
              <button type="button" className="btn-secondary" onClick={() => setStep(1)}>← Back</button>
              <button type="button" className="btn-danger" onClick={() => setStep(3)}>I've configured it →</button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="modal-body" style={{textAlign:'center', padding:'32px 24px'}}>
            <div style={{width:'56px', height:'56px', borderRadius:'50%', background:'#ECFDF5', border:'2px solid #A7F3D0', display:'flex', alignItems:'center', justifyContent:'center', margin:'0 auto 16px'}}>
              <svg fill="none" stroke="#059669" viewBox="0 0 24 24" strokeWidth="3" style={{width:'28px', height:'28px'}}><polyline points="20 6 9 17 4 12"/></svg>
            </div>
            <h3 style={{fontSize:'18px', fontWeight:800, marginBottom:'8px'}}>Integration registered</h3>
            <p style={{fontSize:'13px', color:'var(--sg-grey-500)', maxWidth:'380px', margin:'0 auto 24px', lineHeight:'1.7'}}>The detection engine will begin streaming events as soon as GitHub dispatches the first workflow_job webhook.</p>
            <button className="btn-danger" style={{width:'100%', maxWidth:'240px'}} onClick={handleActivate}>Close &amp; View Pipelines</button>
          </div>
        )}

      </div>
    </div>
  );
}
