import { useState } from 'react';

export default function LoginView({ doLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusText, setStatusText] = useState('Secure internal access · CISO mandate 2024-07');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setStatusText('Signing in…');
    try {
      await doLogin(username, password);
      setStatusText('Signed in');
    } catch (err) {
      setError(err.message || 'Login failed');
      setStatusText('Secure internal access · CISO mandate 2024-07');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="login-view">
      <div className="login-shell">
        <div className="login-brand">
          <div className="sg-logo">
            <div className="sg-logo-top"></div>
            <div className="sg-logo-bottom"></div>
          </div>
          <div className="login-brand-text">
            <h1>Societe Generale</h1>
            <h2>Cybersecurity Operations</h2>
          </div>
        </div>

        <div className="login-card">
          <div className="login-card-header">
            <h3>Sign In</h3>
            <p>Access to the Ephemeral Risk Control console is restricted to authorised personnel.</p>
          </div>
          <div className="login-divider"></div>
          <form id="login-form" autoComplete="on" onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="login-username" className="form-label">Username</label>
              <input 
                id="login-username" 
                name="username" 
                type="text" 
                autoComplete="username" 
                required 
                className="form-input" 
                placeholder="analyst1 or admin1"
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="login-password" className="form-label">Password</label>
              <input 
                id="login-password" 
                name="password" 
                type="password" 
                autoComplete="current-password" 
                required 
                className="form-input" 
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>
            {error && <p id="login-error" className="alert-error">{error}</p>}
            <button type="submit" className="btn-primary" id="login-submit-btn" disabled={loading}>Sign In</button>
            <p style={{marginTop: '14px', padding: '10px 12px', background: 'var(--sg-grey-50)', border: '1px solid var(--sg-grey-200)', borderRadius: '4px', fontSize: '11px', color: 'var(--sg-grey-500)'}}>
              <strong>Demo credentials:</strong>&nbsp; analyst1 / hackathon &nbsp;·&nbsp; admin1 / hackathon
            </p>
          </form>
        </div>
        <p className="login-footer" id="login-status">{statusText}</p>
      </div>
    </div>
  );
}
