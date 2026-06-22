import { useState, useEffect } from 'react';
import { UserPlus, Shield, Users as UsersIcon, Eye, EyeOff, ShieldCheck, CheckCircle2, Trash2 } from 'lucide-react';

export default function Users({ appState }) {
  const { users, refreshUsers, authFetch, addToast, user } = appState;
  const [modalOpen, setModalOpen] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    refreshUsers();
  }, [refreshUsers]);

  const handleClose = () => {
    setUsername('');
    setPassword('');
    setRole('analyst');
    setShowPassword(false);
    setError('');
    setModalOpen(false);
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setLoading(true);
    setError('');
    try {
      const res = await authFetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          password,
          role,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to create user account');
      }

      addToast({
        type: 'success',
        title: 'Account Created',
        message: `Successfully created ${role} account for ${username.trim()}`,
      });

      refreshUsers();
      handleClose();
    } catch (err) {
      setError(err.message || 'An error occurred while creating the account');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (u) => {
    if (!window.confirm(`Are you sure you want to permanently delete the operator account "${u.username}"?`)) {
      return;
    }
    try {
      const res = await authFetch(`/api/users/${u.id}`, {
        method: 'DELETE',
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to delete user');
      }
      addToast({
        type: 'success',
        title: 'Account Deleted',
        message: `Successfully deleted operator account for ${u.username}`,
      });
      refreshUsers();
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Deletion Failed',
        message: err.message || 'An error occurred while deleting the account',
      });
    }
  };

  const totalUsers = users.length;
  const analystCount = users.filter((u) => u.role === 'analyst').length;
  const adminCount = users.filter((u) => u.role === 'admin').length;

  return (
    <div className="page-view" id="view-users">
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div className="breadcrumb">Administration · Analyst Accounts</div>
          <h2>Analyst Accounts</h2>
          <p>Create and manage analyst credentials and system roles for the risk detection engine</p>
        </div>
        <button id="open-user-modal" className="btn-danger flex items-center" onClick={() => setModalOpen(true)}>
          <UserPlus size={14} style={{ marginRight: '6px' }} />
          Register Account
        </button>
      </div>

      <div className="admin-grid">
        <div className="metric-card t-red">
          <div className="metric-label">
            Total Accounts <UsersIcon size={14} style={{ color: 'var(--sg-red)' }} />
          </div>
          <div className="metric-value">{totalUsers}</div>
          <div className="metric-sub">Registered system profiles</div>
        </div>
        <div className="metric-card t-blue">
          <div className="metric-label">
            Analysts <Shield size={14} style={{ color: '#2563EB' }} />
          </div>
          <div className="metric-value">{analystCount}</div>
          <div className="metric-sub">Triage and remediation roles</div>
        </div>
        <div className="metric-card t-green">
          <div className="metric-label">
            Administrators <ShieldCheck size={14} style={{ color: '#059669' }} />
          </div>
          <div className="metric-value">{adminCount}</div>
          <div className="metric-sub">Full system control roles</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Active Accounts</h3>
            <p>Users authorized to authenticate and access the Sentry Platform</p>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--sg-grey-400)' }}>{totalUsers} total</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>Status</th>
                <th style={{ width: '100px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '40px', color: 'var(--sg-grey-400)' }}>
                    Loading active accounts...
                  </td>
                </tr>
              ) : (
                users.map((u) => (
                  <tr key={u.id}>
                    <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>#{u.id}</td>
                    <td className="td-name">{u.username}</td>
                    <td>
                      <span className={`badge ${u.role === 'admin' ? 'badge-critical' : 'badge-info'}`}>
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-active flex items-center gap-2" style={{ display: 'inline-flex' }}>
                        <CheckCircle2 size={10} />
                        Active
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {u.username === user?.username ? (
                        <button
                          className="btn-ghost"
                          disabled
                          title="Cannot delete active session"
                          style={{ opacity: 0.4, cursor: 'not-allowed', padding: '4px', display: 'inline-flex', alignItems: 'center' }}
                        >
                          <Trash2 size={14} />
                        </button>
                      ) : (
                        <button
                          className="btn-ghost text-red"
                          onClick={() => handleDeleteUser(u)}
                          title="Delete operator account"
                          style={{ padding: '4px', display: 'inline-flex', alignItems: 'center' }}
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {modalOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="user-modal-title">
          <div className="modal">
            <div className="modal-top-bar"></div>
            <div className="modal-header">
              <div>
                <p style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'var(--sg-grey-400)', marginBottom: '4px' }}>
                  Access Provisioning
                </p>
                <h2 id="user-modal-title">Create Analyst Account</h2>
              </div>
              <button className="modal-close" aria-label="Close" onClick={handleClose}>
                &times;
              </button>
            </div>

            <form autoComplete="off" onSubmit={handleCreate}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>


                {error && <div className="alert-error">{error}</div>}

                <div className="form-group" style={{ marginTop: '0px' }}>
                  <label className="form-label" htmlFor="username-input">
                    Username
                  </label>
                  <input
                    id="username-input"
                    required
                    minLength={3}
                    maxLength={64}
                    pattern="^[A-Za-z0-9._-]+$"
                    className="form-input"
                    placeholder="e.g. analyst_smith"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>

                <div className="form-group" style={{ marginTop: '0px' }}>
                  <label className="form-label" htmlFor="password-input">
                    Password
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      id="password-input"
                      required
                      minLength={8}
                      maxLength={128}
                      type={showPassword ? 'text' : 'password'}
                      className="form-input"
                      placeholder="••••••••••••"
                      style={{ paddingRight: '40px' }}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      style={{
                        position: 'absolute',
                        right: '12px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        color: 'var(--sg-grey-400)',
                        cursor: 'pointer',
                      }}
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>

                <div className="form-group" style={{ marginTop: '0px' }}>
                  <label className="form-label" htmlFor="role-select">
                    System Role
                  </label>
                  <select
                    id="role-select"
                    className="form-input"
                    style={{ appearance: 'auto', background: 'var(--sg-white)' }}
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                  >
                    <option value="analyst">Analyst (Triage & Remediation)</option>
                    <option value="admin">Administrator (Full Access)</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn-secondary" onClick={handleClose} disabled={loading}>
                  Cancel
                </button>
                <button type="submit" className="btn-danger" disabled={loading}>
                  {loading ? 'Creating...' : 'Register Operator'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
