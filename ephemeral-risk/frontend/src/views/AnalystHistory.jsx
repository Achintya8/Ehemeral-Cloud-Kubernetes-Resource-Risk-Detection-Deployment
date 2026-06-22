import React from 'react';

export default function AnalystHistory({ appState }) {
  const { blocklist, releaseBlocklist, actionLog } = appState;

  return (
    <div className="page-view" id="view-analyst-history">
      <div className="page-header" style={{display:'flex', alignItems:'flex-end', justifyContent:'space-between', flexWrap:'wrap', gap:'12px', marginBottom: '24px'}}>
        <div>
          <div className="breadcrumb">Administration · Analyst History</div>
          <h2>Analyst History & Quarantine</h2>
          <p>Review analyst containment actions and manage the active quarantine blocklist</p>
        </div>
      </div>

      {/* ── Quarantine blocklist ── */}
      {blocklist && blocklist.length > 0 ? (
        <div style={{
          background: '#F0FFF4', border: '1px solid #BBF7D0', borderRadius: 'var(--radius-lg)',
          padding: '14px 18px', flexShrink: 0, marginBottom: '24px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span className="pulse-dot" style={{ width: '6px', height: '6px' }}></span>
                <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.14em', textTransform: 'uppercase', color: '#15803D' }}>
                  Quarantine Active
                </span>
                <span className="badge" style={{ background: '#ECFDF5', borderColor: '#A7F3D0', color: '#065F46', fontSize: '9px' }}>
                  {blocklist.length} source{blocklist.length !== 1 ? 's' : ''} contained
                </span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {blocklist.map(entry => (
                  <span key={entry.principal_id} style={{
                    display: 'inline-flex', alignItems: 'center', gap: '6px',
                    background: 'var(--sg-white)', border: '1px solid var(--sg-grey-200)',
                    borderRadius: 'var(--radius)', padding: '4px 10px', fontSize: '11px',
                    fontFamily: "'JetBrains Mono', monospace", color: 'var(--sg-grey-600)',
                  }}>
                    <span style={{ color: '#15803D', fontWeight: 700 }}>{entry.principal_id}</span>
                    <span style={{ color: 'var(--sg-grey-400)', fontSize: '10px' }}>
                      {entry.action_type.split('_').map(w => w[0]).join('').toUpperCase()} · {entry.created_at?.slice(0, 16).replace('T', ' ')}
                    </span>
                    <button
                      onClick={() => releaseBlocklist(entry.principal_id)}
                      style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        color: 'var(--sg-grey-400)', fontSize: '13px', lineHeight: 1,
                        marginLeft: '2px', padding: '0',
                      }}
                      title="Unblock this source"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="panel" style={{ padding: '24px', textAlign: 'center', color: 'var(--sg-grey-400)', marginBottom: '24px' }}>
          No active quarantines.
        </div>
      )}

      {/* ── Activity timeline (action log) ── */}
      <div className="panel" style={{ padding: '14px 18px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <span className="pulse-dot" style={{ width: '6px', height: '6px', background: 'var(--sg-grey-400)' }}></span>
          <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--sg-grey-600)' }}>
            Analyst Activity Log
          </span>
          {actionLog && actionLog.length > 0 && (
            <span className="badge" style={{ fontSize: '9px' }}>{actionLog.length} actions</span>
          )}
        </div>
        
        {actionLog && actionLog.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '500px', overflowY: 'auto' }}>
            {actionLog.map(entry => {
              const isErr = (entry.result || '').toLowerCase() === 'error';
              const dotColor = isErr ? 'var(--sg-red)' : '#15803D';
              const actionLabel = (entry.action_type || 'action').split('_').map(w => w[0] && w[0].toUpperCase() + w.slice(1)).join(' ');
              return (
                <div key={entry.id} className="history-row" style={{
                  padding: '12px 14px', borderRadius: 'var(--radius)',
                  background: 'var(--sg-white)', border: '1px solid var(--sg-grey-200)',
                }}>
                  <span style={{
                    width: '8px', height: '8px', borderRadius: '50%',
                    background: dotColor, marginTop: '6px', flexShrink: 0,
                  }}></span>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--sg-black)' }}>
                        {actionLabel}
                      </span>
                      <span style={{
                        fontSize: '9px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase',
                        color: isErr ? 'var(--sg-red)' : '#15803D',
                      }}>
                        {entry.result || 'success'}
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--sg-grey-500)', marginTop: '4px' }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", color: 'var(--sg-grey-700)' }}>{entry.target_resource || '—'}</span>
                      <span style={{ color: 'var(--sg-grey-400)' }}> · namespace: {entry.namespace || 'default'}</span>
                    </div>
                    {entry.message && (
                      <div style={{ fontSize: '12px', color: 'var(--sg-grey-600)', marginTop: '4px', background: 'var(--sg-grey-50)', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--sg-grey-200)' }}>
                        {entry.message}
                      </div>
                    )}
                  </div>
                  <div className="history-row-metadata">
                    <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--sg-grey-600)' }}>Operator: {entry.operator || 'system'}</div>
                    <div style={{ fontSize: '11px', color: 'var(--sg-grey-400)', fontFamily: "'JetBrains Mono', monospace", marginTop: '4px' }}>
                      {(entry.created_at || '').slice(0, 16).replace('T', ' ')}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--sg-grey-400)' }}>
            No activity logged yet.
          </div>
        )}
      </div>
    </div>
  );
}
