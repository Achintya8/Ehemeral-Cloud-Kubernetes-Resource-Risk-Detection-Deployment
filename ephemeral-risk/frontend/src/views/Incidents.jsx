import { useState, useCallback } from 'react';
import IncidentCard from '../components/IncidentCard';
import IncidentDetailModal from '../components/IncidentDetailModal';
import AnimatedList from '../components/ui/AnimatedList';

export default function Incidents({ appState }) {
  const { incidents, authFetch, addToast, blocklist, releaseBlocklist, actionLog } = appState;

  const [modalOpen, setModalOpen] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const handleDrillDown = useCallback((incidentId) => {
    // find the seed incident from the current list so the modal has data instantly
    const seed = incidents.find(i => i.incident_id === incidentId) || null;
    setSelectedIncidentId(incidentId);
    setSelectedIncident(seed);
    setModalOpen(true);
  }, [incidents]);

  const handleCloseModal = useCallback(() => {
    setModalOpen(false);
    setSelectedIncidentId(null);
    setSelectedIncident(null);
  }, []);

  return (
    <div className="page-view" id="view-incidents">
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div className="breadcrumb"></div>
          <h2>Prioritised Incident Queue</h2>
          <p>Risk-ranked correlated campaigns</p>
        </div>
        <span className="badge badge-red">{incidents.length} prioritised</span>
      </div>

      {/* ── Quarantine blocklist ── */}
      {blocklist.length > 0 && (
        <div style={{
          background: '#F0FFF4', border: '1px solid #BBF7D0', borderRadius: 'var(--radius-lg)',
          padding: '14px 18px', flexShrink: 0,
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
      )}
      {/* ── Activity timeline (action log) ── */}
      {actionLog?.length > 0 && (
        <div className="panel" style={{ padding: '14px 18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <span className="pulse-dot" style={{ width: '6px', height: '6px' }}></span>
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--sg-grey-600)' }}>
              Analyst Activity
            </span>
            <span className="badge" style={{ fontSize: '9px' }}>{actionLog.length} actions</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '260px', overflowY: 'auto' }}>
            {actionLog.map(entry => {
              const isErr = (entry.result || '').toLowerCase() === 'error';
              const dotColor = isErr ? 'var(--sg-red)' : '#15803D';
              const actionLabel = (entry.action_type || 'action').split('_').map(w => w[0] && w[0].toUpperCase() + w.slice(1)).join(' ');
              return (
                <div key={entry.id} style={{
                  display: 'flex', gap: '10px', alignItems: 'flex-start',
                  padding: '8px 10px', borderRadius: 'var(--radius)',
                  background: 'var(--sg-grey-50)', border: '1px solid var(--sg-grey-100)',
                }}>
                  <span style={{
                    width: '8px', height: '8px', borderRadius: '50%',
                    background: dotColor, marginTop: '5px', flexShrink: 0,
                  }}></span>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--sg-black)' }}>
                        {actionLabel}
                      </span>
                      <span style={{
                        fontSize: '9px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase',
                        color: isErr ? 'var(--sg-red)' : '#15803D',
                      }}>
                        {entry.result || 'success'}
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--sg-grey-500)', marginTop: '2px' }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>{entry.target_resource || '—'}</span>
                      <span style={{ color: 'var(--sg-grey-400)' }}> · ns/{entry.namespace || 'default'}</span>
                    </div>
                    {entry.message && (
                      <div style={{ fontSize: '11px', color: 'var(--sg-grey-600)', marginTop: '3px' }}>{entry.message}</div>
                    )}
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontSize: '10px', fontWeight: 600, color: 'var(--sg-grey-600)' }}>{entry.operator || 'system'}</div>
                    <div style={{ fontSize: '10px', color: 'var(--sg-grey-400)', fontFamily: "'JetBrains Mono', monospace" }}>
                      {(entry.created_at || '').slice(0, 16).replace('T', ' ')}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div id="incident-queue" style={{display:'flex', flexDirection:'column', gap:'16px'}}>
        {incidents.length === 0 ? (
          <div className="empty-state">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            <p>No correlated campaigns detected</p>
            <small>The detection engine is continuously analysing raw telemetry.</small>
          </div>
        ) : (
          <AnimatedList
            items={incidents}
            renderItem={(inc, i, isSelected) => (
              <div style={{ marginBottom: '16px' }}>
                <IncidentCard key={inc.incident_id} inc={inc} idx={i} authFetch={authFetch} addToast={addToast} onDrillDown={handleDrillDown} />
              </div>
            )}
          />
        )}
      </div>

      <IncidentDetailModal
        isOpen={modalOpen}
        incidentId={selectedIncidentId}
        incidentSeed={selectedIncident}
        authFetch={authFetch}
        addToast={addToast}
        onClose={handleCloseModal}
      />
    </div>
  );
}
