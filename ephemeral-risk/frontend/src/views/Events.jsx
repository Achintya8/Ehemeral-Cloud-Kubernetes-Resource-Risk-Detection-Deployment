import React, { useState } from 'react';
import { fmt } from '../utils';
import AnimatedList from '../components/ui/AnimatedList';

export default function Events({ appState }) {
  const { events, showAnomalyOnly, setShowAnomalyOnly } = appState;
  const [sortOption, setSortOption] = useState('latest');

  const filteredEvents = showAnomalyOnly ? events.filter(e => e.is_anomaly) : events;
  
  const sortedEvents = [...filteredEvents].sort((a, b) => {
    if (sortOption === 'risk') {
      return (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0);
    }
    if (sortOption === 'severity') {
      const sevMap = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1 };
      return (sevMap[b.severity] || 0) - (sevMap[a.severity] || 0);
    }
    // Default 'latest'
    return new Date(b.timestamp) - new Date(a.timestamp);
  });
  const anoms = events.filter(e => e.is_anomaly).length;

  return (
    <div className="page-view" id="view-events">
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div className="breadcrumb"></div>
          <h2>Live Event Stream</h2>
          <p>All security telemetry — cloud, K8s and GitHub CI/CD events</p>

        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--sg-grey-500)' }}>
          <span>{events.length} events</span>
          <span className="badge" style={{ borderColor: '#FBBFC7', background: '#FFF0F0', color: '#9B0013' }}>{anoms} anomalies</span>
        </div>
      </div>
      <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          <h3>All Events (last 100)</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '11px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ color: 'var(--sg-grey-500)', fontWeight: 600 }}>SORT BY:</span>
              <select 
                value={sortOption} 
                onChange={(e) => setSortOption(e.target.value)}
                style={{
                  padding: '4px 8px',
                  borderRadius: '4px',
                  border: '1px solid var(--sg-grey-300)',
                  fontSize: '11px',
                  outline: 'none',
                  cursor: 'pointer',
                  backgroundColor: 'var(--sg-white)',
                  color: 'var(--sg-black)'
                }}
              >
                <option value="latest">Latest</option>
                <option value="risk">Highest Risk Score</option>
                <option value="severity">Severity (Critical first)</option>
              </select>
            </div>
            <div style={{ width: '1px', height: '16px', background: 'var(--sg-grey-300)' }}></div>
            <div style={{ display: 'flex', gap: '4px' }}>
              <button className="btn-ghost" style={{ padding: '5px 10px', background: !showAnomalyOnly ? 'var(--sg-grey-100)' : 'transparent' }} onClick={() => setShowAnomalyOnly(false)}>All</button>
              <button className="btn-ghost" style={{ padding: '5px 10px', background: showAnomalyOnly ? 'var(--sg-grey-100)' : 'transparent' }} onClick={() => setShowAnomalyOnly(true)}>Anomalies only</button>
            </div>
          </div>
        </div>
        <div style={{ overflowX: 'auto', flex: 1 }}>
          <div style={{ height: 'calc(100vh - 250px)', minHeight: '400px' }}>
            {sortedEvents.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '32px', color: 'var(--sg-grey-400)' }}>No events yet — stream is live</div>
            ) : (
              <AnimatedList
                items={sortedEvents}
                renderItem={(e, index, isSelected) => {
                  const score = Number(e.risk_score || 0);
                  const sev = e.severity || "INFO";
                  const sevClass = sev === "CRITICAL" ? "badge-critical" : sev === "HIGH" ? "badge-high" : sev === "MEDIUM" ? "badge-medium" : "badge-info";
                  return (
                    <div className={`item ${isSelected ? 'selected' : ''}`} style={{ display: 'flex', gap: '16px', padding: '16px', alignItems: 'center', margin: '0 0 12px 0' }}>
                      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <span className={`badge ${sevClass}`}>{sev}</span>
                          <span style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--sg-grey-500)' }}>{fmt(e.timestamp)}</span>
                          <span style={{ fontSize: '12px', color: 'var(--sg-grey-400)' }}>Source IP: <span style={{ color: 'var(--sg-black)', fontFamily: 'monospace' }}>{e.source_ip || "—"}</span></span>
                          {e.is_anomaly && <span className="badge badge-critical" style={{ marginLeft: 'auto' }}>⚠ Anomaly</span>}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '11px', color: 'var(--sg-grey-400)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '2px' }}></div>
                            <div style={{ fontWeight: 600, fontSize: '14px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--sg-black)' }}>
                              {e.resource_id || e.resource_name || e.pod_name || "—"}
                            </div>
                          </div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '11px', color: 'var(--sg-grey-400)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '2px' }}>Principal</div>
                            <div style={{ fontSize: '13px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--sg-grey-600)' }}>
                              {e.principal_id || e.actor || "—"}
                            </div>
                          </div>
                          <div style={{ width: '120px', flexShrink: 0 }}>
                            <div style={{ fontSize: '11px', color: 'var(--sg-grey-400)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '2px' }}>Namespace</div>
                            <div style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--sg-grey-600)' }}>
                              {e.namespace || "—"}
                            </div>
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', width: '80px', flexShrink: 0 }}>
                            <div style={{ fontSize: '11px', color: 'var(--sg-grey-400)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '2px' }}>Risk</div>
                            <div style={{ fontSize: '20px', fontWeight: score > 40 ? 'bold' : 'normal', color: score > 70 ? '#E30613' : score > 40 ? '#E97C00' : 'var(--sg-grey-400)' }}>
                              {score.toFixed(0)}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                }}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
