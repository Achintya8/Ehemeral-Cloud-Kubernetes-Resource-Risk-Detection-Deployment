import { useState } from 'react';
import BurstChart from '../components/charts/BurstChart';
import SeverityChart from '../components/charts/SeverityChart';
import IncidentCard from '../components/IncidentCard';
import AnimatedList from '../components/ui/AnimatedList';
import { fmt, sevStyle } from '../utils';

export default function Dashboard({ appState }) {
  const { role, events, incidents, authFetch, addToast, dbStats, modelStats, theme } = appState;
  const [showAnomalyOnly, setShowAnomalyOnly] = useState(false);

  const totalEvents = dbStats?.events ?? events.length;
  const anomalies = events.filter(e => e.is_anomaly).length;
  const pct = totalEvents > 0 ? ((anomalies / totalEvents) * 100).toFixed(1) : "0.0";
  const uniqueAssets = new Set(events.map(e => e.resource_id || e.resource_name || e.pod_name).filter(Boolean)).size;
  const avgRisk = events.length ? (events.reduce((s, e) => s + Number(e.risk_score || 0), 0) / events.length).toFixed(0) : 0;
  const highRisk = events.filter(e => Number(e.risk_score || 0) > 70).length;

  const filteredEvents = showAnomalyOnly ? events.filter(e => e.is_anomaly) : events;

  return (
    <div className="page-view" id="view-dashboard">
      <section className="metrics-grid">
        <div className="metric-card t-red">
          <div className="metric-label">Total Events <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#E2001A'}}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
          <div className="metric-value">{totalEvents}</div>
          <div className="metric-sub">Last 4 hours</div>
        </div>
        <div className="metric-card t-orange">
          <div className="metric-label">Anomalies Detected <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#F97316'}}><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></div>
          <div className="metric-value">{anomalies}</div>
          <div className="metric-sub">{pct}% of events</div>
        </div>
        <div className="metric-card t-blue">
          <div className="metric-label">Open Incidents <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#2563EB'}}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
          <div className="metric-value">{incidents.length}</div>
          <div className="metric-sub">Correlated campaigns</div>
        </div>
        <div className="metric-card t-purple">
          <div className="metric-label">Ephemeral Assets <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#7C3AED'}}><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg></div>
          <div className="metric-value">{uniqueAssets}</div>
          <div className="metric-sub">Unique resources seen</div>
        </div>
        <div className="metric-card t-amber">
          <div className="metric-label">Avg Risk Score <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#D97706'}}><path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/></svg></div>
          <div className="metric-value">{avgRisk}</div>
          <div className="metric-sub">0–100 scale</div>
        </div>
        <div className="metric-card t-rose">
          <div className="metric-label">High Risk Events <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{color:'#E11D48'}}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
          <div className="metric-value">{highRisk}</div>
          <div className="metric-sub">Risk score &gt; 70</div>
        </div>
      </section>

      <section className="charts-row">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3>Event Timeline</h3>
              <p>Rolling 60-second event volume and anomaly detections</p>
            </div>
            <div style={{display:'flex', alignItems:'center', gap:'14px', fontSize:'11px', color:'var(--sg-grey-500)'}}>
              <span style={{display:'flex', alignItems:'center', gap:'5px'}}><span style={{width:'8px', height:'8px', borderRadius:'50%', background:'#E2001A', display:'inline-block'}}></span>Events/s</span>
            </div>
          </div>
          <div className="chart-wrap">
            <BurstChart appState={appState} />
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3>Severity Split</h3>
              <p>Distribution across all live events</p>
            </div>
          </div>
          <div className="chart-wrap" style={{height:'200px', display:'flex', alignItems:'center', justifyContent:'center'}}>
            <SeverityChart events={events} theme={theme} />
          </div>
        </div>
      </section>

      <section className="two-col">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3>Recent Events</h3>
              <p>Latest cloud, K8s and identity telemetry</p>
            </div>
            <button className="btn-ghost" style={{fontSize:'11px', padding:'5px 10px'}} onClick={() => setShowAnomalyOnly(!showAnomalyOnly)}>
              {showAnomalyOnly ? 'Show all' : 'Hide noise'}
            </button>
          </div>
          <div className="panel-scroll" style={{ height: '350px' }}>
            {filteredEvents.length === 0 ? (
              <div style={{textAlign:'center', padding:'32px', color:'var(--sg-grey-400)'}}>Awaiting events…</div>
            ) : (
              <AnimatedList
                items={filteredEvents.slice(0, 20)}
                renderItem={(e, index, isSelected) => {
                  const score = Number(e.risk_score || 0);
                  const sev = e.severity || "INFO";
                  const sevClass = sev === "CRITICAL" ? "badge-critical" : sev === "HIGH" ? "badge-high" : sev === "MEDIUM" ? "badge-medium" : "badge-info";
                  return (
                    <div className={`item ${isSelected ? 'selected' : ''}`} style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', gap: '16px', margin: 0}}>
                      <div style={{display: 'flex', flexDirection: 'column', gap: '6px', flex: 1, minWidth: 0}}>
                        <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                          <span className={`badge ${sevClass}`}>{sev}</span>
                          <span style={{fontFamily: 'monospace', fontSize: '11px', color: 'var(--sg-grey-500)'}}>{fmt(e.timestamp)}</span>
                          <span style={{fontWeight: score > 40 ? 'bold' : 'normal', color: score > 70 ? '#E30613' : score > 40 ? '#E97C00' : 'var(--sg-grey-400)', fontSize: '12px'}}>Risk: {score.toFixed(0)}</span>
                        </div>
                        <div style={{fontWeight: 600, fontSize: '13px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>
                          {e.resource_id || e.resource_name || "Unknown Resource"}
                        </div>
                        <div style={{fontSize: '11px', color: 'var(--sg-grey-400)'}}>
                          IP: {e.source_ip || "—"}
                        </div>
                      </div>
                    </div>
                  );
                }}
              />
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <h3>Active Incidents</h3>
              <p>Top priority correlated campaigns</p>
            </div>
            <div style={{display:'flex', alignItems:'center', gap:'8px'}}>
              <span className="badge badge-red">{incidents.length}</span>
              <button onClick={() => appState.setCurrentView('incidents')} className="btn-ghost" style={{fontSize:'11px', padding:'5px 10px'}}>View all →</button>
            </div>
          </div>
          <div className="panel-scroll" style={{padding:'8px', height: '350px'}}>
            {incidents.length === 0 ? (
              <div className="empty-state"><p>No active incidents</p><small>Raw telemetry is being analysed continuously.</small></div>
            ) : (
              <AnimatedList
                items={incidents.slice(0, 5)}
                renderItem={(inc, index, isSelected) => {
                  const sty = sevStyle(inc.severity);
                  return (
                    <div className={`incident-card ${sty.card} ${isSelected ? 'selected' : ''}`} style={{padding:'12px 14px', margin: 0, display:'flex', alignItems:'center', gap:'14px', cursor:'pointer'}} onClick={() => appState.setCurrentView('incidents')}>
                      <div className={`incident-score ${sty.score}`} style={{fontSize:'24px', minWidth:'48px', marginRight:'6px', flexShrink:0}}>{Math.round(Number(inc.risk_score || 0))}</div>
                      <div style={{minWidth:0}}>
                        <div style={{display:'flex', alignItems:'center', gap:'6px'}}><span className={`badge ${sty.badge}`}>{inc.severity}</span></div>
                        <div style={{fontFamily:'monospace', fontSize:'10px', color:'var(--sg-grey-400)', marginTop:'4px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{inc.incident_id}</div>
                      </div>
                    </div>
                  );
                }}
              />
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
