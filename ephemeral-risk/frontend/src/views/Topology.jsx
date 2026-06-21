import React, { useState, useEffect, useRef, useCallback } from 'react';
import Pipeline3D from '../components/Pipeline3D';
import SimulationEngine from '../components/SimulationEngine';
import { fmt } from '../utils';

/* ═══ SocGen Brand Colours ═══ */
const SG = {
  red:      '#E30613',
  redDark:  '#B5040F',
  black:    '#1A1A1A',
  dark:     '#2D2D2D',
  blue:     '#0065B3',
  green:    '#00875A',
  amber:    '#E97C00',
  white:    '#FFFFFF',
  grey200:  '#E8E8E8',
  grey400:  '#A0A0A0',
  grey500:  '#767676',
  bg:       '#0F0F0F',
  bgPanel:  '#141414',
  bgDeep:   '#0A0A0A',
};

const ACTION_COLORS = {
  'POD CONTAINED':        SG.green,
  'CREDENTIALS REVOKED':   SG.red,
  'NETWORK GUARDRAILED':  SG.blue,
  'SESSION TERMINATED':   SG.amber,
  'POLICY ENFORCED':      SG.green,
  'NODE QUARANTINED':     SG.redDark,
};

/* ── Slider ──────────────────────────────────────────────────── */
function Slider({ label, value, min, max, step, unit, onChange, color }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, minWidth: '120px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontWeight: 600 }}>
        <span style={{ color: SG.grey400, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</span>
        <span style={{ color: color || SG.grey200, fontFamily: 'monospace' }}>
          {value}{unit || ''}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        style={{
          width: '100%', height: '4px', borderRadius: '2px', appearance: 'none',
          background: `linear-gradient(90deg, ${color || SG.blue} 0%, ${color || SG.blue} ${((value - min) / (max - min)) * 100}%, ${SG.dark} ${((value - min) / (max - min)) * 100}%, ${SG.dark} 100%)`,
          cursor: 'pointer',
        }}
      />
    </div>
  );
}

/* ── Stat pill ──────────────────────────────────────────────────── */
function StatPill({ label, value, color }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '8px',
      background: SG.bgPanel, border: `1px solid ${SG.dark}`,
      borderRadius: '6px', padding: '8px 14px',
    }}>
      <div style={{ width: '4px', height: '24px', borderRadius: '2px', background: color }} />
      <div>
        <div style={{ fontSize: '10px', color: SG.grey500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
        <div style={{ fontSize: '16px', fontWeight: 700, color: SG.white, fontFamily: 'monospace' }}>{value}</div>
      </div>
    </div>
  );
}

/* ── LB Node card ───────────────────────────────────────────────── */
function LBNodeCard({ index, load, total, color }) {
  const pct = total > 0 ? (load / total * 100).toFixed(0) : 0;
  return (
    <div style={{
      flex: 1, minWidth: '100px', background: SG.bgPanel,
      border: `1px solid ${SG.dark}`, borderRadius: '6px',
      padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '6px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '11px', fontWeight: 600, color: SG.grey400 }}>Node {index + 1}</span>
        <span style={{ fontSize: '18px', fontWeight: 700, color, fontFamily: 'monospace' }}>{load}</span>
      </div>
      <div style={{ width: '100%', height: '3px', borderRadius: '2px', background: SG.dark, overflow: 'hidden' }}>
        <div style={{
          width: `${Math.min(100, pct)}%`, height: '100%', borderRadius: '2px',
          background: color, transition: 'width 0.3s ease',
        }} />
      </div>
      <div style={{ fontSize: '10px', color: SG.grey500, textAlign: 'right' }}>{pct}%</div>
    </div>
  );
}

/* ── Containment log entry ──────────────────────────────────────── */
function ContainmentEntry({ entry }) {
  const actionColor = ACTION_COLORS[entry.action] || SG.grey400;
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '10px',
      padding: '8px 12px', borderBottom: `1px solid ${SG.dark}`,
      animation: 'slideIn 0.3s ease',
    }}>
      {/* Action badge */}
      <div style={{
        padding: '3px 10px', borderRadius: '3px', fontSize: '10px', fontWeight: 700,
        background: `${actionColor}22`, color: actionColor,
        border: `1px solid ${actionColor}44`, letterSpacing: '0.5px', whiteSpace: 'nowrap',
      }}>
        {entry.action}
      </div>
      {/* Resource */}
      <span style={{ fontSize: '11px', color: SG.grey400, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.resource}
      </span>
      {/* Severity */}
      <span style={{
        fontSize: '10px', fontFamily: 'monospace', fontWeight: 700,
        color: entry.severity === 'CRITICAL' ? SG.red : entry.severity === 'HIGH' ? SG.amber : SG.grey400,
      }}>
        {entry.risk}
      </span>
      {/* Time */}
      <span style={{ fontSize: '10px', color: SG.grey500, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
        {fmt(entry.timestamp)}
      </span>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   Topology Page
   ═══════════════════════════════════════════════════════════════════ */
export default function Topology({ appState }) {
  const { events, incidents, streamStatus } = appState;

  // Mode toggle
  const [mode, setMode] = useState('simulation');

  // Simulation config
  const [eventRate, setEventRate] = useState(3);
  const [anomalyMix, setAnomalyMix] = useState(20);
  const [lbNodes, setLbNodes] = useState(3);
  const [playing, setPlaying] = useState(true);
  const [scrubPos, setScrubPos] = useState(1);
  const [autoContainDelay, setAutoContainDelay] = useState(6000);

  // Simulation state
  const [simEvents, setSimEvents] = useState([]);
  const [simIncidents, setSimIncidents] = useState([]);
  const [simStats, setSimStats] = useState({ anomalies: 0, burst: 0, lbLoads: [0, 0, 0], totalEvents: 0 });

  // Containment action log
  const [containmentLog, setContainmentLog] = useState([]);

  const engineRef = useRef(null);

  /* ── Containment callback ───────────────────────────────────── */
  const handleThreatContained = useCallback((eventId, event, action) => {
    const entry = {
      id: Date.now() + Math.random(),
      eventId,
      action,
      resource: event.resource_name || event.pod_name || event.resource_id || event.event_id || 'Unknown',
      severity: event.severity || 'INFO',
      risk: Number(event.risk_score || 0),
      timestamp: event.timestamp || new Date().toISOString(),
      namespace: event.namespace || '—',
      identity: event.identity || event.principal_id || '—',
    };
    setContainmentLog(prev => [entry, ...prev].slice(0, 50));

    // In simulation mode, remove from simEvents so 3D ejects it after containment animation
    if (mode === 'simulation') {
      setSimEvents(prev => prev.filter(e => e.event_id !== eventId));
    }
  }, [mode]);

  /* ── Simulation engine lifecycle ───────────────────────────── */
  useEffect(() => {
    if (mode !== 'simulation') {
      if (engineRef.current) { engineRef.current.dispose(); engineRef.current = null; }
      setSimEvents([]);
      setSimIncidents([]);
      setSimStats({ anomalies: 0, burst: 0, lbLoads: [0, 0, 0], totalEvents: 0 });
      return;
    }

    const engine = new SimulationEngine({
      onTick: (data) => {
        setSimEvents(prev => {
          const merged = [...data.events, ...prev];
          return merged.slice(0, 200);
        });
        setSimIncidents(data.incidents);
        setSimStats(prev => ({
          anomalies: prev.anomalies + data.anomalies,
          burst: data.burst,
          lbLoads: data.lbLoads,
          totalEvents: prev.totalEvents + data.events.length,
        }));
      },
      onIncident: (inc) => {
        setSimIncidents(prev => {
          const exists = prev.find(i => i.incident_id === inc.incident_id);
          if (exists) return prev;
          return [inc, ...prev].slice(0, 20);
        });
      },
    });

    engine.setConfig({ eventRate, anomalyMix, lbNodes, playing, scrubPos });
    engine.start();
    engineRef.current = engine;

    return () => {
      engine.dispose();
      engineRef.current = null;
    };
  }, [mode]);

  useEffect(() => {
    if (engineRef.current) {
      engineRef.current.setConfig({ eventRate, anomalyMix, lbNodes, playing, scrubPos });
    }
  }, [eventRate, anomalyMix, lbNodes, playing, scrubPos]);

  /* ── Scrub playback ─────────────────────────────────────────── */
  useEffect(() => {
    if (mode !== 'simulation' || !engineRef.current) return;
    if (scrubPos < 1 && !playing) {
      const snapshot = engineRef.current.getSnapshotAtPosition(scrubPos);
      setSimEvents(snapshot);
    }
  }, [scrubPos, playing, mode]);

  /* ── Derived ───────────────────────────────────────────────── */
  const activeEvents = mode === 'realtime' ? events : simEvents;
  const activeIncidents = mode === 'realtime' ? incidents : simIncidents;
  const containedCount = containmentLog.length;

  /* ── Reset ──────────────────────────────────────────────────── */
  const handleReset = useCallback(() => {
    if (engineRef.current) engineRef.current.reset();
    setSimEvents([]);
    setSimIncidents([]);
    setContainmentLog([]);
    setSimStats({ anomalies: 0, burst: 0, lbLoads: new Array(lbNodes).fill(0), totalEvents: 0 });
  }, [lbNodes]);

  const totalLBLoad = (simStats.lbLoads || []).reduce((a, b) => a + b, 0);

  const lbColors = [SG.blue, SG.green, SG.amber, '#7C3AED', SG.red, '#00BFA5', SG.grey400, SG.redDark];

  return (
    <div className="page-view" id="view-topology" style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - var(--header-h))',
      maxHeight: 'calc(100vh - var(--header-h))',
      minHeight: 'calc(100vh - var(--header-h))',
      padding: 0,
      margin: 0,
      gap: 0,
      overflow: 'hidden',
      background: SG.bg,
    }}>
      {/* ── Header ────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 20px', borderBottom: `1px solid ${SG.dark}`,
        background: SG.bg, flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: SG.red }} />
            <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: SG.white, letterSpacing: '1px' }}>
              3D TOPOLOGY
            </h2>
          </div>

          {/* Mode toggle */}
          <div style={{
            display: 'flex', background: SG.dark, borderRadius: '4px', overflow: 'hidden',
            border: `1px solid #3D3D3D`,
          }}>
            <button
              onClick={() => setMode('simulation')}
              style={{
                padding: '5px 14px', fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px',
                background: mode === 'simulation' ? SG.red : 'transparent',
                color: mode === 'simulation' ? SG.white : SG.grey400,
                border: 'none', cursor: 'pointer',
              }}
            >SIMULATION</button>
            <button
              onClick={() => setMode('realtime')}
              style={{
                padding: '5px 14px', fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px',
                background: mode === 'realtime' ? SG.red : 'transparent',
                color: mode === 'realtime' ? SG.white : SG.grey400,
                border: 'none', cursor: 'pointer',
              }}
            >REAL-TIME</button>
          </div>

          {mode === 'realtime' && (
            <span style={{
              display: 'flex', alignItems: 'center', gap: '5px',
              fontSize: '10px', color: streamStatus === 'live' ? SG.green : SG.amber,
              fontWeight: 600,
            }}>
              <span style={{
                width: '5px', height: '5px', borderRadius: '50%',
                background: streamStatus === 'live' ? SG.green : SG.amber,
              }} />
              {streamStatus === 'live' ? 'LIVE' : streamStatus === 'reconnecting' ? 'RECONNECTING' : 'OFFLINE'}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          {mode === 'simulation' && (
            <>
              <button onClick={() => setPlaying(!playing)} style={{
                padding: '4px 12px', fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px',
                background: playing ? SG.amber : SG.blue,
                color: SG.white, border: 'none', borderRadius: '3px', cursor: 'pointer',
              }}>
                {playing ? '⏸ PAUSE' : '▶ PLAY'}
              </button>
              <button onClick={handleReset} style={{
                padding: '4px 12px', fontSize: '10px', fontWeight: 700,
                background: 'transparent', color: SG.grey400,
                border: `1px solid ${SG.dark}`, borderRadius: '3px', cursor: 'pointer',
              }}>↺ RESET</button>
            </>
          )}
        </div>
      </div>

      {/* ── Body: 3D + side panels ───────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', gap: '0', minHeight: 0 }}>
        {/* ── Left: 3D viewport + controls ────────────────────── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0, maxHeight: '100%' }}>
          {/* 3D Viewport */}
          <div style={{ flex: 1, position: 'relative', minHeight: '200px' }}>
            <Pipeline3D
              events={activeEvents}
              incidents={activeIncidents}
              lbNodes={lbNodes}
              showLB={mode === 'simulation'}
              onThreatContained={handleThreatContained}
              autoContainDelay={autoContainDelay}
            />

            {/* Overlay: node count */}
            <div style={{
              position: 'absolute', top: '12px', left: '14px',
              background: 'rgba(15,15,15,0.85)', border: `1px solid ${SG.dark}`,
              borderRadius: '4px', padding: '6px 12px', backdropFilter: 'blur(8px)',
            }}>
              <div style={{ fontSize: '8px', color: SG.grey500, textTransform: 'uppercase', letterSpacing: '1px', fontWeight: 600 }}>
                {mode === 'simulation' ? 'SIMULATION' : 'REAL-TIME MIRROR'}
              </div>
              <div style={{ fontSize: '18px', fontWeight: 800, color: SG.white, fontFamily: 'monospace' }}>
                {mode === 'simulation' ? simEvents.length : events.length}
              </div>
              <div style={{ fontSize: '9px', color: SG.grey400 }}>active nodes</div>
            </div>

            {/* Overlay: threat counter */}
            <div style={{
              position: 'absolute', top: '12px', right: '14px',
              background: 'rgba(15,15,15,0.85)', border: `1px solid ${SG.red}44`,
              borderRadius: '4px', padding: '6px 12px', backdropFilter: 'blur(8px)',
            }}>
              <div style={{ fontSize: '8px', color: SG.red, textTransform: 'uppercase', letterSpacing: '1px', fontWeight: 700 }}>
                THREATS
              </div>
              <div style={{ fontSize: '18px', fontWeight: 800, color: SG.red, fontFamily: 'monospace' }}>
                {activeEvents.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH' || Number(e.risk_score) >= 70).length}
              </div>
            </div>

            {/* Overlay: contained counter */}
            {containedCount > 0 && (
              <div style={{
                position: 'absolute', top: '12px', right: '140px',
                background: 'rgba(15,15,15,0.85)', border: `1px solid ${SG.green}44`,
                borderRadius: '4px', padding: '6px 12px', backdropFilter: 'blur(8px)',
              }}>
                <div style={{ fontSize: '8px', color: SG.green, textTransform: 'uppercase', letterSpacing: '1px', fontWeight: 700 }}>
                  CONTAINED
                </div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: SG.green, fontFamily: 'monospace' }}>
                  {containedCount}
                </div>
              </div>
            )}
          </div>

          {/* Control panel */}
          <div style={{
            flexShrink: 0, background: SG.bg,
            borderTop: `1px solid ${SG.dark}`,
            padding: '10px 20px',
            display: 'flex', flexDirection: 'column', gap: '10px',
          }}>
            {/* Sliders */}
            {mode === 'simulation' && (
              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                <Slider label="Event Rate" value={eventRate} min={1} max={20} step={1} unit="/s" onChange={setEventRate} color={SG.blue} />
                <Slider label="Anomaly Mix" value={anomalyMix} min={0} max={80} step={1} unit="%" onChange={setAnomalyMix} color={SG.red} />
                <Slider label="LB Nodes" value={lbNodes} min={2} max={8} step={1} unit="" onChange={setLbNodes} color={SG.green} />
                <Slider label="Contain Delay" value={autoContainDelay / 1000} min={2} max={15} step={1} unit="s" onChange={v => setAutoContainDelay(v * 1000)} color={SG.amber} />
              </div>
            )}

            {/* Stats row */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <StatPill label="Total Events" value={mode === 'simulation' ? simStats.totalEvents : events.length} color={SG.blue} />
              <StatPill label="Anomalies" value={mode === 'simulation' ? simStats.anomalies : events.filter(e => e.is_anomaly).length} color={SG.red} />
              <StatPill label="Burst" value={mode === 'simulation' ? simStats.burst : '—'} color={SG.amber} />
              <StatPill label="Incidents" value={activeIncidents.length} color="#7C3AED" />
              <StatPill label="Contained" value={containedCount} color={SG.green} />
            </div>

            {/* LB load distribution */}
            {mode === 'simulation' && (
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {(simStats.lbLoads || []).map((load, i) => (
                  <LBNodeCard key={i} index={i} load={load} total={totalLBLoad} color={lbColors[i % lbColors.length]} />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Containment action log ───────────────────── */}
        <div style={{
          width: '340px',
          flexShrink: 0,
          background: SG.bg,
          borderLeft: `1px solid ${SG.dark}`,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          minHeight: 0,
          maxHeight: '100%',
        }}>
          <div style={{
            padding: '10px 16px', borderBottom: `1px solid ${SG.dark}`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '6px', height: '6px', borderRadius: '2px', background: SG.green }} />
              <span style={{ fontSize: '11px', fontWeight: 700, color: SG.white, letterSpacing: '0.5px', textTransform: 'uppercase' }}>
                Containment Log
              </span>
            </div>
            <span style={{
              fontSize: '10px', fontWeight: 700, fontFamily: 'monospace',
              color: SG.green, background: `${SG.green}18`,
              padding: '2px 8px', borderRadius: '3px',
            }}>
              {containedCount}
            </span>
          </div>

          <div style={{ flex: 1, overflow: 'auto', minHeight: 0, maxHeight: '100%' }}>
            {containmentLog.length === 0 ? (
              <div style={{
                padding: '32px 16px', textAlign: 'center', color: SG.grey500, fontSize: '11px',
              }}>
                <div style={{ fontSize: '24px', marginBottom: '8px', opacity: 0.3 }}>🛡️</div>
                <div>No containment actions yet</div>
                <div style={{ marginTop: '4px', fontSize: '10px' }}>
                  Threats are auto-contained after {autoContainDelay / 1000}s
                </div>
              </div>
            ) : containmentLog.map(entry => (
              <ContainmentEntry key={entry.id} entry={entry} />
            ))}
          </div>

          {/* Summary at bottom */}
          {containmentLog.length > 0 && (
            <div style={{
              padding: '10px 16px', borderTop: `1px solid ${SG.dark}`,
              background: SG.bgPanel, flexShrink: 0,
            }}>
              <div style={{ fontSize: '9px', color: SG.grey500, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
                Action Breakdown
              </div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {Object.entries(
                  containmentLog.reduce((acc, e) => {
                    acc[e.action] = (acc[e.action] || 0) + 1;
                    return acc;
                  }, {})
                ).map(([action, count]) => (
                  <div key={action} style={{
                    fontSize: '9px', fontWeight: 600, padding: '2px 8px', borderRadius: '3px',
                    background: `${ACTION_COLORS[action] || SG.grey400}18`,
                    color: ACTION_COLORS[action] || SG.grey400,
                    border: `1px solid ${ACTION_COLORS[action] || SG.grey400}33`,
                  }}>
                    {action.replace(/S$/, '')} ×{count}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom: Event table ───────────────────────────────── */}
      <div style={{
        flexShrink: 0, maxHeight: '160px', overflow: 'auto',
        background: SG.bgDeep, borderTop: `1px solid ${SG.dark}`,
      }}>
        <table className="data-table" style={{ fontSize: '11px' }}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Resource</th>
              <th>Namespace</th>
              <th>Risk</th>
              <th>Severity</th>
              {mode === 'simulation' && <th>LB Node</th>}
            </tr>
          </thead>
          <tbody>
            {activeEvents.length === 0 ? (
              <tr><td colSpan={mode === 'simulation' ? 7 : 6} style={{
                textAlign: 'center', padding: '16px', color: SG.grey500,
              }}>
                {mode === 'simulation' ? 'Press Play to start simulation' : 'Waiting for live events…'}
              </td></tr>
            ) : activeEvents.slice(0, 40).map(e => {
              const score = Number(e.risk_score || 0);
              const sev = e.severity || 'INFO';
              const sevClass = sev === 'CRITICAL' ? 'badge-critical' : sev === 'HIGH' ? 'badge-high' : sev === 'MEDIUM' ? 'badge-medium' : 'badge-info';
              return (
                <tr key={e.event_id}>
                  <td style={{ fontFamily: 'monospace', whiteSpace: 'nowrap', fontSize: '10px' }}>{fmt(e.timestamp)}</td>
                  <td style={{ textTransform: 'capitalize' }}>{e.event_type || e.resource_type || '—'}</td>
                  <td style={{ maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {e.resource_name || e.resource_id || '—'}
                  </td>
                  <td style={{ fontSize: '10px' }}>{e.namespace || '—'}</td>
                  <td>
                    <span style={{
                      fontFamily: 'monospace', fontWeight: score > 50 ? 700 : 400,
                      color: score >= 80 ? SG.red : score >= 60 ? SG.amber : score >= 30 ? SG.grey200 : SG.grey500,
                    }}>
                      {score}
                    </span>
                  </td>
                  <td><span className={`badge ${sevClass}`} style={{ fontSize: '10px' }}>{sev}</span></td>
                  {mode === 'simulation' && (
                    <td style={{ fontFamily: 'monospace', fontSize: '10px' }}>
                      {e._lbNode !== undefined ? `Node ${e._lbNode + 1}` : '—'}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Inline keyframe for slide-in animation */}
      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateX(-8px); }
          to   { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </div>
  );
}
