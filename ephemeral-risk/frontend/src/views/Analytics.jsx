import AnalyticsBurstChart from '../components/charts/AnalyticsBurstChart';
import TtlChart from '../components/charts/TtlChart';

export default function Analytics({ appState }) {
  const { events, ttlDistribution, modelStats } = appState;

  // const buckets = getRollingSeries().values;
  // const evPerMin = buckets.reduce((s, v) => s + v, 0);

  // Anomaly rate from live events
  const totalEvents = events.length;
  const anomalies = events.filter(e => e.is_anomaly).length;
  const anomRate = totalEvents > 0
    ? ((anomalies / totalEvents) * 100).toFixed(1)
    : "0.0";

  // Model score from backend pipeline stats (not currently used in render)
  // const modelState = modelStats?.model_state || "—";
  // const totalScored = modelStats?.total_scored ?? "—";
  // const totalAnomalies = modelStats?.total_anomalies ?? "—";

  // Task count — unique distinct event types / actions processed (not currently used in render)
  // const taskTypes = new Set(events.map(e => e.event_name || e.action || e.log_type).filter(Boolean)).size;

  // TTL summary metrics
  const ttlTotal = ttlDistribution?.total_resources ?? 0;
  const ttlCounts = ttlDistribution?.counts ?? [];
  const longLivedCount = (ttlCounts[4] || 0) + (ttlCounts[5] || 0);   // 15m+
  const longLivedPct = ttlTotal > 0 ? Math.round((longLivedCount / ttlTotal) * 100) : 0;

  // Group events by resource name to identify top resources by event count (not currently used in render)
  // const resourceCounts = {};
  // events.forEach(e => {
  //   const res = e.resource_name || e.resource_id || "";
  //   if (res && res !== "unknown" && res !== "unknown_resource") {
  //     resourceCounts[res] = (resourceCounts[res] || 0) + 1;
  //   }
  // });

  // Sort resources by count descending and limit to top 5
  // const sorted = Object.entries(resourceCounts)
  //   .sort((a, b) => b[1] - a[1])
  //   .slice(0, 5);

  // const maxVal = sorted.length > 0 ? sorted[0][1] : 1;

  // Churn <1m represents short-lived resources (0s and <1m buckets: indices 0 and 1)
  const churnCount = (ttlCounts[0] || 0) + (ttlCounts[1] || 0);
  const churnRate = ttlTotal > 0 ? Math.round((churnCount / ttlTotal) * 100) : 0;

  return (
    <div className="page-view" id="view-analytics">
      <div className="page-header">
        <div className="breadcrumb"></div>
        <h2>Analytics &amp; Telemetry</h2>
      </div>

      <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(2,1fr)' }}>
        <div className="metric-card t-orange">
          <div className="metric-label">Anomaly Rate <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" style={{ color: '#F97316' }}><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" /></svg></div>
          <div className="metric-value">{anomRate}%</div>
          <div className="metric-sub">Of total events</div>
        </div>
        <div className="metric-card t-purple">
          <div className="metric-label">Contamination Rate <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" style={{ color: '#7C3AED' }}><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg></div>
          <div className="metric-value">{modelStats?.contamination ? `${(modelStats.contamination * 100).toFixed(1)}%` : "0.17"}</div>
          <div className="metric-sub">Isolation Forest</div>
        </div>
      </div>

      {/* ── Two charts side-by-side ── */}
      <div className="analytics-two-col">
        <div className="panel">
          <div className="panel-header">
            <h3>Burst Rate (60s rolling window)</h3>
            <span style={{ fontSize: '11px', color: 'var(--sg-grey-400)' }}>Events per second</span>
          </div>
          <div style={{ padding: '16px 20px 20px', height: '300px' }}>
            <AnalyticsBurstChart appState={appState} />
          </div>
        </div>

        <div className="panel" style={{ marginTop: '4px' }}>
          <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3>Ephemeral Resource TTL Distribution</h3>
              {/* <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--sg-grey-400)' }}>Tracked</span>
                  <span style={{ fontSize: '18px', fontWeight: 800, color: 'var(--sg-black)', fontFamily: 'monospace' }}>{ttlTotal}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#E97C00' }}>Churn &lt;1m</span>
                  <span style={{ fontSize: '14px', fontWeight: 800, color: '#E97C00', fontFamily: 'monospace' }}>{churnRate}%</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#E30613' }}>Long-lived 15m+</span>
                  <span style={{ fontSize: '14px', fontWeight: 800, color: '#E30613', fontFamily: 'monospace' }}>{longLivedPct}%</span>
                </div>
              </div> */}
            </div>
            {/* <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--sg-grey-400)' }}>Tracked</span>
                <span style={{ fontSize: '18px', fontWeight: 800, color: 'var(--sg-black)', fontFamily: 'monospace' }}>{ttlTotal}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#E97C00' }}>Churn &lt;1m</span>
                <span style={{ fontSize: '18px', fontWeight: 800, color: '#E97C00', fontFamily: 'monospace' }}>{churnRate}%</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                <span style={{ fontSize: '10px', fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#E30613' }}>Long-lived 15m+</span>
                <span style={{ fontSize: '18px', fontWeight: 800, color: '#E30613', fontFamily: 'monospace' }}>{longLivedPct}%</span>
              </div>
            </div> */}
          </div>
          <div style={{ padding: '16px 20px 20px', height: '300px' }}>
            <TtlChart appState={appState} />
          </div>
        </div>
      </div>
    </div>
  );
}
