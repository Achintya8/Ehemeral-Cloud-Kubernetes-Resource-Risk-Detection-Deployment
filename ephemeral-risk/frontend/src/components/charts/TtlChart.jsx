import { PieChart } from '@mui/x-charts/PieChart';

const TTL_COLORS = [
  'rgba(0, 135, 90, 1)',    // 0s      — instantaneous (safest)
  'rgba(22, 163, 74, 1)',   // <1m
  'rgba(233, 124, 0, 1)',   // 1-5m    — amber
  'rgba(249, 115, 22, 1)',  // 5-15m
  'rgba(220, 38, 38, 1)',   // 15-60m  — red
  'rgba(227, 6, 19, 1)',    // 60m+    — deep red (riskiest)
];

export default function TtlChart({ appState }) {
  const ttl = appState?.ttlDistribution || { labels: [], counts: [] };
  const labels = ttl?.labels?.length ? ttl.labels : ['0s', '<1m', '1-5m', '5-15m', '15-60m', '60m+'];
  const counts = ttl?.counts?.length ? ttl.counts : [0, 0, 0, 0, 0, 0];

  const data = labels.map((label, index) => ({
    id: index,
    value: counts[index],
    label: label,
    color: TTL_COLORS[index % TTL_COLORS.length]
  }));

  const theme = appState?.theme;
  const isDark = theme === 'dark' || (theme === 'system' && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  const emptyColor = isDark ? '#2D2D2D' : '#f5f5f5';

  const total = counts.reduce((a, b) => a + b, 0);
  const chartData = total === 0
    ? data.map(d => ({ ...d, value: 0.0001, color: emptyColor }))
    : data;

  const longLivedCount = (counts[4] || 0) + (counts[5] || 0);
  const longLivedPct = total > 0 ? Math.round((longLivedCount / total) * 100) : 0;

  const churnCount = (counts[0] || 0) + (counts[1] || 0);
  const churnRate = total > 0 ? Math.round((churnCount / total) * 100) : 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '20px', width: '100%', height: '100%', padding: '10px 0' }}>

      {/* Left Column: Doughnut Chart with centered Total tracked */}
      <div style={{ position: 'relative', width: '320px', height: '220px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <PieChart
          series={[
            {
              data: chartData,
              innerRadius: 65,
              outerRadius: 90,
              paddingAngle: 2,
              cornerRadius: 4,
              highlightScope: { fade: 'global', highlight: 'item' },
              faded: { innerRadius: 30, additionalRadius: -30, color: 'gray' },
              valueFormatter: (item) => total === 0 ? "0" : item.value.toString(),
            },
          ]}
          width={320}
          height={220}
          margin={{ top: 10, bottom: 10, left: 10, right: 10 }}
          slotProps={{
            legend: { hidden: true }
          }}
          legend={{ hidden: true }}
          hideLegend
        />

        {/* Center label inside the hollow doughnut */}
        <div style={{
          position: 'absolute',
          left: '160px',
          top: '110px',
          transform: 'translate(-50%, -50%)',
          pointerEvents: 'none',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <span style={{ fontSize: '9px', fontWeight: 800, letterSpacing: '0.05em', color: 'var(--sg-grey-400)', textTransform: 'uppercase', fontFamily: "'JetBrains Mono', monospace" }}>Tracked</span>
          <span style={{ fontSize: '24px', fontWeight: 800, color: 'var(--sg-black)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.1 }}>{total}</span>
        </div>
      </div>

      {/* Right Column: Custom Stats & Legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', width: '160px', flexShrink: 0 }}>

        {/* Churn and Long-lived Rates */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
            <span style={{ color: 'var(--sg-grey-500)', fontWeight: 'bold', fontFamily: "'JetBrains Mono', monospace" }}>Churn &lt;1m:</span>
            <span style={{ fontWeight: 800, color: '#E97C00', fontFamily: "'JetBrains Mono', monospace" }}>{churnRate}%</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
            <span style={{ color: 'var(--sg-grey-500)', fontWeight: 'bold', fontFamily: "'JetBrains Mono', monospace" }}>Long-lived:</span>
            <span style={{ fontWeight: 800, color: '#E30613', fontFamily: "'JetBrains Mono', monospace" }}>{longLivedPct}%</span>
          </div>
        </div>

        {/* Divider line */}
        <div style={{ height: '1px', background: 'var(--sg-grey-200)' }} />

        {/* Custom Legend showing values */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {labels.map((label, index) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '10px' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '2px', background: TTL_COLORS[index % TTL_COLORS.length], display: 'inline-block', flexShrink: 0 }} />
              <span style={{ color: isDark ? '#CFCFCF' : '#525252', fontWeight: 'bold', fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>
              <span style={{ color: '#A0A0A0', marginLeft: 'auto', fontFamily: "'JetBrains Mono', monospace" }}>({counts[index] || 0})</span>
            </div>
          ))}
        </div>

      </div>

    </div>
  );
}
