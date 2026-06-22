import { PieChart } from '@mui/x-charts/PieChart';

export default function SeverityChart({ events, theme }) {
  const critical = events.filter(e => String(e.severity).toUpperCase() === "CRITICAL").length;
  const high     = events.filter(e => String(e.severity).toUpperCase() === "HIGH").length;
  const medium   = events.filter(e => String(e.severity).toUpperCase() === "MEDIUM").length;
  const info     = Math.max(0, events.length - critical - high - medium);

  const rawData = [
    { id: 0, value: critical, label: "Critical", color: "#E30613" },
    { id: 1, value: high, label: "High", color: "#F97316" },
    { id: 2, value: medium, label: "Medium", color: "#EAB308" },
    { id: 3, value: info, label: "Info", color: "#3B82F6" },
  ];

  const isDark = theme === 'dark' || (theme === 'system' && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  const emptyColor = isDark ? '#2D2D2D' : '#f5f5f5';

  const total = critical + high + medium + info;
  const chartData = total === 0
    ? rawData.map(d => ({ ...d, value: 0.0001, color: emptyColor })) // tiny value to show empty chart with labels
    : rawData;

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', width: '100%', height: '100%' }}>
      <PieChart
        series={[
          {
            data: chartData,
            innerRadius: 45,
            outerRadius: 65,
            paddingAngle: 2,
            cornerRadius: 4,
            highlightScope: { fade: 'global', highlight: 'item' },
            faded: { innerRadius: 30, additionalRadius: -25, color: 'gray' },
            valueFormatter: (item) => total === 0 ? "0" : item.value.toString(),
          },
        ]}
        width={380}
        height={200}
        margin={{ top: 20, bottom: 40, left: 10, right: 10 }}
        slotProps={{
          legend: {
            direction: 'row',
            position: { vertical: 'bottom', horizontal: 'middle' },
            itemMarkWidth: 10,
            itemMarkHeight: 10,
            labelStyle: {
              fill: isDark ? "#CFCFCF" : "#525252",
              fontSize: 11,
              fontWeight: "bold",
              fontFamily: "'JetBrains Mono', monospace",
            }
          },
        }}
      />
    </div>
  );
}
