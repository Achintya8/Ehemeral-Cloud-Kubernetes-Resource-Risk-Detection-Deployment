import { useEffect, useRef } from 'react';
import { Chart, LineController, LineElement, PointElement, LinearScale, Title, CategoryScale, Tooltip, Filler } from 'chart.js';

Chart.register(LineController, LineElement, PointElement, LinearScale, Title, CategoryScale, Tooltip, Filler);

export default function BurstChart({ appState }) {
  const chartRef = useRef(null);
  const canvasRef = useRef(null);
  const { trigger, getRollingSeries } = appState;

  useEffect(() => {
    if (!canvasRef.current) return;
    const ctx = canvasRef.current.getContext('2d');
    chartRef.current = new Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "Events/s",
          data: [],
          borderColor: "#E30613",
          backgroundColor: "rgba(227,6,19,0.06)",
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
          tension: 0.35,
          fill: true,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { intersect: false, mode: "index" },
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: "#fff", borderColor: "#E0E0E0", borderWidth: 1, titleColor: "#1A1A1A", bodyColor: "#525252" },
        },
        scales: {
          x: { grid: { display: false }, ticks: { color: "#A3A3A3", maxTicksLimit: 8, maxRotation: 0 } },
          y: { beginAtZero: true, suggestedMax: 5, grid: { color: "#F0F0F0" }, ticks: { color: "#A3A3A3", precision: 0 } },
        },
      },
    });

    return () => {
      if (chartRef.current) chartRef.current.destroy();
    };
  }, []);

  useEffect(() => {
    if (!chartRef.current) return;
    const { labels, values } = getRollingSeries();
    chartRef.current.data.labels = labels;
    chartRef.current.data.datasets[0].data = values;
    chartRef.current.update("none");
  }, [trigger, getRollingSeries]);

  return <canvas ref={canvasRef} aria-label="Event timeline chart"></canvas>;
}
