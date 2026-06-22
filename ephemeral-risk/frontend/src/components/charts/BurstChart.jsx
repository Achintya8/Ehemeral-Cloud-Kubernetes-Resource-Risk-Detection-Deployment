import { useEffect, useRef } from 'react';
import { Chart, LineController, LineElement, PointElement, LinearScale, Title, CategoryScale, Tooltip, Filler } from 'chart.js';

Chart.register(LineController, LineElement, PointElement, LinearScale, Title, CategoryScale, Tooltip, Filler);
Chart.defaults.font.family = "'JetBrains Mono', monospace";

export default function BurstChart({ appState }) {
  const chartRef = useRef(null);
  const canvasRef = useRef(null);
  const { trigger, getRollingSeries, theme } = appState;

  useEffect(() => {
    if (!canvasRef.current) return;
    const isDark = theme === 'dark' || (theme === 'system' && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches);
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
          tooltip: {
            backgroundColor: isDark ? "#242424" : "#fff",
            borderColor: isDark ? "#3A3A3A" : "#E0E0E0",
            borderWidth: 1,
            titleColor: isDark ? "#FFFFFF" : "#1A1A1A",
            bodyColor: isDark ? "#CFCFCF" : "#525252",
            titleFont: { family: "'JetBrains Mono', monospace", size: 10, weight: 'bold' },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: isDark ? "#8E8E8E" : "#A3A3A3",
              font: { family: "'JetBrains Mono', monospace", size: 9 },
              maxTicksLimit: 8,
              maxRotation: 0
            }
          },
          y: {
            beginAtZero: true,
            suggestedMax: 5,
            grid: { color: isDark ? "#2D2D2D" : "#F0F0F0" },
            ticks: {
              color: isDark ? "#8E8E8E" : "#A3A3A3",
              font: { family: "'JetBrains Mono', monospace", size: 9 },
              precision: 0
            }
          },
        },
      },
    });

    return () => {
      if (chartRef.current) chartRef.current.destroy();
    };
  }, [theme]);

  useEffect(() => {
    if (!chartRef.current) return;
    const { labels, values } = getRollingSeries();
    chartRef.current.data.labels = labels;
    chartRef.current.data.datasets[0].data = values;
    chartRef.current.update("none");
  }, [trigger, getRollingSeries]);

  return <canvas ref={canvasRef} aria-label="Event timeline chart"></canvas>;
}
