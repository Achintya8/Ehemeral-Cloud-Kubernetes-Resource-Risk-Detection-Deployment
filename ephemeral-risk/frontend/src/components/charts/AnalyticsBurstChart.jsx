import { useEffect, useRef } from 'react';
import { Chart, LineController, LineElement, PointElement, CategoryScale, LinearScale, Tooltip, Filler } from 'chart.js';

Chart.register(LineController, LineElement, PointElement, CategoryScale, LinearScale, Tooltip, Filler);
Chart.defaults.font.family = "'JetBrains Mono', monospace";

export default function AnalyticsBurstChart({ appState }) {
  const chartRef = useRef(null);
  const canvasRef = useRef(null);
  const { trigger, getRollingSeries, theme } = appState;

  useEffect(() => {
    if (!canvasRef.current) return;
    const isDark = theme === 'dark' || (theme === 'system' && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const ctx = canvasRef.current.getContext('2d');

    // Create professional brand gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, 'rgba(227, 6, 19, 0.25)');
    gradient.addColorStop(0.5, 'rgba(227, 6, 19, 0.06)');
    gradient.addColorStop(1, 'rgba(227, 6, 19, 0.00)');

    chartRef.current = new Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "Events/s",
          data: [],
          borderColor: "#E30613",
          borderWidth: 2.5,
          backgroundColor: gradient,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHitRadius: 10,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: "#E30613",
          pointHoverBorderColor: "#FFFFFF",
          pointHoverBorderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 200
        },
        interaction: {
          intersect: false,
          mode: 'index',
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: isDark ? 'rgba(34, 34, 34, 0.95)' : 'rgba(26, 26, 26, 0.95)',
            titleColor: '#FFFFFF',
            bodyColor: '#FFFFFF',
            titleFont: { family: "'JetBrains Mono', monospace", size: 10, weight: 'bold' },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            padding: 8,
            cornerRadius: 4,
            displayColors: false,
            borderColor: isDark ? 'rgba(227, 6, 19, 0.6)' : 'rgba(227, 6, 19, 0.4)',
            borderWidth: 1,
            callbacks: {
              label: (context) => ` Rate: ${context.parsed.y} events/s`
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: isDark ? "#8E8E8E" : "#A0A0A0",
              font: { family: "'JetBrains Mono', monospace", size: 9 },
              maxTicksLimit: 10,
              maxRotation: 0
            }
          },
          y: {
            beginAtZero: true,
            suggestedMax: 5,
            grid: {
              color: isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.05)",
              drawTicks: false
            },
            ticks: {
              color: isDark ? "#8E8E8E" : "#A0A0A0",
              font: { family: "'JetBrains Mono', monospace", size: 9 },
              precision: 0,
              padding: 8
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

  return <canvas ref={canvasRef} aria-label="Analytics burst rate chart"></canvas>;
}
