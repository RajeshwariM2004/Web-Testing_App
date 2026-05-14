/**
 * Chart.js — GitHub light UI (axis/legend contrast on #fff / #f6f8fa).
 */
(function () {
  const cfg = window.WAST_CHARTS;
  if (!cfg) return;

  const fgMuted = "#656d76";
  const grid = "#d0d7de";

  const chartCommon = {
    plugins: {
      legend: {
        labels: { color: fgMuted },
      },
    },
  };

  const ctxType = document.getElementById("chartTypes");
  if (ctxType) {
    new Chart(ctxType, {
      type: "pie",
      data: {
        labels: ["SQLi", "XSS"],
        datasets: [
          {
            data: [cfg.sqli || 0, cfg.xss || 0],
            backgroundColor: ["#0969da", "#bf8700"],
            borderWidth: 1,
            borderColor: "#ffffff",
          },
        ],
      },
      options: {
        ...chartCommon,
        maintainAspectRatio: true,
      },
    });
  }

  const ctxSev = document.getElementById("chartSeverity");
  if (ctxSev) {
    new Chart(ctxSev, {
      type: "bar",
      data: {
        labels: ["Low", "Medium", "High"],
        datasets: [
          {
            label: "Findings",
            data: [cfg.sevLow || 0, cfg.sevMed || 0, cfg.sevHigh || 0],
            backgroundColor: ["#656d76", "#9a6700", "#cf222e"],
            borderWidth: 1,
            borderColor: "#d0d7de",
          },
        ],
      },
      options: {
        ...chartCommon,
        scales: {
          x: {
            ticks: { color: fgMuted },
            grid: { color: grid },
          },
          y: {
            beginAtZero: true,
            ticks: { color: fgMuted, stepSize: 1 },
            grid: { color: grid },
          },
        },
      },
    });
  }

  if (cfg.scanStatus === "pending" || cfg.scanStatus === "running") {
    const poll = () => {
      fetch("/api/scan/" + encodeURIComponent(cfg.scanId) + "/status")
        .then((r) => {
          if (!r.ok) return Promise.reject(new Error("status " + r.status));
          return r.json();
        })
        .then((data) => {
          if (!data || data.error) return;
          const el = document.getElementById("scan-status-text");
          if (el && data.status) el.textContent = data.status;
          if (data.status === "completed" || data.status === "failed") {
            window.location.reload();
          }
        })
        .catch(() => {});
    };
    poll();
    setInterval(poll, 3000);
  }
})();
