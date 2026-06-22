import { jsPDF } from 'jspdf';

export function fmt(ts) {
  const d = new Date(ts);
  return isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString([], { hour12: false });
}

export function decodeJWT(token) {
  try {
    const payload = token.split(".")[1];
    const norm = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = norm.padEnd(norm.length + ((4 - norm.length % 4) % 4), "=");
    return JSON.parse(atob(padded));
  } catch { return null; }
}

export function normaliseIncident(raw) {
  let inc = null;
  if (raw?.correlated_evidence && Array.isArray(raw?.clear_actions)) {
    inc = { ...raw };
  } else if (raw?.report_text) {
    try {
      const parsed = JSON.parse(raw.report_text);
      if (parsed?.correlated_evidence) {
        inc = { ...raw, ...parsed };
      }
    } catch {}
  }
  
  if (!inc) {
    inc = {
      incident_id:         raw?.incident_id || raw?.cluster_id || raw?.event_id || crypto.randomUUID(),
      severity:            String(raw?.severity || "MEDIUM").toUpperCase(),
      risk_score:          Number(raw?.risk_score || 50),
      correlated_evidence: {
        who:       raw?.actor || raw?.username || "Identity unavailable",
        what:      raw?.pod_name || raw?.resource_name || raw?.resource || `${raw?.resource_count || 0} correlated resource(s)`,
        when:      raw?.timestamp || raw?.created_at || "Unknown",
        where:     (raw?.namespace ? `Namespace: ${raw.namespace}` : "") + (raw?.source_ip ? ` | Source: ${raw.source_ip}` : "") || raw?.pivot_ip || "Unknown",
        why_risky: raw?.why_risky || "Raw anomaly detected. Downstream correlation unavailable.",
      },
      clear_actions: ["Contain Pods", "Revoke Credentials", "Enforce Network Guardrails"],
    };
  }

  inc.incident_id = inc.incident_id || inc.cluster_id || raw?.event_id || crypto.randomUUID();
  inc.risk_score = Number(inc.risk_score || 0);
  inc.severity = String(inc.severity || (inc.risk_score > 80 ? "CRITICAL" : "HIGH")).toUpperCase();
  inc.pod_name = inc.pod_name || raw?.pod_name || raw?.resource_name || raw?.resource || "unknown-pod";
  inc.namespace = inc.namespace || raw?.namespace || "default";

  return inc;
}

export function sevStyle(sev) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL") return { card: "sev-critical", badge: "badge-critical", score: "sev-critical" };
  if (s === "HIGH")     return { card: "sev-high",     badge: "badge-high",     score: "sev-high" };
  if (s === "MEDIUM")   return { card: "sev-medium",   badge: "badge-medium",   score: "sev-medium" };
  return                       { card: "sev-info",     badge: "badge-info",     score: "sev-info" };
}

export function downloadReportPDF(title, content, metadata = {}) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageHeight = doc.internal.pageSize.height; // 297
  const pageWidth = doc.internal.pageSize.width; // 210
  const margin = 20;
  const contentWidth = pageWidth - (margin * 2); // 170

  // 1. Draw top brand band (red)
  doc.setFillColor(226, 0, 26); // #E2001A
  doc.rect(margin, 15, contentWidth, 3, 'F');

  // 2. Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(15, 23, 42); // #0F172A
  doc.text(title.toUpperCase(), margin, 28);

  // 3. Subtitle / Timestamp
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139); // #64748B
  const currentDate = new Date().toLocaleString('en-GB', {
    day: '2-digit', month: 'long', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
  doc.text(`Generated on: ${currentDate}`, margin, 34);

  // 4. Metadata Box
  let y = 40;
  doc.setFillColor(248, 250, 252); // #F8FAFC
  doc.setDrawColor(226, 232, 240); // #E2E8F0
  doc.rect(margin, y, contentWidth, 24, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  
  // Draw metadata key-values
  let metaY = y + 6;
  doc.text("STATUS:", margin + 5, metaY);
  doc.text("CLASSIFICATION:", margin + 5, metaY + 6);
  doc.text("TIMEFRAME:", margin + 85, metaY);
  doc.text("SCOPE:", margin + 85, metaY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);
  doc.text("ACTIVE AUDIT", margin + 25, metaY);
  doc.text("INTERNAL USE ONLY", margin + 38, metaY + 6);
  doc.text(metadata['TIMEFRAME'] || metadata['timeframe'] || "N/A", margin + 112, metaY);
  doc.text(metadata['SCOPE'] || metadata['incident_id'] || "ALL ASSETS", margin + 102, metaY + 6);

  y = 72;

  // 5. Body Text Content
  doc.setFont('courier', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);

  const splitText = doc.splitTextToSize(content, contentWidth);
  
  for (let i = 0; i < splitText.length; i++) {
    if (y > pageHeight - margin - 15) {
      // Add page numbers
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.text(`Page ${doc.internal.getNumberOfPages()}`, pageWidth / 2, pageHeight - 10, { align: 'center' });

      doc.addPage();
      y = 25;
      
      // brand band on subsequent pages
      doc.setFillColor(226, 0, 26);
      doc.rect(margin, 15, contentWidth, 1.5, 'F');
      y = 25;
      
      doc.setFont('courier', 'normal');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
    }
    doc.text(splitText[i], margin, y);
    y += 5.5;
  }

  // Footer for current page
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text(`Page ${doc.internal.getNumberOfPages()}`, pageWidth / 2, pageHeight - 10, { align: 'center' });

  // Save the document directly as PDF! No ctrl+p!
  doc.save(`${title.replace(/\s+/g, '_')}_${Date.now()}.pdf`);
}
