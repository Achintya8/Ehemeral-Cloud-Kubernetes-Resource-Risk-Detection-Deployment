import { useState } from 'react';
import html2pdf from 'html2pdf.js';

export default function ReportGenerator({ appState }) {
  const { authFetch, addToast } = appState;
  const [timeframe, setTimeframe] = useState(24);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState('');
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setReport('');
    try {
      const res = await authFetch('/api/reports/summary', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ timeframe_hours: timeframe }),
      });
      const data = await res.json();
      if (res.ok && data.report_text) {
        setReport(data.report_text);
        addToast({
          type: 'success',
          title: 'Report Generated',
          message: `Summary generated for the last ${timeframe} hours.`,
        });
      } else {
        const errorMsg = data.report_text || data.detail || 'Failed to generate report';
        setReport(`Error: ${errorMsg}`);
        addToast({
          type: 'error',
          title: 'Generation Failed',
          message: errorMsg,
        });
      }
    } catch (err) {
      setReport(`Error: ${err.message}`);
      addToast({
        type: 'error',
        title: 'Network Error',
        message: err.message,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!report) return;
    navigator.clipboard.writeText(report);
    setCopied(true);
    addToast({
      type: 'info',
      title: 'Copied to Clipboard',
      message: 'Report text has been copied to your clipboard.',
    });
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPdf = () => {
    if (!report) return;
    
    // Create a beautifully styled hidden container for the PDF rendering
    const element = document.createElement('div');
    element.innerHTML = `
      <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; padding: 30px; color: #222; max-width: 800px; margin: 0 auto;">
        <div style="border-bottom: 2px solid #E2001A; padding-bottom: 10px; margin-bottom: 20px;">
          <h1 style="color: #E2001A; margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 1px;">Executive Threat Summary</h1>
          <p style="color: #666; margin: 5px 0 0 0; font-size: 12px;">Generated via Ephemeral Cloud Risk Detection Engine</p>
        </div>
        <pre style="white-space: pre-wrap; font-family: 'Courier New', Courier, monospace; font-size: 12px; line-height: 1.6; color: #111;">${report}</pre>
        <div style="margin-top: 40px; padding-top: 10px; border-top: 1px solid #ccc; font-size: 10px; color: #999; text-align: center;">
          CONFIDENTIAL — INTERNAL SECURITY EYES ONLY
        </div>
      </div>
    `;

    const opt = {
      margin:       0.5,
      filename:     'Threat_Report.pdf',
      image:        { type: 'jpeg', quality: 0.98 },
      html2canvas:  { scale: 2 },
      jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
    };
    
    html2pdf().set(opt).from(element).save();
    
    addToast({
      type: 'info',
      title: 'Downloading PDF',
      message: 'Your formatted PDF report is downloading.',
    });
  };

  return (
    <div className="panel" style={{ marginTop: '20px' }}>
      <div className="panel-header">
        <div>
          <h3>Threat Report Generator</h3>
          <p>Generate LLM executive threat summaries based on database statistics</p>
        </div>
      </div>
      <div className="panel-body flex flex-col gap-4">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="form-label" style={{ margin: 0, whiteSpace: 'nowrap' }}>Timeframe</span>
            <select
              value={timeframe}
              onChange={(e) => setTimeframe(Number(e.target.value))}
              className="form-input"
              style={{ width: '140px', padding: '6px 10px', height: '36px' }}
              disabled={loading}
            >
              <option value={1}>1 Hour</option>
              <option value={24}>24 Hours</option>
              <option value={168}>7 Days</option>
            </select>
          </div>
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="action-btn action-primary"
            style={{ height: '36px', padding: '0 18px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          >
            {loading ? (
              <>
                <span className="pulse-dot red" style={{ marginRight: '8px' }}></span>
                Generating...
              </>
            ) : (
              'Generate Summary'
            )}
          </button>
        </div>

        {report && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%', position: 'relative' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="form-label" style={{ margin: 0 }}>Generated Report Output</span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  onClick={handleDownloadPdf} 
                  className="action-btn action-primary" 
                  style={{ padding: '4px 10px', fontSize: '11px', background: '#E2001A', color: 'white', border: 'none' }}
                >
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2.5" style={{width:'12px', height:'12px', display:'inline', marginRight:'4px'}}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  Download PDF
                </button>
                <button 
                  onClick={handleCopy} 
                  className="action-btn" 
                  style={{ padding: '4px 10px', fontSize: '11px' }}
                >
                  {copied ? 'Copied!' : 'Copy to Clipboard'}
                </button>
              </div>
            </div>
            <pre className="font-mono text-muted" style={{
              background: 'var(--sg-grey-50)',
              border: '1.5px solid var(--sg-grey-200)',
              padding: '16px',
              borderRadius: 'var(--radius)',
              whiteSpace: 'pre-wrap',
              maxHeight: '400px',
              overflowY: 'auto',
              fontSize: '12px',
              lineHeight: '1.6',
              color: 'var(--sg-black)',
              width: '100%',
              margin: 0
            }}>
              {report}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
