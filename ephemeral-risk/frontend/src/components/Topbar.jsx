import { useState, useEffect } from 'react';
import { SidebarTrigger } from "@/components/ui/sidebar";

const VIEW_CONFIG = {
  dashboard: { title: "Command Centre", sub: "" },
  events: { title: "Event Stream", sub: "" },
  incidents: { title: "Incidents", sub: "" },
  analytics: { title: "Analytics", sub: "" },
  admin: { title: "Pipeline Admin", sub: "" },
  topology: { title: "3D Topology", sub: "" },
};

export default function Topbar({ appState }) {
  const { currentView, streamStatus, user, role } = appState;
  const config = VIEW_CONFIG[currentView] || VIEW_CONFIG.dashboard;
  const [timeStr, setTimeStr] = useState('');

  useEffect(() => {
    const tick = () => {
      setTimeStr(new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC");
    };
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left flex items-center gap-3">
        <SidebarTrigger className="-ml-2" />
        <div>
          <h2 id="topbar-title" className="text-[15px] font-bold text-[#1A1A1A] m-0">{config.title}</h2>
          <p id="topbar-sub" className="text-[11px] text-[#A0A0A0] mt-[1px] m-0">{config.sub}</p>
        </div>
      </div>
      <div className="topbar-right">
        <div className="clock-pill" id="clock-pill">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
          <span id="utc-clock">{timeStr}</span>
        </div>
        <div className={`stream-pill ${streamStatus === 'live' ? 'live' : streamStatus === 'reconnecting' ? 'reconnecting' : ''}`} id="stream-pill">
          <div className="pulse-dot" id="stream-pulse" style={{ display: streamStatus === 'live' ? '' : 'none', background: '#22C55E' }}></div>
          <span id="stream-status">{streamStatus === 'live' ? 'Live' : streamStatus === 'reconnecting' ? 'Reconnecting…' : 'Disconnected'}</span>
        </div>
        <div className="user-pill" id="user-pill">
          <div className="user-avatar" id="user-avatar">{(user?.username || "?").charAt(0).toUpperCase()}</div>
          <div>
            <div className="user-pill-name" id="user-badge">{user?.username}</div>
            <div className="user-pill-role" id="role-badge">{role === 'admin' ? 'System Admin' : 'Analyst'}</div>
          </div>
        </div>
      </div>
    </header>
  );
}
