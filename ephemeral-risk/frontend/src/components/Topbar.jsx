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
  const { currentView } = appState;
  const config = VIEW_CONFIG[currentView] || VIEW_CONFIG.dashboard;

  return (
    <header className="topbar">
      <div className="topbar-left flex items-center gap-3">
        <SidebarTrigger className="-ml-2" />
        <div>
          <h2 id="topbar-title" className="text-[15px] font-bold text-[#1A1A1A] m-0">{config.title}</h2>
          <p id="topbar-sub" className="text-[11px] text-[#A0A0A0] mt-[1px] m-0">{config.sub}</p>
        </div>
      </div>
    </header>
  );
}
