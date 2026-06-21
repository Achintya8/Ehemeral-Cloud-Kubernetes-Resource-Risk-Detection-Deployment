import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarRail,
} from "@/components/ui/sidebar";
import { LayoutDashboard, Activity, AlertTriangle, BarChart3, Box, Settings, LogOut } from "lucide-react";

export function AppSidebar({ appState }) {
  const { currentView, setCurrentView, role, doLogout, events = [], streamStatus, incidents = [] } = appState;
  
  const unreadEvents = events.filter(e => e.is_anomaly).length;
  const unreadIncidents = incidents.length;

  const handleNav = (view) => {
    setCurrentView(view);
  };

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
              <div className="flex aspect-square size-8 items-center justify-center rounded-[2px] text-white flex-col overflow-hidden shadow-sm flex-shrink-0">
                <div className="flex-1 bg-[#E30613] w-full" />
                <div className="flex-1 bg-[#1A1A1A] w-full" />
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight ml-2">
                <span className="truncate font-extrabold tracking-[0.22em] text-[9px] uppercase text-gray-400">Ephemeral Risk</span>
                <span className="truncate font-bold text-[13px] text-gray-900 leading-tight">Sentry Platform</span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <div className="px-4 py-2 mt-2 group-data-[collapsible=icon]:px-0 group-data-[collapsible=icon]:flex group-data-[collapsible=icon]:justify-center">
          <div className={`flex items-center justify-center gap-2 rounded-full px-3 py-1.5 group-data-[collapsible=icon]:p-0 group-data-[collapsible=icon]:w-8 group-data-[collapsible=icon]:h-8 text-[10px] font-extrabold uppercase tracking-widest ${streamStatus === 'live' ? 'bg-[#F0FFF4] border border-[#BBF7D0] text-[#15803D]' : streamStatus === 'reconnecting' ? 'bg-[#FFFBEB] border border-[#FDE68A] text-[#92400E]' : 'bg-[#FFF5F5] border border-[#FBBFC7] text-[#991B1B]'}`}>
            <div className={`h-2 w-2 rounded-full shrink-0 animate-pulse ${streamStatus === 'live' ? 'bg-green-500' : streamStatus === 'reconnecting' ? 'bg-amber-500' : 'bg-red-500'}`} />
            <span className="group-data-[collapsible=icon]:hidden">{streamStatus === 'live' ? 'Live' : streamStatus === 'reconnecting' ? 'Reconnecting…' : 'Disconnected'}</span>
          </div>
        </div>

        <SidebarGroup>
          <SidebarGroupLabel className="text-[9px] font-extrabold uppercase tracking-[0.2em] text-gray-400 mt-2">Detection</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={currentView === 'dashboard'} onClick={() => handleNav('dashboard')} className="font-medium text-[13px]">
                  <LayoutDashboard />
                  <span>Command Centre</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={currentView === 'events'} onClick={() => handleNav('events')} className="font-medium text-[13px]">
                  <Activity />
                  <span>Event Stream</span>
                </SidebarMenuButton>
                {unreadEvents > 0 && <div className="absolute right-2 top-1.5 flex h-5 min-w-5 items-center justify-center bg-[#E30613] text-white rounded-full px-1 text-[10px] font-extrabold group-data-[collapsible=icon]:hidden pointer-events-none">{unreadEvents}</div>}
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={currentView === 'incidents'} onClick={() => handleNav('incidents')} className="font-medium text-[13px]">
                  <AlertTriangle />
                  <span>Incidents</span>
                </SidebarMenuButton>
                {unreadIncidents > 0 && <div className="absolute right-2 top-1.5 flex h-5 min-w-5 items-center justify-center bg-[#E30613] text-white rounded-full px-1 text-[10px] font-extrabold group-data-[collapsible=icon]:hidden pointer-events-none">{unreadIncidents}</div>}
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={currentView === 'analytics'} onClick={() => handleNav('analytics')} className="font-medium text-[13px]">
                  <BarChart3 />
                  <span>Analytics</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={currentView === 'topology'} onClick={() => handleNav('topology')} className="font-medium text-[13px]">
                  <Box />
                  <span>3D Topology</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {role === 'admin' && (
          <SidebarGroup>
            <SidebarGroupLabel className="text-[9px] font-extrabold uppercase tracking-[0.2em] text-gray-400 mt-2">Administration</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={currentView === 'admin'} onClick={() => handleNav('admin')} className="font-medium text-[13px]">
                    <Settings />
                    <span>Pipeline Admin</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={doLogout} className="text-gray-600 hover:text-black font-medium text-[13px] justify-center gap-2">
              <LogOut size={14} />
              <span>Sign Out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
