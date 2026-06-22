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
import { LayoutDashboard, Activity, AlertTriangle, BarChart3, Box, Settings, LogOut, History, Users, Sun, Moon, Laptop } from "lucide-react";

export function AppSidebar({ appState }) {
  const { currentView, setCurrentView, role, doLogout, events = [], streamStatus, incidents = [], user, theme, setTheme } = appState;
  
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
              <div className="flex flex-1 items-center ml-2">
                <span className="font-black tracking-[0.05em] text-[20px] uppercase text-gray-900 leading-none">k8strl</span>
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
                    <span>Pipelines</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={currentView === 'history'} onClick={() => handleNav('history')} className="font-medium text-[13px]">
                    <History />
                    <span>Analyst History</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={currentView === 'users'} onClick={() => handleNav('users')} className="font-medium text-[13px]">
                    <Users />
                    <span>Analyst Accounts</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
      </SidebarContent>

      <SidebarFooter className="border-t border-gray-200 dark:border-zinc-800 p-3 group-data-[collapsible=icon]:p-2">
        <div className="flex items-center justify-between mb-2 px-1 group-data-[collapsible=icon]:hidden">
          <span className="text-[9px] font-extrabold uppercase tracking-widest text-gray-400 dark:text-zinc-500">Theme</span>
          <div className="flex items-center bg-gray-100 dark:bg-zinc-900 rounded-lg p-0.5 border border-gray-200 dark:border-zinc-800">
            <button
              onClick={() => setTheme('light')}
              className={`p-1 rounded-md transition-colors ${theme === 'light' ? 'bg-white dark:bg-zinc-800 text-amber-500 shadow-sm' : 'text-gray-400 hover:text-gray-600 dark:hover:text-gray-200'}`}
              title="Light Theme"
            >
              <Sun size={12} />
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={`p-1 rounded-md transition-colors ${theme === 'dark' ? 'bg-white dark:bg-zinc-800 text-blue-500 shadow-sm' : 'text-gray-400 hover:text-gray-600 dark:hover:text-gray-200'}`}
              title="Dark Theme"
            >
              <Moon size={12} />
            </button>
            <button
              onClick={() => setTheme('system')}
              className={`p-1 rounded-md transition-colors ${theme === 'system' ? 'bg-white dark:bg-zinc-800 text-emerald-500 shadow-sm' : 'text-gray-400 hover:text-gray-600 dark:hover:text-gray-200'}`}
              title="Device Theme"
            >
              <Laptop size={12} />
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3 border-t border-gray-100 dark:border-zinc-800 pt-2.5 px-1 py-1.5 mb-2 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:border-t-0 group-data-[collapsible=icon]:pt-0 group-data-[collapsible=icon]:mb-0">
          <div className="w-8 h-8 rounded-full bg-[#E30613] text-white flex items-center justify-center font-bold text-sm shrink-0 shadow-sm">
            {(user?.username || "?").charAt(0).toUpperCase()}
          </div>
          <div className="flex flex-col min-w-0 group-data-[collapsible=icon]:hidden">
            <span className="text-xs font-bold text-gray-900 dark:text-white truncate">{user?.username}</span>
            <span className="text-[9px] font-bold text-gray-400 dark:text-zinc-500 uppercase tracking-widest leading-none mt-0.5">{role === 'admin' ? 'System Admin' : 'Analyst'}</span>
          </div>
        </div>

        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton 
              onClick={doLogout} 
              className="text-gray-600 dark:text-zinc-400 hover:text-black dark:hover:text-white font-medium text-[13px] justify-center gap-2 border border-gray-200 dark:border-zinc-800 rounded-md py-2 mt-1"
              title="Sign Out"
            >
              <LogOut size={14} />
              <span className="group-data-[collapsible=icon]:hidden">Sign Out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
