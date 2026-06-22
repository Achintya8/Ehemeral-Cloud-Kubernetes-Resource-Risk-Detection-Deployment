import { useState, useEffect } from 'react';
import { useAppLogic } from './hooks/useAppLogic';
import LoginView from './components/LoginView';
import { AppSidebar } from './components/app-sidebar';
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar';
import Topbar from './components/Topbar';
import Dashboard from './views/Dashboard';
import Events from './views/Events';
import Incidents from './views/Incidents';
import Analytics from './views/Analytics';
import Admin from './views/Admin';
import AnalystHistory from './views/AnalystHistory';
import Topology from './views/Topology';
import Users from './views/Users';
import ToastContainer from './components/ToastContainer';
import './index.css';

export default function App() {
  const appState = useAppLogic();
  const { user, currentView } = appState;

  if (!user) {
    return <LoginView doLogin={appState.doLogin} />;
  }

  return (
    <SidebarProvider>
      <AppSidebar appState={appState} />
      <SidebarInset className="flex flex-col flex-1 w-full bg-gray-50">
        <Topbar appState={appState} />
        <main className="flex-1 w-full relative">
          {currentView === 'dashboard' && <Dashboard appState={appState} />}
          {currentView === 'events' && <Events appState={appState} />}
          {currentView === 'incidents' && <Incidents appState={appState} />}
          {currentView === 'analytics' && <Analytics appState={appState} />}
          {currentView === 'topology' && <Topology appState={appState} />}
          {currentView === 'admin' && <Admin appState={appState} />}
          {currentView === 'history' && <AnalystHistory appState={appState} />}
          {currentView === 'users' && <Users appState={appState} />}
        </main>
        <ToastContainer toasts={appState.toasts} />
      </SidebarInset>
    </SidebarProvider>
  );
}
