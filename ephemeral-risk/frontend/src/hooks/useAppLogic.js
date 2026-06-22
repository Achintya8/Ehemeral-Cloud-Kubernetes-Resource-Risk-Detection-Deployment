import { useState, useEffect, useRef, useCallback } from 'react';
import { normaliseIncident, decodeJWT } from '../utils';

const WINDOW_SECONDS = 60;
const MAX_EVENTS = 100;
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

export function useAppLogic() {
  const [token, setToken] = useState(localStorage.getItem('authToken') || '');
  const [user, setUser] = useState(null);
  const [role, setRole] = useState(null);
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [streamStatus, setStreamStatus] = useState('disconnected');
  const [currentView, setCurrentView] = useState('dashboard');
  const [showAnomalyOnly, setShowAnomalyOnly] = useState(false);
  const [pipelines, setPipelines] = useState([]);
  const [users, setUsers] = useState([]);
  
  // Stats
  const [dbStats, setDbStats] = useState({});
  const [modelStats, setModelStats] = useState({});
  const [ttlDistribution, setTtlDistribution] = useState({ labels: [], counts: [], total_resources: 0 });
  const [health, setHealth] = useState({ status: 'checking' });

  // Burst tracking (not in React state for performance, exposed via ref)
  const bucketsRef = useRef(new Map());
  const peakBurstRef = useRef(0);
  const sourceRef = useRef(null);
  const [trigger, setTrigger] = useState(0); // to force re-render charts

  // Toasts
  const [toasts, setToasts] = useState([]);
  const [blocklist, setBlocklist] = useState([]);
  const [actionLog, setActionLog] = useState([]);
  const [ngrokPublicUrl, setNgrokPublicUrl] = useState(null);

  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'system');

  useEffect(() => {
    const root = window.document.documentElement;
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const applyTheme = () => {
      const isDark = theme === 'dark' || (theme === 'system' && mediaQuery.matches);
      if (isDark) {
        root.classList.add('dark');
      } else {
        root.classList.remove('dark');
      }
    };

    applyTheme();
    localStorage.setItem('theme', theme);

    if (theme === 'system') {
      mediaQuery.addEventListener('change', applyTheme);
      return () => mediaQuery.removeEventListener('change', applyTheme);
    }
  }, [theme]);

  const addToast = useCallback((toast) => {
    const id = Date.now() + Math.random();
    setToasts(prev => {
      const next = [...prev, { id, ...toast }];
      if (next.length > 3) return next.slice(next.length - 3);
      return next;
    });
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, toast.duration || 4000);
  }, []);

  const bucketEvent = useCallback((ts) => {
    const t = new Date(ts).getTime();
    if (isNaN(t)) return;
    const sec = Math.floor(t / 1000) * 1000;
    const buckets = bucketsRef.current;
    buckets.set(sec, (buckets.get(sec) || 0) + 1);
    const count = buckets.get(sec);
    if (count > peakBurstRef.current) peakBurstRef.current = count;
    
    // prune
    const cutoff = Date.now() - WINDOW_SECONDS * 1000;
    for (const k of buckets.keys()) {
      if (k < cutoff) buckets.delete(k);
    }
  }, []);

  const pushEvent = useCallback((record) => {
    const score = Number(record.risk_score || 0);
    if (score >= 80) record.severity = "CRITICAL";
    else if (score >= 60) record.severity = "HIGH";
    else if (score >= 30) record.severity = "MEDIUM";

    setEvents(prev => {
      const updated = [record, ...prev];
      if (updated.length > MAX_EVENTS) updated.length = MAX_EVENTS;
      return updated;
    });
    // Bucket live events by arrival time, not their own timestamp. Sources like
    // event_simulator.py backdate events across a 2h window, which would place
    // them outside the rolling 60s window and leave the chart flat at 0.
    // Arrival time is what a live "Events/s" throughput chart should reflect.
    bucketEvent(Date.now());
  }, [bucketEvent]);

  const pushIncident = useCallback((raw) => {
    const inc = normaliseIncident(raw);
    setIncidents(prev => {
      const idx = prev.findIndex(i => i.incident_id === inc.incident_id);
      const next = [...prev];
      if (idx >= 0) next.splice(idx, 1, inc);
      else next.unshift(inc);
      next.sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
      if (next.length > 50) next.length = 50;
      return next;
    });
  }, []);

  const updateStats = useCallback((payload) => {
    if (payload?.database) setDbStats(payload.database);
    if (payload?.model) setModelStats(payload.model);
    if (payload?.ttl_distribution) setTtlDistribution(payload.ttl_distribution);
  }, []);

  const authFetch = useCallback(async (url, opts = {}) => {
    const headers = new Headers(opts.headers || {});
    headers.set("Authorization", `Bearer ${token}`);
    
    // Automatically prepend API_BASE if url is a relative path starting with /
    const fullUrl = url.startsWith('/') ? `${API_BASE}${url}` : url;
    
    const res = await fetch(fullUrl, { ...opts, headers });
    if (res.status === 401) {
      doLogout();
      throw new Error("Session expired");
    }
    return res;
  }, [token]);

  const connectStream = useCallback(() => {
    if (sourceRef.current) sourceRef.current.close();
    setStreamStatus('reconnecting');
    const url = `${API_BASE}/stream?token=${encodeURIComponent(token)}`;
    const src = new EventSource(url);
    sourceRef.current = src;

    src.onopen = () => setStreamStatus('live');
    src.onerror = () => setStreamStatus('reconnecting');

    src.addEventListener('security_event', (event) => {
      try {
        const msg = JSON.parse(event.data);
        const data = msg.record || msg;
        pushEvent(data);
        if (data.is_anomaly === true || data.risk_score >= 70 || data.type === "incident" || data.type === "raw_anomaly") {
          pushIncident(msg.cluster || data);
        }
        updateStats(msg);
      } catch (e) {}
    });

    src.addEventListener("incident", e => {
      try { pushIncident(JSON.parse(e.data)); } catch {}
    });

    src.addEventListener("stats", e => {
      try { updateStats(JSON.parse(e.data)); } catch {}
    });

    src.addEventListener("remediation", e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.incident_id) {
          setIncidents(prev => prev.filter(i => i.incident_id !== msg.incident_id));
          addToast({
            type: "info",
            title: `Playbook: ${msg.action_type || "unknown"}`,
            message: `Executed by ${msg.operator || "system"} — ${msg.message || ""}`,
          });
        }
      } catch {}
    });

    src.addEventListener("blocklist", e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.entries) setBlocklist(msg.entries);
      } catch {}
    });

    src.addEventListener("action_log", e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.entries) setActionLog(msg.entries);
      } catch {}
    });
  }, [token, pushEvent, pushIncident, updateStats, addToast, setBlocklist, setActionLog]);

  const loadInitialState = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/state`);
      const payload = await res.json();
      setEvents(payload.recent_events || []);
      
      // Filter out warmup/seed placeholder incidents (those have 0 risk_score
      // or unresolved pivot fields) before showing on the Incidents view.
      const rawIncidents = (payload.recent_incidents || []).map(normaliseIncident);
      const qualityIncidents = rawIncidents.filter(inc => {
        const score = Number(inc.risk_score || 0);
        const sev = (inc.severity || '').toUpperCase();
        const hasNodes = Number(inc.node_count || 0) > 0;
        const isHighSeverity = sev === 'CRITICAL' || sev === 'HIGH';
        const isMediumWithNodes = sev === 'MEDIUM' && hasNodes;
        const hasRealScore = score > 0;
        return isHighSeverity || isMediumWithNodes || hasRealScore;
      });
      qualityIncidents.sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
      setIncidents(qualityIncidents);

      bucketsRef.current.clear();
      (payload.recent_events || []).forEach(e => bucketEvent(e.timestamp));

      setBlocklist(payload.blocklist || []);

      setActionLog(payload.action_log || []);

      setNgrokPublicUrl(payload.ngrok_public_url || null);

      updateStats(payload);
    } catch (e) {
      console.error(e);
    }
  }, [authFetch, bucketEvent, updateStats]);

  const refreshPipelines = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/pipelines`);
      if (res.ok) {
        const data = await res.json();
        setPipelines(data.pipelines || []);
      }
    } catch {}
  }, [authFetch]);

  const refreshUsers = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/users`);
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } catch {}
  }, [authFetch]);


  const refreshHealth = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/health`);
      if (res.ok) {
        const data = await res.json();
        setHealth({ status: 'ok', ...data });
        if (data.database) setDbStats(data.database);
        if (data.model) setModelStats(data.model);
      } else {
        setHealth({ status: 'error' });
      }
    } catch {
      setHealth({ status: 'error' });
    }
  }, [authFetch]);

  const initWorkspace = useCallback(async () => {
    await loadInitialState();
    connectStream();
    if (role === 'admin') {
      refreshPipelines();
      refreshHealth();
      refreshUsers();
    }
  }, [loadInitialState, connectStream, role, refreshPipelines, refreshHealth, refreshUsers]);

  const doLogin = async (username, password) => {
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const payload = await res.json();
    if (!res.ok) throw new Error(payload.detail || "Login failed");

    const decoded = decodeJWT(payload.access_token);
    if (!decoded?.sub || !["admin", "analyst"].includes(decoded.role)) {
      throw new Error("Invalid role in server token");
    }
    setToken(payload.access_token);
    setUser({ username: decoded.sub });
    setRole(decoded.role);
    localStorage.setItem("authToken", payload.access_token);
  };

  const doLogout = () => {
    if (sourceRef.current) { sourceRef.current.close(); sourceRef.current = null; }
    setToken('');
    setUser(null);
    setRole(null);
    setEvents([]);
    setIncidents([]);
    bucketsRef.current.clear();
    peakBurstRef.current = 0;
    setPipelines([]);
    setActionLog([]);
    setNgrokPublicUrl(null);
    localStorage.removeItem("authToken");
    setStreamStatus('disconnected');
    setCurrentView('dashboard');
  };

  useEffect(() => {
    if (token && !user) {
      const decoded = decodeJWT(token);
      if (decoded?.sub && ["admin", "analyst"].includes(decoded.role)) {
        setUser({ username: decoded.sub });
        setRole(decoded.role);
      } else {
        doLogout();
      }
    }
  }, [token, user]);

  useEffect(() => {
    if (user) {
      initWorkspace();
    }
  }, [user, initWorkspace]);

  // Tick for charts and periodic updates
  useEffect(() => {
    if (!user) return;
    const timer = setInterval(() => {
      // prune
      const cutoff = Date.now() - WINDOW_SECONDS * 1000;
      for (const k of bucketsRef.current.keys()) {
        if (k < cutoff) bucketsRef.current.delete(k);
      }
      setTrigger(t => t + 1);
    }, 1000);

    // Poll TTL distribution every 10 seconds
    const ttlTimer = setInterval(async () => {
      if (sourceRef.current?.readyState === EventSource.OPEN) {
        try {
          const res = await authFetch(`${API_BASE}/api/ttl-distribution`);
          if (res.ok) {
            const data = await res.json();
            setTtlDistribution(data);
          }
        } catch (e) {}
      }
    }, 10000);

    return () => {
      clearInterval(timer);
      clearInterval(ttlTimer);
    };
  }, [user, authFetch]);

  const getRollingSeries = useCallback(() => {
    const now = Date.now();
    const end = Math.floor(now / 1000) * 1000;
    const start = end - (WINDOW_SECONDS - 1) * 1000;
    const labels = [], values = [];
    for (let t = start; t <= end; t += 1000) {
      labels.push(new Date(t).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }));
      values.push(bucketsRef.current.get(t) || 0);
    }
    return { labels, values };
  }, []);

  const releaseBlocklist = useCallback(async (principalId) => {
    try {
      const res = await authFetch(`${API_BASE}/api/blocklist/release/${encodeURIComponent(principalId)}`, {
        method: "POST",
      });
      if (res.ok) {
        const data = await res.json();
        setBlocklist(data.blocklist || []);
        addToast({
          type: "success",
          title: "Blocklist released",
          message: `${principalId} unblocked — future activity will fire incidents normally.`,
        });
      }
    } catch (e) {
      console.error("Failed to release blocklist entry:", e);
    }
  }, [authFetch, addToast]);

  return {
    token, user, role, events, incidents, streamStatus, currentView, setCurrentView,
    showAnomalyOnly, setShowAnomalyOnly, pipelines, refreshPipelines,
    users, refreshUsers,
    theme, setTheme,
    dbStats, modelStats, ttlDistribution, health, refreshHealth,
    blocklist, releaseBlocklist,
    actionLog,
    ngrokPublicUrl,
    doLogin, doLogout, authFetch, addToast, toasts, setIncidents,
    getRollingSeries, trigger, peakBurstRef
  };
}
