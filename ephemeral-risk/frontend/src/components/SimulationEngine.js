/* ═══════════════════════════════════════════════════════════════════
   SimulationEngine  —  Fully browser-isolated event simulation

   Zero backend calls. Generates synthetic K8s/cloud events at a
   configurable rate, applies a lightweight rule-based anomaly
   scorer, and distributes events across virtual load-balancer nodes
   for visualisation.

   Exposed API:
     const engine = new SimulationEngine({ onTick, onIncident });
     engine.setConfig({ eventRate, anomalyMix, lbNodes, playing, scrubPos });
     engine.start();
     engine.stop();
     engine.dispose();
   ═══════════════════════════════════════════════════════════════════ */

const RESOURCE_TYPES = [
  'pod', 'deployment', 'service', 'network', 'identity',
  'configmap', 'secret', 'volume', 'container',
];

const NORMAL_NAMESPACES = [
  'default', 'kube-system', 'kube-public', 'monitoring', 'ingress-nginx',
  'ephemeral-test', 'local-path-storage',
];
const SUSPICIOUS_NAMESPACES = [
  'crypto-mining', 'data-exfil', 'backdoor-c2', 'temp-attack',
];
const NORMAL_IDENTITIES = [
  'system:node:worker-01', 'system:serviceaccount:kube-system:coredns',
  'deploy-bot', 'ci-pipeline', 'kube-proxy', 'prometheus',
  'cert-manager', 'external-dns', 'serviceaccount/default:app',
];
const SUSPICIOUS_IDENTITIES = [
  'unknown-user', 'anonymous:unauthenticated', 'root@k8s-master',
  'serviceaccount/crypto-mining:miner',
  'system:anonymous', 'eve-attacker',
];

const ANOMALY_SCENARIOS = [
  { label: 'crypto-mining',    risk: [75, 95], resourceType: 'pod',      namespace: 'crypto-mining', identity: 'anonymous:unauthenticated' },
  { label: 'data-exfiltration',risk: [70, 90], resourceType: 'secret',   namespace: 'data-exfil',   identity: 'eve-attacker' },
  { label: 'privilege-escal',  risk: [65, 88], resourceType: 'identity', namespace: 'default',      identity: 'root@k8s-master' },
  { label: 'backdoor-c2',      risk: [60, 85], resourceType: 'network', namespace: 'backdoor-c2', identity: 'unknown-user' },
  { label: 'debug-pod-abuse',  risk: [50, 75], resourceType: 'pod',      namespace: 'ephemeral-test',identity: 'system:anonymous' },
];

/* ── UUID helper ─────────────────────────────────────────────── */
function uuid() {
  return 'sim-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

/* ── rand in range ───────────────────────────────────────────── */
function rand(min, max) { return min + Math.random() * (max - min); }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

/* ═══════════════════════════════════════════════════════════════ */
export default class SimulationEngine {
  constructor({ onTick, onIncident } = {}) {
    this.onTick = onTick || (() => {});
    this.onIncident = onIncident || (() => {});

    // Config (defaults)
    this.eventRate = 3;        // events per second
    this.anomalyMix = 20;      // % that are anomalies
    this.lbNodes = 3;
    this.playing = true;
    this.scrubPos = 0;         // 0-1 position in timeline buffer

    // Internal state
    this._running = false;
    this._timer = null;
    this._timeline = [];       // ring buffer of generated events
    this._timelineMax = 600;   // keep last 600 events for scrub
    this._eventCounter = 0;
    this._lbLoads = [];        // load count per LB node
    this._incidentBuffer = [];  // recent sim incidents
    this._burstAcc = 0;        // burst accumulator
    this._burstWindow = [];    // timestamps in current 10s window
  }

  /* ── Configuration ─────────────────────────────────────────── */
  setConfig(cfg) {
    if (cfg.eventRate !== undefined) this.eventRate = cfg.eventRate;
    if (cfg.anomalyMix !== undefined) this.anomalyMix = cfg.anomalyMix;
    if (cfg.lbNodes !== undefined) {
      this.lbNodes = cfg.lbNodes;
      // Re-init load array
      while (this._lbLoads.length < this.lbNodes) this._lbLoads.push(0);
      this._lbLoads.length = this.lbNodes;
    }
    if (cfg.playing !== undefined) this.playing = cfg.playing;
    if (cfg.scrubPos !== undefined) this.scrubPos = cfg.scrubPos;
  }

  /* ── Lifecycle ─────────────────────────────────────────────── */
  start() {
    if (this._running) return;
    this._running = true;
    this._tick();
  }

  stop() {
    this._running = false;
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
  }

  dispose() {
    this.stop();
    this._timeline = [];
    this._incidentBuffer = [];
    this._lbLoads = [];
  }

  /* ── Generate a single synthetic event ─────────────────────── */
  _generateEvent(isAnomaly) {
    this._eventCounter++;
    const now = new Date();

    if (isAnomaly) {
      const scenario = pick(ANOMALY_SCENARIOS);
      const risk = rand(scenario.risk[0], scenario.risk[1]);
      const evt = {
        event_id: uuid(),
        timestamp: now.toISOString(),
        event_type: scenario.resourceType,
        resource_type: scenario.resourceType,
        resource_id: `${scenario.resourceType}/${scenario.label}-${this._eventCounter}`,
        resource_name: `${scenario.label}-pod-${this._eventCounter % 50}`,
        pod_name: `${scenario.label}-pod-${this._eventCounter % 50}`,
        namespace: scenario.namespace,
        identity: scenario.identity,
        principal_id: scenario.identity,
        source_ip: `10.${Math.floor(rand(0,255))}.${Math.floor(rand(0,255))}.${Math.floor(rand(1,254))}`,
        destination_ip: `10.0.${Math.floor(rand(0,255))}.${Math.floor(rand(1,254))}`,
        risk_score: Math.round(risk),
        severity: risk >= 80 ? 'CRITICAL' : risk >= 60 ? 'HIGH' : risk >= 30 ? 'MEDIUM' : 'INFO',
        is_anomaly: true,
        scenario: scenario.label,
        _lbNode: this._assignLB(),
      };
      return evt;
    }

    // Normal event
    const rType = pick(RESOURCE_TYPES);
    const risk = rand(0, 25);
    const evt = {
      event_id: uuid(),
      timestamp: now.toISOString(),
      event_type: rType,
      resource_type: rType,
      resource_id: `${rType}/normal-${this._eventCounter}`,
      resource_name: `app-${this._eventCounter % 200}`,
      pod_name: `app-pod-${this._eventCounter % 200}`,
      namespace: pick(NORMAL_NAMESPACES),
      identity: pick(NORMAL_IDENTITIES),
      principal_id: pick(NORMAL_IDENTITIES),
      source_ip: `10.0.${Math.floor(rand(0,255))}.${Math.floor(rand(1,254))}`,
      destination_ip: `10.0.${Math.floor(rand(0,255))}.${Math.floor(rand(1,254))}`,
      risk_score: Math.round(risk),
      severity: 'INFO',
      is_anomaly: false,
      scenario: 'normal',
      _lbNode: this._assignLB(),
    };
    return evt;
  }

  /* ── Load balancer assignment (round-robin with anomaly bias) ─ */
  _assignLB() {
    const n = this.lbNodes;
    // Anomalies preferentially hit node 0 (hot-spot)
    const idx = Math.floor(Math.random() * n);
    this._lbLoads[idx] = (this._lbLoads[idx] || 0) + 1;
    return idx;
  }

  /* ── Burst detection (simple 10-second window) ─────────────── */
  _checkBurst() {
    const now = Date.now();
    // Prune window
    this._burstWindow = this._burstWindow.filter(t => now - t < 10000);
    this._burstAcc = this._burstWindow.length;
    return this._burstAcc;
  }

  /* ── Correlate into incidents ──────────────────────────────── */
  _correlateIncidents(anomalyEvents) {
    // Group anomalies by scenario within last 30s
    const now = Date.now();
    const recent = anomalyEvents.filter(e => now - new Date(e.timestamp).getTime() < 30000);
    const groups = {};
    recent.forEach(e => {
      const key = e.scenario || e.namespace || 'unknown';
      if (!groups[key]) groups[key] = [];
      groups[key].push(e);
    });

    Object.entries(groups).forEach(([key, evts]) => {
      if (evts.length < 3) return; // need at least 3 events
      const avgRisk = evts.reduce((s, e) => s + e.risk_score, 0) / evts.length;
      if (avgRisk < 45) return;

      // Avoid duplicate incidents for same group
      const existing = this._incidentBuffer.find(i => i.scenario === key && Date.now() - new Date(i.timestamp).getTime() < 15000);
      if (existing) return;

      const inc = {
        incident_id: 'sim-inc-' + key + '-' + Math.random().toString(36).slice(2,6),
        timestamp: new Date().toISOString(),
        severity: avgRisk >= 80 ? 'CRITICAL' : avgRisk >= 60 ? 'HIGH' : 'MEDIUM',
        risk_score: Math.round(avgRisk),
        scenario: key,
        node_count: evts.length,
        pod_name: evts[0]?.pod_name || 'unknown',
        namespace: evts[0]?.namespace || 'unknown',
        events: evts,
        _sim: true,
      };
      this._incidentBuffer.push(inc);
      this.onIncident(inc);
    });
  }

  /* ── Main tick loop ───────────────────────────────────────── */
  _tick() {
    if (!this._running) return;

    if (this.playing) {
      // Generate events for this tick
      const anomalyThreshold = this.anomalyMix / 100;
      const numEvents = Math.max(1, Math.round(this.eventRate));

      const newEvents = [];
      let anomalyCount = 0;

      for (let i = 0; i < numEvents; i++) {
        const isAnomaly = Math.random() < anomalyThreshold;
        const evt = this._generateEvent(isAnomaly);
        newEvents.push(evt);

        if (isAnomaly) {
          anomalyCount++;
          this._burstWindow.push(Date.now());
        }
      }

      // Add to timeline
      this._timeline.push(...newEvents);
      if (this._timeline.length > this._timelineMax) {
        this._timeline.splice(0, this._timeline.length - this._timelineMax);
      }

      const burst = this._checkBurst();
      const lbLoads = [...this._lbLoads];

      // Correlate
      const allAnomalies = this._timeline.filter(e => e.is_anomaly);
      this._correlateIncidents(allAnomalies);

      // Prune old incidents
      this._incidentBuffer = this._incidentBuffer.filter(
        i => Date.now() - new Date(i.timestamp).getTime() < 60000
      );

      this.onTick({
        events: newEvents,
        allEvents: [...this._timeline],
        anomalies: anomalyCount,
        burst,
        lbLoads,
        incidents: [...this._incidentBuffer],
      });
    }

    // Schedule next tick at ~1s interval adjusted by rate
    const interval = Math.max(50, Math.round(1000 / Math.max(1, this.eventRate)));
    this._timer = setTimeout(() => this._tick(), interval);
  }

  /* ── Get snapshot for scrub ────────────────────────────────── */
  getSnapshotAtPosition(pos) {
    const idx = Math.floor(pos * (this._timeline.length - 1));
    if (idx < 0 || idx >= this._timeline.length) return [];
    const count = Math.min(100, this._timeline.length);
    const start = Math.max(0, idx - Math.floor(count / 2));
    return this._timeline.slice(start, start + count);
  }

  /* ── Reset / clear timeline ────────────────────────────────── */
  reset() {
    this._timeline = [];
    this._incidentBuffer = [];
    this._burstWindow = [];
    this._burstAcc = 0;
    this._eventCounter = 0;
    this._lbLoads = new Array(this.lbNodes).fill(0);
  }
}
