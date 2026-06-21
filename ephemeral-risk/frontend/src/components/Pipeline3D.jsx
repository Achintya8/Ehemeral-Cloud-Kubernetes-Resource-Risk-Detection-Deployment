import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

/* ═══════════════════════════════════════════════════════════════════
   SocGen Brand Palette (hex → THREE int)
   Red #E30613  ·  Dark Red #B5040F  ·  Black #1A1A1A  ·  Dark #2D2D2D
   Info Blue #0065B3  ·  Success Green #00875A  ·  Warning Amber #E97C00
   White #FFFFFF  ·  Grey-400 #A0A0A0  ·  Grey-600 #4D4D4D
   ═══════════════════════════════════════════════════════════════════ */
const SG = {
  red: 0xE30613,
  redDark: 0xB5040F,
  black: 0x1A1A1A,
  dark: 0x2D2D2D,
  darkBg: 0x121216,       // slightly blueish dark (was 0x0F0F0F pure black)
  blue: 0x0065B3,
  green: 0x00875A,
  amber: 0xE97C00,
  white: 0xFFFFFF,
  grey400: 0xA0A0A0,
  grey600: 0x4D4D4D,
  gridLine: 0x6A2030,       // brightened red-tinted major grid (was 0x3D1015)
  gridMinor: 0x3A1520,       // visible minor grid (was 0x1A0A0B)
  starfield: 0xCC4060,       // brighter warm red stars (was 0x8B2030)
  fog: 0x1A1214,       // much lighter fog (was 0x0D0808 ~black)
  track: 0x201818,       // pipeline track (was 0x140E0E)
  lbPillar: 0x0065B3,
  lbGlow: 0x0088CC,       // brighter LB glow
  lbRing: 0xE30613,
};

/* ── Geometry helpers by resource type (K8s-themed, large) ─── */
const RESOURCE_GEO = {
  /* Pod = capsule shape (rounded cylinder) — the iconic K8s pod look */
  pod: () => {
    const group = new THREE.Group();
    // Main cylindrical body
    const body = new THREE.CylinderGeometry(0.55, 0.55, 1.6, 16);
    body.rotateZ(Math.PI / 2); // lay it on its side (along X axis)
    const bodyMesh = new THREE.Mesh(body);
    group.add(bodyMesh);
    // Hemisphere caps on each end
    const capGeo = new THREE.SphereGeometry(0.55, 16, 8, 0, Math.PI * 2, 0, Math.PI / 2);
    const capFront = new THREE.Mesh(capGeo);
    capFront.rotation.z = -Math.PI / 2;
    capFront.position.x = 0.8;
    group.add(capFront);
    const capBack = new THREE.Mesh(capGeo.clone());
    capBack.rotation.z = Math.PI / 2;
    capBack.position.x = -0.8;
    group.add(capBack);
    // Small "status LED" indicator on top
    const led = new THREE.Mesh(
      new THREE.SphereGeometry(0.12, 8, 8),
      new THREE.MeshPhongMaterial({ color: 0x00FF88, emissive: 0x00FF88, emissiveIntensity: 0.8 })
    );
    led.position.y = 0.55;
    group.add(led);
    return group;
  },
  container: () => new THREE.BoxGeometry(1.2, 0.9, 0.9),
  deployment: () => new THREE.CylinderGeometry(0.5, 0.7, 1.2, 12),
  service: () => new THREE.TorusGeometry(0.7, 0.22, 12, 24),
  network: () => new THREE.OctahedronGeometry(0.8),
  identity: () => new THREE.IcosahedronGeometry(0.7),
  configmap: () => new THREE.DodecahedronGeometry(0.65),
  secret: () => new THREE.ConeGeometry(0.55, 1.2, 8),
  volume: () => new THREE.BoxGeometry(1.3, 0.6, 0.6),
  default: () => {
    // Same capsule as pod for unknown types
    const group = new THREE.Group();
    const body = new THREE.CylinderGeometry(0.55, 0.55, 1.6, 16);
    body.rotateZ(Math.PI / 2);
    const bodyMesh = new THREE.Mesh(body);
    group.add(bodyMesh);
    const capGeo = new THREE.SphereGeometry(0.55, 16, 8, 0, Math.PI * 2, 0, Math.PI / 2);
    const capFront = new THREE.Mesh(capGeo);
    capFront.rotation.z = -Math.PI / 2;
    capFront.position.x = 0.8;
    group.add(capFront);
    const capBack = new THREE.Mesh(capGeo.clone());
    capBack.rotation.z = Math.PI / 2;
    capBack.position.x = -0.8;
    group.add(capBack);
    const led = new THREE.Mesh(
      new THREE.SphereGeometry(0.12, 8, 8),
      new THREE.MeshPhongMaterial({ color: 0x00FF88, emissive: 0x00FF88, emissiveIntensity: 0.8 })
    );
    led.position.y = 0.55;
    group.add(led);
    return group;
  },
};

function resourceTypeOf(event) {
  const r = (event.resource_type || event.event_type || event.log_type || '').toLowerCase();
  const name = (event.resource_name || event.resource_id || '').toLowerCase();

  if (r.includes('pod') || name.includes('pod') || r.includes('container') || name.includes('container')) return 'pod';
  if (r.includes('deployment') || name.includes('deployment')) return 'deployment';
  if (r.includes('service') || name.includes('service')) return 'service';
  if (r.includes('network') || r.includes('vpc') || r.includes('ingress') || r.includes('firewall')) return 'network';
  if (r.includes('identity') || r.includes('iam') || r.includes('sts') || r.includes('auth') || r.includes('rbac') || r.includes('serviceaccount')) return 'identity';
  if (r.includes('configmap') || name.includes('config')) return 'configmap';
  if (r.includes('secret') || name.includes('secret')) return 'secret';
  if (r.includes('volume') || r.includes('pvc') || r.includes('storage')) return 'volume';

  if (r.includes('cloudtrail') || r.includes('vpc')) return 'network';
  if (r.includes('k8s_audit')) return 'pod';

  return 'pod'; // Fallback to pod as it's the most iconic representation
}

/* ── Severity → SocGen colors (with boosted emissive) ─────── */
const SEV_COLOR = {
  CRITICAL: { main: SG.red, emissive: SG.redDark, emissiveI: 0.7 },
  HIGH: { main: SG.amber, emissive: 0xCC6200, emissiveI: 0.5 },
  MEDIUM: { main: SG.grey400, emissive: 0x666666, emissiveI: 0.15 },
  INFO: { main: SG.blue, emissive: 0x003D6B, emissiveI: 0.2 },
};

function sevColor(sev) {
  return SEV_COLOR[String(sev || '').toUpperCase()] || SEV_COLOR.INFO;
}

const eventIdOf = (e) => String(e.event_id ?? e.id ?? '');

/* ── Containment actions ──────────────────────────────────────── */
const CONTAINMENT_ACTIONS = [
  'POD CONTAINED',
  'CREDENTIALS REVOKED',
  'NETWORK GUARDRAILED',
  'SESSION TERMINATED',
  'POLICY ENFORCED',
  'NODE QUARANTINED',
];

/* ── Incident ring (SocGen red, larger) ─────────────────────── */
function makeIncidentRing() {
  const geo = new THREE.TorusGeometry(2.4, 0.06, 8, 48);
  const mat = new THREE.MeshBasicMaterial({ color: SG.red, transparent: true, opacity: 0.6 });
  return new THREE.Mesh(geo, mat);
}

/* ── Containment burst particles (bigger) ────────────────────── */
function spawnContainmentBurst(scene, position, color) {
  const count = 36;
  const geo = new THREE.BufferGeometry();
  const pos = new Float32Array(count * 3);
  const vel = [];
  for (let i = 0; i < count; i++) {
    pos[i * 3] = position.x;
    pos[i * 3 + 1] = position.y;
    pos[i * 3 + 2] = position.z;
    vel.push(new THREE.Vector3(
      (Math.random() - 0.5) * 0.6,
      Math.random() * 0.4 + 0.15,
      (Math.random() - 0.5) * 0.6
    ));
  }
  geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  const mat = new THREE.PointsMaterial({ color, size: 0.25, transparent: true, opacity: 1 });
  const pts = new THREE.Points(geo, mat);
  pts.userData = { vel, life: 1.0 };
  scene.add(pts);
  return pts;
}

/* ── Load-balancer node visuals (scaled up) ─────────────────── */
function makeLBNode(index, total) {
  const group = new THREE.Group();
  const angle = (index / total) * Math.PI * 2;
  const radius = 6;
  group.position.set(Math.cos(angle) * radius, 0, Math.sin(angle) * radius);

  const pillar = new THREE.Mesh(
    new THREE.CylinderGeometry(0.8, 1.0, 1.6, 8),
    new THREE.MeshPhongMaterial({ color: SG.lbPillar, emissive: 0x004D80, emissiveIntensity: 0.4 })
  );
  group.add(pillar);

  const disc = new THREE.Mesh(
    new THREE.CircleGeometry(1.2, 24),
    new THREE.MeshBasicMaterial({ color: SG.lbGlow, transparent: true, opacity: 0.3, side: THREE.DoubleSide })
  );
  disc.rotation.x = -Math.PI / 2;
  disc.position.y = 0.85;
  group.add(disc);

  // Red ring around base
  const ring = new THREE.Mesh(
    new THREE.TorusGeometry(1.1, 0.04, 8, 24),
    new THREE.MeshBasicMaterial({ color: SG.lbRing, transparent: true, opacity: 0.5 })
  );
  ring.rotation.x = -Math.PI / 2;
  ring.position.y = -0.75;
  group.add(ring);

  const canvas = document.createElement('canvas');
  canvas.width = 128; canvas.height = 48;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#FFFFFF';
  ctx.font = 'bold 22px monospace';
  ctx.textAlign = 'center';
  ctx.fillText(`Node ${index + 1}`, 64, 30);
  const tex = new THREE.CanvasTexture(canvas);
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true }));
  sprite.position.y = 1.8;
  sprite.scale.set(2.4, 0.9, 1);
  group.add(sprite);

  group.userData = { index, disc, pillar, ring, loadCount: 0 };
  return group;
}

/* ═══════════════════════════════════════════════════════════════════
   Main component
   ═══════════════════════════════════════════════════════════════════ */
export default function Pipeline3D({
  events = [],
  incidents = [],
  lbNodes = 3,
  showLB = false,
  className = '',
  onThreatContained,   // (eventId, event, action) => void
  autoContainDelay = 6000,  // ms before threat auto-contains
}) {
  const mountRef = useRef(null);
  const threeRef = useRef(null);
  const meshesMap = useRef({});
  const incidentRings = useRef({});
  const lbGroupRef = useRef(null);
  const prevEventsRef = useRef(new Set());
  const burstParticles = useRef([]);
  const containTimers = useRef({});

  /* ── Scene bootstrap ─────────────────────────────────────── */
  useEffect(() => {
    const mount = mountRef.current;
    if (!mount || threeRef.current) return;

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(SG.fog, 0.007);  // reduced density (was 0.012)

    const w = mount.clientWidth || 800, h = mount.clientHeight || 500;
    const camera = new THREE.PerspectiveCamera(50, w / h, 0.1, 500);
    camera.position.set(0, 16, 28);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(SG.darkBg, 1);
    mount.appendChild(renderer.domElement);

    // Lighting — significantly brighter
    scene.add(new THREE.AmbientLight(SG.white, 0.6));    // was 0.35
    const dir = new THREE.DirectionalLight(SG.white, 1.0); // was 0.7
    dir.position.set(10, 25, 15);
    scene.add(dir);
    // Red accent point light — stronger
    const point = new THREE.PointLight(SG.red, 1.5, 80); // was 0.5, range 60
    point.position.set(-10, 12, -10);
    scene.add(point);
    // Blue fill light from the other side
    const blueFill = new THREE.PointLight(SG.blue, 0.6, 60);
    blueFill.position.set(12, 8, 10);
    scene.add(blueFill);

    // SocGen-tinted grid (brighter)
    const grid = new THREE.GridHelper(200, 60, SG.gridLine, SG.gridMinor);
    grid.position.y = -2;
    scene.add(grid);

    // Pipeline track
    const trackGeo = new THREE.PlaneGeometry(10, 180);
    const trackMat = new THREE.MeshBasicMaterial({ color: SG.track, transparent: true, opacity: 0.5, side: THREE.DoubleSide });
    const track = new THREE.Mesh(trackGeo, trackMat);
    track.rotation.x = -Math.PI / 2;
    track.position.y = -1.95;
    scene.add(track);

    // Starfield (brighter warm red stars)
    const starGeo = new THREE.BufferGeometry();
    const starPos = new Float32Array(1200 * 3);
    for (let i = 0; i < 1200; i++) {
      starPos[i * 3] = (Math.random() - 0.5) * 200;
      starPos[i * 3 + 1] = (Math.random() - 0.5) * 80;
      starPos[i * 3 + 2] = (Math.random() - 0.5) * 200;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({ color: SG.starfield, size: 0.18 }));
    scene.add(stars);

    const lbGroup = new THREE.Group();
    lbGroup.position.y = -1.9;
    scene.add(lbGroup);
    lbGroupRef.current = lbGroup;

    const frameId = { id: 0 };

    const animate = () => {
      frameId.id = requestAnimationFrame(animate);
      const t = performance.now();

      // Event nodes
      Object.keys(meshesMap.current).forEach(id => {
        const m = meshesMap.current[id];
        if (!m) return;

        if (m.userData.active && !m.userData.containing) {
          m.position.z += m.userData.speed;
          // Only rotate non-pod groups on Y axis; pods rotate slowly on their X axis
          if (m.userData.resourceType === 'pod' && m.isGroup) {
            m.rotation.y += (m.userData.spin || 0.003) * 0.5;
          } else {
            m.rotation.y += m.userData.spin || 0.005;
          }
          if (m.userData.isThreat) {
            const intensity = 0.5 + Math.sin(t * 0.004 + m.userData.phase) * 0.4;
            m.traverse(child => {
              if (child.isMesh && child.material && child.material.emissiveIntensity !== undefined) {
                child.material.emissiveIntensity = intensity;
              }
            });
          }
          if (m.position.z > 50) {
            m.position.z = -85;
            m.position.x = (Math.random() - 0.5) * 8;
          }
        } else if (m.userData.containing) {
          // ── CONTAINMENT ANIMATION ──
          const elapsed = t - m.userData.containStart;
          if (elapsed < 500) {
            // Phase 1: freeze + bright flash
            if (m.material) {
              m.material.emissive.setHex(SG.white);
              m.material.emissiveIntensity = 1.0 - (elapsed / 500) * 0.6;
            }
          } else if (elapsed < 1500) {
            // Phase 2: shrink + turn green (contained)
            const p = (elapsed - 500) / 1000;
            m.traverse(child => {
              if (child.isMesh && child.material) {
                if (child.material.color) child.material.color.lerp(new THREE.Color(SG.green), 0.05);
                if (child.material.emissive) {
                  child.material.emissive.setHex(SG.green);
                  child.material.emissiveIntensity = 0.4 * (1 - p);
                }
              }
            });
            m.scale.setScalar(Math.max(0.1, m.userData.containBaseScale * (1 - p * 0.5)));
          } else if (elapsed < 2500) {
            // Phase 3: tiny + eject up
            const p = (elapsed - 1500) / 1000;
            m.position.y += 0.15;
            m.scale.setScalar(Math.max(0.02, 0.5 * (1 - p)));
            m.traverse(child => {
              if (child.isMesh && child.material) child.material.opacity = Math.max(0, 1 - p);
            });
          } else {
            // Done — clean up
            scene.remove(m);
            m.traverse(child => {
              if (child.geometry) child.geometry.dispose();
              if (child.material) child.material.dispose();
            });
            delete meshesMap.current[id];
          }
        } else if (m.userData.deleting) {
          // Normal eject (non-threat removal)
          m.position.y += 0.15;
          m.position.x += m.userData.ejectVx || 0;
          m.position.z += (m.userData.ejectVz || 0) * 0.02;
          m.scale.multiplyScalar(0.92);
          m.traverse(child => {
            if (child.isMesh && child.material) {
              child.material.opacity = Math.max(0, (child.material.opacity ?? 1) - 0.04);
              if (m.userData.isThreat && child.material.emissiveIntensity !== undefined) {
                child.material.emissiveIntensity = (Math.sin(t * 0.015) + 1) * 1.2;
              }
            }
          });
          if (m.scale.x < 0.02) {
            scene.remove(m);
            m.traverse(child => {
              if (child.geometry) child.geometry.dispose();
              if (child.material) child.material.dispose();
            });
            delete meshesMap.current[id];
          }
        }
      });

      // Burst particles
      burstParticles.current = burstParticles.current.filter(pts => {
        const positions = pts.geometry.attributes.position.array;
        const vel = pts.userData.vel;
        for (let i = 0; i < vel.length; i++) {
          positions[i * 3] += vel[i].x;
          positions[i * 3 + 1] += vel[i].y;
          positions[i * 3 + 2] += vel[i].z;
          vel[i].y -= 0.006; // gravity
        }
        pts.geometry.attributes.position.needsUpdate = true;
        pts.userData.life -= 0.012;
        pts.material.opacity = Math.max(0, pts.userData.life);
        if (pts.userData.life <= 0) {
          scene.remove(pts);
          pts.geometry.dispose();
          pts.material.dispose();
          return false;
        }
        return true;
      });

      // Incident rings
      Object.values(incidentRings.current).forEach(ring => {
        ring.rotation.x = Math.sin(t * 0.001) * 0.15;
        ring.rotation.z = t * 0.0005;
        ring.material.opacity = 0.4 + Math.sin(t * 0.003) * 0.2;
      });

      // LB disc pulse
      if (lbGroupRef.current) {
        lbGroupRef.current.children.forEach(node => {
          if (node.userData.disc) {
            node.userData.disc.material.opacity = 0.2 + Math.sin(t * 0.002 + node.userData.index) * 0.1;
          }
          if (node.userData.ring) {
            node.userData.ring.material.opacity = 0.35 + Math.sin(t * 0.003 + node.userData.index) * 0.15;
          }
        });
      }

      renderer.render(scene, camera);
    };
    animate();

    const onResize = () => {
      if (!mount) return;
      const nw = mount.clientWidth || 800, nh = mount.clientHeight || 500;
      if (nw === 0 || nh === 0) return;
      camera.aspect = nw / nh;
      camera.updateProjectionMatrix();
      renderer.setSize(nw, nh);
    };
    window.addEventListener('resize', onResize);
    // Also observe mount size changes (e.g. layout adjustments)
    const ro = new ResizeObserver(onResize);
    if (mount) ro.observe(mount);

    threeRef.current = { scene, camera, renderer, frameId };

    return () => {
      window.removeEventListener('resize', onResize);
      ro.disconnect();
      cancelAnimationFrame(frameId.id);
      // Clear containment timers
      Object.values(containTimers.current).forEach(clearTimeout);
      containTimers.current = {};
      if (mount && renderer.domElement.parentNode === mount) {
        mount.removeChild(renderer.domElement);
      }
      renderer.dispose();
      threeRef.current = null;
    };
  }, []);

  /* ── Rebuild LB nodes ─────────────────────────────────────── */
  useEffect(() => {
    const lbGroup = lbGroupRef.current;
    if (!lbGroup) return;
    while (lbGroup.children.length) {
      const child = lbGroup.children[0];
      lbGroup.remove(child);
      child.traverse(o => {
        if (o.geometry) o.geometry.dispose();
        if (o.material) { if (o.material.map) o.material.map.dispose(); o.material.dispose(); }
      });
    }
    if (!showLB) return;
    for (let i = 0; i < lbNodes; i++) {
      lbGroup.add(makeLBNode(i, lbNodes));
    }
  }, [lbNodes, showLB]);

  /* ── Sync event nodes ──────────────────────────────────────── */
  useEffect(() => {
    const scene = threeRef.current?.scene;
    if (!scene) return;

    const currentIds = new Set(events.map(eventIdOf).filter(Boolean));
    const prev = prevEventsRef.current;

    // Eject nodes that disappeared
    prev.forEach(id => {
      if (!currentIds.has(id) && meshesMap.current[id]) {
        const m = meshesMap.current[id];
        if (m.userData.deleting || m.userData.containing) return;
        m.userData.active = false;
        m.userData.deleting = true;
        m.userData.ejectVx = (Math.random() - 0.5) * 3;
        m.userData.ejectVz = 20 + Math.random() * 15;
        // Clear any pending containment timer
        if (containTimers.current[id]) {
          clearTimeout(containTimers.current[id]);
          delete containTimers.current[id];
        }
      }
    });
    prevEventsRef.current = currentIds;

    // Spawn new nodes
    events.forEach(event => {
      const eid = eventIdOf(event);
      if (!eid || meshesMap.current[eid]) return;

      const sev = event.severity || 'INFO';
      const sc = sevColor(sev);
      const isThreat = sev === 'CRITICAL' || sev === 'HIGH' || (Number(event.risk_score) >= 70);
      const rType = resourceTypeOf(event);
      const geoFactory = RESOURCE_GEO[rType] || RESOURCE_GEO.default;
      const geo = geoFactory();

      // For pod groups, apply material to all children
      const applyMat = (object, material) => {
        if (object.isMesh) {
          // Don't overwrite LED color on pod groups
          if (rType === 'pod' && object.material && object.material.color) {
            const origColor = object.material.color.getHex();
            if (origColor === 0x00FF88) return; // skip LED
          }
          object.material = material.clone();
        }
        if (object.children) object.children.forEach(c => applyMat(c, material));
      };

      const mat = new THREE.MeshPhongMaterial({
        color: sc.main,
        emissive: sc.emissive,
        emissiveIntensity: isThreat ? sc.emissiveI : 0.05,
        transparent: true,
        opacity: 1,
        shininess: 90,
      });

      // Update LED color based on threat status for pods
      let mesh;
      if (geo.isGroup) {
        mesh = geo;
        applyMat(mesh, mat);
        // Set LED to red for threats, green for safe
        mesh.traverse(child => {
          if (child.isMesh && child.material && child.material.color) {
            if (child.material.color.getHex() === 0x00FF88) {
              child.material.color.setHex(isThreat ? SG.red : SG.green);
              if (child.material.emissive) {
                child.material.emissive.setHex(isThreat ? SG.red : SG.green);
                child.material.emissiveIntensity = 0.8;
              }
            }
          }
        });
      } else {
        mesh = new THREE.Mesh(geo, mat);
      }

      const risk = Number(event.risk_score || 0);
      mesh.position.z = -70 + (Math.random() * 30);
      mesh.position.x = (Math.random() - 0.5) * 8;
      mesh.position.y = isThreat ? 0.8 + Math.random() * 0.6 : 0;

      // Bigger scale — threats are 2x, normals are 1.5x
      const baseScale = isThreat ? 2.0 : 1.2 + (risk / 100) * 0.5;
      mesh.scale.setScalar(baseScale);

      mesh.userData = {
        active: true,
        deleting: false,
        containing: false,
        isThreat,
        speed: 0.12 + (risk / 100) * 0.18,
        spin: isThreat ? 0.02 : 0.005,
        phase: Math.random() * Math.PI * 2,
        eventId: eid,
        resourceType: rType,
        severity: sev,
        containBaseScale: baseScale,
        event: event,
      };

      scene.add(mesh);
      meshesMap.current[eid] = mesh;

      // ── Auto-contain threats after delay ───────────────────
      if (isThreat && autoContainDelay > 0 && onThreatContained) {
        containTimers.current[eid] = setTimeout(() => {
          if (!meshesMap.current[eid]) return;
          const m = meshesMap.current[eid];
          if (m.userData.deleting || m.userData.containing) return;

          const action = CONTAINMENT_ACTIONS[Math.floor(Math.random() * CONTAINMENT_ACTIONS.length)];

          // Spawn burst particles at node position
          spawnContainmentBurst(scene, m.position.clone(), SG.green);

          // Start containment animation
          m.userData.active = false;
          m.userData.containing = true;
          m.userData.containStart = performance.now();
          m.userData.containAction = action;

          // Fire callback so parent can log it
          onThreatContained(eid, event, action);
          delete containTimers.current[eid];
        }, autoContainDelay);
      }
    });
  }, [events, autoContainDelay, onThreatContained]);

  /* ── Incident cluster rings ──────────────────────────────── */
  useEffect(() => {
    const scene = threeRef.current?.scene;
    if (!scene) return;

    const activeIds = new Set(incidents.map(i => i.incident_id).filter(Boolean));
    Object.keys(incidentRings.current).forEach(id => {
      if (!activeIds.has(id)) {
        scene.remove(incidentRings.current[id]);
        delete incidentRings.current[id];
      }
    });
    incidents.forEach(inc => {
      if (!inc.incident_id || incidentRings.current[inc.incident_id]) return;
      const ring = makeIncidentRing();
      ring.position.set(
        (Math.random() - 0.5) * 8,
        2,
        -30 + Math.random() * 40
      );
      scene.add(ring);
      incidentRings.current[inc.incident_id] = ring;
    });
  }, [incidents]);

  return (
    <div className={`pipeline3d-root ${className}`} style={{ width: '100%', height: '100%', minHeight: 0 }}>
      <div ref={mountRef} style={{ width: '100%', height: '100%' }} />
    </div>
  );
}
