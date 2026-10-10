import {
  AdditiveBlending,
  BackSide,
  BufferGeometry,
  Color,
  Float32BufferAttribute,
  Mesh,
  PerspectiveCamera,
  Points,
  Scene,
  ShaderMaterial,
  SphereGeometry,
  Vector3,
  WebGLRenderer,
} from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { loadCoastlines } from "./coast";
import { latLonToVec3 } from "./geo";
import { sunDirection } from "./sun";
import { isOpen, type Receiver } from "./types";

const R = 1;

const globeVert = /* glsl */ `
  varying vec3 vNormal;
  varying vec3 vWorld;
  void main() {
    vNormal = normalize(normalMatrix * normal);
    vWorld = normalize(position);
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const globeFrag = /* glsl */ `
  uniform vec3 uSun;
  uniform vec3 uDay;
  uniform vec3 uNight;
  varying vec3 vNormal;
  varying vec3 vWorld;
  void main() {
    float d = dot(vWorld, uSun);
    float light = smoothstep(-0.12, 0.18, d);
    vec3 c = mix(uNight, uDay, light);
    // faint limb brightening so the sphere reads as a sphere
    float rim = pow(1.0 - max(dot(vNormal, vec3(0.0, 0.0, 1.0)), 0.0), 3.0);
    c += vec3(0.08, 0.14, 0.24) * rim;
    gl_FragColor = vec4(c, 1.0);
  }
`;

const atmoVert = /* glsl */ `
  varying vec3 vNormal;
  void main() {
    vNormal = normalize(normalMatrix * normal);
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const atmoFrag = /* glsl */ `
  varying vec3 vNormal;
  void main() {
    float i = pow(0.62 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 4.0);
    gl_FragColor = vec4(0.25, 0.5, 0.9, 1.0) * i;
  }
`;

const pointVert = /* glsl */ `
  attribute float aSize;
  attribute vec3 aColor;
  varying vec3 vColor;
  uniform float uScale;
  void main() {
    vColor = aColor;
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = aSize * uScale / -mv.z;
    gl_Position = projectionMatrix * mv;
  }
`;

const pointFrag = /* glsl */ `
  varying vec3 vColor;
  void main() {
    vec2 p = gl_PointCoord - 0.5;
    float r = length(p) * 2.0;
    if (r > 1.0) discard;
    float core = smoothstep(0.45, 0.0, r);
    float halo = pow(1.0 - r, 2.2) * 0.55;
    gl_FragColor = vec4(vColor * (core + halo), core + halo);
  }
`;

export interface PickResult {
  receiver: Receiver;
  x: number;
  y: number;
}

export class Globe {
  readonly scene = new Scene();
  readonly camera: PerspectiveCamera;
  readonly renderer: WebGLRenderer;
  readonly controls: OrbitControls;

  private readonly sunUniform = { value: new Vector3(1, 0, 0) };
  private readonly pointScale = { value: 1 };
  private points: Points | null = null;
  private receivers: Receiver[] = [];
  private positions = new Float32Array(0);
  private selectedIndex = -1;
  private hoverIndex = -1;
  private lastSunUpdate = 0;
  private readonly tmp = new Vector3();
  private readonly camDir = new Vector3();

  constructor(private readonly canvas: HTMLCanvasElement) {
    this.renderer = new WebGLRenderer({ canvas, antialias: true, alpha: false, powerPreference: "low-power" });
    this.renderer.setClearColor(new Color(0x04060c), 1);
    this.camera = new PerspectiveCamera(40, 1, 0.1, 100);
    this.camera.position.set(0, 0.6, 3.2);

    this.controls = new OrbitControls(this.camera, canvas);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.08;
    this.controls.enablePan = false;
    this.controls.minDistance = 1.35;
    this.controls.maxDistance = 6;
    this.controls.rotateSpeed = 0.6;
    this.controls.zoomSpeed = 0.7;
    this.controls.autoRotate = true;
    this.controls.autoRotateSpeed = 0.25;
    canvas.addEventListener("pointerdown", () => (this.controls.autoRotate = false), { once: true });
    canvas.addEventListener("wheel", () => (this.controls.autoRotate = false), { once: true, passive: true });

    const globe = new Mesh(
      new SphereGeometry(R, 96, 96),
      new ShaderMaterial({
        vertexShader: globeVert,
        fragmentShader: globeFrag,
        uniforms: {
          uSun: this.sunUniform,
          uDay: { value: new Color(0x0d1a2f) },
          uNight: { value: new Color(0x05080f) },
        },
      }),
    );
    this.scene.add(globe);

    const atmosphere = new Mesh(
      new SphereGeometry(R * 1.08, 64, 64),
      new ShaderMaterial({
        vertexShader: atmoVert,
        fragmentShader: atmoFrag,
        blending: AdditiveBlending,
        side: BackSide,
        transparent: true,
        depthWrite: false,
      }),
    );
    this.scene.add(atmosphere);

    void loadCoastlines(R * 1.002).then((lines) => this.scene.add(lines));

    this.resize();
    window.addEventListener("resize", () => this.resize());
    this.updateSun(true);
  }

  private resize(): void {
    const w = this.canvas.clientWidth || window.innerWidth;
    const h = this.canvas.clientHeight || window.innerHeight;
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.pointScale.value = (h * this.renderer.getPixelRatio()) / 240;
  }

  /** Recompute the terminator at most every 30 s. */
  private updateSun(force = false): void {
    const now = Date.now();
    if (!force && now - this.lastSunUpdate < 30_000) return;
    this.lastSunUpdate = now;
    sunDirection(new Date(now), this.sunUniform.value);
  }

  setReceivers(receivers: Receiver[]): void {
    this.receivers = receivers;
    const n = receivers.length;
    this.positions = new Float32Array(n * 3);
    const sizes = new Float32Array(n);
    const colors = new Float32Array(n * 3);
    const v = new Vector3();
    for (let i = 0; i < n; i++) {
      const r = receivers[i]!;
      latLonToVec3(r.lat, r.lon, R * 1.012, v);
      this.positions[i * 3] = v.x;
      this.positions[i * 3 + 1] = v.y;
      this.positions[i * 3 + 2] = v.z;
      this.styleFor(r, i, sizes, colors);
    }
    if (this.points) {
      this.scene.remove(this.points);
      this.points.geometry.dispose();
    }
    const geom = new BufferGeometry();
    geom.setAttribute("position", new Float32BufferAttribute(this.positions, 3));
    geom.setAttribute("aSize", new Float32BufferAttribute(sizes, 1));
    geom.setAttribute("aColor", new Float32BufferAttribute(colors, 3));
    this.points = new Points(
      geom,
      new ShaderMaterial({
        vertexShader: pointVert,
        fragmentShader: pointFrag,
        uniforms: { uScale: this.pointScale },
        transparent: true,
        depthWrite: false,
        depthTest: true,
        blending: AdditiveBlending,
      }),
    );
    this.scene.add(this.points);
  }

  private styleFor(r: Receiver, i: number, sizes: Float32Array, colors: Float32Array): void {
    const open = isOpen(r);
    const selected = i === this.selectedIndex;
    const hovered = i === this.hoverIndex;
    let size = open ? 7 + Math.min(Math.max(r.snr, 0), 40) / 8 : 4;
    if (selected) size *= 2.2;
    else if (hovered) size *= 1.6;
    sizes[i] = size;
    let c: Color;
    if (selected) c = new Color(0xffffff);
    else if (open) c = hovered ? new Color(0xb9ffd9) : new Color(0x6ee7a8);
    else c = new Color(0x3b4454);
    colors[i * 3] = c.r;
    colors[i * 3 + 1] = c.g;
    colors[i * 3 + 2] = c.b;
  }

  private restyle(indices: number[]): void {
    if (!this.points) return;
    const sizes = this.points.geometry.getAttribute("aSize") as Float32BufferAttribute;
    const colors = this.points.geometry.getAttribute("aColor") as Float32BufferAttribute;
    const sz = new Float32Array(1);
    const col = new Float32Array(3);
    for (const i of indices) {
      if (i < 0 || i >= this.receivers.length) continue;
      this.styleFor(this.receivers[i]!, 0, sz, col);
      sizes.setX(i, sz[0]!);
      colors.setXYZ(i, col[0]!, col[1]!, col[2]!);
    }
    sizes.needsUpdate = true;
    colors.needsUpdate = true;
  }

  setHover(index: number): void {
    if (index === this.hoverIndex) return;
    const prev = this.hoverIndex;
    this.hoverIndex = index;
    this.restyle([prev, index]);
  }

  setSelected(index: number): void {
    if (index === this.selectedIndex) return;
    const prev = this.selectedIndex;
    this.selectedIndex = index;
    this.restyle([prev, index]);
  }

  /**
   * Nearest receiver (on the visible hemisphere) within `radiusPx` of a
   * screen position, else null.
   */
  pick(clientX: number, clientY: number, radiusPx = 14): { index: number; receiver: Receiver } | null {
    const rect = this.canvas.getBoundingClientRect();
    const nx = ((clientX - rect.left) / rect.width) * 2 - 1;
    const ny = -(((clientY - rect.top) / rect.height) * 2 - 1);
    this.camera.getWorldDirection(this.camDir);
    const camPos = this.camera.position;
    let best = -1;
    let bestD = Infinity;
    const r2 = radiusPx * radiusPx;
    for (let i = 0; i < this.receivers.length; i++) {
      const p = this.tmp.set(this.positions[i * 3]!, this.positions[i * 3 + 1]!, this.positions[i * 3 + 2]!);
      // Visible hemisphere: the point's normal faces the camera.
      if (p.dot(camPos) <= 0.15 * camPos.length()) continue;
      p.project(this.camera);
      const dx = ((p.x - nx) * rect.width) / 2;
      const dy = ((p.y - ny) * rect.height) / 2;
      const d = dx * dx + dy * dy;
      if (d < r2 && d < bestD) {
        bestD = d;
        best = i;
      }
    }
    return best >= 0 ? { index: best, receiver: this.receivers[best]! } : null;
  }

  /** Smoothly rotate to put a receiver front and centre. */
  focus(index: number): void {
    const r = this.receivers[index];
    if (!r) return;
    const target = latLonToVec3(r.lat, r.lon, this.camera.position.length());
    this.flyTarget = target;
  }
  private flyTarget: Vector3 | null = null;

  start(): void {
    const tick = (): void => {
      this.updateSun();
      if (this.flyTarget) {
        this.camera.position.lerp(this.flyTarget, 0.08);
        if (this.camera.position.distanceTo(this.flyTarget) < 0.01) this.flyTarget = null;
      }
      this.controls.update();
      this.renderer.render(this.scene, this.camera);
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
}
