// The player: one WebSocket to the relay, one AudioWorklet.
//
// Wire format from the relay (internal/server/server.go):
//   text frames   JSON status messages
//   binary frames u8 type=1, u8 flags, u16 rssi LE ((dBm+127)*10), u32 seq LE,
//                 then int16 LE PCM at the receiver's sample rate

export type PlayerState = "idle" | "connecting" | "playing" | "closed";

export interface StatusEvent {
  state: string;
  reason?: string;
  detail?: string;
  retryAfter?: number;
  sampleRate?: number;
  version?: string;
  rx?: string;
  name?: string;
}

export interface BufferStats {
  state: string;
  buffered: number; // seconds
  underruns: number;
  received: number; // samples since the worklet started
  ratio: number;
}

export interface PlayerEvents {
  status: (st: StatusEvent) => void;
  rssi: (dBm: number, flags: number) => void;
  state: (s: PlayerState) => void;
  stats: (s: BufferStats) => void;
}

const WORKLET_URL = "/player-worklet.js";
const WS_AUTH_FIELD = "token";

// Trusted Types: the CSP requires a policy for script URLs. This is the only
// policy in the app and it accepts exactly one URL.
function workletURL(): string {
  const tt = (window as unknown as { trustedTypes?: { createPolicy: (n: string, r: { createScriptURL: (s: string) => string }) => { createScriptURL: (s: string) => unknown } } }).trustedTypes;
  if (!tt) return WORKLET_URL;
  const policy = tt.createPolicy("kg", {
    createScriptURL: (s: string) => {
      if (s !== WORKLET_URL) throw new Error("refused script URL");
      return s;
    },
  });
  return policy.createScriptURL(WORKLET_URL) as string;
}

export class Player {
  private ws: WebSocket | null = null;
  private ctx: AudioContext | null = null;
  private node: AudioWorkletNode | null = null;
  private readonly handlers: Partial<PlayerEvents> = {};
  private _state: PlayerState = "idle";
  private volume = 0.8;
  private wanted: { rx: string; freq: number; mode: string } | null = null;
  private workletReady: Promise<void> | null = null;

  constructor(private readonly token: string) {}

  on<K extends keyof PlayerEvents>(ev: K, fn: PlayerEvents[K]): void {
    this.handlers[ev] = fn;
  }

  get state(): PlayerState {
    return this._state;
  }

  private setState(s: PlayerState): void {
    if (s === this._state) return;
    this._state = s;
    this.handlers.state?.(s);
  }

  /** Must be called from a user gesture the first time (autoplay policy). */
  private async ensureAudio(): Promise<void> {
    if (!this.ctx) {
      this.ctx = new AudioContext({ latencyHint: "playback" });
      this.workletReady = this.ctx.audioWorklet.addModule(workletURL()).then(() => {
        this.node = new AudioWorkletNode(this.ctx!, "kiwi-player", { numberOfInputs: 0, outputChannelCount: [2] });
        this.node.connect(this.ctx!.destination);
        this.node.port.postMessage({ type: "volume", value: this.volume });
        this.node.port.onmessage = (ev: MessageEvent<unknown>) => {
          const m = ev.data;
          if (typeof m !== "object" || m === null) return;
          const s = m as Record<string, unknown>;
          if (s.type !== "stats") return;
          this.handlers.stats?.({
            state: typeof s.state === "string" ? s.state : "",
            buffered: typeof s.buffered === "number" ? s.buffered : 0,
            underruns: typeof s.underruns === "number" ? s.underruns : 0,
            received: typeof s.received === "number" ? s.received : 0,
            ratio: typeof s.ratio === "number" ? s.ratio : 1,
          });
        };
      });
    }
    if (this.ctx.state === "suspended") await this.ctx.resume();
    await this.workletReady;
  }

  private ensureSocket(): Promise<WebSocket> {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return Promise.resolve(this.ws);
    if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
      const ws = this.ws;
      return new Promise((res, rej) => {
        ws.addEventListener("open", () => res(ws), { once: true });
        ws.addEventListener("error", () => rej(new Error("relay socket failed")), { once: true });
      });
    }
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}/api/stream`);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    return new Promise((res, rej) => {
      ws.addEventListener(
        "open",
        () => {
          ws.send(JSON.stringify({ type: "auth", [WS_AUTH_FIELD]: this.token }));
          res(ws);
        },
        { once: true },
      );
      ws.addEventListener("error", () => rej(new Error("relay socket failed")), { once: true });
      ws.addEventListener("message", (ev) => this.onMessage(ev.data));
      ws.addEventListener("close", () => {
        this.ws = null;
        if (this._state !== "idle") {
          this.handlers.status?.({ state: "closed", reason: "relay_disconnected" });
          this.setState("closed");
        }
      });
    });
  }

  private onMessage(data: unknown): void {
    if (typeof data === "string") {
      let st: unknown;
      try {
        st = JSON.parse(data);
      } catch {
        return;
      }
      if (typeof st !== "object" || st === null) return;
      const s = st as Record<string, unknown>;
      if (s.type !== "status" || typeof s.state !== "string") return;
      const ev: StatusEvent = { state: s.state };
      if (typeof s.reason === "string") ev.reason = s.reason;
      if (typeof s.detail === "string") ev.detail = s.detail;
      if (typeof s.retryAfter === "number") ev.retryAfter = s.retryAfter;
      if (typeof s.sampleRate === "number") ev.sampleRate = s.sampleRate;
      if (typeof s.version === "string") ev.version = s.version;
      if (typeof s.rx === "string") ev.rx = s.rx;
      if (typeof s.name === "string") ev.name = s.name;
      this.handleStatus(ev);
      return;
    }
    if (data instanceof ArrayBuffer) {
      if (data.byteLength < 8 || data.byteLength > 1 << 17) return;
      const dv = new DataView(data);
      if (dv.getUint8(0) !== 1) return;
      const flags = dv.getUint8(1);
      const rssi = dv.getUint16(2, true) / 10 - 127;
      const pcm = data.slice(8);
      if (pcm.byteLength % 2 !== 0) return;
      this.node?.port.postMessage({ type: "pcm", buf: pcm }, [pcm]);
      this.handlers.rssi?.(rssi, flags);
    }
  }

  private handleStatus(ev: StatusEvent): void {
    switch (ev.state) {
      case "ready":
        return; // auth accepted; connect is sent separately
      case "connecting":
        this.setState("connecting");
        break;
      case "connected":
        if (ev.sampleRate) this.node?.port.postMessage({ type: "rate", rate: ev.sampleRate });
        this.setState("playing");
        break;
      case "closed":
        this.setState("closed");
        break;
    }
    this.handlers.status?.(ev);
  }

  /** Connect to a receiver. Switching receivers fades the old audio out. */
  async play(rx: string, freq: number, mode: string): Promise<void> {
    await this.ensureAudio();
    this.node?.port.postMessage({ type: "flush" });
    this.wanted = { rx, freq, mode };
    this.setState("connecting");
    const ws = await this.ensureSocket();
    ws.send(JSON.stringify({ type: "connect", rx, freq, mode }));
  }

  /** Retune without reconnecting. Audio keeps flowing; the receiver's own
   *  filter transient is the transition. */
  tune(freq: number, mode: string): void {
    if (!this.wanted) return;
    this.wanted.freq = freq;
    this.wanted.mode = mode;
    if (this.ws?.readyState === WebSocket.OPEN && this._state !== "idle") {
      this.ws.send(JSON.stringify({ type: "tune", freq, mode }));
    }
  }

  stop(): void {
    this.node?.port.postMessage({ type: "flush" });
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify({ type: "disconnect" }));
    this.wanted = null;
    this.setState("idle");
  }

  setVolume(v: number): void {
    this.volume = Math.max(0, Math.min(1, v));
    this.node?.port.postMessage({ type: "volume", value: this.volume });
  }

  get current(): { rx: string; freq: number; mode: string } | null {
    return this.wanted ? { ...this.wanted } : null;
  }
}

/** S-meter conversion: S9 = -73 dBm, 6 dB per S-unit below, dB over 9 above. */
export function sUnits(dBm: number): string {
  if (dBm >= -73) {
    const over = Math.round(dBm + 73);
    return over > 0 ? `S9+${over}` : "S9";
  }
  const s = Math.max(0, Math.round((dBm + 127) / 6));
  return `S${s}`;
}
