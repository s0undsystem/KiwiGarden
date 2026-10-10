import { fetchReceivers } from "./api";
import { Globe } from "./globe";
import * as logbook from "./logbook";
import { Player, sUnits, type StatusEvent } from "./player";
import { BANDS, PRESETS, defaultFor } from "./presets";
import { loadToken } from "./session";
import { isOpen, type Receiver } from "./types";

// Every DOM write in this file goes through textContent or attribute
// setters on elements that already exist in index.html (or are cloned from
// a <template> in it). No markup is ever built from data.

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing #${id}`);
  return e as T;
}

const canvas = el<HTMLCanvasElement>("globe");
const overlay = el<HTMLDivElement>("overlay");
const overlayMsg = el<HTMLParagraphElement>("overlay-msg");
const counts = el<HTMLSpanElement>("counts");
const clock = el<HTMLTimeElement>("clock");
const dirAge = el<HTMLSpanElement>("dir-age");
const tooltip = el<HTMLDivElement>("tooltip");
const ttName = tooltip.querySelector<HTMLDivElement>(".tt-name")!;
const ttLoc = tooltip.querySelector<HTMLDivElement>(".tt-loc")!;
const panel = el<HTMLElement>("panel");
const panelClose = el<HTMLButtonElement>("panel-close");
const rxName = el<HTMLHeadingElement>("rx-name");
const rxLoc = el<HTMLParagraphElement>("rx-loc");
const rxAntenna = el<HTMLElement>("rx-antenna");
const rxSlots = el<HTMLElement>("rx-slots");
const rxSnr = el<HTMLElement>("rx-snr");
const rxVersion = el<HTMLElement>("rx-version");
const rxNote = el<HTMLParagraphElement>("rx-note");
const listenBtn = el<HTMLButtonElement>("listen");

const playerEl = el<HTMLElement>("player");
const pName = el<HTMLSpanElement>("p-name");
const pLoc = el<HTMLSpanElement>("p-loc");
const pStatus = el<HTMLSpanElement>("p-status");
const pFreq = el<HTMLInputElement>("p-freq");
const pVol = el<HTMLInputElement>("p-vol");
const pNote = el<HTMLInputElement>("p-note");
const pLog = el<HTMLButtonElement>("p-log");
const pStop = el<HTMLButtonElement>("p-stop");
const smeterBar = el<HTMLDivElement>("smeter-bar");
const smeterText = el<HTMLSpanElement>("smeter-text");
const modeButtons = Array.from(playerEl.querySelectorAll<HTMLButtonElement>("button[data-mode]"));
const stepButtons = Array.from(playerEl.querySelectorAll<HTMLButtonElement>("button[data-step]"));
const seekButtons = Array.from(playerEl.querySelectorAll<HTMLButtonElement>("button[data-seek]"));
const pPreset = el<HTMLSelectElement>("p-preset");

const lbToggle = el<HTMLButtonElement>("logbook-toggle");
const lbPanel = el<HTMLElement>("logbook");
const lbClose = el<HTMLButtonElement>("lb-close");
const lbList = el<HTMLUListElement>("lb-list");
const lbEmpty = el<HTMLParagraphElement>("lb-empty");
const lbTemplate = el<HTMLTemplateElement>("lb-entry");
const lbExportJSON = el<HTMLButtonElement>("lb-export-json");
const lbExportCSV = el<HTMLButtonElement>("lb-export-csv");

// Seek: step through the band and stop on the first channel whose
// S-meter sits well above the noise floor the receiver has been reporting.
const SEEK_STEP = 5; // kHz, broadcast channel spacing
const SEEK_DWELL_MS = 650; // enough for the AGC and two or three frames
const SEEK_MARGIN_DB = 14;

function showOverlay(msg: string): void {
  overlayMsg.textContent = msg;
  overlay.hidden = false;
}

function startClock(): void {
  const pad = (n: number): string => String(n).padStart(2, "0");
  const tick = (): void => {
    const d = new Date();
    clock.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
    clock.dateTime = d.toISOString();
  };
  tick();
  setInterval(tick, 1000);
}

function describeAge(iso: string, fromCache: boolean): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
  const age = mins < 60 ? `${mins} min` : mins < 48 * 60 ? `${Math.round(mins / 60)} h` : `${Math.round(mins / 1440)} d`;
  return `list ${age} old${fromCache ? " (cached)" : ""}`;
}

function reasonText(ev: StatusEvent): string {
  const r = ev.reason ?? "";
  switch (r) {
    case "closed_by_user":
      return "stopped";
    case "receiver_full":
      return "receiver is full";
    case "receiver_disallows_apps":
      return "receiver does not allow apps";
    case "timeout":
      return ev.detail?.includes("after handshake") ? "receiver did not answer (probably full)" : "receiver timed out";
    case "backoff":
      return `recently failed, try again in ${Math.ceil(ev.retryAfter ?? 0)} s`;
    case "already_connected":
      return "already connected to this receiver";
    case "session_limit":
      return "too many sessions";
    case "redirect_refused":
      return "receiver tried to redirect us (refused)";
    case "receiver_down":
      return "receiver is down";
    case "receiver_closed":
      return "receiver closed the connection";
    case "unexpected_sample_rate":
      return "receiver sent an unexpected sample rate";
    case "protocol_error":
      return "receiver sent malformed data";
    case "rate_limited":
      return "receiver was flooding (cut off)";
    case "duration_limit":
      return "90 minute session limit reached";
    case "bytes_limit":
      return "session data limit reached";
    case "network_error":
      return "could not reach the receiver";
    case "receiver_refused":
      return ev.detail ? `refused (${ev.detail})` : "refused";
    case "relay_disconnected":
      return "lost the relay; is kiwi-garden still running?";
    case "unknown_receiver":
      return "receiver is no longer in the list";
    default:
      return r || "closed";
  }
}

async function main(): Promise<void> {
  startClock();

  const token = loadToken();
  if (!token) {
    showOverlay("Open the exact link printed in the terminal where kiwi-garden is running. It carries a one-time session key.");
    return;
  }

  const globe = new Globe(canvas);
  globe.start();

  let receivers: Receiver[] = [];
  try {
    const dir = await fetchReceivers(token);
    receivers = dir.receivers;
    dirAge.textContent = describeAge(dir.fetchedAt, dir.fromCache);
  } catch (err) {
    showOverlay(`Could not load the receiver list from the relay (${err instanceof Error ? err.message : "error"}). Is kiwi-garden still running?`);
    return;
  }
  globe.setReceivers(receivers);
  const byId = new Map<string, number>();
  receivers.forEach((r, i) => byId.set(r.id, i));
  const open = receivers.filter(isOpen).length;
  counts.textContent = `${receivers.length} receivers · ${open} open`;

  // --- globe interaction ------------------------------------------------------
  let selected = -1;
  function showPanel(r: Receiver): void {
    rxName.textContent = r.name;
    rxLoc.textContent = r.loc;
    rxAntenna.textContent = r.antenna || "—";
    rxSlots.textContent = `${r.users} / ${r.usersMax} in use`;
    rxSnr.textContent = r.snr > 0 ? `${r.snr} dB` : "—";
    rxVersion.textContent = r.version || "—";
    if (r.offline) rxNote.textContent = "Offline.";
    else if (r.extApi === 0) rxNote.textContent = "This receiver's owner does not allow apps like Kiwi Garden to connect.";
    else if (r.users >= r.usersMax) rxNote.textContent = "All listening slots were in use when the list was fetched. You can still try.";
    else rxNote.textContent = "";
    listenBtn.disabled = r.offline || r.extApi === 0;
    panel.hidden = false;
  }

  canvas.addEventListener("pointermove", (ev) => {
    const hit = globe.pick(ev.clientX, ev.clientY);
    if (hit) {
      globe.setHover(hit.index);
      ttName.textContent = hit.receiver.name;
      ttLoc.textContent = hit.receiver.loc;
      tooltip.style.left = `${ev.clientX}px`;
      tooltip.style.top = `${ev.clientY}px`;
      tooltip.hidden = false;
      canvas.classList.add("hover");
    } else {
      globe.setHover(-1);
      tooltip.hidden = true;
      canvas.classList.remove("hover");
    }
  });
  canvas.addEventListener("pointerleave", () => {
    globe.setHover(-1);
    tooltip.hidden = true;
  });

  let downAt: { x: number; y: number } | null = null;
  canvas.addEventListener("pointerdown", (ev) => {
    downAt = { x: ev.clientX, y: ev.clientY };
  });
  canvas.addEventListener("pointerup", (ev) => {
    if (!downAt) return;
    const moved = Math.hypot(ev.clientX - downAt.x, ev.clientY - downAt.y);
    downAt = null;
    if (moved > 5) return; // it was a drag
    const hit = globe.pick(ev.clientX, ev.clientY);
    if (!hit) return;
    selected = hit.index;
    globe.setSelected(selected);
    globe.focus(selected);
    showPanel(hit.receiver);
    // Click a node: play. Same frequency and mode as whatever is current.
    if (!listenBtn.disabled) void play(hit.receiver);
  });
  panelClose.addEventListener("click", () => {
    panel.hidden = true;
    selected = -1;
    globe.setSelected(-1);
  });
  listenBtn.addEventListener("click", () => {
    const r = receivers[selected];
    if (r) void play(r);
  });

  // --- player -------------------------------------------------------------------
  const player = new Player(token);
  let freq = 6070;
  let mode = "am";
  let tunedByUser = false;
  let playingRx: Receiver | null = null;

  // Presets menu.
  for (const group of ["band", "station", "utility"] as const) {
    const og = document.createElement("optgroup");
    og.label = { band: "Broadcast bands", station: "Stations (schedules change)", utility: "Time, weather, amateur" }[group];
    PRESETS.filter((p) => p.group === group).forEach((p) => {
      const o = document.createElement("option");
      o.value = String(PRESETS.indexOf(p));
      o.textContent = `${p.label} · ${p.freq} ${p.mode.toUpperCase()}`;
      og.appendChild(o);
    });
    pPreset.appendChild(og);
  }

  function setStatus(text: string, cls = ""): void {
    pStatus.textContent = text;
    pStatus.className = cls;
  }
  function renderTune(): void {
    // Integers as-is; otherwise up to 3 decimals with trailing zeros trimmed.
    pFreq.value = Number.isInteger(freq) ? String(freq) : freq.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
    for (const b of modeButtons) b.classList.toggle("on", b.dataset.mode === mode);
  }
  function applyTune(f: number, m: string, fromSeek = false): void {
    if (!Number.isFinite(f)) return;
    if (!fromSeek) {
      stopSeek();
      tunedByUser = true;
    }
    freq = Math.min(30000, Math.max(0, Math.round(f * 1000) / 1000));
    mode = m;
    renderTune();
    player.tune(freq, mode);
  }

  // --- seek -------------------------------------------------------------------
  let seekTimer: number | null = null;
  let seekDir = 0;
  let noiseFloor = -110;
  const recentRssi: number[] = [];
  /**
   * Next 5 kHz channel in the seek direction, staying inside the broadcast
   * bands: leaving a band jumps to the next one, and the ends wrap. A
   * frequency outside every band (user typed it) first snaps to the nearest
   * band edge in the direction of travel.
   */
  function nextChannel(f: number, dir: number): number {
    const cand = Math.round(f / SEEK_STEP) * SEEK_STEP + dir * SEEK_STEP;
    const inBand = BANDS.find((b) => cand >= b.lo && cand <= b.hi);
    if (inBand) return cand;
    if (dir > 0) {
      const nextBand = BANDS.find((b) => b.lo > cand) ?? BANDS[0]!;
      return nextBand.lo;
    }
    const prevBand = [...BANDS].reverse().find((b) => b.hi < cand) ?? BANDS[BANDS.length - 1]!;
    return prevBand.hi;
  }
  function stopSeek(): void {
    if (seekTimer !== null) clearTimeout(seekTimer);
    seekTimer = null;
    seekDir = 0;
    for (const b of seekButtons) b.classList.remove("on");
  }
  function seek(dir: number): void {
    if (seekDir === dir) {
      stopSeek();
      return;
    }
    stopSeek();
    seekDir = dir;
    for (const b of seekButtons) b.classList.toggle("on", Number(b.dataset.seek) === dir);
    const start = freq;
    const step = (): void => {
      if (seekDir === 0) return;
      // Decide on the channel just dwelt on.
      if (recentRssi.length >= 2) {
        const avg = recentRssi.reduce((a, b) => a + b, 0) / recentRssi.length;
        noiseFloor = Math.min(noiseFloor * 0.9 + avg * 0.1, avg); // tracks down fast, up slowly
        if (avg > noiseFloor + SEEK_MARGIN_DB && Math.abs(freq - start) >= SEEK_STEP) {
          stopSeek();
          return;
        }
      }
      recentRssi.length = 0;
      const next = nextChannel(freq, seekDir);
      applyTune(next, mode, true);
      seekTimer = window.setTimeout(step, SEEK_DWELL_MS);
    };
    recentRssi.length = 0;
    seekTimer = window.setTimeout(step, SEEK_DWELL_MS);
  }
  for (const b of seekButtons) b.addEventListener("click", () => seek(Number(b.dataset.seek)));
  pPreset.addEventListener("change", () => {
    const p = PRESETS[Number(pPreset.value)];
    pPreset.value = "";
    if (p) applyTune(p.freq, p.mode);
  });
  let autoSeek = false;
  async function play(r: Receiver): Promise<void> {
    stopSeek();
    if (!tunedByUser) {
      // The user has not chosen a frequency by hand, so every click is a
      // fresh hunt: start in the band the sun says is open at this
      // receiver and, once audio is flowing, seek until something is on.
      const d = defaultFor(r.lat, r.lon);
      freq = d.freq;
      mode = d.mode;
      autoSeek = true;
    }
    playingRx = r;
    pName.textContent = r.name;
    pLoc.textContent = r.loc;
    playerEl.hidden = false;
    renderTune();
    setStatus("connecting…");
    smeterBar.style.width = "0";
    smeterText.textContent = "—";
    try {
      await player.play(r.id, freq, mode);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : "failed", "err");
    }
  }

  let liveLabel = "";
  player.on("stats", (s) => {
    if (player.state !== "playing") return;
    const buf = `${s.buffered.toFixed(2)} s buffered`;
    const under = s.underruns ? ` · ${s.underruns} underruns` : "";
    const seeking = seekDir !== 0 ? " · seeking" : "";
    setStatus(`${liveLabel} · ${buf}${under}${seeking}`, "live");
  });
  player.on("status", (ev) => {
    switch (ev.state) {
      case "connecting":
        setStatus("connecting…");
        break;
      case "connected":
        liveLabel = `live · ${ev.sampleRate ? Math.round(ev.sampleRate) : ""} Hz${ev.version ? ` · v${ev.version}` : ""}`;
        setStatus(liveLabel, "live");
        if (autoSeek) {
          autoSeek = false;
          // Give the AGC a moment on the default channel, then hunt.
          window.setTimeout(() => {
            if (player.state === "playing" && !tunedByUser) seek(1);
          }, 900);
        }
        break;
      case "closed":
        stopSeek();
        setStatus(reasonText(ev), ev.reason === "closed_by_user" ? "" : "err");
        smeterBar.style.width = "0";
        break;
      case "error":
        stopSeek();
        setStatus(ev.detail ?? "error", "err");
        break;
    }
  });

  // S-meter: smooth the per-frame reading a little; the bar spans -127 to -43 dBm.
  let rssiSmooth = -127;
  player.on("rssi", (dBm, flags) => {
    rssiSmooth += (dBm - rssiSmooth) * 0.35;
    if (seekDir !== 0 && !(flags & 0x04)) recentRssi.push(dBm); // skip the retune frame itself
    const pct = Math.max(0, Math.min(100, ((rssiSmooth + 127) / 84) * 100));
    smeterBar.style.width = `${pct.toFixed(1)}%`;
    smeterText.textContent = `${sUnits(rssiSmooth)} · ${rssiSmooth.toFixed(0)} dBm${flags & 0x02 ? " · ADC OV" : ""}`;
  });

  for (const b of stepButtons) {
    b.addEventListener("click", () => applyTune(freq + Number(b.dataset.step), mode));
  }
  for (const b of modeButtons) {
    b.addEventListener("click", () => applyTune(freq, b.dataset.mode ?? mode));
  }
  pFreq.addEventListener("change", () => applyTune(Number(pFreq.value), mode));
  pFreq.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      applyTune(Number(pFreq.value), mode);
      pFreq.blur();
    }
    if (ev.key === "ArrowUp" || ev.key === "ArrowDown") {
      ev.preventDefault();
      const step = ev.shiftKey ? 5 : ev.altKey ? 0.1 : 1;
      applyTune(freq + (ev.key === "ArrowUp" ? step : -step), mode);
    }
  });
  pVol.addEventListener("input", () => player.setVolume(Number(pVol.value) / 100));
  pStop.addEventListener("click", () => {
    stopSeek();
    tunedByUser = false; // Stop means start over: the next click hunts again
    player.stop();
    setStatus("stopped");
    smeterBar.style.width = "0";
  });

  // --- logbook --------------------------------------------------------------------
  let catches = logbook.load();
  function renderLogbook(): void {
    lbList.replaceChildren();
    lbEmpty.hidden = catches.length > 0;
    lbToggle.textContent = catches.length ? `Logbook (${catches.length})` : "Logbook";
    catches.forEach((c, i) => {
      const frag = lbTemplate.content.cloneNode(true) as DocumentFragment;
      const li = frag.querySelector<HTMLLIElement>(".lb-entry")!;
      li.querySelector<HTMLSpanElement>(".lb-freq")!.textContent = `${c.freq} kHz`;
      li.querySelector<HTMLSpanElement>(".lb-mode")!.textContent = c.mode;
      const d = new Date(c.ts);
      li.querySelector<HTMLSpanElement>(".lb-time")!.textContent = d.toISOString().slice(0, 16).replace("T", " ") + "Z";
      li.querySelector<HTMLSpanElement>(".lb-rx")!.textContent = c.rxLoc ? `${c.rxName} · ${c.rxLoc}` : c.rxName;
      li.querySelector<HTMLSpanElement>(".lb-note")!.textContent = c.note;
      li.querySelector<HTMLButtonElement>(".lb-retune")!.addEventListener("click", () => {
        const idx = byId.get(c.rxId);
        const r = idx !== undefined ? receivers[idx] : undefined;
        stopSeek();
        freq = c.freq;
        mode = c.mode;
        tunedByUser = true;
        renderTune();
        if (r) {
          selected = idx!;
          globe.setSelected(selected);
          globe.focus(selected);
          showPanel(r);
          void play(r);
        } else {
          setStatus("that receiver is no longer in the list", "err");
          playerEl.hidden = false;
        }
      });
      li.querySelector<HTMLButtonElement>(".lb-delete")!.addEventListener("click", () => {
        catches.splice(i, 1);
        logbook.save(catches);
        renderLogbook();
      });
      lbList.appendChild(frag);
    });
  }
  renderLogbook();
  pLog.addEventListener("click", () => {
    if (!playingRx) return;
    catches.unshift({
      ts: new Date().toISOString(),
      freq,
      mode,
      rxId: playingRx.id,
      rxName: playingRx.name,
      rxLoc: playingRx.loc,
      note: pNote.value.trim().slice(0, 500),
    });
    pNote.value = "";
    logbook.save(catches);
    renderLogbook();
    lbPanel.hidden = false;
  });
  lbToggle.addEventListener("click", () => (lbPanel.hidden = !lbPanel.hidden));
  lbClose.addEventListener("click", () => (lbPanel.hidden = true));
  lbExportJSON.addEventListener("click", () => logbook.download("kiwi-garden-logbook.json", "application/json", logbook.toJSON(catches)));
  lbExportCSV.addEventListener("click", () => logbook.download("kiwi-garden-logbook.csv", "text/csv", logbook.toCSV(catches)));

  // Page-level control events, for automation and tests. Same-origin
  // scripts can already do anything the page can; this just makes it tidy.
  //   document.dispatchEvent(new CustomEvent("kg:play", { detail: { rx, freq, mode } }))
  //   document.dispatchEvent(new CustomEvent("kg:stop"))
  document.addEventListener("kg:play", (ev) => {
    const d = (ev as CustomEvent<unknown>).detail;
    if (typeof d !== "object" || d === null) return;
    const o = d as Record<string, unknown>;
    const idx = typeof o.rx === "string" ? byId.get(o.rx) : undefined;
    const r = idx !== undefined ? receivers[idx] : undefined;
    if (!r) return;
    if (typeof o.freq === "number" && Number.isFinite(o.freq)) {
      freq = Math.min(30000, Math.max(0, o.freq));
      tunedByUser = true;
    }
    if (typeof o.mode === "string" && ["am", "usb", "lsb", "cw"].includes(o.mode)) mode = o.mode;
    selected = idx!;
    globe.setSelected(selected);
    globe.focus(selected);
    showPanel(r);
    void play(r);
  });
  document.addEventListener("kg:stop", () => pStop.click());

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      panel.hidden = true;
      lbPanel.hidden = true;
      selected = -1;
      globe.setSelected(-1);
    }
  });
}

void main();
