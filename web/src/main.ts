import { fetchReceivers } from "./api";
import { Globe } from "./globe";
import { loadToken } from "./session";
import { isOpen, type Receiver } from "./types";

// Every DOM write in this file goes through textContent or attribute
// setters on elements that already exist in index.html. No markup is
// ever built from data.

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

function showPanel(r: Receiver): void {
  rxName.textContent = r.name;
  rxLoc.textContent = r.loc;
  rxAntenna.textContent = r.antenna || "—";
  rxSlots.textContent = `${r.users} / ${r.usersMax} in use`;
  rxSnr.textContent = r.snr > 0 ? `${r.snr} dB` : "—";
  rxVersion.textContent = r.version || "—";
  if (r.offline) rxNote.textContent = "Offline.";
  else if (r.extApi === 0) rxNote.textContent = "This receiver's owner does not allow apps like Kiwi Garden to connect.";
  else if (r.users >= r.usersMax) rxNote.textContent = "All listening slots are in use right now.";
  else rxNote.textContent = "";
  panel.hidden = false;
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
  const open = receivers.filter(isOpen).length;
  counts.textContent = `${receivers.length} receivers · ${open} open`;

  let selected = -1;
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
  });
  panelClose.addEventListener("click", () => {
    panel.hidden = true;
    selected = -1;
    globe.setSelected(-1);
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") panelClose.click();
  });
}

void main();
