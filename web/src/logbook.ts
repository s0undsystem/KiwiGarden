// The logbook: catches saved in localStorage. Entries are untrusted when
// read back (another page on this origin, or a hand-edited profile, could
// have written anything), so every field is re-validated and capped, and
// rendering is textContent only.

export interface Catch {
  ts: string; // ISO-8601 UTC
  freq: number; // kHz
  mode: string;
  rxId: string;
  rxName: string;
  rxLoc: string;
  note: string;
}

const KEY = "kg.logbook";
const MAX_ENTRIES = 2000;
const MODES = new Set(["am", "usb", "lsb", "cw"]);

function str(v: unknown, max: number): string {
  return typeof v === "string" ? Array.from(v).slice(0, max).join("") : "";
}

function validate(v: unknown): Catch | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const ts = str(o.ts, 40);
  if (!Number.isFinite(Date.parse(ts))) return null;
  const freq = typeof o.freq === "number" && Number.isFinite(o.freq) && o.freq >= 0 && o.freq <= 30000 ? Math.round(o.freq * 1000) / 1000 : NaN;
  if (Number.isNaN(freq)) return null;
  const mode = str(o.mode, 8).toLowerCase();
  if (!MODES.has(mode)) return null;
  const rxId = str(o.rxId, 16);
  if (!/^[0-9a-f]{16}$/.test(rxId)) return null;
  return {
    ts,
    freq,
    mode,
    rxId,
    rxName: str(o.rxName, 120),
    rxLoc: str(o.rxLoc, 80),
    note: str(o.note, 500),
  };
}

export function load(): Catch[] {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(KEY);
  } catch {
    return [];
  }
  if (!raw || raw.length > 4_000_000) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out: Catch[] = [];
  for (const v of parsed) {
    const c = validate(v);
    if (c) out.push(c);
    if (out.length >= MAX_ENTRIES) break;
  }
  return out;
}

export function save(entries: Catch[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, MAX_ENTRIES)));
  } catch {
    // quota or disabled storage: the in-memory list still works this session
  }
}

export function toJSON(entries: Catch[]): string {
  return JSON.stringify({ app: "Kiwi Garden", exported: new Date().toISOString(), catches: entries }, null, 2);
}

export function toCSV(entries: Catch[]): string {
  // Quote, and defuse spreadsheet formula injection: a cell starting with
  // = + - @ (or a tab/CR) gets a leading apostrophe.
  const esc = (s: string): string => {
    const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const rows = [["utc", "khz", "mode", "receiver", "location", "note"].join(",")];
  for (const c of entries) {
    rows.push([c.ts, c.freq.toFixed(3), c.mode, esc(c.rxName), esc(c.rxLoc), esc(c.note)].join(","));
  }
  return rows.join("\r\n") + "\r\n";
}

/** Trigger a download of text. A blob: URL on an <a download> is not a
 *  navigation and needs no CSP allowance. */
export function download(filename: string, mime: string, text: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
