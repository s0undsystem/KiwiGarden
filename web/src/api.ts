import type { DirectoryResponse, Receiver } from "./types";

const TOKEN_HEADER = "X-Kiwi-Token";

/** Fetch the validated receiver list from the relay (same origin only). */
export async function fetchReceivers(token: string): Promise<DirectoryResponse> {
  const resp = await fetch("/api/receivers", {
    method: "GET",
    headers: { [TOKEN_HEADER]: token },
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  if (!resp.ok) throw new Error(`relay answered ${resp.status}`);
  const data: unknown = await resp.json();
  return validate(data);
}

// The relay already validated everything, but the browser re-checks shapes
// so a relay bug cannot turn into a rendering bug.
function validate(data: unknown): DirectoryResponse {
  if (!isRecord(data) || !Array.isArray(data.receivers)) throw new Error("bad directory response");
  const receivers: Receiver[] = [];
  for (const r of data.receivers) {
    if (!isRecord(r)) continue;
    const lat = num(r.lat);
    const lon = num(r.lon);
    if (typeof r.id !== "string" || !/^[0-9a-f]{16}$/.test(r.id)) continue;
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) continue;
    receivers.push({
      id: r.id,
      name: str(r.name, 120),
      loc: str(r.loc, 80),
      antenna: str(r.antenna, 120),
      version: str(r.version, 40),
      lat,
      lon,
      users: int(r.users),
      usersMax: int(r.usersMax),
      extApi: int(r.extApi, -1),
      snr: int(r.snr),
      offline: r.offline === true,
    });
  }
  return {
    fetchedAt: typeof data.fetchedAt === "string" ? data.fetchedAt : "",
    fromCache: data.fromCache === true,
    receivers,
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : NaN;
}
function int(v: unknown, def = 0): number {
  return typeof v === "number" && Number.isInteger(v) ? v : def;
}
function str(v: unknown, max: number): string {
  return typeof v === "string" ? Array.from(v).slice(0, max).join("") : "";
}
