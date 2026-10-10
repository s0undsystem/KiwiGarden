// Where to point a shortwave radio. Broadcast bands are the place to start;
// the station entries are long-running transmitters that are on the air
// most of the day, but schedules change every season (A/B), so treat them
// as suggestions and use seek.

export interface Preset {
  label: string;
  freq: number; // kHz
  mode: "am" | "usb" | "lsb" | "cw";
  group: "band" | "station" | "utility";
}

export const PRESETS: Preset[] = [
  { group: "band", label: "120 m tropical (2300–2495)", freq: 2300, mode: "am" },
  { group: "band", label: "90 m tropical (3200–3400)", freq: 3200, mode: "am" },
  { group: "band", label: "75 m (3900–4000)", freq: 3900, mode: "am" },
  { group: "band", label: "60 m (4750–5060)", freq: 4750, mode: "am" },
  { group: "band", label: "49 m (5900–6200)", freq: 5900, mode: "am" },
  { group: "band", label: "41 m (7200–7450)", freq: 7200, mode: "am" },
  { group: "band", label: "31 m (9400–9900)", freq: 9400, mode: "am" },
  { group: "band", label: "25 m (11600–12100)", freq: 11600, mode: "am" },
  { group: "band", label: "22 m (13570–13870)", freq: 13570, mode: "am" },
  { group: "band", label: "19 m (15100–15800)", freq: 15100, mode: "am" },
  { group: "band", label: "16 m (17480–17900)", freq: 17480, mode: "am" },
  { group: "band", label: "13 m (21450–21850)", freq: 21450, mode: "am" },

  { group: "station", label: "Channel 292, Germany, music 24h", freq: 6070, mode: "am" },
  { group: "station", label: "Channel 292, Germany (3955)", freq: 3955, mode: "am" },
  { group: "station", label: "WWCR, Nashville", freq: 4840, mode: "am" },
  { group: "station", label: "WTWW, Tennessee", freq: 5085, mode: "am" },
  { group: "station", label: "WRMI, Florida", freq: 9395, mode: "am" },
  { group: "station", label: "Radio Havana Cuba, English evenings", freq: 6000, mode: "am" },
  { group: "station", label: "Radio Romania International", freq: 7375, mode: "am" },
  { group: "station", label: "BBC World Service, Africa", freq: 12095, mode: "am" },
  { group: "station", label: "Radio Nacional da Amazônia", freq: 11780, mode: "am" },
  { group: "station", label: "Radio New Zealand Pacific", freq: 7390, mode: "am" },

  { group: "utility", label: "WWV / WWVH / BPM time signal, 10 MHz", freq: 10000, mode: "am" },
  { group: "utility", label: "WWV 5 MHz", freq: 5000, mode: "am" },
  { group: "utility", label: "WWV 15 MHz", freq: 15000, mode: "am" },
  { group: "utility", label: "Shannon VOLMET aviation weather", freq: 5505, mode: "usb" },
  { group: "utility", label: "New York VOLMET", freq: 6604, mode: "usb" },
  { group: "utility", label: "40 m amateur band, LSB", freq: 7150, mode: "lsb" },
  { group: "utility", label: "20 m amateur band, USB", freq: 14200, mode: "usb" },
  { group: "utility", label: "20 m amateur CW", freq: 14030, mode: "cw" },
  { group: "utility", label: "HFGCS military (USB)", freq: 11175, mode: "usb" },
];

/** Broadcast bands seek moves through, in kHz. Tropical bands included. */
export const BANDS: { lo: number; hi: number }[] = [
  { lo: 2300, hi: 2495 },
  { lo: 3200, hi: 3400 },
  { lo: 3900, hi: 4000 },
  { lo: 4750, hi: 5060 },
  { lo: 5900, hi: 6200 },
  { lo: 7200, hi: 7450 },
  { lo: 9400, hi: 9900 },
  { lo: 11600, hi: 12100 },
  { lo: 13570, hi: 13870 },
  { lo: 15100, hi: 15800 },
  { lo: 17480, hi: 17900 },
  { lo: 21450, hi: 21850 },
];

/**
 * Where to start listening from a receiver at (lat, lon) right now.
 *
 * Shortwave propagation is about whether the sun is up at the receiver: in
 * daylight the D layer absorbs everything below ~7 MHz and the high bands
 * (19 m, 16 m) carry the long paths; at night the low bands (49 m, 41 m)
 * open and the high bands fade. So: daytime starts in the 19 m band;
 * night starts in the 49 m band, with a station that is known to be on
 * air around the clock where there is one (Channel 292 for Europe, Radio
 * Havana Cuba's evening English for the Americas).
 */
export function defaultFor(lat: number, lon: number, now = new Date()): { freq: number; mode: "am" } {
  if (sunElevation(lat, lon, now) > 0) return { freq: 15100, mode: "am" };
  if (lon >= -30 && lon <= 60) return { freq: 6070, mode: "am" };
  if (lon < -30) return { freq: 6000, mode: "am" };
  return { freq: 5900, mode: "am" };
}

/** Solar elevation in degrees at a point, from the same algorithm as the terminator. */
export function sunElevation(lat: number, lon: number, now: Date): number {
  const rad = Math.PI / 180;
  const n = now.getTime() / 86400000 + 2440587.5 - 2451545.0;
  const L = (280.46 + 0.9856474 * n) % 360;
  const g = (357.528 + 0.9856003 * n) % 360;
  const lambda = L + 1.915 * Math.sin(g * rad) + 0.02 * Math.sin(2 * g * rad);
  const eps = 23.439 - 0.0000004 * n;
  const decl = Math.asin(Math.sin(eps * rad) * Math.sin(lambda * rad));
  const ra = Math.atan2(Math.cos(eps * rad) * Math.sin(lambda * rad), Math.cos(lambda * rad));
  const gmst = ((18.697374558 + 24.06570982441908 * n) % 24) * 15 * rad;
  const ha = gmst + lon * rad - ra; // hour angle
  const sinEl = Math.sin(lat * rad) * Math.sin(decl) + Math.cos(lat * rad) * Math.cos(decl) * Math.cos(ha);
  return Math.asin(Math.max(-1, Math.min(1, sinEl))) / rad;
}
