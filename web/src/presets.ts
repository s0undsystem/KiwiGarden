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

/**
 * A default that is likely to be audible from a receiver at this longitude
 * right now. Europe gets Channel 292 (24 h music on 6070). The Americas
 * get WWCR (24 h on 4840). Elsewhere, the 31 m band, where something is
 * almost always on.
 */
export function defaultFor(lon: number): { freq: number; mode: "am" } {
  if (lon >= -30 && lon <= 60) return { freq: 6070, mode: "am" };
  if (lon < -30) return { freq: 4840, mode: "am" };
  return { freq: 9400, mode: "am" };
}
