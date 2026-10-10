import { Vector3 } from "three";
import { latLonToVec3 } from "./geo";

/**
 * Sub-solar point for a given instant, using the low-precision solar
 * position algorithm (Meeus / NOAA). Accurate to well under a degree,
 * which is far finer than the terminator's visual softness.
 */
export function subsolarPoint(date: Date): { lat: number; lon: number } {
  const ms = date.getTime();
  const jd = ms / 86400000 + 2440587.5;
  const n = jd - 2451545.0; // days since J2000.0
  const rad = Math.PI / 180;

  const L = (280.46 + 0.9856474 * n) % 360; // mean longitude
  const g = (357.528 + 0.9856003 * n) % 360; // mean anomaly
  const lambda = L + 1.915 * Math.sin(g * rad) + 0.02 * Math.sin(2 * g * rad); // ecliptic longitude
  const epsilon = 23.439 - 0.0000004 * n; // obliquity

  const sinDecl = Math.sin(epsilon * rad) * Math.sin(lambda * rad);
  const decl = Math.asin(sinDecl) / rad;

  // Right ascension, then Greenwich hour angle via sidereal time.
  const ra = Math.atan2(Math.cos(epsilon * rad) * Math.sin(lambda * rad), Math.cos(lambda * rad)) / rad;
  const gmst = (18.697374558 + 24.06570982441908 * n) % 24; // hours
  let lon = ((ra / 15 - gmst) * 15) % 360;
  if (lon > 180) lon -= 360;
  if (lon < -180) lon += 360;
  return { lat: decl, lon };
}

/** Unit vector toward the sun in globe coordinates. */
export function sunDirection(date: Date, out = new Vector3()): Vector3 {
  const { lat, lon } = subsolarPoint(date);
  return latLonToVec3(lat, lon, 1, out);
}
