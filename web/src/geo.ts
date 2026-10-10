import { Vector3 } from "three";

/**
 * Globe coordinate convention: Y is north, the prime meridian faces +Z,
 * east is -X... chosen so that OrbitControls' default view (camera on +Z)
 * looks at lon 0, and longitude increases to the right.
 */
export function latLonToVec3(lat: number, lon: number, r: number, out = new Vector3()): Vector3 {
  const phi = (lat * Math.PI) / 180;
  const theta = (lon * Math.PI) / 180;
  const c = Math.cos(phi);
  return out.set(r * c * Math.sin(theta), r * Math.sin(phi), r * c * Math.cos(theta));
}
