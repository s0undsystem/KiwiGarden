import { BufferGeometry, Float32BufferAttribute, LineBasicMaterial, LineSegments } from "three";
import { latLonToVec3 } from "./geo";

/**
 * Loads the bundled Natural Earth coastlines (public domain) from
 * coast.bin: "CST1", u32 segment count, then per segment u32 point count
 * and float32 lon/lat pairs. Little-endian.
 */
export async function loadCoastlines(radius: number): Promise<LineSegments> {
  const resp = await fetch("/coast.bin", { credentials: "omit", cache: "force-cache", redirect: "error" });
  if (!resp.ok) throw new Error("coastline data missing");
  const buf = await resp.arrayBuffer();
  if (buf.byteLength > 8 << 20) throw new Error("coastline data too large");
  const dv = new DataView(buf);
  if (buf.byteLength < 8 || String.fromCharCode(dv.getUint8(0), dv.getUint8(1), dv.getUint8(2), dv.getUint8(3)) !== "CST1") {
    throw new Error("bad coastline header");
  }
  const nseg = dv.getUint32(4, true);
  if (nseg > 100000) throw new Error("bad coastline segment count");

  const positions: number[] = [];
  let off = 8;
  const a = latLonToVec3(0, 0, radius);
  const b = latLonToVec3(0, 0, radius);
  for (let s = 0; s < nseg; s++) {
    if (off + 4 > buf.byteLength) throw new Error("truncated coastline data");
    const n = dv.getUint32(off, true);
    off += 4;
    if (n > 1_000_000 || off + n * 8 > buf.byteLength) throw new Error("truncated coastline data");
    let prevLon = dv.getFloat32(off, true);
    let prevLat = dv.getFloat32(off + 4, true);
    off += 8;
    for (let i = 1; i < n; i++) {
      const lon = dv.getFloat32(off, true);
      const lat = dv.getFloat32(off + 4, true);
      off += 8;
      // Skip segments that wrap around the antimeridian.
      if (Math.abs(lon - prevLon) < 180) {
        latLonToVec3(prevLat, prevLon, radius, a);
        latLonToVec3(lat, lon, radius, b);
        positions.push(a.x, a.y, a.z, b.x, b.y, b.z);
      }
      prevLon = lon;
      prevLat = lat;
    }
  }
  const geom = new BufferGeometry();
  geom.setAttribute("position", new Float32BufferAttribute(positions, 3));
  const mat = new LineBasicMaterial({ color: 0x3f5f8f, transparent: true, opacity: 0.75 });
  return new LineSegments(geom, mat);
}
