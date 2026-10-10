// Session token handling. See THREAT_MODEL.md 4.3.
//
// The relay prints http://127.0.0.1:<port>/#<token>. The fragment never
// reaches the server. We move it into sessionStorage (scoped to this
// origin, including the port, so other local servers cannot read it) and
// strip it from the address bar.

const KEY = "kg.token";
const TOKEN_RE = /^[0-9a-f]{64}$/;

export function loadToken(): string | null {
  const hash = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  if (TOKEN_RE.test(hash)) {
    try {
      sessionStorage.setItem(KEY, hash);
    } catch {
      // Storage unavailable (private mode quirks): keep it in memory only.
    }
    history.replaceState(null, "", location.pathname);
    return hash;
  }
  try {
    const stored = sessionStorage.getItem(KEY);
    if (stored && TOKEN_RE.test(stored)) return stored;
  } catch {
    // ignore
  }
  return null;
}
