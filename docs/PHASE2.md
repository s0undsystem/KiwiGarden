# Phase 2: Globe

Delivered: the front end in `web/`, built by Vite into `internal/ui/dist`
and embedded in the binary with `go:embed`.

## What was built

| File | Role |
| --- | --- |
| `web/src/globe.ts` | three.js scene: dark sphere with a day/night shader, atmosphere rim, coastline `LineSegments`, receiver `Points` with a glow shader, screen-space picking, fly-to |
| `web/src/coast.ts` | Loads `coast.bin` (Natural Earth 50m coastline, public domain, 489 KB, 60 416 points) and validates its header and lengths before use |
| `web/src/sun.ts` | Sub-solar point from UTC (NOAA low-precision algorithm); the terminator is recomputed every 30 s |
| `web/src/session.ts` | Token from the URL fragment into `sessionStorage`, fragment stripped |
| `web/src/api.ts` | Same-origin fetch of `/api/receivers`; re-validates every field's type and range in the browser |
| `web/src/main.ts` | Clock, counts, tooltip, detail panel; every write is `textContent` |
| `web/index.html`, `styles.css` | Static markup and styles, no inline script, system fonts |

Dependencies (pinned exactly in `web/package.json`):

| Package | Version | Why |
| --- | --- | --- |
| `three` | 0.186.1 | WebGL scene graph and OrbitControls. The only runtime dependency. 551 KB minified, bundled, no network use. |
| `vite` | 8.3.4 | Build only. Bundles TypeScript to one hashed JS file with no inline script. |
| `typescript` | 5.9.3 | Build only. `tsc --noEmit` type check with strict options. |
| `@types/three` | 0.186.0 | Build only. |

`globe.gl` was considered and rejected: it pulls in d3 and several more
packages and defaults to fetching textures from a CDN. Writing the globe
directly on three.js is ~400 lines and keeps the dependency list to one.

## Security controls shipped

- CSP on the HTML response (set by the relay): `default-src 'self'`,
  `script-src 'self'`, `connect-src 'self'`, `frame-ancestors 'none'`,
  `base-uri 'none'`, `object-src 'none'`, `require-trusted-types-for
  'script'`. Verified in headless Chrome with no violations.
- No inline scripts: Vite's module-preload polyfill is disabled; the built
  `index.html` contains only `<script type="module" src>` and `<link>`.
- No third-party requests: `internal/ui/ui_test.go` scans the built bundle
  for URLs. The only matches are the XHTML namespace string and a citation
  comment inside three.js. `assetsInlineLimit: 0` so nothing becomes a
  `data:` URI.
- Receiver text is rendered with `textContent` only. A grep test refuses
  `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`
  and `new Function` in `web/src` and in the built bundle.
- The browser never learns a receiver's URL, host or port. It gets an ID.
  Nothing in the UI links to, embeds or opens a receiver.
- Receivers that are full, offline, or whose owner set `ext_api=0` are drawn
  small and grey; the panel explains why they cannot be played.
- `coast.bin` is parsed defensively: magic, caps on segment and point
  counts, bounds checks on every read.

## Verified

- Live run against the real directory: 865 receivers rendered.
- Headless Chrome (`--headless=new`, SwiftShader): page loads, WebGL
  initialises, no console errors, no CSP reports. Screenshot in the Phase 2
  review message.
- `npm run build` runs `tsc --noEmit` under `strict`,
  `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.

## Not in this phase (by design)

- The Listen button is present but disabled. Phase 3 wires the AudioWorklet
  player to the relay's `/api/stream` WebSocket, which already works end to
  end (tested in `internal/server`).

## Adversarial review

- **Hostile receiver name in the panel**: names like `<img src=x
  onerror=...>` and `javascript:` strings arrive as plain text through
  `textContent`. The relay also strips controls and bidi marks before the
  browser sees them (so a name cannot reverse the panel's text direction).
- **Token in the address bar**: stripped by `history.replaceState` on first
  load; a refresh keeps working through `sessionStorage`; a second tab needs
  the printed URL again (deliberate).
- **Foreign page calling the API**: blocked by CSP only for this
  page; the relay's Origin and token checks are what stop it. Tested in
  Phase 1.
- **Oversized or malformed coastline file** (if the embedded asset were ever
  replaced): size cap, header magic and per-segment bounds checks throw
  instead of reading out of range.
- **WebGL unavailable**: three.js throws; the page still shows the clock
  and header. A friendlier message is a TODO.

Residual: three.js is a large dependency surface. It is pinned, bundled,
makes no network requests, and runs under a CSP that forbids inline script
and `eval`.
