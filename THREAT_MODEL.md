# Kiwi Garden Threat Model

Living document. Every phase ends with an adversarial review against this
file and updates it. Last review: Phase 2 (see section 9).

## 1. System

```
 browser (same machine) ──http/ws──> relay (Go, 127.0.0.1 only) ──ws──> KiwiSDR receivers (internet)
                                          │
                                          └──https──> directory mirror (cdn.aethersdr.com)
```

The browser never contacts anything but the relay. The relay dials only hosts
that appear in the validated directory, and only after the resolved IP passes
a policy check at connect time.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| The user's machine and LAN | The relay is a local process that dials out on request. It must not become a proxy into the LAN or a port scanner. |
| The user's browser session | A page at `127.0.0.1:<port>` talks to the relay. Other local pages and remote sites must not be able to drive it. |
| Receiver operators' goodwill | Public KiwiSDRs are volunteer hardware. Abuse gets clients blocked and gives the project a bad name. |
| Availability of the app | A hostile receiver must not hang, crash, or exhaust the relay. |
| The listening user's privacy | No tracking, no third-party requests from the browser, no leaking which receiver is being listened to beyond the receiver itself. |

## 3. Trust boundaries and adversaries

| Adversary | Position | Capabilities assumed |
| --- | --- | --- |
| **Hostile receiver** | Any host the relay dials | Full control of the TCP stream after connect: arbitrary WebSocket frames, lengths, timing, text, redirects, slowloris, floods. Also controls its own directory entry text. |
| **Hostile directory** | The mirror, or anyone who can MITM it, or a receiver that lies in its registration | Arbitrary JSON: hosts that resolve to private IPs, absurd sizes, hostile strings, duplicate IDs, schema drift. |
| **Hostile web page** | Any site the user visits in the same browser, including other local dev servers on other ports of 127.0.0.1 | Can issue fetch/WebSocket requests to `http://127.0.0.1:<port>` with forged Host (via DNS rebinding) and its own Origin. Cannot read same-origin responses without CORS. Cannot set headers on a WebSocket. |
| **Other local processes** | Same user account | Can read/write the on-disk cache, connect to the relay port, read stderr if they are the parent. (A process running as the same user can do anything the user can; we only avoid making things worse.) |
| **Network attacker** | On path between relay and receiver | Receivers are 99 percent plain HTTP. Audio and tuning are visible and tamperable in transit. Accepted: the data is public radio. |

Out of scope: a compromised browser, a compromised OS, malware with the
user's privileges, the receiver operator reading what frequency the user
tunes (inherent to the protocol).

## 4. Controls

### 4.1 Directory (trust root with no trust)

| Control | Where |
| --- | --- |
| Single pinned source: `https://cdn.aethersdr.com/kiwi.json`. Host is a compile-time constant. | `internal/directory` |
| TLS 1.2 minimum, system roots, hostname verified. Plain `http` is impossible by construction. | `internal/directory` |
| The directory fetch goes through the same policy dialer as receivers: resolved IP must be public, port must be 443. | `internal/directory`, `internal/netpolicy` |
| No redirects (`CheckRedirect` always errors). | `internal/directory` |
| Response capped at 4 MiB with `io.LimitReader` (today's file is 0.8 MiB). Exceeding the cap is an error, not a truncation. | `internal/directory` |
| `schema` must be `1`. Receiver count capped at 5000. | `internal/directory` |
| Every field type-checked by `encoding/json` into a struct; unknown fields ignored (the mirror adds fields), malformed known fields reject the **entry**, not the whole file, except where noted. | `internal/directory` |
| `url`: scheme `http` or `https`, host is a DNS name or IP literal, no userinfo, no path, no query, no fragment; port 80, 443 or 1024..65535. `*.proxy.kiwisdr.com` with no port is rewritten to 8073 (documented constant, see PHASE0 2.3). | `internal/directory` |
| `gps`: two finite numbers, lat in [-90,90], lon in [-180,180]; `[0,0]` dropped. | `internal/directory` |
| `name`, `loc`, `antenna`, `sw_version`: sanitised (4.5) and capped at 120 / 80 / 120 / 40 runes. | `internal/directory` |
| Integer fields clamped to sane ranges; `ext_api` missing becomes -1 (unknown), never 0 or "allowed". | `internal/directory` |
| Receiver identity for the browser is `sha256(url)[:16]`; the browser never supplies a host, only an ID that must exist in the current validated set. | `internal/directory`, `internal/server` |
| Refresh daily in the background; cache to disk under the user cache dir with mode 0600, written atomically. **The cache is re-validated on load** as if it were a fresh network response, because another local process could edit it. | `internal/directory` |
| Never fetched per page load. The browser gets the relay's in-memory copy. | `internal/server` |

Residual risk: the mirror operator (AetherSDR) or a compromise of Cloudflare
could feed us any host list. Everything in 4.2 holds regardless, so the worst
case is "we connect to a public IP the attacker chose, on an allowed port, and
treat it as a hostile receiver," which is the case we already defend against.

### 4.2 Dialer (the LAN firewall)

| Control | Where |
| --- | --- |
| Hostname must be in the current validated directory set (checked before resolution). | `internal/relay` |
| `net.Dialer.Control` hook inspects the **resolved** IP of every connection attempt, so a hostname that resolves (or re-resolves) to a private address is refused at connect time. | `internal/netpolicy` |
| Rejected: unspecified, loopback, RFC 1918 private, link-local (169.254/16, fe80::/10), CGNAT 100.64/10, multicast, broadcast, 0.0.0.0/8, documentation and benchmarking ranges, 6to4/Teredo/NAT64 prefixes, IPv4-mapped and NAT64 addresses are unwrapped and the inner IPv4 is checked, ULA fc00::/7, IPv6 site-local, Discard-Only, ORCHID. | `internal/netpolicy` |
| Ports: 80, 443, 1024..65535 only. | `internal/netpolicy` |
| No redirects: a non-101 WebSocket response is terminal. The `Location` header is logged sanitised and never followed, with one pattern-matched exception: a receiver listed at `<label>.proxy.kiwisdr.com` whose 307 points at exactly `<label>.proxy2.kiwisdr.com` (http, port absent or 8073, no userinfo) is retried at that host, once, through the same policy dialer. Same operator, same label, fixed port; `ProxyAlternate` has a table test of the refusals. | `internal/kiwiws`, `internal/relay` |
| TLS used whenever the directory URL is `https`; TLS 1.2 minimum, verified. | `internal/kiwiws` |
| Dial timeout 10 s, handshake timeout 10 s. | `internal/kiwiws` |

Test-only switch: `netpolicy.Policy.AllowLoopback` exists so the mock
receiver can run on 127.0.0.1 in tests. `cmd/kiwi-garden` never sets it; a
test asserts the default is false.

### 4.3 Local HTTP server

| Control | Where |
| --- | --- |
| Binds `127.0.0.1` only (never `0.0.0.0`, never `localhost` which may resolve to `::1` and other things). | `cmd/kiwi-garden` |
| `Host` header must equal the bound `127.0.0.1:<port>` exactly on every route. Defeats DNS rebinding (`evil.com` → 127.0.0.1 arrives with `Host: evil.com`). | `internal/server` |
| `Origin`, when present, must equal `http://127.0.0.1:<port>` exactly. Required (not optional) on the WebSocket upgrade; browsers always send it there. | `internal/server` |
| `Sec-Fetch-Site`, when present, must be `same-origin` for API routes and WebSocket; `none` (user typed the URL) is allowed only for the page and static assets. | `internal/server` |
| Session token: 32 bytes from `crypto/rand`, hex. Compared with `crypto/subtle.ConstantTimeCompare`. Required on every `/api/*` request (header `X-Kiwi-Token`) and as the first message on the WebSocket. **Never in a URL path or query.** Never logged. | `internal/server` |
| Token delivery: printed once at startup as `http://127.0.0.1:<port>/#<token>`. The URL fragment is never sent to any server and never appears in access logs. The page moves it into `sessionStorage` (origin-scoped, so other ports of 127.0.0.1 cannot read it) and strips the fragment with `history.replaceState`. A tab opened without the fragment shows a "paste the URL from the terminal" message. | `internal/server`, `web/src/session.ts` |
| HTTP server: `ReadHeaderTimeout` 5 s, `ReadTimeout` 15 s, `WriteTimeout` 30 s (static only; WebSocket is hijacked and uses its own per-frame deadlines), `IdleTimeout` 60 s, `MaxHeaderBytes` 16 KiB. | `internal/server` |
| **No CORS headers at all.** Not even `Access-Control-Allow-Origin: http://127.0.0.1`. | `internal/server` |
| Response headers on every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`, `Cache-Control: no-store` for API, `Content-Security-Policy` (4.6). | `internal/server` |
| Only `GET` is accepted anywhere. | `internal/server` |
| JSON bodies from the browser capped at 4 KiB; WebSocket messages from the browser capped at 4 KiB, 20 per second. | `internal/server`, `internal/relay` |

### 4.4 Relay sessions and the receiver protocol

| Control | Where |
| --- | --- |
| Max 3 concurrent sessions. One session per receiver (keyed by hostname, so 400 receivers behind the shared proxy IP are still distinct). | `internal/relay` |
| Per-session duration cap 90 min, bytes-from-receiver cap 256 MiB, bytes-to-browser cap 1 GiB. Hitting a cap closes the session with a reason the UI shows. | `internal/relay` |
| Handshake-to-first-message timeout 10 s (silent refusal, PHASE0 5.3). Per-message read deadline 15 s. Per-frame write deadline 5 s both directions. | `internal/kiwiws`, `internal/relay` |
| WebSocket frame reader: RSV bits rejected, control frames capped at 125 bytes, length field checked against the cap **before** allocation, fragmented messages capped in total, 64-bit lengths with the high bit rejected. | `internal/kiwiws` |
| Receiver message cap 256 KiB (`load_cfg` is a few KiB). Audio payload cap 64 KiB per frame. Inbound rate cap 512 KiB/s averaged over 2 s (normal is 6 KiB/s). | `internal/kiwiws`, `internal/relay` |
| `SND` parsing: fixed header checked for length, stereo header checked, odd PCM length rejected, every field read with explicit endianness, no field used as a length or count. | `internal/kiwi` |
| ADPCM: index clamped to [0,88] and predictor to int16 on every sample. State reset on `RESTART` flag. | `internal/kiwi` |
| Sample rate must be within 1 percent of 12000 or 20250 Hz; anything else closes the session. | `internal/relay` |
| `MSG` parsing: token count capped at 64, only the handful of names we act on are read; `load_cfg` and friends are never parsed. Values are not URL-decoded unless we need them. | `internal/kiwi`, `internal/relay` |
| `badp` 1..7, `too_busy`, `down`, `redirect`, `exclusive_use`, `wb_only`, `ip_limit`, `inactivity_timeout` end the session cleanly with a user-visible reason. `redirect` is never followed. | `internal/relay` |
| No goroutine leaks: each session owns a context; both pump goroutines exit on cancel; `Close` waits for them. Tested with a goroutine-count check around hostile-receiver scenarios. | `internal/relay`, tests |
| No shelling out, no `os/exec`, no `ffmpeg`, no `eval`, no `Function`, no `innerHTML`. `go vet` and a grep in CI-style test enforce the Go side. | everywhere |
| Fuzz targets: WebSocket frame reader, `ParseSND`, `ParseMSG`, ADPCM decoder, directory decoder, sanitiser. | `*_test.go` |

### 4.5 Untrusted strings

| Control | Where |
| --- | --- |
| `sanitize.Text(s, max)`: invalid UTF-8 replaced, all `Cc` and `Cf` runes removed (covers C0/C1 controls, bidi overrides and isolates, zero-width joiners, BOM, soft hyphen, invisible separators seen in the live directory), noncharacters removed, whitespace collapsed to single spaces, trimmed, truncated by rune count. Applied in Go before anything reaches the browser or a log. | `internal/sanitize` |
| Logs: receiver-supplied strings go through `sanitize.ForLog` (sanitise, then `%q`). The session token is never passed to the logger. `Location` headers and `MSG` values are logged sanitised and truncated. | `internal/sanitize`, callers |
| Browser: all receiver text is set with `textContent`. CSP forbids inline script and requires Trusted Types for any sink. | `web/src` |

### 4.6 Front end (Phase 2)

| Control | Where |
| --- | --- |
| CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'`. Set by the relay on the HTML response. | `internal/server` |
| Zero third-party requests: Vite bundles everything; coastlines are a bundled Natural Earth file; fonts are system fonts; no `<link>` to any remote; no `fetch` outside `/api`. Verified by the CSP (`connect-src 'self'`) and a test that greps the built bundle for `https?://`. | `web/`, tests |
| Vite built with `modulePreload.polyfill: false` so the HTML contains no inline script. | `web/vite.config.ts` |
| Receiver web UIs are never embedded, iframed, linked as `<a href>`, or opened. The receiver's `url` is **not sent to the browser at all**; the browser only gets an ID, name, location, antenna, GPS, counts and flags. | `internal/server` |
| Trusted Types: no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout(string)`. Enforced by CSP in the browser and a grep test over `web/src`. | `web/src`, tests |

### 4.6a Player and logbook

| Control | Where |
| --- | --- |
| The audio worklet is the only script loaded by URL. The page's single Trusted Types policy (`kg`, named in the CSP `trusted-types` directive) accepts exactly `/player-worklet.js` and throws for anything else. | `web/src/player.ts` |
| Audio frames from the relay are re-validated in the browser: type byte, minimum and maximum length (128 KiB), even PCM length. The worklet drops `pcm` messages over 65 536 samples and never grows its ring buffer. | `web/src/player.ts`, `web/public/player-worklet.js` |
| Output limiter: peak follower with a -1 dBFS ceiling plus a hard clamp at 0.98, applied after the volume control, so no receiver can produce full-scale output whatever it sends. | `web/public/player-worklet.js` |
| Seek reads only the S-meter from frames and issues tune commands at most every 650 ms, well under the relay's 20 messages/s cap. | `web/src/main.ts` |
| Logbook entries are untrusted on read: every field type-checked, `freq` range-checked, `mode` allow-listed, receiver ID pattern-checked, strings capped by rune count, at most 2000 entries, 4 MB raw cap. Rendered by cloning a `<template>` and setting `textContent`. Receivers are referenced by ID and re-resolved against the live list; a vanished receiver cannot be dialled. | `web/src/logbook.ts`, `web/src/main.ts` |
| Export is a `blob:` URL on an `<a download>`; no CSP exception, no navigation. CSV fields are quoted. (Spreadsheet formula injection is the importing application's problem, but a note starting with `=` is still exported as-is inside quotes; see residual.) | `web/src/logbook.ts` |
| `kg:play` / `kg:stop` DOM events let same-origin scripts drive the player. Same-origin scripts can already do anything the page can, so this adds no capability; the handler still validates the receiver ID against the list and clamps the frequency. | `web/src/main.ts` |
| `-dev` flag: the session token is stored at `<cache dir>/kiwi-garden/dev-token` (0600) and reused across restarts. Any same-user process can read it. Off by default, printed as a warning when on, intended only while working on the UI. | `cmd/kiwi-garden/main.go` |

### 4.7 Good citizen

| Control | Where |
| --- | --- |
| Ident `Kiwi Garden (github.com/s0undsystem/KiwiGarden)` sent as `ident_user` and as `User-Agent`. | `internal/relay` |
| kiwirecorder-style URL so the admin's `ext_api` limit applies to us (PHASE0 3). Receivers with `ext_api == 0` or no free slot are dimmed in the UI and refused by the relay. | `internal/relay`, `web/src` |
| One connection per receiver. Keepalive every second. Clean close frame on every exit path. | `internal/relay` |
| Exponential backoff per receiver after any failure or busy response: 5 s doubling to 10 min, reset after 30 s of successful audio. Attempts during backoff are refused locally without touching the network. | `internal/relay` |
| 90-minute session cap so a forgotten tab does not hold a volunteer's channel all night. | `internal/relay` |

## 5. Things we deliberately do not do

- No directory fetch from `kiwisdr.com/public/` (HTTP only; operator asked apps not to).
- No per-receiver `/status` polling (870 HTTP requests to volunteer hardware every refresh). We rely on the mirror's hourly snapshot and on the receiver's own `badp=1` when it is full.
- No `localhost` hostname anywhere. Always the literal `127.0.0.1`.
- No auto-open of the browser by default. The URL is printed; `-open` is opt-in because it means shelling out to the OS opener and we want zero `os/exec` in the default path. (Phase 2 decision: `-open` is **not implemented**; there is no `os/exec` import anywhere.)

## 6. Residual risks (accepted, with reasoning)

| Risk | Why accepted |
| --- | --- |
| Third-party mirror as directory source | Only HTTPS option; see 4.1 residual. |
| Plain HTTP to 99 percent of receivers | The protocol offers nothing else; data is public radio; audio bytes are fully bounds-checked regardless. |
| A local process with the user's privileges | Cannot be defended against from inside the process. We avoid making it worse (0600 cache, re-validation, no secrets on disk). |
| A hostile receiver can waste up to 256 MiB of bandwidth over 90 min before caps | Those are the caps. Rate cap of 512 KiB/s limits burst. |
| Cookies are not port-scoped, but we use none | Noted so nobody adds one later. |
| Receiver operators see the user's public IP and the ident | Inherent. The ident is honest about who we are. |

## 7. Hostile receiver test matrix

Each case must end with: session closed, close frame sent to the browser
with a reason, no panic, no goroutine left, memory bounded by the caps.

| Case | Mock behaviour | Expected relay outcome |
| --- | --- | --- |
| oversized frame | declares a 16 MiB payload | closed: frame exceeds limit |
| lying length | declares 4000 bytes, sends 100, stalls | closed: read deadline |
| slow drip | one byte every 2 s | closed: first-message or read deadline |
| mid-stream garbage | valid audio, then random bytes with SND tag, then unknown tags | garbage frames dropped or session closed, never panics |
| HTTP redirect | 307 on the upgrade | connect failed: not upgraded, Location not followed |
| giant metadata | `MSG` with a 200 KiB name value | ignored (within message cap) or closed (over cap); never forwarded unsanitised |
| silent after handshake | 101 then nothing | closed: first-message timeout |
| busy | `badp=1` | closed: receiver full; backoff recorded |
| too_busy | `MSG too_busy=8` | same |
| redirect message | `MSG redirect=http://evil` | closed; not followed |
| bad sample rate | `sample_rate=48000` | closed: unexpected sample rate |
| flood | 2000 frames/s | closed: rate limit |
| masked server frames | server masks its frames | tolerated (unmasked), content still validated |
| RSV bits / reserved opcode | | closed: protocol error |
| directory entry → 127.0.0.1 | | dial refused by policy, never connects |
| directory entry → 10.0.0.1 | | dial refused by policy |
| directory entry port 22 | | rejected at validation, never dialed |

## 8. Review log

### Phase 1 review (relay and security core)

Tried:
- Every row of section 7 against the mock receiver (`internal/relay` tests).
- Table-driven IP and port filter tests including IPv4-mapped IPv6 and NAT64 forms of private addresses.
- Header checks: missing Host, wrong port in Host, `localhost` Host, `Origin: null`, Origin with trailing slash, Origin from another port, `Sec-Fetch-Site: cross-site`, token missing, token wrong length, token with one bit flipped.
- Goroutine count before/after 50 hostile sessions.
- Fuzzing (30 s each) of the frame reader, SND, MSG, ADPCM, directory.

Held: every row of section 7; every header case; goroutine count returned
to baseline; fuzzers found no crashes. Details and numbers in
`docs/PHASE1.md`.

Found and fixed during review (details in `docs/PHASE1.md`): duplicate
directory URLs were not collapsed; U+0085 was treated as whitespace;
duplicate-receiver check was ordered after the session cap; backoff retry
time was rounded to zero below one second; Phase 0 CLI misread `badp=0`.

Residual added: `MaxSessions` (3) is only enforced per relay process; the
token is the real gate against a local script opening several.

### Phase 2 review (globe)

Tried:
- Receiver names containing `<img onerror>`, `javascript:` and bidi
  overrides, rendered through the panel and tooltip: plain text, direction
  unaffected (controls stripped server-side, `textContent` client-side).
- Headless Chrome with the production CSP: zero violations, zero console
  errors; WebGL initialised under SwiftShader.
- Scanned the built bundle for `http(s)://`, `innerHTML`, `eval`,
  `new Function`, `data:` URIs: only the XHTML namespace string and a
  citation comment inside three.js.
- Token lifecycle: fragment stripped on load, refresh works via
  `sessionStorage`, new tab without the fragment shows the instruction
  overlay, no token ever appears in a request URL.
- Malformed `coast.bin` (truncated, bad magic, absurd counts): parser throws
  before any out-of-range read.

Held: all of the above. Nothing needed fixing in the security controls.

Residual added: three.js is a 550 KB dependency; pinned, bundled, no
network, no inline script allowed. A WebGL-less browser gets a blank globe
and no message yet (UX, not security).

### Phase 3 and 4 review (player, logbook)

Tried:
- Live session driven over the Chrome DevTools Protocol under the
  production CSP: worklet loaded through the Trusted Types policy, audio
  frames decoded and buffered (0.25 to 0.3 s steady state, ratio chase
  holding), retune and mode change mid-stream, seek, log a catch, read it
  back, stop. Zero CSP reports, zero exceptions.
- Audio frame with a wrong type byte, odd length, or over 128 KiB: dropped
  in the browser before reaching the worklet.
- Worklet fed a `pcm` message of 1 MB: dropped (65 536-sample cap). Fed
  frames faster than real time: ring buffer drops oldest, never grows.
- Full-scale square wave from the mock receiver: output held at -1 dBFS by
  the limiter.
- Logbook with hand-edited `localStorage`: entries with a `javascript:`
  receiver name, a 100 kB note, `freq: 1e9`, `mode: "iq"`, a non-hex
  receiver ID, and a non-array root: all dropped or capped, nothing rendered
  as markup, nothing dialled.
- Retune from a logbook entry whose receiver has left the list: status
  message, no connection attempt.

Held: all of the above.

Residual added: a CSV note beginning with `=`, `+`, `-` or `@` is exported
inside quotes and could be interpreted as a formula by a spreadsheet that
ignores quoting. Mitigated by prefixing such notes with a single quote in
the CSV export.
