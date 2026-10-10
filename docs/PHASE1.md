# Phase 1: Relay and Security Core

Delivered: the `kiwi-garden` binary's back end. `THREAT_MODEL.md` was written
first and every control in its section 4 maps to a package below.

## What was built

| Package | Role | Lines |
| --- | --- | --- |
| `internal/netpolicy` | IP and port policy, `net.Dialer` with a `Control` hook that checks the **resolved** address of every attempt | 180 |
| `internal/directory` | Pinned-host HTTPS fetch, 4 MiB cap, no redirects, strict per-entry validation, URL rules, 0600 atomic disk cache that is re-validated on load, daily refresh | 480 |
| `internal/kiwiws` | RFC 6455 client and server, zero dependencies, every length checked before allocation | 520 |
| `internal/kiwi` | SND/MSG parsing, IMA ADPCM with clamped state, sample-rate allowlist | 240 |
| `internal/sanitize` | Control/format/bidi/zero-width stripping, rune-capped truncation, log quoting | 80 |
| `internal/relay` | Session manager: concurrency cap, one per receiver, backoff, duration/byte/rate caps, first-message timeout, clean close on every path | 560 |
| `internal/server` | 127.0.0.1 HTTP: Host/Origin/Sec-Fetch-Site checks, constant-time token, security headers, no CORS, browser WebSocket with auth-first, rate limit and 4 KiB cap | 470 |
| `internal/mockkiwi` | Hostile receiver with 23 behaviours | 430 |
| `cmd/kiwi-garden` | Wires it up, prints the launch URL once | 110 |

Dependencies: **none** outside the Go standard library. The WebSocket code
is ours so that the frame reader's bounds checks are in code we own and
fuzz.

## Session token delivery (THREAT_MODEL 4.3)

The binary prints `http://127.0.0.1:<port>/#<64 hex>`. The fragment is
never sent over HTTP, so it is absent from any access log. The page moves
it to `sessionStorage` (origin-scoped, port included) and strips it from
the URL bar. API calls send it in `X-Kiwi-Token`; the WebSocket sends it as
the first text message, which must arrive within 5 s. Comparison uses
`crypto/subtle.ConstantTimeCompare` on the decoded bytes.

## Test results

```
go test ./...          all packages pass (race-free; relay suite ~21 s)
go vet ./...           clean
fuzz (6 targets, ~70 s total)   no crashes; corpus grew to 250+ inputs
```

Hostile receiver matrix (THREAT_MODEL section 7), every row ends in a clean
close with a user-visible reason and zero leaked goroutines:

| Case | Close reason observed |
| --- | --- |
| oversized frame (16 MiB declared) | `protocol_error` |
| lying length | `timeout` |
| slow drip (1 byte / 2 s) | `timeout` |
| mid-stream garbage | audio continued; garbage dropped or `protocol_error` |
| HTTP 307 on upgrade | `redirect_refused`, Location logged sanitised, not followed |
| HTTP 403 on upgrade | `receiver_refused` |
| 200 KiB metadata value | ignored (under the 256 KiB message cap) |
| silent after handshake | `timeout` after 10 s (1.5 s in tests) |
| `badp=1` | `receiver_full`, backoff armed |
| `too_busy` | `receiver_full` |
| `MSG redirect=` | `redirect_refused` |
| `sample_rate=48000` | `unexpected_sample_rate` |
| flood | `rate_limited` |
| masked server frames | tolerated, content still validated |
| RSV bits / reserved opcode | `protocol_error` |
| close immediately | `receiver_closed` |
| fragmented audio | reassembled, capped |
| unexpected stereo frame | `protocol_error` |
| odd PCM length | `protocol_error` |
| uncompressed PCM | played |
| sequence jump to 2^32 | played, gap logged at debug |

Goroutine leak test: 3 rounds of 8 concurrent hostile sessions, count
returns to baseline (+2 tolerance for the test server itself).

Header check table (`internal/server`): 29 cases including DNS-rebinding
Host, `localhost` Host, Host without port, `Origin: null`, Origin on another
port, Origin with trailing slash, `Sec-Fetch-Site: cross-site` and
`same-site`, token missing / short / bit-flipped / in query string, direct
navigation to the API, every non-GET method, path traversal, WebSocket
without Origin or with a foreign Origin.

## Adversarial review

What I tried, beyond the tables above:

- **DNS rebinding of a receiver**: a directory hostname that resolves to
  127.0.0.1. Validation lets a hostname through (it cannot know), but the
  dial hook refuses the resolved address. Test: `TestDialerRefusesLoopback`
  and `TestPolicyBlocksLoopbackInProduction`.
- **Cache tampering**: injected a loopback entry into the on-disk cache.
  Re-validation on load dropped it. Corrupt cache falls through to the
  network. Stale cache is served only when the network fails.
- **Token in a URL**: `/api/receivers?token=...` is ignored (401). The token
  is only ever read from a header or a WebSocket message.
- **Cross-port local attacker**: a page on `127.0.0.1:9999` has an Origin
  that does not match ours and is refused on both fetch and WebSocket.
  Cookies are not used at all, so there is nothing for it to ride on.
- **Browser disappears mid-stream** without a close frame: the relay's
  write to the dead socket fails within the write deadline, the sink error
  tears down the receiver session, the receiver gets a close frame.
  Test: `TestWebSocketCloseReleasesReceiver`.
- **Panic in the decoder**: `run()` recovers, converts it to
  `protocol_error`, and still frees the session.
- **Non-integer / wrong-type directory fields**: clamped or defaulted per
  field; the entry survives if its URL and GPS are valid.
- **Huge token count / deep JSON nesting** in the directory: decoder limits
  and the 4 MiB cap; the 100 000-deep array is rejected.

Found and fixed during this phase:

1. `Parse` did not collapse duplicate URLs (map was filled after the loop).
   Caught by `TestParseDuplicateURLsCollapse`.
2. U+0085 (NEL) was treated as whitespace and became a space instead of
   being removed as a control. Caught by the sanitiser table test.
3. Duplicate-receiver check ran after the session cap, so a duplicate open
   reported `session_limit` instead of `already_connected`.
4. Backoff `RetryAfter` was rounded to whole seconds, which rounded sub-second
   test backoffs to zero and would have shown "retry in 0 s" in the UI.
5. Phase 0 CLI treated `badp=0` (success) as a rejection.

## Residual risk after Phase 1

- The directory mirror is a third party (accepted, THREAT_MODEL 6).
- Rate and byte caps are generous enough that a hostile receiver can still
  waste bandwidth for a while; they bound it, they do not prevent it.
- `MaxSessions` is 3; the browser only ever opens one, but nothing stops a
  local script with the token from opening three. The token is the gate.
- The relay logs receiver hostnames (from the directory, LDH-validated). A
  hostile directory could still choose an embarrassing hostname; it cannot
  inject control characters.
