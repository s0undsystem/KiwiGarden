# Phase 0: Spike Report

Date: 2026-10-10 (UTC). All live tests ran against public receivers from a
residential IPv4 address. Receivers tested ran KiwiSDR firmware v1.902.

## 1. Licensing of the reference

| Source | License | Decision |
| --- | --- | --- |
| `jks-prv/kiwiclient` top level | **No LICENSE file** | |
| `kiwiclient/kiwi/client.py`, `wsclient.py` (the protocol) | **No license header** = all rights reserved | Not ported. Read for understanding only. |
| `kiwiclient/mod_pywebsocket/` | BSD-3 (Google, 2011) | Not needed; WebSocket client written from RFC 6455. |
| `kiwiclient/kiwi/rigctld.py` | GPL-2.0-or-later | Irrelevant to us. |
| `jks-prv/KiwiSDR` (server) | Mix of GPL 2/3 and MIT per directory | Read to confirm wire format and refusal paths. Not ported. |

Everything in `internal/` is original code. The IMA ADPCM step and index
tables are the published IMA constants.

## 2. Public receiver directory

### 2.1 The official list is HTTP-only and gated

- `http://kiwisdr.com/public/` is served by lighttpd over **plain HTTP**.
  Port 443 is **refused** on `kiwisdr.com`, `rx.kiwisdr.com`, and
  `www.kiwisdr.com` (connection refused, not a cert problem).
- The page is a click-through interstitial. The real list is released only
  after the browser's click handler sends a scripted GET with an
  `x-kiwi-auth: <64-hex token>` header (token embedded in the page), after
  which the server unlocks that client IP. Replaying the header from curl
  returned `200` with an empty body; the list did not unlock for us.
- Per [AetherSDR issue #5447](https://github.com/aethersdr/AetherSDR/issues/5447),
  the KiwiSDR maintainer explicitly asked third-party apps to **stop
  per-client scraping** of this page, and set up an authenticated HTTPS
  source (`https://files.kiwisdr.com/public/`, returns `403` without the
  shared secret) for a single upstream mirror to pull from.

Conclusion: fetching `kiwisdr.com/public/` from every user's machine, even
daily, is exactly what the operator asked people not to do, and it cannot be
done over HTTPS. **Kiwi Garden should not fetch it.**

### 2.2 Recommended source: the AetherSDR mirror

`https://cdn.aethersdr.com/kiwi.json`

| Property | Observed |
| --- | --- |
| Transport | HTTPS (Cloudflare), HTTP/2, valid cert |
| Size | 821,766 bytes for 870 receivers |
| Caching | `cache-control: public, max-age=1800`; `x-fetched-at`, `x-receiver-count` headers |
| Refresh | Hourly worker; `fetched_at` in body |
| Stability | `"schema": 1`, URL committed "in perpetuity" per the issue |
| CORS | `access-control-allow-origin: *` (irrelevant to us; the relay fetches it) |

Top-level shape:

```json
{"schema":1,"source":"https://files.kiwisdr.com/public/","fetched_at":"...",
 "receiver_count":870,"receivers":[ ... ]}
```

Per-receiver fields (all 870 entries had every field unless noted):

| Field | Type | Notes |
| --- | --- | --- |
| `url` | string | `http://host[:port]`. 868 `http`, 2 `https`. Max length seen 50. |
| `name`, `loc`, `antenna` | string | Free text. Max lengths seen: 227 / 97 / 249. Contains emoji and U+2063 invisible separators. |
| `sdr_hw`, `sw_version`, `debian` | string | Free text. |
| `gps` | `[lat, lon]` | One entry was `[0,0]`. |
| `grid` | string | Maidenhead; missing in 17. |
| `users`, `users_max` | int | Live counts at mirror fetch time. 808 of 870 had a free slot. |
| `ext_api` | int | **Channels the admin allows for non-Kiwi apps** (us). 441 = 4, 141 = 0, 25 missing (older firmware). See 5.3. |
| `preempt` | int | Channels running pre-emptible autorun extensions. |
| `offline`, `status`, `flagged` | bool / string | All 870 were `active`, `offline:false`. |
| `bands` | `[lo_hz, hi_hz]` | e.g. `[3000, 30000000]` |
| `freq_offset` | number | kHz offset for down-converters. |
| `mode` | string | FPGA config: `rx8.wf3` (712), `rx4.wf4` (76), `rx3.wf3` (30), ... Determines sample rate. |
| `snr`, `snr_all`, `snr_hf` | ints | Receiver self-reported SNR. Useful for ranking. |
| `id`, `seq`, `updated`, `date`, `uptime`, `tdoa_*`, `fixes*`, `gps_good`, `asl`, `sm_cal`, `wf_cal`, `adc_ov`, `clk_ext_*`, `ip_blacklist`, `dx_file`, `avatar_ctime`, `ant_connected` | misc | Not needed. |

The mirror **omits** `op_email`, which each receiver's own `/status` endpoint
exposes. We must never display or store it even if a future schema adds it.

### 2.3 Proxied receivers

402 of 870 URLs are `http://<name>.proxy.kiwisdr.com` with **no port**. That
host (50.116.2.70, kiwisdr.com's own box) answers port 80 with a
`307 Temporary Redirect` to the **same host on port 8073**. Our rule is no
redirects, so the relay should rewrite `*.proxy.kiwisdr.com` with no port to
`:8073` as a documented constant, then connect directly. Tested: direct
`:8073` works. Note that the proxy is HTTP-only and all 402 of those receivers
share one IP, so the "one connection per receiver" rule needs to key on
hostname, and any per-IP throttling must not treat the proxy as one receiver.

### 2.4 Alternative mirror

`http://rx.linkfanel.net/kiwisdr_com.js` (Pierre Ynard's list used by TDoA):
HTTP only, port 443 refused. Not usable under the HTTPS rule.

### 2.5 Trust implication

The directory is our allowlist, and the only HTTPS copy is run by a third
party (AetherSDR). A compromise there would let an attacker add arbitrary
hosts. That is why Phase 1 keeps every defence that does not depend on the
directory being honest: resolved-IP filtering at dial time, port filter, size
cap, strict schema, string sanitising, and no redirects.

## 3. WebSocket handshake and session setup

Verified live and against `rx/rx_server.cpp`, `rx/rx_cmd.cpp`.

1. **TCP** to the URL's host and port (TLS if the URL is `https`).
2. **HTTP upgrade** `GET /<unix_seconds>/SND HTTP/1.1` with standard
   `Upgrade`, `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`.
   No subprotocol, no extensions. Server replies `101`.
   - The URL form `/<ts>/SND` is what kiwirecorder uses. The server pattern
     matches it as `isKrec` (external API client) and applies the admin's
     `ext_api` channel limit. The browser UI uses `/kiwi/<ts>/SND` and is not
     limited that way. **We use the kiwirecorder form on purpose.** It is
     honest, and it means a receiver owner who set `ext_api=0` is respected.
3. Server immediately sends `MSG sample_rate=<float>` (e.g. `11998.992692`)
   on channel allocation, **before** auth.
4. Client sends `SET auth t=kiwi p=` (empty password). Server only accepts
   `SET auth`, `SET options`, and `SET keepalive` before auth succeeds.
5. Server replies with a burst of `MSG` lines. Seen on every receiver:
   `client_public_ip`, `rx_chans`, `firmware_sel`, `chan_no_pwd`,
   `chan_no_pwd_true`, `is_local`, `max_camp`, **`badp=0`** (success),
   `version_maj`, `version_min`, `debian_ver`, `model`, `platform`, `hw`,
   `ext_clk`, `freq_offset`, `abyy`, `dx_db_name`, `has_attn`,
   `load_cfg=<url-encoded JSON, several KiB>`, `load_dxcfg`,
   `load_dxcomm_cfg`, `cfg_loaded`, `center_freq`, `bandwidth`,
   `adc_clk_nom`, `audio_init`, **`audio_rate=12000`**,
   `last_community_download`, `max_thr`, `rf_attn`, later
   `antsw_AntennaDenySwitching`.
6. On `audio_rate=R` client sends `SET AR OK in=R out=44100` (the browser
   does this; harmless acknowledgement).
7. Client configures the channel (order as the browser UI and kiwiclient):

   ```
   SET squelch=0 max=0
   SET genattn=0
   SET gen=0 mix=-1
   SET ident_user=Kiwi%20Garden%20(github.com/s0undsystem/KiwiGarden)
   SET mod=am low_cut=-4900 high_cut=4900 freq=9420.000
   SET agc=1 hang=0 thresh=-100 slope=6 decay=1000 manGain=50
   SET keepalive
   ```

   `freq` is in kHz. Default passbands: AM ±4900, USB 300..2700,
   LSB -2700..-300, CW 300..700. `ident_user` is parsed with `sscanf %256ms`:
   max 256 bytes, **stops at whitespace**, so spaces must be `%20`. The
   public `/users` listing truncates it (ours shows as `Kiwi Garden (git`);
   the receiver's admin log records the full string, which is where an
   operator who wants to find us will look.
8. **Audio flows** as `SND` binary messages, about 5.9 per second at 12 kHz
   (2048 samples per frame).
9. Client must send `SET keepalive` at least every **60 s** (`KEEPALIVE_SEC`),
   or every 20 s while unauthenticated. We send one per second, as
   kiwiclient does.
10. Close: client sends a WebSocket close frame (1001). The receiver freed
    the slot immediately (verified via its `/users` endpoint before and after).

Retune is `SET mod=... freq=...` again on the same connection. The next SND
frame carries `FLAG_NEW_FREQ`.

## 4. Audio frame format

Every message begins with a 3-byte ASCII tag. `MSG` is tag + space + text.
`SND` is:

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 3 | `"SND"` | |
| 3 | 1 | flags | see below |
| 4 | 4 | seq | **little-endian** u32, increments by 1 per frame |
| 8 | 2 | smeter | **big-endian** u16. `rssi_dBm = smeter / 10 - 127`. Server clamps to [-127, +3.4] dBm. |
| 10 | 10 | GPS header | **only if `FLAG_STEREO`** (IQ/DRM modes; we never request these) |
| 10 | n | audio | see flags |

Flags (`rx/rx_sound.cpp`):

| Bit | Name | Meaning |
| --- | --- | --- |
| 0x01 | LPF | low-pass filter changed |
| 0x02 | ADC_OVFL | front-end overload |
| 0x04 | NEW_FREQ | first frame after a retune |
| 0x08 | STEREO | IQ / DRM; two channels, never compressed |
| 0x10 | COMPRESSED | audio is **IMA ADPCM** |
| 0x20 | RESTART | decoder state should be reset |
| 0x40 | SQUELCH_UI | squelch closed |
| 0x80 | LITTLE_ENDIAN | PCM samples are LE (default is big-endian) |

- **Default is compressed**: first frame had `flags=0x15` (LPF, NEW_FREQ,
  COMPRESSED). ADPCM is IMA/DVI4, 4 bits per sample, two per byte, **low
  nibble first**, 1024 bytes per frame = 2048 samples. Decoder state persists
  across frames and is reset by the server on mode change (`RESTART` flag).
- `SET compression=0` switches to 16-bit PCM, big-endian. Verified live on
  `websdr.heppen.be:8073`: the first frame still arrived compressed
  (`flags=0x10`, the request had not been processed yet), then frames
  switched to PCM. **The compression flag must be honoured per frame**, not
  assumed from what we asked for. That receiver runs older firmware: 480-byte
  frames (240 samples, 50 per second), no `version_maj`, no `firmware_sel`,
  and an empty MSG token. The MSG set varies by firmware version, so nothing
  in the burst may be treated as mandatory except `sample_rate`, `badp`, and
  `audio_rate`.
- **Signal strength lives in every audio frame** (the smeter field). No
  separate channel is needed. The first frame's RSSI is stale (leftover from
  the channel's previous user); kiwiclient skips it too.

Sample rate is reported as a calibrated float. Observed `11998.99` on
`rx8.wf3` / `rx4.wf4` receivers and `20250.95` on an `rx3.wf3` receiver.
Nominal `audio_rate` is `12000` or `20250`. Validate against those two with a
1 percent tolerance; anything else is a hostile or broken receiver.

## 5. Receiver behaviour

### 5.1 Origin header

**Not checked.** A session with `Origin: http://evil.example` ran to
completion on a fresh receiver with identical output to one without an
Origin. Server source confirms: the only Origin handling is
`Access-Control-Allow-Origin: *` on HTTP responses. Implication: any web page
a user visits could open a WebSocket to a receiver directly. That is why the
browser side of Kiwi Garden talks only to the relay, and the relay checks
Origin itself.

### 5.2 TLS

Rare. 2 of 870 directory URLs are `https`. Tested `https://kwsdr.db0nas.de:443`:
valid certificate, handshake and auth succeeded over TLS. Of 7 `http`
receivers probed for TLS on their service port, none offered it (plain HTTP
server resets the TLS hello). The 402 proxied receivers are HTTP-only. So
"use TLS when offered" means: honour an `https` URL in the directory, and do
not try to upgrade `http` entries.

### 5.3 Busy, full, and refused receivers

| Condition | What the receiver does | Our handling |
| --- | --- | --- |
| Password-free channels all in use | Completes handshake, sends the MSG burst, then **`badp=1`** and holds the connection | Treat `badp=1` as "full", close, back off |
| All rx channels in use, including protected ones | `MSG too_busy=<rx_chans>` then close (from source; not reproduced live) | Same as full |
| Admin configured a redirect URL for overflow | `MSG redirect=<url>` | Refuse. Never follow. |
| `ext_api=0`, or external-API slots exhausted | **Completes the WebSocket handshake and then sends nothing.** Connection stays open, idle. Seen on three receivers. | Needs a first-message timeout (the spike used 15 s). Dim or hide `ext_api=0` receivers in the UI. |
| Receiver down / updating | `MSG down` or `badp` variants 2..7 | Close, back off |
| Receiver unreachable | TCP timeout (one directory entry) | Normal dial timeout |
| Front-end proxy rejects the upgrade | `HTTP 403` to the WebSocket GET (`kiwisdr.dfm.hu`, port 80) | Any non-101 is a hard failure; never retry with a different URL form |
| Inactivity / 24-hour time limit | `MSG inactivity_timeout`, `MSG ip_limit=<mins>,<ip>` | Close, show reason |

The silent refusal is the important one: a naive client would hang forever
holding a socket. The directory's `ext_api` and `users`/`users_max` fields
let us avoid most of these attempts up front, but they are up to an hour
stale, so the timeout is mandatory.

### 5.4 Per-IP limits

The server has an optional "no multiple connections from the same IP"
setting (`badp=5`). None of the tested receivers enforced it, but Kiwi Garden
should hold at most one connection per receiver anyway.

## 6. Spike results

`kiwispike -url http://sdr.autreradioautreculture.com:8074 -freq 9420 -mode am -secs 10`

| Measure | Value |
| --- | --- |
| Receiver firmware | 1.902 |
| Reported sample rate | 11998.992736 Hz |
| Frames | 59, zero sequence gaps |
| Compression | ADPCM (flags 0x15) |
| Audio | 60,416 bytes in, 120,832 samples out, 10.07 s |
| RSSI | avg -98.9 dBm (noise floor; 9420 kHz was empty at 01:21 UTC) |
| WAV | 241,708 bytes, RMS 1789, peak 12468, DC -1.7, no stuck zeros |
| Wall time | 10.9 s |

Also recorded successfully: a proxied receiver on `:8073`, a TLS receiver, an
`rx3.wf3` receiver at 20.25 kHz, and a receiver with a bogus Origin.

## 7. What Phase 1 must carry forward

- Directory: fetch `https://cdn.aethersdr.com/kiwi.json` only, pinned host,
  size cap (4 MiB is 5x today's size), `schema == 1`, strict per-field
  validation, daily refresh with disk cache. Document the third-party trust
  in `THREAT_MODEL.md`. Never contact `kiwisdr.com/public/`.
- URL rules: scheme `http`/`https` only, host must be a DNS name or literal
  IP from the directory, port 80/443/1024+; rewrite port-less
  `*.proxy.kiwisdr.com` to `:8073`; no path, query, or userinfo accepted.
- Handshake-to-first-message timeout, and a MSG burst cap (the `load_cfg`
  payload is several KiB of attacker-controlled JSON we do not need to parse).
- `badp` semantics: `0` success, `1` full, others reject.
- Keepalive every second; server kicks at 60 s.
- Sample-rate allowlist {12000, 20250} ±1 percent; frame payload cap; ADPCM
  state clamped (already done in `internal/kiwi/adpcm.go`).
- Ident string: `Kiwi Garden (github.com/s0undsystem/KiwiGarden)`, `%20`
  encoded.
- Strings from the directory contain emoji and invisible Unicode separators
  (U+2063) today; expect bidi controls tomorrow. Sanitise in Go.

## Sources

- https://github.com/jks-prv/kiwiclient (reference client)
- https://github.com/jks-prv/KiwiSDR (server: `rx/rx_sound.cpp`, `rx/rx_sound.h`, `rx/rx_server.cpp`, `rx/rx_cmd.cpp`, `kiwi.h`)
- https://github.com/aethersdr/AetherSDR/issues/5447 (directory access, mirror)
- https://cdn.aethersdr.com/kiwi.json (mirror)
