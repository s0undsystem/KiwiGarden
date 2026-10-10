# Player and logbook

## Player

`web/public/player-worklet.js` is an `AudioWorkletProcessor`. It is plain
JavaScript rather than bundled TypeScript because it is loaded by URL
through the page's only Trusted Types policy, and keeping it a single file
with no imports makes that policy's allow-list exactly one string.

Signal path per 128-frame render quantum:

1. Ring buffer (4 s at source rate) holds int16 PCM converted to float.
   Playback starts once 250 ms is buffered.
2. Linear-interpolation resampler from the receiver's calibrated rate
   (11998.99 Hz on a typical 12 kHz Kiwi, 20250.95 on an `rx3` one) to the
   context rate. The ratio is nudged by at most 1 percent toward a 300 ms
   buffer target, proportional to the error. This absorbs clock offset and
   jitter without hard skips. Observed steady state in testing: 0.18 to
   0.31 s.
3. Gain ramp, 5 ms up and down. An underrun ramps to silence and back
   rather than clicking; a receiver switch (`flush`) ramps down, clears,
   and refills. A retune does nothing here on purpose: the receiver's own
   filter transient is the transition, as on a real radio.
4. Volume.
5. Limiter: peak follower (1 ms attack, 250 ms release), gain reduction to
   hold -1 dBFS, then a hard clamp at ±0.98.

The main thread (`web/src/player.ts`) owns one WebSocket to
`/api/stream`, sends the token as the first message, re-validates every
binary frame's header and length, and transfers the PCM `ArrayBuffer` to
the worklet. The S-meter shown is the per-frame value from the relay,
smoothed with a 0.35 one-pole, mapped to S-units (S9 = -73 dBm, 6 dB per
unit).

## Tuning

Steps of ±1 and ±5 kHz (broadcast channel spacing), a numeric field with
arrow keys (Shift for 5 kHz, Alt for 100 Hz), AM/USB/LSB/CW with the Kiwi
UI's default passbands, and presets for the broadcast bands, a handful of
long-running stations, time signals, VOLMET and amateur segments.

Seek steps the 5 kHz grid every 650 ms, staying inside the broadcast bands
(leaving one jumps to the start of the next; the ends wrap), and stops on
the first channel whose average S-meter reading is 14 dB above a running
noise-floor estimate. The
floor tracks downward immediately and upward slowly, so a band full of
strong signals does not raise the bar out of reach. The frame flagged
`NEW_FREQ` (the first after a retune) is excluded from the average because
its AGC state belongs to the previous channel.

The first click on a receiver computes the sun's elevation at the
receiver. Daylight starts in the 19 m band (15100 kHz), because the D layer
kills the low bands by day; night starts in the 49 m band, at a station
known to be on around the clock where there is one (6070 kHz Channel 292
for Europe and Africa, 6000 kHz Radio Havana Cuba for the Americas, 5900
elsewhere). 900 ms after audio starts flowing it seeks upward until it finds
a signal. Once the user has
tuned anything, by hand, preset, logbook or seek, clicking another receiver
keeps that tuning and does not seek.

Known limitation: a few receivers listed as `<name>.proxy.kiwisdr.com`
answer the upgrade with a 307 to `<name>.proxy2.kiwisdr.com`. The relay
never follows redirects, so those show "receiver tried to redirect us".
The second proxy host is not in the directory, so there is nothing to
validate it against; this stays refused until the mirror lists the real
host.

## Logbook

`localStorage` key `kg.logbook`, a JSON array of `{ts, freq, mode, rxId,
rxName, rxLoc, note}`. Read-back validation is in `web/src/logbook.ts`;
rendering clones a `<template>` and uses `textContent`. Clicking an entry
retunes and reconnects by receiver ID against the current list. Export to
JSON or CSV via a `blob:` download; CSV cells are quoted and
formula-prefixed cells get a leading apostrophe.

## Verified

Driven over the Chrome DevTools Protocol against a live receiver
(`AutreRadioAutreCulture 1`, France) under the production CSP:

```
t=4s   live · 11999 Hz · 0.00 s buffered   S6 · -93 dBm
t=8s   live · 11999 Hz · 0.30 s buffered   S7 · -86 dBm
t=12s  live · 11999 Hz · 0.24 s buffered   S8 · -82 dBm
retune 9420 USB                             S4 · -101 dBm
logbook: 1 entry, retune works, stop → "stopped"
console: no CSP reports, no exceptions
```
