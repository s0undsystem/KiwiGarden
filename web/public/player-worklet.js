// Kiwi Garden audio worklet: jitter buffer, resampler, limiter.
//
// Runs on the audio rendering thread. Plain JS on purpose: it is loaded by
// URL through a Trusted Types policy and must not depend on the bundler.
//
// Input: int16 little-endian PCM at the receiver's rate (12000 or 20250 Hz,
// as a calibrated float), posted from the main thread in ~170 ms frames.
// Output: the AudioContext rate (typically 44100 or 48000), mono duplicated
// to every output channel.
//
// Design:
//  - Ring buffer of 4 s at the source rate. Playback starts after 250 ms
//    is buffered and the read pointer then chases a 300 ms target by
//    nudging the resampling ratio by up to 1 %: this absorbs the receiver's
//    calibrated-rate drift and network jitter without ever hard-skipping.
//  - Linear interpolation resampler. Good enough for 12 kHz AM/SSB audio
//    going to a 48 kHz context; the receiver's passband is below 5 kHz.
//  - Underrun handling: gain ramps to zero over 5 ms and back up over 5 ms,
//    so a stall is a soft dip, not a click. "flush" (receiver switch) does
//    the same ramp and clears the buffer.
//  - Limiter: peak follower with 1 ms attack and 250 ms release holding the
//    output at or below -1 dBFS, then a hard clamp at 0.98 as a backstop.
//    A receiver with its AGC off and a strong carrier can send full-scale
//    squares; the user's ears are the asset.

class KiwiPlayer extends AudioWorkletProcessor {
  constructor() {
    super();
    this.srcRate = 12000;
    this.capacity = 0;
    this.buf = null;
    this.writeIdx = 0;
    this.readPos = 0; // fractional read index
    this.available = 0; // samples between read and write
    this.state = "filling";
    this.gain = 0; // underrun/flush ramp
    this.volume = 0.8;
    this.peak = 0;
    this.ratioAdjust = 1;
    this.underruns = 0;
    this.received = 0;
    this.sinceStats = 0;
    this.setRate(12000);
    this.port.onmessage = (ev) => this.onMessage(ev.data);
  }

  // Once a second, tell the main thread how the buffer is doing.
  stats() {
    this.port.postMessage({
      type: "stats",
      state: this.state,
      buffered: this.available / this.srcRate,
      underruns: this.underruns,
      received: this.received,
      ratio: this.ratioAdjust,
    });
  }

  setRate(rate) {
    if (!(rate > 1000 && rate < 100000)) return;
    this.srcRate = rate;
    this.capacity = Math.ceil(rate * 4);
    this.buf = new Float32Array(this.capacity);
    this.writeIdx = 0;
    this.readPos = 0;
    this.available = 0;
    this.state = "filling";
  }

  onMessage(m) {
    if (!m || typeof m !== "object") return;
    switch (m.type) {
      case "rate":
        this.setRate(Number(m.rate));
        break;
      case "pcm": {
        if (!(m.buf instanceof ArrayBuffer)) return;
        const n = m.buf.byteLength >> 1;
        if (n === 0 || n > 65536) return;
        const view = new DataView(m.buf);
        // Drop the oldest audio if the sender is far ahead (should not
        // happen with the ratio chase, but never grow unbounded).
        if (this.available + n > this.capacity - 1) {
          const drop = this.available + n - (this.capacity - 1);
          this.readPos = (this.readPos + drop) % this.capacity;
          this.available -= drop;
        }
        for (let i = 0; i < n; i++) {
          this.buf[this.writeIdx] = view.getInt16(i * 2, true) / 32768;
          this.writeIdx = (this.writeIdx + 1) % this.capacity;
        }
        this.available += n;
        this.received += n;
        break;
      }
      case "flush":
        this.state = "flushing";
        break;
      case "volume": {
        const v = Number(m.value);
        if (v >= 0 && v <= 1) this.volume = v;
        break;
      }
    }
  }

  process(_inputs, outputs) {
    const out = outputs[0];
    if (!out || out.length === 0 || !this.buf) return true;
    const ch0 = out[0];
    const frames = ch0.length;
    const prebuffer = this.srcRate * 0.25;
    const target = this.srcRate * 0.3;
    const rampStep = 1 / (sampleRate * 0.005); // 5 ms

    if (this.state === "filling" && this.available >= prebuffer) this.state = "playing";

    // Chase the target latency with a bounded ratio tweak.
    const err = (this.available - target) / this.srcRate; // seconds
    this.ratioAdjust = 1 + Math.max(-0.01, Math.min(0.01, err * 0.05));
    const ratio = (this.srcRate / sampleRate) * this.ratioAdjust;

    const limCeil = 0.89; // -1 dBFS
    const attack = Math.exp(-1 / (sampleRate * 0.001));
    const release = Math.exp(-1 / (sampleRate * 0.25));

    for (let i = 0; i < frames; i++) {
      let s = 0;
      let wantGain = 0;
      if (this.state === "playing" && this.available >= 2) {
        const i0 = Math.floor(this.readPos);
        const frac = this.readPos - i0;
        const a = this.buf[i0 % this.capacity];
        const b = this.buf[(i0 + 1) % this.capacity];
        s = a + (b - a) * frac;
        this.readPos += ratio;
        const consumed = Math.floor(this.readPos) - i0;
        if (consumed > 0) {
          this.available -= consumed;
          if (this.readPos >= this.capacity) this.readPos -= this.capacity;
        }
        wantGain = 1;
      } else if (this.state === "playing") {
        // underrun: go back to filling, fade handles the click
        this.state = "filling";
        this.underruns++;
      }
      if (this.state === "flushing") {
        wantGain = 0;
        if (this.gain <= 0) {
          this.readPos = this.writeIdx;
          this.available = 0;
          this.state = "filling";
        }
      }
      if (this.gain < wantGain) this.gain = Math.min(wantGain, this.gain + rampStep);
      else if (this.gain > wantGain) this.gain = Math.max(wantGain, this.gain - rampStep);

      s *= this.gain * this.volume;

      // Limiter.
      const mag = Math.abs(s);
      this.peak = mag > this.peak ? mag + (this.peak - mag) * attack : mag + (this.peak - mag) * release;
      if (this.peak > limCeil) s *= limCeil / this.peak;
      if (s > 0.98) s = 0.98;
      else if (s < -0.98) s = -0.98;

      ch0[i] = s;
    }
    for (let c = 1; c < out.length; c++) out[c].set(ch0);
    this.sinceStats += frames;
    if (this.sinceStats >= sampleRate) {
      this.sinceStats = 0;
      this.stats();
    }
    return true;
  }
}

registerProcessor("kiwi-player", KiwiPlayer);
