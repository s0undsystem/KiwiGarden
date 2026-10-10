// kiwispike is the Phase 0 spike: connect to one public KiwiSDR, tune one
// frequency, record N seconds of audio to a WAV file, and report what the
// receiver told us along the way.
//
// Usage:
//
//	kiwispike -url http://host:8073 -freq 9420 -mode am -secs 10 -out out.wav
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/kiwi"
	"github.com/s0undsystem/KiwiGarden/internal/kiwiws"
	"github.com/s0undsystem/KiwiGarden/internal/wav"
)

const ident = "Kiwi Garden (github.com/s0undsystem/KiwiGarden)"

var passbands = map[string][2]int{
	"am":  {-4900, 4900},
	"usb": {300, 2700},
	"lsb": {-2700, -300},
	"cw":  {300, 700},
}

// Sample rates a KiwiSDR can legitimately report (Hz), with a tolerance
// for the fractional clock-corrected value the server sends.
var expectedRates = []float64{12000, 20250}

func main() {
	var (
		rawURL   = flag.String("url", "", "receiver base URL, e.g. http://host:8073 (https for TLS)")
		freq     = flag.Float64("freq", 9420, "frequency in kHz")
		mode     = flag.String("mode", "am", "am | usb | lsb | cw")
		secs     = flag.Float64("secs", 10, "seconds of audio to record")
		out      = flag.String("out", "out.wav", "output WAV path")
		origin   = flag.String("origin", "", "send this Origin header (test receiver Origin checks)")
		password = flag.String("password", "", "receiver user password, if any")
		noComp   = flag.Bool("nocomp", false, "ask for uncompressed PCM instead of ADPCM")
		verbose  = flag.Bool("v", false, "log every MSG")
	)
	flag.Parse()
	if *rawURL == "" {
		flag.Usage()
		os.Exit(2)
	}
	pb, ok := passbands[*mode]
	if !ok {
		log.Fatalf("unknown mode %q", *mode)
	}

	wsURL, err := toWSURL(*rawURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("connecting %s", wsURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*secs)*time.Second+60*time.Second)
	defer cancel()

	conn, err := kiwiws.Dial(ctx, wsURL, &kiwiws.Options{
		Origin:    *origin,
		UserAgent: ident,
	})
	if err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer conn.Close()
	log.Printf("connected to %s tls=%v", conn.RemoteAddr(), conn.TLSState() != nil)

	// log.Fatal skips deferred calls; always send a close frame first so the
	// receiver frees the channel immediately instead of waiting for a
	// keepalive timeout.
	fatalf := func(format string, args ...any) {
		conn.Close()
		log.Fatalf(format, args...)
	}

	send := func(s string) {
		if *verbose && s != "SET keepalive" {
			log.Printf("-> %s", s)
		}
		if err := conn.WriteText(s); err != nil {
			fatalf("send %q: %v", s, err)
		}
	}

	// Step 1: authenticate as a normal user. Empty password is the norm.
	send("SET auth t=kiwi p=" + *password)

	var (
		dec        kiwi.ADPCM
		samples    []int16
		sampleRate float64
		started    bool
		frames     int
		audioBytes int
		rssiSum    float64
		rssiMin    = math.Inf(1)
		rssiMax    = math.Inf(-1)
		lastSeq    uint32
		seqGaps    int
		compressed = -1
		firstFlags byte
		lastKA     time.Time
		version    string
		msgNames   = map[string]int{}
		t0         = time.Now()
	)
	want := int(*secs * 12000) // adjusted once sample_rate is known

	for {
		op, msg, err := conn.Read()
		if err != nil {
			var ce *kiwiws.ErrClosed
			if errors.As(err, &ce) {
				log.Printf("receiver closed the connection: %v", ce)
			} else {
				log.Printf("read error: %v", err)
			}
			break
		}
		tag, body, ok := kiwi.SplitTag(msg)
		if !ok {
			log.Printf("short message (%d bytes, opcode %d)", len(msg), op)
			continue
		}
		switch tag {
		case "MSG":
			params, perr := kiwi.ParseMSG(body)
			if perr != nil {
				log.Printf("MSG parse: %v", perr)
			}
			for _, p := range params {
				msgNames[p.Name]++
				if *verbose {
					v := p.Value
					if len(v) > 120 {
						v = v[:120] + fmt.Sprintf("...(%d bytes)", len(p.Value))
					}
					log.Printf("<- MSG %s=%s", p.Name, v)
				}
				switch p.Name {
				case "too_busy":
					fatalf("receiver busy: all %s channels in use", p.Value)
				case "badp":
					// badp=0 is the success acknowledgement; 1..7 are rejections.
					if p.Value != "0" {
						fatalf("receiver rejected auth: badp=%s (%s)", p.Value, badpText(p.Value))
					}
					log.Printf("auth accepted (badp=0)")
				case "down":
					fatalf("receiver reports it is down")
				case "redirect":
					fatalf("receiver asked us to redirect to %q (refused)", kiwi.Unescape(p.Value))
				case "exclusive_use", "wb_only", "inactivity_timeout", "ip_limit", "camp_disconnect":
					fatalf("receiver refused: %s=%s", p.Name, p.Value)
				case "version_maj":
					version = p.Value
				case "version_min":
					version += "." + p.Value
				case "audio_rate":
					// Server tells us its nominal rate; we acknowledge with
					// our output rate, as the browser UI does.
					send("SET AR OK in=" + p.Value + " out=44100")
				case "sample_rate":
					sr, err := strconv.ParseFloat(p.Value, 64)
					if err != nil || !rateOK(sr) {
						fatalf("receiver reported unexpected sample_rate=%q", p.Value)
					}
					sampleRate = sr
					want = int(*secs * sr)
					if started {
						break
					}
					started = true
					// Step 2: configure the channel. Order follows the
					// browser UI and kiwiclient; keepalive is required
					// within KEEPALIVE_SEC or the server kicks us.
					send("SET squelch=0 max=0")
					send("SET genattn=0")
					send("SET gen=0 mix=-1")
					// Server parses with sscanf %256ms: stops at whitespace, so
					// spaces must be %20 (not '+', which it would keep literally).
					send("SET ident_user=" + strings.ReplaceAll(url.QueryEscape(ident), "+", "%20"))
					send(fmt.Sprintf("SET mod=%s low_cut=%d high_cut=%d freq=%.3f", *mode, pb[0], pb[1], *freq))
					send("SET agc=1 hang=0 thresh=-100 slope=6 decay=1000 manGain=50")
					if *noComp {
						send("SET compression=0")
					}
					send("SET keepalive")
					lastKA = time.Now()
				}
			}
		case "SND":
			f, err := kiwi.ParseSND(body)
			if err != nil {
				log.Printf("bad SND frame: %v", err)
				continue
			}
			if frames == 0 {
				firstFlags = f.Flags
				// The first buffer may be leftover from the channel's previous
				// user; kiwiclient discards its RSSI for the same reason.
			} else {
				if f.Seq != lastSeq+1 {
					seqGaps++
				}
				r := f.RSSI()
				rssiSum += r
				rssiMin = math.Min(rssiMin, r)
				rssiMax = math.Max(rssiMax, r)
			}
			lastSeq = f.Seq
			frames++
			audioBytes += len(f.Audio)
			c := 0
			if f.Compressed() {
				c = 1
			}
			if compressed != -1 && compressed != c {
				log.Printf("compression flag changed mid-stream: %d -> %d (flags=0x%02x)", compressed, c, f.Flags)
			}
			compressed = c
			if f.Flags&kiwi.FlagRestart != 0 {
				dec.Reset()
			}
			samples = kiwi.DecodeAudio(samples, &f, &dec)
			if time.Since(lastKA) >= time.Second {
				send("SET keepalive")
				lastKA = time.Now()
			}
			if started && len(samples) >= want {
				goto done
			}
		default:
			log.Printf("unexpected tag %q (%d bytes)", tag, len(body))
		}
	}
done:
	elapsed := time.Since(t0)
	if err := conn.Close(); err != nil {
		log.Printf("close: %v", err)
	}

	if sampleRate == 0 {
		log.Fatal("never received sample_rate; nothing recorded")
	}
	fh, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	if err := wav.Write(fh, int(math.Round(sampleRate)), samples); err != nil {
		log.Fatal(err)
	}
	fh.Close()

	fmt.Println()
	fmt.Printf("receiver        %s\n", *rawURL)
	fmt.Printf("kiwi version    %s\n", version)
	fmt.Printf("sample_rate     %.6f Hz\n", sampleRate)
	fmt.Printf("frames          %d (seq gaps: %d)\n", frames, seqGaps)
	fmt.Printf("first flags     0x%02x compressed=%v\n", firstFlags, firstFlags&kiwi.FlagCompressed != 0)
	fmt.Printf("audio bytes     %d -> %d samples (%.2f s)\n", audioBytes, len(samples), float64(len(samples))/sampleRate)
	if frames > 1 {
		fmt.Printf("rssi dBm        avg %.1f  min %.1f  max %.1f\n", rssiSum/float64(frames-1), rssiMin, rssiMax)
	}
	fmt.Printf("wall time       %.1fs\n", elapsed.Seconds())
	fmt.Printf("MSG names seen  %s\n", keys(msgNames))
	fmt.Printf("wrote           %s\n", *out)
}

func toWSURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("url missing host")
	}
	// kiwirecorder-style path: /<timestamp>/SND. The server classifies
	// this form as an external-API client subject to the ext_api limit.
	ts := uint32(time.Now().Unix())
	u.Path = fmt.Sprintf("/%d/SND", ts)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func rateOK(sr float64) bool {
	for _, e := range expectedRates {
		if math.Abs(sr-e)/e < 0.01 {
			return true
		}
	}
	return false
}

func badpText(v string) string {
	switch v {
	case "1":
		return "bad password, or all no-password channels busy"
	case "2":
		return "server still determining local interface address"
	case "3":
		return "admin connection not allowed from this IP"
	case "4":
		return "no admin password set"
	case "5":
		return "no multiple connections from the same IP"
	case "6":
		return "database update in progress"
	case "7":
		return "another admin connection already open"
	}
	return "unknown"
}

func keys(m map[string]int) string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	// deterministic enough for a report
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return strings.Join(s, " ")
}
