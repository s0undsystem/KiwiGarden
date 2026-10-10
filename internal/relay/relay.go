// Package relay owns the connection to a KiwiSDR receiver on behalf of one
// browser session: it dials through the network policy, speaks the
// protocol, decodes audio, enforces every per-session limit, and hands
// decoded PCM and status events to a Sink.
package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/directory"
	"github.com/s0undsystem/KiwiGarden/internal/kiwi"
	"github.com/s0undsystem/KiwiGarden/internal/kiwiws"
	"github.com/s0undsystem/KiwiGarden/internal/netpolicy"
	"github.com/s0undsystem/KiwiGarden/internal/sanitize"
)

// Ident names us honestly to receiver operators.
const Ident = "Kiwi Garden (github.com/s0undsystem/KiwiGarden)"

// Config holds the limits. Zero values take the documented defaults.
type Config struct {
	Policy              netpolicy.Policy
	MaxSessions         int           // default 3
	MaxDuration         time.Duration // default 90 min
	MaxRxBytes          int64         // from receiver, default 256 MiB
	MaxTxBytes          int64         // to browser, default 1 GiB
	DialTimeout         time.Duration // default 10 s
	FirstMessageTimeout time.Duration // after handshake, default 10 s
	ReadTimeout         time.Duration // between messages, default 15 s
	MaxRxRate           int           // bytes/s averaged over RateWindow, default 512 KiB
	RateWindow          time.Duration // default 2 s
	KeepaliveInterval   time.Duration // default 1 s
	BackoffBase         time.Duration // default 5 s
	BackoffMax          time.Duration // default 10 min
	SuccessAfter        time.Duration // audio time that clears backoff, default 30 s
	MaxMessageBytes     int           // websocket message cap, default 256 KiB
}

func (c Config) withDefaults() Config {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 3
	}
	def(&c.MaxDuration, 90*time.Minute)
	if c.MaxRxBytes <= 0 {
		c.MaxRxBytes = 256 << 20
	}
	if c.MaxTxBytes <= 0 {
		c.MaxTxBytes = 1 << 30
	}
	def(&c.DialTimeout, 10*time.Second)
	def(&c.FirstMessageTimeout, 10*time.Second)
	def(&c.ReadTimeout, 15*time.Second)
	if c.MaxRxRate <= 0 {
		c.MaxRxRate = 512 << 10
	}
	def(&c.RateWindow, 2*time.Second)
	def(&c.KeepaliveInterval, time.Second)
	def(&c.BackoffBase, 5*time.Second)
	def(&c.BackoffMax, 10*time.Minute)
	def(&c.SuccessAfter, 30*time.Second)
	if c.MaxMessageBytes <= 0 {
		c.MaxMessageBytes = 256 << 10
	}
	return c
}

// Modes we offer and their default passbands (Hz), matching the KiwiSDR UI.
var Modes = map[string][2]int{
	"am":  {-4900, 4900},
	"usb": {300, 2700},
	"lsb": {-2700, -300},
	"cw":  {300, 700},
}

// Frequency limits in kHz. Receivers report their own bandwidth; 30 MHz
// covers every standard KiwiSDR.
const (
	MinFreqKHz = 0
	MaxFreqKHz = 30000
)

// Reason is a machine-readable close reason shown to the user.
type Reason string

const (
	ReasonUser           Reason = "closed_by_user"
	ReasonReceiverClosed Reason = "receiver_closed"
	ReasonReceiverFull   Reason = "receiver_full"
	ReasonRefused        Reason = "receiver_refused"
	ReasonDown           Reason = "receiver_down"
	ReasonRedirect       Reason = "redirect_refused"
	ReasonTimeout        Reason = "timeout"
	ReasonProtocol       Reason = "protocol_error"
	ReasonRateLimit      Reason = "rate_limited"
	ReasonDuration       Reason = "duration_limit"
	ReasonBytes          Reason = "bytes_limit"
	ReasonNetwork        Reason = "network_error"
	ReasonSampleRate     Reason = "unexpected_sample_rate"
	ReasonBackoff        Reason = "backoff"
	ReasonBusyLocal      Reason = "session_limit"
	ReasonDuplicate      Reason = "already_connected"
	ReasonNotAllowed     Reason = "receiver_disallows_apps"
)

// CloseError carries the reason a session ended.
type CloseError struct {
	Reason     Reason
	Detail     string
	RetryAfter time.Duration
}

func (e *CloseError) Error() string {
	if e.Detail != "" {
		return string(e.Reason) + ": " + e.Detail
	}
	return string(e.Reason)
}

// AudioFrame is one decoded audio frame.
type AudioFrame struct {
	Seq        uint32
	Flags      byte
	RSSI       float64 // dBm
	SampleRate float64
	PCM        []int16
}

// Status is a lifecycle event.
type Status struct {
	State      string  // "connecting", "connected", "closed"
	Reason     Reason  // for "closed"
	Detail     string  // sanitised, for "closed"
	SampleRate float64 // for "connected"
	Version    string  // receiver firmware, sanitised, for "connected"
}

// Sink receives events. Methods are called from the session goroutine and
// must return promptly; an error from either ends the session.
type Sink interface {
	Audio(f AudioFrame) error
	Status(s Status) error
}

// Manager enforces global limits: concurrent sessions, one per receiver,
// and per-receiver backoff.
type Manager struct {
	cfg Config

	mu       sync.Mutex
	sessions map[string]*Session // keyed by receiver host
	backoff  map[string]*backoffState
}

type backoffState struct {
	failures int
	until    time.Time
}

// NewManager creates a manager.
func NewManager(cfg Config) *Manager {
	return &Manager{
		cfg:      cfg.withDefaults(),
		sessions: make(map[string]*Session),
		backoff:  make(map[string]*backoffState),
	}
}

// ValidateTune checks a frequency/mode pair from the browser.
func ValidateTune(freqKHz float64, mode string) (float64, string, error) {
	if math.IsNaN(freqKHz) || math.IsInf(freqKHz, 0) || freqKHz < MinFreqKHz || freqKHz > MaxFreqKHz {
		return 0, "", errors.New("frequency out of range")
	}
	f := math.Round(freqKHz*1000) / 1000
	m := strings.ToLower(mode)
	if _, ok := Modes[m]; !ok {
		return 0, "", errors.New("unknown mode")
	}
	return f, m, nil
}

// Open starts a session to rx. It returns quickly; connection progress is
// reported through sink. Errors returned here are local refusals.
func (m *Manager) Open(ctx context.Context, rx *directory.Receiver, freqKHz float64, mode string, sink Sink) (*Session, error) {
	freq, mode, err := ValidateTune(freqKHz, mode)
	if err != nil {
		return nil, &CloseError{Reason: ReasonProtocol, Detail: err.Error()}
	}
	if rx.ExtAPI == 0 {
		return nil, &CloseError{Reason: ReasonNotAllowed, Detail: "receiver does not allow external clients"}
	}

	m.mu.Lock()
	if _, dup := m.sessions[rx.Host]; dup {
		m.mu.Unlock()
		return nil, &CloseError{Reason: ReasonDuplicate}
	}
	if len(m.sessions) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		return nil, &CloseError{Reason: ReasonBusyLocal, Detail: fmt.Sprintf("at most %d sessions", m.cfg.MaxSessions)}
	}
	if b := m.backoff[rx.Host]; b != nil && time.Now().Before(b.until) {
		m.mu.Unlock()
		return nil, &CloseError{Reason: ReasonBackoff, RetryAfter: time.Until(b.until), Detail: "receiver recently failed"}
	}
	sctx, cancel := context.WithCancel(ctx)
	s := &Session{
		m: m, rx: rx, sink: sink, cfg: m.cfg,
		ctx: sctx, cancel: cancel,
		done:  make(chan struct{}),
		freq:  freq,
		mode:  mode,
		start: time.Now(),
	}
	m.sessions[rx.Host] = s
	m.mu.Unlock()

	go s.run()
	return s, nil
}

// ActiveSessions reports the current count.
func (m *Manager) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func (m *Manager) remove(s *Session, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[s.rx.Host] == s {
		delete(m.sessions, s.rx.Host)
	}
	if success {
		delete(m.backoff, s.rx.Host)
		return
	}
	b := m.backoff[s.rx.Host]
	if b == nil {
		b = &backoffState{}
		m.backoff[s.rx.Host] = b
	}
	b.failures++
	d := m.cfg.BackoffBase << (b.failures - 1)
	if b.failures > 20 || d > m.cfg.BackoffMax || d <= 0 {
		d = m.cfg.BackoffMax
	}
	b.until = time.Now().Add(d)
}

// Session is one relay connection.
type Session struct {
	m    *Manager
	rx   *directory.Receiver
	sink Sink
	cfg  Config

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	start  time.Time

	connMu sync.Mutex
	conn   *kiwiws.Conn

	tuneMu sync.Mutex
	freq   float64
	mode   string

	errMu sync.Mutex
	err   *CloseError

	// stats
	rxBytes, txBytes int64
	audioSamples     int64
	sampleRate       float64
}

// Done is closed when the session has fully stopped (all goroutines gone).
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns the close reason after Done.
func (s *Session) Err() *CloseError {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// Receiver returns the receiver this session is for.
func (s *Session) Receiver() *directory.Receiver { return s.rx }

// Close ends the session (user request) and waits for it to stop.
func (s *Session) Close() {
	s.fail(&CloseError{Reason: ReasonUser})
	<-s.done
}

// Tune changes frequency/mode on the live connection.
func (s *Session) Tune(freqKHz float64, mode string) error {
	freq, mode, err := ValidateTune(freqKHz, mode)
	if err != nil {
		return err
	}
	s.tuneMu.Lock()
	s.freq, s.mode = freq, mode
	s.tuneMu.Unlock()
	s.connMu.Lock()
	c := s.conn
	s.connMu.Unlock()
	if c == nil {
		return nil // applied when the connection comes up
	}
	return c.WriteText(s.modCommand())
}

func (s *Session) modCommand() string {
	s.tuneMu.Lock()
	defer s.tuneMu.Unlock()
	pb := Modes[s.mode]
	return fmt.Sprintf("SET mod=%s low_cut=%d high_cut=%d freq=%.3f", s.mode, pb[0], pb[1], s.freq)
}

// fail records the first close reason and cancels the context.
func (s *Session) fail(e *CloseError) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = e
	}
	s.errMu.Unlock()
	s.cancel()
}

func (s *Session) run() {
	log := slog.With("rx", s.rx.Host)
	var wg sync.WaitGroup
	defer func() {
		if r := recover(); r != nil {
			// A panic in the decoder must never take the relay down.
			log.Error("relay session panic", "panic", fmt.Sprint(r))
			s.fail(&CloseError{Reason: ReasonProtocol, Detail: "internal error"})
		}
		s.cancel()
		s.connMu.Lock()
		if s.conn != nil {
			s.conn.Close()
		}
		s.connMu.Unlock()
		wg.Wait()
		e := s.Err()
		if e == nil {
			e = &CloseError{Reason: ReasonReceiverClosed}
			s.errMu.Lock()
			s.err = e
			s.errMu.Unlock()
		}
		success := s.sampleRate > 0 && float64(s.audioSamples)/s.sampleRate >= s.cfg.SuccessAfter.Seconds()
		s.m.remove(s, success)
		_ = s.sink.Status(Status{State: "closed", Reason: e.Reason, Detail: e.Detail})
		log.Info("relay session closed", "reason", e.Reason, "detail", sanitize.ForLog(e.Detail, 120),
			"rx_bytes", s.rxBytes, "tx_bytes", s.txBytes, "audio_s", s.audioSeconds(), "elapsed", time.Since(s.start).Round(time.Second))
		close(s.done)
	}()

	if err := s.sink.Status(Status{State: "connecting"}); err != nil {
		s.fail(&CloseError{Reason: ReasonUser})
		return
	}

	// --- dial ---------------------------------------------------------------
	wsURL := s.rx.WSURL() + "/" + strconv.FormatInt(time.Now().Unix()&0xffffffff, 10) + "/SND"
	dctx, dcancel := context.WithTimeout(s.ctx, s.cfg.DialTimeout+s.cfg.DialTimeout)
	conn, err := kiwiws.Dial(dctx, wsURL, &kiwiws.Options{
		Dialer:           s.cfg.Policy.Dialer(s.cfg.DialTimeout),
		UserAgent:        Ident,
		MaxMessageBytes:  s.cfg.MaxMessageBytes,
		HandshakeTimeout: s.cfg.DialTimeout,
		ReadTimeout:      s.cfg.FirstMessageTimeout,
		WriteTimeout:     5 * time.Second,
	})
	dcancel()
	if err != nil {
		var nu *kiwiws.ErrNotUpgraded
		switch {
		case errors.As(err, &nu):
			if nu.Location != "" {
				log.Warn("receiver redirected; refused", "status", nu.StatusCode, "location", sanitize.ForLog(nu.Location, 100))
				s.fail(&CloseError{Reason: ReasonRedirect, Detail: fmt.Sprintf("HTTP %d", nu.StatusCode)})
			} else {
				s.fail(&CloseError{Reason: ReasonRefused, Detail: fmt.Sprintf("HTTP %d", nu.StatusCode)})
			}
		case errors.Is(err, netpolicy.ErrForbidden):
			log.Warn("dial refused by policy", "err", err)
			s.fail(&CloseError{Reason: ReasonRefused, Detail: "address not allowed"})
		default:
			s.fail(&CloseError{Reason: ReasonNetwork, Detail: "connect failed"})
		}
		return
	}
	s.connMu.Lock()
	s.conn = conn
	s.connMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}

	// Hard duration cap.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTimer(s.cfg.MaxDuration)
		defer t.Stop()
		select {
		case <-t.C:
			s.fail(&CloseError{Reason: ReasonDuration})
		case <-s.ctx.Done():
		}
	}()

	if err := conn.WriteText("SET auth t=kiwi p="); err != nil {
		s.fail(&CloseError{Reason: ReasonNetwork, Detail: "send failed"})
		return
	}

	// Keepalive pump. The server kicks after 60 s without one.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(s.cfg.KeepaliveInterval)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				if err := conn.WriteText("SET keepalive"); err != nil {
					s.fail(&CloseError{Reason: ReasonNetwork, Detail: "send failed"})
					return
				}
			}
		}
	}()

	// --- read loop ----------------------------------------------------------
	var (
		dec        kiwi.ADPCM
		configured bool
		first      = true
		version    string
		lastSeq    uint32
		pcm        = make([]int16, 0, 4096)
		rate       = rateWindow{window: s.cfg.RateWindow, limit: int64(s.cfg.MaxRxRate)}
	)
	for s.ctx.Err() == nil {
		op, msg, err := conn.Read()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			var ce *kiwiws.ErrClosed
			switch {
			case errors.As(err, &ce):
				s.fail(&CloseError{Reason: ReasonReceiverClosed, Detail: fmt.Sprintf("code %d", ce.Code)})
			case isTimeout(err):
				if first {
					s.fail(&CloseError{Reason: ReasonTimeout, Detail: "receiver sent nothing after handshake (busy or external clients disallowed)"})
				} else {
					s.fail(&CloseError{Reason: ReasonTimeout, Detail: "receiver stopped sending"})
				}
			case strings.Contains(err.Error(), "websocket:"):
				log.Warn("protocol error from receiver", "err", err)
				s.fail(&CloseError{Reason: ReasonProtocol, Detail: "malformed frame"})
			default:
				s.fail(&CloseError{Reason: ReasonNetwork, Detail: "read failed"})
			}
			return
		}
		_ = op
		if first {
			first = false
			conn.SetReadTimeout(s.cfg.ReadTimeout)
		}
		s.rxBytes += int64(len(msg))
		if s.rxBytes > s.cfg.MaxRxBytes {
			s.fail(&CloseError{Reason: ReasonBytes, Detail: "received bytes limit"})
			return
		}
		if !rate.add(len(msg), time.Now()) {
			log.Warn("receiver exceeded inbound rate limit")
			s.fail(&CloseError{Reason: ReasonRateLimit, Detail: "receiver flooding"})
			return
		}

		tag, body, ok := kiwi.SplitTag(msg)
		if !ok {
			continue // too short to matter; counted against rate and bytes
		}
		switch tag {
		case "MSG":
			params, _ := kiwi.ParseMSG(body)
			for _, p := range params {
				switch p.Name {
				case "badp":
					switch p.Value {
					case "0":
					case "1":
						s.fail(&CloseError{Reason: ReasonReceiverFull, Detail: "all public channels in use"})
						return
					case "5":
						s.fail(&CloseError{Reason: ReasonRefused, Detail: "receiver allows one connection per IP"})
						return
					default:
						s.fail(&CloseError{Reason: ReasonRefused, Detail: "auth rejected"})
						return
					}
				case "too_busy":
					s.fail(&CloseError{Reason: ReasonReceiverFull, Detail: "all channels in use"})
					return
				case "down":
					s.fail(&CloseError{Reason: ReasonDown})
					return
				case "redirect":
					log.Warn("receiver sent redirect message; refused", "to", sanitize.ForLog(kiwi.Unescape(p.Value), 100))
					s.fail(&CloseError{Reason: ReasonRedirect})
					return
				case "exclusive_use", "wb_only", "inactivity_timeout", "ip_limit", "camp_disconnect":
					s.fail(&CloseError{Reason: ReasonRefused, Detail: p.Name})
					return
				case "version_maj":
					version = sanitize.Text(p.Value, 8)
				case "version_min":
					version = sanitize.Text(version+"."+p.Value, 16)
				case "audio_rate":
					if n, err := strconv.Atoi(p.Value); err == nil && n > 0 && n < 1_000_000 {
						if err := conn.WriteText("SET AR OK in=" + strconv.Itoa(n) + " out=44100"); err != nil {
							s.fail(&CloseError{Reason: ReasonNetwork, Detail: "send failed"})
							return
						}
					}
				case "sample_rate":
					sr, err := strconv.ParseFloat(p.Value, 64)
					if err != nil || !kiwi.SampleRateOK(sr) {
						log.Warn("unexpected sample rate", "value", sanitize.ForLog(p.Value, 32))
						s.fail(&CloseError{Reason: ReasonSampleRate})
						return
					}
					s.sampleRate = sr
					if configured {
						break
					}
					configured = true
					for _, cmd := range []string{
						"SET squelch=0 max=0",
						"SET genattn=0",
						"SET gen=0 mix=-1",
						"SET ident_user=" + strings.ReplaceAll(url.QueryEscape(Ident), "+", "%20"),
						s.modCommand(),
						"SET agc=1 hang=0 thresh=-100 slope=6 decay=1000 manGain=50",
						"SET keepalive",
					} {
						if err := conn.WriteText(cmd); err != nil {
							s.fail(&CloseError{Reason: ReasonNetwork, Detail: "send failed"})
							return
						}
					}
					if err := s.sink.Status(Status{State: "connected", SampleRate: sr, Version: version}); err != nil {
						s.fail(&CloseError{Reason: ReasonUser})
						return
					}
				}
			}
		case "SND":
			if s.sampleRate == 0 {
				continue // audio before sample_rate: ignore, cannot interpret
			}
			f, err := kiwi.ParseSND(body)
			if err != nil {
				log.Warn("bad SND frame", "err", err)
				s.fail(&CloseError{Reason: ReasonProtocol, Detail: "bad audio frame"})
				return
			}
			if f.Flags&kiwi.FlagStereo != 0 {
				// We never request IQ; a stereo frame means a hostile or
				// confused receiver.
				s.fail(&CloseError{Reason: ReasonProtocol, Detail: "unexpected stereo frame"})
				return
			}
			if f.Flags&kiwi.FlagRestart != 0 {
				dec.Reset()
			}
			if s.audioSamples > 0 && f.Seq != lastSeq+1 {
				log.Debug("audio sequence gap", "expected", lastSeq+1, "got", f.Seq)
			}
			lastSeq = f.Seq
			pcm = kiwi.DecodeAudio(pcm[:0], &f, &dec)
			s.audioSamples += int64(len(pcm))
			s.txBytes += int64(len(pcm) * 2)
			if s.txBytes > s.cfg.MaxTxBytes {
				s.fail(&CloseError{Reason: ReasonBytes, Detail: "sent bytes limit"})
				return
			}
			out := make([]int16, len(pcm))
			copy(out, pcm)
			if err := s.sink.Audio(AudioFrame{Seq: f.Seq, Flags: f.Flags, RSSI: f.RSSI(), SampleRate: s.sampleRate, PCM: out}); err != nil {
				s.fail(&CloseError{Reason: ReasonUser})
				return
			}
		default:
			// W/F, EXT or garbage: never requested, ignore. Still counted
			// toward rate and byte caps above.
		}
	}
}

func (s *Session) audioSeconds() float64 {
	if s.sampleRate == 0 {
		return 0
	}
	return math.Round(float64(s.audioSamples)/s.sampleRate*10) / 10
}

func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

// rateWindow is a fixed-window byte counter.
type rateWindow struct {
	window time.Duration
	limit  int64 // bytes per second
	start  time.Time
	bytes  int64
}

func (r *rateWindow) add(n int, now time.Time) bool {
	if r.start.IsZero() || now.Sub(r.start) >= r.window {
		r.start, r.bytes = now, 0
	}
	r.bytes += int64(n)
	return r.bytes <= r.limit*int64(r.window/time.Second)
}
