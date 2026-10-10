// Package server is the local HTTP/WebSocket front door: static UI, the
// receiver list API, and the audio WebSocket. Everything in
// THREAT_MODEL.md section 4.3 lives here.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/directory"
	"github.com/s0undsystem/KiwiGarden/internal/kiwiws"
	"github.com/s0undsystem/KiwiGarden/internal/relay"
)

// CSP for the HTML page. Phase 2 UI must work under this exactly.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'self'; worker-src 'self'; media-src 'self'; base-uri 'none'; form-action 'none'; " +
	"frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types kg"

// TokenHeader carries the session token on API requests.
const TokenHeader = "X-Kiwi-Token"

// Limits for browser-originated input.
const (
	maxClientMessage = 4 << 10
	clientMsgPerSec  = 20
	authTimeout      = 5 * time.Second
	clientIdle       = 120 * time.Second
	writeTimeout     = 5 * time.Second
)

// Server is the local front door.
type Server struct {
	addr   string // "127.0.0.1:port" as bound
	origin string // "http://127.0.0.1:port"
	token  []byte // raw 32 bytes
	tokHex string

	dir   *directory.Store
	relay *relay.Manager
	ui    fs.FS
	mux   *http.ServeMux
	log   *slog.Logger
}

// New builds a server. ui is the embedded front end (may be nil in tests).
func New(dir *directory.Store, rm *relay.Manager, ui fs.FS) (*Server, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	s := &Server{token: tok, tokHex: hex.EncodeToString(tok), dir: dir, relay: rm, ui: ui, log: slog.Default()}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /api/receivers", s.apiReceivers)
	s.mux.HandleFunc("GET /api/stream", s.wsStream)
	s.mux.HandleFunc("GET /", s.static)
	return s, nil
}

// Token returns the hex session token, for printing the launch URL once.
// Callers must not log it anywhere else.
func (s *Server) Token() string { return s.tokHex }

// UseToken replaces the random token. Only the -dev flag uses this, to keep
// the token stable across restarts while working on the UI. Must be 32 bytes.
func (s *Server) UseToken(raw []byte) error {
	if len(raw) != 32 {
		return errors.New("token must be 32 bytes")
	}
	s.token = append([]byte(nil), raw...)
	s.tokHex = hex.EncodeToString(s.token)
	return nil
}

// Listen binds 127.0.0.1:port (0 = ephemeral) and returns the listener.
func (s *Server) Listen(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	s.addr = ln.Addr().String()
	s.origin = "http://" + s.addr
	return ln, nil
}

// Addr returns the bound address after Listen.
func (s *Server) Addr() string { return s.addr }

// LaunchURL is the one-time URL with the token in the fragment.
func (s *Server) LaunchURL() string { return s.origin + "/#" + s.tokHex }

// HTTPServer returns a configured *http.Server.
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          nil,
	}
}

// ServeHTTP applies the header checks and security headers to every route.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.checkHost(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.checkOrigin(r, false); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// checkHost requires Host to be exactly our bound address. Defeats DNS
// rebinding and any "localhost" alias games.
func (s *Server) checkHost(r *http.Request) error {
	if r.Host != s.addr {
		return fmt.Errorf("bad host %q", r.Host)
	}
	return nil
}

// checkOrigin enforces Origin and Sec-Fetch-Site. For API/WebSocket routes
// (strict) an Origin is required and must match; Sec-Fetch-Site must be
// same-origin. For the page and assets, Origin is optional but must match
// when present, and Sec-Fetch-Site may be none/same-origin.
func (s *Server) checkOrigin(r *http.Request, strict bool) error {
	origin := r.Header.Get("Origin")
	if origin != "" && origin != s.origin {
		return fmt.Errorf("bad origin")
	}
	sfs := r.Header.Get("Sec-Fetch-Site")
	switch sfs {
	case "", "same-origin":
	case "none":
		if strict {
			return errors.New("direct navigation to API")
		}
	default:
		return fmt.Errorf("sec-fetch-site %q", sfs)
	}
	if strict && origin == "" && sfs == "" {
		// Neither header: not a browser fetch from our page. Still allow
		// if the token proves it (checked by caller), since curl-style
		// local tooling has no Origin. The token is the real gate.
		return nil
	}
	if strict && origin == "" && r.Header.Get("Upgrade") != "" {
		return errors.New("websocket without origin")
	}
	return nil
}

func (s *Server) checkToken(given string) bool {
	if len(given) != len(s.tokHex) {
		return false
	}
	raw, err := hex.DecodeString(given)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(raw, s.token) == 1
}

// --- routes ---------------------------------------------------------------------

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if s.ui == nil {
		http.Error(w, "ui not built", http.StatusNotFound)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}
	if strings.Contains(p, "..") {
		http.NotFound(w, r)
		return
	}
	f, err := s.ui.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	ct := contentType(p)
	w.Header().Set("Content-Type", ct)
	if strings.HasPrefix(ct, "text/html") {
		w.Header().Set("Content-Security-Policy", CSP)
	} else {
		// Hashed asset names are immutable; the HTML is not.
		w.Header().Set("Cache-Control", "private, max-age=3600")
	}
	rs, ok := f.(interface {
		fs.File
		Seek(int64, int) (int64, error)
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, p, st.ModTime(), rs)
}

func contentType(p string) string {
	switch {
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(p, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(p, ".json"):
		return "application/json"
	case strings.HasSuffix(p, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(p, ".png"):
		return "image/png"
	case strings.HasSuffix(p, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(p, ".bin"):
		return "application/octet-stream"
	}
	return "application/octet-stream"
}

// receiverJSON is what the browser sees: no URL, no host, no port.
type receiverJSON struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Loc      string  `json:"loc"`
	Antenna  string  `json:"antenna"`
	Version  string  `json:"version"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Users    int     `json:"users"`
	UsersMax int     `json:"usersMax"`
	ExtAPI   int     `json:"extApi"`
	SNR      int     `json:"snr"`
	Offline  bool    `json:"offline"`
}

func (s *Server) apiReceivers(w http.ResponseWriter, r *http.Request) {
	if err := s.checkOrigin(r, true); err != nil || !s.checkToken(r.Header.Get(TokenHeader)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	snap := s.dir.Current()
	if snap == nil {
		http.Error(w, "directory not loaded", http.StatusServiceUnavailable)
		return
	}
	out := struct {
		FetchedAt string         `json:"fetchedAt"`
		FromCache bool           `json:"fromCache"`
		Receivers []receiverJSON `json:"receivers"`
	}{FetchedAt: snap.FetchedAt.UTC().Format(time.RFC3339), FromCache: snap.FromCache}
	out.Receivers = make([]receiverJSON, 0, len(snap.Receivers))
	for i := range snap.Receivers {
		rx := &snap.Receivers[i]
		out.Receivers = append(out.Receivers, receiverJSON{
			ID: rx.ID, Name: rx.Name, Loc: rx.Loc, Antenna: rx.Antenna, Version: rx.Version,
			Lat: rx.Lat, Lon: rx.Lon, Users: rx.Users, UsersMax: rx.UsersMax, ExtAPI: rx.ExtAPI,
			SNR: rx.SNR, Offline: rx.Offline,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// --- websocket ------------------------------------------------------------------

// Client → server messages.
type clientMsg struct {
	Type  string  `json:"type"` // auth | connect | tune | disconnect
	Token string  `json:"token,omitempty"`
	RX    string  `json:"rx,omitempty"`
	Freq  float64 `json:"freq,omitempty"`
	Mode  string  `json:"mode,omitempty"`
}

// Server → client status message (text frame).
type statusMsg struct {
	Type       string  `json:"type"` // status
	State      string  `json:"state"`
	Reason     string  `json:"reason,omitempty"`
	Detail     string  `json:"detail,omitempty"`
	RetryAfter float64 `json:"retryAfter,omitempty"`
	SampleRate float64 `json:"sampleRate,omitempty"`
	Version    string  `json:"version,omitempty"`
	RX         string  `json:"rx,omitempty"`
	Name       string  `json:"name,omitempty"`
}

// Audio frames to the browser are binary:
//
//	u8  type = 1
//	u8  flags (receiver flags byte)
//	u16 rssi  (little-endian, (dBm + 127) * 10)
//	u32 seq   (little-endian)
//	int16 PCM little-endian ...
const audioHeaderLen = 8

// wsSink adapts a browser WebSocket to relay.Sink.
type wsSink struct {
	conn *kiwiws.Conn
	rxID string
	name string
	buf  []byte
}

func (k *wsSink) Audio(f relay.AudioFrame) error {
	need := audioHeaderLen + 2*len(f.PCM)
	if cap(k.buf) < need {
		k.buf = make([]byte, need)
	}
	b := k.buf[:need]
	b[0] = 1
	b[1] = f.Flags
	rssi := (f.RSSI + 127) * 10
	if rssi < 0 {
		rssi = 0
	}
	if rssi > 65535 {
		rssi = 65535
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(rssi))
	binary.LittleEndian.PutUint32(b[4:], f.Seq)
	for i, v := range f.PCM {
		binary.LittleEndian.PutUint16(b[audioHeaderLen+2*i:], uint16(v))
	}
	return k.conn.WriteBinary(b)
}

func (k *wsSink) Status(st relay.Status) error {
	m := statusMsg{Type: "status", State: st.State, Reason: string(st.Reason), Detail: st.Detail,
		SampleRate: st.SampleRate, Version: st.Version, RX: k.rxID, Name: k.name}
	js, _ := json.Marshal(m)
	return k.conn.WriteText(string(js))
}

func (s *Server) wsStream(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.origin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.checkOrigin(r, true); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := kiwiws.Accept(w, r, &kiwiws.Options{
		MaxMessageBytes: maxClientMessage,
		ReadTimeout:     authTimeout,
		WriteTimeout:    writeTimeout,
	})
	if err != nil {
		return
	}
	go s.serveWS(conn)
}

func (s *Server) serveWS(conn *kiwiws.Conn) {
	defer conn.Close()
	send := func(m statusMsg) {
		m.Type = "status"
		js, _ := json.Marshal(m)
		_ = conn.WriteText(string(js))
	}

	// First message must be auth, within authTimeout.
	var m clientMsg
	if err := readJSON(conn, &m); err != nil || m.Type != "auth" || !s.checkToken(m.Token) {
		conn.CloseWithReason(4001, "unauthorized")
		return
	}
	conn.SetReadTimeout(clientIdle)
	send(statusMsg{State: "ready"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var sess *relay.Session
	closeSess := func() {
		if sess != nil {
			sess.Close()
			sess = nil
		}
	}
	defer closeSess()

	limiter := newRateLimiter(clientMsgPerSec)
	for {
		var m clientMsg
		if err := readJSON(conn, &m); err != nil {
			return // browser went away or sent junk; defer closes the receiver session
		}
		if !limiter.allow(time.Now()) {
			conn.CloseWithReason(4008, "too many messages")
			return
		}
		switch m.Type {
		case "connect":
			closeSess()
			snap := s.dir.Current()
			rx, ok := snap.Lookup(m.RX)
			if !ok {
				send(statusMsg{State: "closed", Reason: "unknown_receiver"})
				continue
			}
			sink := &wsSink{conn: conn, rxID: rx.ID, name: rx.Name}
			sess2, err := s.relay.Open(ctx, rx, m.Freq, m.Mode, sink)
			if err != nil {
				var ce *relay.CloseError
				if errors.As(err, &ce) {
					send(statusMsg{State: "closed", Reason: string(ce.Reason), Detail: ce.Detail,
						RetryAfter: ce.RetryAfter.Seconds(), RX: rx.ID, Name: rx.Name})
				} else {
					send(statusMsg{State: "closed", Reason: "error", RX: rx.ID, Name: rx.Name})
				}
				continue
			}
			sess = sess2
		case "tune":
			if sess == nil {
				continue
			}
			if err := sess.Tune(m.Freq, m.Mode); errors.Is(err, relay.ErrInvalidTune) {
				send(statusMsg{State: "error", Detail: "bad tune request"})
			}
			// Any other error: the receiver connection is dying and the
			// session will deliver its own "closed" status with the reason.
		case "disconnect":
			closeSess()
		case "ping":
			send(statusMsg{State: "pong"})
		default:
			conn.CloseWithReason(4002, "bad message")
			return
		}
	}
}

func readJSON(conn *kiwiws.Conn, v *clientMsg) error {
	op, p, err := conn.Read()
	if err != nil {
		return err
	}
	if op != kiwiws.OpText || len(p) > maxClientMessage {
		return errors.New("bad frame")
	}
	dec := json.NewDecoder(strings.NewReader(string(p)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if len(v.RX) > 64 || len(v.Mode) > 8 || len(v.Token) > 128 {
		return errors.New("field too long")
	}
	return nil
}

type rateLimiter struct {
	perSec int
	start  time.Time
	n      int
}

func newRateLimiter(perSec int) *rateLimiter { return &rateLimiter{perSec: perSec} }

func (l *rateLimiter) allow(now time.Time) bool {
	if now.Sub(l.start) >= time.Second {
		l.start, l.n = now, 0
	}
	l.n++
	return l.n <= l.perSec
}
