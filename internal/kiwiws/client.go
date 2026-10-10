// Package kiwiws is a deliberately small RFC 6455 WebSocket client used to
// talk to KiwiSDR receivers.
//
// It is written from the RFC rather than ported from another implementation
// so that every length field read from the network is bounds-checked here,
// in code we own. It supports exactly what the KiwiSDR protocol needs:
// an HTTP/1.1 upgrade handshake, masked client->server text frames,
// unmasked server->client binary/text frames, fragmentation with a total
// size cap, and ping/pong/close control frames.
//
// Nothing here follows redirects. A non-101 response is an error.
package kiwiws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Opcodes from RFC 6455 section 5.2.
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// ErrNotUpgraded is returned when the server answers the handshake with
// anything other than 101 Switching Protocols (including redirects).
type ErrNotUpgraded struct {
	StatusCode int
	Location   string
}

func (e *ErrNotUpgraded) Error() string {
	if e.Location != "" {
		return fmt.Sprintf("websocket handshake refused: HTTP %d (Location: %s)", e.StatusCode, e.Location)
	}
	return fmt.Sprintf("websocket handshake refused: HTTP %d", e.StatusCode)
}

// ErrClosed is returned from Read after the peer sent a close frame.
type ErrClosed struct {
	Code   uint16
	Reason string
}

func (e *ErrClosed) Error() string {
	return fmt.Sprintf("websocket closed by peer: code=%d reason=%q", e.Code, e.Reason)
}

// Options controls dialing and resource limits.
type Options struct {
	// Dialer performs the TCP connection. Its Control hook is where the
	// relay will later enforce the resolved-IP allowlist. If nil a plain
	// net.Dialer with a 10 s timeout is used.
	Dialer *net.Dialer
	// TLSConfig is used for wss:// URLs. nil means Go defaults (verify).
	TLSConfig *tls.Config
	// Origin, if non-empty, is sent as the Origin header. Browsers always
	// send one; kiwiclient sends none. Used to test receiver behaviour.
	Origin string
	// UserAgent is sent as User-Agent. Keep it honest.
	UserAgent string
	// MaxMessageBytes caps a complete (possibly fragmented) message.
	// Default 256 KiB, far above the largest KiwiSDR frame (~2 KiB SND,
	// ~10 KiB config MSG).
	MaxMessageBytes int
	// HandshakeTimeout bounds the HTTP upgrade exchange. Default 10 s.
	HandshakeTimeout time.Duration
	// ReadTimeout is the per-message read deadline. Default 15 s.
	ReadTimeout time.Duration
	// WriteTimeout is the per-frame write deadline. Default 5 s.
	WriteTimeout time.Duration

	// serverSide is set by Accept: servers must not mask (RFC 6455 5.1).
	serverSide bool
}

func (o *Options) withDefaults() Options {
	r := Options{}
	if o != nil {
		r = *o
	}
	if r.Dialer == nil {
		r.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	if r.MaxMessageBytes <= 0 {
		r.MaxMessageBytes = 256 << 10
	}
	if r.HandshakeTimeout <= 0 {
		r.HandshakeTimeout = 10 * time.Second
	}
	if r.ReadTimeout <= 0 {
		r.ReadTimeout = 15 * time.Second
	}
	if r.WriteTimeout <= 0 {
		r.WriteTimeout = 5 * time.Second
	}
	return r
}

// Conn is a WebSocket connection. Read and Write may be used from
// different goroutines; Write is serialized by a mutex.
type Conn struct {
	nc   net.Conn
	br   *bufio.Reader
	opts Options

	wmu    sync.Mutex
	closed bool
}

// Dial connects to a ws:// or wss:// URL and performs the opening handshake.
func Dial(ctx context.Context, rawURL string, opts *Options) (*Conn, error) {
	o := opts.withDefaults()

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	var secure bool
	switch u.Scheme {
	case "ws":
	case "wss":
		secure = true
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("missing host")
	}
	port := u.Port()
	if port == "" {
		if secure {
			port = "443"
		} else {
			port = "80"
		}
	}

	nc, err := o.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if secure {
		cfg := o.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			cfg = cfg.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		tc := tls.Client(nc, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			nc.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		nc = tc
	}

	c := &Conn{nc: nc, br: bufio.NewReaderSize(nc, 16<<10), opts: o}
	if err := c.handshake(u, host, port, secure); err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) handshake(u *url.URL, host, port string, secure bool) error {
	deadline := time.Now().Add(c.opts.HandshakeTimeout)
	if err := c.nc.SetDeadline(deadline); err != nil {
		return err
	}
	defer c.nc.SetDeadline(time.Time{})

	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])

	hostHdr := host
	if (secure && port != "443") || (!secure && port != "80") {
		hostHdr = net.JoinHostPort(host, port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", hostHdr)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	if c.opts.Origin != "" {
		fmt.Fprintf(&b, "Origin: %s\r\n", c.opts.Origin)
	}
	if c.opts.UserAgent != "" {
		fmt.Fprintf(&b, "User-Agent: %s\r\n", c.opts.UserAgent)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c.nc, b.String()); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	// http.ReadResponse bounds header size via the bufio reader and the
	// net/http header limits; we never read a body.
	resp, err := http.ReadResponse(c.br, &http.Request{Method: "GET"})
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return &ErrNotUpgraded{StatusCode: resp.StatusCode, Location: resp.Header.Get("Location")}
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade") {
		return errors.New("handshake: missing Upgrade/Connection headers")
	}
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if resp.Header.Get("Sec-WebSocket-Accept") != want {
		return errors.New("handshake: bad Sec-WebSocket-Accept")
	}
	return nil
}

// Read returns the next complete data message (text or binary). Control
// frames are handled internally: pings are answered, pongs ignored, and a
// close frame is echoed and reported as *ErrClosed. The returned slice is
// freshly allocated and owned by the caller.
func (c *Conn) Read() (opcode byte, payload []byte, err error) {
	var msg []byte
	var msgOp byte
	for {
		if err := c.nc.SetReadDeadline(time.Now().Add(c.opts.ReadTimeout)); err != nil {
			return 0, nil, err
		}
		fin, op, data, err := c.readFrame(c.opts.MaxMessageBytes - len(msg))
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case OpPing:
			if err := c.writeFrame(OpPong, data); err != nil {
				return 0, nil, err
			}
			continue
		case OpPong:
			continue
		case OpClose:
			ce := &ErrClosed{}
			if len(data) >= 2 {
				ce.Code = binary.BigEndian.Uint16(data)
				ce.Reason = string(data[2:])
			}
			_ = c.writeFrame(OpClose, data[:min(len(data), 2)])
			c.markClosed()
			return 0, nil, ce
		case OpText, OpBinary:
			if msg != nil {
				return 0, nil, errors.New("websocket: new data frame while message in progress")
			}
			msgOp = op
			msg = data
		case OpContinuation:
			if msg == nil {
				return 0, nil, errors.New("websocket: continuation without start")
			}
			msg = append(msg, data...)
		default:
			return 0, nil, fmt.Errorf("websocket: reserved opcode %d", op)
		}
		if fin {
			return msgOp, msg, nil
		}
	}
}

// readFrame reads one frame. remaining is the number of payload bytes the
// caller is still willing to accept; a larger frame is a protocol error and
// the connection should be dropped.
func (c *Conn) readFrame(remaining int) (fin bool, op byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	if hdr[0]&0x70 != 0 {
		return false, 0, nil, errors.New("websocket: RSV bits set (no extensions negotiated)")
	}
	op = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = binary.BigEndian.Uint64(ext[:])
		if n>>63 != 0 {
			return false, 0, nil, errors.New("websocket: invalid 64-bit length")
		}
	}
	// Control frames are at most 125 bytes (RFC 6455 5.5).
	if op >= 0x8 && (n > 125 || !fin) {
		return false, 0, nil, errors.New("websocket: oversized or fragmented control frame")
	}
	// The length field is attacker-controlled: never allocate from it
	// before checking it against our cap.
	if remaining < 0 || n > uint64(remaining) {
		return false, 0, nil, fmt.Errorf("websocket: frame of %d bytes exceeds limit", n)
	}
	var mask [4]byte
	if masked {
		// Servers MUST NOT mask (RFC 6455 5.1). Tolerate it but unmask,
		// since the bytes are untrusted either way.
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, int(n))
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return fin, op, payload, nil
}

// WriteText sends a single unfragmented, masked text frame.
func (c *Conn) WriteText(s string) error {
	return c.writeFrame(OpText, []byte(s))
}

func (c *Conn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if err := c.nc.SetWriteDeadline(time.Now().Add(c.opts.WriteTimeout)); err != nil {
		return err
	}
	n := len(payload)
	var maskBit byte
	if !c.opts.serverSide {
		maskBit = 0x80
	}
	buf := make([]byte, 0, 14+n)
	buf = append(buf, 0x80|op)
	switch {
	case n < 126:
		buf = append(buf, maskBit|byte(n))
	case n < 1<<16:
		buf = append(buf, maskBit|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, maskBit|127)
		buf = binary.BigEndian.AppendUint64(buf, uint64(n))
	}
	if c.opts.serverSide {
		buf = append(buf, payload...)
		_, err := c.nc.Write(buf)
		return err
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	buf = append(buf, mask[:]...)
	start := len(buf)
	buf = append(buf, payload...)
	for i := range payload {
		buf[start+i] ^= mask[i&3]
	}
	_, err := c.nc.Write(buf)
	return err
}

func (c *Conn) markClosed() {
	c.wmu.Lock()
	c.closed = true
	c.wmu.Unlock()
}

// Close sends a close frame (code 1001 Going Away, like a browser tab
// closing) and closes the socket. It does not wait for the peer's reply.
func (c *Conn) Close() error {
	_ = c.writeFrame(OpClose, []byte{0x03, 0xE9})
	c.markClosed()
	return c.nc.Close()
}

// RemoteAddr reports the peer address actually connected to.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// TLSState returns the TLS connection state, or nil for plaintext.
func (c *Conn) TLSState() *tls.ConnectionState {
	if tc, ok := c.nc.(*tls.Conn); ok {
		s := tc.ConnectionState()
		return &s
	}
	return nil
}
