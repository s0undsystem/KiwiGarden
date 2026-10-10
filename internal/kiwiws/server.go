package kiwiws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Accept upgrades an incoming HTTP request to a WebSocket connection. The
// caller has already validated Origin, Host, and authentication; Accept only
// checks the protocol-level handshake fields. On error it has written the
// HTTP error response.
//
// The returned Conn unmasks client frames (RFC 6455 requires clients to
// mask; unmasked frames are tolerated) and writes unmasked frames, as RFC
// 6455 section 5.1 requires of servers.
func Accept(w http.ResponseWriter, r *http.Request, opts *Options) (*Conn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("websocket: method not GET")
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return nil, errors.New("websocket: not an upgrade request")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported websocket version", http.StatusUpgradeRequired)
		return nil, errors.New("websocket: bad version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		http.Error(w, "bad Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("websocket: bad key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade not supported", http.StatusInternalServerError)
		return nil, errors.New("websocket: ResponseWriter cannot hijack")
	}

	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	nc, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("websocket: hijack: %w", err)
	}
	o := opts.withDefaults()
	o.serverSide = true

	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Accept: %s\r\n", accept)
	// Security headers are harmless here and keep every response uniform.
	b.WriteString("X-Content-Type-Options: nosniff\r\n")
	b.WriteString("Referrer-Policy: no-referrer\r\n")
	b.WriteString("\r\n")
	nc.SetWriteDeadline(time.Now().Add(o.WriteTimeout))
	if _, err := io.WriteString(nc, b.String()); err != nil {
		nc.Close()
		return nil, fmt.Errorf("websocket: write 101: %w", err)
	}
	nc.SetWriteDeadline(time.Time{})

	// Reuse any bytes the HTTP server already buffered.
	var br *bufio.Reader
	if brw != nil && brw.Reader.Buffered() > 0 {
		br = brw.Reader
	} else {
		br = bufio.NewReaderSize(nc, 16<<10)
	}
	return &Conn{nc: nc, br: br, opts: o}, nil
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// SetReadTimeout changes the per-message read deadline for subsequent reads.
func (c *Conn) SetReadTimeout(d time.Duration) { c.opts.ReadTimeout = d }

// WriteBinary sends a single unfragmented binary frame.
func (c *Conn) WriteBinary(p []byte) error { return c.writeFrame(OpBinary, p) }

// CloseWithReason sends a close frame with a status code and short reason
// (truncated to fit the 125-byte control frame limit) and closes the socket.
func (c *Conn) CloseWithReason(code uint16, reason string) error {
	if len(reason) > 120 {
		reason = reason[:120]
	}
	payload := make([]byte, 2, 2+len(reason))
	payload[0] = byte(code >> 8)
	payload[1] = byte(code)
	payload = append(payload, reason...)
	_ = c.writeFrame(OpClose, payload)
	c.markClosed()
	return c.nc.Close()
}

// NetConn exposes the underlying connection (for deadlines in tests).
func (c *Conn) NetConn() net.Conn { return c.nc }

// NewClientConnForTest wraps an already-upgraded connection as a client
// (masking) Conn. Tests use it to drive the server from a raw socket.
func NewClientConnForTest(nc net.Conn, br *bufio.Reader) *Conn {
	o := (&Options{ReadTimeout: 5 * time.Second}).withDefaults()
	return &Conn{nc: nc, br: br, opts: o}
}
