package kiwiws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// pipeConn returns a Conn reading from the given bytes.
func connFromBytes(b []byte, opts Options) *Conn {
	c1, c2 := net.Pipe()
	go func() {
		c2.Write(b)
		c2.Close()
	}()
	o := opts
	if o.ReadTimeout == 0 {
		o.ReadTimeout = time.Second
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = time.Second
	}
	if o.MaxMessageBytes == 0 {
		o.MaxMessageBytes = 1 << 16
	}
	return &Conn{nc: c1, br: bufio.NewReader(c1), opts: o}
}

func frame(fin bool, op byte, payload []byte) []byte {
	b := []byte{op}
	if fin {
		b[0] |= 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		b = append(b, byte(n))
	case n < 1<<16:
		b = append(b, 126, byte(n>>8), byte(n))
	default:
		b = append(b, 127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	return append(b, payload...)
}

func TestReadSimple(t *testing.T) {
	c := connFromBytes(frame(true, OpBinary, []byte("SND hello")), Options{})
	op, p, err := c.Read()
	if err != nil || op != OpBinary || string(p) != "SND hello" {
		t.Fatalf("%d %q %v", op, p, err)
	}
}

func TestReadFragmented(t *testing.T) {
	b := append(frame(false, OpText, []byte("ab")), frame(true, OpContinuation, []byte("cd"))...)
	c := connFromBytes(b, Options{})
	op, p, err := c.Read()
	if err != nil || op != OpText || string(p) != "abcd" {
		t.Fatalf("%d %q %v", op, p, err)
	}
}

func TestReadRejects(t *testing.T) {
	cases := map[string][]byte{
		"rsv bits":               {0xF2, 1, 'x'},
		"reserved opcode 3":      {0x83, 1, 'x'},
		"reserved opcode 0xB":    {0x8B, 1, 'x'},
		"oversized declared":     {0x82, 127, 0, 0, 0, 0, 1, 0, 0, 0},
		"64-bit high bit":        {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"over cap 16-bit":        {0x82, 126, 0xFF, 0xFF},
		"control frame too big":  {0x89, 126, 0, 200},
		"fragmented control":     {0x09, 0},
		"continuation w/o start": frame(true, OpContinuation, []byte("x")),
		"new data mid-message":   append(frame(false, OpBinary, []byte("a")), frame(true, OpBinary, []byte("b"))...),
	}
	for name, b := range cases {
		c := connFromBytes(b, Options{MaxMessageBytes: 1000})
		_, _, err := c.Read()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		var ce *ErrClosed
		if errors.As(err, &ce) {
			t.Errorf("%s: reported as peer close", name)
		}
	}
}

func TestFragmentTotalCap(t *testing.T) {
	// Two 600-byte fragments against a 1000-byte cap must fail on the second.
	b := append(frame(false, OpBinary, make([]byte, 600)), frame(true, OpContinuation, make([]byte, 600))...)
	c := connFromBytes(b, Options{MaxMessageBytes: 1000})
	if _, _, err := c.Read(); err == nil {
		t.Fatal("fragment total exceeded cap but was accepted")
	}
}

func TestCloseFrame(t *testing.T) {
	payload := []byte{0x03, 0xE8, 'b', 'y', 'e'}
	c := connFromBytes(frame(true, OpClose, payload), Options{})
	_, _, err := c.Read()
	var ce *ErrClosed
	if !errors.As(err, &ce) || ce.Code != 1000 || ce.Reason != "bye" {
		t.Fatalf("%v", err)
	}
}

func TestPingAnswered(t *testing.T) {
	c1, c2 := net.Pipe()
	c := &Conn{nc: c1, br: bufio.NewReader(c1), opts: Options{ReadTimeout: time.Second, WriteTimeout: time.Second, MaxMessageBytes: 1000}}
	go func() {
		c2.Write(frame(true, OpPing, []byte("hi")))
		// read pong
		hdr := make([]byte, 2)
		c2.Read(hdr)
		if hdr[0] != 0x80|OpPong || hdr[1]&0x80 == 0 {
			t.Errorf("bad pong header %x", hdr)
		}
		rest := make([]byte, 4+2)
		c2.Read(rest)
		c2.Write(frame(true, OpBinary, []byte("ok")))
		c2.Close()
	}()
	_, p, err := c.Read()
	if err != nil || string(p) != "ok" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestMaskedServerFrameTolerated(t *testing.T) {
	mask := []byte{1, 2, 3, 4}
	payload := []byte("SND x")
	b := []byte{0x82, 0x80 | byte(len(payload))}
	b = append(b, mask...)
	for i, c := range payload {
		b = append(b, c^mask[i&3])
	}
	c := connFromBytes(b, Options{})
	_, p, err := c.Read()
	if err != nil || string(p) != "SND x" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestClientWritesMaskedServerWritesUnmasked(t *testing.T) {
	for _, server := range []bool{false, true} {
		c1, c2 := net.Pipe()
		c := &Conn{nc: c1, br: bufio.NewReader(c1), opts: Options{WriteTimeout: time.Second, serverSide: server}}
		done := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 100)
			n, _ := c2.Read(buf)
			done <- buf[:n]
		}()
		if err := c.WriteText("SET x"); err != nil {
			t.Fatal(err)
		}
		got := <-done
		masked := got[1]&0x80 != 0
		if masked == server {
			t.Fatalf("server=%v masked=%v", server, masked)
		}
		if !server {
			mask := got[2:6]
			body := got[6:]
			for i := range body {
				body[i] ^= mask[i&3]
			}
			if string(body) != "SET x" {
				t.Fatalf("payload %q", body)
			}
		} else if string(got[2:]) != "SET x" {
			t.Fatalf("payload %q", got[2:])
		}
	}
}

func TestHandshakeRejectsNon101(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\n\r\n"))
		c.Close()
	}()
	_, err := Dial(t.Context(), "ws://"+ln.Addr().String()+"/1/SND", &Options{Dialer: &net.Dialer{Timeout: time.Second}})
	var nu *ErrNotUpgraded
	if !errors.As(err, &nu) || nu.StatusCode != 307 || nu.Location != "http://evil.example/" {
		t.Fatalf("%v", err)
	}
}

func TestHandshakeRejectsBadAccept(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"))
		time.Sleep(200 * time.Millisecond)
		c.Close()
	}()
	_, err := Dial(t.Context(), "ws://"+ln.Addr().String()+"/1/SND", &Options{Dialer: &net.Dialer{Timeout: time.Second}})
	if err == nil || !strings.Contains(err.Error(), "Accept") {
		t.Fatalf("%v", err)
	}
}

func TestDialRejectsSchemes(t *testing.T) {
	for _, u := range []string{"http://x.example/", "ftp://x/", "x", "ws://"} {
		if _, err := Dial(t.Context(), u, &Options{Dialer: &net.Dialer{Timeout: 100 * time.Millisecond}}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add(frame(true, OpBinary, []byte("SND")))
	f.Add([]byte{0x82, 127, 0, 0, 0, 0, 1, 0, 0, 0})
	f.Add(append(frame(false, OpText, []byte("a")), frame(true, OpContinuation, []byte("b"))...))
	f.Add(frame(true, OpClose, []byte{3, 232}))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := connFromBytes(data, Options{MaxMessageBytes: 4096, ReadTimeout: 200 * time.Millisecond})
		defer c.nc.Close()
		for i := 0; i < 8; i++ {
			_, p, err := c.Read()
			if err != nil {
				return
			}
			if len(p) > 4096 {
				t.Fatalf("message %d bytes exceeds cap", len(p))
			}
		}
	})
}

var _ = bytes.Equal
