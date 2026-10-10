// Package mockkiwi is a KiwiSDR impersonator for tests. It speaks just
// enough of the protocol to satisfy the relay, and it can misbehave in
// every way THREAT_MODEL.md section 7 lists.
package mockkiwi

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/kiwiws"
)

// Behavior selects how the mock misbehaves.
type Behavior int

const (
	Normal Behavior = iota
	OversizedFrame
	LyingLength
	SlowDrip
	MidStreamGarbage
	HTTPRedirect
	HTTP403
	GiantMetadata
	SilentAfterHandshake
	Busy
	TooBusy
	RedirectMessage
	BadSampleRate
	Flood
	MaskedFrames
	RSVBits
	ReservedOpcode
	CloseImmediately
	FragmentedAudio
	StereoFrame
	OddPCM
	PCMUncompressed
	HugeSeqJump
)

// Server is a running mock receiver.
type Server struct {
	HTTP *httptest.Server

	Behavior   Behavior
	FrameEvery time.Duration // audio cadence; default 20 ms (fast tests)
	SampleRate float64       // default 12000

	// Observations for assertions.
	Keepalives  atomic.Int64
	Auths       atomic.Int64
	ModCmds     atomic.Int64
	Idents      atomic.Int64
	Conns       atomic.Int64
	CloseFrames atomic.Int64 // close frames received from the relay
	LastIdent   atomic.Pointer[string]
	LastOrigin  atomic.Pointer[string]
	LastUA      atomic.Pointer[string]
	LastPath    atomic.Pointer[string]

	mu    sync.Mutex
	conns []net.Conn
}

// New starts a mock on 127.0.0.1.
func New(b Behavior) *Server {
	s := &Server{Behavior: b, FrameEvery: 20 * time.Millisecond, SampleRate: 12000}
	s.HTTP = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Host returns "127.0.0.1".
func (s *Server) Host() string { return "127.0.0.1" }

// Port returns the listening port.
func (s *Server) Port() int {
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(s.HTTP.URL, "http://"))
	var n int
	fmt.Sscanf(p, "%d", &n)
	return n
}

// Close stops the server and all connections.
func (s *Server) Close() {
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.HTTP.CloseClientConnections()
	s.HTTP.Close()
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

func strp(v string) *string { return &v }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.Conns.Add(1)
	s.LastPath.Store(strp(r.URL.Path))
	s.LastOrigin.Store(strp(r.Header.Get("Origin")))
	s.LastUA.Store(strp(r.Header.Get("User-Agent")))

	switch s.Behavior {
	case HTTPRedirect:
		w.Header().Set("Location", "http://127.0.0.1:1/"+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	case HTTP403:
		w.WriteHeader(http.StatusForbidden)
		return
	}

	conn, err := kiwiws.Accept(w, r, &kiwiws.Options{ReadTimeout: 30 * time.Second, MaxMessageBytes: 1 << 20})
	if err != nil {
		return
	}
	raw := conn.NetConn()
	s.track(raw)
	defer raw.Close()

	switch s.Behavior {
	case CloseImmediately:
		conn.CloseWithReason(1000, "bye")
		return
	case SilentAfterHandshake:
		s.drain(conn) // read until the relay gives up
		return
	case OversizedFrame:
		// Header declares 16 MiB, then a few bytes.
		raw.Write([]byte{0x82, 127, 0, 0, 0, 0, 1, 0, 0, 0})
		raw.Write([]byte("SND garbage"))
		s.drain(conn)
		return
	case LyingLength:
		raw.Write([]byte{0x82, 126, 0x0F, 0xA0}) // 4000 bytes
		raw.Write(make([]byte, 100))
		s.drain(conn)
		return
	case SlowDrip:
		msg := wsFrame(kiwiws.OpBinary, []byte("MSG sample_rate=12000.000000"), false)
		for _, b := range msg {
			if _, err := raw.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
		s.drain(conn)
		return
	case RSVBits:
		raw.Write([]byte{0xF2, 3, 'M', 'S', 'G'})
		s.drain(conn)
		return
	case ReservedOpcode:
		raw.Write([]byte{0x83, 3, 'M', 'S', 'G'})
		s.drain(conn)
		return
	}

	// --- normal-ish session -------------------------------------------------
	write := func(p []byte) error {
		if s.Behavior == MaskedFrames {
			_, err := raw.Write(wsFrame(kiwiws.OpBinary, p, true))
			return err
		}
		return conn.WriteBinary(p)
	}
	msg := func(format string, a ...any) error {
		return write([]byte("MSG " + fmt.Sprintf(format, a...)))
	}

	sr := s.SampleRate
	if s.Behavior == BadSampleRate {
		sr = 48000
	}
	if err := msg("sample_rate=%.6f", sr); err != nil {
		return
	}

	// Command reader: observes keepalives, auth, mod, ident; exits on close.
	cmds := make(chan string, 64)
	go func() {
		defer close(cmds)
		for {
			_, p, err := conn.Read()
			if err != nil {
				if _, ok := err.(*kiwiws.ErrClosed); ok {
					s.CloseFrames.Add(1)
				}
				return
			}
			cmd := string(p)
			switch {
			case cmd == "SET keepalive":
				s.Keepalives.Add(1)
			case strings.HasPrefix(cmd, "SET auth "):
				s.Auths.Add(1)
			case strings.HasPrefix(cmd, "SET mod="):
				s.ModCmds.Add(1)
			case strings.HasPrefix(cmd, "SET ident_user="):
				s.Idents.Add(1)
				s.LastIdent.Store(strp(strings.TrimPrefix(cmd, "SET ident_user=")))
			}
			select {
			case cmds <- cmd:
			default:
			}
		}
	}()

	// Wait for auth.
	authed := false
	timeout := time.After(5 * time.Second)
	for !authed {
		select {
		case c, ok := <-cmds:
			if !ok {
				return
			}
			if strings.HasPrefix(c, "SET auth ") {
				authed = true
			}
		case <-timeout:
			return
		}
	}

	switch s.Behavior {
	case Busy:
		msg("badp=1")
		s.drainCmds(cmds)
		return
	case TooBusy:
		msg("too_busy=8")
		s.drainCmds(cmds)
		return
	case RedirectMessage:
		msg("badp=0")
		msg("redirect=http%%3A%%2F%%2Fevil.example%%2F")
		s.drainCmds(cmds)
		return
	case GiantMetadata:
		msg("badp=0")
		msg("version_maj=1 version_min=902")
		msg("name=%s", strings.Repeat("A", 200<<10))
		msg("audio_rate=12000")
	default:
		msg("badp=0")
		msg("version_maj=1 version_min=902 debian_ver=11")
		msg("load_cfg=%s", strings.Repeat("%7B%22x%22%3A1%7D", 200))
		msg("audio_rate=12000")
	}

	// Audio.
	enc := &adpcmEncoder{}
	var seq uint32
	newFreq := false
	every := s.FrameEvery
	if s.Behavior == Flood {
		every = 0
	}
	ticker := time.NewTicker(max(every, time.Microsecond))
	defer ticker.Stop()
	frames := 0
	for {
		select {
		case c, ok := <-cmds:
			if !ok {
				return
			}
			if strings.HasPrefix(c, "SET mod=") {
				newFreq = true
			}
		case <-ticker.C:
		}
		if every == 0 {
			// Flood: do not wait on the ticker at all.
			select {
			case c, ok := <-cmds:
				if !ok {
					return
				}
				_ = c
			default:
			}
		}
		seq++
		if s.Behavior == HugeSeqJump && seq == 5 {
			seq = math.MaxUint32 - 2
		}
		var flags byte
		if newFreq {
			flags |= 0x04
			newFreq = false
		}
		if frames == 0 {
			flags |= 0x20 // RESTART on first frame
		}
		samples := tone(2048, frames, sr)
		var body []byte
		switch s.Behavior {
		case PCMUncompressed, OddPCM:
			for _, v := range samples {
				body = binary.BigEndian.AppendUint16(body, uint16(v))
			}
			if s.Behavior == OddPCM {
				body = body[:len(body)-1]
			}
		case StereoFrame:
			flags |= 0x08
			body = make([]byte, 10)
			for _, v := range samples {
				body = binary.BigEndian.AppendUint16(body, uint16(v))
				body = binary.BigEndian.AppendUint16(body, uint16(v))
			}
		default:
			flags |= 0x10
			body = enc.encode(samples)
		}
		rssi := uint16((-80.0 + 127.0) * 10)
		frame := make([]byte, 0, 3+7+len(body))
		frame = append(frame, 'S', 'N', 'D', flags)
		frame = binary.LittleEndian.AppendUint32(frame, seq)
		frame = binary.BigEndian.AppendUint16(frame, rssi)
		frame = append(frame, body...)

		var err error
		switch {
		case s.Behavior == MidStreamGarbage && frames == 10:
			g := make([]byte, 3000)
			rand.Read(g)
			copy(g, "SND")
			err = write(g)
		case s.Behavior == MidStreamGarbage && frames == 11:
			err = write([]byte("XYZ unknown tag"))
		case s.Behavior == MidStreamGarbage && frames == 12:
			err = write([]byte("SN")) // too short
		case s.Behavior == MidStreamGarbage && frames == 13:
			err = write([]byte("MSG \xff\xfe=\x00 badp=zzz sample_rate=abc"))
		case s.Behavior == FragmentedAudio:
			// Split into two frames: first without FIN, then continuation.
			f1 := wsFrame(kiwiws.OpBinary, frame[:len(frame)/2], false)
			f1[0] &^= 0x80
			if _, err = raw.Write(f1); err == nil {
				_, err = raw.Write(wsFrame(kiwiws.OpContinuation, frame[len(frame)/2:], false))
			}
		default:
			err = write(frame)
		}
		if err != nil {
			return
		}
		frames++
	}
}

func (s *Server) drain(conn *kiwiws.Conn) {
	for {
		if _, _, err := conn.Read(); err != nil {
			if _, ok := err.(*kiwiws.ErrClosed); ok {
				s.CloseFrames.Add(1)
			}
			return
		}
	}
}

func (s *Server) drainCmds(cmds <-chan string) {
	for range cmds {
	}
}

// wsFrame builds a single-frame message; masked frames are what a server
// must not send, used to test tolerance.
func wsFrame(op byte, payload []byte, masked bool) []byte {
	n := len(payload)
	var b []byte
	b = append(b, 0x80|op)
	mb := byte(0)
	if masked {
		mb = 0x80
	}
	switch {
	case n < 126:
		b = append(b, mb|byte(n))
	case n < 1<<16:
		b = append(b, mb|126, byte(n>>8), byte(n))
	default:
		b = append(b, mb|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if masked {
		mask := []byte{1, 2, 3, 4}
		b = append(b, mask...)
		for i, c := range payload {
			b = append(b, c^mask[i&3])
		}
		return b
	}
	return append(b, payload...)
}

func tone(n, frame int, sr float64) []int16 {
	out := make([]int16, n)
	for i := range out {
		t := float64(frame*n+i) / sr
		out[i] = int16(8000 * math.Sin(2*math.Pi*440*t))
	}
	return out
}

// adpcmEncoder is a straightforward IMA encoder (low nibble first).
type adpcmEncoder struct {
	index int
	prev  int
}

var stepTable = [89]int{
	7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34,
	37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
	157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494,
	544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552,
	1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026,
	4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442,
	11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623,
	27086, 29794, 32767,
}
var indexAdjust = [16]int{-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8}

func (e *adpcmEncoder) encodeSample(s int) byte {
	step := stepTable[e.index]
	diff := s - e.prev
	var code byte
	if diff < 0 {
		code = 8
		diff = -diff
	}
	d := step >> 3
	if diff >= step {
		code |= 4
		diff -= step
		d += step
	}
	if diff >= step>>1 {
		code |= 2
		diff -= step >> 1
		d += step >> 1
	}
	if diff >= step>>2 {
		code |= 1
		d += step >> 2
	}
	if code&8 != 0 {
		e.prev -= d
	} else {
		e.prev += d
	}
	if e.prev > 32767 {
		e.prev = 32767
	} else if e.prev < -32768 {
		e.prev = -32768
	}
	e.index += indexAdjust[code]
	if e.index < 0 {
		e.index = 0
	} else if e.index > 88 {
		e.index = 88
	}
	return code
}

func (e *adpcmEncoder) encode(samples []int16) []byte {
	out := make([]byte, 0, (len(samples)+1)/2)
	for i := 0; i+1 < len(samples); i += 2 {
		lo := e.encodeSample(int(samples[i]))
		hi := e.encodeSample(int(samples[i+1]))
		out = append(out, lo|hi<<4)
	}
	return out
}

// ReadRawRequest is a helper for tests that want to inspect the upgrade
// request line without a full server.
func ReadRawRequest(c net.Conn) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(c))
}
