package server

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/directory"
	"github.com/s0undsystem/KiwiGarden/internal/kiwiws"
	"github.com/s0undsystem/KiwiGarden/internal/mockkiwi"
	"github.com/s0undsystem/KiwiGarden/internal/netpolicy"
	"github.com/s0undsystem/KiwiGarden/internal/relay"
)

type fixture struct {
	srv  *Server
	addr string
	hs   *http.Server
	mock *mockkiwi.Server
	rxID string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	mock := mockkiwi.New(mockkiwi.Normal)
	t.Cleanup(mock.Close)

	// Directory with one receiver pointing at the mock (loopback allowed
	// only via the test policy; directory validation would reject a
	// loopback URL, so we build the snapshot by hand through Parse with a
	// public-looking host and then patch the host).
	doc := fmt.Sprintf(`{"schema":1,"receivers":[{"url":"http://mock.example.com:%d","name":"Mock <b>Kiwi</b>","loc":"Nowhere","antenna":"wire","gps":[10,20],"users":0,"users_max":4,"ext_api":4}]}`, mock.Port())
	snap, err := directory.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	snap.Receivers[0].Host = "127.0.0.1"
	store := directory.NewStore(nil, "")
	setSnapshot(store, snap)

	rm := relay.NewManager(relay.Config{Policy: netpolicy.Policy{AllowLoopback: true}, FirstMessageTimeout: 2 * time.Second})
	ui := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>Kiwi Garden</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	srv, err := New(store, rm, ui)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer()
	go hs.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	})
	return &fixture{srv: srv, addr: srv.Addr(), hs: hs, mock: mock, rxID: snap.Receivers[0].ID}
}

// setSnapshot injects a snapshot into a store (test hook via exported API:
// Store has no setter, so we go through a tiny internal helper).
func setSnapshot(s *directory.Store, snap *directory.Snapshot) {
	directory.SetForTest(s, snap)
}

func (f *fixture) get(t *testing.T, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+f.addr+path, nil)
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestSecurityHeadersAndNoCORS(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/", "/assets/app.js", "/api/receivers", "/nope"} {
		resp, _ := f.get(t, path, map[string]string{"Origin": "http://evil.example"})
		want := map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
			"X-Frame-Options":              "DENY",
		}
		for k, v := range want {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s: header %s = %q, want %q", path, k, got, v)
			}
		}
		for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Expose-Headers"} {
			if resp.Header.Get(k) != "" {
				t.Errorf("%s: CORS header %s present", path, k)
			}
		}
	}
	resp, _ := f.get(t, "/", nil)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "require-trusted-types-for 'script'") {
		t.Errorf("index: status %d csp %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("csp incomplete: %q", resp.Header.Get("Content-Security-Policy"))
	}
	resp, _ = f.get(t, "/assets/app.js", nil)
	if resp.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("js content type %q", resp.Header.Get("Content-Type"))
	}
}

func TestHostAndOriginChecks(t *testing.T) {
	f := newFixture(t)
	_, port, _ := net.SplitHostPort(f.addr)
	tok := f.srv.Token()
	cases := []struct {
		name string
		path string
		hdr  map[string]string
		want int
	}{
		{"page ok", "/", nil, 200},
		{"page wrong host", "/", map[string]string{"Host": "evil.example"}, 403},
		{"page rebinding host w/ port", "/", map[string]string{"Host": "evil.example:" + port}, 403},
		{"page localhost host", "/", map[string]string{"Host": "localhost:" + port}, 403},
		{"page host without port", "/", map[string]string{"Host": "127.0.0.1"}, 403},
		{"page bad origin", "/", map[string]string{"Origin": "http://evil.example"}, 403},
		{"page origin other port", "/", map[string]string{"Origin": "http://127.0.0.1:1"}, 403},
		{"page origin null", "/", map[string]string{"Origin": "null"}, 403},
		{"page origin trailing slash", "/", map[string]string{"Origin": "http://" + f.addr + "/"}, 403},
		{"page good origin", "/", map[string]string{"Origin": "http://" + f.addr}, 200},
		{"page sec-fetch none", "/", map[string]string{"Sec-Fetch-Site": "none"}, 200},
		{"page sec-fetch cross-site", "/", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"page sec-fetch same-site", "/", map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"api no token", "/api/receivers", nil, 401},
		{"api wrong token", "/api/receivers", map[string]string{TokenHeader: strings.Repeat("0", 64)}, 401},
		{"api short token", "/api/receivers", map[string]string{TokenHeader: tok[:63]}, 401},
		{"api flipped token", "/api/receivers", map[string]string{TokenHeader: flip(tok)}, 401},
		{"api token in query", "/api/receivers?token=" + tok, nil, 401},
		{"api good", "/api/receivers", map[string]string{TokenHeader: tok, "Origin": "http://" + f.addr, "Sec-Fetch-Site": "same-origin"}, 200},
		{"api good no origin (curl)", "/api/receivers", map[string]string{TokenHeader: tok}, 200},
		{"api direct navigation", "/api/receivers", map[string]string{TokenHeader: tok, "Sec-Fetch-Site": "none"}, 401},
		{"api cross-site w/ token", "/api/receivers", map[string]string{TokenHeader: tok, "Sec-Fetch-Site": "cross-site", "Origin": "http://evil.example"}, 403},
		{"api bad origin w/ token", "/api/receivers", map[string]string{TokenHeader: tok, "Origin": "http://evil.example"}, 403},
		{"api wrong host w/ token", "/api/receivers", map[string]string{TokenHeader: tok, "Host": "evil.example:" + port}, 403},
		{"traversal", "/../../etc/passwd", nil, 404},
		{"ws without upgrade", "/api/stream", map[string]string{"Origin": "http://" + f.addr}, 400},
		{"ws bad origin", "/api/stream", map[string]string{"Origin": "http://evil.example", "Upgrade": "websocket", "Connection": "Upgrade"}, 403},
		{"ws no origin", "/api/stream", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := f.get(t, c.path, c.hdr)
			if resp.StatusCode != c.want {
				t.Fatalf("status %d, want %d (body %q)", resp.StatusCode, c.want, strings.TrimSpace(body))
			}
		})
	}
	// Non-GET methods.
	for _, m := range []string{"POST", "PUT", "DELETE", "OPTIONS", "HEAD"} {
		req, _ := http.NewRequest(m, "http://"+f.addr+"/api/receivers", nil)
		req.Header.Set(TokenHeader, tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 405 {
			t.Errorf("%s: status %d", m, resp.StatusCode)
		}
	}
}

func flip(hexTok string) string {
	b := []byte(hexTok)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func TestReceiversAPIHidesConnectionDetails(t *testing.T) {
	f := newFixture(t)
	resp, body := f.get(t, "/api/receivers", map[string]string{TokenHeader: f.srv.Token()})
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	var out struct {
		Receivers []map[string]any `json:"receivers"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Receivers) != 1 {
		t.Fatalf("%d receivers", len(out.Receivers))
	}
	for _, forbidden := range []string{"url", "host", "port", "scheme", "127.0.0.1", "mock.example.com", fmt.Sprint(f.mock.Port())} {
		if strings.Contains(body, forbidden) {
			t.Errorf("response leaks %q", forbidden)
		}
	}
	if out.Receivers[0]["id"] != f.rxID {
		t.Errorf("id mismatch")
	}
	// Markup in a name is data; it must survive intact (the browser renders
	// it with textContent) and must not appear raw in the JSON bytes.
	if out.Receivers[0]["name"] != "Mock <b>Kiwi</b>" {
		t.Errorf("name altered: %v", out.Receivers[0]["name"])
	}
	if strings.Contains(body, "<b>") {
		t.Errorf("raw angle brackets in JSON body")
	}
}

// --- websocket --------------------------------------------------------------------

func wsDial(t *testing.T, addr, origin string) (*kiwiws.Conn, int) {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	req := "GET /api/stream HTTP/1.1\r\nHost: " + addr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nSec-Fetch-Site: same-origin\r\n"
	if origin != "" {
		req += "Origin: " + origin + "\r\n"
	}
	req += "\r\n"
	io.WriteString(nc, req)
	br := bufio.NewReader(nc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		nc.Close()
		return nil, resp.StatusCode
	}
	h := sha1.New()
	io.WriteString(h, key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(h.Sum(nil)) {
		t.Fatal("bad accept")
	}
	return kiwiws.NewClientConnForTest(nc, br), 101
}

func readStatus(t *testing.T, c *kiwiws.Conn) statusMsg {
	t.Helper()
	for {
		op, p, err := c.Read()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if op != kiwiws.OpText {
			continue
		}
		var m statusMsg
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatalf("bad status json %q", p)
		}
		return m
	}
}

func TestWebSocketAuthAndStream(t *testing.T) {
	f := newFixture(t)
	origin := "http://" + f.addr

	// Wrong origin on upgrade.
	if _, code := wsDial(t, f.addr, "http://evil.example"); code != 403 {
		t.Fatalf("evil origin: %d", code)
	}
	// Missing origin on upgrade.
	if _, code := wsDial(t, f.addr, ""); code != 403 {
		t.Fatalf("no origin: %d", code)
	}

	// Bad token as first message.
	c, _ := wsDial(t, f.addr, origin)
	c.WriteText(`{"type":"auth","token":"` + strings.Repeat("0", 64) + `"}`)
	if _, _, err := c.Read(); err == nil {
		t.Fatal("bad token accepted")
	}
	c.Close()

	// Non-auth first message.
	c, _ = wsDial(t, f.addr, origin)
	c.WriteText(`{"type":"connect","rx":"` + f.rxID + `","freq":9420,"mode":"am"}`)
	if _, _, err := c.Read(); err == nil {
		t.Fatal("connect before auth accepted")
	}
	c.Close()

	// Unknown field rejected.
	c, _ = wsDial(t, f.addr, origin)
	c.WriteText(`{"type":"auth","token":"` + f.srv.Token() + `","evil":1}`)
	if _, _, err := c.Read(); err == nil {
		t.Fatal("unknown field accepted")
	}
	c.Close()

	// Good flow.
	c, _ = wsDial(t, f.addr, origin)
	defer c.Close()
	c.WriteText(`{"type":"auth","token":"` + f.srv.Token() + `"}`)
	if st := readStatus(t, c); st.State != "ready" {
		t.Fatalf("after auth: %+v", st)
	}
	c.WriteText(`{"type":"connect","rx":"nope","freq":9420,"mode":"am"}`)
	if st := readStatus(t, c); st.Reason != "unknown_receiver" {
		t.Fatalf("unknown rx: %+v", st)
	}
	c.WriteText(`{"type":"connect","rx":"` + f.rxID + `","freq":9420,"mode":"am"}`)
	if st := readStatus(t, c); st.State != "connecting" {
		t.Fatalf("expected connecting, got %+v", st)
	}
	if st := readStatus(t, c); st.State != "connected" || st.SampleRate < 11000 || st.Name == "" {
		t.Fatalf("expected connected, got %+v", st)
	}
	// Audio frames: binary, header, PCM.
	frames := 0
	for frames < 3 {
		op, p, err := c.Read()
		if err != nil {
			t.Fatal(err)
		}
		if op != kiwiws.OpBinary {
			continue
		}
		if p[0] != 1 || len(p) != audioHeaderLen+2*2048 {
			t.Fatalf("audio frame type=%d len=%d", p[0], len(p))
		}
		frames++
	}
	c.WriteText(`{"type":"tune","freq":7200,"mode":"lsb"}`)
	c.WriteText(`{"type":"disconnect"}`)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("no closed status after disconnect")
		}
		op, p, err := c.Read()
		if err != nil {
			t.Fatal(err)
		}
		if op != kiwiws.OpText {
			continue
		}
		var st statusMsg
		json.Unmarshal(p, &st)
		if st.State == "closed" {
			if st.Reason != "closed_by_user" {
				t.Fatalf("reason %s", st.Reason)
			}
			break
		}
	}
	if f.mock.ModCmds.Load() < 2 {
		t.Errorf("tune not forwarded: %d mod commands", f.mock.ModCmds.Load())
	}
	// Receiver connection must be gone shortly after.
	time.Sleep(100 * time.Millisecond)
	if n := f.srv.relay.ActiveSessions(); n != 0 {
		t.Fatalf("%d sessions still active", n)
	}
}

func TestWebSocketCloseReleasesReceiver(t *testing.T) {
	f := newFixture(t)
	c, _ := wsDial(t, f.addr, "http://"+f.addr)
	c.WriteText(`{"type":"auth","token":"` + f.srv.Token() + `"}`)
	readStatus(t, c)
	c.WriteText(`{"type":"connect","rx":"` + f.rxID + `","freq":9420,"mode":"am"}`)
	readStatus(t, c) // connecting
	readStatus(t, c) // connected
	// Browser vanishes without a close frame.
	c.NetConn().Close()
	deadline := time.Now().Add(3 * time.Second)
	for f.srv.relay.ActiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("receiver session not released after browser disappeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWebSocketRateLimit(t *testing.T) {
	f := newFixture(t)
	c, _ := wsDial(t, f.addr, "http://"+f.addr)
	defer c.Close()
	c.WriteText(`{"type":"auth","token":"` + f.srv.Token() + `"}`)
	readStatus(t, c)
	for i := 0; i < clientMsgPerSec+5; i++ {
		c.WriteText(`{"type":"ping"}`)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, _, err := c.Read()
		if err != nil {
			if ce, ok := err.(*kiwiws.ErrClosed); ok && ce.Code == 4008 {
				return
			}
			t.Fatalf("unexpected error %v", err)
		}
	}
	t.Fatal("flood not cut off")
}

func TestWebSocketOversizedMessage(t *testing.T) {
	f := newFixture(t)
	c, _ := wsDial(t, f.addr, "http://"+f.addr)
	defer c.Close()
	c.WriteText(`{"type":"auth","token":"` + f.srv.Token() + `"}`)
	readStatus(t, c)
	c.WriteText(`{"type":"ping","token":"` + strings.Repeat("x", maxClientMessage) + `"}`)
	if _, _, err := c.Read(); err == nil {
		t.Fatal("oversized message tolerated")
	}
}

func TestTokenNeverInLaunchURLPathOrQuery(t *testing.T) {
	f := newFixture(t)
	u := f.srv.LaunchURL()
	if !strings.HasPrefix(u, "http://127.0.0.1:") || !strings.Contains(u, "/#") {
		t.Fatalf("launch url %q", u)
	}
	if strings.Contains(strings.SplitN(u, "#", 2)[0], f.srv.Token()) {
		t.Fatal("token before the fragment")
	}
}

// TestNoForbiddenImportsOrSinks greps the repo for things the threat model
// promises are absent.
func TestNoForbiddenImportsOrSinks(t *testing.T) {
	root := filepath.Join("..", "..")
	forbiddenGo := []string{`"os/exec"`, "syscall.Exec", "unsafe.Pointer"}
	forbiddenWeb := []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localhost"}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == "node_modules" || name == ".git" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		switch {
		case strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go"):
			for _, f := range forbiddenGo {
				if strings.Contains(s, f) {
					t.Errorf("%s contains %s", p, f)
				}
			}
		case strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".html"):
			if strings.Contains(p, string(filepath.Separator)+"web"+string(filepath.Separator)+"src") || strings.HasSuffix(name, "index.html") {
				for _, f := range forbiddenWeb {
					if strings.Contains(s, f) {
						t.Errorf("%s contains %s", p, f)
					}
				}
				if strings.HasSuffix(name, ".html") && strings.Contains(s, "<script>") {
					t.Errorf("%s has an inline script", p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
