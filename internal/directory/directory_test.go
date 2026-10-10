package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/netpolicy"
)

func TestParseReceiverURL(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		scheme string
		host   string
		port   int
		note   string
	}{
		{"http://sdr.example.com:8073", true, "http", "sdr.example.com", 8073, "typical"},
		{"http://sdr.example.com", true, "http", "sdr.example.com", 80, "default http port"},
		{"https://kwsdr.example.de:443", true, "https", "kwsdr.example.de", 443, "https explicit"},
		{"https://kwsdr.example.de", true, "https", "kwsdr.example.de", 443, "https default"},
		{"http://SDR.Example.COM:8073/", true, "http", "sdr.example.com", 8073, "case folded, trailing slash"},
		{"http://pb8w.proxy.kiwisdr.com", true, "http", "pb8w.proxy.kiwisdr.com", 8073, "proxy rewritten to 8073"},
		{"http://pb8w.proxy.kiwisdr.com:8074", true, "http", "pb8w.proxy.kiwisdr.com", 8074, "proxy explicit port kept"},
		{"http://178.17.3.34:8073", true, "http", "178.17.3.34", 8073, "public IP literal"},
		{"http://[2606:4700::1111]:8073", true, "http", "2606:4700::1111", 8073, "public v6 literal"},
		{"http://127.0.0.1:8073", false, "", "", 0, "loopback literal"},
		{"http://10.1.2.3:8073", false, "", "", 0, "private literal"},
		{"http://[::1]:8073", false, "", "", 0, "v6 loopback literal"},
		{"http://[::ffff:10.0.0.1]:8073", false, "", "", 0, "mapped private literal"},
		{"http://169.254.169.254", false, "", "", 0, "link-local literal"},
		{"http://sdr.example.com:22", false, "", "", 0, "ssh port"},
		{"http://sdr.example.com:1023", false, "", "", 0, "just below 1024"},
		{"http://sdr.example.com:0", false, "", "", 0, "port zero"},
		{"http://sdr.example.com:65536", false, "", "", 0, "port too big"},
		{"http://sdr.example.com:08073", false, "", "", 0, "leading zero port"},
		{"ftp://sdr.example.com", false, "", "", 0, "ftp"},
		{"ws://sdr.example.com", false, "", "", 0, "ws scheme"},
		{"file:///etc/passwd", false, "", "", 0, "file"},
		{"javascript:alert(1)", false, "", "", 0, "javascript"},
		{"//sdr.example.com", false, "", "", 0, "schemeless"},
		{"sdr.example.com:8073", false, "", "", 0, "bare host"},
		{"http://user:pw@sdr.example.com", false, "", "", 0, "userinfo"},
		{"http://sdr.example.com/admin", false, "", "", 0, "path"},
		{"http://sdr.example.com/?x=1", false, "", "", 0, "query"},
		{"http://sdr.example.com/#frag", false, "", "", 0, "fragment"},
		{"http://localhost:8073", false, "", "", 0, "localhost (no dot)"},
		{"http://kiwi:8073", false, "", "", 0, "single label"},
		{"http://sdr.example.com.:8073", false, "", "", 0, "trailing dot"},
		{"http://-bad.example.com", false, "", "", 0, "leading hyphen"},
		{"http://bad_host.example.com", false, "", "", 0, "underscore"},
		{"http://exämple.com", false, "", "", 0, "non-ascii host"},
		{"http://xn--4ca.example.com:8073", true, "http", "xn--4ca.example.com", 8073, "punycode is LDH"},
		{"", false, "", "", 0, "empty"},
		{"http://", false, "", "", 0, "no host"},
		{"http://" + strings.Repeat("a", 64) + ".com", false, "", "", 0, "label too long"},
	}
	for _, c := range cases {
		t.Run(c.note, func(t *testing.T) {
			scheme, host, port, err := ParseReceiverURL(c.in)
			if c.ok {
				if err != nil {
					t.Fatalf("%q: unexpected error %v", c.in, err)
				}
				if scheme != c.scheme || host != c.host || port != c.port {
					t.Fatalf("%q: got %s %s %d", c.in, scheme, host, port)
				}
			} else if err == nil {
				t.Fatalf("%q: accepted as %s://%s:%d", c.in, scheme, host, port)
			}
		})
	}
}

func entry(overrides map[string]any) map[string]any {
	m := map[string]any{
		"url": "http://sdr.example.com:8073", "name": "Test Kiwi | Somewhere", "loc": "Somewhere",
		"antenna": "wire", "sw_version": "KiwiSDR_v1.902", "gps": []float64{44.8, 0.8},
		"users": 1, "users_max": 8, "ext_api": 4, "preempt": 0, "snr_hf": 30, "offline": false,
		"extra_field_we_ignore": map[string]any{"deep": []int{1, 2, 3}},
	}
	for k, v := range overrides {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func doc(entries ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"schema": 1, "source": "x", "fetched_at": "2026-10-10T01:00:35.000Z",
		"receiver_count": len(entries), "receivers": entries,
	})
	return b
}

func TestParseGood(t *testing.T) {
	snap, err := Parse(doc(entry(nil), entry(map[string]any{"url": "https://other.example.org", "ext_api": nil})))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Receivers) != 2 {
		t.Fatalf("got %d receivers", len(snap.Receivers))
	}
	if snap.FetchedAt.IsZero() {
		t.Error("fetched_at not parsed")
	}
	var a, b *Receiver
	for i := range snap.Receivers {
		switch snap.Receivers[i].Host {
		case "sdr.example.com":
			a = &snap.Receivers[i]
		case "other.example.org":
			b = &snap.Receivers[i]
		}
	}
	if a == nil || b == nil {
		t.Fatal("hosts missing")
	}
	if a.ExtAPI != 4 || b.ExtAPI != -1 {
		t.Errorf("ext_api: %d %d (missing must be -1)", a.ExtAPI, b.ExtAPI)
	}
	if b.Scheme != "https" || b.Port != 443 {
		t.Errorf("https entry: %s %d", b.Scheme, b.Port)
	}
	if len(a.ID) != 16 {
		t.Errorf("id %q", a.ID)
	}
	if r, ok := snap.Lookup(a.ID); !ok || r.Host != a.Host {
		t.Error("lookup failed")
	}
	if _, ok := snap.Lookup("nope"); ok {
		t.Error("lookup of unknown id succeeded")
	}
	// Browser JSON must not carry connection details.
	js, _ := json.Marshal(a)
	for _, forbidden := range []string{"sdr.example.com", "8073", "http"} {
		if strings.Contains(string(js), forbidden) {
			t.Errorf("browser JSON leaks %q: %s", forbidden, js)
		}
	}
}

func TestParseDropsBadEntriesKeepsGood(t *testing.T) {
	bad := []map[string]any{
		entry(map[string]any{"url": "http://127.0.0.1:8073"}),
		entry(map[string]any{"url": "http://10.0.0.5:8073"}),
		entry(map[string]any{"url": "http://sdr.example.com:22"}),
		entry(map[string]any{"url": 12345}),
		entry(map[string]any{"url": nil}),
		entry(map[string]any{"gps": []float64{0, 0}}),
		entry(map[string]any{"gps": []float64{91, 0}}),
		entry(map[string]any{"gps": []float64{1, 181}}),
		entry(map[string]any{"gps": "44,0"}),
		entry(map[string]any{"gps": []float64{1}}),
		entry(map[string]any{"gps": nil}),
		entry(map[string]any{"url": "http://" + strings.Repeat("a", 300) + ".com"}),
	}
	good := entry(map[string]any{"url": "http://good.example.com:8073"})
	snap, err := Parse(doc(append(bad, good)...))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Receivers) != 1 || snap.Receivers[0].Host != "good.example.com" {
		t.Fatalf("got %+v", snap.Receivers)
	}
}

func TestParseSanitisesAndClamps(t *testing.T) {
	e := entry(map[string]any{
		"name":      "Evil\u202E Kiwi\x00\x1b[31m " + strings.Repeat("x", 500),
		"loc":       "\u2066Paris\u2069",
		"antenna":   12345, // wrong type: becomes empty
		"users":     -5,
		"users_max": 1e9,
		"ext_api":   "4", // wrong type: unknown
		"preempt":   2.5, // non-integer: default
		"snr_hf":    999,
		"offline":   "yes", // wrong type: false
	})
	snap, err := Parse(doc(e))
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Receivers[0]
	if strings.ContainsAny(r.Name, "\u202E\x00\x1b") || len([]rune(r.Name)) > maxName {
		t.Errorf("name not sanitised: %q", r.Name)
	}
	if r.Loc != "Paris" {
		t.Errorf("loc = %q", r.Loc)
	}
	if r.Antenna != "" || r.Users != 0 || r.UsersMax != 1000 || r.ExtAPI != -1 || r.Preempt != 0 || r.SNR != 150 || r.Offline {
		t.Errorf("clamping: %+v", r)
	}
}

func TestParseRejectsDocument(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"not json":         []byte("<html>"),
		"array":            []byte("[]"),
		"wrong schema":     []byte(`{"schema":2,"receivers":[]}`),
		"no receivers":     []byte(`{"schema":1,"receivers":[]}`),
		"receivers object": []byte(`{"schema":1,"receivers":{}}`),
		"trailing data":    append(doc(entry(nil)), []byte(`{"schema":1}`)...),
		"too big":          make([]byte, MaxBytes+1),
		"deep nesting":     []byte(`{"schema":1,"receivers":[` + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + `]}`),
	}
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// too many receivers
	many := make([]map[string]any, MaxReceivers+1)
	for i := range many {
		many[i] = entry(map[string]any{"url": fmt.Sprintf("http://r%d.example.com:8073", i)})
	}
	if _, err := Parse(doc(many...)); err == nil {
		t.Error("too many receivers accepted")
	}
}

func TestParseDuplicateURLsCollapse(t *testing.T) {
	snap, err := Parse(doc(entry(nil), entry(map[string]any{"name": "Impostor"}), entry(map[string]any{"url": "http://SDR.EXAMPLE.COM:8073/"})))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Receivers) != 1 {
		t.Fatalf("duplicates not collapsed: %d", len(snap.Receivers))
	}
}

// --- fetcher ---------------------------------------------------------------

func testFetcher(t *testing.T, h http.Handler) (*Fetcher, *httptest.Server) {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	// httptest listens on 127.0.0.1:<port>; the fetcher's pinned host is
	// compared against the hostname part only.
	host := strings.TrimPrefix(srv.URL, "http://")
	f := newFetcher(netpolicy.Policy{AllowLoopback: true}, srv.URL+"/kiwi.json", strings.Split(host, ":")[0])
	return f, srv
}

func TestFetcherRefusesRedirect(t *testing.T) {
	f, _ := testFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	_, _, err := f.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
}

func TestFetcherCapsBody(t *testing.T) {
	f, _ := testFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"schema":1,"receivers":[`))
		filler := []byte(strings.Repeat(" ", 64<<10))
		for i := 0; i < (MaxBytes/len(filler))+2; i++ {
			w.Write(filler)
		}
		w.Write([]byte(`]}`))
	}))
	_, _, err := f.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size cap error, got %v", err)
	}
}

func TestFetcherRejectsNon200(t *testing.T) {
	f, _ := testFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	if _, _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("503 accepted")
	}
}

func TestFetcherRequiresTLSForRealSource(t *testing.T) {
	// The production fetcher must only ever dial the pinned host.
	f := NewFetcher(netpolicy.Policy{})
	tr := f.client.Transport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "evil.example.com:443"); err == nil {
		t.Fatal("dialed a non-pinned host")
	}
	if !strings.HasPrefix(f.url, "https://"+SourceHost+"/") {
		t.Fatalf("source url %q", f.url)
	}
}

func TestFetcherOK(t *testing.T) {
	f, _ := testFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" || !strings.Contains(r.Header.Get("User-Agent"), "Kiwi Garden") {
			t.Error("missing honest user agent")
		}
		w.Write(doc(entry(nil)))
	}))
	snap, body, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Receivers) != 1 || len(body) == 0 {
		t.Fatal("bad result")
	}
}

// --- store -------------------------------------------------------------------

func TestStoreCacheRoundTripAndRevalidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "directory.json")
	calls := 0
	f, _ := testFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write(doc(entry(nil)))
	}))
	s := NewStore(f, path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("cache mode %v", fi.Mode().Perm())
	}
	// Second store loads from cache without a network call.
	s2 := NewStore(f, path)
	if err := s2.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !s2.Current().FromCache {
		t.Fatalf("cache not used: calls=%d", calls)
	}
	// Tamper with the cache: inject a loopback receiver. It must be dropped
	// on re-validation, and the good entry kept.
	tampered := doc(entry(map[string]any{"url": "http://127.0.0.1:8073", "name": "LAN scanner"}), entry(nil))
	os.WriteFile(path, tampered, 0o600)
	s3 := NewStore(f, path)
	if err := s3.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range s3.Current().Receivers {
		if r.Host == "127.0.0.1" {
			t.Fatal("tampered loopback entry survived cache load")
		}
	}
	// Corrupt cache entirely: falls through to network.
	os.WriteFile(path, []byte("garbage"), 0o600)
	s4 := NewStore(f, path)
	if err := s4.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("corrupt cache did not trigger fetch: calls=%d", calls)
	}
	// Stale cache + failing network: stale data is served.
	old := time.Now().Add(-48 * time.Hour)
	os.WriteFile(path, doc(entry(nil)), 0o600)
	os.Chtimes(path, old, old)
	fbad, _ := testFetcher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	s5 := NewStore(fbad, path)
	if err := s5.Load(context.Background()); err != nil {
		t.Fatalf("stale fallback failed: %v", err)
	}
	if s5.Current() == nil || !s5.Current().FromCache {
		t.Fatal("stale cache not served")
	}
	// No cache + failing network: error.
	s6 := NewStore(fbad, filepath.Join(dir, "none.json"))
	if err := s6.Load(context.Background()); err == nil {
		t.Fatal("expected error with no cache and no network")
	}
	_ = errors.New
}

func FuzzParse(f *testing.F) {
	f.Add(doc(entry(nil)))
	f.Add([]byte(`{"schema":1,"receivers":[{"url":"http://a.b:8073","gps":[1,2]}]}`))
	f.Add([]byte(`{"schema":1,"receivers":[{"url":"http://127.0.0.1","gps":[1,2]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		snap, err := Parse(data)
		if err != nil {
			return
		}
		for _, r := range snap.Receivers {
			if err := (netpolicy.Policy{}).CheckPort(r.Port); err != nil {
				t.Fatalf("bad port survived: %d", r.Port)
			}
			if r.Host == "" || r.ID == "" || len([]rune(r.Name)) > maxName {
				t.Fatalf("bad receiver survived: %+v", r)
			}
			if r.Lat == 0 && r.Lon == 0 {
				t.Fatal("0,0 survived")
			}
		}
	})
}
