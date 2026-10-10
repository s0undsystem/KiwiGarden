// Package directory fetches, validates, caches and serves the public
// KiwiSDR receiver list. The list is the relay's allowlist, and it is
// treated as hostile input at every step (see THREAT_MODEL.md 4.1).
package directory

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/netpolicy"
	"github.com/s0undsystem/KiwiGarden/internal/sanitize"
)

// Source is the single pinned directory URL. Only this host is ever
// contacted for the list. See docs/PHASE0.md section 2 for why.
const (
	SourceHost = "cdn.aethersdr.com"
	SourceURL  = "https://" + SourceHost + "/kiwi.json"

	// MaxBytes caps the response body. Today's file is ~0.8 MiB.
	MaxBytes = 4 << 20
	// MaxReceivers caps the number of entries we keep.
	MaxReceivers = 5000
	// RefreshInterval is how often the list is re-fetched.
	RefreshInterval = 24 * time.Hour
	// StaleAfter is the cache age beyond which we fetch before serving.
	StaleAfter = 24 * time.Hour
	// ExpectedSchema is the mirror's schema version we understand.
	ExpectedSchema = 1

	// proxyDomain is kiwisdr.com's reverse proxy. Entries there omit the
	// port and the :80 front end redirects to :8073; we never follow
	// redirects so we go to 8073 directly (docs/PHASE0.md 2.3).
	proxyDomain = ".proxy.kiwisdr.com"
	proxyPort   = 8073

	maxName    = 120
	maxLoc     = 80
	maxAntenna = 120
	maxVersion = 40
)

// Receiver is one validated entry. Everything here is safe to hand to the
// browser except the connection fields, which the server layer omits.
type Receiver struct {
	// ID is sha256(canonical URL) truncated; the browser's only handle.
	ID string `json:"id"`

	Name    string  `json:"name"`
	Loc     string  `json:"loc"`
	Antenna string  `json:"antenna"`
	Version string  `json:"version"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`

	Users    int  `json:"users"`
	UsersMax int  `json:"usersMax"`
	ExtAPI   int  `json:"extApi"` // -1 unknown, 0 refuses external clients
	Preempt  int  `json:"preempt"`
	SNR      int  `json:"snr"`
	Offline  bool `json:"offline"`

	// Connection details. Never serialised to the browser.
	Scheme string `json:"-"` // "http" or "https"
	Host   string `json:"-"` // hostname or IP literal, lower-case
	Port   int    `json:"-"`
}

// DialAddr is host:port.
func (r *Receiver) DialAddr() string { return net.JoinHostPort(r.Host, fmt.Sprint(r.Port)) }

// WSURL is the ws(s):// base URL (no path).
func (r *Receiver) WSURL() string {
	s := "ws"
	if r.Scheme == "https" {
		s = "wss"
	}
	return s + "://" + r.DialAddr()
}

// Snapshot is an immutable validated list plus provenance.
type Snapshot struct {
	Receivers []Receiver
	FetchedAt time.Time // when the mirror says it fetched from upstream
	LoadedAt  time.Time // when we obtained it
	FromCache bool
	byID      map[string]*Receiver
}

// Lookup returns the receiver with the given ID.
func (s *Snapshot) Lookup(id string) (*Receiver, bool) {
	if s == nil {
		return nil, false
	}
	r, ok := s.byID[id]
	return r, ok
}

// --- wire format -----------------------------------------------------------

type wireFile struct {
	Schema    int            `json:"schema"`
	FetchedAt string         `json:"fetched_at"`
	Receivers []wireReceiver `json:"receivers"`
}

// wireReceiver uses json.RawMessage for fields whose type we do not fully
// trust, so one malformed entry cannot abort decoding of the whole file.
type wireReceiver struct {
	URL      json.RawMessage `json:"url"`
	Name     json.RawMessage `json:"name"`
	Loc      json.RawMessage `json:"loc"`
	Antenna  json.RawMessage `json:"antenna"`
	Version  json.RawMessage `json:"sw_version"`
	GPS      json.RawMessage `json:"gps"`
	Users    json.RawMessage `json:"users"`
	UsersMax json.RawMessage `json:"users_max"`
	ExtAPI   json.RawMessage `json:"ext_api"`
	Preempt  json.RawMessage `json:"preempt"`
	SNRHF    json.RawMessage `json:"snr_hf"`
	Offline  json.RawMessage `json:"offline"`
}

// Parse validates a raw directory document. It is used for network
// responses and for the on-disk cache alike.
func Parse(data []byte) (*Snapshot, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("directory: %d bytes exceeds cap", len(data))
	}
	var f wireFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("directory: decode: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("directory: trailing data after JSON document")
	}
	if f.Schema != ExpectedSchema {
		return nil, fmt.Errorf("directory: schema %d, want %d", f.Schema, ExpectedSchema)
	}
	if len(f.Receivers) > MaxReceivers {
		return nil, fmt.Errorf("directory: %d receivers exceeds cap", len(f.Receivers))
	}
	snap := &Snapshot{LoadedAt: time.Now(), byID: make(map[string]*Receiver, len(f.Receivers))}
	if t, err := time.Parse(time.RFC3339, f.FetchedAt); err == nil {
		snap.FetchedAt = t
	}
	dropped := 0
	seen := make(map[string]bool, len(f.Receivers))
	for i := range f.Receivers {
		r, err := validate(&f.Receivers[i])
		if err != nil {
			dropped++
			slog.Debug("directory entry dropped", "url", sanitize.ForLog(strOr(f.Receivers[i].URL), 80), "err", sanitize.ForLog(err.Error(), 120))
			continue
		}
		if seen[r.ID] {
			dropped++
			continue
		}
		seen[r.ID] = true
		snap.Receivers = append(snap.Receivers, r)
	}
	sort.Slice(snap.Receivers, func(i, j int) bool { return snap.Receivers[i].ID < snap.Receivers[j].ID })
	for i := range snap.Receivers {
		snap.byID[snap.Receivers[i].ID] = &snap.Receivers[i]
	}
	if len(snap.Receivers) == 0 {
		return nil, errors.New("directory: no valid receivers")
	}
	slog.Info("directory parsed", "receivers", len(snap.Receivers), "dropped", dropped)
	return snap, nil
}

func validate(w *wireReceiver) (Receiver, error) {
	var r Receiver
	rawURL, err := str(w.URL, 256)
	if err != nil {
		return r, fmt.Errorf("url: %w", err)
	}
	scheme, host, port, err := ParseReceiverURL(rawURL)
	if err != nil {
		return r, err
	}
	r.Scheme, r.Host, r.Port = scheme, host, port
	sum := sha256.Sum256([]byte(scheme + "://" + r.DialAddr()))
	r.ID = hex.EncodeToString(sum[:8])

	r.Name = sanitize.Text(strOr(w.Name), maxName)
	r.Loc = sanitize.Text(strOr(w.Loc), maxLoc)
	r.Antenna = sanitize.Text(strOr(w.Antenna), maxAntenna)
	r.Version = sanitize.Text(strOr(w.Version), maxVersion)
	if r.Name == "" {
		r.Name = r.Host
	}

	var gps []float64
	if err := json.Unmarshal(w.GPS, &gps); err != nil || len(gps) != 2 {
		return r, errors.New("gps: not [lat, lon]")
	}
	lat, lon := gps[0], gps[1]
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) ||
		lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0) {
		return r, errors.New("gps: out of range")
	}
	r.Lat, r.Lon = lat, lon

	r.Users = intOr(w.Users, 0, 0, 1000)
	r.UsersMax = intOr(w.UsersMax, 0, 0, 1000)
	r.ExtAPI = intOr(w.ExtAPI, -1, 0, 64)
	r.Preempt = intOr(w.Preempt, 0, 0, 64)
	r.SNR = intOr(w.SNRHF, 0, -50, 150)
	var off bool
	if err := json.Unmarshal(w.Offline, &off); err == nil {
		r.Offline = off
	}
	return r, nil
}

// ParseReceiverURL applies the URL rules from THREAT_MODEL.md 4.1.
func ParseReceiverURL(raw string) (scheme, host string, port int, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, fmt.Errorf("url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", 0, fmt.Errorf("url: scheme %q", u.Scheme)
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return "", "", 0, errors.New("url: userinfo/query/fragment not allowed")
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", 0, errors.New("url: path not allowed")
	}
	host = strings.ToLower(u.Hostname())
	if host == "" || len(host) > 253 {
		return "", "", 0, errors.New("url: bad host")
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		// Literal IP: apply the policy now as well as at dial time.
		if cerr := (netpolicy.Policy{}).CheckIP(ip); cerr != nil {
			return "", "", 0, cerr
		}
		if ip.Is6() {
			host = ip.String()
		}
	} else if !validHostname(host) {
		return "", "", 0, errors.New("url: bad hostname")
	}
	switch p := u.Port(); {
	case p != "":
		port, err = netpolicy.ParsePort(p)
		if err != nil {
			return "", "", 0, err
		}
	case strings.HasSuffix(host, proxyDomain):
		port = proxyPort
	case u.Scheme == "https":
		port = 443
	default:
		port = 80
	}
	if err := (netpolicy.Policy{}).CheckPort(port); err != nil {
		return "", "", 0, err
	}
	return u.Scheme, host, port, nil
}

// validHostname accepts LDH labels only (RFC 1123), no trailing dot.
func validHostname(h string) bool {
	if strings.HasSuffix(h, ".") || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func str(raw json.RawMessage, max int) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	if len(s) > max {
		return "", errors.New("too long")
	}
	return s, nil
}

func strOr(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	if len(s) > 4096 {
		s = s[:4096]
	}
	return s
}

func intOr(raw json.RawMessage, def, lo, hi int) int {
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return def
	}
	n := int(f)
	if float64(n) != f {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// --- fetching ----------------------------------------------------------------

// Fetcher downloads the directory from the pinned source.
type Fetcher struct {
	client *http.Client
	url    string
}

// NewFetcher builds an HTTP client restricted to the pinned host: policy
// dialer, TLS 1.2+, no redirects, no proxies from the environment.
func NewFetcher(policy netpolicy.Policy) *Fetcher {
	return newFetcher(policy, SourceURL, SourceHost)
}

func newFetcher(policy netpolicy.Policy, srcURL, srcHost string) *Fetcher {
	dialer := policy.Dialer(15 * time.Second)
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil || !strings.EqualFold(host, srcHost) {
				return nil, fmt.Errorf("directory: refusing to dial %q", addr)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: srcHost},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	return &Fetcher{
		url: srcURL,
		client: &http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("directory: redirects are not followed")
			},
		},
	}
}

// Fetch downloads and validates the directory.
func (f *Fetcher) Fetch(ctx context.Context) (*Snapshot, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Kiwi Garden (github.com/s0undsystem/KiwiGarden)")
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("directory: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("directory: HTTP %d", resp.StatusCode)
	}
	if resp.TLS == nil && !strings.HasPrefix(f.url, "http://127.0.0.1") {
		return nil, nil, errors.New("directory: response was not over TLS")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("directory: read: %w", err)
	}
	if len(body) > MaxBytes {
		return nil, nil, fmt.Errorf("directory: body exceeds %d bytes", MaxBytes)
	}
	snap, err := Parse(body)
	if err != nil {
		return nil, nil, err
	}
	return snap, body, nil
}

// --- store (cache + refresh) ---------------------------------------------------

// Store holds the current snapshot, persists it to disk and refreshes it.
type Store struct {
	fetcher   *Fetcher
	cachePath string

	mu   sync.RWMutex
	snap *Snapshot
}

// DefaultCachePath is <user cache dir>/kiwi-garden/directory.json.
func DefaultCachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "kiwi-garden", "directory.json"), nil
}

// NewStore creates a store. cachePath may be "" to disable the disk cache.
func NewStore(f *Fetcher, cachePath string) *Store {
	return &Store{fetcher: f, cachePath: cachePath}
}

// Current returns the latest snapshot (nil if none yet).
func (s *Store) Current() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// Load populates the store: from a fresh-enough cache if present, otherwise
// from the network, falling back to a stale cache if the network fails.
func (s *Store) Load(ctx context.Context) error {
	cached, cachedAt := s.readCache()
	if cached != nil && time.Since(cachedAt) < StaleAfter {
		cached.FromCache = true
		s.set(cached)
		slog.Info("directory loaded from cache", "age", time.Since(cachedAt).Round(time.Minute), "receivers", len(cached.Receivers))
		return nil
	}
	if err := s.Refresh(ctx); err != nil {
		if cached != nil {
			cached.FromCache = true
			s.set(cached)
			slog.Warn("directory refresh failed; using stale cache", "err", err, "age", time.Since(cachedAt).Round(time.Minute))
			return nil
		}
		return err
	}
	return nil
}

// Refresh fetches from the network and updates cache and snapshot.
func (s *Store) Refresh(ctx context.Context) error {
	snap, body, err := s.fetcher.Fetch(ctx)
	if err != nil {
		return err
	}
	s.set(snap)
	s.writeCache(body)
	slog.Info("directory refreshed", "receivers", len(snap.Receivers), "upstream_fetched_at", snap.FetchedAt.Format(time.RFC3339))
	return nil
}

// RunRefresh refreshes every RefreshInterval until ctx is done.
func (s *Store) RunRefresh(ctx context.Context) {
	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil {
				slog.Warn("directory refresh failed", "err", err)
			}
		}
	}
}

func (s *Store) set(snap *Snapshot) {
	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
}

// readCache loads and RE-VALIDATES the cache file. Another local process
// could have edited it, so it gets exactly the treatment a network
// response gets.
func (s *Store) readCache() (*Snapshot, time.Time) {
	if s.cachePath == "" {
		return nil, time.Time{}
	}
	fi, err := os.Stat(s.cachePath)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxBytes {
		return nil, time.Time{}
	}
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return nil, time.Time{}
	}
	snap, err := Parse(data)
	if err != nil {
		slog.Warn("directory cache invalid; ignoring", "err", err)
		return nil, time.Time{}
	}
	return snap, fi.ModTime()
}

func (s *Store) writeCache(body []byte) {
	if s.cachePath == "" {
		return
	}
	dir := filepath.Dir(s.cachePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("directory cache dir", "err", err)
		return
	}
	tmp, err := os.CreateTemp(dir, "directory-*.tmp")
	if err != nil {
		slog.Warn("directory cache write", "err", err)
		return
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	if err := os.Rename(tmpName, s.cachePath); err != nil {
		slog.Warn("directory cache rename", "err", err)
		return
	}
	ok = true
}
