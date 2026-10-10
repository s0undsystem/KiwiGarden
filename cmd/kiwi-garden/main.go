// kiwi-garden serves the globe UI on 127.0.0.1 and relays audio from
// public KiwiSDR receivers to it.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/s0undsystem/KiwiGarden/internal/directory"
	"github.com/s0undsystem/KiwiGarden/internal/netpolicy"
	"github.com/s0undsystem/KiwiGarden/internal/relay"
	"github.com/s0undsystem/KiwiGarden/internal/server"
	"github.com/s0undsystem/KiwiGarden/internal/ui"
)

func main() {
	var (
		port    = flag.Int("port", 0, "port on 127.0.0.1 (0 = pick a free one)")
		cache   = flag.String("cache", "", "directory cache file (default: user cache dir)")
		noCache = flag.Bool("no-cache", false, "do not read or write the directory cache")
		verbose = flag.Bool("v", false, "debug logging")
		dev     = flag.Bool("dev", false, "developer mode: reuse a session token stored in the cache dir so the browser tab survives restarts")
	)
	flag.Parse()

	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Production policy: zero value. Nothing here ever sets AllowLoopback.
	policy := netpolicy.Policy{}

	cachePath := *cache
	if !*noCache && cachePath == "" {
		p, err := directory.DefaultCachePath()
		if err != nil {
			slog.Warn("no user cache dir; running without directory cache", "err", err)
		} else {
			cachePath = p
		}
	}
	if *noCache {
		cachePath = ""
	}
	store := directory.NewStore(directory.NewFetcher(policy), cachePath)
	lctx, lcancel := context.WithTimeout(ctx, 90*time.Second)
	if err := store.Load(lctx); err != nil {
		lcancel()
		slog.Error("cannot load receiver directory", "err", err)
		os.Exit(1)
	}
	lcancel()
	go store.RunRefresh(ctx)

	rm := relay.NewManager(relay.Config{Policy: policy})

	srv, err := server.New(store, rm, ui.FS())
	if err != nil {
		slog.Error("server init", "err", err)
		os.Exit(1)
	}
	if *dev {
		if err := useDevToken(srv); err != nil {
			slog.Error("dev token", "err", err)
			os.Exit(1)
		}
		slog.Warn("developer mode: session token is persisted on disk and reused across restarts")
	}
	ln, err := srv.Listen(*port)
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
	hs := srv.HTTPServer()
	go func() {
		if err := hs.Serve(ln); err != nil && ctx.Err() == nil {
			slog.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	if ui.FS() == nil {
		slog.Warn("UI not built: only the API is available (run `make ui`)")
	}
	// The one and only place the token is printed. It is in the URL
	// fragment, which browsers never send to the server.
	fmt.Fprintf(os.Stdout, "\nKiwi Garden is running. Open this URL in your browser:\n\n    %s\n\nKeep this terminal open. Press Ctrl-C to quit.\n\n", srv.LaunchURL())

	<-ctx.Done()
	slog.Info("shutting down")
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	hs.Shutdown(sctx)
}

// useDevToken loads or creates <cache dir>/kiwi-garden/dev-token (0600) and
// installs it. A same-user process can read it; that is the documented
// trade-off of -dev (THREAT_MODEL.md 4.3).
func useDevToken(srv *server.Server) error {
	base, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(base, "kiwi-garden")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, "dev-token")
	raw, err := os.ReadFile(p)
	if err == nil && len(raw) == 32 {
		return srv.UseToken(raw)
	}
	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return err
	}
	return srv.UseToken(raw)
}
