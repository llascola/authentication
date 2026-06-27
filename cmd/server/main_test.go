package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"authentication/internal/config"
)

func testConfig() config.Config {
	return config.Config{
		ListenAddr:   "127.0.0.1:0",
		IdleTTL:      30 * time.Minute,
		AbsTTL:       24 * time.Hour,
		BcryptCost:   4,
		CookieSecure: true,
	}
}

func TestNewServerBuildsDependencyGraph(t *testing.T) {
	srv := newServer(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if srv == nil {
		t.Fatal("newServer returned nil")
	}
	if srv.Handler == nil {
		t.Error("server has no handler; wiring incomplete")
	}
	if srv.Addr != "127.0.0.1:0" {
		t.Errorf("Addr = %q, want 127.0.0.1:0", srv.Addr)
	}
}

func TestServerStartsAndShutsDownCleanly(t *testing.T) {
	srv := newServer(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// The server is up; a graceful shutdown must return without error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-serveErr; err != nil && err != http.ErrServerClosed {
		t.Fatalf("Serve returned %v, want ErrServerClosed", err)
	}
}
