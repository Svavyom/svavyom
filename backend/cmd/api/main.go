// Command api is the Svavyom control-plane API process (stories M0-E01-S04, M1-E04-S05, M1-E04-S01).
//
//	api serve --db FILE [--listen ADDR] [--static-dir DIR] [--host-name NAME] [--tls-cert F --tls-key F | --behind-tls-proxy]
//	api bootstrap-admin --db FILE --username NAME      (password on standard input)
//	api reset-admin-password --db FILE                 (password on standard input; revokes every session)
//
// Without a subcommand it starts the loopback development scaffold (GET /healthz only). The listener is loopback
// unless native TLS is configured. --behind-tls-proxy is accepted only with a loopback listener.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/api"
)

// listenAddr is loopback-only: the scaffold must never listen publicly.
const listenAddr = "127.0.0.1:8081"

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

// newHandler returns the scaffold browser-api handler: GET /healthz only. Every other route declared in
// contracts/openapi.yaml is rejected with a typed error, anything else is not_found (M0-E01-S04).
func newHandler() http.Handler {
	return api.NewHandler()
}

func newServer() *http.Server {
	return &http.Server{Addr: listenAddr, Handler: newHandler(), ReadHeaderTimeout: 5 * time.Second}
}

func main() {
	if len(os.Args) > 1 {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	server := newServer()
	log.Printf("development scaffold only at %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Print(err)
		os.Exit(1)
	}
}
