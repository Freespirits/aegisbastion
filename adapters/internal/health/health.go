// Package health serves the /healthz (liveness) and /readyz (readiness)
// endpoints every adapter exposes. Readiness means the adapter can reach its
// upstreams (Orchestrator PlannerService; the HexStrike server in live mode);
// liveness means the process is up.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"
)

// ReadyFunc reports whether an upstream dependency is usable. It must be
// cheap and must honour the passed context's deadline.
type ReadyFunc func(ctx context.Context) error

// Server is a small HTTP server dedicated to the health surface.
type Server struct {
	addr string
	srv  *http.Server
	ln   net.Listener
}

// Handler returns the health/readiness handler pair for mounting into any
// mux (the CAI adapter serves health on its main listener this way).
func Handler(service string, ready ReadyFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": service})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready == nil {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "service": service})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := ready(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready", "service": service, "error": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "service": service})
	})
	return mux
}

// New builds the health server. ready is called (with a bounded context) on
// every /readyz request; a nil ready means "always ready".
func New(addr, service string, ready ReadyFunc) *Server {
	return &Server{
		addr: addr,
		srv:  &http.Server{Handler: Handler(service, ready), ReadHeaderTimeout: 5 * time.Second},
	}
}

// Start binds and serves in the background. It returns an error immediately
// if the address cannot be bound.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("health: serve %s: %v", s.addr, err)
		}
	}()
	return nil
}

// Addr returns the bound address (useful with ":0").
func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.addr
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
