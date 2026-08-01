// Package oob is the OOB Interaction Service (doc 04 D7): the platform-owned
// callback collector for blind-vulnerability validation (SSRF, blind XSS,
// XXE, async RCE). It issues unique canary tokens/URLs per validation,
// records interactions, and exposes a lookup API to AVE/EVS.
//
// Self-hosted, single instance at MVP (doc 04 §9: no third party ever sees
// customer targets). State is in-memory with TTL — a restart loses pending
// canaries, which only downgrades affected validations to INCONCLUSIVE.
package oob

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
)

// Interaction is one recorded callback (doc 04 D7).
type Interaction struct {
	Token      string    `json:"token"`
	At         time.Time `json:"at"`
	Remote     string    `json:"remote"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"user_agent,omitempty"`
	BodySHA256 string    `json:"body_sha256,omitempty"`
}

// Canary is one issued canary.
type Canary struct {
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	Purpose   string    `json:"purpose"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Service is the OOB collector + lookup API.
type Service struct {
	publicBase string
	ttl        time.Duration
	log        *slog.Logger

	mu       sync.RWMutex
	canaries map[string]*Canary
	hits     map[string][]Interaction

	srv *http.Server
	ln  net.Listener
}

// New builds the Service. publicBase is the base URL embedded into canary
// URLs (e.g. "http://detect:8090").
func New(publicBase string, ttl time.Duration, log *slog.Logger) *Service {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		publicBase: strings.TrimRight(publicBase, "/"),
		ttl:        ttl,
		log:        log,
		canaries:   map[string]*Canary{},
		hits:       map[string][]Interaction{},
	}
}

// Mint issues a canary bound to purpose (in-process path used by AVE/EVS).
func (s *Service) Mint(purpose string) Canary {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := "s48" + hex.EncodeToString(b)
	now := time.Now().UTC()
	c := &Canary{
		Token:     token,
		URL:       s.publicBase + "/c/" + token,
		Purpose:   purpose,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.mu.Lock()
	s.canaries[token] = c
	s.mu.Unlock()
	return *c
}

// Lookup returns the recorded interactions for token (in-process path).
func (s *Service) Lookup(token string) []Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Interaction, len(s.hits[token]))
	copy(out, s.hits[token])
	return out
}

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------

// Handler returns the service's HTTP handler:
//
//	GET  /c/{token}            — canary callback (also POST/PUT — blind
//	                             callbacks arrive with any method/body)
//	POST /v1/canaries          — mint {purpose} → Canary
//	GET  /v1/interactions?token= — lookup API for AVE/EVS
//	GET  /healthz              — liveness
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/c/", s.handleCallback)
	mux.HandleFunc("POST /v1/canaries", s.handleMint)
	mux.HandleFunc("GET /v1/interactions", s.handleLookup)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// ListenAndServe starts the service on addr (e.g. ":8090"). It returns the
// bound address (useful with ":0" in tests).
func (s *Service) ListenAndServe(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("oob: listen %s: %w", addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("oob: serve failed", "err", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Shutdown stops the HTTP surface.
func (s *Service) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// handleCallback records any request to /c/{token} as an interaction.
func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/c/")
	token = strings.Trim(token, "/")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	_, known := s.canaries[token]
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 4096))
	}
	h := Interaction{
		Token:     token,
		At:        time.Now().UTC(),
		Remote:    r.RemoteAddr,
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		h.BodySHA256 = hex.EncodeToString(sum[:])
	}
	s.hits[token] = append(s.hits[token], h)
	s.mu.Unlock()
	if known {
		s.log.Info("oob interaction", "token", token, "method", r.Method, "remote", r.RemoteAddr)
	} else {
		s.log.Warn("oob interaction for UNKNOWN token (recorded, never trusted blindly)",
			"token", token, "remote", r.RemoteAddr)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleMint issues a canary via the lookup API.
func (s *Service) handleMint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c := s.Mint(req.Purpose)
	writeJSON(w, http.StatusCreated, c)
}

// handleLookup returns recorded interactions for a token.
func (s *Service) handleLookup(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"interactions": s.Lookup(token),
	})
}

// Client is the AVE/EVS OOBClient over the in-process service (doc 04 D7:
// "exposes lookup API to AVE/EVS"). It satisfies ave.OOBClient without an
// HTTP hop when embedded; the HTTP surface exists for sandboxed EVS packs.
type Client struct{ svc *Service }

// NewClient wraps svc for in-process consumers.
func NewClient(svc *Service) *Client { return &Client{svc: svc} }

// NewCanary implements ave.OOBClient.
func (c *Client) NewCanary(ctx context.Context, purpose string) (string, string, error) {
	canary := c.svc.Mint(purpose)
	return canary.Token, canary.URL, nil
}

// Interactions implements ave.OOBClient.
func (c *Client) Interactions(ctx context.Context, token string) ([]ave.OOBInteraction, error) {
	hits := c.svc.Lookup(token)
	out := make([]ave.OOBInteraction, 0, len(hits))
	for _, h := range hits {
		out = append(out, ave.OOBInteraction{
			Token: h.Token, At: h.At, Remote: h.Remote,
			Method: h.Method, Path: h.Path, UserAgent: h.UserAgent,
		})
	}
	return out, nil
}

// GC drops expired canaries and their hits (called periodically by main).
func (s *Service) GC() {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, c := range s.canaries {
		if now.After(c.ExpiresAt) {
			delete(s.canaries, token)
			delete(s.hits, token)
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
