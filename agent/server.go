package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

// AlertServer provides an SSE endpoint for live alerts.
type AlertServer struct {
	addr        string
	corsOrigin  string
	token       string
	logger      *log.Logger
	subscribers map[chan Alert]struct{}
	mu          sync.Mutex
}

// ErrTokenRequired is returned when the server is asked to listen beyond the loopback
// interface without a token to protect the alert stream.
var ErrTokenRequired = errors.New("LISTEN_ADDR is not a loopback address: set EVENTS_TOKEN, or listen on 127.0.0.1")

// CheckListenConfig refuses the one unsafe combination: an address other hosts can reach and
// no token. Alerts carry process names, paths and connection targets, so the stream is never
// served to the network unauthenticated.
func CheckListenConfig(addr, token string) error {
	if token != "" || isLoopbackAddr(addr) {
		return nil
	}
	return ErrTokenRequired
}

// isLoopbackAddr reports whether a listen address ("host:port") is bound to loopback only.
// An empty host (":8090") means every interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewAlertServer constructs a server bound to addr.
//
// corsOrigin is the one browser origin allowed to read /events (the dashboard's); an empty
// string sends no CORS header. token, if not empty, must be presented to /events as
// "Authorization: Bearer <token>". Call CheckListenConfig first: this constructor does not
// decide whether the combination is safe.
func NewAlertServer(addr, corsOrigin, token string, logger *log.Logger) *AlertServer {
	return &AlertServer{
		addr:        addr,
		corsOrigin:  corsOrigin,
		token:       token,
		logger:      logger,
		subscribers: make(map[chan Alert]struct{}),
	}
}

// ListenAndServe starts the HTTP server and streams alerts over /events.
func (s *AlertServer) ListenAndServe(ctx context.Context, alerts <-chan Alert) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		if s.corsOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.corsOrigin)
		}

		// Subscribe before the headers go out, so a client that has seen the response
		// start is already receiving alerts.
		client := make(chan Alert, 32)
		s.addSubscriber(client)
		defer s.removeSubscriber(client)

		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		notify := r.Context().Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-notify:
				return
			case alert := <-client:
				data, err := json.Marshal(alert)
				if err != nil {
					s.logger.Printf("marshal alert: %v", err)
					continue
				}
				if _, err := w.Write([]byte("data: " + string(data) + "\n\n")); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})

	srv := &http.Server{Addr: s.addr, Handler: mux}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	go func() {
		for alert := range alerts {
			s.broadcast(alert)
		}
	}()

	s.logger.Printf("http server listening on %s", s.addr)
	return srv.ListenAndServe()
}

func (s *AlertServer) addSubscriber(ch chan Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers[ch] = struct{}{}
}

func (s *AlertServer) removeSubscriber(ch chan Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subscribers, ch)
	close(ch)
}

func (s *AlertServer) broadcast(alert Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- alert:
		default:
			// Drop if client is slow to avoid blocking producer.
		}
	}
}

// authorized reports whether the request may read the alert stream. With no token configured
// (loopback only, see CheckListenConfig) every request may. Otherwise the request must carry
// the token as a bearer credential; the comparison is constant-time, and on digests so that
// it does not leak the token's length either.
func (s *AlertServer) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	want := sha256.Sum256([]byte(s.token))
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}
