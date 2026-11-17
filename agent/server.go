package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// AlertServer provides an SSE endpoint for live alerts.
type AlertServer struct {
	addr        string
	corsOrigin  string
	logger      *log.Logger
	subscribers map[chan Alert]struct{}
	mu          sync.Mutex
}

// NewAlertServer constructs a server bound to addr. corsOrigin is the one browser origin
// allowed to read /events (the dashboard's); an empty string sends no CORS header.
//
// The endpoints have no authentication. Bind to a loopback address unless the network is
// trusted.
func NewAlertServer(addr, corsOrigin string, logger *log.Logger) *AlertServer {
	return &AlertServer{
		addr:        addr,
		corsOrigin:  corsOrigin,
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
