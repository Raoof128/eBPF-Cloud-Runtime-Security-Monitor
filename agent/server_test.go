package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestEventsStreamDeliversAlertsWithTheCORSHeader(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alerts := make(chan Alert, 1)
	srv := NewAlertServer(addr, "http://localhost:4173", log.New(io.Discard, "", 0))
	go func() { _ = srv.ListenAndServe(ctx, alerts) }()

	var resp *http.Response
	var err error
	for attempt := 0; attempt < 50; attempt++ {
		resp, err = http.Get("http://" + addr + "/events")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to /events: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:4173" {
		t.Fatalf("CORS header %q", got)
	}

	// The response headers have arrived, so the handler has subscribed (it does so first).
	alerts <- Alert{RuleID: "reverse_shell", Event: RuntimeEvent{Comm: "bash"}}

	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		lines <- line
	}()
	select {
	case line := <-lines:
		if !strings.HasPrefix(line, "data: ") || !strings.Contains(line, `"rule_id":"reverse_shell"`) {
			t.Fatalf("unexpected frame: %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no alert arrived on the stream")
	}
}

func TestHealthz(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewAlertServer(addr, "", log.New(io.Discard, "", 0))
	go func() { _ = srv.ListenAndServe(ctx, make(chan Alert)) }()

	var resp *http.Response
	var err error
	for attempt := 0; attempt < 50; attempt++ {
		resp, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
