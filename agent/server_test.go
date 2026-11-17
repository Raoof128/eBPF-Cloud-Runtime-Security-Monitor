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
	srv := NewAlertServer(addr, "http://localhost:4173", "", log.New(io.Discard, "", 0))
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
	srv := NewAlertServer(addr, "", "", log.New(io.Discard, "", 0))
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

func TestCheckListenConfig(t *testing.T) {
	tests := []struct {
		addr, token string
		wantErr     bool
	}{
		{"127.0.0.1:8090", "", false},
		{"localhost:8090", "", false},
		{"[::1]:8090", "", false},
		{":8090", "", true}, // every interface
		{"0.0.0.0:8090", "", true},
		{"[::]:8090", "", true},
		{"10.0.0.5:8090", "", true},
		{"not-an-address", "", true},
		{":8090", "s3cret", false},
		{"0.0.0.0:8090", "s3cret", false},
	}
	for _, tc := range tests {
		err := CheckListenConfig(tc.addr, tc.token)
		if (err != nil) != tc.wantErr {
			t.Errorf("CheckListenConfig(%q, token set: %v) = %v, want error: %v", tc.addr, tc.token != "", err, tc.wantErr)
		}
	}
}

func TestEventsRequiresTheBearerTokenWhenOneIsSet(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewAlertServer(addr, "", "correct-token", log.New(io.Discard, "", 0))
	go func() { _ = srv.ListenAndServe(ctx, make(chan Alert)) }()

	// Wait for the listener through the endpoint that needs no token.
	for attempt := 0; attempt < 50; attempt++ {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	tests := []struct {
		name, header string
		want         int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong-token", http.StatusUnauthorized},
		{"prefix of the token", "Bearer correct", http.StatusUnauthorized},
		{"token with a suffix", "Bearer correct-token-and-more", http.StatusUnauthorized},
		{"wrong scheme", "Basic correct-token", http.StatusUnauthorized},
		{"token without the scheme", "correct-token", http.StatusUnauthorized},
		{"right token", "Bearer correct-token", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx, cancelReq := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelReq()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/events", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
