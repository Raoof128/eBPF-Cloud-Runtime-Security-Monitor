//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// tracepoints maps each program in ebpf/process_monitor.c to the syscall tracepoint it
// attaches to.
var tracepoints = map[string]string{
	"handle_execve":  "sys_enter_execve",
	"handle_connect": "sys_enter_connect",
	"handle_ptrace":  "sys_enter_ptrace",
	"handle_memfd":   "sys_enter_memfd_create",
	"handle_mmap":    "sys_enter_mmap",
}

func main() {
	logger := log.New(os.Stdout, "agent ", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	objectPath := envOr("BPF_OBJECT", "../ebpf/process_monitor.bpf.o")
	listenAddr := envOr("LISTEN_ADDR", "127.0.0.1:8090")

	// Kernels before 5.11 charge BPF memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Printf("remove memlock limit: %v (continuing)", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		logger.Fatalf("read %s: %v", objectPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		logger.Fatalf("load programs into the kernel: %v", err)
	}
	defer coll.Close()

	for progName, tracepoint := range tracepoints {
		prog := coll.Programs[progName]
		if prog == nil {
			logger.Fatalf("program %s is missing from %s", progName, objectPath)
		}
		attached, err := link.Tracepoint("syscalls", tracepoint, prog, nil)
		if err != nil {
			logger.Fatalf("attach %s to syscalls:%s: %v", progName, tracepoint, err)
		}
		defer attached.Close()
	}

	events := coll.Maps["events"]
	if events == nil {
		logger.Fatalf("map events is missing from %s", objectPath)
	}
	reader, err := perf.NewReader(events, 64*os.Getpagesize())
	if err != nil {
		logger.Fatalf("open perf reader: %v", err)
	}
	defer reader.Close()

	alertCh := make(chan Alert, 1024)
	srv := NewAlertServer(listenAddr, envOr("CORS_ORIGIN", "http://localhost:4173"), logger)
	go func() {
		if err := srv.ListenAndServe(ctx, alertCh); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("http server stopped: %v", err)
		}
	}()

	// reader.Read blocks, so closing the reader is what ends the loop on a signal.
	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	self := uint32(os.Getpid())
	logger.Printf("attached %d tracepoints; listening for kernel events", len(tracepoints))

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				logger.Println("shutting down")
				return
			}
			logger.Printf("read perf event: %v", err)
			continue
		}
		if record.LostSamples > 0 {
			logger.Printf("warning: the kernel dropped %d events (reader too slow)", record.LostSamples)
			continue
		}

		evt, err := decodeEvent(record.RawSample)
		if err != nil {
			logger.Printf("skip event: %v", err)
			continue
		}
		if evt.PID == self {
			continue // the agent's own syscalls
		}
		evt.Container = LookupContainerMetadata(int(evt.PID))
		evt.Pod = LookupPodMeta()
		evt.Timestamp = time.Now().UTC()

		for _, alert := range EvaluateRules(evt) {
			payload, err := json.Marshal(alert)
			if err != nil {
				logger.Printf("marshal alert: %v", err)
				continue
			}
			logger.Println(string(payload))
			select {
			case alertCh <- alert:
			default:
				logger.Printf("alert queue full, dropping %s alert", alert.RuleID)
			}
		}
	}
}

// envOr returns the environment value for key, or def if it is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
