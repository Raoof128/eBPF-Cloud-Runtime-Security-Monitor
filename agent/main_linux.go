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
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// programName is the one program in ebpf/process_monitor.c. It attaches to the raw sys_enter
// tracepoint and picks out the six syscalls itself.
const programName = "handle_sys_enter"

func main() {
	logger := log.New(os.Stdout, "agent ", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	objectPath := envOr("BPF_OBJECT", "../ebpf/process_monitor.bpf.o")
	listenAddr := envOr("LISTEN_ADDR", "127.0.0.1:8090")
	eventsToken := os.Getenv("EVENTS_TOKEN")
	if err := CheckListenConfig(listenAddr, eventsToken); err != nil {
		logger.Fatalf("refusing to start: %v", err)
	}

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

	prog := coll.Programs[programName]
	if prog == nil {
		logger.Fatalf("program %s is missing from %s", programName, objectPath)
	}
	attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: prog})
	if err != nil {
		logger.Fatalf("attach %s to the sys_enter raw tracepoint: %v", programName, err)
	}
	defer attached.Close()

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
	srv := NewAlertServer(listenAddr, envOr("CORS_ORIGIN", "http://localhost:4173"), eventsToken, logger)
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

	// LOG_EVENTS=1 prints every event the probe sends, not only the ones a rule fires on.
	// It is for debugging: on a busy host that is a great deal of output.
	logEvents := os.Getenv("LOG_EVENTS") == "1"
	logger.Println("attached to sys_enter; listening for kernel events")

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
		if evt.Type == EventExec || evt.Type == EventExecveat {
			evt.ResolvedPath = resolveExecPath(evt.Filename, evt.PID, evt.DirFD, processDir)
		}
		evt.Container = LookupContainerMetadata(int(evt.PID))
		evt.Pod = LookupPodMeta()
		evt.Timestamp = time.Now().UTC()

		if logEvents {
			if payload, err := json.Marshal(evt); err == nil {
				logger.Printf("event cpu=%d %s", record.CPU, payload)
			}
		}

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

// processDir finds the directory a relative exec path is relative to: the process's working
// directory for AT_FDCWD, otherwise whatever its descriptor dirfd is open on. Both come from
// /proc, so it fails for a process that has already exited, which a short-lived one may have
// by the time its event is read.
func processDir(pid uint32, dirfd int32) (string, bool) {
	link := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cwd"
	if dirfd != atFdCwd {
		if dirfd < 0 {
			return "", false
		}
		link = "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/fd/" + strconv.Itoa(int(dirfd))
	}
	dir, err := os.Readlink(link)
	if err != nil {
		return "", false
	}
	return dir, true
}

// envOr returns the environment value for key, or def if it is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
