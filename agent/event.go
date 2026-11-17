package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// rawEventSize is sizeof(struct event_t) in ebpf/process_monitor.c.
const rawEventSize = 320

// rawEvent mirrors struct event_t in ebpf/process_monitor.c byte for byte. The C struct has no
// hidden padding (its one pad byte is named), so reading the fields in order is correct. The
// address and port are kept as bytes because the kernel hands them over in network order.
type rawEvent struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	CgroupID  uint64
	DstIP     [4]byte
	DstPort   [2]byte
	Proto     uint8
	_         uint8
	Comm      [16]byte
	Filename  [256]byte
	EventType [16]byte
}

// Event types the probe emits.
const (
	EventExec    = "exec"
	EventConnect = "connect"
	EventPtrace  = "ptrace"
	EventMemfd   = "memfd"
	EventMmapWX  = "mmap_wx"
)

// RuntimeEvent is one decoded kernel event plus what the agent could find out about the
// process. It is what the rules look at and what an alert carries as JSON.
type RuntimeEvent struct {
	Type string `json:"type"`
	PID  uint32 `json:"pid"`
	// PPID is always 0: the probe does not look up the parent process.
	PPID      uint32        `json:"ppid"`
	UID       uint32        `json:"uid"`
	GID       uint32        `json:"gid"`
	CgroupID  uint64        `json:"cgroup_id"`
	Comm      string        `json:"comm"`
	Filename  string        `json:"filename,omitempty"`
	DstIP     string        `json:"dst_ip,omitempty"`
	DstPort   uint16        `json:"dst_port,omitempty"`
	Container ContainerMeta `json:"container"`
	Pod       PodMeta       `json:"pod"`
	Timestamp time.Time     `json:"timestamp"`
}

// decodeEvent turns one perf sample into a RuntimeEvent. Container, pod and timestamp are
// left for the caller to fill in. A perf sample may carry trailing padding, so anything
// beyond rawEventSize is ignored; a shorter sample is an error.
func decodeEvent(sample []byte) (RuntimeEvent, error) {
	if len(sample) < rawEventSize {
		return RuntimeEvent{}, fmt.Errorf("sample is %d bytes, want at least %d", len(sample), rawEventSize)
	}

	var raw rawEvent
	if err := binary.Read(bytes.NewReader(sample[:rawEventSize]), binary.LittleEndian, &raw); err != nil {
		return RuntimeEvent{}, fmt.Errorf("decode event: %w", err)
	}

	evt := RuntimeEvent{
		Type:     cString(raw.EventType[:]),
		PID:      raw.PID,
		PPID:     raw.PPID,
		UID:      raw.UID,
		GID:      raw.GID,
		CgroupID: raw.CgroupID,
		Comm:     cString(raw.Comm[:]),
		Filename: cString(raw.Filename[:]),
	}
	if evt.Type == EventConnect {
		evt.DstIP = net.IP(raw.DstIP[:]).String()
		evt.DstPort = binary.BigEndian.Uint16(raw.DstPort[:])
	}
	return evt, nil
}

// cString returns the bytes up to the first NUL as a string.
func cString(buf []byte) string {
	if n := bytes.IndexByte(buf, 0); n >= 0 {
		buf = buf[:n]
	}
	return string(buf)
}
