package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path"
	"strings"
	"time"
)

// rawEventSize is sizeof(struct event_t) in ebpf/process_monitor.c.
const rawEventSize = 360

// rawEvent mirrors struct event_t in ebpf/process_monitor.c byte for byte. The C struct has no
// hidden padding (its one pad byte is named), so reading the fields in order is correct. The
// addresses and the port are kept as bytes because the kernel hands them over in network
// order.
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
	Family    uint32
	DirFD     int32
	Arg0      uint64
	Arg1      uint64
	DstIP6    [16]byte
	Comm      [16]byte
	Filename  [256]byte
	EventType [16]byte
}

// Event types the probe emits.
const (
	EventExec     = "exec"
	EventExecveat = "execveat"
	EventConnect  = "connect"
	EventPtrace   = "ptrace"
	EventMemfd    = "memfd"
	EventMmapExec = "mmap_exec"
)

// Linux constants the decoder and the rules need. They are spelled out so the package builds
// and its tests run on any OS.
const (
	afUnix  = 1
	afInet  = 2
	afInet6 = 10

	atFdCwd     = -100   // execveat: "relative to the working directory"
	atEmptyPath = 0x1000 // execveat: run the file the descriptor refers to

	protWrite    = 0x2
	protExec     = 0x4
	mapAnonymous = 0x20 // the same value on x86-64 and arm64
)

// RuntimeEvent is one decoded kernel event plus what the agent could find out about the
// process. It is what the rules look at and what an alert carries as JSON. Fields that only
// one event type uses are omitted from the JSON of the others.
type RuntimeEvent struct {
	Type string `json:"type"`
	PID  uint32 `json:"pid"`
	// PPID is always 0: the probe does not look up the parent process.
	PPID     uint32 `json:"ppid"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	CgroupID uint64 `json:"cgroup_id"`
	Comm     string `json:"comm"`

	// exec, execveat, memfd: the path or name the caller passed.
	Filename string `json:"filename,omitempty"`
	// exec, execveat: Filename made absolute and cleaned. See resolveExecPath.
	ResolvedPath string `json:"resolved_path,omitempty"`
	// execveat: the directory descriptor and flags arguments.
	DirFD     int32  `json:"dirfd,omitempty"`
	ExecFlags uint64 `json:"exec_flags,omitempty"`

	// connect: the address family as a number (2 IPv4, 10 IPv6, 1 Unix, ...) and, for IPv4
	// and IPv6, the destination. An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is given in
	// its IPv4 form, with Family still 10.
	Family  uint32 `json:"family,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	// ptrace: the request number and its name where the agent knows one. Request 0
	// (PTRACE_TRACEME) is left out of the JSON as a number; its name is still there.
	PtraceRequest     uint64 `json:"ptrace_request,omitempty"`
	PtraceRequestName string `json:"ptrace_request_name,omitempty"`

	// mmap_exec: the prot and flags arguments.
	MmapProt  uint64 `json:"mmap_prot,omitempty"`
	MmapFlags uint64 `json:"mmap_flags,omitempty"`

	Container ContainerMeta `json:"container"`
	Pod       PodMeta       `json:"pod"`
	Timestamp time.Time     `json:"timestamp"`
}

// decodeEvent turns one perf sample into a RuntimeEvent. ResolvedPath, container, pod and
// timestamp are left for the caller to fill in. A perf sample may carry trailing padding, so
// anything beyond rawEventSize is ignored; a shorter sample is an error.
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

	switch evt.Type {
	case EventExec:
		evt.DirFD = atFdCwd // execve resolves a relative path against the working directory
	case EventExecveat:
		evt.DirFD = raw.DirFD
		evt.ExecFlags = raw.Arg0
	case EventConnect:
		evt.Family = raw.Family
		switch raw.Family {
		case afInet:
			evt.DstIP = net.IP(raw.DstIP[:]).String()
			evt.DstPort = binary.BigEndian.Uint16(raw.DstPort[:])
		case afInet6:
			// net.IP.String prints an IPv4-mapped address in its IPv4 form.
			evt.DstIP = net.IP(raw.DstIP6[:]).String()
			evt.DstPort = binary.BigEndian.Uint16(raw.DstPort[:])
		}
	case EventPtrace:
		evt.PtraceRequest = raw.Arg0
		evt.PtraceRequestName = ptraceRequestNames[raw.Arg0]
	case EventMmapExec:
		evt.MmapProt = raw.Arg0
		evt.MmapFlags = raw.Arg1
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

// resolveExecPath turns the string a process passed to execve or execveat into the path the
// rules match on: made absolute if it was relative, then cleaned lexically, so
// "/tmp/../tmp/x", "//tmp/x" and "./x" run from /tmp all come out as "/tmp/x".
//
// A relative path is relative to dirfd: the working directory when dirfd is AT_FDCWD (always
// the case for execve), otherwise the directory that descriptor is open on. lookupDir finds
// that directory for a process and reports whether it could (the agent reads
// /proc/<pid>/cwd or /proc/<pid>/fd/<n>). When it cannot, usually because the process has
// already exited, the path is returned cleaned but still relative.
//
// This is string work in user space. It does not follow symbolic or hard links and it does
// not see through mount namespaces, so it is not proof of which file ran.
func resolveExecPath(filename string, pid uint32, dirfd int32, lookupDir func(pid uint32, dirfd int32) (string, bool)) string {
	name := strings.TrimSpace(filename)
	if name == "" {
		return ""
	}
	if !path.IsAbs(name) && lookupDir != nil {
		if dir, ok := lookupDir(pid, dirfd); ok && path.IsAbs(dir) {
			name = dir + "/" + name
		}
	}
	return path.Clean(name)
}
