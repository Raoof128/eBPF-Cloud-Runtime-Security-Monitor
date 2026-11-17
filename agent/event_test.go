package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// Offsets of struct event_t in ebpf/process_monitor.c. The samples below are laid out by hand
// at these offsets, so a change to rawEvent that shifts a field fails these tests.
const (
	offPID      = 0
	offPPID     = 4
	offUID      = 8
	offGID      = 12
	offCgroup   = 16
	offDstIP    = 24
	offDstPort  = 28
	offProto    = 30
	offFamily   = 32
	offDirFD    = 36
	offArg0     = 40
	offArg1     = 48
	offDstIP6   = 56
	offComm     = 72
	offFilename = 88
	offType     = 344
)

// sample builds an event with the common fields set. Callers add what their event type needs.
func sample(eventType, comm, filename string) []byte {
	buf := make([]byte, rawEventSize)
	binary.LittleEndian.PutUint32(buf[offPID:], 1234)
	binary.LittleEndian.PutUint32(buf[offPPID:], 0)
	binary.LittleEndian.PutUint32(buf[offUID:], 1000)
	binary.LittleEndian.PutUint32(buf[offGID:], 1001)
	binary.LittleEndian.PutUint64(buf[offCgroup:], 0x1122334455667788)
	copy(buf[offComm:], comm)
	copy(buf[offFilename:], filename)
	copy(buf[offType:], eventType)
	return buf
}

func connectV4(comm string, ip [4]byte, port uint16) []byte {
	buf := sample("connect", comm, "")
	binary.LittleEndian.PutUint32(buf[offFamily:], afInet)
	copy(buf[offDstIP:], ip[:]) // network order, as the kernel gives it
	binary.BigEndian.PutUint16(buf[offDstPort:], port)
	return buf
}

func connectV6(comm string, ip [16]byte, port uint16) []byte {
	buf := sample("connect", comm, "")
	binary.LittleEndian.PutUint32(buf[offFamily:], afInet6)
	copy(buf[offDstIP6:], ip[:])
	binary.BigEndian.PutUint16(buf[offDstPort:], port)
	return buf
}

func TestRawEventMatchesTheCStruct(t *testing.T) {
	if got := binary.Size(rawEvent{}); got != rawEventSize {
		t.Fatalf("rawEvent is %d bytes, want %d (sizeof(struct event_t))", got, rawEventSize)
	}
}

func TestDecodeIPv4Connect(t *testing.T) {
	evt, err := decodeEvent(connectV4("bash", [4]byte{10, 0, 0, 5}, 4444))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Type != "connect" || evt.Comm != "bash" {
		t.Fatalf("type %q comm %q", evt.Type, evt.Comm)
	}
	if evt.PID != 1234 || evt.UID != 1000 || evt.GID != 1001 || evt.CgroupID != 0x1122334455667788 {
		t.Fatalf("ids decoded wrongly: %+v", evt)
	}
	if evt.Family != afInet || evt.DstIP != "10.0.0.5" || evt.DstPort != 4444 {
		t.Fatalf("got family %d %s:%d, want 2 10.0.0.5:4444", evt.Family, evt.DstIP, evt.DstPort)
	}
}

func TestDecodeIPv6Connect(t *testing.T) {
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01} // 2001:db8::1
	evt, err := decodeEvent(connectV6("nc", addr, 9001))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Family != afInet6 || evt.DstIP != "2001:db8::1" || evt.DstPort != 9001 {
		t.Fatalf("got family %d [%s]:%d, want 10 [2001:db8::1]:9001", evt.Family, evt.DstIP, evt.DstPort)
	}
}

func TestDecodeIPv4MappedIPv6Connect(t *testing.T) {
	addr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7} // ::ffff:192.0.2.7
	evt, err := decodeEvent(connectV6("nc", addr, 4444))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Family != afInet6 {
		t.Fatalf("family %d, want 10: the socket was IPv6", evt.Family)
	}
	if evt.DstIP != "192.0.2.7" || evt.DstPort != 4444 {
		t.Fatalf("got %s:%d, want the IPv4 form 192.0.2.7:4444", evt.DstIP, evt.DstPort)
	}
}

func TestDecodeUnixConnectCarriesOnlyTheFamily(t *testing.T) {
	buf := sample("connect", "bash", "")
	binary.LittleEndian.PutUint32(buf[offFamily:], afUnix)
	evt, err := decodeEvent(buf)
	if err != nil {
		t.Fatal(err)
	}
	if evt.Family != afUnix || evt.DstIP != "" || evt.DstPort != 0 {
		t.Fatalf("got family %d %q:%d", evt.Family, evt.DstIP, evt.DstPort)
	}
}

func TestDecodeExecEvent(t *testing.T) {
	evt, err := decodeEvent(sample("exec", "sh", "/tmp/evil"))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Filename != "/tmp/evil" {
		t.Fatalf("filename %q", evt.Filename)
	}
	if evt.DirFD != atFdCwd {
		t.Fatalf("dirfd %d, want AT_FDCWD: execve is relative to the working directory", evt.DirFD)
	}
	if evt.DstIP != "" || evt.DstPort != 0 || evt.Family != 0 {
		t.Fatalf("an exec event should carry no address, got family %d %q:%d", evt.Family, evt.DstIP, evt.DstPort)
	}
}

func TestDecodeExecveatEvent(t *testing.T) {
	buf := sample("execveat", "python3", "")
	binary.LittleEndian.PutUint32(buf[offDirFD:], 5)
	binary.LittleEndian.PutUint64(buf[offArg0:], atEmptyPath)
	evt, err := decodeEvent(buf)
	if err != nil {
		t.Fatal(err)
	}
	if evt.DirFD != 5 || evt.ExecFlags != atEmptyPath || evt.Filename != "" {
		t.Fatalf("got dirfd %d flags %#x filename %q", evt.DirFD, evt.ExecFlags, evt.Filename)
	}
}

func TestDecodeNegativeDirFD(t *testing.T) {
	buf := sample("execveat", "x", "bin/tool")
	fd := int32(atFdCwd)
	binary.LittleEndian.PutUint32(buf[offDirFD:], uint32(fd))
	evt, err := decodeEvent(buf)
	if err != nil {
		t.Fatal(err)
	}
	if evt.DirFD != atFdCwd {
		t.Fatalf("dirfd %d, want %d", evt.DirFD, atFdCwd)
	}
}

func TestDecodePtraceEvent(t *testing.T) {
	buf := sample("ptrace", "gdb", "")
	binary.LittleEndian.PutUint64(buf[offArg0:], 16)
	evt, err := decodeEvent(buf)
	if err != nil {
		t.Fatal(err)
	}
	if evt.PtraceRequest != 16 || evt.PtraceRequestName != "PTRACE_ATTACH" {
		t.Fatalf("got request %d %q", evt.PtraceRequest, evt.PtraceRequestName)
	}
}

func TestDecodeMmapEvent(t *testing.T) {
	buf := sample("mmap_exec", "node", "")
	binary.LittleEndian.PutUint64(buf[offArg0:], protWrite|protExec)
	binary.LittleEndian.PutUint64(buf[offArg1:], mapAnonymous|0x2)
	evt, err := decodeEvent(buf)
	if err != nil {
		t.Fatal(err)
	}
	if evt.MmapProt != protWrite|protExec || evt.MmapFlags != mapAnonymous|0x2 {
		t.Fatalf("got prot %#x flags %#x", evt.MmapProt, evt.MmapFlags)
	}
}

func TestDecodeIgnoresTrailingPadding(t *testing.T) {
	padded := append(sample("memfd", "x", "payload"), 0xAA, 0xBB, 0xCC, 0xDD)
	evt, err := decodeEvent(padded)
	if err != nil {
		t.Fatal(err)
	}
	if evt.Type != "memfd" || evt.Filename != "payload" {
		t.Fatalf("type %q filename %q", evt.Type, evt.Filename)
	}
}

func TestDecodeRejectsAShortSample(t *testing.T) {
	if _, err := decodeEvent(make([]byte, rawEventSize-1)); err == nil {
		t.Fatal("expected an error for a short sample")
	}
}

func TestDecodeFullWidthStringsAreNotOverread(t *testing.T) {
	// A comm of exactly 16 bytes has no terminating NUL inside its field.
	evt, err := decodeEvent(sample("exec", "sixteen-byte-nam", strings.Repeat("a", 256)))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Comm != "sixteen-byte-nam" || len(evt.Filename) != 256 {
		t.Fatalf("comm %q, filename length %d", evt.Comm, len(evt.Filename))
	}
}

func TestAlertJSONUsesReadableFields(t *testing.T) {
	evt, err := decodeEvent(connectV4("bash", [4]byte{10, 0, 0, 5}, 4444))
	if err != nil {
		t.Fatal(err)
	}
	alerts := EvaluateRules(evt)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	payload, err := json.Marshal(alerts[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"rule_id":"reverse_shell"`, `"comm":"bash"`, `"family":2`, `"dst_ip":"10.0.0.5"`, `"dst_port":4444`, `"type":"connect"`} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("alert JSON lacks %s:\n%s", want, payload)
		}
	}
	for _, unwanted := range []string{"ptrace_request", "mmap_prot", "exec_flags", "resolved_path"} {
		if strings.Contains(string(payload), unwanted) {
			t.Errorf("a connect alert should not carry %s:\n%s", unwanted, payload)
		}
	}
}
