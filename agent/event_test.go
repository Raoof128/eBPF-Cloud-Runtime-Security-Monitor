package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// Offsets of struct event_t in ebpf/process_monitor.c. The sample below is laid out by hand
// at these offsets, so a change to rawEvent that shifts a field fails this test.
const (
	offPID      = 0
	offPPID     = 4
	offUID      = 8
	offGID      = 12
	offCgroup   = 16
	offDstIP    = 24
	offDstPort  = 28
	offProto    = 30
	offComm     = 32
	offFilename = 48
	offType     = 304
)

func sample(eventType, comm, filename string) []byte {
	buf := make([]byte, rawEventSize)
	binary.LittleEndian.PutUint32(buf[offPID:], 1234)
	binary.LittleEndian.PutUint32(buf[offPPID:], 0)
	binary.LittleEndian.PutUint32(buf[offUID:], 1000)
	binary.LittleEndian.PutUint32(buf[offGID:], 1001)
	binary.LittleEndian.PutUint64(buf[offCgroup:], 0x1122334455667788)
	copy(buf[offDstIP:], []byte{10, 0, 0, 5})  // 10.0.0.5 in network order
	copy(buf[offDstPort:], []byte{0x11, 0x5c}) // 4444 in network order
	buf[offProto] = 6
	copy(buf[offComm:], comm)
	copy(buf[offFilename:], filename)
	copy(buf[offType:], eventType)
	return buf
}

func TestRawEventMatchesTheCStruct(t *testing.T) {
	if got := binary.Size(rawEvent{}); got != rawEventSize {
		t.Fatalf("rawEvent is %d bytes, want %d (sizeof(struct event_t))", got, rawEventSize)
	}
}

func TestDecodeConnectEvent(t *testing.T) {
	evt, err := decodeEvent(sample("connect", "bash", ""))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Type != "connect" || evt.Comm != "bash" {
		t.Fatalf("type %q comm %q", evt.Type, evt.Comm)
	}
	if evt.PID != 1234 || evt.UID != 1000 || evt.GID != 1001 || evt.CgroupID != 0x1122334455667788 {
		t.Fatalf("ids decoded wrongly: %+v", evt)
	}
	if evt.DstIP != "10.0.0.5" {
		t.Fatalf("dst ip %q, want 10.0.0.5", evt.DstIP)
	}
	if evt.DstPort != 4444 {
		t.Fatalf("dst port %d, want 4444", evt.DstPort)
	}
}

func TestDecodeExecEventHasNoAddress(t *testing.T) {
	evt, err := decodeEvent(sample("exec", "sh", "/tmp/evil"))
	if err != nil {
		t.Fatal(err)
	}
	if evt.Filename != "/tmp/evil" {
		t.Fatalf("filename %q", evt.Filename)
	}
	if evt.DstIP != "" || evt.DstPort != 0 {
		t.Fatalf("an exec event should carry no address, got %q:%d", evt.DstIP, evt.DstPort)
	}
}

func TestDecodeIgnoresTrailingPadding(t *testing.T) {
	padded := append(sample("ptrace", "gdb", ""), 0xAA, 0xBB, 0xCC, 0xDD)
	evt, err := decodeEvent(padded)
	if err != nil {
		t.Fatal(err)
	}
	if evt.Type != "ptrace" {
		t.Fatalf("type %q", evt.Type)
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
	evt, err := decodeEvent(sample("connect", "bash", ""))
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
	for _, want := range []string{`"rule_id":"reverse_shell"`, `"comm":"bash"`, `"dst_ip":"10.0.0.5"`, `"dst_port":4444`, `"type":"connect"`} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("alert JSON lacks %s:\n%s", want, payload)
		}
	}
}
