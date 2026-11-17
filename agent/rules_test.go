package main

import (
	"fmt"
	"reflect"
	"testing"
)

func ruleIDs(alerts []Alert) []string {
	var ids []string
	for _, a := range alerts {
		ids = append(ids, a.RuleID)
	}
	return ids
}

func expectRules(t *testing.T, evt RuntimeEvent, want []string) {
	t.Helper()
	if got := ruleIDs(EvaluateRules(evt)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got rules %v, want %v (event %+v)", got, want, evt)
	}
}

func TestConnectRules(t *testing.T) {
	tests := []struct {
		name string
		evt  RuntimeEvent
		want []string
	}{
		{"IPv4 to a watched port", RuntimeEvent{Comm: "nc", Family: afInet, DstIP: "10.0.0.5", DstPort: 4444}, []string{"reverse_shell"}},
		{"IPv4 to a watched port as root", RuntimeEvent{Comm: "nc", UID: 0, Family: afInet, DstPort: 9001}, []string{"reverse_shell"}},
		{"IPv6 to a watched port", RuntimeEvent{Comm: "nc", Family: afInet6, DstIP: "2001:db8::1", DstPort: 4444}, []string{"reverse_shell"}},
		{"IPv4-mapped IPv6 to a watched port", RuntimeEvent{Comm: "nc", Family: afInet6, DstIP: "192.0.2.7", DstPort: 8081}, []string{"reverse_shell"}},
		{"shell to a watched port is reported once", RuntimeEvent{Comm: "bash", Family: afInet, DstPort: 4444}, []string{"reverse_shell"}},
		{"shell to a watched port over IPv6 is reported once", RuntimeEvent{Comm: "bash", Family: afInet6, DstPort: 4444}, []string{"reverse_shell"}},
		{"shell elsewhere over IPv4", RuntimeEvent{Comm: "bash", Family: afInet, DstPort: 443}, []string{"shell_network_activity"}},
		{"shell elsewhere over IPv6", RuntimeEvent{Comm: "sh", Family: afInet6, DstIP: "2001:db8::1", DstPort: 443}, []string{"shell_network_activity"}},
		{"shell as root", RuntimeEvent{Comm: "zsh", UID: 0, Family: afInet, DstPort: 22}, []string{"shell_network_activity"}},
		{"python", RuntimeEvent{Comm: "python", Family: afInet, DstPort: 443}, []string{"shell_network_activity"}},
		{"python3", RuntimeEvent{Comm: "python3", Family: afInet, DstPort: 443}, []string{"shell_network_activity"}},
		{"python3.12", RuntimeEvent{Comm: "python3.12", Family: afInet6, DstPort: 443}, []string{"shell_network_activity"}},
		{"shell with a family the probe could not read", RuntimeEvent{Comm: "bash", Family: 0}, []string{"shell_network_activity"}},
		{"shell over another family (netlink)", RuntimeEvent{Comm: "bash", Family: 16}, []string{"shell_network_activity"}},
		{"shell over a Unix socket", RuntimeEvent{Comm: "bash", Family: afUnix}, nil},
		{"ordinary program elsewhere", RuntimeEvent{Comm: "curl", Family: afInet, DstPort: 443}, nil},
		{"ordinary program elsewhere over IPv6", RuntimeEvent{Comm: "curl", Family: afInet6, DstPort: 443}, nil},
		{"Unix socket whose port field happens to be watched", RuntimeEvent{Comm: "nc", Family: afUnix, DstPort: 4444}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.evt.Type = EventConnect
			expectRules(t, tc.evt, tc.want)
		})
	}
}

// Every ptrace request raises an alert. The ones that take control of a process or change it
// raise process_injection; the rest raise ptrace_activity.
func TestPtraceRules(t *testing.T) {
	takesControl := map[uint64]string{
		0:      "PTRACE_TRACEME",
		4:      "PTRACE_POKETEXT",
		5:      "PTRACE_POKEDATA",
		6:      "PTRACE_POKEUSER",
		13:     "PTRACE_SETREGS",
		15:     "PTRACE_SETFPREGS",
		16:     "PTRACE_ATTACH",
		0x4203: "PTRACE_SETSIGINFO",
		0x4205: "PTRACE_SETREGSET",
		0x4206: "PTRACE_SEIZE",
	}
	for request, name := range takesControl {
		t.Run(name, func(t *testing.T) {
			if ptraceRequestNames[request] != name {
				t.Fatalf("request %#x is named %q, want %q", request, ptraceRequestNames[request], name)
			}
			evt := RuntimeEvent{Type: EventPtrace, PtraceRequest: request, PtraceRequestName: name}
			expectRules(t, evt, []string{"process_injection"})
		})
	}

	observes := []uint64{1, 2, 3, 7, 8, 9, 12, 14, 17, 24, 0x4200, 0x4201, 0x4202, 0x4204, 0x4207}
	for _, request := range observes {
		t.Run(fmt.Sprintf("request %#x", request), func(t *testing.T) {
			evt := RuntimeEvent{Type: EventPtrace, PtraceRequest: request, PtraceRequestName: ptraceRequestNames[request]}
			expectRules(t, evt, []string{"ptrace_activity"})
		})
	}

	t.Run("a request number the agent has no name for is still reported", func(t *testing.T) {
		expectRules(t, RuntimeEvent{Type: EventPtrace, PtraceRequest: 0x9999}, []string{"ptrace_activity"})
	})
}

func TestMmapAndMemfdRules(t *testing.T) {
	tests := []struct {
		name string
		evt  RuntimeEvent
		want []string
	}{
		{"writable and executable, anonymous", RuntimeEvent{Type: EventMmapExec, MmapProt: protWrite | protExec, MmapFlags: mapAnonymous}, []string{"process_injection"}},
		{"writable and executable, file-backed", RuntimeEvent{Type: EventMmapExec, MmapProt: protWrite | protExec}, []string{"process_injection"}},
		{"executable and anonymous, not writable", RuntimeEvent{Type: EventMmapExec, MmapProt: protExec, MmapFlags: mapAnonymous}, []string{"anonymous_exec_mapping"}},
		{"memfd_create", RuntimeEvent{Type: EventMemfd, Filename: "payload"}, []string{"process_injection"}},
		{"memfd_create with no name", RuntimeEvent{Type: EventMemfd}, []string{"process_injection"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectRules(t, tc.evt, tc.want)
		})
	}
}

// Each of these is a way of writing a path that the first version of the rule missed, or a
// near miss that must stay quiet. dir is what the process's working directory (or, for
// execveat, its directory descriptor) resolves to; "" means it could not be read.
func TestSuspiciousExecPathForms(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		dir      string
		want     bool
	}{
		{"plain", "/tmp/x", "/", true},
		{"dot-dot back into /tmp", "/tmp/../tmp/x", "/", true},
		{"dot-dot through another directory", "/usr/../tmp/x", "/", true},
		{"doubled slash", "//tmp/x", "/", true},
		{"doubled slash inside", "/tmp//x", "/", true},
		{"dot component", "/tmp/./x", "/", true},
		{"relative, run from /tmp", "./x", "/tmp", true},
		{"bare relative, run from /tmp", "x", "/tmp", true},
		{"relative into /tmp from elsewhere", "../tmp/x", "/home", true},
		{"relative, run from a subdirectory of /dev/shm", "./x", "/dev/shm/a", true},
		{"/var/tmp", "/var/tmp/x", "/", true},
		{"surrounding spaces", " /tmp/x ", "/", true},

		{"/dev/fd form", "/dev/fd/3", "/", true},
		{"/proc/self/fd", "/proc/self/fd/3", "/", true},
		{"/proc/thread-self/fd", "/proc/thread-self/fd/3", "/", true},
		{"/proc/<pid>/fd", "/proc/1234/fd/7", "/", true},
		{"/proc/<pid>/task/<tid>/fd", "/proc/1234/task/1235/fd/7", "/", true},
		{"fd path written with dot-dot", "/proc/self/../self/fd/3", "/", true},
		{"relative fd path, run from /proc/self", "fd/3", "/proc/self", true},
		{"path that mentions memfd", "/memfd:payload (deleted)", "/", true},

		{"name that only starts with tmp", "/tmpfoo/x", "/", false},
		{"the directory itself", "/tmp", "/", false},
		{"dot-dot out of /tmp", "/tmp/../usr/bin/ls", "/", false},
		{"relative, run from a normal directory", "./x", "/home/user", false},
		{"relative, directory unknown", "./x", "", false},
		{"/proc/self/exe", "/proc/self/exe", "/", false},
		{"fd directory itself", "/proc/self/fd", "/", false},
		{"not a number after fd", "/proc/self/fd/abc", "/", false},
		{"fd under an unrelated directory", "/home/proc/self/fd/3", "/", false},
		{"/dev/fd without a number", "/dev/fd/", "/", false},
		{"ordinary binary", "/usr/bin/ls", "/", false},
		{"empty", "", "/", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(uint32, int32) (string, bool) { return tc.dir, tc.dir != "" }
			evt := RuntimeEvent{Type: EventExec, PID: 7, DirFD: atFdCwd, Filename: tc.filename}
			evt.ResolvedPath = resolveExecPath(evt.Filename, evt.PID, evt.DirFD, lookup)

			_, got := detectSuspiciousExec(evt)
			if got != tc.want {
				t.Fatalf("filename %q (dir %q) resolved to %q: alert = %v, want %v",
					tc.filename, tc.dir, evt.ResolvedPath, got, tc.want)
			}
		})
	}
}

func TestExecveatRules(t *testing.T) {
	// The directory descriptor 5 is open on /tmp; the working directory is /home/user.
	lookup := func(_ uint32, dirfd int32) (string, bool) {
		switch dirfd {
		case atFdCwd:
			return "/home/user", true
		case 5:
			return "/tmp", true
		}
		return "", false
	}
	tests := []struct {
		name     string
		filename string
		dirfd    int32
		flags    uint64
		want     bool
	}{
		{"fexecve: empty path with AT_EMPTY_PATH", "", 3, atEmptyPath, true},
		{"empty path without the flag (the kernel would refuse it; still reported)", "", 3, 0, true},
		{"relative to a descriptor open on /tmp", "x", 5, 0, true},
		{"absolute path into /tmp ignores the descriptor", "/tmp/x", 9, 0, true},
		{"relative to the working directory, which is not world-writable", "x", atFdCwd, 0, false},
		{"relative to a descriptor that cannot be resolved", "x", 9, 0, false},
		{"ordinary absolute path", "/usr/bin/ls", atFdCwd, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt := RuntimeEvent{Type: EventExecveat, PID: 7, Filename: tc.filename, DirFD: tc.dirfd, ExecFlags: tc.flags}
			evt.ResolvedPath = resolveExecPath(evt.Filename, evt.PID, evt.DirFD, lookup)
			if _, got := detectSuspiciousExec(evt); got != tc.want {
				t.Fatalf("resolved to %q: alert = %v, want %v", evt.ResolvedPath, got, tc.want)
			}
		})
	}
}

// The rule must not depend on the agent having filled ResolvedPath in.
func TestSuspiciousExecCleansTheRawPathWhenUnresolved(t *testing.T) {
	for _, filename := range []string{"/tmp/../tmp/x", "//tmp/x", "/dev/fd/3"} {
		if _, ok := detectSuspiciousExec(RuntimeEvent{Type: EventExec, Filename: filename}); !ok {
			t.Errorf("%q should alert without ResolvedPath", filename)
		}
	}
	if _, ok := detectSuspiciousExec(RuntimeEvent{Type: EventExec, Filename: "/tmpfoo/x"}); ok {
		t.Error("/tmpfoo/x should not alert")
	}
}

func TestResolveExecPath(t *testing.T) {
	inTmp := func(uint32, int32) (string, bool) { return "/tmp", true }
	gone := func(uint32, int32) (string, bool) { return "", false }
	tests := []struct {
		filename string
		lookup   func(uint32, int32) (string, bool)
		want     string
	}{
		{"/usr/bin/ls", inTmp, "/usr/bin/ls"}, // absolute paths ignore the directory
		{"./x", inTmp, "/tmp/x"},
		{"a/../x", inTmp, "/tmp/x"},
		{"./x", gone, "x"}, // stays relative: nothing to resolve it against
		{"./x", nil, "x"},
		{"/a//b/./c/..", inTmp, "/a/b"},
		{"", inTmp, ""},
	}
	for _, tc := range tests {
		if got := resolveExecPath(tc.filename, 1, atFdCwd, tc.lookup); got != tc.want {
			t.Errorf("resolveExecPath(%q) = %q, want %q", tc.filename, got, tc.want)
		}
	}
}

func TestOtherEvents(t *testing.T) {
	expectRules(t, RuntimeEvent{Type: "something_else", Filename: "/tmp/evil", Family: afInet, DstPort: 4444}, nil)

	alerts := EvaluateRules(RuntimeEvent{Type: EventExec, PID: 42, Filename: "/tmp/evil"})
	if len(alerts) != 1 || alerts[0].Event.PID != 42 || alerts[0].Reason != "binary executed from /tmp" {
		t.Fatalf("unexpected alerts: %+v", alerts)
	}
}
