package main

import (
	"path"
	"strings"
)

// Alert is one rule firing on one event.
type Alert struct {
	RuleID         string       `json:"rule_id"`
	Severity       string       `json:"severity"`
	RiskScore      int          `json:"risk_score"`
	Reason         string       `json:"reason"`
	Recommendation string       `json:"recommendation"`
	Event          RuntimeEvent `json:"event"`
}

// These lists are examples chosen for the simulations, not threat intelligence. The risk
// scores are fixed numbers attached to each rule; nothing computes them.
var (
	watchedPorts = map[uint16]struct{}{4444: {}, 8081: {}, 9001: {}}
	// Exact command names, plus anything starting with "python" (python3, python3.12).
	shellNames = map[string]struct{}{"bash": {}, "sh": {}, "zsh": {}, "dash": {}, "python": {}}
	// Directories any user can write to, where a dropped binary would usually land.
	worldWritableDirs = []string{"/tmp", "/dev/shm", "/var/tmp"}
)

// ptraceRequestNames names the requests the rules distinguish. Numbers are the Linux ones;
// 12 to 15 are the x86 register requests and mean nothing on arm64, which uses 0x4204/0x4205.
var ptraceRequestNames = map[uint64]string{
	0:      "PTRACE_TRACEME",
	1:      "PTRACE_PEEKTEXT",
	2:      "PTRACE_PEEKDATA",
	3:      "PTRACE_PEEKUSER",
	4:      "PTRACE_POKETEXT",
	5:      "PTRACE_POKEDATA",
	6:      "PTRACE_POKEUSER",
	7:      "PTRACE_CONT",
	8:      "PTRACE_KILL",
	9:      "PTRACE_SINGLESTEP",
	12:     "PTRACE_GETREGS",
	13:     "PTRACE_SETREGS",
	14:     "PTRACE_GETFPREGS",
	15:     "PTRACE_SETFPREGS",
	16:     "PTRACE_ATTACH",
	17:     "PTRACE_DETACH",
	24:     "PTRACE_SYSCALL",
	0x4200: "PTRACE_SETOPTIONS",
	0x4201: "PTRACE_GETEVENTMSG",
	0x4202: "PTRACE_GETSIGINFO",
	0x4203: "PTRACE_SETSIGINFO",
	0x4204: "PTRACE_GETREGSET",
	0x4205: "PTRACE_SETREGSET",
	0x4206: "PTRACE_SEIZE",
	0x4207: "PTRACE_INTERRUPT",
}

// ptraceTakesControl holds the requests that put a process under a tracer or change its
// memory, registers or pending signal. These raise process_injection. Every other request
// (peeks, continues, detach, and numbers the agent has no name for) still raises an alert,
// as ptrace_activity, so no ptrace call goes unreported.
var ptraceTakesControl = map[uint64]struct{}{
	0:      {}, // TRACEME: the caller asks to be traced by its parent
	4:      {}, // POKETEXT
	5:      {}, // POKEDATA
	6:      {}, // POKEUSER
	13:     {}, // SETREGS (x86)
	15:     {}, // SETFPREGS (x86)
	16:     {}, // ATTACH
	0x4203: {}, // SETSIGINFO
	0x4205: {}, // SETREGSET
	0x4206: {}, // SEIZE
}

// EvaluateRules runs every rule on one event. Each rule looks at a single event on its own:
// nothing here correlates events or remembers earlier ones.
func EvaluateRules(evt RuntimeEvent) []Alert {
	var alerts []Alert
	for _, rule := range []func(RuntimeEvent) (Alert, bool){
		detectReverseShell,
		detectShellNetworkActivity,
		detectPtrace,
		detectExecutableMapping,
		detectMemfd,
		detectSuspiciousExec,
	} {
		if alert, ok := rule(evt); ok {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

func isIPFamily(family uint32) bool {
	return family == afInet || family == afInet6
}

func isShell(comm string) bool {
	if _, ok := shellNames[comm]; ok {
		return true
	}
	return strings.HasPrefix(comm, "python")
}

// detectReverseShell fires on a connect() over IPv4 or IPv6 to a port on the watch list, by
// any process and any user. It is a port match and nothing more: it cannot tell a reverse
// shell from any other connection to that port.
func detectReverseShell(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventConnect || !isIPFamily(evt.Family) {
		return Alert{}, false
	}
	if _, watched := watchedPorts[evt.DstPort]; !watched {
		return Alert{}, false
	}
	return Alert{
		RuleID:         "reverse_shell",
		Severity:       "high",
		RiskScore:      85,
		Reason:         "outbound connection to a port on the watch list",
		Recommendation: "check what the process is and whether the destination is expected",
		Event:          evt,
	}, true
}

// detectShellNetworkActivity fires when a shell or a Python interpreter itself calls
// connect() and reverse_shell has not already reported it. Unix-domain sockets are left out:
// a shell talks to local services over them all the time (name lookups, for one) and they
// do not leave the machine. Every other family counts, including one the probe could not
// read.
func detectShellNetworkActivity(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventConnect || !isShell(evt.Comm) || evt.Family == afUnix {
		return Alert{}, false
	}
	if _, watched := watchedPorts[evt.DstPort]; watched && isIPFamily(evt.Family) {
		return Alert{}, false // already reported as reverse_shell
	}
	return Alert{
		RuleID:         "shell_network_activity",
		Severity:       "medium",
		RiskScore:      55,
		Reason:         "a shell or interpreter process opened a connection itself",
		Recommendation: "check whether the session is expected",
		Event:          evt,
	}, true
}

// detectPtrace reports every ptrace call. A request that takes control of a process or
// changes it raises process_injection; any other request raises the lower ptrace_activity.
func detectPtrace(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventPtrace {
		return Alert{}, false
	}
	name := evt.PtraceRequestName
	if name == "" {
		name = "an unrecognised request"
	}
	if _, takesControl := ptraceTakesControl[evt.PtraceRequest]; takesControl {
		return Alert{
			RuleID:         "process_injection",
			Severity:       "high",
			RiskScore:      90,
			Reason:         "ptrace request that takes control of a process or changes it: " + name,
			Recommendation: "check whether the caller is a debugger before treating it as injection",
			Event:          evt,
		}, true
	}
	return Alert{
		RuleID:         "ptrace_activity",
		Severity:       "low",
		RiskScore:      30,
		Reason:         "ptrace call: " + name,
		Recommendation: "expected from debuggers and tracers; check the caller if it is neither",
		Event:          evt,
	}, true
}

// detectExecutableMapping reports the executable mappings the probe sends: writable and
// executable at once (process_injection), or executable and anonymous (the lower
// anonymous_exec_mapping). JIT runtimes make both.
func detectExecutableMapping(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventMmapExec {
		return Alert{}, false
	}
	if evt.MmapProt&protWrite != 0 {
		return Alert{
			RuleID:         "process_injection",
			Severity:       "high",
			RiskScore:      90,
			Reason:         "memory mapped writable and executable at once",
			Recommendation: "check whether the process is a JIT runtime before treating it as injection",
			Event:          evt,
		}, true
	}
	return Alert{
		RuleID:         "anonymous_exec_mapping",
		Severity:       "medium",
		RiskScore:      50,
		Reason:         "executable memory mapped with no file behind it",
		Recommendation: "check whether the process is a JIT runtime",
		Event:          evt,
	}, true
}

// detectMemfd reports every memfd_create: an anonymous in-memory file, which is one way to
// run code that never touches the disk. Ordinary libraries use it too.
func detectMemfd(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventMemfd {
		return Alert{}, false
	}
	return Alert{
		RuleID:         "process_injection",
		Severity:       "high",
		RiskScore:      90,
		Reason:         "memfd_create called (an anonymous in-memory file)",
		Recommendation: "check what the process does with the descriptor",
		Event:          evt,
	}, true
}

// detectSuspiciousExec looks at execve and execveat. It fires when the path, once made
// absolute and cleaned, is inside a world-writable directory; when the path names an open
// file descriptor or execveat runs a descriptor directly (how a memfd-backed binary is
// started); or when the path mentions memfd.
//
// It matches on a path string, so it can be walked around: a symbolic or hard link from
// somewhere else, or a relative path from a process that exits before its working directory
// can be read, passes unseen. Resolving the executed file in the kernel (the
// sched_process_exec tracepoint, or the bprm hooks) is the robust way, and is not done here.
func detectSuspiciousExec(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventExec && evt.Type != EventExecveat {
		return Alert{}, false
	}

	// The agent fills ResolvedPath in. Fall back to cleaning the raw string so the rule
	// behaves the same on an event that was built without it.
	execPath := evt.ResolvedPath
	if execPath == "" {
		execPath = resolveExecPath(evt.Filename, evt.PID, evt.DirFD, nil)
	}

	reason := ""
	for _, dir := range worldWritableDirs {
		if isInsideDir(execPath, dir) {
			reason = "binary executed from " + dir
			break
		}
	}
	switch {
	case reason != "":
	case isFdPath(execPath):
		reason = "binary executed through a file descriptor path"
	case evt.Type == EventExecveat && (execPath == "" || evt.ExecFlags&atEmptyPath != 0):
		reason = "execveat ran an open file descriptor directly"
	case strings.Contains(execPath, "memfd"):
		reason = "executed path mentions memfd"
	default:
		return Alert{}, false
	}

	return Alert{
		RuleID:         "suspicious_exec",
		Severity:       "medium",
		RiskScore:      60,
		Reason:         reason,
		Recommendation: "find out what wrote the file and what started it",
		Event:          evt,
	}, true
}

// isInsideDir reports whether the cleaned path p is strictly inside dir. The test is on whole
// path components: /tmpfoo/x is not inside /tmp.
func isInsideDir(p, dir string) bool {
	return strings.HasPrefix(path.Clean(p), dir+"/")
}

// isFdPath reports whether the cleaned path p names an open file descriptor:
// /dev/fd/N, /proc/self/fd/N, /proc/thread-self/fd/N, /proc/<pid>/fd/N or
// /proc/<pid>/task/<tid>/fd/N.
func isFdPath(p string) bool {
	parts := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	switch {
	case len(parts) == 3 && parts[0] == "dev" && parts[1] == "fd":
		return isDecimal(parts[2])
	case len(parts) == 4 && parts[0] == "proc" && parts[2] == "fd":
		return isProcOwner(parts[1]) && isDecimal(parts[3])
	case len(parts) == 6 && parts[0] == "proc" && parts[2] == "task" && parts[4] == "fd":
		return isProcOwner(parts[1]) && isDecimal(parts[3]) && isDecimal(parts[5])
	}
	return false
}

func isProcOwner(s string) bool {
	return s == "self" || s == "thread-self" || isDecimal(s)
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
