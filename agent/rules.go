package main

import "strings"

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
	shellNames   = map[string]struct{}{"bash": {}, "sh": {}, "zsh": {}, "dash": {}}
	// Directories any user can write to, where a dropped binary would usually land.
	worldWritableDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}
)

// EvaluateRules runs every rule on one event. Each rule looks at a single event on its own:
// nothing here correlates events or remembers earlier ones.
func EvaluateRules(evt RuntimeEvent) []Alert {
	var alerts []Alert
	for _, rule := range []func(RuntimeEvent) (Alert, bool){
		detectReverseShell,
		detectShellNetworkActivity,
		detectInjection,
		detectSuspiciousExec,
	} {
		if alert, ok := rule(evt); ok {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// detectReverseShell fires on a connect() to a port on the watch list. It is a port match and
// nothing more: it cannot tell a reverse shell from any other connection to that port.
func detectReverseShell(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventConnect {
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

// detectShellNetworkActivity fires when a shell itself calls connect() to any other port
// (bash's /dev/tcp does this; a shell running curl does not, because curl makes the call).
func detectShellNetworkActivity(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventConnect {
		return Alert{}, false
	}
	if _, isShell := shellNames[evt.Comm]; !isShell {
		return Alert{}, false
	}
	if _, watched := watchedPorts[evt.DstPort]; watched {
		return Alert{}, false // already reported as reverse_shell
	}
	return Alert{
		RuleID:         "shell_network_activity",
		Severity:       "medium",
		RiskScore:      55,
		Reason:         "a shell process opened a network connection itself",
		Recommendation: "check whether the session is expected",
		Event:          evt,
	}, true
}

// detectInjection fires on the three primitives the probe reports: a ptrace request that
// attaches to a process or writes into it, a mapping that is writable and executable at once,
// and memfd_create. Debuggers, JIT compilers and some ordinary programs do all three.
func detectInjection(evt RuntimeEvent) (Alert, bool) {
	var reason string
	switch evt.Type {
	case EventPtrace:
		reason = "ptrace attach, seize or poke request"
	case EventMmapWX:
		reason = "memory mapped writable and executable at once"
	case EventMemfd:
		reason = "memfd_create called (an anonymous in-memory file)"
	default:
		return Alert{}, false
	}
	return Alert{
		RuleID:         "process_injection",
		Severity:       "high",
		RiskScore:      90,
		Reason:         reason,
		Recommendation: "check whether the process is a debugger or a JIT runtime before treating it as injection",
		Event:          evt,
	}, true
}

// detectSuspiciousExec fires when the path given to execve is in a world-writable directory,
// or goes through /proc/<pid>/fd/, which is how a memfd-backed binary is started.
func detectSuspiciousExec(evt RuntimeEvent) (Alert, bool) {
	if evt.Type != EventExec {
		return Alert{}, false
	}

	path := strings.TrimSpace(evt.Filename)
	reason := ""
	for _, dir := range worldWritableDirs {
		if strings.HasPrefix(path, dir) {
			reason = "binary executed from " + strings.TrimSuffix(dir, "/")
			break
		}
	}
	if reason == "" && isProcFdPath(path) {
		reason = "binary executed through a file descriptor path"
	}
	if reason == "" {
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

// isProcFdPath reports whether path looks like /proc/self/fd/N or /proc/<pid>/fd/N.
func isProcFdPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return false
	}
	owner, fd, ok := strings.Cut(rest, "/fd/")
	return ok && owner != "" && fd != "" && !strings.Contains(owner, "/")
}
