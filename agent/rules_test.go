package main

import "testing"

func ruleIDs(alerts []Alert) []string {
	ids := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ids = append(ids, a.RuleID)
	}
	return ids
}

func TestEvaluateRules(t *testing.T) {
	tests := []struct {
		name string
		evt  RuntimeEvent
		want []string
	}{
		{
			name: "connect to a watched port",
			evt:  RuntimeEvent{Type: EventConnect, Comm: "nc", DstIP: "10.0.0.5", DstPort: 4444},
			want: []string{"reverse_shell"},
		},
		{
			name: "connect to a watched port as root is reported too",
			evt:  RuntimeEvent{Type: EventConnect, Comm: "nc", UID: 0, DstPort: 9001},
			want: []string{"reverse_shell"},
		},
		{
			name: "shell connecting to a watched port is reported once",
			evt:  RuntimeEvent{Type: EventConnect, Comm: "bash", DstPort: 4444},
			want: []string{"reverse_shell"},
		},
		{
			name: "shell connecting elsewhere",
			evt:  RuntimeEvent{Type: EventConnect, Comm: "bash", DstPort: 443},
			want: []string{"shell_network_activity"},
		},
		{
			name: "ordinary program connecting elsewhere",
			evt:  RuntimeEvent{Type: EventConnect, Comm: "curl", DstPort: 443},
			want: nil,
		},
		{
			name: "ptrace",
			evt:  RuntimeEvent{Type: EventPtrace, Comm: "gdb"},
			want: []string{"process_injection"},
		},
		{
			name: "writable and executable mapping",
			evt:  RuntimeEvent{Type: EventMmapWX, Comm: "node"},
			want: []string{"process_injection"},
		},
		{
			name: "memfd_create",
			evt:  RuntimeEvent{Type: EventMemfd, Filename: "payload"},
			want: []string{"process_injection"},
		},
		{
			name: "exec from /tmp",
			evt:  RuntimeEvent{Type: EventExec, Filename: "/tmp/evil"},
			want: []string{"suspicious_exec"},
		},
		{
			name: "exec from /dev/shm",
			evt:  RuntimeEvent{Type: EventExec, Filename: "/dev/shm/x"},
			want: []string{"suspicious_exec"},
		},
		{
			name: "exec through a file descriptor",
			evt:  RuntimeEvent{Type: EventExec, Filename: "/proc/self/fd/3"},
			want: []string{"suspicious_exec"},
		},
		{
			name: "a directory that only starts with /tmp is not /tmp",
			evt:  RuntimeEvent{Type: EventExec, Filename: "/tmpfiles/tool"},
			want: nil,
		},
		{
			name: "ordinary exec",
			evt:  RuntimeEvent{Type: EventExec, Filename: "/usr/bin/ls"},
			want: nil,
		},
		{
			name: "a file under /proc that is not an fd path",
			evt:  RuntimeEvent{Type: EventExec, Filename: "/proc/self/exe"},
			want: nil,
		},
		{
			name: "unknown event type",
			evt:  RuntimeEvent{Type: "something_else", Filename: "/tmp/evil", DstPort: 4444},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(EvaluateRules(tc.evt))
			if len(got) != len(tc.want) {
				t.Fatalf("got rules %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got rules %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestAlertCarriesTheEvent(t *testing.T) {
	evt := RuntimeEvent{Type: EventExec, PID: 42, Filename: "/tmp/evil"}
	alerts := EvaluateRules(evt)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Event.PID != 42 || alerts[0].Reason != "binary executed from /tmp" {
		t.Fatalf("unexpected alert: %+v", alerts[0])
	}
}
