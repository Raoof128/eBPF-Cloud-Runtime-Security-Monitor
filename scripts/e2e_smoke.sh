#!/usr/bin/env bash
# End-to-end check on a real kernel: build the probes and the agent, attach the probes, make
# a handful of harmless syscalls, and expect the matching alerts in the agent's output.
#
# Needs Linux, root (through sudo unless already root), clang, the libbpf headers, Go and
# python3. Nothing is left running or installed afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
LOG="$(mktemp)"
SMOKE_BIN="/tmp/ecrsm-smoke-binary"
SMOKE_SLEEP="/tmp/ecrsm-smoke-sleep"

make bpf agent

# tracefs is where the kernel lists its tracepoints. Most systems mount it already.
# (It is readable by root only, so the test has to be made as root.)
if ! $SUDO test -d /sys/kernel/tracing/events && ! $SUDO test -d /sys/kernel/debug/tracing/events; then
    $SUDO mount -t tracefs nodev /sys/kernel/tracing
fi

$SUDO env BPF_OBJECT=ebpf/process_monitor.bpf.o LISTEN_ADDR=127.0.0.1:8090 LOG_EVENTS=1 \
    ./bin/ecrsm-agent >"$LOG" 2>&1 &

stop_agent() { $SUDO pkill -INT -x ecrsm-agent 2>/dev/null || true; }
trap 'stop_agent; rm -f "$SMOKE_BIN" "$SMOKE_SLEEP"' EXIT

for _ in $(seq 1 100); do
    grep -q "listening for kernel events" "$LOG" && break
    sleep 0.2
done
if ! grep -q "listening for kernel events" "$LOG"; then
    echo "the agent did not start:"
    cat "$LOG"
    exit 1
fi
echo "agent: $(grep 'listening for kernel events' "$LOG")"

# 1. Run a binary from /tmp.
cp /bin/true "$SMOKE_BIN"
"$SMOKE_BIN"

# 2. Ask to ptrace-attach (to this script's own python process; the kernel refuses).
python3 scripts/simulate_injection.py

# 3. Connect to a port on the watch list.
bash scripts/simulate_reverse_shell.sh

# 4. Run a binary from /tmp by a relative path. The process has to live long enough for the
#    agent to read its working directory, so it is a copy of sleep.
cp /bin/sleep "$SMOKE_SLEEP"
(cd /tmp && ./ecrsm-smoke-sleep 2)

# 5. Run a memfd-backed binary through execveat (what fexecve does).
python3 scripts/simulate_fexecve.py

# 6. Connect over IPv6, once to an IPv6 address and once to an IPv4-mapped one. A machine
#    with IPv6 switched off cannot make the socket; the script says so and 6 is skipped.
IPV6_RESULT="$(python3 scripts/simulate_ipv6_connect.py)"
echo "$IPV6_RESULT"

sleep 2
stop_agent
sleep 1

status=0
expect() {
    if grep -Eq -- "$2" "$LOG"; then
        echo "ok       $1"
    else
        echo "MISSING  $1"
        status=1
    fi
}
expect "exec from /tmp raises suspicious_exec with the path decoded" \
    '"rule_id":"suspicious_exec".*"type":"exec".*"filename":"/tmp/ecrsm-smoke-binary"'
expect "ptrace attach raises process_injection" \
    '"rule_id":"process_injection".*"type":"ptrace".*"comm":"python3?".*"ptrace_request":16,"ptrace_request_name":"PTRACE_ATTACH"'
expect "connect to 127.0.0.1:4444 raises reverse_shell with address and port decoded" \
    '"rule_id":"reverse_shell".*"type":"connect".*"comm":"bash".*"family":2,"dst_ip":"127\.0\.0\.1","dst_port":4444'
expect "relative exec from /tmp is resolved and raises suspicious_exec" \
    '"rule_id":"suspicious_exec".*"filename":"\./ecrsm-smoke-sleep","resolved_path":"/tmp/ecrsm-smoke-sleep"'
expect "memfd_create raises process_injection" \
    '"rule_id":"process_injection".*"type":"memfd".*"filename":"ecrsm-smoke"'
expect "execveat on a descriptor raises suspicious_exec" \
    '"rule_id":"suspicious_exec".*"reason":"execveat ran an open file descriptor directly".*"type":"execveat"'
if echo "$IPV6_RESULT" | grep -q "ipv6-unavailable"; then
    echo "skipped  IPv6 connects (no IPv6 socket on this machine)"
else
    expect "connect to [::1]:4444 raises reverse_shell" \
        '"rule_id":"reverse_shell".*"family":10,"dst_ip":"::1","dst_port":4444'
    expect "connect to an IPv4-mapped address is reported in its IPv4 form" \
        '"rule_id":"reverse_shell".*"family":10,"dst_ip":"127\.0\.0\.1","dst_port":9001'
fi

echo "kernel: $(uname -sr) $(uname -m)"
echo "alerts by rule:"
grep -o '"rule_id":"[a-z_]*"' "$LOG" | sort | uniq -c || true
echo "one alert as printed (reverse_shell):"
grep -m1 '"rule_id":"reverse_shell"' "$LOG" | sed 's/^[^{]*//' || true
echo "events by type:"
grep ' event cpu=' "$LOG" | grep -o '"type":"[a-z_]*"' | sort | uniq -c || true
if [ "$status" -ne 0 ]; then
    echo "--- agent output: alerts, and events from the smoke processes ---"
    grep -v ' event cpu=' "$LOG" | cut -c1-200 || true
    echo "cpus online: $(nproc)"
    grep ' event cpu=' "$LOG" | cut -c1-330 | tail -80 || true
fi
rm -f "$LOG"
exit "$status"
