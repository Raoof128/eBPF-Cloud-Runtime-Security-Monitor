#!/usr/bin/env bash
# End-to-end check on a real kernel: build the probes and the agent, attach the probes, make
# three harmless syscalls, and expect the three matching alerts in the agent's output.
#
# Needs Linux, root (through sudo unless already root), clang, the libbpf headers, Go and
# python3. Nothing is left running or installed afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
LOG="$(mktemp)"
SMOKE_BIN="/tmp/ecrsm-smoke-binary"

make bpf agent

# tracefs is where the kernel lists its tracepoints. Most systems mount it already.
if [ ! -d /sys/kernel/tracing/events ] && [ ! -d /sys/kernel/debug/tracing/events ]; then
    $SUDO mount -t tracefs nodev /sys/kernel/tracing
fi

$SUDO env BPF_OBJECT=ebpf/process_monitor.bpf.o LISTEN_ADDR=127.0.0.1:8090 \
    ./bin/ecrsm-agent >"$LOG" 2>&1 &

stop_agent() { $SUDO pkill -INT -x ecrsm-agent 2>/dev/null || true; }
trap 'stop_agent; rm -f "$SMOKE_BIN"' EXIT

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
    '"rule_id":"process_injection".*"type":"ptrace".*"comm":"python3?"'
expect "connect to 127.0.0.1:4444 raises reverse_shell with address and port decoded" \
    '"rule_id":"reverse_shell".*"type":"connect".*"comm":"bash".*"dst_ip":"127\.0\.0\.1","dst_port":4444'

echo "kernel: $(uname -sr) $(uname -m)"
echo "alerts by rule:"
grep -o '"rule_id":"[a-z_]*"' "$LOG" | sort | uniq -c || true
echo "one alert as printed (reverse_shell):"
grep -m1 '"rule_id":"reverse_shell"' "$LOG" | sed 's/^[^{]*//' || true
if [ "$status" -ne 0 ]; then
    echo "--- agent output ---"
    cat "$LOG"
fi
rm -f "$LOG"
exit "$status"
