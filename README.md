# eBPF Cloud Runtime Security Monitor (educational)

[![CI](https://github.com/Raoof128/eBPF-Cloud-Runtime-Security-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Raoof128/eBPF-Cloud-Runtime-Security-Monitor/actions/workflows/ci.yml)

A small teaching project that shows the parts of a kernel-level runtime monitor and how they connect: eBPF programs on five syscall tracepoints, a Go agent that loads them and applies a few rules, and a React page that lists the alerts.

**Status.** The probe-to-alert path works and is checked on every CI run: the job loads the programs into the runner's kernel, attaches them, makes three harmless syscalls and expects the three matching alerts. Everything past that is unproven. The rules are four single-event heuristics with no measured detection or false-positive rate. Overhead has not been measured. The Helm chart has never been installed on a cluster, and there is no container image to install. This is not a tool to protect anything with.

## What it does

```
 kernel                          user space
+---------------------+  perf   +----------------------------+  SSE   +-----------+
| 5 tracepoint progs  | ------> | Go agent                   | -----> | dashboard |
| (ebpf/)             | buffer  | decode -> rules -> alerts  | /events| (React)   |
+---------------------+         +----------------------------+        +-----------+
```

1. `ebpf/process_monitor.c` attaches to the entry of `execve`, `connect`, `ptrace`, `memfd_create` and `mmap`. Each program records the process ID, user and group ID, cgroup ID, command name, and a path or an IPv4 destination, and sends that to user space through a perf event array. The programs only read; they do not change or block any syscall.
2. `agent/` loads the compiled object with [cilium/ebpf](https://github.com/cilium/ebpf), attaches the five programs, decodes each event and runs the rules. Alerts are printed as JSON lines and streamed over Server-Sent Events at `/events`.
3. `dashboard/` is a single React page that subscribes to `/events` and lists what arrives.

## Rules

Each rule looks at one event on its own. Nothing is correlated across events, and the lists and risk scores are fixed examples, not threat intelligence.

| Rule | Fires when | Known noise |
|---|---|---|
| `reverse_shell` | any process calls `connect()` to port 4444, 8081 or 9001 | it is a port match: any service on those ports triggers it, and a reverse shell on another port does not |
| `shell_network_activity` | `bash`, `sh`, `zsh` or `dash` itself calls `connect()` to another port | scripts that use `/dev/tcp` |
| `process_injection` | a `ptrace` attach, seize or poke request; an `mmap` that is writable and executable at once; or `memfd_create` | debuggers, JIT runtimes (Node, Java), and libraries that use memfd |
| `suspicious_exec` | `execve` of a path under `/tmp`, `/dev/shm` or `/var/tmp`, or through `/proc/<pid>/fd/` | build tools and installers that run from `/tmp` |

Example alert, as the agent printed it during an end-to-end run in a container on 17 November 2026 (reformatted; the IDs, host name and time differ from run to run):

```json
{
  "rule_id": "reverse_shell",
  "severity": "high",
  "risk_score": 85,
  "reason": "outbound connection to a port on the watch list",
  "recommendation": "check what the process is and whether the destination is expected",
  "event": {
    "type": "connect",
    "pid": 31867,
    "ppid": 0,
    "uid": 0,
    "gid": 0,
    "cgroup_id": 1327,
    "comm": "bash",
    "dst_ip": "127.0.0.1",
    "dst_port": 4444,
    "container": {"id": "host", "name": "", "runtime": ""},
    "pod": {"name": "ecrsm-demo", "namespace": "default", "node": "node-unknown"},
    "timestamp": "2026-11-17T11:59:10.242266923Z"
  }
}
```

Note `"container": {"id": "host"}` although this ran inside a container: with cgroup v2 a process sees its own cgroup as `/`, so the hex-string guess finds nothing. See Limits.

## Limits

- **`ppid` is always 0.** Finding the parent needs kernel structure offsets (CO-RE), which the probe does not use. There is no process lineage.
- **IPv4 only**, and `connect()` on a UDP socket is reported the same as TCP. Connections that are accepted, not made, are not seen.
- **Only the syscall's arguments are seen**, at entry. A path is whatever string the caller passed (relative paths stay relative), and a refused or failed call is reported like a successful one.
- **Events can be lost.** If the agent reads slower than the kernel writes, the perf buffer drops events and the agent logs how many.
- **Container attribution is a guess.** The container ID is the first long hex string in `/proc/<pid>/cgroup`; a process that has already exited shows as `host`. The `pod` block is the agent's own pod (from environment variables), the same for every event. The agent does not talk to the Kubernetes API.
- **The alert stream has no authentication.** The agent listens on `127.0.0.1:8090` unless `LISTEN_ADDR` says otherwise.
- **Easy to evade.** A port not on the list, a binary outside the listed directories, or injection through `process_vm_writev` passes unseen.

## Build and run

Needs Linux with syscall tracepoints, root, clang, the libbpf headers, and Go 1.22 or later (1.23 was used here). On Debian or Ubuntu: `sudo apt-get install clang libbpf-dev`. Kernels it has actually run on are listed under Tests.

```bash
make bpf agent                       # ebpf/process_monitor.bpf.o and bin/ecrsm-agent
sudo BPF_OBJECT=ebpf/process_monitor.bpf.o ./bin/ecrsm-agent
```

In another terminal, trigger an alert:

```bash
bash scripts/simulate_reverse_shell.sh   # bash connects to 127.0.0.1:4444 (refused; nothing listens)
python3 scripts/simulate_injection.py    # ptrace attach to itself (the kernel refuses)
cp /bin/true /tmp/demo && /tmp/demo      # exec from /tmp
```

Dashboard (optional):

```bash
cd dashboard
npm ci
npm run dev        # http://localhost:4173, reads http://localhost:8090/events
```

Set `VITE_EVENTS_URL` if the agent is elsewhere, and `CORS_ORIGIN` on the agent if the page is served from another origin. The agent's settings are in [docs/API.md](docs/API.md).

## Tests

```bash
make test    # go vet and unit tests: rules, event decoding, the SSE server (runs on any OS)
make e2e     # Linux and root: loads the probes and checks three alerts end to end
```

CI runs both, builds the dashboard, and renders the Helm chart. The end-to-end job is the evidence for the status line above; it has run on GitHub's `ubuntu-latest` runner (x86-64) and, by hand, on a 7.0 kernel on arm64.

## Kubernetes

`deploy/helm/` is a chart template: a privileged DaemonSet for the agent and a Deployment for the dashboard. It renders (`helm template` runs in CI) and that is all that has been checked. It has never been installed, there is no Dockerfile or published image for it to pull, and the values file points at placeholder image names. Treat it as a sketch of what a deployment would need, including the fact that it asks for a fully privileged container.

## Layout

- `ebpf/process_monitor.c`: the five tracepoint programs
- `agent/`: loader, event decoder, rules, SSE server, and their tests
- `dashboard/`: React page (Vite)
- `deploy/helm/`: chart template
- `scripts/`: the three demo triggers and the end-to-end check
- `docs/`: [architecture notes](docs/ARCHITECTURE.md) and the [alert format](docs/API.md)

## Safety

Run it on a machine you own. The agent needs root and sees the command names, paths and connection targets of every process on the host, which can include sensitive strings. The demo scripts make one refused local connection, one refused ptrace request and one `/tmp` exec; they do not open a shell or touch another process.

MIT licence. See [SECURITY.md](SECURITY.md) to report a problem.
