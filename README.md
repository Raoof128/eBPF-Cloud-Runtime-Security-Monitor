# eBPF Cloud Runtime Security Monitor (educational)

[![CI](https://github.com/Raoof128/eBPF-Cloud-Runtime-Security-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Raoof128/eBPF-Cloud-Runtime-Security-Monitor/actions/workflows/ci.yml)

A small teaching project that shows the parts of a kernel-level runtime monitor and how they connect: eBPF programs on six syscall tracepoints, a Go agent that loads them and applies a few rules, and a React page that lists the alerts.

**Status.** The probe-to-alert path works and is checked on every CI run: the job compiles the eBPF object, loads the programs into the runner's kernel, attaches them, makes a handful of harmless syscalls and expects the matching alerts. Everything past that is unproven. The rules are single-event heuristics with no measured detection or false-positive rate. Overhead has not been measured. The Helm chart has never been installed on a cluster, and there is no container image to install. This is not a tool to protect anything with.

## What it does

```
 kernel                          user space
+---------------------+  perf   +----------------------------+  SSE   +-----------+
| 6 tracepoint progs  | ------> | Go agent                   | -----> | dashboard |
| (ebpf/)             | buffer  | decode -> rules -> alerts  | /events| (React)   |
+---------------------+         +----------------------------+        +-----------+
```

1. `ebpf/process_monitor.c` attaches to the entry of `execve`, `execveat`, `connect`, `ptrace`, `memfd_create` and `mmap`. Each program records the process ID, user and group ID, cgroup ID, command name, and the arguments that matter (a path, an IPv4 or IPv6 destination, a ptrace request, mapping flags), and sends that to user space through a perf event array. The programs only read; they do not change or block any syscall. Every call to the first five is reported; `mmap` is the one filtered in the kernel (see the table).
2. `agent/` loads the compiled object with [cilium/ebpf](https://github.com/cilium/ebpf), attaches the six programs, decodes each event and runs the rules. Alerts are printed as JSON lines and streamed over Server-Sent Events at `/events`.
3. `dashboard/` is a single React page that subscribes to `/events` and lists what arrives.

## Rules

Each rule looks at one event on its own. Nothing is correlated across events, and the lists and risk scores are fixed examples, not threat intelligence.

| Rule | Severity | Fires when | Known noise |
|---|---|---|---|
| `reverse_shell` | high | any process calls `connect()` over IPv4 or IPv6 to port 4444, 8081 or 9001 | it is a port match: any service on those ports triggers it, and a reverse shell on another port does not |
| `shell_network_activity` | medium | `bash`, `sh`, `zsh`, `dash` or a `python*` interpreter itself calls `connect()` to anything else, except over a Unix socket | scripts, and every Python program that uses the network |
| `process_injection` | high | a `ptrace` request that takes control of a process or changes it (`TRACEME`, `ATTACH`, `SEIZE`, `POKETEXT`, `POKEDATA`, `POKEUSER`, `SETREGS`, `SETFPREGS`, `SETREGSET`, `SETSIGINFO`); an `mmap` that is writable and executable at once; or any `memfd_create` | debuggers, JIT runtimes (Node, Java), and libraries that use memfd |
| `ptrace_activity` | low | any other `ptrace` request, including ones the agent has no name for | every debugger and `strace` session |
| `anonymous_exec_mapping` | medium | an `mmap` that is executable and anonymous but not writable | JIT runtimes |
| `suspicious_exec` | medium | `execve` or `execveat` of a path that, made absolute and cleaned, is under `/tmp`, `/dev/shm` or `/var/tmp`; a path that names a file descriptor (`/dev/fd/N`, `/proc/<pid>/fd/N`); `execveat` on a descriptor with no path (how a memfd-backed binary is started); or a path that mentions `memfd` | build tools and installers that run from `/tmp` |

The one thing dropped before the rules see it is an executable, read-only `mmap` of a file. That is what loading any program or shared library does, on every process on the host; reporting it would bury everything else and overflow the perf buffer, which loses events at random. A mapping made that way and turned writable later with `mprotect` is therefore not seen (`mprotect` is not traced).

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
- **Only the syscall's arguments are seen**, at entry. A refused or failed call is reported like a successful one, and what the call went on to do is not known.
- **`suspicious_exec` matches a path string in user space, and that can be walked around.** The agent makes the path absolute (against `/proc/<pid>/cwd`, or the directory descriptor for `execveat`) and cleans it, so `/tmp/../tmp/x`, `//tmp/x` and `./x` run from `/tmp` are all caught. It does not follow symbolic or hard links, so a link from another directory to a file in `/tmp` passes. A relative path from a process that has exited before the agent reads its working directory stays relative and passes too. The robust fix is to resolve the executed file inside the kernel (the `sched_process_exec` tracepoint or the `bprm` hooks); that is not implemented.
- **Other ways to write into a process are not traced:** `process_vm_writev`, writes to `/proc/<pid>/mem`, and `mprotect`.
- **Connections:** only `connect()` is traced, so accepted connections and `sendto()` on an unconnected socket are not seen. The protocol is not known (a UDP `connect()` looks like a TCP one). Families other than IPv4 and IPv6 are reported with the family number and no address.
- **Events can be lost.** If the agent reads slower than the kernel writes, the perf buffer drops events and the agent logs how many.
- **Container attribution is a guess.** The container ID is the first long hex string in `/proc/<pid>/cgroup`; a process that has already exited, or one seen from inside its own cgroup namespace, shows as `host`. The `pod` block is the agent's own pod (from environment variables), the same for every event. The agent does not talk to the Kubernetes API.
- **The alert stream.** Alerts carry process names, paths and connection targets. The agent listens on `127.0.0.1:8090` and serves `/events` without authentication there. It refuses to start on any other address unless `EVENTS_TOKEN` is set, and then `/events` requires `Authorization: Bearer <token>`. The bundled dashboard uses the browser's `EventSource`, which cannot send that header, so it only works against the loopback address.
- **Easy to evade.** Beyond the above: a port not on the list, or a binary in any directory that is not listed.

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
python3 scripts/simulate_fexecve.py      # /bin/true copied into a memfd and run from it
python3 scripts/simulate_ipv6_connect.py # the same connection attempt over IPv6
cp /bin/true /tmp/demo && /tmp/demo      # exec from /tmp
```

Dashboard (optional):

```bash
cd dashboard
npm ci
npm run dev        # http://localhost:4173, reads http://localhost:8090/events
```

Set `CORS_ORIGIN` on the agent if the page is served from another origin. The page only works against an agent on the loopback address (see Limits). The agent's settings are in [docs/API.md](docs/API.md).

## Tests

```bash
make test    # go vet and unit tests: rules, event decoding, the SSE server (runs on any OS)
make e2e     # Linux and root: loads the probes and checks the alerts end to end
```

CI runs both, builds the dashboard, and renders the Helm chart. The end-to-end job is the evidence for the status line above; it has run on GitHub's `ubuntu-latest` runner (x86-64) and, by hand, on a 7.0 kernel on arm64.

## Kubernetes

`deploy/helm/` is a chart template: a privileged DaemonSet for the agent and a Deployment for the dashboard. It renders (`helm template` runs in CI) and that is all that has been checked. It has never been installed, there is no Dockerfile or published image for it to pull, and the values file points at placeholder image names.

The chart does not expose the alert stream. The agent keeps its default address, `127.0.0.1:8090` inside its own pod, and the chart creates no Service or NetworkPolicy for it; CI fails if the rendered chart sets `LISTEN_ADDR`. Alerts are on the agent's standard output, so in a cluster they would be read with `kubectl logs`, and the dashboard Deployment has nothing to connect to. Exposing the stream would take `LISTEN_ADDR` plus `EVENTS_TOKEN` from a Secret and a NetworkPolicy admitting only the client; none of that is in the chart, and the agent will not listen beyond loopback without the token. Treat the chart as a sketch of what a deployment would need, including the fact that it asks for a fully privileged container.

## Layout

- `ebpf/process_monitor.c`: the six tracepoint programs
- `agent/`: loader, event decoder, rules, SSE server, and their tests
- `dashboard/`: React page (Vite)
- `deploy/helm/`: chart template
- `scripts/`: the demo triggers and the end-to-end check
- `docs/`: [architecture notes](docs/ARCHITECTURE.md) and the [alert format](docs/API.md)

## Safety

Run it on a machine you own. The agent needs root and sees the command names, paths and connection targets of every process on the host, which can include sensitive strings. The demo scripts make refused local connections, one refused ptrace request, one `/tmp` exec and one in-memory run of `/bin/true`; they do not open a shell or touch another process.

MIT licence. See [SECURITY.md](SECURITY.md) to report a problem.
