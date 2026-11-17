# Agent interface

## Endpoints

| Path | Response |
|---|---|
| `GET /events` | Server-Sent Events (`text/event-stream`). Each alert is one frame: `data: <alert as JSON>` followed by a blank line. Alerts raised before a client connected are not replayed. |
| `GET /healthz` | `200 OK` with body `ok` |

On the default loopback address neither endpoint has authentication. The agent refuses to listen on any other address unless `EVENTS_TOKEN` is set; with it set, `/events` requires `Authorization: Bearer <token>` (compared in constant time) and answers `401` otherwise, while `/healthz` stays open. A client that reads too slowly loses alerts: each client has a queue of 32, and the agent drops a client's alert instead of waiting for it.

## Alert

```
{
  "rule_id":        "reverse_shell" | "shell_network_activity" | "process_injection" |
                    "ptrace_activity" | "anonymous_exec_mapping" | "suspicious_exec",
  "severity":       "high" | "medium" | "low",
  "risk_score":     integer, fixed per rule (85, 55, 90, 30, 50, 60); nothing computes it
  "reason":         string,
  "recommendation": string,
  "event":          Event
}
```

## Event

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `exec`, `execveat`, `connect`, `ptrace`, `memfd` or `mmap_exec` |
| `pid` | number | process (thread group) ID that made the syscall |
| `ppid` | number | always 0; the probe does not look up the parent |
| `uid`, `gid` | number | real user and group ID |
| `cgroup_id` | number | cgroup v2 ID of the process |
| `comm` | string | command name, at most 15 characters |
| `filename` | string, optional | `exec`, `execveat`: the path passed. `memfd`: the name passed to `memfd_create`. At most 255 characters |
| `resolved_path` | string, optional | `exec`, `execveat`: `filename` made absolute and cleaned by the agent. Links are not followed; a relative path stays relative if the process had exited |
| `dirfd`, `exec_flags` | number, optional | `execveat`: its directory descriptor and flags (`exec` events carry `dirfd` -100, meaning the working directory) |
| `family` | number, optional | `connect`: the address family as passed (2 IPv4, 10 IPv6, 1 Unix, ...); absent if it could not be read |
| `dst_ip` | string, optional | `connect` over IPv4 or IPv6: the destination. An IPv4-mapped IPv6 address is given in its IPv4 form |
| `dst_port` | number, optional | `connect` over IPv4 or IPv6: the destination port |
| `ptrace_request`, `ptrace_request_name` | number, string, optional | `ptrace`: the request and its name where known (request 0, `PTRACE_TRACEME`, appears by name only) |
| `mmap_prot`, `mmap_flags` | number, optional | `mmap_exec`: the `prot` and `flags` arguments |
| `container` | object | `{id, name, runtime}` guessed from `/proc/<pid>/cgroup`; `id` is `host` when nothing was found |
| `pod` | object | `{name, namespace, node}` of the agent itself, from its environment; not the pod of the process |
| `timestamp` | string | RFC 3339 time at which the agent read the event (not the time of the syscall) |

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `BPF_OBJECT` | `../ebpf/process_monitor.bpf.o` | compiled probe object to load |
| `LISTEN_ADDR` | `127.0.0.1:8090` | address for `/events` and `/healthz`. Anything but a loopback address needs `EVENTS_TOKEN` |
| `EVENTS_TOKEN` | unset | if set, the bearer token `/events` requires |
| `CORS_ORIGIN` | `http://localhost:4173` | the one browser origin allowed to read `/events`; the Vite dev server's address |
| `POD_NAME`, `POD_NAMESPACE`, `NODE_NAME` | host name, `default`, `node-unknown` | copied into every event's `pod` block |
