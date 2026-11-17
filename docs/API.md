# Agent interface

## Endpoints

| Path | Response |
|---|---|
| `GET /events` | Server-Sent Events (`text/event-stream`). Each alert is one frame: `data: <alert as JSON>` followed by a blank line. Alerts raised before a client connected are not replayed. |
| `GET /healthz` | `200 OK` with body `ok` |

Neither endpoint has authentication. A client that reads too slowly loses alerts: each client has a queue of 32, and the agent drops a client's alert instead of waiting for it.

## Alert

```
{
  "rule_id":        "reverse_shell" | "shell_network_activity" | "process_injection" | "suspicious_exec",
  "severity":       "high" | "medium",
  "risk_score":     integer, fixed per rule (85, 55, 90, 60); nothing computes it
  "reason":         string,
  "recommendation": string,
  "event":          Event
}
```

## Event

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `exec`, `connect`, `ptrace`, `memfd` or `mmap_wx` |
| `pid` | number | process (thread group) ID that made the syscall |
| `ppid` | number | always 0; the probe does not look up the parent |
| `uid`, `gid` | number | real user and group ID |
| `cgroup_id` | number | cgroup v2 ID of the process |
| `comm` | string | command name, at most 15 characters |
| `filename` | string, optional | `exec`: the path passed to `execve`. `memfd`: the name passed to `memfd_create`. At most 255 characters |
| `dst_ip` | string, optional | `connect` only: IPv4 destination |
| `dst_port` | number, optional | `connect` only: destination port |
| `container` | object | `{id, name, runtime}` guessed from `/proc/<pid>/cgroup`; `id` is `host` when nothing was found |
| `pod` | object | `{name, namespace, node}` of the agent itself, from its environment; not the pod of the process |
| `timestamp` | string | RFC 3339 time at which the agent read the event (not the time of the syscall) |

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `BPF_OBJECT` | `../ebpf/process_monitor.bpf.o` | compiled probe object to load |
| `LISTEN_ADDR` | `127.0.0.1:8090` | address for `/events` and `/healthz` |
| `CORS_ORIGIN` | `http://localhost:4173` | the one browser origin allowed to read `/events`; the Vite dev server's address |
| `POD_NAME`, `POD_NAMESPACE`, `NODE_NAME` | host name, `default`, `node-unknown` | copied into every event's `pod` block |
