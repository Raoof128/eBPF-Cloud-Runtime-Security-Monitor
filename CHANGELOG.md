# Changelog

Notable changes to this project, newest first. Dates are Australia/Sydney. Changes before
17 November 2026 are in the Git log only.

## [Unreleased]

### Raouf: 2026-11-17 (Australia/Sydney): the probe-to-alert path works and is tested end to end

- **Scope:** `ebpf/`, `agent/`, `dashboard/`, `deploy/helm/`, `scripts/`, CI, `README.md`, `docs/`.
- **What was wrong before:** The agent never worked end to end. It opened the perf map but never
  loaded or attached a program, so no event could reach it. The event layout in Go did not match
  the C struct, the destination address was byte-swapped, and alerts encoded process names as
  lists of numbers.
- **Probe:** One program on the raw `sys_enter` tracepoint picks out `execve`, `execveat`,
  `connect`, `ptrace`, `memfd_create` and `mmap`. An earlier attempt with one program per syscall
  tracepoint delivered some events from CPU 0 only on the CI kernel. The cause was not tracked
  down; the raw tracepoint delivers from every CPU.
- **Agent:** Loads and attaches the program and decodes events into documented JSON fields. Exec
  paths are made absolute and cleaned before matching, on whole path components. Connects are
  reported for any address family, with IPv6 decoded. Every ptrace request is reported:
  control-taking requests as high, the rest as low.
- **Alert stream:** Bound to `127.0.0.1` by default. The agent refuses any other address without
  `EVENTS_TOKEN`, and `/events` then requires that bearer token.
- **Dashboard and Helm:** The dashboard reads the new fields and shows plain counts in place of
  bars that presented alert counts as utilisation. The Helm chart is documented as a template that
  has never been installed.
- **Docs:** README rewritten around a status line and a Limits section. No detection rate,
  overhead figure or Kubernetes claim is made.
- **Verification:** CI on GitHub's `ubuntu-latest` runner (x86-64, kernel 7.0): `go vet` and the
  agent's unit tests; the end-to-end job, which loads the probe and expects alerts, eight of eight
  checks; the dashboard lint and build; the Helm chart render.
- **Follow-ups:** The arm64 register offsets and syscall numbers are written from the ABI and have
  not been run. Known evasions are listed under Limits in the README.
