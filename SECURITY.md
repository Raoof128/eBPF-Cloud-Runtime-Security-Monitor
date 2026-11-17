# Security Policy

This is an educational project. It is not hardened and should not be used to protect a real system; the README lists what it does not do.

## Reporting a problem

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting: the **Report a vulnerability** button on this repository's Security tab, or <https://github.com/Raoof128/eBPF-Cloud-Runtime-Security-Monitor/security/advisories/new>.

Reports are read as time allows. There is no guaranteed response time and there are no supported releases; fixes land on the default branch.

## What to keep in mind when running it

- The agent runs as root and loads programs into the kernel. Run it only on a machine you own.
- It sees the command name, executed paths and connection targets of every process on the host. Those strings can be sensitive.
- The alert stream (`/events`) has no authentication. The agent binds to `127.0.0.1` by default; change `LISTEN_ADDR` only on a network you trust.
- The Helm chart asks for a fully privileged container and has never been installed on a cluster.
