#!/usr/bin/env python3
"""Runs a copy of /bin/true from an anonymous in-memory file.

The script creates a memfd, copies /bin/true into it and has a child process execute the
descriptor (fexecve, which the C library turns into execveat with an empty path and
AT_EMPTY_PATH). Nothing is written to disk and the child exits at once. It is the shape of
a "fileless" execution with a harmless payload.
"""

import os

fd = os.memfd_create("ecrsm-smoke")
with open("/bin/true", "rb") as source:
    payload = source.read()
written = 0
while written < len(payload):
    written += os.write(fd, payload[written:])

print(f"[demo] executing a {len(payload)}-byte copy of /bin/true from memfd descriptor {fd}")
pid = os.fork()
if pid == 0:
    os.execve(fd, ["ecrsm-smoke"], {})
    os._exit(127)  # only reached if the exec failed

_, status = os.waitpid(pid, 0)
print(f"[demo] child exited with status {os.waitstatus_to_exitcode(status)}")
