#!/usr/bin/env python3
"""Calls ptrace(PTRACE_ATTACH) on this script's own process.

A process cannot attach to itself, so the kernel refuses and nothing is traced. The probe
sits on syscall entry, so it still sees the request, which is all the demo needs.
"""

import ctypes
import ctypes.util
import os

PTRACE_ATTACH = 16

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
pid = os.getpid()
print(f"[demo] ptrace(PTRACE_ATTACH) on own pid {pid}")

if libc.ptrace(PTRACE_ATTACH, pid, None, None) != 0:
    print(f"[demo] refused as expected: {os.strerror(ctypes.get_errno())}")
else:
    print("[demo] unexpectedly allowed")
print("[demo] done")
