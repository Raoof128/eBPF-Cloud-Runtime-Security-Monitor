#!/usr/bin/env python3
"""Makes two local connection attempts on an IPv6 socket.

One goes to [::1]:4444 and one to the IPv4-mapped address [::ffff:127.0.0.1]:9001. Both
ports are on the agent's watch list. Nothing listens on either, so both are refused; the
probe sees the attempt, which is the point. Prints "ipv6-unavailable" and does nothing if
this machine cannot create an IPv6 socket.
"""

import socket

TARGETS = [("::1", 4444), ("::ffff:127.0.0.1", 9001)]

try:
    probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    probe.close()
except OSError as err:
    print(f"ipv6-unavailable: {err}")
else:
    for host, port in TARGETS:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            print(f"[demo] connect to [{host}]:{port} returned {result}")
