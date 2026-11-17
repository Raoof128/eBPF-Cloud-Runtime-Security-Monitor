#!/usr/bin/env bash
# Makes bash open one TCP connection to 127.0.0.1 on a port from the agent's watch list
# (4444 by default). That is the syscall a reverse shell starts with, and it is all this
# script does: nothing is listening, so the connection is refused, and no shell is exposed.
set -euo pipefail

PORT="${1:-4444}"
echo "[demo] bash connecting to 127.0.0.1:${PORT} (expected to be refused)"
bash -c "exec 3<>/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null || true
echo "[demo] done"
