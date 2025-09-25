#!/usr/bin/env bash
set -euo pipefail

LIBDIR=/home/jma/NEX/src/sims/ib/rdma-core/build/lib
export LD_LIBRARY_PATH="$LIBDIR"

./bin/nex_cm_srv &
cm_pid=$!
sleep 0.2

./bin/ibv_rc_pingpong -d nex0 -p 20001 -n 1 &
srv_pid=$!
sleep 0.2

./bin/ibv_rc_pingpong -d nex0 -p 20001 127.0.0.1 -n 1 &
cli_pid=$!

wait "$cli_pid"
echo "test finished; kill all now"

if kill -9 "$srv_pid" 2>/dev/null; then
	wait "$srv_pid" || true
fi
if kill -9 "$cm_pid" 2>/dev/null; then
	wait "$cm_pid" || true
fi
