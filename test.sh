#!/usr/bin/env bash
set -euo pipefail

LIBDIR=/home/jiacma/nex-dist/src/sims/ib/rdma-core/build/lib
export LD_LIBRARY_PATH="$LIBDIR:$LD_LIBRARY_PATH"

sudo rm /dev/shm/*:*

NEX_ID=0 /home/jiacma/nex-dist/nex ./build/bin/ibv_rc_pingpong -d nex0 -p 20001 -n 1 &
srv_pid=$!
sleep 0.2

NEX_ID=1 /home/jiacma/nex-dist/nex ./build/bin/ibv_rc_pingpong -d nex0 -p 20001 127.0.0.1 -n 1 &
cli_pid=$!

wait "$cli_pid"
echo "test finished; kill all now"

if kill -9 "$srv_pid" 2>/dev/null; then
	wait "$srv_pid" || true
fi
if kill -9 "$cm_pid" 2>/dev/null; then
	wait "$cm_pid" || true
fi
