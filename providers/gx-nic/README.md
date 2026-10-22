# GX NIC provider

This is the fiber-based `MJChku/rdma-core` provider, with the timing model
separate from functional transport. The built provider remains `gx` (`gx0`);
the CMake source directory is now `providers/gx-nic`.

## Provenance

The original fiber workers and direct-to-destination payload path are present
in `5b0c22d8` (`providers/nex`). `0fd1737d` includes the GX rename, peer-error
handling, and SRQ fixes. This copy retains the subsequent kernel-free device,
node-scoped LIDs/QP counters, scoped CPU compression, and queued READ-response
fixes from the GX working tree. It does not restore the old central timing
server, kernel-module dependency, or obsolete `accvm.so` loading.

`nex_tcp.c` and `nex_tcp.h` are copied unchanged from `0fd1737d`.
`nex_shm.c` retains the original ring/iovec transport. There is no NIC-specific
epoll reactor or full-message staging buffer in this implementation.

## Model and epoch boundary

`nex.c` calls `gx_nic_send()` once per functional message. All QPs of the NIC
pthread share the local processing/wire serializer in `nex_service.h`:

```
processing_finish = max(now, processing_free) + 140 ns
wire_finish       = max(processing_finish, wire_free) + payload_bytes / BW
delivery          = wire_finish + latency
RC completion     = wire_finish + 2 * latency
```

The message header carries delivery time in picoseconds. The RX fiber waits
for that time before streaming payload into the actual receive destination.
The TX completion fiber waits for its own completion deadline. READ replies
are ordinary timed messages; the requester completes after receiving its reply.
Timestamps are not rounded to epochs (only to the clock's nanosecond unit).
All communicating providers must use the same new header layout.

When all active fibers are idle, the existing scheduler invokes the model's
idle hook. The hook calls one native global-epoch checkpoint. The pthread
remains enrolled across epochs and yields while waiting. Fiber busy/idle state
is not reset at epoch boundaries. With no worker fibers, it leaves
membership; new work rejoins. Before GXVM's start marker, timing is a no-op.

Transport selection is unchanged: `GX_IO_BACKEND=tcp` selects sockets; otherwise
the shared-memory path uses the original locality/ring mechanism. Timing does
not force TCP. This is not automatic cross-host TCP fallback: select TCP for
peers that do not share the required shared-memory namespace/bridge.

Existing settings are `GX_NIC_BANDWIDTH_GBPS`, `GX_NIC_LATENCY_NS`,
`GXVM_EPOCH_NS`, and `GXVM_EPOCH_PATH`. No new mode switches are introduced.

## Validation

From the NEX repository root:

```sh
make -f tests/comm/rdma_timing.mk local-model-check \
  BUILD="$PWD/build/rdma-local-model" ITERATIONS=16 EPOCH_NS=10000
```

This checks SEND, WRITE, READ, payload correctness, exact TX/RX byte counts,
and the bandwidth ceiling on both transports, with one and four QPs.
