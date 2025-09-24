# NEX RDMA Emulation Provider

The NEX provider implements RDMA (Remote Direct Memory Access) emulation over TCP/IP networks instead of using real InfiniBand hardware. This allows RDMA applications to run on standard Ethernet networks with TCP/IP transport.

## Features

- **TCP/IP Transport**: Uses standard TCP sockets for RDMA operations
- **Full RDMA Verbs API**: Implements all standard RDMA verbs (QP, CQ, MR, AH, etc.)
- **Zero-copy Emulation**: Simulates RDMA semantics over TCP connections
- **Multi-threaded**: Thread-safe implementation with proper locking

## Architecture

The NEX provider consists of:

1. **nex.c**: Main provider implementation
2. **nex.h**: Provider header with data structures
3. **nex-abi.h**: User-space ABI definitions
4. **kernel-headers/rdma/nex-abi.h**: Kernel ABI definitions

## Building

The provider is built as part of the rdma-core build system:

```bash
cd /home/jma/NEX/src/sims/ib/rdma-core
mkdir build && cd build
cmake ..
make
```

## Usage

To use the NEX provider, set the `RDMAV_FORK_SAFE` and `IBV_FORK_SAFE` environment variables:

```bash
export RDMAV_FORK_SAFE=1
export IBV_FORK_SAFE=1
```

Then specify the NEX provider when running RDMA applications:

```bash
# List available devices
ibv_devices

# Use NEX provider explicitly
RDMAV_HUGEPAGES_SAFE=1 ibv_devinfo -d nex0

# Run applications with NEX
RDMAV_HUGEPAGES_SAFE=1 my_rdma_app -d nex0
```

## Configuration

The NEX provider uses the following default settings:

- **Default Port**: 12345
- **Max Inline Data**: 512 bytes
- **Max SGE**: 16 entries
- **TCP Socket Buffer**: System default

## Limitations

- **Performance**: TCP/IP overhead vs native RDMA
- **Latency**: Higher latency than native RDMA
- **Bandwidth**: Limited by TCP/IP stack
- **No Hardware Offload**: All operations emulated in software

## Debugging

Enable debug logging:

```bash
export NEX_DEBUG=1
export LIBVERBS_DEBUG=1
```

## Testing

A simple test program is provided to verify basic functionality:

```bash
cd /home/jma/NEX/src/sims/ib/rdma-core
make test_nex
./test_nex
```

## Future Enhancements

- UDP transport option for lower latency
- Connection multiplexing for better performance
- RDMA over WebSockets for browser compatibility
- Hardware acceleration integration