#!/bin/bash

# NEX RDMA Provider Build and Test Script

set -e

echo "=== Building NEX RDMA Emulation Provider ==="

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Please run this script from the rdma-core root directory"
    exit 1
fi

# Create build directory if it doesn't exist
if [ ! -d "build" ]; then
    mkdir build
fi

cd build

# Configure with CMake
echo "Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build the NEX provider
echo "Building NEX provider..."
make nex

# Build the test program
echo "Building test program..."
make test_nex

echo "=== Build completed successfully ==="
echo ""
echo "To test the NEX provider:"
echo "1. Set environment variables:"
echo "   export RDMAV_FORK_SAFE=1"
echo "   export IBV_FORK_SAFE=1"
echo ""
echo "2. Run the test:"
echo "   ./providers/nex/test_nex"
echo ""
echo "3. List available devices:"
echo "   LD_LIBRARY_PATH=\$PWD/lib:\$LD_LIBRARY_PATH ibv_devices"
echo ""
echo "The NEX provider should appear as 'nex0' or similar."