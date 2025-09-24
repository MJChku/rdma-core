rdma_provider(nex
  nex.c
)

# Build test program
add_executable(test_nex test_nex.c)
target_link_libraries(test_nex ibverbs)