add_compile_options(-O2)
rdma_provider(nex
  nex.c
  nex_shm.c
  cm/nex_cm.c
)

## Convenience target to match build script expectation
add_custom_target(nex DEPENDS "nex-rdmav${IBVERBS_PABI_VERSION}")

# Build test program (installed: OFF, output to build/bin)
rdma_test_executable(test_nex test_nex.c)
target_link_libraries(test_nex LINK_PRIVATE ibverbs)

add_executable(nex_cm_srv
  cm/nex_cm_srv.c
  cm/nex_cm.c)
set_target_properties(nex_cm_srv PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
