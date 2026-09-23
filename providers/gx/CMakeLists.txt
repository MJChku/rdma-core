add_compile_options(-O2)
get_filename_component(GX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../.." ABSOLUTE)
include_directories("${GX_ROOT}" "${GX_ROOT}/third_party/simbricks/lib")
rdma_provider(gx
  nex.c
  nex_shm.c
  nex_tcp.c
  nex_simbricks.c
  "${GX_ROOT}/third_party/simbricks/lib/simbricks/base/if.c"
  cm/nex_cm.c
)

## Convenience target to match build script expectation
add_custom_target(gx_provider DEPENDS "gx-rdmav${IBVERBS_PABI_VERSION}")

# Build test program (installed: OFF, output to build/bin)
rdma_test_executable(test_nex test_nex.c)
target_link_libraries(test_nex LINK_PRIVATE ibverbs)

add_executable(gx_cm_srv
  cm/nex_cm_srv.c
  cm/nex_cm.c)
set_target_properties(gx_cm_srv PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
