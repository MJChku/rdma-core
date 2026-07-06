#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdbool.h>

typedef void (*nex_fiber_fn_t)(void *arg);
typedef int (*nex_sched_init_t)(uint32_t nex_id);
typedef int (*nex_sched_new_fiber_t)(nex_fiber_fn_t fn, void *arg);
typedef void (*nex_sched_shutdown_t)(void);
typedef void (*nex_fiber_yield_t)(void);
typedef void (*nex_fiber_idle_yield_t)(void);

struct accvm_symbols {
    nex_sched_init_t nex_sched_init;
    nex_sched_new_fiber_t nex_sched_new_fiber;
    nex_sched_shutdown_t nex_sched_shutdown;
    nex_fiber_yield_t nex_fiber_yield;
    nex_fiber_idle_yield_t nex_fiber_idle_yield;
};

int nex_shm_dial(const char* service_id, int* fd_out);
ssize_t nex_shm_read(int fd, void* buf, size_t len, int apply_perf_model);
ssize_t nex_shm_write(int fd, const void* buf, size_t len, int apply_perf_model);
ssize_t nex_shm_writev(int fd, const struct iovec *iov, int iovcnt,
                       int apply_perf_model, bool wait_completion, int *slot_out,
                       uint32_t tag);
ssize_t nex_shm_readv(int fd, const struct iovec *iov, int iovcnt,
                      int apply_perf_model, bool wait_completion, int *slot_out,
                      uint32_t tag);
int nex_shm_close(int fd);
int nex_shm_shutdown(int fd);
void nex_fast_memcpy(void* dst, const void* src, size_t len);
void nex_fiber_yield(void);
void nex_fiber_idle_yield(void);
int get_accvm_symbols(struct accvm_symbols* syms);

extern struct accvm_symbols accvm_syms;
