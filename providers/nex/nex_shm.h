#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdbool.h>

typedef void (*compressT_t)(float percentage);
typedef void (*jailbreakT_t)(float percentage);
typedef void (*end_jailbreakT_t)(void);
typedef int (*send_data_qp_t)(uint32_t src_addr, uint32_t dst_addr, size_t len,
                              uint32_t src_qp, uint32_t dst_qp, uint32_t tag,
                              bool wait_required);
typedef int (*recv_data_qp_t)(uint32_t src_addr, uint32_t dst_addr, size_t len,
                              uint32_t src_qp, uint32_t dst_qp, uint32_t tag,
                              bool wait_required);
typedef void (*wait_for_completion_t)(uint32_t slot);
typedef void (*changeEpoch_t)(int epoch_duration_ns, int cnt);

struct accvm_symbols {
    changeEpoch_t changeEpoch;
    compressT_t compressT;
    jailbreakT_t jailbreakT;
    end_jailbreakT_t endJailbreakT;
    send_data_qp_t send_data_qp;
    recv_data_qp_t recv_data_qp;
    wait_for_completion_t wait_for_completion;
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
int get_accvm_symbols(struct accvm_symbols* syms);

extern struct accvm_symbols accvm_syms;
