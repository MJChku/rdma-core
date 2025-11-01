#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef void (*compressT_t)(float percentage);
typedef void (*jailbreakT_t)(float percentage);
typedef void (*end_jailbreakT_t)(void);
typedef int (*send_data_t)(uint32_t src_addr, uint32_t dst_addr, size_t len);
typedef int (*recv_data_t)(uint32_t src_addr, uint32_t dst_addr, size_t len);
typedef int (*send_data_qp_t)(uint32_t src_addr, uint32_t dst_addr, size_t len,
                              uint32_t src_qp, uint32_t dst_qp);
typedef int (*recv_data_qp_t)(uint32_t src_addr, uint32_t dst_addr, size_t len,
                              uint32_t src_qp, uint32_t dst_qp);


                              
struct accvm_symbols {
    compressT_t compressT;
    jailbreakT_t jailbreakT;
    end_jailbreakT_t endJailbreakT;
    send_data_t send_data;
    recv_data_t recv_data;
    send_data_qp_t send_data_qp;
    recv_data_qp_t recv_data_qp;
};

int nex_shm_dial(const char* service_id, int* fd_out);
ssize_t nex_shm_read(int fd, void* buf, size_t len, int apply_perf_model);
ssize_t nex_shm_write(int fd, const void* buf, size_t len, int apply_perf_model);
int nex_shm_close(int fd);
int nex_shm_shutdown(int fd);
void nex_fast_memcpy(void* dst, const void* src, size_t len);
int get_accvm_symbols(struct accvm_symbols* syms);

extern struct accvm_symbols accvm_syms;