#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

int nex_tcp_dial(const char *service_id, int *fd_out);
ssize_t nex_tcp_read(int fd, void *buf, size_t len, int apply_perf_model);
ssize_t nex_tcp_write(int fd, const void *buf, size_t len, int apply_perf_model);
ssize_t nex_tcp_writev(int fd, const struct iovec *iov, int iovcnt,
                       int apply_perf_model, bool wait_completion, int *slot_out,
                       uint32_t tag);
ssize_t nex_tcp_readv(int fd, const struct iovec *iov, int iovcnt,
                      int apply_perf_model, bool wait_completion, int *slot_out,
                      uint32_t tag);
int nex_tcp_close(int fd);
int nex_tcp_shutdown(int fd);
