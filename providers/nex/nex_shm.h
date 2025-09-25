#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
int nex_shm_dial(const char* service_id, int* fd_out);
ssize_t nex_shm_read(int fd, void* buf, size_t len);
ssize_t nex_shm_write(int fd, const void* buf, size_t len);
int nex_shm_close(int fd);
int nex_shm_shutdown(int fd);