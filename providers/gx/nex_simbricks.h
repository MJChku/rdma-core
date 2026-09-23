#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
struct gx_nic_link;
/* A connected nonblocking TCP socket carries SimBricks base messages. The
 * existing CM still establishes QPs; no separate central timing simulator. */
int gx_nic_enabled(void);
int gx_nic_prepare(void);
void gx_nic_config(uint64_t values[4]);
struct gx_nic_link *gx_nic_open(int socket, uint32_t local_nic);
void gx_nic_shutdown(struct gx_nic_link *link);
void gx_nic_close(struct gx_nic_link *link);
int gx_nic_begin(struct gx_nic_link *link, size_t payload_bytes);
void gx_nic_end(struct gx_nic_link *link);
uint64_t gx_nic_completion_time(struct gx_nic_link *link, bool acknowledged);
void gx_nic_wait_until(struct gx_nic_link *link, uint64_t time_ns);
ssize_t gx_nic_read(struct gx_nic_link *link, void *dst, size_t len);
ssize_t gx_nic_write(struct gx_nic_link *link, const void *src, size_t len);
