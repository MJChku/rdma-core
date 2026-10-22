#pragma once
#include <stddef.h>
#include <stdint.h>

/* One local service model per NIC pthread, shared by its QP fibers.
 * Functional transfer and routing stay in nex.c / nex_{shm,tcp}.c. */
int gx_nic_prepare(void);
/* UINT64_MAX denotes a request submitted before timing activation. */
uint64_t gx_nic_submission_ns(void);
void gx_nic_send(uint64_t submitted_ns, size_t bytes, int acknowledged,
                 uint64_t *delivery_ps, uint64_t *completion_ns);
void gx_nic_receive(uint64_t delivery_ps);
void gx_nic_received(size_t bytes);
void gx_nic_wait(uint64_t completion_ns);
