/* Two pipelined NIC stages. Times are picoseconds, never epoch-rounded. */
#pragma once
#include <stdint.h>

struct nex_service {
    uint64_t processing_free;
    uint64_t wire_free;
};

/* RC completion includes forward delivery plus a return acknowledgement.
 * The acknowledgement is a timing delay, not another payload transfer. */
static inline uint64_t nex_service_ack(uint64_t end, uint64_t epoch, uint64_t latency)
{
    return ((end + epoch - 1) / epoch) * epoch + 2 * latency;
}

/* One call per outgoing functional message, independent of CQ polling and
 * completion signaling. All QPs of a NIC share this state. Processing the
 * next message overlaps transmission of the previous message. */
static inline uint64_t nex_service_reserve(struct nex_service *s, uint64_t now,
                                           uint64_t processing, uint64_t wire)
{
    s->processing_free = (s->processing_free > now ? s->processing_free : now)
                        + processing;
    s->wire_free = (s->wire_free > s->processing_free ? s->wire_free
                                                      : s->processing_free)
                   + wire;
    return s->wire_free;
}
