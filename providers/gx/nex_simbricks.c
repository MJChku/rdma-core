/* Functional RDMA byte stream over synchronized SimBricks base messages.
 * The socket adapter below only transports queue entries. BaseIf owns message
 * timestamping, ordering and receive-time gating; GXVM owns epoch advancement.
 * All links and the NIC serializer belong to the provider's ONE fiber pthread.
 */
#define _GNU_SOURCE
#include "nex_simbricks.h"
#include "nex_shm.h"
#include "nex_service.h"
#include <simbricks/base/if.h>
#include "tools/gxvm/src/epoch/runtime.h"
#include "tools/gxvm/src/epoch/epoch_abi.h"
#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define DATA SIMBRICKS_PROTO_MSG_TYPE_UPPER_START
struct frame { union SimbricksProtoBaseMsg base; unsigned char data[]; };
struct gx_nic_link {
    struct SimbricksBaseIf base;
    struct frame *in, *out;
    int socket;
    _Atomic int closed;
    size_t rx_bytes, tx_bytes, read_offset;
    uint64_t last_sync;
    uint64_t send_time;
    uint64_t frontier;
    size_t written, capacity;
    bool sending;
    struct gx_nic_link *next;
};
static struct gx_nic_link *links;
static struct nex_service service;
/* Fitted to the supplied ~5.6 Mops/s small-message curves, including the
 * existing link/epoch latency. A modeled NIC cost, not host emulation time.
 * One policy for SEND, WRITE, READ request and READ response. */
static const uint64_t processing_ps = 140000;
static uint64_t latency_ps, epoch_ps;
static double bytes_per_ns;
static gxvm_epoch_native_member_t member;
static uint64_t tx_total, rx_total, epochs;
static uint64_t messages;
static bool checkpoint_waiting;
static _Atomic unsigned started;
static struct {
    void (*attach)(const gxvm_epoch_config_t *, const char *);
    struct gxvm_epoch_page *(*page)(void);
    uint64_t (*time)(void);
    void (*join)(gxvm_epoch_native_member_t *);
    void (*leave)(gxvm_epoch_native_member_t *);
    void (*checkpoint)(gxvm_epoch_native_member_t *, void (*)(void *), void *);
    void (*hook)(void (*)(void *), void (*)(bool, void *), void (*)(void *), void *);
    void (*busy)(void);
} api;

static void fail(const char *why) {
    fprintf(stderr, "GX_NIC FAIL %s (errno=%d)\n", why, errno);
    abort();
}
static uint64_t ns_config(const char *name, uint64_t fallback) {
    const char *s = getenv(name);
    if (!s) return fallback;
    char *end;
    errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || end == s || *end || *s == '-' || !n || n > UINT64_MAX / 1000)
        fail(name);
    return n;
}
int gx_nic_enabled(void) {
    const char *s = getenv("GX_NIC_BANDWIDTH_GBPS");
    if (!s || !*s) return 0;
    char *end;
    double n = strtod(s, &end);
    if (*end || !isfinite(n) || n < 0) fail("invalid GX_NIC_BANDWIDTH_GBPS");
    return n > 0;
}
static uint64_t now(void) { return api.time() * 1000; }
static uint32_t length(const struct frame *f) {
    uint32_t n;
    memcpy(&n, f->base.header.pad, sizeof(n));
    return be32toh(n);
}
static void set_length(volatile union SimbricksProtoBaseMsg *m, uint32_t n) {
    n = htobe32(n);
    memcpy((void *)m->header.pad, &n, sizeof(n));
}
static uint64_t payload_size(struct frame *f) {
    uint64_t n;
    memcpy(&n, f->base.header.pad + 8, sizeof(n));
    return be64toh(n);
}
static bool retry(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }

/* Single-entry queues, backed by private memory instead of shared memory:
 * this embedded socket proxy fills/drains them, like SimBricks' external
 * proxy. Never publish a partially received entry to BaseIfInPoll. */
static void pump(struct gx_nic_link *l) {
    int closed = atomic_load(&l->closed);
    if (closed) {
        /* close() follows QP worker drain. Retire its large buffers on their
         * owning pthread; a concurrent main-thread close never frees memory
         * underneath a transport pump. Keep only the small list node. */
        if (closed == 2) {
            free(l->in); free(l->out); l->in = l->out = NULL;
            atomic_store(&l->closed, 3);
        }
        return;
    }
    if (l->out->base.header.own_type & SIMBRICKS_PROTO_MSG_OWN_CON) {
        size_t total = 64 + (size_t)length(l->out);
        ssize_t n = send(l->socket, (char *)l->out + l->tx_bytes,
                         total - l->tx_bytes, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
            l->tx_bytes += n;
            if (l->tx_bytes == total) {
                l->tx_bytes = 0;
                l->out->base.header.own_type &= ~SIMBRICKS_PROTO_MSG_OWN_MASK;
            }
        } else if (n == 0 || !retry()) { atomic_store(&l->closed, 1); return; }
    }
    if (l->in->base.header.own_type & SIMBRICKS_PROTO_MSG_OWN_CON) return;
    size_t target = l->rx_bytes < 64 ? 64 : 64 + (size_t)length(l->in);
    if (l->rx_bytes < target) {
        ssize_t n = recv(l->socket, (char *)l->in + l->rx_bytes,
                         target - l->rx_bytes, MSG_DONTWAIT);
        if (n > 0) {
            l->rx_bytes += n;
            if (target == 64 && l->rx_bytes == 64) {
                /* Allocate only the real wire message, not a per-QP large ring. */
                struct frame *f = realloc(l->in, 64 + (size_t)length(l->in));
                if (!f) fail("incoming message allocation");
                l->base.in_queue = l->in = f;
            }
        }
        else if (n == 0 || !retry()) { atomic_store(&l->closed, 1); return; }
    }
    if (l->rx_bytes >= 64) {
        l->in->base.header.own_type &= ~SIMBRICKS_PROTO_MSG_OWN_MASK;
        if (l->rx_bytes == 64 + (size_t)length(l->in))
            l->in->base.header.own_type |= SIMBRICKS_PROTO_MSG_OWN_CON;
    }
}
static void done(struct gx_nic_link *l) {
    SimbricksBaseIfInDone(&l->base, &l->in->base);
    l->rx_bytes = l->read_offset = 0;
}
static void sync_link(struct gx_nic_link *l, uint64_t t) {
    pump(l);
    if (atomic_load(&l->closed)) return;
    if (!l->sending && l->last_sync != t &&
        !(l->out->base.header.own_type & SIMBRICKS_PROTO_MSG_OWN_CON) &&
        t >= l->base.out_timestamp) {
        /* OutSync leaves payload bytes untouched when reusing an entry. */
        set_length(&l->out->base, 0);
        if (!SimbricksBaseIfOutSync(&l->base, t)) l->last_sync = t;
        pump(l);
    }
    volatile union SimbricksProtoBaseMsg *m;
    /* Null messages are promises, not functional deliveries: consume them
     * early so a full input slot never obstructs transport progress. */
    while ((m = SimbricksBaseIfInPeek(&l->base, UINT64_MAX)) &&
           SimbricksBaseIfInType(&l->base, m) == SIMBRICKS_PROTO_MSG_TYPE_SYNC) {
        if (m->header.timestamp < l->frontier) fail("nonmonotonic sync");
        l->frontier = m->header.timestamp;
        SimbricksBaseIfInPoll(&l->base, UINT64_MAX);
        done(l);
        pump(l);
    }
    m = SimbricksBaseIfInPeek(&l->base, UINT64_MAX);
    if (m) {
        if (m->header.timestamp < l->frontier) fail("data overtaken by sync");
        l->frontier = m->header.timestamp;
    }
}
static void drain(void *unused) {
    (void)unused;
    /* No application memory writes/CQ completions while waiting for epoch.
     * Only move existing socket bytes and consume sync promises. */
    for (struct gx_nic_link *l = links; l; l = l->next) sync_link(l, now());
    /* Connection setup is functional transport work too. Let those fibers
     * progress while arrived. read/begin/completion below gate model effects
     * until this checkpoint returns; nested idle hooks cannot arrive twice. */
    gx_fiber_yield();
}
static void idle(void *unused) {
    (void)unused;
    if (checkpoint_waiting) return;
    uint64_t t = now();
    bool safe = true;
    for (struct gx_nic_link *l = links; l; l = l->next) {
        sync_link(l, t);
        if (atomic_load(&l->closed)) continue;
        /* Do not overtake data at this time or an unfinished outgoing WR.
         * A future entry (data OR sync) is the peer's safe-time promise. */
        if (l->sending ||
            ((l->out->base.header.own_type & SIMBRICKS_PROTO_MSG_OWN_CON) &&
             l->out->base.header.timestamp < t + epoch_ps) ||
            SimbricksBaseIfInPeek(&l->base, t) ||
            l->frontier < t + epoch_ps)
            safe = false;
    }
    /* A disconnected peer has no remaining deliveries to constrain time.
     * Still finish this member's epoch: the CPU may need that transition to
     * reach destroy_qp and stop our otherwise-idle TX fibers. */
    if (safe) {
        checkpoint_waiting = true;
        api.checkpoint(&member, drain, NULL);
        checkpoint_waiting = false;
        ++epochs;
    }
    else sched_yield();
}
static void active(bool running, void *unused) {
    (void)unused;
    /* An open context without worker fibers must not hold the global epoch.
     * Rejoin on dispatch, before any new model work executes. */
    if (running && !member.active) api.join(&member);
    else if (!running && member.active) api.leave(&member);
}
static void stop(void *unused) {
    (void)unused;
    if (member.active) api.leave(&member);
    fprintf(stderr, "GX_NIC bytes_tx=%llu bytes_rx=%llu epochs=%llu\n",
            (unsigned long long)tx_total, (unsigned long long)rx_total,
            (unsigned long long)epochs);
    fprintf(stderr, "GX_NIC_SERVICE messages=%llu processing_ns=%llu processing_total_ns=%llu\n",
            (unsigned long long)messages, (unsigned long long)(processing_ps / 1000),
            (unsigned long long)(messages * processing_ps / 1000));
    while (links) { struct gx_nic_link *p = links; links = p->next;
        free(p->in); free(p->out); free(p); }
    service = (struct nex_service){0};
    tx_total = rx_total = epochs = messages = 0;
    /* A later context starts a new pthread/TID and needs a fresh observer
     * registration; native_leave alone intentionally retains a thread slot. */
    member = (gxvm_epoch_native_member_t){0};
    atomic_store(&started, 0);
}
static void start(void) {
    if (member.active) return;
#define RESOLVE(field, name) do { *(void **)(&api.field) = dlsym(RTLD_DEFAULT, name); \
    if (!api.field) fail("missing " name); } while (0)
    RESOLVE(attach, "gxvm_epoch_runtime_attach");
    RESOLVE(page, "gxvm_epoch_shared_page");
    RESOLVE(time, "gxvm_epoch_time_ns");
    RESOLVE(join, "gxvm_epoch_native_join");
    RESOLVE(leave, "gxvm_epoch_native_leave");
    RESOLVE(checkpoint, "gxvm_epoch_native_checkpoint_poll");
    RESOLVE(hook, "gx_sched_set_idle_hook");
    RESOLVE(busy, "gx_fiber_mark_busy");
#undef RESOLVE
    const char *path = getenv("GXVM_EPOCH_PATH");
    if (!path || !*path) fail("NIC timing requires GXVM_EPOCH_PATH");
    gxvm_epoch_config_t config = {.epoch_ns = ns_config("GXVM_EPOCH_NS", 1000)};
    if (!api.page()) api.attach(&config, path);
    epoch_ps = api.page()->epoch_ns * 1000;
    latency_ps = ns_config("GX_NIC_LATENCY_NS", epoch_ps / 1000) * 1000;
    if (latency_ps < epoch_ps || latency_ps % epoch_ps)
        fail("NIC latency must be a positive whole number of epochs");
    if (latency_ps > (UINT64_MAX - epoch_ps) / 2)
        fail("NIC round-trip latency overflow");
    bytes_per_ns = strtod(getenv("GX_NIC_BANDWIDTH_GBPS"), NULL);
    api.join(&member);
    api.hook(idle, active, stop, NULL);
}
static void start_fiber(void *unused) {
    (void)unused;
    start();
    atomic_store_explicit(&started, 2, memory_order_release);
}
int gx_nic_prepare(void) {
    if (!gx_nic_enabled()) return 0;
    unsigned expected = 0;
    if (atomic_compare_exchange_strong(&started, &expected, 1)) {
        if (accvm_syms.gx_sched_new_fiber(start_fiber, NULL)) {
            atomic_store(&started, 0); return -1;
        }
    }
    /* Publish configuration before context creation returns. Worker activity
     * owns membership; simply keeping a context open must not stop time. */
    while (atomic_load_explicit(&started, memory_order_acquire) == 1) sched_yield();
    return atomic_load(&started) == 2 ? 0 : -1;
}
void gx_nic_config(uint64_t values[4]) {
    values[0] = epoch_ps; values[1] = latency_ps;
    memcpy(&values[2], &bytes_per_ns, sizeof(bytes_per_ns));
    values[3] = processing_ps;
}
struct gx_nic_link *gx_nic_open(int socket, uint32_t local_nic) {
    (void)local_nic;
    start();
    struct gx_nic_link *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->in = calloc(1, 64);
    l->out = calloc(1, 64);
    if (!l->in || !l->out) fail("queue allocation");
    struct SimbricksBaseIfParams p;
    SimbricksBaseIfDefaultParams(&p);
    p.link_latency = latency_ps;
    p.sync_interval = epoch_ps;
    p.sync_mode = kSimbricksBaseIfSyncRequired;
    if (SimbricksBaseIfInit(&l->base, &p)) fail("base init");
    l->base.in_queue = l->in;
    l->base.out_queue = l->out;
    l->base.in_elen = l->base.out_elen = 64;
    l->base.in_enum = l->base.out_enum = 1;
    l->base.sync = true;
    l->socket = socket;
    l->last_sync = UINT64_MAX;
    l->next = links;
    links = l;
    return l;
}
void gx_nic_shutdown(struct gx_nic_link *l) { if (l) atomic_store(&l->closed, 1); }
void gx_nic_close(struct gx_nic_link *l) { if (l) atomic_store(&l->closed, 2); }
int gx_nic_begin(struct gx_nic_link *l, size_t bytes) {
    /* All outgoing QPs on this NIC share a serializer. Provider currently
     * has one logical NIC per process (GX_ID), regardless of QP count. */
    while (checkpoint_waiting || (l->out->base.header.own_type & SIMBRICKS_PROTO_MSG_OWN_CON)) {
        pump(l);
        if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
        gx_fiber_idle_yield();
    }
    if (bytes > UINT32_MAX - 128) { errno = EMSGSIZE; return -1; }
    struct frame *f = realloc(l->out, 64 + bytes + 128);
    if (!f) return -1;
    l->base.out_queue = l->out = f;
    l->written = 0; l->capacity = bytes + 128;
    uint64_t t = now();
    double modeled_ps = ceil((double)bytes * 1000 / bytes_per_ns);
    if (!isfinite(modeled_ps) || modeled_ps >= (double)(UINT64_MAX / 2))
        fail("NIC serialization duration overflow");
    uint64_t cost = (uint64_t)modeled_ps;
    uint64_t latest = service.wire_free > t ? service.wire_free : t;
    if (latest > UINT64_MAX - processing_ps - cost)
        fail("NIC service timestamp overflow");
    uint64_t end = nex_service_reserve(&service, t, processing_ps, cost);
    ++messages;
    if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
    api.busy();
    l->sending = true;
    l->send_time = end;
    /* Delivery is quantized upward, never early. Keep the serializer exact:
     * rounding stage availability would incorrectly consume capacity per message. */
    uint64_t publish = ((end + epoch_ps - 1) / epoch_ps) * epoch_ps;
    if (!SimbricksBaseIfOutAlloc(&l->base, publish)) fail("outgoing queue ownership");
    uint64_t payload = htobe64(bytes);
    memcpy(l->out->base.header.pad + 8, &payload, sizeof(payload));
    tx_total += bytes;
    return 0;
}
void gx_nic_end(struct gx_nic_link *l) {
    set_length(&l->out->base, l->written);
    SimbricksBaseIfOutSend(&l->base, &l->out->base, DATA);
    l->sending = false;
    pump(l);
}
uint64_t gx_nic_completion_time(struct gx_nic_link *l, bool acknowledged) {
    uint64_t end = l->send_time;
    if (acknowledged) {
        if (end > UINT64_MAX - epoch_ps - 2 * latency_ps)
            fail("NIC acknowledgement timestamp overflow");
        end = nex_service_ack(end, epoch_ps, latency_ps);
    }
    if (end > UINT64_MAX - 999) fail("NIC completion rounding overflow");
    return (end + 999) / 1000;
}
void gx_nic_wait_until(struct gx_nic_link *l, uint64_t time_ns) {
    while (!atomic_load(&l->closed) && (checkpoint_waiting || api.time() < time_ns))
        gx_fiber_idle_yield();
    api.busy();
}
ssize_t gx_nic_write(struct gx_nic_link *l, const void *src, size_t len) {
    if (!l->sending || len > l->capacity - l->written) fail("message framing");
    memcpy(l->out->data + l->written, src, len);
    l->written += len;
    return len;
}
ssize_t gx_nic_read(struct gx_nic_link *l, void *dst, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        uint64_t t = now();
        sync_link(l, t);
        if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
        if (checkpoint_waiting) { gx_fiber_idle_yield(); continue; }
        volatile union SimbricksProtoBaseMsg *m = SimbricksBaseIfInPeek(&l->base, t);
        if (!m) {
            if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
            gx_fiber_idle_yield(); continue;
        }
        if (SimbricksBaseIfInType(&l->base, m) != DATA) fail("unexpected message");
        size_t n = length(l->in) - l->read_offset;
        if (n > len - pos) n = len - pos;
        if (!n) fail("empty data frame");
        memcpy((char *)dst + pos, l->in->data + l->read_offset, n);
        pos += n; l->read_offset += n;
        if (l->read_offset == length(l->in)) {
            rx_total += payload_size(l->in);
            SimbricksBaseIfInPoll(&l->base, now());
            done(l);
        }
        api.busy();
    }
    return len;
}
