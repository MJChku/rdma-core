/* Timestamped functional RDMA transport. Node synchronization belongs to GX's
 * epoch adapters, not QPs. Receivers gate data against their local epoch clock.
 * All links and the NIC serializer belong to the provider's ONE fiber pthread.
 */
#define _GNU_SOURCE
#include "nex_timing.h"
#include "nex_shm.h"
#include "nex_service.h"
#include "tools/gxvm/src/epoch/runtime.h"
#include "tools/gxvm/src/epoch/epoch_abi.h"
#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <math.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

struct frame {
    uint64_t timestamp, payload;
    uint32_t length;
    unsigned char reserved[44];
    unsigned char data[];
};
_Static_assert(sizeof(struct frame) == 64, "NIC wire header");
struct gx_nic_link {
    struct frame *in, *out;
    int socket;
    _Atomic int closed;
    size_t rx_bytes, tx_bytes, read_offset;
    size_t rx_capacity;
    struct iovec *tx_iov;
    size_t tx_count, tx_index, tx_capacity;
    uint64_t send_time;
    size_t written, capacity;
    bool sending, incoming, outgoing;
    bool rx_ready, tx_ready, watch_write;
    struct gx_nic_link *next;
};
static struct gx_nic_link *links;
static int readiness_fd = -1;
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
static bool notifications_registered;
static char epoch_notification, work_notification;
/* Cooperative idle pass: each idle fiber checks one link, not the whole NIC.
 * New model work invalidates the pass. Only the pthread closes its epoch. */
static struct gx_nic_link *idle_next;
static uint64_t idle_time;
static bool idle_safe;
static uint64_t idle_calls, idle_passes, idle_link_checks;
static uint64_t recv_calls, recv_empty;
static _Atomic unsigned started;
static bool initialized;
static struct {
    int (*started)(void);
    void (*attach)(const gxvm_epoch_config_t *, const char *);
    struct gxvm_epoch_page *(*page)(void);
    uint64_t (*time)(void);
    void (*join)(gxvm_epoch_native_member_t *);
    void (*leave)(gxvm_epoch_native_member_t *);
    void (*checkpoint)(gxvm_epoch_native_member_t *, void (*)(void *), void *);
    void (*hook)(void (*)(void *), void (*)(bool, void *), void (*)(void *), void *);
    void (*busy)(void);
    void (*recheck_idle)(void);
    int (*epoch_fd)(void);
    int (*work_fd)(void);
    int (*can_wait)(void);
    void (*publish)(void);
} api;

/* GX publishes this at gxvm_start, not when the shared page is created.
 * Standalone native model tests have no deferred application start marker. */
static bool timing_active(void) {
    if (api.started && !api.started()) return false;
    if (!member.active) {
        api.join(&member);
        idle_next = NULL;
    }
    return true;
}

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
    return be32toh(f->length);
}
static uint64_t payload_size(struct frame *f) {
    return be64toh(f->payload);
}
static bool retry(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }

/* One nonblocking readiness set for the NIC, not one syscall per idle QP.
 * Write readiness is subscribed only while a frame is still being sent. */
static void watch(struct gx_nic_link *l, bool add) {
    if (readiness_fd < 0) {
        readiness_fd = epoll_create1(EPOLL_CLOEXEC);
        if (readiness_fd < 0) fail("NIC readiness creation");
    }
    struct epoll_event event = {
        /* Keep readiness until EAGAIN. A buffered future frame must not make
         * every epoch-wait poll report the same unread second frame again. */
        .events = EPOLLET | EPOLLIN | EPOLLRDHUP | (l->outgoing ? EPOLLOUT : 0),
        .data.ptr = l,
    };
    if (epoll_ctl(readiness_fd, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
                  l->socket, &event)) {
        /* The application can close a drained QP on another pthread. */
        if (atomic_load(&l->closed)) return;
        fail("NIC readiness registration");
    }
    l->watch_write = l->outgoing;
    if (add) l->rx_ready = l->tx_ready = true;
}

/* One buffered frame per QP. A partial frame is never visible to the model. */
static void pump(struct gx_nic_link *l) {
    int closed = atomic_load(&l->closed);
    if (closed) {
        /* close() follows QP worker drain. Retire its large buffers on their
         * owning pthread; a concurrent main-thread close never frees memory
         * underneath a transport pump. Keep only the small list node. */
        if (closed == 2) {
            free(l->in); free(l->out); free(l->tx_iov);
            l->in = l->out = NULL; l->tx_iov = NULL;
            atomic_store(&l->closed, 3);
        }
        return;
    }
    while (l->outgoing && l->tx_ready) {
        size_t total = 64 + (size_t)length(l->out);
        size_t count = l->tx_count - l->tx_index;
        /* Bound each syscall below IOV_MAX, including multi-SGE requests. */
        struct msghdr msg = {.msg_iov = l->tx_iov + l->tx_index,
                            .msg_iovlen = count < 64 ? count : 64};
        ssize_t n = sendmsg(l->socket, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
            l->tx_bytes += n;
            size_t consumed = (size_t)n;
            while (consumed) {
                struct iovec *iov = &l->tx_iov[l->tx_index];
                size_t part = consumed < iov->iov_len ? consumed : iov->iov_len;
                iov->iov_base = (char *)iov->iov_base + part;
                iov->iov_len -= part;
                consumed -= part;
                if (!iov->iov_len) ++l->tx_index;
            }
            if (l->tx_bytes == total) {
                l->tx_bytes = 0;
                l->outgoing = false;
            }
        } else if (n == 0 || !retry()) { atomic_store(&l->closed, 1); return; }
        else if (errno != EINTR) l->tx_ready = false;
    }
    if (l->outgoing != l->watch_write) watch(l, false);
    if (l->incoming || !l->rx_ready) return;
    /* Header and body belong to one message, not two fiber/epoch turns.
     * Drain this frame until complete or the host socket is actually empty. */
    for (;;) {
        size_t target = l->rx_bytes < 64 ? 64 : 64 + (size_t)length(l->in);
        if (l->rx_bytes == target && l->rx_bytes >= 64) break;
        ++recv_calls;
        ssize_t n = recv(l->socket, (char *)l->in + l->rx_bytes,
                         target - l->rx_bytes, MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            ++recv_empty;
            l->rx_ready = false;
        }
        if (n > 0) {
            l->rx_bytes += n;
            if (target == 64 && l->rx_bytes == 64) {
                /* Grow for actual messages only. Shrinking on a control
                 * message would unmap the payload pages and fault them back
                 * in on every following bulk transfer on this same QP. */
                size_t needed = 64 + (size_t)length(l->in);
                if (needed > l->rx_capacity) {
                    struct frame *f = realloc(l->in, needed);
                    if (!f) fail("incoming message allocation");
                    l->in = f;
                    l->rx_capacity = needed;
                }
            }
        }
        else if (n == 0 || !retry()) { atomic_store(&l->closed, 1); return; }
        if (n < 0) {
            if (errno == EINTR) continue;
            return;
        }
    }
    if (l->rx_bytes >= 64 && l->rx_bytes == 64 + (size_t)length(l->in))
        l->incoming = true;
}
static void poll_transport_wait(int timeout) {
    if (readiness_fd < 0) return;
    struct epoll_event events[64];
    int n = epoll_wait(readiness_fd, events, 64, timeout);
    if (n < 0 && errno != EINTR) fail("NIC readiness poll");
    for (int i = 0; i < n; ++i) {
        /* Notifications are wake hints. Epoch broadcast is never drained;
         * work notification is drained by the scheduler's can_wait check. */
        if (events[i].data.ptr == &epoch_notification ||
            events[i].data.ptr == &work_notification) continue;
        struct gx_nic_link *l = events[i].data.ptr;
        uint32_t flags = events[i].events;
        if (flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) l->rx_ready = true;
        if (flags & (EPOLLOUT | EPOLLHUP | EPOLLERR)) l->tx_ready = true;
        pump(l);
    }
}
static void poll_transport(void) { poll_transport_wait(0); }
static bool register_notifications(void) {
    if (notifications_registered) return true;
    int epoch_fd = api.epoch_fd();
    /* Standalone domains without a blocking observer retain cooperative
     * polling. Production GX domains already have an observer FD broker. */
    if (epoch_fd < 0 || readiness_fd < 0) return false;
    struct epoll_event event = {.events = EPOLLIN | EPOLLET,
                               .data.ptr = &epoch_notification};
    if (epoll_ctl(readiness_fd, EPOLL_CTL_ADD, epoch_fd, &event)) fail("epoch notification");
    event.data.ptr = &work_notification;
    if (epoll_ctl(readiness_fd, EPOLL_CTL_ADD, api.work_fd(), &event)) fail("work notification");
    notifications_registered = true;
    return true;
}
static void done(struct gx_nic_link *l) {
    l->incoming = false;
    l->rx_bytes = l->read_offset = 0;
}
static bool ready(const struct gx_nic_link *l, uint64_t t) {
    return l->incoming && be64toh(l->in->timestamp) <= t;
}
static void drain(void *unused) {
    (void)unused;
    /* Connection setup is functional transport work too. Let those fibers
     * progress while arrived. read/begin/completion below gate model effects
     * until this checkpoint returns; nested idle hooks cannot arrive twice. */
    gx_fiber_yield();
    /* No application memory writes/CQ completions while arrived. Drain the
     * current notification before checking time to avoid a lost epoch wake.
     * Incoming socket bytes and remote work both wake a blocked NIC. */
    poll_transport();
    if (register_notifications() && api.can_wait()) {
        /* A consumed notification may mean the last CPU blocked, not that
         * another publisher already advanced. Recheck before sleeping. */
        api.publish();
        if (now() == idle_time) poll_transport_wait(-1);
    }
}
static void idle(void *unused) {
    (void)unused;
    if (checkpoint_waiting) return;
    bool timed = timing_active();
    ++idle_calls;
    uint64_t t = timed ? now() : UINT64_MAX;
    if (!idle_next || idle_time != t) {
        poll_transport();
        idle_next = links;
        idle_time = t;
        idle_safe = true;
    }
    if (idle_next) {
        struct gx_nic_link *l = idle_next;
        idle_next = l->next;
        ++idle_link_checks;
        pump(l);
        /* Drain executable work before completing the NIC pthread's epoch.
         * An empty QP does NOT wait for a separate peer clock promise. */
        if (!atomic_load(&l->closed) && (l->sending ||
            (l->outgoing && (!timed || be64toh(l->out->timestamp) < t + epoch_ps)) ||
            /* A known-due frame whose body is still in host transport is
             * not future model work. Do not advance past its delivery. */
            (l->rx_bytes >= 64 && be64toh(l->in->timestamp) <= t)))
            idle_safe = false;
    }
    if (idle_next) return;
    ++idle_passes;
    /* A disconnected peer has no remaining deliveries to constrain time.
     * Still finish this member's epoch: the CPU may need that transition to
     * reach destroy_qp and stop our otherwise-idle TX fibers. */
    if (timed && idle_safe) {
        checkpoint_waiting = true;
        api.checkpoint(&member, drain, NULL);
        checkpoint_waiting = false;
        api.recheck_idle();
        ++epochs;
    }
    else sched_yield();
}
static void active(bool running, void *unused) {
    (void)unused;
    idle_next = NULL;
    /* An open context without worker fibers must not hold the global epoch.
     * Rejoin on dispatch, before any new model work executes. */
    if (running) (void)timing_active();
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
    fprintf(stderr, "GX_NIC_POLL idle_calls=%llu passes=%llu link_checks=%llu\n",
            (unsigned long long)idle_calls, (unsigned long long)idle_passes,
            (unsigned long long)idle_link_checks);
    fprintf(stderr, "GX_NIC_TRANSPORT sync_tx=0 sync_rx=0 recv_calls=%llu recv_empty=%llu\n",
            (unsigned long long)recv_calls, (unsigned long long)recv_empty);
    if (readiness_fd >= 0) close(readiness_fd);
    readiness_fd = -1;
    notifications_registered = false;
    while (links) { struct gx_nic_link *p = links; links = p->next;
        free(p->in); free(p->out); free(p->tx_iov); free(p); }
    service = (struct nex_service){0};
    tx_total = rx_total = epochs = messages = 0;
    idle_next = NULL;
    idle_calls = idle_passes = idle_link_checks = 0;
    recv_calls = recv_empty = 0;
    /* A later context starts a new pthread/TID and needs a fresh observer
     * registration; native_leave alone intentionally retains a thread slot. */
    member = (gxvm_epoch_native_member_t){0};
    initialized = false;
    atomic_store(&started, 0);
}
static void start(void) {
    if (initialized) return;
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
    RESOLVE(recheck_idle, "gx_sched_recheck_idle");
    RESOLVE(epoch_fd, "gxvm_epoch_notification_fd");
    RESOLVE(work_fd, "gx_sched_notification_fd");
    RESOLVE(can_wait, "gx_sched_can_wait");
    RESOLVE(publish, "gxvm_epoch_pump");
#undef RESOLVE
    *(void **)(&api.started) = dlsym(RTLD_DEFAULT, "gxvm_gpu_timing_started");
    const char *path = getenv("GXVM_EPOCH_PATH");
    if (!path || !*path) fail("NIC timing requires GXVM_EPOCH_PATH");
    gxvm_epoch_config_t config = {.epoch_ns = ns_config("GXVM_EPOCH_NS", 1000)};
    api.attach(&config, path);
    epoch_ps = api.page()->epoch_ns * 1000;
    latency_ps = ns_config("GX_NIC_LATENCY_NS", epoch_ps / 1000) * 1000;
    if (latency_ps > (UINT64_MAX - epoch_ps) / 2)
        fail("NIC round-trip latency overflow");
    bytes_per_ns = strtod(getenv("GX_NIC_BANDWIDTH_GBPS"), NULL);
    initialized = true;
    (void)timing_active();
    api.hook(idle, active, stop, NULL);
    fprintf(stderr, "GX_NIC transport=timestamped-data sync=gx-epoch epoch_ns=%llu latency_ns=%llu bandwidth_GBps=%g\n",
            (unsigned long long)(epoch_ps / 1000),
            (unsigned long long)(latency_ps / 1000), bytes_per_ns);
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
    l->rx_capacity = 64;
    l->socket = socket;
    watch(l, true);
    l->next = links;
    links = l;
    idle_next = NULL;
    return l;
}
void gx_nic_shutdown(struct gx_nic_link *l) { if (l) atomic_store(&l->closed, 1); }
void gx_nic_close(struct gx_nic_link *l) { if (l) atomic_store(&l->closed, 2); }
int gx_nic_begin(struct gx_nic_link *l, size_t bytes) {
    /* All outgoing QPs on this NIC share a serializer. Provider currently
     * has one logical NIC per process (GX_ID), regardless of QP count. */
    while (checkpoint_waiting || l->outgoing) {
        pump(l);
        if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
        gx_fiber_idle_yield();
    }
    if (bytes > UINT32_MAX - 128) { errno = EMSGSIZE; return -1; }
    if (!l->tx_capacity) {
        l->tx_iov = malloc(8 * sizeof(*l->tx_iov));
        if (!l->tx_iov) return -1;
        l->tx_capacity = 8;
    }
    l->tx_iov[0] = (struct iovec){.iov_base = l->out, .iov_len = 64};
    l->tx_count = 1; l->tx_index = 0;
    l->written = 0; l->capacity = bytes + 128;
    bool timed = timing_active();
    uint64_t t = timed ? now() : 0;
    double modeled_ps = ceil((double)bytes * 1000 / bytes_per_ns);
    if (!isfinite(modeled_ps) || modeled_ps >= (double)(UINT64_MAX / 2))
        fail("NIC serialization duration overflow");
    uint64_t cost = (uint64_t)modeled_ps;
    uint64_t latest = service.wire_free > t ? service.wire_free : t;
    if (latest > UINT64_MAX - processing_ps - cost)
        fail("NIC service timestamp overflow");
    uint64_t end = timed ? nex_service_reserve(&service, t, processing_ps, cost) : 0;
    if (timed) ++messages;
    if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
    idle_next = NULL;
    api.busy();
    l->sending = true;
    l->send_time = end;
    /* Preserve sub-epoch timestamps; only the receiver clock gates delivery. */
    if (end > UINT64_MAX - latency_ps) fail("delivery timestamp overflow");
    memset(l->out, 0, sizeof(*l->out));
    l->out->timestamp = htobe64(timed ? end + latency_ps : 0);
    l->out->payload = htobe64(bytes);
    tx_total += bytes;
    return 0;
}
int gx_nic_end(struct gx_nic_link *l) {
    l->out->length = htobe32(l->written);
    l->outgoing = true;
    l->sending = false;
    /* The send task owns the header and all source SGEs until we return.
     * Do not publish a completion/free that task while sendmsg still refers
     * to it. Other fibers and transport pumping remain cooperative here. */
    do {
        pump(l);
        if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
        if (l->outgoing) gx_fiber_idle_yield();
    } while (l->outgoing);
    return 0;
}
uint64_t gx_nic_completion_time(struct gx_nic_link *l, bool acknowledged) {
    uint64_t end = l->send_time;
    if (!end) return 0; /* This message was issued before timing activation. */
    if (acknowledged) {
        if (end > UINT64_MAX - 2 * latency_ps)
            fail("NIC acknowledgement timestamp overflow");
        end = nex_service_ack(end, latency_ps);
    }
    if (end > UINT64_MAX - 999) fail("NIC completion rounding overflow");
    return (end + 999) / 1000;
}
void gx_nic_wait_until(struct gx_nic_link *l, uint64_t time_ns) {
    (void)timing_active();
    while (!atomic_load(&l->closed) && (checkpoint_waiting || api.time() < time_ns))
        gx_fiber_idle_yield();
    idle_next = NULL;
    api.busy();
}
ssize_t gx_nic_write(struct gx_nic_link *l, const void *src, size_t len) {
    if (!l->sending || len > l->capacity - l->written) fail("message framing");
    if (!len) return 0;
    if (l->tx_count == l->tx_capacity) {
        size_t capacity = l->tx_capacity * 2;
        struct iovec *iov = realloc(l->tx_iov, capacity * sizeof(*iov));
        if (!iov) return -1;
        l->tx_iov = iov; l->tx_capacity = capacity;
    }
    l->tx_iov[l->tx_count++] = (struct iovec){.iov_base = (void *)src, .iov_len = len};
    l->written += len;
    return len;
}
ssize_t gx_nic_read(struct gx_nic_link *l, void *dst, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        uint64_t t = timing_active() ? now() : UINT64_MAX;
        pump(l);
        if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
        if (checkpoint_waiting) { gx_fiber_idle_yield(); continue; }
        if (!ready(l, t)) {
            if (atomic_load(&l->closed)) { errno = EPIPE; return -1; }
            gx_fiber_idle_yield(); continue;
        }
        size_t n = length(l->in) - l->read_offset;
        if (n > len - pos) n = len - pos;
        if (!n) fail("empty data frame");
        memcpy((char *)dst + pos, l->in->data + l->read_offset, n);
        pos += n; l->read_offset += n;
        if (l->read_offset == length(l->in)) {
            rx_total += payload_size(l->in);
            done(l);
        }
        idle_next = NULL;
        api.busy();
    }
    return len;
}
