/* Local NIC service model. The jailbroken worker is not an epoch member.
 * Its fibers enforce delivery/completion deadlines against the shared clock;
 * they never wait at its global epoch barrier. An idle acknowledgement keeps
 * the clock from outrunning the worker without stopping its fibers. */
#define _GNU_SOURCE
#include "nex_timing.h"
#include "nex_service.h"
#include "nex_shm.h"
#include "tools/gxvm/src/epoch/runtime.h"
#include <dlfcn.h>
#include <errno.h>
#include <math.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static struct nex_service service;
static uint64_t latency_ps, tx_bytes, rx_bytes, messages;
static double bytes_per_ns;
static const uint64_t processing_ps = 140000; /* Existing 140 ns service cost. */
static _Atomic unsigned initialized;
static uint64_t epoch_token, blocked_epoch;
static struct {
    int (*started)(void);
    void (*attach)(const gxvm_epoch_config_t *, const char *);
    uint64_t (*time)(void);
    uint64_t (*generation)(void);
    uint64_t (*reserve)(uint64_t, bool);
    int (*release)(uint64_t);
    void (*idle_hook)(void (*)(bool, void *), void *);
    void (*stop_hook)(void (*)(void *), void *);
} api;

static void fail(const char *message)
{
    fprintf(stderr, "GX_NIC FAIL %s\n", message);
    abort();
}

static uint64_t setting(const char *name, uint64_t fallback)
{
    const char *s = getenv(name);
    if (!s) return fallback;
    char *end;
    errno = 0;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno || end == s || *end || *s == '-' || !value || value > UINT64_MAX / 1000)
        fail(name);
    return value;
}

static bool active(void)
{
    return bytes_per_ns && (!api.started || api.started());
}

/* Worker-thread only. Install the next guard before releasing this one.
 * A blocker at G permits reaching G, but not advancing beyond it. */
static void acknowledge(bool has_fibers, void *unused)
{
    (void)unused;
    if (!has_fibers) {
        if (epoch_token) api.release(epoch_token);
        epoch_token = 0;
        return;
    }
    if (!active()) return;
    if (!epoch_token) {
        epoch_token = api.reserve(0, true);
        if (!epoch_token) fail("cannot guard NIC epoch");
        blocked_epoch = api.generation();
    }
    if (api.generation() < blocked_epoch) return;
    uint64_t next = api.reserve(blocked_epoch + 1, false);
    if (!next) fail("cannot guard next NIC epoch");
    uint64_t previous = epoch_token;
    epoch_token = next;
    ++blocked_epoch;
    if (!api.release(previous)) fail("cannot acknowledge NIC epoch");
}

static void stop(void *unused)
{
    (void)unused;
    acknowledge(false, NULL);
    if (api.idle_hook) api.idle_hook(NULL, NULL);
    fprintf(stderr, "GX_NIC bytes_tx=%llu bytes_rx=%llu epoch_member=0 messages=%llu\n",
            (unsigned long long)tx_bytes, (unsigned long long)rx_bytes,
            (unsigned long long)messages);
    service = (struct nex_service){0};
    tx_bytes = rx_bytes = messages = 0;
    bytes_per_ns = 0;
    atomic_store(&initialized, 0);
}

static void start(void *unused)
{
    (void)unused;
#define LOAD(field, symbol) do { *(void **)(&api.field) = dlsym(RTLD_DEFAULT, symbol); \
    if (!api.field) fail("missing " symbol); } while (0)
    LOAD(attach, "gxvm_epoch_runtime_attach");
    LOAD(time, "gxvm_epoch_time_ns");
    LOAD(generation, "gxvm_epoch_generation");
    LOAD(reserve, "gxvm_epoch_reserve");
    LOAD(release, "gxvm_epoch_release");
    LOAD(idle_hook, "gx_sched_set_idle_hook");
    LOAD(stop_hook, "gx_sched_set_stop_hook");
#undef LOAD
    *(void **)(&api.started) = dlsym(RTLD_DEFAULT, "gxvm_gpu_timing_started");
    const char *path = getenv("GXVM_EPOCH_PATH");
    if (!path || !*path) fail("NIC timing requires GXVM_EPOCH_PATH");
    gxvm_epoch_config_t config = {.epoch_ns = setting("GXVM_EPOCH_NS", 1000)};
    api.attach(&config, path);
    latency_ps = setting("GX_NIC_LATENCY_NS", config.epoch_ns) * 1000;
    api.stop_hook(stop, NULL);
    api.idle_hook(acknowledge, NULL);
    atomic_store_explicit(&initialized, 2, memory_order_release);
}

int gx_nic_prepare(void)
{
    const char *s = getenv("GX_NIC_BANDWIDTH_GBPS");
    if (!s || !*s) return 0;
    char *end;
    double bw = strtod(s, &end);
    if (end == s || *end || !isfinite(bw) || bw < 0) fail("GX_NIC_BANDWIDTH_GBPS");
    if (!bw) return 0;
    unsigned expected = 0;
    if (atomic_compare_exchange_strong(&initialized, &expected, 1)) {
        bytes_per_ns = bw;
        int rc = accvm_syms.gx_sched_new_fiber(start, NULL);
        if (rc) { atomic_store(&initialized, 0); bytes_per_ns = 0; return rc; }
    }
    while (atomic_load_explicit(&initialized, memory_order_acquire) != 2) sched_yield();
    return 0;
}

uint64_t gx_nic_submission_ns(void)
{
    return active() ? api.time() : UINT64_MAX;
}

void gx_nic_send(uint64_t submitted_ns, size_t bytes, int acknowledged,
                 uint64_t *delivery_ps, uint64_t *completion_ns)
{
    *delivery_ps = *completion_ns = 0;
    tx_bytes += bytes;
    if (submitted_ns == UINT64_MAX || !active()) return;
    if (submitted_ns > UINT64_MAX / 1000) fail("NIC submission timestamp overflow");
    uint64_t now = submitted_ns * 1000;
    double cost = ceil((double)bytes * 1000 / bytes_per_ns);
    uint64_t free = service.wire_free > now ? service.wire_free : now;
    if (!isfinite(cost) || cost >= (double)(UINT64_MAX / 2) ||
        latency_ps > (UINT64_MAX - processing_ps - 999) / 2)
        fail("NIC timestamp overflow");
    uint64_t overhead = processing_ps + 2 * latency_ps + 999;
    if ((uint64_t)cost > UINT64_MAX - overhead ||
        free > UINT64_MAX - overhead - (uint64_t)cost)
        fail("NIC timestamp overflow");
    uint64_t finish = nex_service_reserve(&service, now, processing_ps, (uint64_t)cost);
    *delivery_ps = finish + latency_ps;
    *completion_ns = ((acknowledged ? nex_service_ack(finish, latency_ps) : finish) + 999) / 1000;
    ++messages;
}

void gx_nic_wait(uint64_t deadline_ns)
{
    if (!deadline_ns) return;
    if (!active()) fail("timed peer requires an active local NIC model");
    while (api.time() < deadline_ns) gx_fiber_idle_yield();
}

void gx_nic_receive(uint64_t delivery_ps)
{
    /* Only unit conversion is rounded, never to an epoch boundary. */
    gx_nic_wait(delivery_ps / 1000 + (delivery_ps % 1000 != 0));
}

void gx_nic_received(size_t bytes) { rx_bytes += bytes; }
