/*
 * NEX RDMA Provider - userspace RDMA semantics over a local software queue
 */

#include <config.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sched.h>
#include <infiniband/driver.h>
#include <infiniband/verbs.h>

#include "nex.h"
#include "nex_shm.h"
#include "nex_tcp.h"
#include "cm/nex_cm.h"

static int get_nex_id(void);
static bool nex_use_tcp_backend(void);

static bool nex_use_tcp_backend(void)
{
#ifdef USE_TCP
	return true;
#else
	static int initialized = 0;
	static bool use_tcp = false;

	if (!initialized) {
		const char *backend = getenv("GX_IO_BACKEND");
		if (backend && strcmp(backend, "tcp") == 0) {
			use_tcp = true;
		}
		initialized = 1;
	}

	return use_tcp;
#endif
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

#define NEX_INFO(fmt, ...) fprintf(stderr, "nex (%d, %lu us): " fmt "\n", get_nex_id(), now_ns() / 1000, ##__VA_ARGS__)

#define NEX_ERROR(fmt, ...) fprintf(stderr, "ERROR: nex (%d, %lu us): " fmt "\n", get_nex_id(), now_ns() / 1000, ##__VA_ARGS__)

static bool nex_trace_enabled(void)
{
	static int enabled = -1;
	if (enabled < 0) {
		const char *value = getenv("GX_RDMA_TRACE");
		enabled = value && *value && strcmp(value, "0") != 0;
	}
	return enabled;
}

#define NEX_TRACE(fmt, ...) do { \
	if (nex_trace_enabled()) \
		fprintf(stderr, "nex (%d, %lu ns): " fmt "\n", \
			get_nex_id(), now_ns(), ##__VA_ARGS__); \
} while (0)

#ifndef IBV_LINK_WIDTH_1X
#define IBV_LINK_WIDTH_1X 1
#endif
#ifndef IBV_LINK_SPEED_EDR
#define IBV_LINK_SPEED_EDR 8
#endif

/* Utility helpers ------------------------------------------------------- */

/*
 * Port selection: use ephemeral ports for per-process loopback self-connect.
 * This avoids inter-process collisions when multiple processes use nex0.
 */

#define NEX_DEFAULT_MAX_QP 1024

enum nex_msg_opcode {
	NEX_MSG_RDMA_WRITE = 0,
	NEX_MSG_RDMA_WRITE_IMM = 1,
	NEX_MSG_SEND = 2,
	NEX_MSG_SEND_WITH_IMM = 3,
	NEX_MSG_RDMA_READ_REQ = 4,
	// RESP is only in NEX
	NEX_MSG_RDMA_READ_RESP = 5,
	NEX_MSG_ATOMIC_FETCH_ADD_REQ = 6,
	NEX_MSG_ATOMIC_FETCH_ADD_RESP = 7,
};

enum nex_msg_status {
    NEX_MSG_STATUS_OK = 0,
    NEX_MSG_STATUS_REMOTE_ERROR = 1,
};

/*
 * Model a small request payload for RDMA READ requests so the request
 * itself incurs modeled network delay. The responder will read and wait
 * on this payload before generating the READ_RESP.
 */
#ifndef NEX_RDMA_READ_REQ_PLD
#define NEX_RDMA_READ_REQ_PLD 20
#endif
static const uint8_t nex_read_req_payload[NEX_RDMA_READ_REQ_PLD] = {0};

struct nex_msg_hdr {
	uint32_t opcode;
	uint32_t status;
	uint64_t wr_id;
	uint64_t remote_addr;
	uint32_t rkey;
	uint32_t length;
	uint32_t imm_data;
	uint32_t reserved;
	uint64_t atomic_operand;
};

struct nex_pending_msg {
	struct nex_msg_hdr hdr;
	uint8_t *payload;
	size_t payload_len;
	struct nex_pending_msg *next;
};

static int get_nex_id(void){
	static int initialized = 0;
	static int nex_id = 0;
	
	if(__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) return nex_id;
	//get env NEX_ID
	const char* env_p = getenv("GX_ID");
	if(env_p == NULL){
		return nex_id;
	}
	nex_id = atoi(env_p);
	
	__atomic_thread_fence(__ATOMIC_RELEASE);

	__atomic_store_n(&initialized, 1, __ATOMIC_RELEASE);

	return nex_id;
}

static pthread_mutex_t g_sched_ref_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_sched_refcount = 0;

static int gx_sched_acquire(void)
{
	int rc = 0;

	pthread_mutex_lock(&g_sched_ref_lock);
	if (g_sched_refcount == 0) {
		rc = accvm_syms.gx_sched_init((uint32_t)get_nex_id());
		if (rc != 0) {
			pthread_mutex_unlock(&g_sched_ref_lock);
			return rc;
		}
	}
	++g_sched_refcount;
	pthread_mutex_unlock(&g_sched_ref_lock);
	return 0;
}

static void gx_sched_release(void)
{
	pthread_mutex_lock(&g_sched_ref_lock);
	if (g_sched_refcount > 0) {
		--g_sched_refcount;
		if (g_sched_refcount == 0)
			accvm_syms.gx_sched_shutdown();
	}
	pthread_mutex_unlock(&g_sched_ref_lock);
}

static inline void fiber_pthread_spin_lock(pthread_spinlock_t *lock)
{
	for (;;) {
		int rc = pthread_spin_trylock(lock);
		if (rc == 0)
			return;
		assert(rc == EBUSY);
		gx_fiber_yield();
	}
}

static inline void fiber_pthread_spin_unlock(pthread_spinlock_t *lock)
{
	pthread_spin_unlock(lock);
}

static inline uint32_t nex_next_handle(struct nex_context *ctx)
{
	return atomic_fetch_add_explicit(&ctx->next_handle, 1, memory_order_relaxed);
}

static inline uint32_t nex_next_key(struct nex_context *ctx)
{
	uint32_t key = atomic_fetch_add_explicit(&ctx->next_key, 1, memory_order_relaxed);
	return 0x1000 + key;
}

static int fiber_write_full(int fd, const void *buf, size_t len, int apply_perf)
{

	ssize_t n = nex_use_tcp_backend()
		    ? nex_tcp_write(fd, buf, len, apply_perf)
		    : nex_shm_write(fd, buf, len, apply_perf);
	if (n != len) {
		NEX_TRACE("backend_write failed n=%zd len=%zu errno=%d", n, len, errno);
		return -1;
	}

	return 0;
}

static int fiber_write_fullv(int fd, const struct iovec *iov, int iovcnt,
	   size_t total_len, int apply_perf, bool wait_completion, int *slot_out,
	   uint32_t tag)
{
	if (!iov || iovcnt <= 0 || total_len == 0) {
		if (slot_out)
			*slot_out = -1;
		return 0;
	}

	ssize_t n = nex_use_tcp_backend()
		    ? nex_tcp_writev(fd, iov, iovcnt, apply_perf, wait_completion, slot_out, tag)
		    : nex_shm_writev(fd, iov, iovcnt, apply_perf, wait_completion, slot_out, tag);
	if (n < 0 || (size_t)n != total_len)
		return -1;
	return 0;
}

static int fiber_read_full(int fd, void *buf, size_t len, int apply_perf)
{
	ssize_t n = nex_use_tcp_backend()
		    ? nex_tcp_read(fd, buf, len, apply_perf)
		    : nex_shm_read(fd, buf, len, apply_perf);
	if (n != len) return -1;
	return 0;
}

static int fiber_read_fullv(int fd, const struct iovec *iov, int iovcnt,
						  size_t total_len, int apply_perf, bool wait_completion, int *slot_out,
						  uint32_t tag)
{
    if (!iov || iovcnt <= 0 || total_len == 0) {
        return 0;
    }
	// if wait, wait should happen inside nex_shm_readv
	ssize_t n = nex_use_tcp_backend()
		    ? nex_tcp_readv(fd, iov, iovcnt, apply_perf, wait_completion, slot_out, tag)
		    : nex_shm_readv(fd, iov, iovcnt, apply_perf, wait_completion, slot_out, tag);
	    if (n < 0 || (size_t)n != total_len)
	        return -1;
    return 0;
}

static int nex_map_qp_counter(struct nex_context *ctx)
{
	if (ctx->qp_counter)
		return 0;
	int nex_id = get_nex_id();
	char shm_name[128];
	snprintf(shm_name, sizeof(shm_name), "/nex_qpcnt_dev%d", nex_id);
	int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, sizeof(uint32_t)) != 0) {
		if (errno != EINVAL) {
			close(fd);
			return -1;
		}
	}
	uint32_t *ptr = mmap(NULL, sizeof(uint32_t), PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		close(fd);
		return -1;
	}
	ctx->qp_counter_fd = fd;
	ctx->qp_counter = ptr;
	return 0;
}

static void fiber_cq_push(struct nex_cq *cq, const struct ibv_wc *wc)
{
	NEX_TRACE("enter cq_push wr_id=%" PRIu64 " opcode=%u status=%u len=%u qp_local=%u",
	       (uint64_t)wc->wr_id, wc->opcode, wc->status, wc->byte_len,
	       wc->qp_num);
	fiber_pthread_spin_lock(&cq->lock);
	uint32_t next_tail = (cq->tail + 1) % cq->capacity;
	if (next_tail == cq->head) {
		/* Drop completion on overflow */
		fiber_pthread_spin_unlock(&cq->lock);
		NEX_TRACE("WARNING: cq overflow dropping completion wr_id=%" PRIu64,
			(uint64_t)wc->wr_id);
		return;
	}
	cq->entries[cq->tail] = *wc;
	cq->tail = next_tail;
       
	fiber_pthread_spin_unlock(&cq->lock);
	NEX_TRACE("cq_push wr_id=%" PRIu64 " opcode=%u status=%u len=%u qp_local=%u",
	       (uint64_t)wc->wr_id, wc->opcode, wc->status, wc->byte_len,
	       wc->qp_num);
}

static int nex_cq_pop(struct nex_cq *cq, int num_entries, struct ibv_wc *wc)
{
	int produced = 0;
	// enabling this will increase latency simulated
	// the rational is likely that cq_pop need to be fast
	if(cq->head == cq->tail) {
		return 0;
	}
	pthread_spin_lock(&cq->lock);
	while (produced < num_entries && cq->head != cq->tail) {
		wc[produced++] = cq->entries[cq->head];
		cq->head = (cq->head + 1) % cq->capacity;
	}
	pthread_spin_unlock(&cq->lock);
	if( produced == num_entries ) {
		//all done
		NEX_TRACE("nex_cq_pop produced=%d/%d", produced, num_entries);
	}
	return produced;
}

static void fiber_rx_worker(void *arg);
static void fiber_tx_send_worker(void *arg);
static int fiber_send_msg(struct nex_qp *qp, struct nex_msg_hdr *hdr,
			  const struct iovec *payload_iov,
			  int payload_iovcnt, size_t payload_len,
			  bool wait_completion,
			  int *out_slot);
static int nex_txq_send_msg(struct nex_qp *qp, struct nex_msg_hdr *hdr,
			    struct iovec *payload_iov,
			    int payload_iovcnt, size_t payload_len,
			    bool wait_completion,
			    uint64_t tx_wr_id);
static void nex_sendq_push(struct nex_qp *qp, struct nex_send_task *task);
static bool fiber_sendq_try_pop(struct nex_qp *qp, struct nex_send_task **out);
static void fiber_txq_push(struct nex_qp *qp, const struct nex_tx_wait_entry *entry);
static bool fiber_txq_try_pop(struct nex_qp *qp, struct nex_tx_wait_entry *out);

static struct nex_mr *fiber_find_mr(struct nex_context *ctx, uint32_t rkey);
static int nex_add_pending_read(struct nex_qp *qp, uint64_t wr_id,
		      const struct ibv_sge *sg_list, int num_sge,
		      size_t total_len, bool completion_requested,
		      enum ibv_wc_opcode wc_opcode);
static struct nex_pending_read *nex_take_pending_read(struct nex_qp *qp,
					       uint64_t wr_id);
static struct ibv_mr *nex_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
			       uint64_t length, uint64_t iova, int fd, int access);
static int fiber_qp_establish_sync(struct nex_qp *qp);
static int nex_qp_start_connect(struct nex_qp *qp);
static int nex_qp_wait_connected(struct nex_qp *qp);
static int nex_qp_reserve(struct nex_qp *qp);
static void nex_qp_release(struct nex_qp *qp);

static bool nex_qp_has_peer_addr(const struct nex_qp *qp)
{
	return qp->remote_qp_num != 0 && qp->remote_lid != 0;
}

static bool fiber_try_take_recv(struct nex_qp *qp, struct nex_recv_entry *out)
{
    bool ok = false;
    if (qp->srq) {
        /* QP is attached to a shared receive queue: consume from it. */
        struct nex_srq *srq = qp->srq;
        fiber_pthread_spin_lock(&srq->lock);
        if (srq->recv_head != srq->recv_tail) {
            struct nex_recv_entry *entry = &srq->recv_queue[srq->recv_head];
            srq->recv_head = (srq->recv_head + 1) % srq->recv_size;
            *out = *entry;
            ok = true;
        }
        fiber_pthread_spin_unlock(&srq->lock);
        return ok;
    }
    fiber_pthread_spin_lock(&qp->lock);
    if (qp->recv_head != qp->recv_tail) {
        struct nex_recv_entry *entry = &qp->recv_queue[qp->recv_head];
        qp->recv_head = (qp->recv_head + 1) % qp->recv_size;
        *out = *entry;
        ok = true;
    }
    fiber_pthread_spin_unlock(&qp->lock);
    return ok;
}


static void fiber_push_pending_msg(struct nex_qp *qp, const struct nex_msg_hdr *hdr,
					uint8_t *payload, size_t payload_len) {
	struct nex_pending_msg *msg = malloc(sizeof(*msg));
	if (!msg) {
		free(payload);
		return;
	}
	msg->hdr = *hdr;
	msg->payload = payload;
	msg->payload_len = payload_len;
	msg->next = NULL;
	if (qp->pending_tail)
		qp->pending_tail->next = msg;
	else
		qp->pending_head = msg;
	qp->pending_tail = msg;
}

static struct nex_pending_msg *fiber_pop_pending_msg(struct nex_qp *qp) {
	struct nex_pending_msg *msg = NULL;
	if (qp->pending_head) {
		msg = qp->pending_head;
		qp->pending_head = msg->next;
		if (qp->pending_head == NULL)
			qp->pending_tail = NULL;
	}
	return msg;
}

struct nex_send_task {
	struct nex_qp *qp;
	struct nex_msg_hdr hdr;
	struct iovec *payload_iov;
	int payload_iovcnt;
	size_t payload_len;
	bool wait_completion;
	uint64_t tx_wr_id;
};

struct nex_tx_wait_entry {
	uint64_t wr_id;
	enum ibv_wc_opcode wc_op;
	uint32_t byte_len;
	int slot;
	bool wait_completion;
};

static struct nex_mr *fiber_find_mr(struct nex_context *ctx, uint32_t rkey)
{
	struct nex_mr *mr = NULL;
	fiber_pthread_spin_lock(&ctx->mr_lock);
	int count_match = 0;
	for (struct nex_mr *iter = ctx->mr_list; iter; iter = iter->next) {
		if (iter->vmr.ibv_mr.rkey == rkey) {
			if(count_match == 0){
				mr = iter;
			}
			count_match++;
			break;
		}
	}
	fiber_pthread_spin_unlock(&ctx->mr_lock);

	if(count_match > 1){
		NEX_ERROR("rkey=%u matched %d MRs, returning first match", rkey, count_match);
	}
	return mr;
}

static int nex_add_pending_read(struct nex_qp *qp, uint64_t wr_id,
              const struct ibv_sge *sg_list, int num_sge,
              size_t total_len, bool completion_requested,
              enum ibv_wc_opcode wc_opcode)
{
    struct nex_pending_read *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        errno = ENOMEM;
        return ENOMEM;
    }
    entry->wr_id = wr_id;
    entry->num_sge = num_sge;
    entry->total_len = total_len;
    entry->completion_requested = completion_requested;
	entry->wc_opcode = wc_opcode;
    entry->next = NULL;
    for (int i = 0; i < num_sge; ++i)
        entry->sge[i] = sg_list[i];
    fiber_pthread_spin_lock(&qp->rdma_lock);
    /* Add to tail for FIFO ordering */
    if (!qp->pending_reads) {
        qp->pending_reads = entry;
    } else {
        struct nex_pending_read *tail = qp->pending_reads;
        while (tail->next)
            tail = tail->next;
        tail->next = entry;
    }
    fiber_pthread_spin_unlock(&qp->rdma_lock);
    return 0;
}

static struct nex_pending_read *nex_take_pending_read(struct nex_qp *qp, uint64_t wr_id)
{
	struct nex_pending_read *entry = NULL;
	fiber_pthread_spin_lock(&qp->rdma_lock);
	struct nex_pending_read **prev = &qp->pending_reads;
	while (*prev && (*prev)->wr_id != wr_id)
		prev = &(*prev)->next;
	if (*prev) {
		entry = *prev;
		*prev = entry->next;
	}
	fiber_pthread_spin_unlock(&qp->rdma_lock);
	return entry;
}

static int fiber_send_msg(struct nex_qp *qp, struct nex_msg_hdr *hdr,
			  const struct iovec *payload_iov,
			  int payload_iovcnt, size_t payload_len,
			  bool wait_completion,
			  int *out_slot)
{
	int rc = 0;
	fiber_pthread_spin_lock(&qp->tx_wire_lock);
	uint32_t tag = qp->next_tag;
	qp->next_tag = (qp->next_tag % 0xFFFFu) + 1u;
	// Use reserved header field to pass a unique tag to the network backend.
	hdr->reserved = tag;
	if (fiber_write_full(qp->tx_fd, hdr, sizeof(*hdr), 0))  // header: no perf model
		rc = errno ? errno : EIO;
	NEX_TRACE("nex_send_msg sent hdr");
	if (!rc && payload_len && payload_iovcnt > 0 && payload_iov) {
		if (fiber_write_fullv(qp->tx_fd, payload_iov, payload_iovcnt,
				    payload_len, 1, wait_completion, out_slot, tag))  // payload: apply perf model (non-blocking)
			rc = errno ? errno : EIO;
	} else if (out_slot) {
		*out_slot = -1;
	}
	NEX_TRACE("nex_send_msg sent payload");
	fiber_pthread_spin_unlock(&qp->tx_wire_lock);
	return rc;
}

static void nex_sendq_push(struct nex_qp *qp, struct nex_send_task *task)
{
	for (;;) {
		pthread_spin_lock(&qp->send_task_lock);
		uint32_t next = (qp->send_task_tail + 1) % qp->send_task_qsize;
		if (next != qp->send_task_head) {
			qp->send_task_queue[qp->send_task_tail] = task;
			qp->send_task_tail = next;
			pthread_spin_unlock(&qp->send_task_lock);
			return;
		}
		pthread_spin_unlock(&qp->send_task_lock);
		sched_yield();
	}
}

static bool fiber_sendq_try_pop(struct nex_qp *qp, struct nex_send_task **out)
{
	fiber_pthread_spin_lock(&qp->send_task_lock);
	if (qp->send_task_head == qp->send_task_tail) {
		fiber_pthread_spin_unlock(&qp->send_task_lock);
		return false;
	}
	*out = qp->send_task_queue[qp->send_task_head];
	qp->send_task_head = (qp->send_task_head + 1) % qp->send_task_qsize;
	fiber_pthread_spin_unlock(&qp->send_task_lock);
	return true;
}

static void fiber_txq_push(struct nex_qp *qp, const struct nex_tx_wait_entry *entry)
{
	for (;;) {
		uint32_t next = (qp->tx_wait_tail + 1) % qp->tx_wait_qsize;
		if (next != qp->tx_wait_head) {
			qp->tx_wait_queue[qp->tx_wait_tail] = *entry;
			qp->tx_wait_tail = next;
			return;
		}
		gx_fiber_idle_yield();
	}
}

static bool fiber_txq_try_pop(struct nex_qp *qp, struct nex_tx_wait_entry *out)
{
	if (qp->tx_wait_head == qp->tx_wait_tail) {
		return false;
	}
	*out = qp->tx_wait_queue[qp->tx_wait_head];
	qp->tx_wait_head = (qp->tx_wait_head + 1) % qp->tx_wait_qsize;
	return true;
}

static int nex_txq_send_msg(struct nex_qp *qp, struct nex_msg_hdr *hdr,
			    struct iovec *payload_iov,
			    int payload_iovcnt, size_t payload_len,
			    bool wait_completion,
			    uint64_t tx_wr_id)
{
	struct nex_send_task *task = calloc(1, sizeof(*task));
	if (!task) {
		free(payload_iov);
		return ENOMEM;
	}

	*task = (struct nex_send_task){
		.qp = qp,
		.hdr = *hdr,
		.payload_iov = payload_iov,
		.payload_iovcnt = payload_iovcnt,
		.payload_len = payload_len,
		.wait_completion = wait_completion,
		.tx_wr_id = tx_wr_id,
	};

	if (payload_iovcnt > 0 && !payload_iov) {
		free(task);
		return EINVAL;
	}

	nex_sendq_push(qp, task);
	return 0;
}

static void fiber_tx_send_worker(void *arg)
{
	struct nex_qp *qp = arg;

	uint64_t last_consume_time = now_ns();
	int consume_count = 0;
	float rate = 0;
	for (;;) {
		struct nex_send_task *task = NULL;
		if (fiber_sendq_try_pop(qp, &task)) {
			// apply rate limiting:
			// 5 per us, 20 per 4 us, 40, per 8us.
			// consume_count++;
			// if(consume_count % 20 == 0){
			// 	uint64_t now;
			// 	do{
			// 		now = now_ns();
			// 		rate = 20.0 / (now - last_consume_time);
			// 		if(rate > 0.005){
			// 			gx_fiber_idle_yield();
			// 		}else{
			// 			break;
			// 		}
			// 	} while(1);
			// 	last_consume_time = now;
			// 	consume_count = 0;
			// }

			int tx_slot = -1;
			int rc = fiber_send_msg(task->qp, &task->hdr,
						task->payload_iov, task->payload_iovcnt,
						task->payload_len, task->wait_completion,
						&tx_slot);
			bool response_owned_req =
				task->hdr.opcode == NEX_MSG_RDMA_READ_REQ ||
				task->hdr.opcode == NEX_MSG_ATOMIC_FETCH_ADD_REQ;
			if (rc) {
				/* Peer died mid-send: surface an error completion so the
				 * consumer (e.g. NCCL's proxy) sees ncclRemoteError and can
				 * abort, instead of crashing or hanging the process. */
				if (response_owned_req) {
					struct nex_pending_read *pending =
						nex_take_pending_read(qp, task->tx_wr_id);
					if (pending) {
						struct ibv_wc err_wc = {
							.wr_id = task->tx_wr_id,
							.status = IBV_WC_RETRY_EXC_ERR,
							.opcode = pending->wc_opcode,
							.qp_num = qp->vqp.qp.qp_num,
						};
						fiber_cq_push(qp->send_cq, &err_wc);
						free(pending);
					}
				} else {
					struct ibv_wc err_wc = {
						.wr_id = task->tx_wr_id,
						.status = IBV_WC_RETRY_EXC_ERR,
						.opcode =
							(task->hdr.opcode == NEX_MSG_RDMA_WRITE ||
							 task->hdr.opcode == NEX_MSG_RDMA_WRITE_IMM)
								? IBV_WC_RDMA_WRITE
								: IBV_WC_SEND,
						.qp_num = qp->vqp.qp.qp_num,
					};
					if (task->wait_completion)
						fiber_cq_push(qp->send_cq, &err_wc);
				}
			} else if (!response_owned_req) {
				struct nex_tx_wait_entry entry = {
					.wr_id = task->tx_wr_id,
					.wc_op = (task->hdr.opcode == NEX_MSG_RDMA_WRITE ||
						  task->hdr.opcode == NEX_MSG_RDMA_WRITE_IMM)
						 ? IBV_WC_RDMA_WRITE
						 : IBV_WC_SEND,
					.byte_len = (uint32_t)task->payload_len,
					.slot = tx_slot,
					.wait_completion = task->wait_completion,
				};
				fiber_txq_push(qp, &entry);
			}
			free(task->payload_iov);
			free(task);
			gx_fiber_yield();
			continue;
		}

		bool running = atomic_load_explicit(&qp->tx_running, memory_order_acquire);
		if (!running)
			break;
		gx_fiber_idle_yield();
	}

	pthread_mutex_lock(&qp->state_lock);
	qp->tx_sender_done = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
}

static void fiber_tx_worker(void *arg)
{
	struct nex_qp *qp = arg;

	for (;;) {
		struct nex_tx_wait_entry entry;
		if (fiber_txq_try_pop(qp, &entry)) {
			struct ibv_wc wc = {
				.wr_id = entry.wr_id,
				.status = IBV_WC_SUCCESS,
				.opcode = entry.wc_op,
				.byte_len = entry.byte_len,
				.qp_num = qp->vqp.qp.qp_num,
			};
			if (entry.wait_completion)
				fiber_cq_push(qp->send_cq, &wc);
			NEX_TRACE("nex_tx_worker completed wr_id=%" PRIu64 " opcode=%u len=%u",
				(uint64_t)wc.wr_id, wc.opcode, wc.byte_len);
			gx_fiber_yield();
			continue;
		}

		bool running = atomic_load_explicit(&qp->tx_running, memory_order_acquire);
		if (!running) {
			pthread_mutex_lock(&qp->state_lock);
			bool sender_done = qp->tx_sender_done;
			pthread_mutex_unlock(&qp->state_lock);
			if (sender_done)
				break;
		}
		gx_fiber_idle_yield();
	}

	pthread_mutex_lock(&qp->state_lock);
	qp->tx_worker_done = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
}

static int fiber_start_qp_workers(struct nex_qp *qp)
{
	int rc;

	pthread_mutex_lock(&qp->state_lock);
	if (qp->destroying) {
		qp->rx_worker_done = true;
		qp->tx_sender_done = true;
		qp->tx_worker_done = true;
		pthread_cond_broadcast(&qp->state_cond);
		pthread_mutex_unlock(&qp->state_lock);
		return ECANCELED;
	}
	qp->rx_worker_done = false;
	qp->tx_sender_done = false;
	qp->tx_worker_done = false;
	pthread_mutex_unlock(&qp->state_lock);

	atomic_store_explicit(&qp->tx_running, true, memory_order_release);

	rc = accvm_syms.gx_sched_new_fiber(fiber_rx_worker, qp);
	if (rc != 0)
		goto spawn_rx_fail;

	rc = accvm_syms.gx_sched_new_fiber(fiber_tx_worker, qp);
	if (rc != 0)
		goto spawn_tx_wait_fail;

	rc = accvm_syms.gx_sched_new_fiber(fiber_tx_send_worker, qp);
	if (rc != 0)
		goto spawn_tx_send_fail;

	return 0;

spawn_tx_send_fail:
	fiber_pthread_spin_lock(&qp->lock);
	qp->rx_running = false;
	fiber_pthread_spin_unlock(&qp->lock);
	atomic_store_explicit(&qp->tx_running, false, memory_order_release);
	pthread_mutex_lock(&qp->state_lock);
	qp->tx_sender_done = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
	return rc < 0 ? -rc : rc;

spawn_tx_wait_fail:
	fiber_pthread_spin_lock(&qp->lock);
	qp->rx_running = false;
	fiber_pthread_spin_unlock(&qp->lock);
	atomic_store_explicit(&qp->tx_running, false, memory_order_release);
	pthread_mutex_lock(&qp->state_lock);
	qp->tx_sender_done = true;
	qp->tx_worker_done = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
	return rc < 0 ? -rc : rc;

spawn_rx_fail:
	atomic_store_explicit(&qp->tx_running, false, memory_order_release);
	pthread_mutex_lock(&qp->state_lock);
	qp->rx_worker_done = true;
	qp->tx_sender_done = true;
	qp->tx_worker_done = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
	return rc < 0 ? -rc : rc;
}

/* Device and port queries ---------------------------------------------- */
static int nex_query_device(struct ibv_context *context,
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size)
{
	memset(attr, 0, attr_size);

	// doesn't care
	attr->orig_attr.device_cap_flags = 
		IBV_DEVICE_MEM_WINDOW |
		IBV_ACCESS_REMOTE_READ |
		IBV_ACCESS_REMOTE_WRITE;
	attr->orig_attr.max_qp = 1024;
	attr->orig_attr.max_cq = 1024;
	attr->orig_attr.max_qp_wr = 1024;
	attr->orig_attr.max_cqe = 1024;
	attr->orig_attr.max_mr = 1024;
	attr->orig_attr.max_mr_size = UINT64_MAX;
	attr->orig_attr.max_sge = NEX_MAX_SGE;
	attr->orig_attr.max_sge_rd = NEX_MAX_SGE;
	attr->orig_attr.max_pd = 1024;
	attr->orig_attr.max_qp_rd_atom = 1;
	attr->orig_attr.max_res_rd_atom = 1;
	attr->orig_attr.max_qp_init_rd_atom = 1;
	attr->orig_attr.atomic_cap = IBV_ATOMIC_HCA;
	attr->orig_attr.max_srq = 1024;
	attr->orig_attr.max_srq_wr = 65536;
	attr->orig_attr.max_srq_sge = 1;
	attr->orig_attr.phys_port_cnt = 1;

	return 0;
}


static int nex_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	if (port != 1)
		return EINVAL;

	struct nex_context *ctx = to_nctx(context);

	memset(attr, 0, sizeof(*attr));
	attr->state = IBV_PORT_ACTIVE;
	// MTU (Maximum Transmission Unit): 
	// the largest payload size that can be placed in one link-layer packet
	attr->max_mtu = IBV_MTU_4096;
	attr->active_mtu = IBV_MTU_1024;
	// a 16-bit address used within an InfiniBand subnet to route packets to a port
	attr->lid = ctx->lid;
	// the LID of the Subnet Manager that configured this port.
	attr->sm_lid = 0;
	// lets a port expose multiple logical identifiers (LIDs) for the same physical port
	attr->lmc = 0;
	attr->port_cap_flags = IBV_PORT_CM_SUP;
	attr->gid_tbl_len = 1;
	attr->pkey_tbl_len = 1;
	attr->link_layer = IBV_LINK_LAYER_INFINIBAND;
	attr->active_width = IBV_LINK_WIDTH_1X;
	attr->active_speed = IBV_LINK_SPEED_EDR;
	return 0;
}

/* 
PD / MR --------------------------------------------------------------- 
Protection Domain and Memory Region management
PD (Protection Domain): a logical container that defines which queue pairs (QPs) 
can access which memory regions (MRs).

MR (Memory Region): a registered buffer in host memory. 
Registering it pins the pages and gives lkey/rkey so one can post SEND/RECV or RDMA ops. 
lkey (local key): returned when you register a memory region. 
rkey (remote key): you give it to a remote peer when you want them to access your buffer with RDMA READ/WRITE
*/

static struct ibv_pd *nex_alloc_pd(struct ibv_context *context)
{
	struct nex_context *nctx = to_nctx(context);
	struct nex_pd *pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	pd->ibv_pd.context = context;
	pd->ibv_pd.handle = nex_next_handle(nctx);
	return &pd->ibv_pd;
}

static int nex_dealloc_pd(struct ibv_pd *pd)
{
	free(to_npd(pd));
	return 0;
}

static struct ibv_mr *nex_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access)
{
	NEX_TRACE("reg_mr addr=%p len=%zu access=0x%x", addr, length, access);

	if (!length) {
		errno = EINVAL;
		NEX_TRACE("reg_mr rejecting zero-length registration");
		return NULL;
	}

	if (!addr && !(access & IBV_ACCESS_ZERO_BASED)) {
		errno = EINVAL;
		NEX_TRACE("reg_mr requires valid addr unless zero-based flag set");
		return NULL;
	}
	struct nex_context *ctx = to_nctx(pd->context);
	struct nex_mr *mr = calloc(1, sizeof(*mr));
	if (!mr) {
		errno = ENOMEM;
		return NULL;
	}

	mr->vmr.ibv_mr.context = pd->context;
	mr->vmr.ibv_mr.pd = pd;
	mr->vmr.ibv_mr.addr = addr;
	mr->vmr.ibv_mr.length = length;
	mr->vmr.ibv_mr.handle = nex_next_handle(ctx);
	mr->vmr.ibv_mr.lkey = nex_next_key(ctx);
	mr->vmr.ibv_mr.rkey = mr->vmr.ibv_mr.lkey;
	mr->vmr.mr_type = IBV_MR_TYPE_MR;
	mr->vmr.access = access;
	(void)hca_va;
	(void)access;
	mr->next = NULL;
	pthread_spin_lock(&ctx->mr_lock);
	mr->next = ctx->mr_list;
	ctx->mr_list = mr;
	pthread_spin_unlock(&ctx->mr_lock);
	NEX_TRACE("reg_mr addr=%p len=%zu lkey=%u rkey=%u",
		addr, length, mr->vmr.ibv_mr.lkey, mr->vmr.ibv_mr.rkey);
	return &mr->vmr.ibv_mr;
}

static struct ibv_mr *nex_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
			       uint64_t length, uint64_t iova, int fd, int access)
{
	(void)offset;
	(void)fd;
	void *addr = (void *)(uintptr_t)iova;
	return nex_reg_mr(pd, addr, (size_t)length, iova, access);
}

static int nex_dereg_mr(struct verbs_mr *vmr)
{
	struct nex_mr *mr = container_of(vmr, struct nex_mr, vmr);
	struct nex_context *ctx = to_nctx(vmr->ibv_mr.context);
	pthread_spin_lock(&ctx->mr_lock);
	struct nex_mr **prev = &ctx->mr_list;
	while (*prev && *prev != mr)
		prev = &(*prev)->next;
	if (*prev == mr)
		*prev = mr->next;
	pthread_spin_unlock(&ctx->mr_lock);
	free(mr);
	return 0;
}

/* Completion Queue ------------------------------------------------------ */

static struct ibv_cq *nex_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct nex_context *ctx = to_nctx(context);
	struct nex_cq *cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	if (cqe <= 0)
		cqe = 1;

	/*
	 * Maintain an extra slot so the ring buffer can store the requested
	 * number of CQEs without hitting the overflow guard.
	 */
	size_t ring_capacity = (size_t)cqe + 1;
	cq->entries = calloc(ring_capacity, sizeof(*cq->entries));
	if (!cq->entries) {
		free(cq);
		return NULL;
	}

	cq->capacity = ring_capacity;
	cq->head = cq->tail = 0;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	verbs_init_cq(&cq->vcq.cq, context, channel, NULL);
	cq->vcq.cq.handle = nex_next_handle(ctx);
	// completion queue depth (i.e., the number of entries it can hold)
	cq->vcq.cq.cqe = cqe;
	return &cq->vcq.cq;
}

/*
 * Extended CQ support is a view over the same completion ring used by
 * ibv_poll_cq.  start_poll keeps the ring lock until end_poll, as required by
 * the CQ_EX batch-poll contract, and current_wc owns the entry exposed through
 * the read_* callbacks.
 */
static int nex_cq_ex_pop_locked(struct nex_cq *cq)
{
	struct ibv_cq_ex *cq_ex = &cq->vcq.cq_ex;

	if (cq->head == cq->tail)
		return ENOENT;

	cq->current_wc = cq->entries[cq->head];
	cq->head = (cq->head + 1) % cq->capacity;
	cq_ex->status = cq->current_wc.status;
	cq_ex->wr_id = cq->current_wc.wr_id;
	return 0;
}

static int nex_cq_ex_start_poll(struct ibv_cq_ex *ibcq_ex,
				struct ibv_poll_cq_attr *attr)
{
	struct nex_cq *cq = to_ncq(ibv_cq_ex_to_cq(ibcq_ex));
	int ret;

	if (attr && attr->comp_mask)
		return EINVAL;

	ret = pthread_spin_lock(&cq->lock);
	if (ret)
		return ret;

	ret = nex_cq_ex_pop_locked(cq);
	if (ret)
		pthread_spin_unlock(&cq->lock);
	return ret;
}

static int nex_cq_ex_next_poll(struct ibv_cq_ex *ibcq_ex)
{
	struct nex_cq *cq = to_ncq(ibv_cq_ex_to_cq(ibcq_ex));

	return nex_cq_ex_pop_locked(cq);
}

static void nex_cq_ex_end_poll(struct ibv_cq_ex *ibcq_ex)
{
	struct nex_cq *cq = to_ncq(ibv_cq_ex_to_cq(ibcq_ex));

	pthread_spin_unlock(&cq->lock);
}

static enum ibv_wc_opcode nex_cq_ex_read_opcode(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.opcode;
}

static uint32_t nex_cq_ex_read_vendor_err(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.vendor_err;
}

static uint32_t nex_cq_ex_read_byte_len(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.byte_len;
}

static __be32 nex_cq_ex_read_imm_data(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.imm_data;
}

static uint32_t nex_cq_ex_read_qp_num(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.qp_num;
}

static uint32_t nex_cq_ex_read_src_qp(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.src_qp;
}

static unsigned int nex_cq_ex_read_wc_flags(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.wc_flags;
}

static uint32_t nex_cq_ex_read_slid(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.slid;
}

static uint8_t nex_cq_ex_read_sl(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.sl;
}

static uint8_t nex_cq_ex_read_dlid_path_bits(struct ibv_cq_ex *ibcq_ex)
{
	return to_ncq(ibv_cq_ex_to_cq(ibcq_ex))->current_wc.dlid_path_bits;
}

static struct ibv_cq_ex *
nex_create_cq_ex(struct ibv_context *context,
		 struct ibv_cq_init_attr_ex *attr)
{
	const uint64_t supported_wc_flags = IBV_WC_STANDARD_FLAGS;
	struct nex_context *ctx = to_nctx(context);
	struct nex_cq *cq;
	size_t ring_capacity;

	if (!attr || attr->cqe == 0 || attr->comp_vector != 0) {
		errno = EINVAL;
		return NULL;
	}
	if (attr->comp_mask || attr->flags || attr->channel) {
		errno = EOPNOTSUPP;
		return NULL;
	}
	if (attr->wc_flags & ~supported_wc_flags) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	ring_capacity = (size_t)attr->cqe + 1;
	cq->entries = calloc(ring_capacity, sizeof(*cq->entries));
	if (!cq->entries) {
		free(cq);
		return NULL;
	}

	cq->capacity = ring_capacity;
	cq->head = cq->tail = 0;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	cq->vcq.cq_ex.handle = nex_next_handle(ctx);
	cq->vcq.cq_ex.cqe = attr->cqe;
	cq->vcq.cq_ex.start_poll = nex_cq_ex_start_poll;
	cq->vcq.cq_ex.next_poll = nex_cq_ex_next_poll;
	cq->vcq.cq_ex.end_poll = nex_cq_ex_end_poll;
	cq->vcq.cq_ex.read_opcode = nex_cq_ex_read_opcode;
	cq->vcq.cq_ex.read_vendor_err = nex_cq_ex_read_vendor_err;
	cq->vcq.cq_ex.read_wc_flags = nex_cq_ex_read_wc_flags;

	if (attr->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		cq->vcq.cq_ex.read_byte_len = nex_cq_ex_read_byte_len;
	if (attr->wc_flags & IBV_WC_EX_WITH_IMM)
		cq->vcq.cq_ex.read_imm_data = nex_cq_ex_read_imm_data;
	if (attr->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		cq->vcq.cq_ex.read_qp_num = nex_cq_ex_read_qp_num;
	if (attr->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		cq->vcq.cq_ex.read_src_qp = nex_cq_ex_read_src_qp;
	if (attr->wc_flags & IBV_WC_EX_WITH_SLID)
		cq->vcq.cq_ex.read_slid = nex_cq_ex_read_slid;
	if (attr->wc_flags & IBV_WC_EX_WITH_SL)
		cq->vcq.cq_ex.read_sl = nex_cq_ex_read_sl;
	if (attr->wc_flags & IBV_WC_EX_WITH_DLID_PATH_BITS)
		cq->vcq.cq_ex.read_dlid_path_bits =
			nex_cq_ex_read_dlid_path_bits;

	return &cq->vcq.cq_ex;
}

static int nex_destroy_cq(struct ibv_cq *ibcq)
{
	struct nex_cq *cq = to_ncq(ibcq);
	pthread_spin_destroy(&cq->lock);
	free(cq->entries);
	free(cq);
	return 0;
}

static int nex_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct nex_cq *cq = to_ncq(ibcq);
	return nex_cq_pop(cq, num_entries, wc);
}

static int nex_req_notify_cq(struct ibv_cq *ibcq, int solicited_only)
{
	(void)ibcq;
	(void)solicited_only;
	return 0;
}

/* Queue Pair ------------------------------------------------------------ */

static void nex_wr_start(struct ibv_qp_ex *ibqpx);
static int nex_wr_complete(struct ibv_qp_ex *ibqpx);
static void nex_wr_abort(struct ibv_qp_ex *ibqpx);
static void nex_wr_rdma_read(struct ibv_qp_ex *ibqpx, uint32_t rkey,
			     uint64_t remote_addr);
static void nex_wr_rdma_write(struct ibv_qp_ex *ibqpx, uint32_t rkey,
			      uint64_t remote_addr);
static void nex_wr_rdma_write_imm(struct ibv_qp_ex *ibqpx, uint32_t rkey,
				  uint64_t remote_addr, __be32 imm_data);
static void nex_wr_set_inline_data(struct ibv_qp_ex *ibqpx, void *addr,
				   size_t length);
static void nex_wr_set_sge(struct ibv_qp_ex *ibqpx, uint32_t lkey,
			   uint64_t addr, uint32_t length);
static void nex_wr_set_sge_list(struct ibv_qp_ex *ibqpx, size_t num_sge,
				const struct ibv_sge *sg_list);

static struct ibv_qp *nex_create_qp(struct ibv_pd *pd,
                    struct ibv_qp_init_attr *attr)
{
    struct nex_context *ctx = to_nctx(pd->context);
    struct nex_qp *qp = calloc(1, sizeof(*qp));
	if (!qp){
		NEX_TRACE("create_qp: calloc failed");
		return NULL;
	}

	struct nex_cq *send_cq = to_ncq(attr->send_cq);
	struct nex_cq *recv_cq = to_ncq(attr->recv_cq);
	if (!send_cq || !recv_cq) {
		free(qp);
		NEX_TRACE("create_qp: invalid send/recv CQ");
		errno = EINVAL;
		return NULL;
	}

	uint32_t recv_wr = attr->cap.max_recv_wr;
	if (recv_wr == 0)
		recv_wr = 16;

	/*
	 * Maintain a single empty slot so the ring-buffer full/empty tests work
	 * while still allowing max_recv_wr outstanding WRs.
	 */
	qp->recv_size = recv_wr + 1;
	qp->recv_queue = calloc(qp->recv_size, sizeof(*qp->recv_queue));
	if (!qp->recv_queue) {
		free(qp);
		NEX_TRACE("create_qp: recv_queue calloc failed");
		return NULL;
	}
	qp->recv_head = qp->recv_tail = 0;
	pthread_spin_init(&qp->lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rdma_lock, PTHREAD_PROCESS_PRIVATE);
	qp->pending_reads = NULL;
	pthread_mutex_init(&qp->state_lock, NULL);
	pthread_cond_init(&qp->state_cond, NULL);
	qp->tx_fd = -1;
	qp->rx_fd = -1;
	qp->rx_running = false;
    qp->remote_qp_num = 0;
	qp->destroying = false;
	qp->connect_in_progress = false;
	qp->connect_status = 0;
	qp->rx_worker_done = true;
	qp->tx_sender_done = true;
	qp->tx_worker_done = true;
	qp->sq_sig_all = attr->sq_sig_all != 0;

	qp->pending_head = qp->pending_tail = NULL;

	// init tx task queue (post_send -> tx fiber)
	uint32_t send_wr = attr->cap.max_send_wr;
	if (send_wr == 0)
		send_wr = 64;
	qp->send_task_qsize = send_wr + 1;
	qp->send_task_queue = calloc(qp->send_task_qsize, sizeof(*qp->send_task_queue));
	if (!qp->send_task_queue) {
		pthread_mutex_destroy(&qp->state_lock);
		pthread_cond_destroy(&qp->state_cond);
		pthread_spin_destroy(&qp->rdma_lock);
		pthread_spin_destroy(&qp->lock);
		free(qp->recv_queue);
		free(qp);
		errno = ENOMEM;
		return NULL;
	}
	qp->send_task_head = qp->send_task_tail = 0;
	pthread_spin_init(&qp->send_task_lock, PTHREAD_PROCESS_PRIVATE);

	qp->tx_wait_qsize = send_wr + 1;
	qp->tx_wait_queue = calloc(qp->tx_wait_qsize, sizeof(*qp->tx_wait_queue));
	if (!qp->tx_wait_queue) {
		pthread_spin_destroy(&qp->send_task_lock);
		free(qp->send_task_queue);
		pthread_mutex_destroy(&qp->state_lock);
		pthread_cond_destroy(&qp->state_cond);
		pthread_spin_destroy(&qp->rdma_lock);
		pthread_spin_destroy(&qp->lock);
		free(qp->recv_queue);
		free(qp);
		errno = ENOMEM;
		return NULL;
	}
	qp->tx_wait_head = qp->tx_wait_tail = 0;
	pthread_spin_init(&qp->ex_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->tx_wire_lock, PTHREAD_PROCESS_PRIVATE);

	atomic_init(&qp->tx_running, false);
	qp->next_tag = 1;

	qp->ctx = ctx;
	qp->send_cq = send_cq;
	qp->recv_cq = recv_cq;

	qp->vqp.qp.context = pd->context;
	qp->vqp.qp.qp_context = attr->qp_context;
	qp->vqp.qp.pd = pd;
	qp->vqp.qp.send_cq = attr->send_cq;
	qp->vqp.qp.recv_cq = attr->recv_cq;
	/* Shared receive queue: when set, this QP's incoming SEND /
	 * RDMA_WRITE_WITH_IMM consume recv WRs from the SRQ ring instead of
	 * the per-QP ring (see fiber_try_take_recv). */
	qp->vqp.qp.srq = attr->srq;
	qp->srq = attr->srq ? to_nsrq(attr->srq) : NULL;
	qp->vqp.qp.handle = nex_next_handle(ctx);
	qp->vqp.qp.qp_num = nex_next_handle(ctx);
	qp->vqp.qp.qp_type = attr->qp_type;
	qp->vqp.qp.state = IBV_QPS_RESET;
	pthread_mutex_init(&qp->vqp.qp.mutex, NULL);
	pthread_cond_init(&qp->vqp.qp.cond, NULL);

	if (nex_qp_reserve(qp)) {
		pthread_spin_destroy(&qp->lock);
		pthread_spin_destroy(&qp->rdma_lock);
		pthread_mutex_destroy(&qp->state_lock);
		pthread_cond_destroy(&qp->state_cond);
		pthread_spin_destroy(&qp->send_task_lock);
		pthread_spin_destroy(&qp->ex_lock);
		pthread_spin_destroy(&qp->tx_wire_lock);
		free(qp->send_task_queue);
		free(qp->tx_wait_queue);
		pthread_mutex_destroy(&qp->vqp.qp.mutex);
		pthread_cond_destroy(&qp->vqp.qp.cond);
		free(qp->recv_queue);
		free(qp);
		NEX_TRACE("create_qp: nex_qp_reserve failed");
		return NULL;
	}

	return &qp->vqp.qp;
}

static struct ibv_qp *nex_create_qp_ex(struct ibv_context *context,
				       struct ibv_qp_init_attr_ex *attr)
{
	(void)context;
	const uint64_t supported = IBV_QP_EX_WITH_RDMA_WRITE |
		IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM | IBV_QP_EX_WITH_RDMA_READ;
	if (!(attr->comp_mask & IBV_QP_INIT_ATTR_PD) || !attr->pd ||
	    (attr->send_ops_flags & ~supported)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	struct ibv_qp *ibqp = nex_create_qp(
		attr->pd, (struct ibv_qp_init_attr *)attr);
	if (!ibqp)
		return NULL;
	struct nex_qp *qp = to_nqp(ibqp);
	qp->vqp.comp_mask |= VERBS_QP_EX;
	qp->vqp.qp_ex.wr_start = nex_wr_start;
	qp->vqp.qp_ex.wr_complete = nex_wr_complete;
	qp->vqp.qp_ex.wr_abort = nex_wr_abort;
	qp->vqp.qp_ex.wr_set_inline_data = nex_wr_set_inline_data;
	qp->vqp.qp_ex.wr_set_sge = nex_wr_set_sge;
	qp->vqp.qp_ex.wr_set_sge_list = nex_wr_set_sge_list;
	if (attr->send_ops_flags & IBV_QP_EX_WITH_RDMA_READ)
		qp->vqp.qp_ex.wr_rdma_read = nex_wr_rdma_read;
	if (attr->send_ops_flags & IBV_QP_EX_WITH_RDMA_WRITE)
		qp->vqp.qp_ex.wr_rdma_write = nex_wr_rdma_write;
	if (attr->send_ops_flags & IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
		qp->vqp.qp_ex.wr_rdma_write_imm = nex_wr_rdma_write_imm;
	return ibqp;
}

static int nex_destroy_qp(struct ibv_qp *ibqp)
{
	struct nex_qp *qp = to_nqp(ibqp);
	nex_qp_release(qp);

	pthread_mutex_lock(&qp->state_lock);
	qp->destroying = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);

	/* Stop TX worker first to avoid sending on a shutdown fd. */
	atomic_store_explicit(&qp->tx_running, false, memory_order_release);

	pthread_mutex_lock(&qp->state_lock);
	while (qp->connect_in_progress || !qp->tx_sender_done || !qp->tx_worker_done)
		pthread_cond_wait(&qp->state_cond, &qp->state_lock);
	pthread_mutex_unlock(&qp->state_lock);

	if (qp->rx_running) {
		pthread_spin_lock(&qp->lock);
		qp->rx_running = false;
		pthread_spin_unlock(&qp->lock);

		int shm_fd = qp->tx_fd >= 0 ? qp->tx_fd : qp->rx_fd;
		if (shm_fd >= 0) {
			if (nex_use_tcp_backend())
				nex_tcp_shutdown(shm_fd);
			else
				nex_shm_shutdown(shm_fd);
		}
	}

	pthread_mutex_lock(&qp->state_lock);
	while (qp->connect_in_progress || !qp->rx_worker_done)
		pthread_cond_wait(&qp->state_cond, &qp->state_lock);
	pthread_mutex_unlock(&qp->state_lock);

	if (qp->tx_fd >= 0) {
		if (nex_use_tcp_backend())
			nex_tcp_close(qp->tx_fd);
		else
			nex_shm_close(qp->tx_fd);
		qp->tx_fd = -1;
		qp->rx_fd = -1;
	} else if (qp->rx_fd >= 0) {
		/* Safety: handle hypothetical cases where tx/rx differ. */
		if (nex_use_tcp_backend())
			nex_tcp_close(qp->rx_fd);
		else
			nex_shm_close(qp->rx_fd);
		qp->rx_fd = -1;
	}
	/* Drain any leftover queued send tasks (should be empty once tx worker exits). */
	pthread_spin_lock(&qp->send_task_lock);
	while (qp->send_task_head != qp->send_task_tail) {
		struct nex_send_task *task = qp->send_task_queue[qp->send_task_head];
		qp->send_task_head = (qp->send_task_head + 1) % qp->send_task_qsize;
		if (task) {
			free(task->payload_iov);
			free(task);
		}
	}
	pthread_spin_unlock(&qp->send_task_lock);

	/* Drain leftover TX wait entries. */
	qp->tx_wait_head = qp->tx_wait_tail;

	pthread_spin_destroy(&qp->lock);
	pthread_spin_lock(&qp->rdma_lock);
	struct nex_pending_read *pending = qp->pending_reads;
	while (pending) {
		struct nex_pending_read *next = pending->next;
		free(pending);
		pending = next;
	}
	qp->pending_reads = NULL;
	pthread_spin_unlock(&qp->rdma_lock);
	pthread_spin_destroy(&qp->rdma_lock);
	pthread_mutex_destroy(&qp->state_lock);
	pthread_cond_destroy(&qp->state_cond);
	pthread_mutex_destroy(&qp->vqp.qp.mutex);
	pthread_cond_destroy(&qp->vqp.qp.cond);
	struct nex_pending_msg *pmsg = qp->pending_head;
	while (pmsg) {
		struct nex_pending_msg *next = pmsg->next;
		free(pmsg->payload);
		free(pmsg);
		pmsg = next;
	}
	qp->pending_head = qp->pending_tail = NULL;
	pthread_spin_destroy(&qp->send_task_lock);
	pthread_spin_destroy(&qp->ex_lock);
	pthread_spin_destroy(&qp->tx_wire_lock);
	free(qp->send_task_queue);
	free(qp->tx_wait_queue);
	free(qp->recv_queue);
	free(qp);
	return 0;
}

/*
Every reliable connection (RC) queue pair walks through a fixed set of states. 
You move between them with ibv_modify_qp and a bitmask that tells 
the provider which fields you’re changing. 
In order:
- RESET 
	Freshly created QP; nothing programmed yet.
- INIT 
	Local access properties set (port number, pkey index, access flags).
	You must call ibv_modify_qp with IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS to get here.
- RTR (Ready To Receive)
	Remote path information filled in (remote QP number, path MTU, PSNs, address vector).
	Typical mask: IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER.
- RTS (Ready To Send) 
	Transmit fields programmed (send queue PSN, retry counters, timeout). At this point both send and receive wrs can be posted.
	Mask usually: IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC.
- SQD (Send Queue Draining)
	Optional drain state if you want to wait until outstanding sends finish.
- SQE (Send Queue Error)
	An error occurred on the send queue; the provider sets this in completions.
- ERR
	General error state.
- Unknown
	For completeness; the provider uses it internally if queried at the wrong time.
Most applications only care about INIT → RTR → RTS.
*/
static int nex_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			 int attr_mask)
{
	NEX_TRACE("modify_qp qpn=%u mask=0x%x state=%d\n",
		ibqp->qp_num, attr_mask,
		(attr_mask & IBV_QP_STATE) ? attr->qp_state : -1);
		
	struct nex_qp *qp = to_nqp(ibqp);

	if (attr_mask & IBV_QP_DEST_QPN) {
		qp->remote_qp_num = attr->dest_qp_num;
		qp->remote_lid = attr->ah_attr.dlid;
		NEX_TRACE("modify_qp remote_lid=%u; dest_qpn=%u; qp_pair=%u:%u", attr->ah_attr.dlid, attr->dest_qp_num, qp->vqp.qp.qp_num, qp->remote_qp_num);
		pthread_mutex_lock(&qp->state_lock);
		pthread_cond_broadcast(&qp->state_cond);
		bool should_connect = !qp->connect_in_progress && qp->tx_fd < 0 && nex_qp_has_peer_addr(qp);
		if (should_connect) {
			pthread_mutex_unlock(&qp->state_lock);
			int rc = nex_qp_start_connect(qp);
			if (rc && rc != EAGAIN) {
				errno = rc;
				return rc;
			}
		} else {
			pthread_mutex_unlock(&qp->state_lock);
		}
	}

	if (attr_mask & IBV_QP_STATE) {
		qp->vqp.qp.state = attr->qp_state;
		if (attr->qp_state == IBV_QPS_RTS) {
			int rc = nex_qp_start_connect(qp);
			if (rc && rc != EAGAIN) {
				NEX_TRACE("modify_qp start_connect FAILED rc=%d", rc);
				errno = rc;
				return rc;
			}
			if (!rc)
				NEX_TRACE("modify_qp start_connect returned OK");
		}
	}

	return 0;
}

static int nex_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	(void)attr_mask;
	(void)init_attr;

	struct nex_qp *qp = to_nqp(ibqp);
	memset(attr, 0, sizeof(*attr));
	attr->qp_state = qp->vqp.qp.state;
	attr->cur_qp_state = qp->vqp.qp.state;
	attr->dest_qp_num = qp->remote_qp_num;
	return 0;
}

static void fiber_connect_qp(void *arg)
{
	struct nex_qp *qp = arg;
	int rc = fiber_qp_establish_sync(qp);
	pthread_mutex_lock(&qp->state_lock);
	qp->connect_status = rc;
	qp->connect_in_progress = false;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
}

static int nex_qp_start_connect(struct nex_qp *qp)
{
	if (qp->tx_fd >= 0)
		return 0;

	pthread_mutex_lock(&qp->state_lock);
	if (qp->tx_fd >= 0) {
		pthread_mutex_unlock(&qp->state_lock);
		return 0;
	}
	if (qp->destroying) {
		qp->connect_status = ECANCELED;
		pthread_cond_broadcast(&qp->state_cond);
		pthread_mutex_unlock(&qp->state_lock);
		return ECANCELED;
	}
	if (qp->connect_in_progress) {
		pthread_mutex_unlock(&qp->state_lock);
		return 0;
	}
	if (!nex_qp_has_peer_addr(qp)) {
		qp->connect_status = EAGAIN;
		pthread_cond_broadcast(&qp->state_cond);
		pthread_mutex_unlock(&qp->state_lock);
		return EAGAIN;
	}
	qp->connect_in_progress = true;
	qp->connect_status = EINPROGRESS;
	pthread_mutex_unlock(&qp->state_lock);

	int rc = accvm_syms.gx_sched_new_fiber(fiber_connect_qp, qp);
	if (rc) {
		pthread_mutex_lock(&qp->state_lock);
		qp->connect_in_progress = false;
		qp->connect_status = rc < 0 ? -rc : rc;
		pthread_cond_broadcast(&qp->state_cond);
		pthread_mutex_unlock(&qp->state_lock);
		return rc < 0 ? -rc : rc;
	}
	return 0;
}

static int nex_qp_wait_connected(struct nex_qp *qp)
{
	for (;;) {
		int rc = nex_qp_start_connect(qp);
		if (rc && rc != EAGAIN)
			return rc;

		pthread_mutex_lock(&qp->state_lock);
		while (qp->tx_fd < 0 && qp->connect_in_progress)
			pthread_cond_wait(&qp->state_cond, &qp->state_lock);
		if (qp->tx_fd >= 0) {
			pthread_mutex_unlock(&qp->state_lock);
			return 0;
		}

		rc = qp->connect_status;
		if (rc == EAGAIN && !nex_qp_has_peer_addr(qp)) {
			while (!nex_qp_has_peer_addr(qp))
				pthread_cond_wait(&qp->state_cond, &qp->state_lock);
			pthread_mutex_unlock(&qp->state_lock);
			continue;
		}

		if (!rc)
			rc = EIO;
		pthread_mutex_unlock(&qp->state_lock);
		return rc;
	}
}

static int nex_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	struct nex_qp *qp = to_nqp(ibqp);

	// iterate through work requests (wr)
	// wr has next and sg_list (scatter-gather list)
	// each sg_list has addr, length, lkey
	NEX_TRACE("nex_post_recv produced");

	for (; wr; wr = wr->next) {
		if (wr->num_sge > 1) {
			if (bad_wr)
				*bad_wr = wr;
			NEX_ERROR("post_recv num_sge=%d unsupported", wr->num_sge);
			errno = ENOTSUP;
			return ENOTSUP;
		}
	    
		NEX_TRACE("post_recv wr_id=%" PRIu64 " num_sge=%d len=%u qp=%u",
		       (uint64_t)wr->wr_id, wr->num_sge,
		       wr->num_sge ? wr->sg_list[0].length : 0U,
		       qp->vqp.qp.qp_num);
			   
    	// Wait for available space instead of failing when queue is full
		for (;;) {
			pthread_spin_lock(&qp->lock);
			uint32_t next_tail = (qp->recv_tail + 1) % qp->recv_size;
			if (next_tail != qp->recv_head) {
				// Space available; enqueue and break
				struct nex_recv_entry *entry = &qp->recv_queue[qp->recv_tail];
				entry->wr_id = wr->wr_id;
				if (wr->num_sge == 1)
					entry->sge = wr->sg_list[0];
				else
					memset(&entry->sge, 0, sizeof(entry->sge));
				qp->recv_tail = next_tail;
				pthread_spin_unlock(&qp->lock);
				break;
			}
			// Queue full; release lock and yield before retrying
			pthread_spin_unlock(&qp->lock);
			NEX_TRACE("post_recv queue full; waiting for space");
			sched_yield();
		}
	}
	return 0;
}

/* Shared receive queue -------------------------------------------------- */

static struct ibv_srq *nex_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *attr)
{
	struct nex_srq *srq = calloc(1, sizeof(*srq));
	if (!srq) {
		errno = ENOMEM;
		return NULL;
	}

	uint32_t max_wr = attr->attr.max_wr;
	if (max_wr == 0)
		max_wr = 16;

	/* One empty slot so the ring full/empty tests work (as per-QP rq). */
	srq->recv_size = max_wr + 1;
	srq->recv_queue = calloc(srq->recv_size, sizeof(*srq->recv_queue));
	if (!srq->recv_queue) {
		free(srq);
		errno = ENOMEM;
		return NULL;
	}
	srq->recv_head = srq->recv_tail = 0;
	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);

	NEX_TRACE("create_srq max_wr=%u max_sge=%u", attr->attr.max_wr,
		  attr->attr.max_sge);
	return &srq->ibv_srq;
}

static int nex_destroy_srq(struct ibv_srq *ibsrq)
{
	struct nex_srq *srq = to_nsrq(ibsrq);

	pthread_spin_destroy(&srq->lock);
	free(srq->recv_queue);
	free(srq);
	return 0;
}

static int nex_query_srq(struct ibv_srq *ibsrq, struct ibv_srq_attr *attr)
{
	struct nex_srq *srq = to_nsrq(ibsrq);

	attr->max_wr = srq->recv_size - 1;
	attr->max_sge = 1;
	attr->srq_limit = 0;
	return 0;
}

static int nex_post_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr,
			     struct ibv_recv_wr **bad_wr)
{
	struct nex_srq *srq = to_nsrq(ibsrq);

	for (; wr; wr = wr->next) {
		if (wr->num_sge > 1) {
			if (bad_wr)
				*bad_wr = wr;
			NEX_ERROR("post_srq_recv num_sge=%d unsupported",
				  wr->num_sge);
			errno = ENOTSUP;
			return ENOTSUP;
		}

		NEX_TRACE("post_srq_recv wr_id=%" PRIu64 " num_sge=%d len=%u",
			  (uint64_t)wr->wr_id, wr->num_sge,
			  wr->num_sge ? wr->sg_list[0].length : 0U);

		/* Wait for space instead of failing, as nex_post_recv does. */
		for (;;) {
			pthread_spin_lock(&srq->lock);
			uint32_t next_tail = (srq->recv_tail + 1) % srq->recv_size;
			if (next_tail != srq->recv_head) {
				struct nex_recv_entry *entry =
					&srq->recv_queue[srq->recv_tail];
				entry->wr_id = wr->wr_id;
				if (wr->num_sge == 1)
					entry->sge = wr->sg_list[0];
				else
					memset(&entry->sge, 0, sizeof(entry->sge));
				srq->recv_tail = next_tail;
				pthread_spin_unlock(&srq->lock);
				break;
			}
			pthread_spin_unlock(&srq->lock);
			NEX_TRACE("post_srq_recv queue full; waiting for space");
			sched_yield();
		}
	}
	return 0;
}

static int nex_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{

	

	struct nex_qp *qp = to_nqp(ibqp);
	NEX_TRACE("nex_post_send produced");

	if (qp->vqp.qp.state != IBV_QPS_RTS) {
		if (bad_wr)
			*bad_wr = wr;
		NEX_ERROR("ERROR: post_send qp not in RTS state");
		errno = EINVAL;
		return EINVAL;
	}

	if (qp->tx_fd < 0) {
		int rc = nex_qp_wait_connected(qp);
		if (rc) {
			if (bad_wr)
				*bad_wr = wr;
			NEX_ERROR("post_send wait_connected failed");
			errno = rc;
			return rc;
		}
	}


	for (; wr; wr = wr->next) {

		bool wr_signaled = (wr->send_flags & IBV_SEND_SIGNALED) != 0;
		bool completion_requested = wr_signaled || qp->sq_sig_all;

		NEX_TRACE("post_send wr_id=%" PRIu64 " opcode=%u num_sge=%d qp_pair=%u:%u signaled=%d sq_sig_all=%d completion=%d",
			   (uint64_t)wr->wr_id, wr->opcode, wr->num_sge,
			   qp->vqp.qp.qp_num, qp->remote_qp_num, wr_signaled, qp->sq_sig_all, completion_requested);

		bool allow_zero_sge =
			wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
			wr->opcode == IBV_WR_SEND;

		if ((!allow_zero_sge && wr->num_sge == 0) || wr->num_sge > NEX_MAX_SGE) {
			if (bad_wr) *bad_wr = wr;
			errno = EINVAL;
			NEX_ERROR("post_send num_sge=%d unsupported\n", wr->num_sge);
			goto ERROR_OUT;
		}

		size_t total_len = 0;
		for (int i = 0; i < wr->num_sge; ++i)
			total_len += wr->sg_list[i].length;

		struct nex_msg_hdr hdr = {
			.opcode = NEX_MSG_SEND,
			.status = NEX_MSG_STATUS_OK,
			.wr_id = wr->wr_id,
			.remote_addr = 0,
			.rkey = 0,
			.length = (uint32_t)total_len,
			.imm_data = 0,
			.reserved = 0,
			.atomic_operand = 0,
		};

		int rc = 0;
		size_t payload_len = total_len;
		struct iovec *payload_iov = NULL;
		int payload_iovcnt = 0;

		switch (wr->opcode) {
		case IBV_WR_SEND:
			hdr.opcode = NEX_MSG_SEND;
			break;
		case IBV_WR_RDMA_WRITE:
			hdr.opcode = NEX_MSG_RDMA_WRITE;
			hdr.remote_addr = wr->wr.rdma.remote_addr;
			hdr.rkey = wr->wr.rdma.rkey;
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			hdr.opcode = NEX_MSG_RDMA_WRITE_IMM;
			hdr.remote_addr = wr->wr.rdma.remote_addr;
			hdr.rkey = wr->wr.rdma.rkey;
			hdr.imm_data = wr->imm_data;
			break;
		case IBV_WR_RDMA_READ: {
				hdr.opcode = NEX_MSG_RDMA_READ_REQ;
				hdr.remote_addr = wr->wr.rdma.remote_addr;
				hdr.rkey = wr->wr.rdma.rkey;
				/* hdr.length carries the requested READ size (response payload). */
				hdr.length = (uint32_t)total_len;

				/* Attach a small request payload to model request transfer. */
				payload_iov = calloc(1, sizeof(*payload_iov));
				if (!payload_iov) {
					if (bad_wr)
						*bad_wr = wr;
					errno = ENOMEM;
					goto ERROR_OUT;
				}
				payload_iov[0].iov_base = (void *)nex_read_req_payload;
				payload_iov[0].iov_len = (size_t)NEX_RDMA_READ_REQ_PLD;
				payload_iovcnt = 1;
				payload_len = (size_t)NEX_RDMA_READ_REQ_PLD;
				/* Do not wait here; responder will wait on recv side. */

			rc = nex_add_pending_read(qp, wr->wr_id, wr->sg_list,
					wr->num_sge, total_len, completion_requested,
					IBV_WC_RDMA_READ);

			/* READ request send does not generate a send-side completion. */
			completion_requested = false;

				if (rc) {
					if (bad_wr)
						*bad_wr = wr;
					errno = rc;
					free(payload_iov);
					NEX_ERROR("post_send add_pending_read failed");
					goto ERROR_OUT;
				}
				break;
			}
		case IBV_WR_ATOMIC_FETCH_AND_ADD:
			if (wr->num_sge != 1 || total_len != sizeof(uint64_t) ||
			    (wr->sg_list[0].addr & (sizeof(uint64_t) - 1)) != 0 ||
			    (wr->wr.atomic.remote_addr & (sizeof(uint64_t) - 1)) != 0) {
				if (bad_wr)
					*bad_wr = wr;
				errno = EINVAL;
				NEX_ERROR("post_send fetch-add requires one aligned 8-byte SGE and remote address");
				goto ERROR_OUT;
			}
			hdr.opcode = NEX_MSG_ATOMIC_FETCH_ADD_REQ;
			hdr.remote_addr = wr->wr.atomic.remote_addr;
			hdr.rkey = wr->wr.atomic.rkey;
			hdr.length = sizeof(uint64_t);
			hdr.atomic_operand = wr->wr.atomic.compare_add;
			payload_len = 0;
			rc = nex_add_pending_read(qp, wr->wr_id, wr->sg_list,
					wr->num_sge, total_len, completion_requested,
					IBV_WC_FETCH_ADD);
			if (rc) {
				if (bad_wr)
					*bad_wr = wr;
				errno = rc;
				NEX_ERROR("post_send add_pending_fetch_add failed");
				goto ERROR_OUT;
			}
			/* The response writes the fetched value and owns completion. */
			completion_requested = false;
			break;
		default:
			if (bad_wr)
				*bad_wr = wr;
			errno = ENOTSUP;
			NEX_ERROR("post_send opcode=%d unsupported\n", wr->opcode);
			goto ERROR_OUT;
		}

		if ((wr->opcode == IBV_WR_SEND ||
		     wr->opcode == IBV_WR_RDMA_WRITE ||
		     wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM) && total_len) {
			if (wr->send_flags & IBV_SEND_INLINE) {
				/* Inline verbs semantics allow the caller to reuse every SGE
				 * as soon as ibv_post_send returns. The GX transport sends on
				 * a worker fiber, so retain an owned snapshot rather than SGE
				 * pointers into memory UCCL may immediately recycle. Keep the
				 * bytes adjacent to the sole iovec so the existing task cleanup
				 * frees both with one free(payload_iov). */
				if (total_len > NEX_MAX_INLINE_DATA ||
				    total_len > SIZE_MAX - sizeof(*payload_iov)) {
					if (bad_wr)
						*bad_wr = wr;
					errno = ENOSPC;
					goto ERROR_OUT;
				}
				payload_iov = malloc(sizeof(*payload_iov) + total_len);
				if (!payload_iov) {
					if (bad_wr)
						*bad_wr = wr;
					errno = ENOMEM;
					goto ERROR_OUT;
				}
				uint8_t *dst = (uint8_t *)(payload_iov + 1);
				for (int i = 0; i < wr->num_sge; ++i) {
					uint32_t len = wr->sg_list[i].length;
					if (!len)
						continue;
					memcpy(dst, (const void *)(uintptr_t)wr->sg_list[i].addr,
					       len);
					dst += len;
				}
				payload_iov[0].iov_base = payload_iov + 1;
				payload_iov[0].iov_len = total_len;
				payload_iovcnt = 1;
			} else {
				payload_iov = calloc((size_t)wr->num_sge,
						     sizeof(*payload_iov));
				if (!payload_iov) {
					if (bad_wr)
						*bad_wr = wr;
					errno = ENOMEM;
					goto ERROR_OUT;
				}
				for (int i = 0; i < wr->num_sge; ++i) {
					if (wr->sg_list[i].length == 0)
						continue;
					payload_iov[payload_iovcnt].iov_base =
						(void *)(uintptr_t)wr->sg_list[i].addr;
					payload_iov[payload_iovcnt].iov_len =
						wr->sg_list[i].length;
					++payload_iovcnt;
				}
			}
		}

		NEX_TRACE("about to send");
		rc = nex_txq_send_msg(qp, &hdr,
					payload_iovcnt ? payload_iov : NULL,
					payload_iovcnt, payload_len,
					completion_requested,
					wr->wr_id);
					
		if (rc) {
			if (wr->opcode == IBV_WR_RDMA_READ ||
			    wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) {
				struct nex_pending_read *entry =
				nex_take_pending_read(qp, wr->wr_id);
				free(entry);
			}
			if (bad_wr)
				*bad_wr = wr;
			errno = rc;
			NEX_ERROR("post_send send_msg failed");
			goto ERROR_OUT;
		}

		NEX_TRACE("send wr_id=%" PRIu64 " opcode=%u len=%zu qp_pair=%u:%u",
			(uint64_t)wr->wr_id, hdr.opcode, total_len,
			qp->vqp.qp.qp_num, qp->remote_qp_num);
	}

	return 0;

ERROR_OUT:
	return errno;
}

/* Extended posting API -------------------------------------------------- */

static inline struct nex_qp *nex_qpx(struct ibv_qp_ex *ibqpx)
{
	return container_of(ibqpx, struct nex_qp, vqp.qp_ex);
}

static void nex_wr_start(struct ibv_qp_ex *ibqpx)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	pthread_spin_lock(&qp->ex_lock);
	memset(&qp->ex_wr, 0, sizeof(qp->ex_wr));
	memset(qp->ex_sge, 0, sizeof(qp->ex_sge));
	qp->ex_has_inline_data = false;
	qp->ex_error = 0;
}

static void nex_wr_rdma_read(struct ibv_qp_ex *ibqpx, uint32_t rkey,
			     uint64_t remote_addr)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	qp->ex_wr.opcode = IBV_WR_RDMA_READ;
	qp->ex_wr.wr.rdma.rkey = rkey;
	qp->ex_wr.wr.rdma.remote_addr = remote_addr;
}

static void nex_wr_rdma_write(struct ibv_qp_ex *ibqpx, uint32_t rkey,
			      uint64_t remote_addr)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	qp->ex_wr.opcode = IBV_WR_RDMA_WRITE;
	qp->ex_wr.wr.rdma.rkey = rkey;
	qp->ex_wr.wr.rdma.remote_addr = remote_addr;
}

static void nex_wr_rdma_write_imm(struct ibv_qp_ex *ibqpx, uint32_t rkey,
				  uint64_t remote_addr, __be32 imm_data)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	qp->ex_wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
	qp->ex_wr.wr.rdma.rkey = rkey;
	qp->ex_wr.wr.rdma.remote_addr = remote_addr;
	qp->ex_wr.imm_data = imm_data;
}

static void nex_wr_set_inline_data(struct ibv_qp_ex *ibqpx, void *addr,
				   size_t length)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	if (length > NEX_MAX_INLINE_DATA) {
		qp->ex_error = ENOSPC;
		return;
	}
	memcpy(qp->ex_inline_data, addr, length);
	qp->ex_sge[0] = (struct ibv_sge){
		.addr = (uintptr_t)qp->ex_inline_data,
		.length = (uint32_t)length,
		.lkey = 0,
	};
	qp->ex_wr.sg_list = qp->ex_sge;
	qp->ex_wr.num_sge = length ? 1 : 0;
	qp->ex_has_inline_data = true;
}

static void nex_wr_set_sge(struct ibv_qp_ex *ibqpx, uint32_t lkey,
			   uint64_t addr, uint32_t length)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	qp->ex_has_inline_data = false;
	qp->ex_sge[0] = (struct ibv_sge){.addr = addr, .length = length, .lkey = lkey};
	qp->ex_wr.sg_list = qp->ex_sge;
	qp->ex_wr.num_sge = length ? 1 : 0;
}

static void nex_wr_set_sge_list(struct ibv_qp_ex *ibqpx, size_t num_sge,
				const struct ibv_sge *sg_list)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	if (num_sge > NEX_MAX_SGE) {
		qp->ex_error = ENOSPC;
		return;
	}
	qp->ex_has_inline_data = false;
	memcpy(qp->ex_sge, sg_list, num_sge * sizeof(*sg_list));
	qp->ex_wr.sg_list = qp->ex_sge;
	qp->ex_wr.num_sge = (int)num_sge;
}

static int nex_wr_complete(struct ibv_qp_ex *ibqpx)
{
	struct nex_qp *qp = nex_qpx(ibqpx);
	int rc = qp->ex_error;
	if (!rc) {
		qp->ex_wr.wr_id = ibqpx->wr_id;
		qp->ex_wr.send_flags = ibqpx->wr_flags |
			(qp->ex_has_inline_data ? IBV_SEND_INLINE : 0);
		struct ibv_send_wr *bad_wr = NULL;
		rc = nex_post_send(&qp->vqp.qp, &qp->ex_wr, &bad_wr);
	}
	pthread_spin_unlock(&qp->ex_lock);
	return rc;
}

static void nex_wr_abort(struct ibv_qp_ex *ibqpx)
{
	pthread_spin_unlock(&nex_qpx(ibqpx)->ex_lock);
}

/* Peer died: fail every posted-but-unmatched recv with an error completion.
 * NCCL's ib net plugin turns a non-success WC into ncclRemoteError, which
 * reaches the comm's asyncResult and lets ncclCommAbort unwedge the
 * fiber-emulated device kernels (they already poll abortFlag). */
static void fiber_rx_fail_pending_recvs(struct nex_qp *qp)
{
	struct nex_recv_entry entry;

	/* SRQ entries are shared with other (live) QPs — never drain them on
	 * a single peer's death. */
	if (qp->srq)
		return;

	while (fiber_try_take_recv(qp, &entry)) {
		struct ibv_wc wc = {
			.wr_id = entry.wr_id,
			.status = IBV_WC_RETRY_EXC_ERR,
			.opcode = IBV_WC_RECV,
			.qp_num = qp->vqp.qp.qp_num,
		};
		fiber_cq_push(qp->recv_cq, &wc);
	}
}

/* READ and atomic WRs complete only after a response.  If the transport dies,
 * detach every response-owned operation and report an error CQE (including
 * unsignaled WRs, for which verbs still requires error reporting). */
static void fiber_rx_fail_pending_rdma(struct nex_qp *qp)
{
	struct nex_pending_read *pending;

	fiber_pthread_spin_lock(&qp->rdma_lock);
	pending = qp->pending_reads;
	qp->pending_reads = NULL;
	fiber_pthread_spin_unlock(&qp->rdma_lock);

	while (pending) {
		struct nex_pending_read *next = pending->next;
		struct ibv_wc wc = {
			.wr_id = pending->wr_id,
			.status = IBV_WC_RETRY_EXC_ERR,
			.opcode = pending->wc_opcode,
			.qp_num = qp->vqp.qp.qp_num,
		};
		fiber_cq_push(qp->send_cq, &wc);
		free(pending);
		pending = next;
	}
}

static void fiber_rx_worker(void *arg)
{

	//
	struct nex_qp *qp = arg;
	uint8_t *payload_buf = NULL;
	size_t payload_capacity = 0;
	const size_t initial_capacity = 4096;
	struct nex_msg_hdr hdr;
	uint8_t *payload;
	size_t payload_len;
	bool payload_from_pending;

	for (;;) {
		payload = NULL;
		payload_from_pending = false;
		
		struct nex_pending_msg *pending = fiber_pop_pending_msg(qp);
		if (pending) {
			hdr = pending->hdr;
			payload = pending->payload;
			payload_from_pending = true;
			   NEX_TRACE("replay pending hdr wr_id=%" PRIu64 " opcode=%u len=%u status=%u qp_pair=%u:%u",
				   hdr.wr_id, hdr.opcode, hdr.length, hdr.status,
				   qp->vqp.qp.qp_num, qp->remote_qp_num);
			free(pending);
		} else {
			// get header; op handlers will stream payload directly as needed
			if (!qp->rx_running)
				break;			
			
			if (fiber_read_full(qp->rx_fd, &hdr, sizeof(hdr), 0)) {  // header: no perf model
				/* Read failure with the QP still up = peer death (local
				 * teardown clears rx_running first). Surface it. */
				if (qp->rx_running) {
					fiber_rx_fail_pending_recvs(qp);
					fiber_rx_fail_pending_rdma(qp);
				}
				break;
			}

			
			// NEX_TRACE("rx header, no perf, wr_id=%" PRIu64 " opcode=%u len=%u status=%u hdr.length=%u qp_pair=%u:%u",
			// 	   hdr.wr_id, hdr.opcode, hdr.length, hdr.status, hdr.length,
			// 	   qp->vqp.qp.qp_num, qp->remote_qp_num);
		}

		bool should_exit = false;
		switch (hdr.opcode) {
		case NEX_MSG_SEND: {
			struct nex_recv_entry entry_copy;
			if (!fiber_try_take_recv(qp, &entry_copy)) {
				fprintf(stderr, "ERROR: send without posted recv, wr_id=%" PRIu64 " qp_pair=%u:%u", hdr.wr_id,
					   qp->vqp.qp.qp_num, qp->remote_qp_num);
				fflush(stderr);
				exit(1);
			}

			NEX_TRACE("recv match wr_id=%" PRIu64 " opcode=%u len=%u qp_pair=%u:%u",
				   entry_copy.wr_id, hdr.opcode, hdr.length,
				   qp->vqp.qp.qp_num, qp->remote_qp_num);

			size_t want = hdr.length;
			size_t dst_cap = entry_copy.sge.length;
			size_t to_read = want < dst_cap ? want : dst_cap;
			size_t read_bytes = 0;
			enum ibv_wc_status wc_status = IBV_WC_SUCCESS;

            if (to_read) {
                struct iovec iov = {
                    .iov_base = (void *)(uintptr_t)entry_copy.sge.addr,
                    .iov_len  = to_read,
                };
				int rc = fiber_read_fullv(qp->rx_fd, &iov, 1, to_read, 1, true, NULL, hdr.reserved);
                if (rc != 0) {
                    wc_status = IBV_WC_LOC_LEN_ERR;
                } else {
                    read_bytes = to_read;
                }
            }

			if (read_bytes != want)
				wc_status = IBV_WC_LOC_LEN_ERR;

			struct ibv_wc recv_wc = {
				.wr_id    = entry_copy.wr_id,
				.status   = wc_status,
				.opcode   = IBV_WC_RECV,
				.byte_len = (uint32_t)read_bytes,
				.qp_num   = qp->vqp.qp.qp_num,
			};
			fiber_cq_push(qp->recv_cq, &recv_wc);
			break;
		}
		case NEX_MSG_RDMA_WRITE:
		case NEX_MSG_RDMA_WRITE_IMM: {
			int status = 0;
			bool zero_len_imm = (hdr.opcode == NEX_MSG_RDMA_WRITE_IMM && hdr.length == 0);

			/*
			* Fast-path: zero-byte RDMA_WRITE_WITH_IMM is a "doorbell".
			* Do NOT validate rkey/addr and do NOT touch memory.
			* We only need to generate a successful RECV_RDMA_WITH_IMM CQE.
			*/
			if (!zero_len_imm) {
				struct nex_mr *mr = NULL;
				if (hdr.length) {
					mr = fiber_find_mr(qp->ctx, hdr.rkey);
					if (!mr || !(mr->vmr.access & IBV_ACCESS_REMOTE_WRITE)) {
						status = -EACCES;
					} else {
						uintptr_t base = (uintptr_t)mr->vmr.ibv_mr.addr;
						uintptr_t end  = base + mr->vmr.ibv_mr.length;
						uintptr_t dest = hdr.remote_addr;

                        if (dest < base || dest + hdr.length > end) {
                            status = -EINVAL;
                        } else if (hdr.length) {
                            // Stream payload directly from ring into target memory
							struct iovec iov = {
								.iov_base = (void *)dest,
								.iov_len  = hdr.length,
							};
							if (fiber_read_fullv(qp->rx_fd, &iov, 1, hdr.length, 1, true, NULL, hdr.reserved) != 0) {
								status = -EIO;
							} 
							NEX_TRACE("rdma_write to rkey=0x%x hdr.opcode=%d hdr.remote_addr=0x%" PRIxPTR
									" addr=0x%" PRIxPTR " mr_len=%u qp_pair=%u:%u",
									hdr.rkey, hdr.opcode, dest, mr->vmr.ibv_mr.addr, mr->vmr.ibv_mr.length,
									qp->vqp.qp.qp_num, qp->remote_qp_num);
                        }
					}
				}
				if (status)
					NEX_TRACE("rdma_write failure status=%d qp_pair=%u:%u",
								status, qp->vqp.qp.qp_num, qp->remote_qp_num);
			}

			if (hdr.opcode == NEX_MSG_RDMA_WRITE_IMM) {
				NEX_TRACE("rx processing rdma_write_imm wr_id=%" PRIu64 " imm_data=0x%x len=%u status=%d qp_pair=%u:%u",
							hdr.wr_id, hdr.imm_data, hdr.length, status,
							qp->vqp.qp.qp_num, qp->remote_qp_num);

				struct nex_recv_entry entry_copy;

				if (!fiber_try_take_recv(qp, &entry_copy)) {
					// If no posted RECV
					payload = NULL;
					NEX_ERROR("rdma_write_imm without posted recv, wr_id=%" PRIu64 " qp_pair=%u:%u",
								hdr.wr_id, qp->vqp.qp.qp_num, qp->remote_qp_num);
					fflush(stderr);
					exit(1);
					break;
				}

				/*
				 * RDMA_WRITE_WITH_IMM consumes a receive WQE only to deliver
				 * the immediate-data completion.  Its payload was already
				 * streamed to hdr.remote_addr above; it is never copied into
				 * the receive WQE's SGE.  Reading it again here consumes the
				 * next wire header and corrupts framing.
				 */
				NEX_TRACE("RDMA_WRITE recved match wr_id=%" PRIu64
					  " opcode=%u len=%u qp_pair=%u:%u",
					  entry_copy.wr_id, hdr.opcode,
					  zero_len_imm ? 0 : hdr.length,
					  qp->vqp.qp.qp_num, qp->remote_qp_num);

					enum ibv_wc_status wc_status;
					if (status != 0) {
						wc_status = IBV_WC_REM_ACCESS_ERR;
					} else {
						wc_status = IBV_WC_SUCCESS;
					}

				/* IB semantics: for RDMA_WRITE_WITH_IMM the consumed recv
				 * completes with byte_len = length of the written payload,
				 * whether or not the recv WR carried an SGE (the data goes
				 * to the sender-named (rkey, remote_addr), not the recv
				 * buffer). Consumers (e.g. UCCL rc_rx_chunk) accumulate
				 * wc->byte_len, so reporting 0 for sge-less recvs loses
				 * the payload size. */
				struct ibv_wc recv_wc = {
					.wr_id    = entry_copy.wr_id,
					.status   = wc_status,
					.opcode   = IBV_WC_RECV_RDMA_WITH_IMM,
					.byte_len = zero_len_imm ? 0 : hdr.length,
					.qp_num   = qp->vqp.qp.qp_num,
					.src_qp   = qp->remote_qp_num,
					.imm_data = hdr.imm_data,
					.wc_flags = IBV_WC_WITH_IMM,
				};
				fiber_cq_push(qp->recv_cq, &recv_wc);
            // No prefetch used; nothing to free
			} else {
				// Plain RDMA_WRITE: nothing to signal on RX.
				// No prefetch used; nothing to free
			}
			break;
		}

        case NEX_MSG_RDMA_READ_REQ: {
            /* Consume the small request payload and wait for completion
             * so the request transfer is modeled before crafting RESP. */
            if (NEX_RDMA_READ_REQ_PLD > 0) {
                uint8_t req_buf[NEX_RDMA_READ_REQ_PLD];
                struct iovec iov = {
                    .iov_base = (void *)req_buf,
                    .iov_len  = (size_t)NEX_RDMA_READ_REQ_PLD,
                };
                /* apply_perf=1, wait_completion=true */
				if (fiber_read_fullv(qp->rx_fd, &iov, 1,
								   (size_t)NEX_RDMA_READ_REQ_PLD,
								   1, true, NULL, hdr.reserved) != 0) {
                    NEX_ERROR("rdma_read_req payload recv failed qp_pair=%u:%u",
                              qp->vqp.qp.qp_num, qp->remote_qp_num);
                }
            }
            struct nex_msg_hdr resp = {
                .opcode = NEX_MSG_RDMA_READ_RESP,
                .status = NEX_MSG_STATUS_OK,
                .wr_id = hdr.wr_id,
                .remote_addr = 0,
				.rkey = 0,
				.length = hdr.length,
			};
			uint8_t *resp_buf = NULL;
			struct nex_mr *mr = fiber_find_mr(qp->ctx, hdr.rkey);
			if (!mr || !(mr->vmr.access & IBV_ACCESS_REMOTE_READ)) {
				resp.status = NEX_MSG_STATUS_REMOTE_ERROR;
				resp.length = 0;
				NEX_ERROR("rdma_read remote error: invalid rkey=0x%x qp_pair=%u:%u",
							hdr.rkey, qp->vqp.qp.qp_num, qp->remote_qp_num);
			} else {
				uintptr_t base = (uintptr_t)mr->vmr.ibv_mr.addr;
				uintptr_t end = base + mr->vmr.ibv_mr.length;
				uintptr_t src = hdr.remote_addr;
				if (src < base || src + hdr.length > end) {
					resp.status = NEX_MSG_STATUS_REMOTE_ERROR;
					resp.length = 0;
					NEX_ERROR("rdma_read remote error: invalid rkey=0x%x qp_pair=%u:%u",
							hdr.rkey, qp->vqp.qp.qp_num, qp->remote_qp_num);
				} else if (hdr.length) {
					resp_buf = (uint8_t *)src;
				}
			}
			struct iovec resp_iov = {
				.iov_base = resp_buf,
				.iov_len = resp.length,
			};
            int tx_slot = -1;
			if (fiber_send_msg(qp, &resp,
                             (resp.length && resp_buf) ? &resp_iov : NULL,
                             (resp.length && resp_buf) ? 1 : 0,
                             resp.length,
                             false,
				     &tx_slot)) {
				NEX_ERROR("failed to send rdma_read_resp qp_pair=%u:%u",
					  qp->vqp.qp.qp_num, qp->remote_qp_num);
				if (nex_use_tcp_backend())
					nex_tcp_shutdown(qp->tx_fd);
				else
					nex_shm_shutdown(qp->tx_fd);
				fiber_rx_fail_pending_recvs(qp);
				fiber_rx_fail_pending_rdma(qp);
				should_exit = true;
			}
			
			NEX_TRACE("rdma_read_resp sent wr_id=%" PRIu64 " len=%u qp_pair=%u:%u",
					   resp.wr_id, resp.length,
					   qp->vqp.qp.qp_num, qp->remote_qp_num);

			if (payload_from_pending)
				free(payload);
			break;
		}
		case NEX_MSG_RDMA_READ_RESP: {
            struct nex_pending_read *entry = nex_take_pending_read(qp, hdr.wr_id);
            if (!entry) {
                NEX_ERROR("rdma_read_resp with no pending read wr_id=%" PRIu64 " qp_pair=%u:%u",
						   hdr.wr_id, qp->vqp.qp.qp_num, qp->remote_qp_num);
				free(entry);
                break;
            }
            struct ibv_wc read_wc = {
                .wr_id = hdr.wr_id,
                .status = (hdr.status == NEX_MSG_STATUS_OK) ?
                          IBV_WC_SUCCESS : IBV_WC_REM_ACCESS_ERR,
				.opcode = entry->wc_opcode,
                .byte_len = hdr.length,
                .qp_num = qp->vqp.qp.qp_num,
            };
            if (read_wc.status == IBV_WC_SUCCESS && hdr.length) {
                struct iovec iov[NEX_MAX_SGE];
                int iovcnt = 0;
                size_t remaining = hdr.length;
                for (int i = 0; i < entry->num_sge && remaining; ++i) {
                    size_t len = entry->sge[i].length;
                    if (len > remaining) len = remaining;
                    if (len == 0) continue;
                    iov[iovcnt].iov_base = (void *)(uintptr_t)entry->sge[i].addr;
                    iov[iovcnt].iov_len  = len;
                    ++iovcnt;
                    remaining -= len;
                }
                if (remaining == 0) {
					uint64_t start_ns = now_ns();
					if (fiber_read_fullv(qp->rx_fd, iov, iovcnt, hdr.length, 1, true, NULL, hdr.reserved) != 0) {
                        read_wc.status = IBV_WC_REM_ACCESS_ERR;
						NEX_ERROR("rdma_read_resp read_fullv failed hdr.length=%u qp_pair=%u:%u",
								   hdr.length, qp->vqp.qp.qp_num, qp->remote_qp_num);
                    }

					uint64_t dur_ns = now_ns()-start_ns;

					// futher modeling should be added
					// 130ns per MTU (1024 bytes) + 100ns per MTU PCIe delay
					// why - dur_ns? because packet processing is parallelized with transmission.
					int delay_ns = hdr.length/1024 * (40 + 60) - dur_ns;
					// if(delay_ns > 0){
					// 	int quantum_ns = EPOCH_DUR;
					// 	if(delay_ns > 10000) quantum_ns = 1000;  
					// 	int sched_cnt = delay_ns / quantum_ns;
					// 	NEX_TRACE("rdma_read_resp modeling delay for hdr.length=%u, delay_ns=%d, dur_ns=%d",
					// 				hdr.length, delay_ns, dur_ns);
					// 	for(int i=0; i<sched_cnt; i++){
					// 		sched_yield();
					// 	}
					// 	NEX_TRACE("rdma_read_resp modeling delay finish");
					// }
					
                } else {
					NEX_ERROR("rdma_read_resp length mismatch wr_id=%" PRIu64 " qp_pair=%u:%u",
							   hdr.wr_id, qp->vqp.qp.qp_num, qp->remote_qp_num);
                }
            }
			NEX_TRACE("rdma_read_resp recv complete wr_id=%" PRIu64 " len=%u status=%u qp_pair=%u:%u",
					   hdr.wr_id, hdr.length, read_wc.status,
					   qp->vqp.qp.qp_num, qp->remote_qp_num);
			bool report_completion = entry->completion_requested || read_wc.status != IBV_WC_SUCCESS;
			if (report_completion)
				fiber_cq_push(qp->send_cq, &read_wc);
            free(entry);
            break;
        }
		case NEX_MSG_ATOMIC_FETCH_ADD_REQ: {
			struct nex_msg_hdr resp = {
				.opcode = NEX_MSG_ATOMIC_FETCH_ADD_RESP,
				.status = NEX_MSG_STATUS_OK,
				.wr_id = hdr.wr_id,
				.length = sizeof(uint64_t),
			};
			uint64_t old_value = 0;
			struct nex_mr *mr = fiber_find_mr(qp->ctx, hdr.rkey);
			uintptr_t dest = (uintptr_t)hdr.remote_addr;
			if (!mr || !(mr->vmr.access & IBV_ACCESS_REMOTE_ATOMIC)) {
				resp.status = NEX_MSG_STATUS_REMOTE_ERROR;
				resp.length = 0;
			} else {
				uintptr_t base = (uintptr_t)mr->vmr.ibv_mr.addr;
				uintptr_t end = base + mr->vmr.ibv_mr.length;
				if (end < base || dest < base || dest > end ||
				    end - dest < sizeof(uint64_t) ||
				    (dest & (sizeof(uint64_t) - 1)) != 0) {
					resp.status = NEX_MSG_STATUS_REMOTE_ERROR;
					resp.length = 0;
				} else {
					old_value = __atomic_fetch_add((uint64_t *)dest,
							hdr.atomic_operand, __ATOMIC_SEQ_CST);
				}
			}

			struct iovec resp_iov = {
				.iov_base = &old_value,
				.iov_len = resp.length,
			};
			int tx_slot = -1;
			if (fiber_send_msg(qp, &resp,
					   resp.length ? &resp_iov : NULL,
					   resp.length ? 1 : 0, resp.length,
					   true, &tx_slot)) {
				NEX_ERROR("failed to send fetch-add response qp_pair=%u:%u",
					  qp->vqp.qp.qp_num, qp->remote_qp_num);
				if (nex_use_tcp_backend())
					nex_tcp_shutdown(qp->tx_fd);
				else
					nex_shm_shutdown(qp->tx_fd);
				fiber_rx_fail_pending_recvs(qp);
				fiber_rx_fail_pending_rdma(qp);
				should_exit = true;
			}
			break;
		}
		case NEX_MSG_ATOMIC_FETCH_ADD_RESP: {
			struct nex_pending_read *entry =
				nex_take_pending_read(qp, hdr.wr_id);
			if (!entry) {
				NEX_ERROR("fetch-add response with no pending operation wr_id=%" PRIu64,
					  hdr.wr_id);
				break;
			}
			struct ibv_wc atomic_wc = {
				.wr_id = hdr.wr_id,
				.status = hdr.status == NEX_MSG_STATUS_OK
					? IBV_WC_SUCCESS : IBV_WC_REM_ACCESS_ERR,
				.opcode = entry->wc_opcode,
				.byte_len = hdr.length,
				.qp_num = qp->vqp.qp.qp_num,
			};
			if (atomic_wc.status == IBV_WC_SUCCESS) {
				if (entry->num_sge != 1 || entry->total_len != sizeof(uint64_t) ||
				    hdr.length != sizeof(uint64_t)) {
					atomic_wc.status = IBV_WC_LOC_LEN_ERR;
				} else {
					struct iovec iov = {
						.iov_base = (void *)(uintptr_t)entry->sge[0].addr,
						.iov_len = sizeof(uint64_t),
					};
					if (fiber_read_fullv(qp->rx_fd, &iov, 1,
							    sizeof(uint64_t), 1, true, NULL,
							    hdr.reserved) != 0)
						atomic_wc.status = IBV_WC_REM_ACCESS_ERR;
				}
			}
			if (entry->completion_requested ||
			    atomic_wc.status != IBV_WC_SUCCESS)
				fiber_cq_push(qp->send_cq, &atomic_wc);
			free(entry);
			break;
		}
		default:
			   NEX_TRACE("unknown opcode %u qp_pair=%u:%u", hdr.opcode,
				   qp->vqp.qp.qp_num, qp->remote_qp_num);
			if (payload_from_pending)
				free(payload);
			should_exit = true;
			break;
		}
		if (should_exit)
			break;
	
		gx_fiber_yield();
	}

	free(payload_buf);
	fiber_pthread_spin_lock(&qp->lock);
	qp->rx_running = false;
	fiber_pthread_spin_unlock(&qp->lock);
	pthread_mutex_lock(&qp->state_lock);
	qp->rx_worker_done = true;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
	return;
}

// should replace this with real test; don't know how to handle yet
static char *fiber_get_service_id(struct nex_qp* qp)
{
	struct nex_context* ctx = qp->ctx;
	int lid = ctx->lid;
	char* service_id = calloc(128, 1);
	snprintf(service_id, 128, "%u:%u:%u:%u", lid, qp->remote_lid, qp->vqp.qp.qp_num, qp->remote_qp_num);
	return service_id;
}

/* Determine local host address that would be used to reach the given peer.
 * peer_host: pointer to peer hostname or IP string
 * peer_port: peer port number
 * out: buffer to fill with textual address
 * outlen: length of out buffer
 * Returns 0 on success (out filled), -1 on failure (out may be "unknown").
 */
static int fiber_get_local_host_for_peer(const char *peer_host, unsigned peer_port, char *out, size_t outlen)
{
	if (!out || outlen == 0) return -1;
	out[0] = '\0';
	if (!peer_host || !peer_host[0]) {
		strncpy(out, "unknown", outlen);
		return -1;
	}

	struct addrinfo hints = {0}, *res = NULL;
	char portbuf[16];
	snprintf(portbuf, sizeof(portbuf), "%u", peer_port);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(peer_host, portbuf, &hints, &res) != 0)
		goto fail;

	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		int s = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
		if (s < 0)
			continue;
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
			if (ai->ai_family == AF_INET) {
				struct sockaddr_in local;
				socklen_t llen = sizeof(local);
				if (getsockname(s, (struct sockaddr*)&local, &llen) == 0) {
					inet_ntop(AF_INET, &local.sin_addr, out, outlen);
					close(s);
					freeaddrinfo(res);
					return 0;
				}
			} else if (ai->ai_family == AF_INET6) {
				struct sockaddr_in6 local6;
				socklen_t llen = sizeof(local6);
				if (getsockname(s, (struct sockaddr*)&local6, &llen) == 0) {
					inet_ntop(AF_INET6, &local6.sin6_addr, out, outlen);
					close(s);
					freeaddrinfo(res);
					return 0;
				}
			}
		}
		close(s);
	}
	freeaddrinfo(res);
fail:
	strncpy(out, "unknown", outlen);
	return -1;
}

// Establish connection to remote QP
// - use TCP socket to exchange connection info (QP number, port) via nex_cm
// - create socket pair for data transfer
// central server assigns role (listen/connect) to each side, and match the pairs
static int fiber_qp_establish_sync(struct nex_qp *qp)
{
	/* after role is determined */
	char* service_id = fiber_get_service_id(qp);
	int unified_fd = -1;
	int err = 0;

	int rc = nex_use_tcp_backend()
		 ? nex_tcp_dial(service_id, &unified_fd)
		 : nex_shm_dial(service_id, &unified_fd);
	if (rc != 0) {
		NEX_TRACE("backend dial failed service_id=%s error=%d",
			   service_id, rc);
		return rc;
	}	

	NEX_TRACE("backend ready service_id=%s unified_fd=%d qp_pair=%u:%u",
			service_id, unified_fd, qp->vqp.qp.qp_num, qp->remote_qp_num);

	qp->tx_fd = unified_fd;
	qp->rx_fd = unified_fd;
	qp->rx_running = true;

	err = fiber_start_qp_workers(qp);
	if (err != 0)
		goto shm_worker_fail;
	return 0;

shm_worker_fail:
	fiber_pthread_spin_lock(&qp->lock);
	qp->rx_running = false;
	fiber_pthread_spin_unlock(&qp->lock);
	atomic_store_explicit(&qp->tx_running, false, memory_order_release);
	if (unified_fd >= 0) {
		if (nex_use_tcp_backend()) {
			nex_tcp_shutdown(unified_fd);
			nex_tcp_close(unified_fd);
		} else {
			nex_shm_shutdown(unified_fd);
			nex_shm_close(unified_fd);
		}
	}
	qp->tx_fd = qp->rx_fd = -1;
	return err ? err : EIO;
}

/* Global QP reservation (per device; cross processes) -------------------------------- */
static int nex_qp_reserve(struct nex_qp *qp)
{
    struct nex_context *ctx = qp->ctx;

    if (!ctx->qp_counter && nex_map_qp_counter(ctx) != 0)
        return 0; /* best effort if shared counter unavailable */

    if (!ctx->qp_counter)
        return 0;

    uint32_t new = __sync_add_and_fetch(ctx->qp_counter, 1);
    uint32_t limit = ctx->qp_limit ? ctx->qp_limit : NEX_DEFAULT_MAX_QP;
    if (new > limit) {
		NEX_ERROR("QP limit exceeded (%u) new=%u", limit, new);
        __sync_sub_and_fetch(ctx->qp_counter, 1);
        errno = ENOSPC;
        return -1;
    }
    return 0;
}

static void nex_qp_release(struct nex_qp *qp)
{
    struct nex_context *ctx = qp->ctx;
    if (ctx->qp_counter)
        __sync_sub_and_fetch(ctx->qp_counter, 1);
}

/* Address handle stubs -------------------------------------------------- */

static struct ibv_ah *nex_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	(void)pd;
	(void)attr;
	return calloc(1, sizeof(struct ibv_ah));
}

static int nex_destroy_ah(struct ibv_ah *ah)
{
	free(ah);
	return 0;
}

/* Context management ---------------------------------------------------- */

static void nex_free_context(struct ibv_context *ibctx)
{
	struct nex_context *ctx = to_nctx(ibctx);
	if (ctx->qp_counter) {
		munmap(ctx->qp_counter, sizeof(uint32_t));
		ctx->qp_counter = NULL;
	}
	if (ctx->qp_counter_fd >= 0) {
		close(ctx->qp_counter_fd);
		ctx->qp_counter_fd = -1;
	}
	pthread_spin_lock(&ctx->mr_lock);
	struct nex_mr *mr = ctx->mr_list;
	while (mr) {
		struct nex_mr *next = mr->next;
		free(mr);
		mr = next;
	}
	ctx->mr_list = NULL;
	pthread_spin_unlock(&ctx->mr_lock);
	pthread_spin_destroy(&ctx->mr_lock);
	gx_sched_release();
	verbs_uninit_context(&ctx->ibv_ctx);
	free(ctx);
}

static const struct verbs_context_ops nex_ctx_ops = {
	.query_device_ex = nex_query_device,
	.query_port = nex_query_port,
	.alloc_pd = nex_alloc_pd,
	.dealloc_pd = nex_dealloc_pd,
	.reg_mr = nex_reg_mr,
	.reg_dmabuf_mr = nex_reg_dmabuf_mr,
	.dereg_mr = nex_dereg_mr,
	.create_cq = nex_create_cq,
	.create_cq_ex = nex_create_cq_ex,
	.destroy_cq = nex_destroy_cq,
	.poll_cq = nex_poll_cq,
	.req_notify_cq = nex_req_notify_cq,
	.create_srq = nex_create_srq,
	.destroy_srq = nex_destroy_srq,
	.query_srq = nex_query_srq,
	.post_srq_recv = nex_post_srq_recv,
	.create_qp = nex_create_qp,
	.create_qp_ex = nex_create_qp_ex,
	.destroy_qp = nex_destroy_qp,
	.modify_qp = nex_modify_qp,
	.query_qp = nex_query_qp,
	.post_send = nex_post_send,
	.post_recv = nex_post_recv,
	.create_ah = nex_create_ah,
	.destroy_ah = nex_destroy_ah,
	.free_context = nex_free_context,
};

/* Device matching ------------------------------------------------------- */

static const struct verbs_match_ent hca_table[] = {
	VERBS_NAME_MATCH("gx", NULL),
	{},
};

static bool nex_match_device(struct verbs_sysfs_dev *sysfs_dev)
{
	if (!strncmp(sysfs_dev->ibdev_name, "gx", 2)) {
		sysfs_dev->match = &hca_table[0];
		return true;
	}
	return false;
}

/* Device allocation ----------------------------------------------------- */

static struct verbs_context *nex_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd, void *private_data)
{
	struct nex_context *ctx;
	
	if (get_accvm_symbols(&accvm_syms) != 0) {
    	fprintf(stderr, "Error: required ACCVM symbols not available\n");
    	return NULL;
  	}

	if (gx_sched_acquire() != 0) {
		fprintf(stderr, "Error: failed to initialize ACCVM fiber scheduler\n");
		return NULL;
	}

	// MACRO
	ctx = verbs_init_and_alloc_context(ibdev, cmd_fd, ctx, ibv_ctx,
					       RDMA_DRIVER_UNKNOWN);
	if (!ctx) {
		gx_sched_release();
		return NULL;
	}

	struct ibv_get_context cmd = {};
	struct ib_uverbs_get_context_resp resp = {};
	if (ibv_cmd_get_context(&ctx->ibv_ctx, &cmd, sizeof(cmd), NULL,
					&resp, sizeof(resp))) {
		free(ctx);
		gx_sched_release();
		return NULL;
	}

	atomic_init(&ctx->next_handle, 1);
	atomic_init(&ctx->next_key, 1);
	atomic_init(&ctx->next_port, 0);
    ctx->qp_counter_fd = -1;
    ctx->qp_counter = NULL;
    ctx->qp_limit = NEX_DEFAULT_MAX_QP;
    pthread_spin_init(&ctx->mr_lock, PTHREAD_PROCESS_PRIVATE);
    ctx->mr_list = NULL;
    const char *env_limit = getenv("GX_MAX_QP");
    if (env_limit && *env_limit) {
        long v = strtol(env_limit, NULL, 10);
        if (v > 0 && v < INT32_MAX)
            ctx->qp_limit = (uint32_t)v;
    }
    nex_map_qp_counter(ctx);

	int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (efd >= 0)
		ctx->ibv_ctx.context.async_fd = efd;

	verbs_set_ops(&ctx->ibv_ctx, &nex_ctx_ops);

	ctx->lid = get_nex_id()+0x1000; // avoid 0 lid
	return &ctx->ibv_ctx;
}

static void nex_uninit_device(struct verbs_device *verbs_device)
{
	struct nex_device *dev = to_ndev(&verbs_device->device);
	free(dev);
}

static struct verbs_device *nex_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	(void)sysfs_dev;
	struct nex_device *dev = calloc(1, sizeof(*dev));
	return dev ? &dev->ibv_dev : NULL;
}

static const struct verbs_device_ops nex_dev_ops = {
	.name = "gx",
	/* Match the kernel uverbs_abi_ver below (currently 1) */
	.match_min_abi_version = 1,
	.match_max_abi_version = 1,
	.match_table = hca_table,
	.match_device = nex_match_device,
	.alloc_device = nex_device_alloc,
	.uninit_device = nex_uninit_device,
	.alloc_context = nex_alloc_context,
};

PROVIDER_DRIVER(nex, nex_dev_ops);
