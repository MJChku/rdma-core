/*
 * NEX RDMA Provider - userspace RDMA semantics over a local software queue
 */

#include <config.h>
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
#include "cm/nex_cm.h"

// #define USE_TCP

static int get_nex_id(void);

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// #define DEBUG
#define NEX_ERROR(fmt, ...) fprintf(stderr, "ERROR: nex (%d, %lu us): " fmt "\n", get_nex_id(), now_ns() / 1000, ##__VA_ARGS__)

#ifdef DEBUG
#define NEX_TRACE_TIMING(fmt, ...) fprintf(stderr, "nex (%d, %lu us): " fmt "\n", get_nex_id(), now_ns() / 1000, ##__VA_ARGS__)
#define NEX_TRACE(fmt, ...) fprintf(stderr, "nex (%d, %lu ms): " fmt "\n", get_nex_id(), now_ns() / 1000000, ##__VA_ARGS__)
#else
#define NEX_TRACE_TIMING(fmt, ...) do { } while (0)
#define NEX_TRACE(fmt, ...) do { } while (0)
#endif

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
};

enum nex_msg_status {
	NEX_MSG_STATUS_OK = 0,
	NEX_MSG_STATUS_REMOTE_ERROR = 1,
};

struct nex_msg_hdr {
	uint32_t opcode;
	uint32_t status;
	uint64_t wr_id;
	uint64_t remote_addr;
	uint32_t rkey;
	uint32_t length;
	uint32_t imm_data;
	uint32_t reserved;
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
	const char* env_p = getenv("NEX_ID");
	if(env_p == NULL){
		return nex_id;
	}
	nex_id = atoi(env_p);
	
	__atomic_thread_fence(__ATOMIC_RELEASE);

	__atomic_store_n(&initialized, 1, __ATOMIC_RELEASE);

	return nex_id;
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

static int nex_write_full(int fd, const void *buf, size_t len, int apply_perf)
{
#ifdef USE_TCP
	const uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
#else
	ssize_t n = nex_shm_write(fd, buf, len, apply_perf);
	if (n != len) {
		NEX_TRACE("nex_shm_write failed n=%zd len=%zu errno=%d", n, len, errno);
		return -1;
	}
#endif

	return 0;
}

static int nex_write_fullv(int fd, const struct iovec *iov, int iovcnt,
		   size_t total_len, int apply_perf, bool wait_completion, int *slot_out)
{
	if (!iov || iovcnt <= 0 || total_len == 0) {
		if (slot_out)
			*slot_out = -1;
		return 0;
	}

#ifdef USE_TCP
	(void)apply_perf;
	const int stack_cap = NEX_MAX_SGE;
	struct iovec stack_iov[stack_cap];
	struct iovec *local = stack_iov;

	if (iovcnt > stack_cap) {
		local = malloc((size_t)iovcnt * sizeof(*local));
		if (!local)
			return -1;
	}

	memcpy(local, iov, (size_t)iovcnt * sizeof(*local));

	size_t remaining = total_len;
	int idx = 0;
	while (remaining > 0) {
		ssize_t n = writev(fd, &local[idx], iovcnt - idx);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (local != stack_iov)
				free(local);
			return -1;
		}
		if (n == 0) {
			if (local != stack_iov)
				free(local);
			return -1;
		}

		remaining -= (size_t)n;

		ssize_t consumed = n;
		while (idx < iovcnt && consumed > 0) {
			if (consumed >= (ssize_t)local[idx].iov_len) {
				consumed -= (ssize_t)local[idx].iov_len;
				++idx;
			} else {
				local[idx].iov_base =
					(uint8_t *)local[idx].iov_base + consumed;
				local[idx].iov_len -= (size_t)consumed;
				consumed = 0;
			}
		}
	}

	if (local != stack_iov)
		free(local);
	if (slot_out)
		*slot_out = -1;
#else
	ssize_t n = nex_shm_writev(fd, iov, iovcnt, apply_perf, wait_completion, slot_out);
	if (n < 0 || (size_t)n != total_len)
		return -1;
#endif

	return 0;
}

static int nex_read_full(int fd, void *buf, size_t len, int apply_perf)
{
#ifdef USE_TCP
	uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
#else 
	ssize_t n = nex_shm_read(fd, buf, len, apply_perf);
	if (n != len) return -1;
#endif
	return 0;
}

static int nex_map_qp_counter(struct nex_context *ctx)
{
	if (ctx->qp_counter)
		return 0;
	const char *dev_name = ctx->ibv_ctx.context.device->name;
	char shm_name[128];
	snprintf(shm_name, sizeof(shm_name), "/nex_qpcnt_%s", dev_name);
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

static void nex_cq_push(struct nex_cq *cq, const struct ibv_wc *wc)
{
	pthread_spin_lock(&cq->lock);
	uint32_t next_tail = (cq->tail + 1) % cq->capacity;
	if (next_tail == cq->head) {
		/* Drop completion on overflow */
		pthread_spin_unlock(&cq->lock);
		NEX_TRACE("WARNING: cq overflow dropping completion wr_id=%" PRIu64,
			(uint64_t)wc->wr_id);
		return;
	}
	cq->entries[cq->tail] = *wc;
	cq->tail = next_tail;
       NEX_TRACE("cq_push wr_id=%" PRIu64 " opcode=%u status=%u len=%u qp_local=%u",
	       (uint64_t)wc->wr_id, wc->opcode, wc->status, wc->byte_len,
	       wc->qp_num);
	pthread_spin_unlock(&cq->lock);
}

static int nex_cq_pop(struct nex_cq *cq, int num_entries, struct ibv_wc *wc)
{
	int produced = 0;
	accvm_syms.compressT(2000.0f);
	accvm_syms.changeEpoch(250, 4);
	pthread_spin_lock(&cq->lock);
	while (produced < num_entries && cq->head != cq->tail) {
		wc[produced++] = cq->entries[cq->head];
		cq->head = (cq->head + 1) % cq->capacity;
	}
	pthread_spin_unlock(&cq->lock);
	accvm_syms.compressT(1.0f);
	NEX_TRACE_TIMING("nex_cq_pop produced=%d/%d", produced, num_entries);
	return produced;
}

static void *nex_rx_worker(void *arg);
static int nex_send_msg(struct nex_qp *qp, const struct nex_msg_hdr *hdr,
                        const struct iovec *payload_iov,
                        int payload_iovcnt, size_t payload_len,
						bool wait_completion,
                        int* out_slot);

static struct nex_mr *nex_find_mr(struct nex_context *ctx, uint32_t rkey);
static int nex_add_pending_read(struct nex_qp *qp, uint64_t wr_id,
			      const struct ibv_sge *sg_list, int num_sge,
			      size_t total_len);
static struct nex_pending_read *nex_take_pending_read(struct nex_qp *qp,
					       uint64_t wr_id);
static struct ibv_mr *nex_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
			       uint64_t length, uint64_t iova, int fd, int access);
static int nex_qp_establish_sync(struct nex_qp *qp);
static int nex_qp_start_connect(struct nex_qp *qp);
static int nex_qp_wait_connected(struct nex_qp *qp);
static int nex_qp_reserve(struct nex_qp *qp);
static void nex_qp_release(struct nex_qp *qp);

static bool nex_qp_has_peer_addr(const struct nex_qp *qp)
{
	return qp->remote_qp_num != 0 && qp->remote_lid != 0;
}

static bool nex_try_take_recv(struct nex_qp *qp, struct nex_recv_entry *out)
{
    bool ok = false;
    pthread_spin_lock(&qp->lock);
    if (qp->recv_head != qp->recv_tail) {
        struct nex_recv_entry *entry = &qp->recv_queue[qp->recv_head];
        qp->recv_head = (qp->recv_head + 1) % qp->recv_size;
        *out = *entry;
        ok = true;
    }
    pthread_spin_unlock(&qp->lock);
    return ok;
}


static void nex_push_pending_msg(struct nex_qp *qp, const struct nex_msg_hdr *hdr,
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
	pthread_spin_lock(&qp->pending_lock);
	if (qp->pending_tail)
		qp->pending_tail->next = msg;
	else
		qp->pending_head = msg;
	qp->pending_tail = msg;
	pthread_spin_unlock(&qp->pending_lock);
}

static struct nex_pending_msg *nex_pop_pending_msg(struct nex_qp *qp) {
	struct nex_pending_msg *msg = NULL;
	pthread_spin_lock(&qp->pending_lock);
	if (qp->pending_head) {
		msg = qp->pending_head;
		qp->pending_head = msg->next;
		if (qp->pending_head == NULL)
			qp->pending_tail = NULL;
	}
	pthread_spin_unlock(&qp->pending_lock);
	return msg;
}

static struct nex_mr *nex_find_mr(struct nex_context *ctx, uint32_t rkey)
{
	struct nex_mr *mr = NULL;
	pthread_spin_lock(&ctx->mr_lock);
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
	pthread_spin_unlock(&ctx->mr_lock);

	if(count_match > 1){
		NEX_ERROR("rkey=%u matched %d MRs, returning first match", rkey, count_match);
	}
	return mr;
}

static int nex_add_pending_read(struct nex_qp *qp, uint64_t wr_id,
			      const struct ibv_sge *sg_list, int num_sge,
			      size_t total_len)
{
	struct nex_pending_read *entry = calloc(1, sizeof(*entry));
	if (!entry) {
		errno = ENOMEM;
		return ENOMEM;
	}
	entry->wr_id = wr_id;
	entry->num_sge = num_sge;
	entry->total_len = total_len;
	for (int i = 0; i < num_sge; ++i)
		entry->sge[i] = sg_list[i];
	pthread_spin_lock(&qp->rdma_lock);
	entry->next = qp->pending_reads;
	qp->pending_reads = entry;
	pthread_spin_unlock(&qp->rdma_lock);
	return 0;
}

static struct nex_pending_read *nex_take_pending_read(struct nex_qp *qp,
					       uint64_t wr_id)
{
	struct nex_pending_read *entry = NULL;
	pthread_spin_lock(&qp->rdma_lock);
	struct nex_pending_read **prev = &qp->pending_reads;
	while (*prev && (*prev)->wr_id != wr_id)
		prev = &(*prev)->next;
	if (*prev) {
		entry = *prev;
		*prev = entry->next;
	}
	pthread_spin_unlock(&qp->rdma_lock);
	return entry;
}

static int nex_send_msg(struct nex_qp *qp, const struct nex_msg_hdr *hdr,
                        const struct iovec *payload_iov,
                        int payload_iovcnt, size_t payload_len,
                        bool wait_completion,
                        int* out_slot)
{
    int rc = 0;
    pthread_spin_lock(&qp->send_lock);
    if (nex_write_full(qp->tx_fd, hdr, sizeof(*hdr), 0))  // header: no perf model
        rc = errno ? errno : EIO;
    if (!rc && payload_len && payload_iovcnt > 0 && payload_iov) {
        if (nex_write_fullv(qp->tx_fd, payload_iov, payload_iovcnt,
                            payload_len, 1, wait_completion, out_slot))  // payload: apply perf model (non-blocking)
            rc = errno ? errno : EIO;
    }
    pthread_spin_unlock(&qp->send_lock);
    return rc;
}

static void nex_txq_push(struct nex_qp* qp, uint64_t wr_id, enum ibv_wc_opcode op, uint32_t len, int slot, bool signaled)
{
    for (;;) {
        pthread_spin_lock(&qp->tx_lock);
        uint32_t next = (qp->tx_tail + 1) % qp->tx_qsize;
        if (next != qp->tx_head) {
            qp->tx_queue[qp->tx_tail].wr_id = wr_id;
            qp->tx_queue[qp->tx_tail].wc_op = op;
            qp->tx_queue[qp->tx_tail].byte_len = len;
            qp->tx_queue[qp->tx_tail].slot = slot;
			qp->tx_queue[qp->tx_tail].signaled = signaled;
            qp->tx_tail = next;
            pthread_spin_unlock(&qp->tx_lock);
			NEX_TRACE_TIMING("nex_txq_push pushed wr_id=%" PRIu64 " opcode=%u len=%u",
				(uint64_t)wr_id, op, len);
            return;
        }
        pthread_spin_unlock(&qp->tx_lock);
		NEX_TRACE_TIMING("nex_txq_push waiting for free space");
    }
}

static bool nex_txq_pop(struct nex_qp* qp, struct nex_tx_entry* out)
{
    for (;;) {
        pthread_spin_lock(&qp->tx_lock);
        if (qp->tx_head != qp->tx_tail) {
            *out = qp->tx_queue[qp->tx_head];
            qp->tx_head = (qp->tx_head + 1) % qp->tx_qsize;
            pthread_spin_unlock(&qp->tx_lock);
            return true;
        }
        bool running = qp->tx_running;
        pthread_spin_unlock(&qp->tx_lock);
        if (!running)
            return false;
        sched_yield();
    }
}

static void* nex_tx_worker(void* arg)
{
	accvm_syms.compressT(2000.0f);
    struct nex_qp* qp = arg;
    struct nex_tx_entry entry;
    while (nex_txq_pop(qp, &entry)) {
        if (entry.slot >= 0)
            accvm_syms.wait_for_completion((uint32_t)entry.slot);
        struct ibv_wc wc = {
            .wr_id = entry.wr_id,
            .status = IBV_WC_SUCCESS,
            .opcode = entry.wc_op,
            .byte_len = entry.byte_len,
            .qp_num = qp->vqp.qp.qp_num,
        };
		if(entry.signaled){
	        nex_cq_push(qp->send_cq, &wc);
		}
		NEX_TRACE_TIMING("nex_tx_worker completed wr_id=%" PRIu64 " opcode=%u len=%u",
			(uint64_t)wc.wr_id, wc.opcode, wc.byte_len);
    }
    return NULL;
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
	pthread_spin_init(&qp->send_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rdma_lock, PTHREAD_PROCESS_PRIVATE);
	qp->pending_reads = NULL;
	pthread_mutex_init(&qp->state_lock, NULL);
	pthread_cond_init(&qp->state_cond, NULL);
	qp->tx_fd = -1;
	qp->rx_fd = -1;
	qp->rx_running = false;
    qp->remote_qp_num = 0;
    qp->connect_in_progress = false;
    qp->connect_status = 0;
    qp->connect_thread_valid = false;

	qp->pending_head = qp->pending_tail = NULL;
	pthread_spin_init(&qp->pending_lock, PTHREAD_PROCESS_PRIVATE);

	// init tx completion machinery
	uint32_t send_wr = attr->cap.max_send_wr;
	if (send_wr == 0)
		send_wr = 64;
	qp->tx_qsize = send_wr + 1;
	qp->tx_queue = calloc(qp->tx_qsize, sizeof(*qp->tx_queue));
	if (!qp->tx_queue) {
		pthread_spin_destroy(&qp->pending_lock);
		pthread_mutex_destroy(&qp->state_lock);
		pthread_cond_destroy(&qp->state_cond);
		pthread_spin_destroy(&qp->rdma_lock);
		pthread_spin_destroy(&qp->send_lock);
		pthread_spin_destroy(&qp->lock);
		free(qp->recv_queue);
		free(qp);
		errno = ENOMEM;
		return NULL;
	}
	qp->tx_head = qp->tx_tail = 0;
	pthread_spin_init(&qp->tx_lock, PTHREAD_PROCESS_PRIVATE);
	qp->tx_running = false;
	qp->tx_thread = 0;

	qp->ctx = ctx;
	qp->send_cq = send_cq;
	qp->recv_cq = recv_cq;

	qp->vqp.qp.context = pd->context;
	qp->vqp.qp.qp_context = attr->qp_context;
	qp->vqp.qp.pd = pd;
	qp->vqp.qp.send_cq = attr->send_cq;
	qp->vqp.qp.recv_cq = attr->recv_cq;
	// shared receive queue (SRQ) is an optional feature that allows multiple QPs to share a single receive queue
	// not supported here
	qp->vqp.qp.srq = attr->srq;
	qp->vqp.qp.handle = nex_next_handle(ctx);
	qp->vqp.qp.qp_num = nex_next_handle(ctx);
	qp->vqp.qp.qp_type = attr->qp_type;
	qp->vqp.qp.state = IBV_QPS_RESET;
	pthread_mutex_init(&qp->vqp.qp.mutex, NULL);
	pthread_cond_init(&qp->vqp.qp.cond, NULL);

    if (nex_qp_reserve(qp)) {
        pthread_spin_destroy(&qp->lock);
        pthread_spin_destroy(&qp->send_lock);
        pthread_spin_destroy(&qp->rdma_lock);
        pthread_mutex_destroy(&qp->state_lock);
        pthread_cond_destroy(&qp->state_cond);
        pthread_spin_destroy(&qp->pending_lock);
        pthread_spin_destroy(&qp->tx_lock);
        free(qp->tx_queue);
        pthread_mutex_destroy(&qp->vqp.qp.mutex);
        pthread_cond_destroy(&qp->vqp.qp.cond);
        free(qp->recv_queue);
        free(qp);
	NEX_TRACE("create_qp: nex_qp_reserve failed");
        return NULL;
    }

    return &qp->vqp.qp;
}

static int nex_destroy_qp(struct ibv_qp *ibqp)
{
    struct nex_qp *qp = to_nqp(ibqp);
    nex_qp_release(qp);
    if (qp->rx_running) {
        pthread_spin_lock(&qp->lock);
        qp->rx_running = false;
        pthread_spin_unlock(&qp->lock);
		#ifdef USE_TCP
		if (qp->rx_fd >= 0)
			shutdown(qp->rx_fd, SHUT_RDWR);
		if (qp->tx_fd >= 0)
			shutdown(qp->tx_fd, SHUT_RDWR);
		#else
		int shm_fd = qp->tx_fd >= 0 ? qp->tx_fd : qp->rx_fd;
		if (shm_fd >= 0)
			nex_shm_shutdown(shm_fd);
		#endif

		pthread_join(qp->rx_thread, NULL);
	}
	#ifdef USE_TCP
	if (qp->tx_fd >= 0)
		close(qp->tx_fd);
	if (qp->rx_fd >= 0)
		close(qp->rx_fd);
#else
	if (qp->tx_fd >= 0) {
		nex_shm_close(qp->tx_fd);
		qp->tx_fd = -1;
		qp->rx_fd = -1;
	} else if (qp->rx_fd >= 0) {
		/* Safety: handle hypothetical cases where tx/rx differ. */
		nex_shm_close(qp->rx_fd);
		qp->rx_fd = -1;
	}
	#endif

    // stop tx worker
    pthread_spin_lock(&qp->tx_lock);
    qp->tx_running = false;
    pthread_spin_unlock(&qp->tx_lock);
    if (qp->tx_thread) {
        pthread_join(qp->tx_thread, NULL);
        qp->tx_thread = 0;
    }

	pthread_spin_destroy(&qp->lock);
	pthread_spin_destroy(&qp->send_lock);
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
	if (qp->connect_thread_valid) {
		pthread_join(qp->connect_thread, NULL);
		qp->connect_thread_valid = false;
	}
	pthread_mutex_destroy(&qp->state_lock);
	pthread_cond_destroy(&qp->state_cond);
	pthread_mutex_destroy(&qp->vqp.qp.mutex);
	pthread_cond_destroy(&qp->vqp.qp.cond);
	pthread_spin_lock(&qp->pending_lock);
	struct nex_pending_msg *pmsg = qp->pending_head;
	while (pmsg) {
		struct nex_pending_msg *next = pmsg->next;
		free(pmsg->payload);
		free(pmsg);
		pmsg = next;
	}
	qp->pending_head = qp->pending_tail = NULL;
	pthread_spin_unlock(&qp->pending_lock);
    pthread_spin_destroy(&qp->pending_lock);
    pthread_spin_destroy(&qp->tx_lock);
    free(qp->tx_queue);
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

static void *nex_connect_thread(void *arg)
{
	struct nex_qp *qp = arg;
	int rc = nex_qp_establish_sync(qp);
	pthread_mutex_lock(&qp->state_lock);
	qp->connect_status = rc;
	qp->connect_in_progress = false;
	pthread_cond_broadcast(&qp->state_cond);
	pthread_mutex_unlock(&qp->state_lock);
	return NULL;
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

	int rc = pthread_create(&qp->connect_thread, NULL, nex_connect_thread, qp);
	if (rc) {
		// if rc is non-zero, the thread creation failed
		pthread_mutex_lock(&qp->state_lock);
		qp->connect_in_progress = false;
		qp->connect_status = rc;
		pthread_cond_broadcast(&qp->state_cond);
		pthread_mutex_unlock(&qp->state_lock);
		return rc;
	}
	qp->connect_thread_valid = true;
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

	accvm_syms.compressT(2000.0f);
	accvm_syms.changeEpoch(250, 16);

	// iterate through work requests (wr)
	// wr has next and sg_list (scatter-gather list)
	// each sg_list has addr, length, lkey
	NEX_TRACE_TIMING("nex_post_recv produced");

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
	accvm_syms.compressT(1.0f);
	return 0;
}

static int nex_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{

	accvm_syms.compressT(2000.0f);
	accvm_syms.changeEpoch(250, 16);

	struct nex_qp *qp = to_nqp(ibqp);
	NEX_TRACE_TIMING("nex_post_send produced");

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

		bool signaled = (wr->send_flags & IBV_SEND_SIGNALED) != 0;

	    NEX_TRACE("post_send wr_id=%" PRIu64 " opcode=%u num_sge=%d qp_pair=%u:%u signaled=%d",
		       (uint64_t)wr->wr_id, wr->opcode, wr->num_sge,
		       qp->vqp.qp.qp_num, qp->remote_qp_num, signaled);

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
		};

		int rc = 0;
		size_t payload_len = total_len;
		struct iovec payload_iov[NEX_MAX_SGE];
		int payload_iovcnt = 0;

		bool wait_completion = true;

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
		case IBV_WR_RDMA_READ:
			hdr.opcode = NEX_MSG_RDMA_READ_REQ;
			hdr.remote_addr = wr->wr.rdma.remote_addr;
			hdr.rkey = wr->wr.rdma.rkey;
			hdr.length = (uint32_t)total_len;
			payload_len = 0;
			wait_completion = false;
			rc = nex_add_pending_read(qp, wr->wr_id, wr->sg_list,
					      wr->num_sge, total_len);
			if (rc) {
				if (bad_wr)
					*bad_wr = wr;
				errno = rc;
				NEX_ERROR("post_send add_pending_read failed");
				goto ERROR_OUT;
			}
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

        // bool wait_completion = signaled;
		// occupy slots in tx queue
        int tx_slot = -1;
        rc = nex_send_msg(qp, &hdr,
                          payload_iovcnt ? payload_iov : NULL,
                          payload_iovcnt, payload_len,
                          wait_completion,
                          &tx_slot);
        if (rc) {
            if (wr->opcode == IBV_WR_RDMA_READ) {
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

        if (wr->opcode == IBV_WR_RDMA_READ)
            continue;

        // if (signaled) {
		// everyone here needs to wait for completion
            enum ibv_wc_opcode wc_op =
                (wr->opcode == IBV_WR_RDMA_WRITE || wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
                    ? IBV_WC_RDMA_WRITE
                    : IBV_WC_SEND;
            nex_txq_push(qp, wr->wr_id, wc_op, (uint32_t)total_len, tx_slot, signaled);
        // }
	}

	accvm_syms.compressT(1.0f);
	return 0;

ERROR_OUT:
	accvm_syms.compressT(1.0f);
	return errno;
}

static void *nex_rx_worker(void *arg)
{
	
	accvm_syms.compressT(2000.0f);

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
		
		struct nex_pending_msg *pending = nex_pop_pending_msg(qp);
		if (pending) {
			hdr = pending->hdr;
			payload = pending->payload;
			payload_from_pending = true;
			   NEX_TRACE("replay pending hdr wr_id=%" PRIu64 " opcode=%u len=%u status=%u qp_pair=%u:%u",
				   hdr.wr_id, hdr.opcode, hdr.length, hdr.status,
				   qp->vqp.qp.qp_num, qp->remote_qp_num);
			free(pending);
		} else {
			// get header then get payload
			if (!qp->rx_running)
				break;
			if (nex_read_full(qp->rx_fd, &hdr, sizeof(hdr), 0))  // header: no perf model
				break;
			accvm_syms.changeEpoch(250, 16);

            bool expect_payload = (hdr.opcode == NEX_MSG_SEND ||
                                    hdr.opcode == NEX_MSG_RDMA_WRITE ||
                                    hdr.opcode == NEX_MSG_RDMA_WRITE_IMM);
			
			   NEX_TRACE("rx header wr_id=%" PRIu64 " opcode=%u len=%u status=%u hdr.length=%u qp_pair=%u:%u",
				   hdr.wr_id, hdr.opcode, hdr.length, hdr.status, hdr.length,
				   qp->vqp.qp.qp_num, qp->remote_qp_num);

			if (expect_payload && hdr.length) {
				// Reuse or grow buffer
				if (hdr.length > payload_capacity) {
					size_t new_capacity = hdr.length;
					if (new_capacity < initial_capacity)
						new_capacity = initial_capacity;
					uint8_t *new_buf = realloc(payload_buf, new_capacity);
					if (!new_buf)
						break;
					payload_buf = new_buf;
					payload_capacity = new_capacity;
				}
				if (nex_read_full(qp->rx_fd, payload_buf, hdr.length, 1))  // payload: apply perf model
					break;
				payload = payload_buf;
				NEX_TRACE("read completed: rx payload wr_id=%" PRIu64 " len=%u qp_pair=%u:%u",
					   hdr.wr_id, hdr.length, qp->vqp.qp.qp_num, qp->remote_qp_num);
			}
		}

		bool should_exit = false;
		switch (hdr.opcode) {
		case NEX_MSG_SEND: {
			struct nex_recv_entry entry_copy;
			size_t copy_len = 0;
			bool have_recv = false;

			if (!nex_try_take_recv(qp, &entry_copy)) {
				/* No RECV posted yet: queue for later and continue */
				fprintf(stderr, "ERROR: send without posted recv, wr_id=%" PRIu64 " qp_pair=%u:%u", hdr.wr_id,
					   qp->vqp.qp.qp_num, qp->remote_qp_num);
				fflush(stderr);
				exit(1);
				// nex_push_pending_msg(qp, &hdr, payload, payload_len);
				payload = NULL; 
				break;
			}
			
			NEX_TRACE("recv match wr_id=%" PRIu64 " opcode=%u len=%u qp_pair=%u:%u",
				   entry_copy.wr_id, hdr.opcode, hdr.length,
				   qp->vqp.qp.qp_num, qp->remote_qp_num);

			if (hdr.length && payload) {
				copy_len = hdr.length;
				if (copy_len > entry_copy.sge.length)
					copy_len = entry_copy.sge.length;
				// DOTO, optimize, no memcpy.
				memcpy((void *)(uintptr_t)entry_copy.sge.addr, payload, copy_len);
			}

			struct ibv_wc recv_wc = {
				.wr_id = entry_copy.wr_id,
				.status = copy_len == hdr.length ?
					IBV_WC_SUCCESS : IBV_WC_LOC_LEN_ERR,
				.opcode = IBV_WC_RECV,
				.byte_len = (uint32_t)copy_len,
				.qp_num = qp->vqp.qp.qp_num,
			};
			nex_cq_push(qp->recv_cq, &recv_wc);
			if (payload_from_pending)
				free(payload);
			break;
		}
		case NEX_MSG_RDMA_WRITE:
		case NEX_MSG_RDMA_WRITE_IMM: {
			int status = 0;
			size_t copy_len = 0;
			bool zero_len_imm = (hdr.opcode == NEX_MSG_RDMA_WRITE_IMM && hdr.length == 0);

			/*
			* Fast-path: zero-byte RDMA_WRITE_WITH_IMM is a "doorbell".
			* Do NOT validate rkey/addr and do NOT touch memory.
			* We only need to generate a successful RECV_RDMA_WITH_IMM CQE.
			*/
			if (!zero_len_imm) {
				struct nex_mr *mr = NULL;
				if (hdr.length) {
					mr = nex_find_mr(qp->ctx, hdr.rkey);
					if (!mr || !(mr->vmr.access & IBV_ACCESS_REMOTE_WRITE)) {
						status = -EACCES;
					} else {
						uintptr_t base = (uintptr_t)mr->vmr.ibv_mr.addr;
						uintptr_t end  = base + mr->vmr.ibv_mr.length;
						uintptr_t dest = hdr.remote_addr;

						NEX_TRACE("rdma_write to rkey=0x%x hdr.opcode=%d hdr.remote_addr=0x%" PRIxPTR
									" addr=0x%" PRIxPTR " mr_len=%u header_len=%u qp_pair=%u:%u",
									hdr.rkey, hdr.opcode, dest, mr->vmr.ibv_mr.addr, mr->vmr.ibv_mr.length, hdr.length,
									qp->vqp.qp.qp_num, qp->remote_qp_num);

						if (dest < base || dest + hdr.length > end) {
							status = -EINVAL;
						} else if (payload && hdr.length) {
							memcpy((void *)dest, payload, hdr.length);
							copy_len = hdr.length;
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

				if (!nex_try_take_recv(qp, &entry_copy)) {
					// If no posted RECV
					payload = NULL;
					NEX_ERROR("rdma_write_imm without posted recv, wr_id=%" PRIu64 " qp_pair=%u:%u",
								hdr.wr_id, qp->vqp.qp.qp_num, qp->remote_qp_num);
					fflush(stderr);
					exit(1);
					break;
				}

				NEX_TRACE("recv match wr_id=%" PRIu64 " opcode=%u len=%u qp_pair=%u:%u",
							entry_copy.wr_id, hdr.opcode, zero_len_imm ? 0 : hdr.length,
							qp->vqp.qp.qp_num, qp->remote_qp_num);

				if (!zero_len_imm) {
					if (hdr.length && payload && entry_copy.sge.length) {
						copy_len = hdr.length;
						if (copy_len > entry_copy.sge.length)
							copy_len = entry_copy.sge.length;
						memcpy((void *)(uintptr_t)entry_copy.sge.addr, payload, copy_len);
					}
				} else {
					copy_len = 0;
				}

				enum ibv_wc_status wc_status;
				if (status != 0) {
					wc_status = IBV_WC_REM_ACCESS_ERR;
				} else if (!zero_len_imm &&
							entry_copy.sge.length && hdr.length && copy_len != hdr.length) {
					wc_status = IBV_WC_LOC_LEN_ERR;
				} else {
					wc_status = IBV_WC_SUCCESS;
				}

				struct ibv_wc recv_wc = {
					.wr_id    = entry_copy.wr_id,
					.status   = wc_status,
					.opcode   = IBV_WC_RECV_RDMA_WITH_IMM,
					.byte_len = zero_len_imm ? 0 :
								(entry_copy.sge.length ? (uint32_t)copy_len : 0),
					.qp_num   = qp->vqp.qp.qp_num,
					.imm_data = hdr.imm_data,
				};
				nex_cq_push(qp->recv_cq, &recv_wc);
				if (payload_from_pending)
					free(payload);
			} else {
				// Plain RDMA_WRITE: nothing to signal on RX.
				if (payload_from_pending)
					free(payload);
			}
			break;
		}

		case NEX_MSG_RDMA_READ_REQ: {
			struct nex_msg_hdr resp = {
				.opcode = NEX_MSG_RDMA_READ_RESP,
				.status = NEX_MSG_STATUS_OK,
				.wr_id = hdr.wr_id,
				.remote_addr = 0,
				.rkey = 0,
				.length = hdr.length,
			};
			uint8_t *resp_buf = NULL;
			struct nex_mr *mr = nex_find_mr(qp->ctx, hdr.rkey);
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
            if (nex_send_msg(qp, &resp,
                             (resp.length && resp_buf) ? &resp_iov : NULL,
                             (resp.length && resp_buf) ? 1 : 0,
                             resp.length,
                             false,
                             &tx_slot))
                   NEX_TRACE("failed to send rdma_read_resp qp_pair=%u:%u",
                           qp->vqp.qp.qp_num, qp->remote_qp_num);

			if (payload_from_pending)
				free(payload);
			break;
		}
        case NEX_MSG_RDMA_READ_RESP: {
            struct nex_pending_read *entry = nex_take_pending_read(qp, hdr.wr_id);
            if (!entry) {
                // Consume and drop payload to keep ring in sync if any
                if (hdr.length) {
                    if (hdr.length > payload_capacity) {
                        size_t new_capacity = hdr.length;
                        if (new_capacity < initial_capacity)
                            new_capacity = initial_capacity;
                        uint8_t *new_buf = realloc(payload_buf, new_capacity);
                        if (!new_buf)
                            break;
                        payload_buf = new_buf;
                        payload_capacity = new_capacity;
                    }
                    (void)nex_read_full(qp->rx_fd, payload_buf, hdr.length, 1);
                }
                break;
            }
            struct ibv_wc read_wc = {
                .wr_id = hdr.wr_id,
                .status = (hdr.status == NEX_MSG_STATUS_OK) ?
                          IBV_WC_SUCCESS : IBV_WC_REM_ACCESS_ERR,
                .opcode = IBV_WC_RDMA_READ,
                .byte_len = 0,
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
                    int slot = -1;
                    ssize_t n = nex_shm_readv(qp->rx_fd, iov, iovcnt, 1, true, &slot);
                    if (n < 0 || (size_t)n != hdr.length) {
                        read_wc.status = IBV_WC_REM_ACCESS_ERR;
                    } else {
                        read_wc.byte_len = (uint32_t)n;
                    }
                } else {
                    read_wc.status = IBV_WC_REM_ACCESS_ERR;
                }
            }
            nex_cq_push(qp->send_cq, &read_wc);
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
	}

	free(payload_buf);
	pthread_spin_lock(&qp->lock);
	qp->rx_running = false;
	pthread_spin_unlock(&qp->lock);
	return NULL;
}

// should replace this with real test; don't know how to handle yet
static char *nex_get_service_id(struct nex_qp* qp)
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
static int nex_get_local_host_for_peer(const char *peer_host, unsigned peer_port, char *out, size_t outlen)
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
static int nex_qp_establish_sync(struct nex_qp *qp)
{

#ifdef USE_TCP
	int listen_fd = -1;
	uint16_t listen_port = 0;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	struct nex_cm_peer peer;
	int role;
	char* service_id = nex_get_service_id(qp);

	NEX_TRACE("qp_establish qpn=%u service=%s qp_pair=%u:%u",
		   qp->vqp.qp.qp_num, service_id, qp->vqp.qp.qp_num, qp->remote_qp_num);

	if (qp->tx_fd >= 0 && qp->rx_fd >= 0)
		return 0;

	listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listen_fd < 0)
		return errno ? errno : EIO;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = 0;
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		goto close_listen;
	if (listen(listen_fd, 1) != 0)
		goto close_listen;
	if (getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) != 0)
		goto close_listen;

	listen_port = ntohs(addr.sin_port);

	NEX_TRACE("listen on port %u qp_pair=%u:%u", listen_port, qp->vqp.qp.qp_num, qp->remote_qp_num);
	// contact cm server
	if (nex_cm_exchange(service_id, qp->vqp.qp.qp_num, listen_port, &peer, &role) != 0 || !peer.host[0])
		goto close_listen;

	char my_host[INET6_ADDRSTRLEN];
	if (nex_get_local_host_for_peer(peer.host, peer.port, my_host, sizeof(my_host)) != 0) {
		/* my_host already set to "unknown" by helper on failure */
	}
	NEX_TRACE("cm matched service_id=%s, peer_qpn=%u my_host=%s peer_host=%s port=%u role=%d qp_pair=%u:%u",
		   service_id, peer.qp_num, my_host, peer.host, peer.port, role, qp->vqp.qp.qp_num, peer.qp_num);

	int data_fd = -1;

	if (role == NEX_CM_ROLE_LISTEN) {
		data_fd = accept(listen_fd, NULL, NULL);
		if (data_fd < 0)
			goto close_listen;
		close(listen_fd);
		listen_fd = -1;
		NEX_TRACE("accepted connection qp_pair=%u:%u", qp->vqp.qp.qp_num, qp->remote_qp_num);
	} else {
		char portbuf[16];
		struct addrinfo hints = {
			.ai_family = AF_INET,
			.ai_socktype = SOCK_STREAM
		};
		struct addrinfo *res = NULL;
		snprintf(portbuf, sizeof(portbuf), "%u", peer.port);
		close(listen_fd);
		listen_fd = -1;
		if (getaddrinfo(peer.host, portbuf, &hints, &res) != 0)
			return errno ? errno : EIO;
		int attempts = 50;
		while (attempts-- > 0 && data_fd < 0) {
			for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
				data_fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
				if (data_fd < 0)
					continue;
				if (connect(data_fd, ai->ai_addr, ai->ai_addrlen) == 0)
					break;
				int err = errno;
				close(data_fd);
				data_fd = -1;
				if (attempts > 0 && (err == ECONNREFUSED || err == ENETUNREACH || err == ETIMEDOUT))
					nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 2000000 }, NULL);
			}
		}
		freeaddrinfo(res);
		if (data_fd < 0)
			return errno ? errno : EIO;
		NEX_TRACE("connected to %s:%u qp_pair=%u:%u", peer.host, peer.port, qp->vqp.qp.qp_num, peer.qp_num);
	}


	qp->remote_qp_num = peer.qp_num;
	qp->tx_fd = data_fd;
	qp->rx_fd = data_fd;
	qp->rx_running = true;
    if (pthread_create(&qp->rx_thread, NULL, nex_rx_worker, qp)) {
        int err = errno ? errno : EIO;
        qp->rx_running = false;
        close(data_fd);
        qp->tx_fd = qp->rx_fd = -1;
        return err;
    }
    // start tx completion worker
    if (pthread_create(&qp->tx_thread, NULL, nex_tx_worker, qp)) {
        int err = errno ? errno : EIO;
        nex_shm_shutdown(unified_fd);
        pthread_join(qp->rx_thread, NULL);
        nex_shm_close(unified_fd);
		fprintf(stderr, "Failed to create tx thread\n");
		exit(1);

    }
    return 0;


close_listen:
	if (listen_fd >= 0)
		close(listen_fd);
	return errno ? errno : EIO;
#else

	/* after role is determined */
	struct nex_context* ctx = qp->ctx;
	char* service_id = nex_get_service_id(qp);
	int unified_fd = -1;

	int rc = nex_shm_dial(service_id, &unified_fd);
	if (rc != 0) {
		NEX_TRACE("SHM dial failed service_id=%s error=%d",
			   service_id, rc);
		return rc;
	}	

	NEX_TRACE("SHM ready service_id=%s unified_fd=%d qp_pair=%u:%u",
			service_id, unified_fd, qp->vqp.qp.qp_num, qp->remote_qp_num);

	qp->tx_fd = unified_fd;
	qp->rx_fd = unified_fd;
	qp->rx_running = true;
    if (pthread_create(&qp->rx_thread, NULL, nex_rx_worker, qp)) {
        int err = errno ? errno : EIO;
        qp->rx_running = false;
        nex_shm_close(unified_fd);
        qp->tx_fd = qp->rx_fd = -1;
        return err;
    }
    // start tx completion worker
    pthread_spin_lock(&qp->tx_lock);
    qp->tx_running = true;
    pthread_spin_unlock(&qp->tx_lock);
    if (pthread_create(&qp->tx_thread, NULL, nex_tx_worker, qp)) {
        int err = errno ? errno : EIO;
        nex_shm_shutdown(unified_fd);
        pthread_join(qp->rx_thread, NULL);
        nex_shm_close(unified_fd);
		fprintf(stderr, "Failed to create tx thread\n");
		exit(1);
    }
    return 0;

#endif
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
	.destroy_cq = nex_destroy_cq,
	.poll_cq = nex_poll_cq,
	.req_notify_cq = nex_req_notify_cq,
	.create_qp = nex_create_qp,
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
	VERBS_NAME_MATCH("nex", NULL),
	{},
};

static bool nex_match_device(struct verbs_sysfs_dev *sysfs_dev)
{
	if (!strncmp(sysfs_dev->ibdev_name, "nex", 3)) {
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
    	return -1;
  	}

	// MACRO
	ctx = verbs_init_and_alloc_context(ibdev, cmd_fd, ctx, ibv_ctx,
					       RDMA_DRIVER_UNKNOWN);
	if (!ctx)
		return NULL;

	struct ibv_get_context cmd = {};
	struct ib_uverbs_get_context_resp resp = {};
	if (ibv_cmd_get_context(&ctx->ibv_ctx, &cmd, sizeof(cmd), NULL,
					&resp, sizeof(resp))) {
		free(ctx);
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
    const char *env_limit = getenv("NEX_MAX_QP");
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
	.name = "nex",
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
