/*
 * NEX RDMA Emulation Provider Header
 *
 * Minimal in-process RDMA semantics implemented completely in user space.
 */

#ifndef NEX_H
#define NEX_H

#include <infiniband/driver.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>

#define NEX_MAX_SGE           8

struct nex_device {
	struct verbs_device ibv_dev;
};

struct nex_mr;

struct nex_context {
	struct verbs_context ibv_ctx;
	atomic_uint next_handle;
	atomic_uint next_key;
	atomic_uint next_port;
    int qp_counter_fd;
    uint32_t *qp_counter;
    uint32_t qp_limit;
    pthread_spinlock_t mr_lock;
    struct nex_mr *mr_list;
	int gid;
	int lid;
};

struct nex_pd {
	struct ibv_pd ibv_pd;
};

struct nex_cq {
	struct verbs_cq vcq;
	struct ibv_wc *entries;
	uint32_t capacity;
	uint32_t head;
	uint32_t tail;
	pthread_spinlock_t lock;
	pthread_cond_t cond;
};

struct nex_recv_entry {
	uint64_t wr_id;
	struct ibv_sge sge;
};

struct nex_pending_msg;

struct nex_pending_read {
	uint64_t wr_id;
	int num_sge;
	size_t total_len;
	struct ibv_sge sge[NEX_MAX_SGE];
	struct nex_pending_read *next;
};

struct nex_qp {
	struct verbs_qp vqp;
	struct nex_context *ctx;
	struct nex_cq *send_cq;
	struct nex_cq *recv_cq;
	pthread_spinlock_t lock;
	pthread_cond_t recv_cond;
	struct nex_recv_entry *recv_queue;
	uint32_t recv_size;
	uint32_t recv_head;
	uint32_t recv_tail;
	int tx_fd;
	int rx_fd;
	bool rx_running;
	pthread_t rx_thread;
	uint32_t remote_qp_num;
	uint32_t remote_lid;
	pthread_spinlock_t send_lock;
	uint8_t *send_buf;
	size_t send_buf_capacity;
	pthread_spinlock_t rdma_lock;
	struct nex_pending_read *pending_reads;
	pthread_mutex_t state_lock;
	pthread_cond_t state_cond;
	bool connect_in_progress;
	int connect_status;
	bool connect_thread_valid;
	
	struct nex_pending_msg *pending_head;
	struct nex_pending_msg *pending_tail;
	pthread_spinlock_t pending_lock;

	pthread_t connect_thread;
};

struct nex_mr {
	struct verbs_mr vmr;
	struct nex_mr *next;
};

/*
 * Convert libibverbs public objects back to our provider-private containers.
 * These must walk through the verbs_* wrappers, not jump directly.
 */
static inline struct nex_context *to_nctx(struct ibv_context *ibctx)
{
    struct verbs_context *vctx = container_of(ibctx, struct verbs_context, context);
    return container_of(vctx, struct nex_context, ibv_ctx);
}

static inline struct nex_device *to_ndev(struct ibv_device *ibdev)
{
    struct verbs_device *vdev = container_of(ibdev, struct verbs_device, device);
    return container_of(vdev, struct nex_device, ibv_dev);
}

static inline struct nex_pd *to_npd(struct ibv_pd *pd)
{
	return container_of(pd, struct nex_pd, ibv_pd);
}

static inline struct nex_cq *to_ncq(struct ibv_cq *ibcq)
{
	return container_of(ibcq, struct nex_cq, vcq.cq);
}

static inline struct nex_qp *to_nqp(struct ibv_qp *ibqp)
{
	return container_of(ibqp, struct nex_qp, vqp.qp);
}

static inline struct nex_mr *to_nmr(struct ibv_mr *ibmr)
{
	return container_of(ibmr, struct nex_mr, vmr.ibv_mr);
}

#endif /* NEX_H */
