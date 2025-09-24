/*
 * NEX RDMA Emulation Provider Header
 *
 * This provider implements RDMA emulation over TCP/IP stack
 * instead of using real InfiniBand hardware.
 *
 * Copyright (c) 2025 NEX Project
 */

#ifndef NEX_H
#define NEX_H

#include <infiniband/driver.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include "nex-abi.h"

#define NEX_MAX_INLINE_DATA 512
#define NEX_MAX_SGE 16
#define NEX_DEFAULT_PORT 12345

/* NEX device structure */
struct nex_device {
	struct verbs_device ibv_dev;
	int abi_version;
	char *device_name;
};

/* NEX context structure */
struct nex_context {
	struct verbs_context ibv_ctx;
	int tcp_sock;  /* TCP socket for communication */
	struct sockaddr_in server_addr;
	pthread_mutex_t lock;
};

/* NEX completion queue */
struct nex_cq {
	struct verbs_cq vcq;
	struct nex_wc *wc_queue;
	uint32_t queue_size;
	uint32_t head;
	uint32_t tail;
	pthread_spinlock_t lock;
};

/* NEX work completion */
struct nex_wc {
	uint64_t wr_id;
	enum ibv_wc_status status;
	enum ibv_wc_opcode opcode;
	uint32_t vendor_err;
	uint32_t byte_len;
	uint32_t imm_data;
	uint32_t qp_num;
	uint32_t src_qp;
	uint16_t pkey_index;
	uint16_t slid;
	uint8_t sl;
	uint8_t dlid_path_bits;
};

/* NEX queue pair */
struct nex_qp {
	struct verbs_qp vqp;
	uint32_t qp_num;
	uint32_t remote_qp_num;
	struct nex_context *ctx;
	struct nex_cq *send_cq;
	struct nex_cq *recv_cq;

	/* Queue state */
	enum ibv_qp_state state;
	uint32_t qkey;

	/* Send/Receive queues */
	struct nex_wq *sq;
	struct nex_wq *rq;

	/* Connection info */
	int conn_sock;  /* Connected TCP socket */
	struct sockaddr_in remote_addr;
};

/* NEX work queue */
struct nex_wq {
	void *buf;
	size_t buf_size;
	uint32_t head;
	uint32_t tail;
	uint32_t max_sge;
	uint32_t max_inline;
	pthread_spinlock_t lock;
};

/* NEX memory region */
struct nex_mr {
	struct verbs_mr vmr;
	void *buf;
	size_t size;
	uint32_t lkey;
	uint32_t rkey;
};

/* NEX address handle */
struct nex_ah {
	struct ibv_ah ibv_ah;
	uint16_t dlid;
	uint8_t sl;
	uint8_t src_path_bits;
	uint8_t static_rate;
	uint8_t ah_num;
};

/* NEX shared receive queue */
struct nex_srq {
	struct verbs_srq vsrq;
	struct nex_wq *rq;
	uint32_t srq_num;
};

/* Utility functions */
static inline struct nex_context *to_nctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct nex_context, ibv_ctx);
}

static inline struct nex_device *to_ndev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct nex_device, ibv_dev);
}

static inline struct nex_cq *to_ncq(struct ibv_cq *ibcq)
{
	return container_of(ibcq, struct nex_cq, vcq);
}

static inline struct nex_qp *to_nqp(struct ibv_qp *ibqp)
{
	return container_of(ibqp, struct nex_qp, vqp);
}

static inline struct nex_mr *to_nmr(struct ibv_mr *ibmr)
{
	return container_of(ibmr, struct nex_mr, vmr);
}

static inline struct nex_ah *to_nah(struct ibv_ah *ibah)
{
	return container_of(ibah, struct nex_ah, ibv_ah);
}

static inline struct nex_srq *to_nsrq(struct ibv_srq *ibsrq)
{
	return container_of(ibsrq, struct nex_srq, vsrq);
}

/* TCP communication functions */
int nex_tcp_connect(struct nex_context *ctx, const char *host, int port);
int nex_tcp_send(struct nex_qp *qp, void *data, size_t size);
int nex_tcp_recv(struct nex_qp *qp, void *data, size_t size);
int nex_tcp_listen(struct nex_context *ctx, int port);
int nex_tcp_accept(struct nex_context *ctx);

/* RDMA operation emulation */
int nex_emulate_send(struct nex_qp *qp, struct ibv_send_wr *wr);
int nex_emulate_recv(struct nex_qp *qp, struct ibv_recv_wr *wr);
int nex_emulate_write(struct nex_qp *qp, struct ibv_send_wr *wr);
int nex_emulate_read(struct nex_qp *qp, struct ibv_send_wr *wr);

#endif /* NEX_H */