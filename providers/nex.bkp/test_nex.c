/*
 * NEX RDMA Provider Test Program
 *
 * Simple test to verify NEX provider functionality
 *
 * Copyright (c) 2025 NEX Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <infiniband/verbs.h>

#define TEST_MSG "Hello from NEX RDMA Emulation!"

int main(int argc, char *argv[])
{
	struct ibv_device **dev_list;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_init_attr;
	struct ibv_qp_attr qp_attr;
	int ret;

	/* Get device list */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		fprintf(stderr, "Failed to get device list\n");
		return 1;
	}

	/* Find NEX device */
	dev = NULL;
	for (int i = 0; dev_list[i]; ++i) {
		if (strstr(ibv_get_device_name(dev_list[i]), "nex")) {
			dev = dev_list[i];
			break;
		}
	}

	if (!dev) {
		fprintf(stderr, "NEX device not found\n");
		ibv_free_device_list(dev_list);
		return 1;
	}

	printf("Found NEX device: %s\n", ibv_get_device_name(dev));

	/* Open device context */
	ctx = ibv_open_device(dev);
	if (!ctx) {
		fprintf(stderr, "Failed to open device context\n");
		ibv_free_device_list(dev_list);
		return 1;
	}

	/* Allocate protection domain */
	pd = ibv_alloc_pd(ctx);
	if (!pd) {
		fprintf(stderr, "Failed to allocate PD\n");
		goto cleanup_ctx;
	}

	/* Register memory region */
	char *buf = malloc(4096);
	if (!buf) {
		fprintf(stderr, "Failed to allocate buffer\n");
		goto cleanup_pd;
	}

	mr = ibv_reg_mr(pd, buf, 4096, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (!mr) {
		fprintf(stderr, "Failed to register MR\n");
		goto cleanup_buf;
	}

	/* Create completion queue */
	cq = ibv_create_cq(ctx, 10, NULL, NULL, 0);
	if (!cq) {
		fprintf(stderr, "Failed to create CQ\n");
		goto cleanup_mr;
	}

	/* Create queue pair */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = cq;
	qp_init_attr.recv_cq = cq;
	qp_init_attr.cap.max_send_wr = 10;
	qp_init_attr.cap.max_recv_wr = 10;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.qp_type = IBV_QPT_RC;

	qp = ibv_create_qp(pd, &qp_init_attr);
	if (!qp) {
		fprintf(stderr, "Failed to create QP\n");
		goto cleanup_cq;
	}

	/* Modify QP to INIT state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = 1;
	qp_attr.pkey_index = 0;
	qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
	if (ret) {
		fprintf(stderr, "Failed to modify QP to INIT: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	/* Modify QP to RTR state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	qp_attr.path_mtu = IBV_MTU_1024;
	qp_attr.dest_qp_num = qp->qp_num;  /* Loopback for testing */
	qp_attr.rq_psn = 0;
	qp_attr.max_dest_rd_atomic = 1;
	qp_attr.min_rnr_timer = 12;

	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
	if (ret) {
		fprintf(stderr, "Failed to modify QP to RTR: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	/* Modify QP to RTS state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTS;
	qp_attr.sq_psn = 0;
	qp_attr.timeout = 14;
	qp_attr.retry_cnt = 7;
	qp_attr.rnr_retry = 7;
	qp_attr.max_rd_atomic = 1;

	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
	if (ret) {
		fprintf(stderr, "Failed to modify QP to RTS: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	/* Test basic memory copy */
	strcpy(buf, TEST_MSG);
	printf("Buffer content: %s\n", buf);

	/* Post send request */
	struct ibv_send_wr send_wr = {};
	struct ibv_sge send_sge = {};

	send_sge.addr = (uintptr_t)buf;
	send_sge.length = strlen(TEST_MSG) + 1;
	send_sge.lkey = mr->lkey;

	send_wr.wr_id = 1;
	send_wr.sg_list = &send_sge;
	send_wr.num_sge = 1;
	send_wr.opcode = IBV_WR_SEND;
	send_wr.send_flags = IBV_SEND_SIGNALED;

	struct ibv_send_wr *bad_send_wr;
	ret = ibv_post_send(qp, &send_wr, &bad_send_wr);
	if (ret) {
		fprintf(stderr, "Failed to post send: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	/* Poll for completion */
	struct ibv_wc wc;
	int num_comp;
	do {
		num_comp = ibv_poll_cq(cq, 1, &wc);
	} while (num_comp == 0);

	if (num_comp < 0) {
		fprintf(stderr, "Failed to poll CQ\n");
		goto cleanup_qp;
	}

	if (wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Send failed with status %d\n", wc.status);
		goto cleanup_qp;
	}

	printf("✅ NEX RDMA provider test completed successfully!\n");
	printf("   - Device: %s\n", ibv_get_device_name(dev));
	printf("   - QP Number: %d\n", qp->qp_num);
	printf("   - Send completed with status: %d\n", wc.status);

cleanup_qp:
	ibv_destroy_qp(qp);
cleanup_cq:
	ibv_destroy_cq(cq);
cleanup_mr:
	ibv_dereg_mr(mr);
cleanup_buf:
	free(buf);
cleanup_pd:
	ibv_dealloc_pd(pd);
cleanup_ctx:
	ibv_close_device(ctx);
	ibv_free_device_list(dev_list);

	return ret ? 1 : 0;
}