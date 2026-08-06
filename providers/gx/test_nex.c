/*
 * NEX RDMA Provider Test Program
 *
 * Simple test to verify NEX provider functionality
 *
 * Copyright (c) 2025 NEX Project
 */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <infiniband/verbs.h>

#define TEST_MSG "Hello from NEX RDMA Emulation!"

enum conn_mode {
	MODE_LOOPBACK,
	MODE_LISTEN,
	MODE_CONNECT
};

struct conn_config {
	enum conn_mode mode;
	char host[128];
	uint16_t port;
	bool use_cq_ex;
	bool cq_ex_create_only;
};

struct handshake_msg {
	uint32_t qp_num;
	uint32_t rkey;
	uint16_t lid;
	uint16_t reserved;
	uint64_t atomic_addr;
};

static int parse_endpoint(const char *arg, char *host, size_t host_sz, uint16_t *port)
{
	const char *colon = strrchr(arg, ':');
	if (!colon || colon == arg)
		return -1;
	size_t len = (size_t)(colon - arg);
	if (len >= host_sz)
		len = host_sz - 1;
	memcpy(host, arg, len);
	host[len] = '\0';
	char *endptr = NULL;
	long p = strtol(colon + 1, &endptr, 10);
	if (!endptr || *endptr != '\0' || p <= 0 || p > 65535)
		return -1;
	*port = (uint16_t)p;
	return 0;
}

static int send_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len) {
		ssize_t n = send(fd, p, len, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	while (len) {
		ssize_t n = recv(fd, p, len, 0);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int exchange_conn_listen(const struct conn_config *cfg,
				uint32_t local_qp, uint32_t local_rkey,
				uint16_t local_lid,
				uint64_t local_atomic_addr,
				uint32_t *remote_qp, uint32_t *remote_rkey,
				uint16_t *remote_lid,
				uint64_t *remote_atomic_addr)
{
	char portbuf[16];
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE
	};
	struct addrinfo *res = NULL;
	snprintf(portbuf, sizeof(portbuf), "%u", cfg->port);
	int rc = getaddrinfo(cfg->host[0] ? cfg->host : "127.0.0.1", portbuf, &hints, &res);
	if (rc)
		return -1;
	int listen_fd = -1;
	int conn_fd = -1;
	int ret = -1;
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (listen_fd < 0)
			continue;
		int opt = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		if (bind(listen_fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		perror("bind");
		close(listen_fd);
		listen_fd = -1;
	}
	freeaddrinfo(res);
	if (listen_fd < 0)
		return -1;
	if (listen(listen_fd, 1) < 0) {
		perror("listen");
		goto out;
	}
	conn_fd = accept(listen_fd, NULL, NULL);
	if (conn_fd < 0) {
		perror("accept");
		goto out;
	}

	struct handshake_msg msg = {
		.qp_num = htonl(local_qp),
		.rkey = htonl(local_rkey),
		.lid = htons(local_lid),
		.atomic_addr = htobe64(local_atomic_addr),
	};
	if (send_all(conn_fd, &msg, sizeof(msg)) ||
	    recv_all(conn_fd, &msg, sizeof(msg))) {
		perror("exchange");
		goto out;
	}
	*remote_qp = ntohl(msg.qp_num);
	*remote_rkey = ntohl(msg.rkey);
	*remote_lid = ntohs(msg.lid);
	*remote_atomic_addr = be64toh(msg.atomic_addr);
	ret = 0;
out:
	if (conn_fd >= 0)
		close(conn_fd);
	if (listen_fd >= 0)
		close(listen_fd);
	return ret;
}

static int exchange_conn_connect(const struct conn_config *cfg,
				 uint32_t local_qp, uint32_t local_rkey,
				 uint16_t local_lid,
				 uint64_t local_atomic_addr,
				 uint32_t *remote_qp, uint32_t *remote_rkey,
				 uint16_t *remote_lid,
				 uint64_t *remote_atomic_addr)
{
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};
	struct addrinfo *res = NULL;
	char portbuf[16];
	snprintf(portbuf, sizeof(portbuf), "%u", cfg->port);
	if (getaddrinfo(cfg->host, portbuf, &hints, &res))
		return -1;
	int fd = -1;
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		return -1;
	struct handshake_msg msg = {
		.qp_num = htonl(local_qp),
		.rkey = htonl(local_rkey),
		.lid = htons(local_lid),
		.atomic_addr = htobe64(local_atomic_addr),
	};
	int ret = -1;
	if (send_all(fd, &msg, sizeof(msg)) ||
	    recv_all(fd, &msg, sizeof(msg))) {
		perror("exchange");
		goto out;
	}
	*remote_qp = ntohl(msg.qp_num);
	*remote_rkey = ntohl(msg.rkey);
	*remote_lid = ntohs(msg.lid);
	*remote_atomic_addr = be64toh(msg.atomic_addr);
	ret = 0;
out:
	close(fd);
	return ret;
}

static int parse_args(int argc, char **argv, struct conn_config *cfg)
{
	cfg->mode = MODE_LOOPBACK;
	cfg->host[0] = '\0';
	cfg->port = 0;
	cfg->use_cq_ex = false;
	cfg->cq_ex_create_only = false;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
			if (cfg->mode != MODE_LOOPBACK)
				return -1;
			if (parse_endpoint(argv[i + 1], cfg->host, sizeof(cfg->host), &cfg->port))
				return -1;
			cfg->mode = MODE_LISTEN;
			++i;
		} else if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
			if (cfg->mode != MODE_LOOPBACK)
				return -1;
			if (parse_endpoint(argv[i + 1], cfg->host, sizeof(cfg->host), &cfg->port))
				return -1;
			cfg->mode = MODE_CONNECT;
			++i;
		} else if (strcmp(argv[i], "--cq-ex") == 0) {
			cfg->use_cq_ex = true;
		} else if (strcmp(argv[i], "--cq-ex-create-only") == 0) {
			cfg->use_cq_ex = true;
			cfg->cq_ex_create_only = true;
		} else {
			return -1;
		}
	}
	return 0;
}

static int poll_completions(struct ibv_cq *cq, struct ibv_cq_ex *cq_ex,
			    int max_entries, struct ibv_wc *wc)
{
	if (!cq_ex)
		return ibv_poll_cq(cq, max_entries, wc);

	struct ibv_poll_cq_attr attr = {};
	int rc = ibv_start_poll(cq_ex, &attr);
	if (rc == ENOENT)
		return 0;
	if (rc) {
		errno = rc;
		return -1;
	}

	int count = 0;
	for (;;) {
		struct ibv_wc *entry = &wc[count++];
		memset(entry, 0, sizeof(*entry));
		entry->status = cq_ex->status;
		entry->wr_id = cq_ex->wr_id;
		entry->opcode = ibv_wc_read_opcode(cq_ex);
		entry->vendor_err = ibv_wc_read_vendor_err(cq_ex);
		entry->byte_len = ibv_wc_read_byte_len(cq_ex);
		entry->imm_data = ibv_wc_read_imm_data(cq_ex);
		entry->qp_num = ibv_wc_read_qp_num(cq_ex);
		entry->src_qp = ibv_wc_read_src_qp(cq_ex);
		entry->wc_flags = ibv_wc_read_wc_flags(cq_ex);
		entry->sl = ibv_wc_read_sl(cq_ex);
		if (!ibv_wc_read_completion_ts(cq_ex)) {
			ibv_end_poll(cq_ex);
			errno = EIO;
			return -1;
		}

		if (count == max_entries)
			break;
		rc = ibv_next_poll(cq_ex);
		if (rc == ENOENT)
			break;
		if (rc) {
			ibv_end_poll(cq_ex);
			errno = rc;
			return -1;
		}
	}
	ibv_end_poll(cq_ex);
	return count;
}

int main(int argc, char *argv[])
{
	struct ibv_device **dev_list;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd = NULL;
	struct ibv_mr *mr = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_cq_ex *cq_ex = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_qp_init_attr qp_init_attr;
	struct ibv_qp_attr qp_attr;
	int ret = 0;
	bool success = false;
	struct conn_config cfg;
	uint32_t remote_qp_num;
	uint32_t remote_rkey;
	uint16_t local_lid;
	uint16_t remote_lid;
	uint64_t remote_atomic_addr;

	if (parse_args(argc, argv, &cfg)) {
		fprintf(stderr, "Usage: %s [--cq-ex | --cq-ex-create-only] [--listen host:port | --connect host:port]\n", argv[0]);
		return 1;
	}

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		fprintf(stderr, "Failed to get device list\n");
		return 1;
	}

	const char *preferred = getenv("GX_RDMA_DEVICE");
	if (!preferred || !*preferred)
		preferred = "gx0";

	/* Try exact match first if caller requested one */
	dev = NULL;
	if (preferred) {
		for (int i = 0; dev_list[i]; ++i) {
			const char *dev_name = ibv_get_device_name(dev_list[i]);
			if (strcmp(dev_name, preferred) == 0) {
				dev = dev_list[i];
				break;
			}
		}
		if (!dev)
			fprintf(stderr, "Requested device '%s' not found, falling back.\n",
				preferred);
	}

	/* Otherwise, prefer a GX device, then retain legacy fallbacks. */
	if (!dev) {
		for (int i = 0; dev_list[i]; ++i) {
			const char *dev_name = ibv_get_device_name(dev_list[i]);
			if (strstr(dev_name, "gx")) {
				dev = dev_list[i];
				break;
			}
		}
	}
	if (!dev) {
		for (int i = 0; dev_list[i]; ++i) {
			const char *dev_name = ibv_get_device_name(dev_list[i]);
			if (strstr(dev_name, "nex")) {
				dev = dev_list[i];
				break;
			}
		}
	}
	if (!dev) {
		for (int i = 0; dev_list[i]; ++i) {
			const char *dev_name = ibv_get_device_name(dev_list[i]);
			if (strstr(dev_name, "siw")) {
				dev = dev_list[i];
				break;
			}
		}
	}

	if (!dev) {
		fprintf(stderr, "No usable RDMA device (gx/nex/siw) found\n");
		ibv_free_device_list(dev_list);
		return 1;
	}

	printf("Found RDMA device: %s\n", ibv_get_device_name(dev));

    /* Open device context */
	ctx = ibv_open_device(dev);
	if (!ctx) {
		perror("ibv_open_device");
		ibv_free_device_list(dev_list);
		return 1;
	}
	if (cfg.use_cq_ex) {
		struct ibv_values_ex values = {
			.comp_mask = IBV_VALUES_MASK_RAW_CLOCK,
		};
		if (ibv_query_rt_values_ex(ctx, &values) ||
		    !(values.comp_mask & IBV_VALUES_MASK_RAW_CLOCK) ||
		    (values.raw_clock.tv_sec == 0 && values.raw_clock.tv_nsec == 0)) {
			fprintf(stderr, "extended CQ raw clock query failed\n");
			ret = 1;
			goto cleanup_ctx;
		}
	}
	struct ibv_port_attr port_attr = {};
	if (ibv_query_port(ctx, 1, &port_attr)) {
		perror("ibv_query_port");
		ret = 1;
		goto cleanup_ctx;
	}
	local_lid = port_attr.lid;

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

	mr = ibv_reg_mr(pd, buf, 4096,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC);
	if (!mr) {
		perror("ibv_reg_mr");
	ret = ENOMEM;
	goto cleanup_buf;
	}
	uint64_t *atomic_target = (uint64_t *)(void *)(buf + 512);
	uint64_t *atomic_result = (uint64_t *)(void *)(buf + 520);
	*atomic_target = 41;
	*atomic_result = 0;

	/* Create completion queue */
	if (cfg.use_cq_ex) {
		struct ibv_cq_init_attr_ex cq_attr = {
			.cqe = 10,
			.comp_vector = 0,
			.wc_flags = IBV_WC_EX_WITH_BYTE_LEN |
				    IBV_WC_EX_WITH_IMM |
				    IBV_WC_EX_WITH_QP_NUM |
				    IBV_WC_EX_WITH_SRC_QP |
				    IBV_WC_EX_WITH_SL |
				    IBV_WC_EX_WITH_COMPLETION_TIMESTAMP,
			.comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS,
			.flags = IBV_CREATE_CQ_ATTR_SINGLE_THREADED |
				 IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN,
		};
		cq_ex = ibv_create_cq_ex(ctx, &cq_attr);
		cq = cq_ex ? ibv_cq_ex_to_cq(cq_ex) : NULL;
	} else {
		cq = ibv_create_cq(ctx, 10, NULL, NULL, 0);
	}
	if (!cq) {
		perror(cfg.use_cq_ex ? "Failed to create CQ_EX" :
		       "Failed to create CQ");
		ret = 1;
		goto cleanup_mr;
	}
	if (cfg.use_cq_ex) {
		struct ibv_modify_cq_attr modify_attr = {
			.attr_mask = IBV_CQ_ATTR_MODERATE,
			.moderate = {
				.cq_count = 16,
				.cq_period = 10,
			},
		};
		if (ibv_modify_cq(cq, &modify_attr)) {
			fprintf(stderr, "extended CQ moderation request failed\n");
			ret = 1;
			goto cleanup_cq;
		}
	}
	if (cfg.cq_ex_create_only) {
		struct ibv_wc empty_wc = {};
		int n = ibv_poll_cq(cq, 1, &empty_wc);
		if (n != 0) {
			fprintf(stderr,
				"CQ_EX legacy empty poll returned %d instead of 0\n",
				n);
			ret = 1;
			goto cleanup_cq;
		}
		printf("NEX_CQ_EX_CREATE_CHECK PASS cqe=%d legacy_poll=0\n",
		       cq->cqe);
		success = true;
		goto cleanup_cq;
	}

    /* Create queue pair */
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = cq;
	qp_init_attr.recv_cq = cq;
	qp_init_attr.cap.max_send_wr = 10;
	qp_init_attr.cap.max_recv_wr = 10;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_inline_data = strlen(TEST_MSG) + 1;
	qp_init_attr.qp_type = IBV_QPT_RC;

    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        fprintf(stderr, "Failed to create QP\n");
        goto cleanup_cq;
    }

	printf("Successfully created QP with number: %d\n", qp->qp_num);

	remote_qp_num = qp->qp_num;
	remote_rkey = mr->rkey;
	remote_lid = local_lid;
	remote_atomic_addr = (uintptr_t)atomic_target;
	if (cfg.mode == MODE_LISTEN) {
		char envbuf[256];
		snprintf(envbuf, sizeof(envbuf), "%s:%u",
			 cfg.host[0] ? cfg.host : "127.0.0.1", cfg.port);
		setenv("NEX_LISTEN", envbuf, 1);
		unsetenv("NEX_CONNECT");
		if (exchange_conn_listen(&cfg, qp->qp_num, mr->rkey, local_lid,
					 (uintptr_t)atomic_target,
					 &remote_qp_num, &remote_rkey,
					 &remote_lid,
					 &remote_atomic_addr)) {
			fprintf(stderr, "Connection exchange failed\n");
			goto cleanup_qp;
		}
	} else if (cfg.mode == MODE_CONNECT) {
		char envbuf[256];
		snprintf(envbuf, sizeof(envbuf), "%s:%u", cfg.host, cfg.port);
		setenv("NEX_CONNECT", envbuf, 1);
		unsetenv("NEX_LISTEN");
		if (exchange_conn_connect(&cfg, qp->qp_num, mr->rkey, local_lid,
					  (uintptr_t)atomic_target,
					  &remote_qp_num, &remote_rkey,
					  &remote_lid,
					  &remote_atomic_addr)) {
			fprintf(stderr, "Connection exchange failed\n");
			goto cleanup_qp;
		}
	} else {
		unsetenv("NEX_CONNECT");
		unsetenv("NEX_LISTEN");
	}

	/* Post a receive so peer data (or loopback) has a buffer */
	struct ibv_sge r_sge = {
		.addr = (uintptr_t)buf,
		.length = 4096,
		.lkey = mr->lkey,
	};
	struct ibv_recv_wr r_wr = {
		.wr_id = 0xCAFE,
		.sg_list = &r_sge,
		.num_sge = 1,
	};
	struct ibv_recv_wr *bad_rwr = NULL;
	ret = ibv_post_recv(qp, &r_wr, &bad_rwr);
	if (ret) {
		fprintf(stderr, "Failed to post recv: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	/* Modify QP to INIT state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = 1;
	qp_attr.pkey_index = 0;
	qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
		IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;

	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
	if (ret) {
		fprintf(stderr, "Failed to modify QP to INIT: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	printf("Successfully modified QP to INIT state\n");

	/* Modify QP to RTR state */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	qp_attr.path_mtu = IBV_MTU_1024;
	qp_attr.dest_qp_num = remote_qp_num;
	qp_attr.ah_attr.dlid = remote_lid;
	qp_attr.ah_attr.port_num = 1;
	qp_attr.rq_psn = 0;
	qp_attr.max_dest_rd_atomic = 1;
	qp_attr.min_rnr_timer = 12;

	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
	if (ret) {
		fprintf(stderr, "Failed to modify QP to RTR: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	printf("Successfully modified QP to RTR state\n");

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
	send_wr.send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

	struct ibv_send_wr *bad_send_wr;
	ret = ibv_post_send(qp, &send_wr, &bad_send_wr);
	if (ret) {
		fprintf(stderr, "Failed to post send: %s\n", strerror(ret));
		goto cleanup_qp;
	}
	/* Inline sends snapshot their SGEs before ibv_post_send returns. Reusing
	 * the source immediately must not change what the peer receives. */
	memset(buf, 0, strlen(TEST_MSG) + 1);

	/* Poll for both send and recv completions */
	int got_send = 0, got_recv = 0;
	for (;;) {
		struct ibv_wc wc[2];
		int n = poll_completions(cq, cq_ex, 2, wc);
		if (n < 0) {
			fprintf(stderr, "Failed to poll CQ\n");
			goto cleanup_qp;
		}
		if (n == 0)
			continue;
		for (int i = 0; i < n; ++i) {
			if (wc[i].status != IBV_WC_SUCCESS) {
				fprintf(stderr, "Completion error: op=%d status=%d\n",
					wc[i].opcode, wc[i].status);
				goto cleanup_qp;
			}
			if (wc[i].opcode == IBV_WC_SEND)
				got_send = 1;
			if (wc[i].opcode == IBV_WC_RECV)
				got_recv = 1;
		}
		if (got_send && got_recv)
			break;
	}
	if (strcmp(buf, TEST_MSG) != 0) {
		fprintf(stderr, "Inline payload changed after source reuse: got '%s'\n",
			buf);
		ret = EIO;
		goto cleanup_qp;
	}

	{
		struct ibv_sge atomic_sge = {
			.addr = (uintptr_t)atomic_result,
			.length = sizeof(*atomic_result),
			.lkey = mr->lkey,
		};
		struct ibv_send_wr atomic_wr = {
			.wr_id = 0xADD,
			.sg_list = &atomic_sge,
			.num_sge = 1,
			.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD,
			.send_flags = IBV_SEND_SIGNALED,
		};
		atomic_wr.wr.atomic.remote_addr = remote_atomic_addr;
		atomic_wr.wr.atomic.rkey = remote_rkey;
		atomic_wr.wr.atomic.compare_add = 7;
		ret = ibv_post_send(qp, &atomic_wr, &bad_send_wr);
		if (ret) {
			fprintf(stderr, "Failed to post atomic fetch-add: %s\n",
				strerror(ret));
			goto cleanup_qp;
		}

		for (;;) {
			struct ibv_wc wc = {};
			int n = poll_completions(cq, cq_ex, 1, &wc);
			if (n < 0) {
				fprintf(stderr, "Failed to poll atomic CQ\n");
				ret = EIO;
				goto cleanup_qp;
			}
			if (n == 0)
				continue;
			if (wc.status != IBV_WC_SUCCESS ||
			    wc.opcode != IBV_WC_FETCH_ADD) {
				fprintf(stderr, "Atomic completion error: op=%d status=%d\n",
					wc.opcode, wc.status);
				ret = EIO;
				goto cleanup_qp;
			}
			break;
		}
		/* Each endpoint posts one operation.  Our completion proves that the
		 * peer's target changed, but its reciprocal request may still be in
		 * flight.  Wait briefly for that independently ordered update. */
		struct timespec atomic_deadline;
		clock_gettime(CLOCK_MONOTONIC, &atomic_deadline);
		atomic_deadline.tv_sec += 5;
		while (__atomic_load_n(atomic_target, __ATOMIC_ACQUIRE) != 48) {
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec > atomic_deadline.tv_sec ||
			    (now.tv_sec == atomic_deadline.tv_sec &&
			     now.tv_nsec >= atomic_deadline.tv_nsec))
				break;
			sched_yield();
		}
		if (*atomic_result != 41 ||
		    __atomic_load_n(atomic_target, __ATOMIC_ACQUIRE) != 48) {
			fprintf(stderr,
				"Atomic fetch-add mismatch: fetched=%llu remote=%llu\n",
				(unsigned long long)*atomic_result,
				(unsigned long long)*atomic_target);
			ret = EIO;
			goto cleanup_qp;
		}
		printf("NEX_ATOMIC_FETCH_ADD_CHECK PASS old=%llu new=%llu\n",
		       (unsigned long long)*atomic_result,
		       (unsigned long long)*atomic_target);
	}

	success = true;
	printf("✅ NEX RDMA provider test completed successfully!\n");
	printf("   - Device: %s\n", ibv_get_device_name(dev));
	printf("   - CQ API: %s\n", cfg.use_cq_ex ? "extended" : "legacy");
	printf("   - QP Number: %d\n", qp->qp_num);
	printf("   - Both send and recv completed.\n");
	printf("   - Inline source reuse preserved the posted payload.\n");

cleanup_qp:
    if (qp)
        ibv_destroy_qp(qp);
cleanup_cq:
	if (cq)
		ibv_destroy_cq(cq);
cleanup_mr:
	if (mr)
		ibv_dereg_mr(mr);
cleanup_buf:
	free(buf);
cleanup_pd:
	if (pd)
		ibv_dealloc_pd(pd);
cleanup_ctx:
	if (ctx)
		ibv_close_device(ctx);
    ibv_free_device_list(dev_list);

	return success ? 0 : 1;
}
