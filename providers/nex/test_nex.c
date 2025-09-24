/*
 * NEX RDMA Provider Test Program
 *
 * Simple test to verify NEX provider functionality
 *
 * Copyright (c) 2025 NEX Project
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
};

struct handshake_msg {
	uint32_t qp_num;
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

static int exchange_conn_listen(const struct conn_config *cfg, uint32_t local_qp, uint32_t *remote_qp)
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

	struct handshake_msg msg = { .qp_num = htonl(local_qp) };
	if (send_all(conn_fd, &msg, sizeof(msg)) ||
	    recv_all(conn_fd, &msg, sizeof(msg))) {
		perror("exchange");
		goto out;
	}
	*remote_qp = ntohl(msg.qp_num);
	ret = 0;
out:
	if (conn_fd >= 0)
		close(conn_fd);
	if (listen_fd >= 0)
		close(listen_fd);
	return ret;
}

static int exchange_conn_connect(const struct conn_config *cfg, uint32_t local_qp, uint32_t *remote_qp)
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
	struct handshake_msg msg = { .qp_num = htonl(local_qp) };
	int ret = -1;
	if (send_all(fd, &msg, sizeof(msg)) ||
	    recv_all(fd, &msg, sizeof(msg))) {
		perror("exchange");
		goto out;
	}
	*remote_qp = ntohl(msg.qp_num);
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
		} else {
			return -1;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct ibv_device **dev_list;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd = NULL;
	struct ibv_mr *mr = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_qp_init_attr qp_init_attr;
	struct ibv_qp_attr qp_attr;
	int ret = 0;
	struct conn_config cfg;
	uint32_t remote_qp_num;

	if (parse_args(argc, argv, &cfg)) {
		fprintf(stderr, "Usage: %s [--listen host:port | --connect host:port]\n", argv[0]);
		return 1;
	}

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		fprintf(stderr, "Failed to get device list\n");
		return 1;
	}

    const char *preferred = NULL;

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

	/* Otherwise, prefer a NEX device, then fall back to SIW */
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
		fprintf(stderr, "No usable RDMA device (nex/siw) found\n");
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
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (!mr) {
		perror("ibv_reg_mr");
	ret = ENOMEM;
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

	printf("Successfully created QP with number: %d\n", qp->qp_num);

	remote_qp_num = qp->qp_num;
	if (cfg.mode == MODE_LISTEN) {
		char envbuf[256];
		snprintf(envbuf, sizeof(envbuf), "%s:%u",
			 cfg.host[0] ? cfg.host : "127.0.0.1", cfg.port);
		setenv("NEX_LISTEN", envbuf, 1);
		unsetenv("NEX_CONNECT");
		if (exchange_conn_listen(&cfg, qp->qp_num, &remote_qp_num)) {
			fprintf(stderr, "Connection exchange failed\n");
			goto cleanup_qp;
		}
	} else if (cfg.mode == MODE_CONNECT) {
		char envbuf[256];
		snprintf(envbuf, sizeof(envbuf), "%s:%u", cfg.host, cfg.port);
		setenv("NEX_CONNECT", envbuf, 1);
		unsetenv("NEX_LISTEN");
		if (exchange_conn_connect(&cfg, qp->qp_num, &remote_qp_num)) {
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
	qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

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
	send_wr.send_flags = IBV_SEND_SIGNALED;

	struct ibv_send_wr *bad_send_wr;
	ret = ibv_post_send(qp, &send_wr, &bad_send_wr);
	if (ret) {
		fprintf(stderr, "Failed to post send: %s\n", strerror(ret));
		goto cleanup_qp;
	}

	/* Poll for both send and recv completions */
	int got_send = 0, got_recv = 0;
	for (;;) {
		struct ibv_wc wc;
		int n = ibv_poll_cq(cq, 1, &wc);
		if (n < 0) {
			fprintf(stderr, "Failed to poll CQ\n");
			goto cleanup_qp;
		}
		if (n == 0)
			continue;
		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stderr, "Completion error: op=%d status=%d\n", wc.opcode, wc.status);
			goto cleanup_qp;
		}
		if (wc.opcode == IBV_WC_SEND) got_send = 1;
		if (wc.opcode == IBV_WC_RECV) got_recv = 1;
		if (got_send && got_recv)
			break;
	}

	printf("✅ NEX RDMA provider test completed successfully!\n");
	printf("   - Device: %s\n", ibv_get_device_name(dev));
	printf("   - QP Number: %d\n", qp->qp_num);
	printf("   - Both send and recv completed.\n");

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

    return ret ? 1 : 0;
}
