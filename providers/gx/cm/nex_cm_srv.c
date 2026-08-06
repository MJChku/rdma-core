#include "nex_cm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CM_LISTEN_PORT 5690
#define CM_LISTEN_BACKLOG 8192
#define CM_TARGET_NOFILE 131072
#define CM_PENDING_BUCKETS 4096
#define NEX_CM_LISTEN_ACK 0xa5

struct nex_cm_req {
	char service_id[64];
	uint32_t qp_num;
	uint16_t listen_port;
	uint16_t reserved;
};

struct nex_cm_rsp {
	uint32_t peer_qp_num;
	uint16_t peer_port;
	uint16_t role;
	char peer_host[64];
};

struct pending_entry {
	int sock;
	char host[64];
	uint16_t port;
	uint32_t qp_num;
	char service_id[64];
	struct pending_entry *next;
};

static struct pending_entry *pending_buckets[CM_PENDING_BUCKETS];

static void raise_nofile_best_effort(void)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
		return;

	rlim_t target = CM_TARGET_NOFILE;
	rlim_t new_cur = rl.rlim_cur;
	rlim_t new_max = rl.rlim_max;

	if (new_cur < target) {
		if (new_max < target)
			new_max = target;
		new_cur = target;
	}

	if (new_cur == rl.rlim_cur && new_max == rl.rlim_max)
		return;

	{
		struct rlimit want = {
			.rlim_cur = new_cur,
			.rlim_max = new_max,
		};
		if (setrlimit(RLIMIT_NOFILE, &want) != 0) {
			/* If raising hard limit is not permitted, still try
			 * to raise soft limit up to existing hard limit. */
			if (rl.rlim_cur < rl.rlim_max) {
				want.rlim_cur = rl.rlim_max;
				want.rlim_max = rl.rlim_max;
				(void)setrlimit(RLIMIT_NOFILE, &want);
			}
		}
	}
}

static uint32_t hash_key(const char *s)
{
	/* 32-bit FNV-1a */
	uint32_t h = 2166136261u;
	while (*s) {
		h ^= (uint8_t)(*s++);
		h *= 16777619u;
	}
	return h;
}

static int send_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len) {
		ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
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
			if (n == 0)
				errno = ECONNRESET;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static void add_pending(struct pending_entry *entry)
{
	uint32_t b = hash_key(entry->service_id) % CM_PENDING_BUCKETS;
	entry->next = pending_buckets[b];
	pending_buckets[b] = entry;
}

static int pending_socket_alive(int fd)
{
	uint8_t byte;
	ssize_t n = recv(fd, &byte, sizeof(byte), MSG_PEEK | MSG_DONTWAIT);

	if (n > 0)
		return 1;
	if (n == 0)
		return 0;
	return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

static int parse_service_id(const char *service_id,
			    uint32_t *local_lid,
			    uint32_t *remote_lid,
			    uint32_t *local_qpn,
			    uint32_t *remote_qpn)
{
	unsigned llid = 0, rlid = 0, lqp = 0, rqp = 0;
	if (sscanf(service_id, "%u:%u:%u:%u", &llid, &rlid, &lqp, &rqp) != 4)
		return -1;

	*local_lid = (uint32_t)llid;
	*remote_lid = (uint32_t)rlid;
	*local_qpn = (uint32_t)lqp;
	*remote_qpn = (uint32_t)rqp;
	return 0;
}

static int make_reverse_service_id(const char *service_id, char *out, size_t out_size)
{
	uint32_t local_lid = 0, remote_lid = 0, local_qpn = 0, remote_qpn = 0;
	if (parse_service_id(service_id, &local_lid, &remote_lid, &local_qpn, &remote_qpn) != 0)
		return -1;
	return snprintf(out, out_size, "%u:%u:%u:%u",
			remote_lid, local_lid, remote_qpn, local_qpn) >= (int)out_size ? -1 : 0;
}

static struct pending_entry *take_pending(const char *service_id)
{
	char peer_service_id[64] = {0};
	if (make_reverse_service_id(service_id, peer_service_id, sizeof(peer_service_id)) != 0)
		return NULL;
	uint32_t b = hash_key(peer_service_id) % CM_PENDING_BUCKETS;
	struct pending_entry **prev = &pending_buckets[b];
	while (*prev) {
		struct pending_entry *node = *prev;
		if (!pending_socket_alive(node->sock)) {
			*prev = node->next;
			close(node->sock);
			free(node);
			continue;
		}
		if (strcmp(node->service_id, peer_service_id) == 0) {
			*prev = node->next;
			node->next = NULL;
			return node;
		}
		prev = &(*prev)->next;
	}
	return NULL;
}

static void serve(int listen_fd)
{
	for (;;) {
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int fd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
		if (fd < 0) {
			perror("accept");
			continue;
		}

		struct nex_cm_req req;
		if (recv_all(fd, &req, sizeof(req))) {
			perror("recv");
			close(fd);
			continue;
		}

		uint32_t qp_num = ntohl(req.qp_num);
		uint16_t port = ntohs(req.listen_port);
		uint32_t local_lid = 0, remote_lid = 0, local_qpn = 0, remote_qpn = 0;
		if (parse_service_id(req.service_id, &local_lid, &remote_lid, &local_qpn, &remote_qpn) != 0) {
			fprintf(stderr, "ERROR: gx_cm_srv: invalid service_id format '%s'\n", req.service_id);
			close(fd);
			continue;
		}

		struct pending_entry *match = take_pending(req.service_id);
		if (!match) {
			struct pending_entry *entry = calloc(1, sizeof(*entry));
			if (!entry) {
				close(fd);
				continue;
			}
			entry->sock = fd;
			entry->qp_num = qp_num;
			entry->port = port;
			strncpy(entry->service_id, req.service_id, sizeof(entry->service_id) - 1);
			inet_ntop(AF_INET, &addr.sin_addr, entry->host, sizeof(entry->host));
			add_pending(entry);
			continue;
		}

		/* Pair found */
		char connect_host[64] = {0};
		inet_ntop(AF_INET, &addr.sin_addr, connect_host, sizeof(connect_host));

		struct nex_cm_rsp rsp_connect = {
			.peer_qp_num = htonl(match->qp_num),
			.peer_port = htons(match->port),
			.role = NEX_CM_ROLE_CONNECT,
		};
		strncpy(rsp_connect.peer_host, match->host,
			sizeof(rsp_connect.peer_host) - 1);

		struct nex_cm_rsp rsp_listen = {
			.peer_qp_num = htonl(qp_num),
			.peer_port = htons(port),
			.role = NEX_CM_ROLE_LISTEN,
		};
		strncpy(rsp_listen.peer_host, connect_host, sizeof(rsp_listen.peer_host) - 1);
		uint8_t listen_ack = 0;
		int pending_ok = send_all(match->sock, &rsp_listen,
					  sizeof(rsp_listen));
		if (pending_ok == 0)
			pending_ok = recv_all(match->sock, &listen_ack,
					      sizeof(listen_ack));
		if (pending_ok == 0 && listen_ack != NEX_CM_LISTEN_ACK) {
			errno = EPROTO;
			pending_ok = -1;
		}
		if (pending_ok != 0) {
			perror("pending peer acknowledgement");
			close(match->sock);
			free(match);

			/* The pending peer disappeared between the liveness check and
			 * this response. Keep the current peer available for its real
			 * counterpart instead of pairing it with the stale request. */
			struct pending_entry *entry = calloc(1, sizeof(*entry));
			if (!entry) {
				close(fd);
				continue;
			}
			entry->sock = fd;
			entry->qp_num = qp_num;
			entry->port = port;
			strncpy(entry->service_id, req.service_id,
				sizeof(entry->service_id) - 1);
			strncpy(entry->host, connect_host, sizeof(entry->host) - 1);
			add_pending(entry);
			continue;
		}
		close(match->sock);
		free(match);

		if (send_all(fd, &rsp_connect, sizeof(rsp_connect)) != 0)
			perror("send connecting peer");
		close(fd);
	}
}

int main(void)
{
	raise_nofile_best_effort();
	/* A peer can disappear while waiting for its counterpart. Never let a
	 * failed rendezvous response terminate the shared CM service. */
	(void)signal(SIGPIPE, SIG_IGN);

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return 1;
	}
	int opt = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(CM_LISTEN_PORT),
	};
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(listen_fd);
		return 1;
	}
	if (listen(listen_fd, CM_LISTEN_BACKLOG) < 0) {
		perror("listen");
		close(listen_fd);
		return 1;
	}
	printf("gx_cm_srv listening on port %d (backlog=%d)\n",
	       CM_LISTEN_PORT, CM_LISTEN_BACKLOG);
	serve(listen_fd);
	close(listen_fd);
	return 0;
}
