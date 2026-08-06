#include "nex_cm.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#define NEX_CM_DEFAULT_SERVICE_HOST "gx-mpi-0"
#define NEX_CM_DEFAULT_SERVICE_PORT "5690"
#define NEX_CM_TARGET_NOFILE 131072
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

typedef void (*cm_idle_yield_fn_t)(void);

static int cm_debug_enabled(void)
{
	static int initialized = 0;
	static int enabled = 0;
	if (!initialized) {
		const char *v = getenv("GX_CM_DEBUG");
		enabled = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
		initialized = 1;
	}
	return enabled;
}

#define CM_DEBUG_LOG(...)                                                     \
	do {                                                                  \
		if (cm_debug_enabled())                                       \
			fprintf(stderr, __VA_ARGS__);                         \
	} while (0)

static void cm_idle_yield(void)
{
	static int initialized = 0;
	static cm_idle_yield_fn_t fn = NULL;
	if (!initialized) {
		fn = (cm_idle_yield_fn_t)dlsym(RTLD_DEFAULT, "gx_fiber_idle_yield");
		initialized = 1;
	}
	if (fn) {
		fn();
		return;
	}
	sched_yield();
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	return 0;
}

static int wait_writable_nb(int fd)
{
	for (;;) {
		struct pollfd pfd = {
			.fd = fd,
			.events = POLLOUT,
		};
		int rc = poll(&pfd, 1, 0);
		if (rc > 0)
			return 0;
		if (rc < 0 && errno != EINTR)
			return -1;
		if (rc > 0 && (pfd.revents & POLLNVAL)) {
			errno = EBADF;
			return -1;
		}
		cm_idle_yield();
	}
}

static int connect_nonblocking(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (connect(fd, addr, addrlen) == 0)
		return 0;
	if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
		return -1;
	if (wait_writable_nb(fd) != 0)
		return -1;
	int so_error = 0;
	socklen_t so_error_len = sizeof(so_error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0)
		return -1;
	if (so_error != 0) {
		errno = so_error;
		return -1;
	}
	return 0;
}

static void nex_raise_nofile_best_effort(void)
{
	static int tuned = 0;
	if (__atomic_load_n(&tuned, __ATOMIC_ACQUIRE))
		return;

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		rlim_t target = NEX_CM_TARGET_NOFILE;
		rlim_t new_cur = rl.rlim_cur;
		rlim_t new_max = rl.rlim_max;

		if (new_cur < target) {
			if (new_max < target)
				new_max = target;
			new_cur = target;
		}
		if (new_cur != rl.rlim_cur || new_max != rl.rlim_max) {
			struct rlimit want = {
				.rlim_cur = new_cur,
				.rlim_max = new_max,
			};
			if (setrlimit(RLIMIT_NOFILE, &want) != 0) {
				if (rl.rlim_cur < rl.rlim_max) {
					want.rlim_cur = rl.rlim_max;
					want.rlim_max = rl.rlim_max;
					(void)setrlimit(RLIMIT_NOFILE, &want);
				}
			}
		}
	}

	__atomic_store_n(&tuned, 1, __ATOMIC_RELEASE);
}

static int send_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len) {
		ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				cm_idle_yield();
				continue;
			}
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
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				cm_idle_yield();
				continue;
			}
			if (n == 0)
				errno = ECONNRESET;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

int nex_cm_exchange(const char *service_id,
		       uint32_t local_qp_num,
		       uint16_t listen_port,
		       struct nex_cm_peer *peer,
		       int *role)
{
	nex_raise_nofile_best_effort();

	const char *cm_host = getenv("GX_CM_SERVICE_HOST");
	const char *cm_port = getenv("GX_CM_SERVICE_PORT");
	if (!cm_host || !*cm_host)
		cm_host = NEX_CM_DEFAULT_SERVICE_HOST;
	if (!cm_port || !*cm_port)
		cm_port = NEX_CM_DEFAULT_SERVICE_PORT;

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *res = NULL;
	int fd = -1;
	int err = 0;

	if (!service_id || !*service_id)
		service_id = "default";

	if (!peer || !role)
		return EINVAL;

	CM_DEBUG_LOG("nex_cm: connecting to CM server %s:%s for service=%s qp=%u port=%u\n",
		     cm_host, cm_port, service_id, local_qp_num, listen_port);

	if (getaddrinfo(cm_host, cm_port, &hints, &res)) {
		fprintf(stderr, "nex_cm: getaddrinfo FAILED errno=%d\n", errno);
		return errno ? errno : EIO;
	}
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (set_nonblocking(fd) != 0) {
			close(fd);
			fd = -1;
			continue;
		}
		CM_DEBUG_LOG("nex_cm: attempting connect fd=%d\n", fd);
		if (connect_nonblocking(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			CM_DEBUG_LOG("nex_cm: connect SUCCESS fd=%d\n", fd);
			break;
		}
		CM_DEBUG_LOG("nex_cm: connect FAILED fd=%d errno=%d\n", fd, errno);
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		err = errno ? errno : EIO;
		fprintf(stderr, "nex_cm: all connect attempts FAILED err=%d\n", err);
		goto out;
	}

	struct nex_cm_req req = {0};
	strncpy(req.service_id, service_id, sizeof(req.service_id) - 1);
	req.qp_num = htonl(local_qp_num);
	req.listen_port = htons(listen_port);
	CM_DEBUG_LOG("nex_cm: sending request\n");
	if (send_all(fd, &req, sizeof(req))) {
		err = errno ? errno : EIO;
		fprintf(stderr, "nex_cm: send_all FAILED err=%d\n", err);
		goto out;
	}

	CM_DEBUG_LOG("nex_cm: waiting for response\n");
	struct nex_cm_rsp rsp;
	if (recv_all(fd, &rsp, sizeof(rsp))) {
		err = errno ? errno : EIO;
		fprintf(stderr, "nex_cm: recv_all FAILED err=%d\n", err);
		goto out;
	}
	/* The server must know that the peer which waited in its pending table is
	 * still alive before it releases the newly connecting peer.  Without this
	 * acknowledgement, a late TCP reset can make a fresh connection pair with
	 * a stale waiter even when a pre-send liveness probe looked healthy. */
	if (rsp.role == NEX_CM_ROLE_LISTEN) {
		const uint8_t ack = NEX_CM_LISTEN_ACK;
		if (send_all(fd, &ack, sizeof(ack))) {
			err = errno ? errno : EIO;
			fprintf(stderr, "nex_cm: pending-peer ack FAILED err=%d\n", err);
			goto out;
		}
	}

	peer->qp_num = ntohl(rsp.peer_qp_num);
	peer->port = ntohs(rsp.peer_port);
	peer->host[0] = '\0';
	strncpy(peer->host, rsp.peer_host, sizeof(peer->host) - 1);
	peer->host[sizeof(peer->host) - 1] = '\0';
	*role = rsp.role;
	CM_DEBUG_LOG("nex_cm: SUCCESS peer_qp=%u peer_port=%u role=%d host=%s\n",
		     peer->qp_num, peer->port, *role, peer->host);
	err = 0;

out:
	if (fd >= 0)
		close(fd);
	return err;
}
