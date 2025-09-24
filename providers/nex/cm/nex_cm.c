#include "nex_cm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NEX_CM_SERVICE_HOST "10.1.2.254"
#define NEX_CM_SERVICE_PORT "5690"

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

int nex_cm_exchange(const char *service_id,
		       uint32_t local_qp_num,
		       uint16_t listen_port,
		       struct nex_cm_peer *peer,
		       int *role)
{
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

	if (getaddrinfo(NEX_CM_SERVICE_HOST, NEX_CM_SERVICE_PORT, &hints, &res))
		return errno ? errno : EIO;
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
	if (fd < 0) {
		err = errno ? errno : EIO;
		goto out;
	}

	struct nex_cm_req req = {0};
	strncpy(req.service_id, service_id, sizeof(req.service_id) - 1);
	req.qp_num = htonl(local_qp_num);
	req.listen_port = htons(listen_port);
	if (send_all(fd, &req, sizeof(req))) {
		err = errno ? errno : EIO;
		goto out;
	}

	struct nex_cm_rsp rsp;
	if (recv_all(fd, &rsp, sizeof(rsp))) {
		err = errno ? errno : EIO;
		goto out;
	}

	peer->qp_num = ntohl(rsp.peer_qp_num);
	peer->port = ntohs(rsp.peer_port);
	peer->host[0] = '\0';
	strncpy(peer->host, rsp.peer_host, sizeof(peer->host) - 1);
	peer->host[sizeof(peer->host) - 1] = '\0';
	*role = rsp.role;
	err = 0;

out:
	if (fd >= 0)
		close(fd);
	return err;
}
