#include "nex_cm.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CM_LISTEN_PORT 5690

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

static struct pending_entry *pending_head;

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

static void add_pending(struct pending_entry *entry)
{
	entry->next = pending_head;
	pending_head = entry;
}

static struct pending_entry *take_pending(const char *service_id)
{
	char base[64], peer_service_id[128];
    uint32_t local, remote;

    /* new numeric 4-field format: lid:remote_lid:local_qpn:remote_qpn */
    unsigned lid1 = 0, lid2 = 0;
    unsigned qpn1 = 0, qpn2 = 0;
    if (sscanf(service_id, "%u:%u:%u:%u", &lid1, &lid2, &qpn1, &qpn2) == 4) {
        /* build peer service id by swapping lids and qp nums */
        snprintf(peer_service_id, sizeof(peer_service_id), "%u:%u:%u:%u",
             lid2, lid1, qpn2, qpn1);
        struct pending_entry **prev = &pending_head;
        while (*prev) {
            if (strcmp((*prev)->service_id, peer_service_id) == 0) {
                struct pending_entry *node = *prev;
                *prev = node->next;
                node->next = NULL;
                return node;
            }
            prev = &(*prev)->next;
        }
        return NULL;
    }else{
		// directly fault
		fprintf(stderr, "ERROR: nex_cm_srv: invalid service_id format '%s'\n", service_id);
		exit(1);
	}

	struct pending_entry **prev = &pending_head;
	while (*prev) {
		if (strcmp((*prev)->service_id, peer_service_id) == 0) {
			struct pending_entry *node = *prev;
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
		strncpy(rsp_connect.peer_host, match->host, sizeof(rsp_connect.peer_host) - 1);
		send_all(fd, &rsp_connect, sizeof(rsp_connect));
		close(fd);

		struct nex_cm_rsp rsp_listen = {
			.peer_qp_num = htonl(qp_num),
			.peer_port = htons(port),
			.role = NEX_CM_ROLE_LISTEN,
		};
		strncpy(rsp_listen.peer_host, connect_host, sizeof(rsp_listen.peer_host) - 1);
		send_all(match->sock, &rsp_listen, sizeof(rsp_listen));
		close(match->sock);
		free(match);
	}
}

int main(void)
{
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
	if (listen(listen_fd, 8) < 0) {
		perror("listen");
		close(listen_fd);
		return 1;
	}
	printf("nex_cm_srv listening on port %d\n", CM_LISTEN_PORT);
	serve(listen_fd);
	close(listen_fd);
	return 0;
}
