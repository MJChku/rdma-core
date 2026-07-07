/* Minimal user-space CM shim for NEX provider */
#ifndef NEX_CM_H
#define NEX_CM_H

#include <stdint.h>

#define NEX_CM_ROLE_LISTEN  0
#define NEX_CM_ROLE_CONNECT 1

struct nex_cm_peer {
	char host[64];
	uint16_t port;
	uint32_t qp_num;
};

/* Exchange connection information with the central CM service */
int nex_cm_exchange(const char *service_id,
		       uint32_t local_qp_num,
		       uint16_t listen_port,
		       struct nex_cm_peer *peer,
		       int *role);

#endif /* NEX_CM_H */
