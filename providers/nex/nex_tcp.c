#include "nex_tcp.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "cm/nex_cm.h"
#include "nex_shm.h"

#ifndef NEX_TCP_MAX_CONN
#define NEX_TCP_MAX_CONN 4096
#endif

struct nex_tcp_conn {
    int in_use;
    int sock_fd;
    uint32_t local_lid;
    uint32_t remote_lid;
    uint32_t local_qp;
    uint32_t remote_qp;
};

static struct nex_tcp_conn g_conns[NEX_TCP_MAX_CONN];
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t parse_u32(const char *s)
{
    if (!s || !*s)
        return 0;
    errno = 0;
    char *endp = NULL;
    unsigned long v = strtoul(s, &endp, 10);
    if (errno != 0 || !endp || *endp != '\0' || v > UINT32_MAX)
        return 0;
    return (uint32_t)v;
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

static int wait_socket_ready(int fd, short events)
{
    for (;;) {
        struct pollfd pfd = {
            .fd = fd,
            .events = events,
            .revents = 0,
        };
        int rc = poll(&pfd, 1, 0);
        if (rc > 0)
            return 0;
        if (rc < 0 && errno != EINTR)
            return -1;
        nex_fiber_idle_yield();
    }
}

static int connect_nonblocking(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (connect(fd, addr, addrlen) == 0)
        return 0;
    if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
        return -1;
    if (wait_socket_ready(fd, POLLOUT) != 0)
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

static int conn_alloc(void)
{
    pthread_mutex_lock(&g_conn_mutex);
    for (int i = 0; i < NEX_TCP_MAX_CONN; ++i) {
        if (!g_conns[i].in_use) {
            memset(&g_conns[i], 0, sizeof(g_conns[i]));
            g_conns[i].in_use = 1;
            g_conns[i].sock_fd = -1;
            pthread_mutex_unlock(&g_conn_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&g_conn_mutex);
    errno = EMFILE;
    return -1;
}

static struct nex_tcp_conn *conn_get(int fd)
{
    pthread_mutex_lock(&g_conn_mutex);
    if (fd < 0 || fd >= NEX_TCP_MAX_CONN || !g_conns[fd].in_use) {
        pthread_mutex_unlock(&g_conn_mutex);
        return NULL;
    }
    pthread_mutex_unlock(&g_conn_mutex);
    return &g_conns[fd];
}

static void conn_release(int fd)
{
    if (fd < 0 || fd >= NEX_TCP_MAX_CONN)
        return;
    pthread_mutex_lock(&g_conn_mutex);
    g_conns[fd].in_use = 0;
    g_conns[fd].sock_fd = -1;
    pthread_mutex_unlock(&g_conn_mutex);
}

static int parse_service_id(const char *service_id,
                            char **llid, char **lqp,
                            char **rlid, char **rqp,
                            char *scratch, size_t scratch_len)
{
    size_t n = strnlen(service_id, scratch_len);
    if (n == 0 || n >= scratch_len)
        return -EINVAL;
    memcpy(scratch, service_id, n + 1);
    int parts = 0;
    char *save = scratch;
    while (*save) {
        if (*save == ':') {
            *save = '\0';
            parts++;
        }
        save++;
    }
    if (parts != 3)
        return -EINVAL;
    char *p0 = scratch;
    char *p1 = p0 + strlen(p0) + 1;
    char *p2 = p1 + strlen(p1) + 1;
    char *p3 = p2 + strlen(p2) + 1;
    if (!*p0 || !*p1 || !*p2 || !*p3)
        return -EINVAL;
    *llid = p0;
    *lqp = p2;
    *rlid = p1;
    *rqp = p3;
    return 0;
}

static int setup_listener(uint16_t *listen_port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 256) != 0) {
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    *listen_port_out = ntohs(addr.sin_port);
    return fd;
}

static int connect_with_retry(const char *host, uint16_t port)
{
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portbuf, &hints, &res) != 0)
        return -1;

    int data_fd = -1;
    int attempts = 10000;
    while (attempts-- > 0 && data_fd < 0) {
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            int s = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
            if (s < 0)
                continue;
            int one = 1;
            (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            if (set_nonblocking(s) != 0) {
                close(s);
                continue;
            }
            if (connect_nonblocking(s, ai->ai_addr, ai->ai_addrlen) == 0) {
                data_fd = s;
                break;
            }
            close(s);
        }
        if (data_fd < 0)
            nex_fiber_idle_yield();
    }

    freeaddrinfo(res);
    return data_fd;
}

static int write_all_sock(int sock_fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(sock_fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                nex_fiber_idle_yield();
                continue;
            }
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all_sock(int sock_fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(sock_fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                nex_fiber_idle_yield();
                continue;
            }
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int writev_all_sock(int sock_fd, const struct iovec *iov, int iovcnt, size_t total_len)
{
    const int stack_cap = 32;
    struct iovec stack_iov[stack_cap];
    struct iovec *local = stack_iov;

    if (iovcnt > stack_cap) {
        local = malloc((size_t)iovcnt * sizeof(*local));
        if (!local)
            return -1;
    }

    memcpy(local, iov, (size_t)iovcnt * sizeof(*local));

    size_t remaining = total_len;
    int idx = 0;
    while (remaining > 0) {
        ssize_t n = writev(sock_fd, &local[idx], iovcnt - idx);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                nex_fiber_idle_yield();
                continue;
            }
            if (local != stack_iov)
                free(local);
            return -1;
        }
        if (n == 0) {
            if (local != stack_iov)
                free(local);
            return -1;
        }

        remaining -= (size_t)n;

        ssize_t consumed = n;
        while (idx < iovcnt && consumed > 0) {
            if (consumed >= (ssize_t)local[idx].iov_len) {
                consumed -= (ssize_t)local[idx].iov_len;
                ++idx;
            } else {
                local[idx].iov_base = (uint8_t *)local[idx].iov_base + consumed;
                local[idx].iov_len -= (size_t)consumed;
                consumed = 0;
            }
        }
    }

    if (local != stack_iov)
        free(local);
    return 0;
}

static int readv_all_sock(int sock_fd, const struct iovec *iov, int iovcnt, size_t total_len)
{
    size_t remaining = total_len;
    int idx = 0;
    while (remaining > 0 && idx < iovcnt) {
        uint8_t *p = (uint8_t *)iov[idx].iov_base;
        size_t len = iov[idx].iov_len;
        while (len > 0) {
            ssize_t n = read(sock_fd, p, len);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    nex_fiber_idle_yield();
                    continue;
                }
                return -1;
            }
            if (n == 0)
                return -1;
            p += (size_t)n;
            len -= (size_t)n;
            remaining -= (size_t)n;
        }
        ++idx;
    }
    return (remaining == 0) ? 0 : -1;
}

int nex_tcp_dial(const char *service_id, int *fd_out)
{
    if (!service_id || !fd_out)
        return EINVAL;

    char scratch[256];
    char *llid = NULL, *lqp = NULL, *rlid = NULL, *rqp = NULL;
    int rc = parse_service_id(service_id, &llid, &lqp, &rlid, &rqp, scratch, sizeof(scratch));
    if (rc != 0)
        return -rc;

    uint32_t local_lid = parse_u32(llid);
    uint32_t remote_lid = parse_u32(rlid);
    uint32_t local_qp = parse_u32(lqp);
    uint32_t remote_qp = parse_u32(rqp);

    uint16_t listen_port = 0;
    int listen_fd = setup_listener(&listen_port);
    if (listen_fd < 0)
        return errno ? errno : EIO;

    struct nex_cm_peer peer;
    memset(&peer, 0, sizeof(peer));
    int role = NEX_CM_ROLE_CONNECT;
    if (nex_cm_exchange(service_id, local_qp, listen_port, &peer, &role) != 0 || !peer.host[0]) {
        close(listen_fd);
        return errno ? errno : EIO;
    }

    int data_fd = -1;
    if (role == NEX_CM_ROLE_LISTEN) {
        for (;;) {
            data_fd = accept(listen_fd, NULL, NULL);
            if (data_fd >= 0)
                break;
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                nex_fiber_idle_yield();
                continue;
            }
            break;
        }
        if (data_fd >= 0) {
            int one = 1;
            (void)setsockopt(data_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            (void)set_nonblocking(data_fd);
        }
    } else {
        data_fd = connect_with_retry(peer.host, peer.port);
    }
    close(listen_fd);
    if (data_fd < 0)
        return errno ? errno : EIO;

    int slot = conn_alloc();
    if (slot < 0) {
        close(data_fd);
        return errno ? errno : EMFILE;
    }

    struct nex_tcp_conn *c = conn_get(slot);
    if (!c) {
        close(data_fd);
        conn_release(slot);
        return EBADF;
    }

    c->sock_fd = data_fd;
    c->local_lid = local_lid;
    c->remote_lid = remote_lid;
    c->local_qp = local_qp;
    c->remote_qp = peer.qp_num ? peer.qp_num : remote_qp;
    *fd_out = slot;
    return 0;
}

ssize_t nex_tcp_read(int fd, void *buf, size_t len, int apply_perf_model)
{
    struct nex_tcp_conn *c = conn_get(fd);
    if (!c) {
        errno = EBADF;
        return -1;
    }
    if (len == 0)
        return 0;

    (void)apply_perf_model;

    if (read_all_sock(c->sock_fd, buf, len) != 0)
        return -1;

    return (ssize_t)len;
}

ssize_t nex_tcp_write(int fd, const void *buf, size_t len, int apply_perf_model)
{
    struct nex_tcp_conn *c = conn_get(fd);
    if (!c) {
        errno = EBADF;
        return -1;
    }
    if (len == 0)
        return 0;

    (void)apply_perf_model;

    if (write_all_sock(c->sock_fd, buf, len) != 0)
        return -1;

    return (ssize_t)len;
}

ssize_t nex_tcp_writev(int fd, const struct iovec *iov, int iovcnt,
                       int apply_perf_model, bool wait_completion, int *slot_out,
                       uint32_t tag)
{
    if (iovcnt < 0 || (iovcnt > 0 && !iov)) {
        errno = EINVAL;
        return -1;
    }

    size_t total_len = 0;
    for (int i = 0; i < iovcnt; ++i) {
        if (SIZE_MAX - total_len < iov[i].iov_len) {
            errno = EOVERFLOW;
            return -1;
        }
        total_len += iov[i].iov_len;
    }
    if (total_len == 0)
        return 0;

    struct nex_tcp_conn *c = conn_get(fd);
    if (!c) {
        errno = EBADF;
        return -1;
    }

    (void)apply_perf_model;
    (void)wait_completion;
    (void)tag;
    if (slot_out)
        *slot_out = -1;

    if (writev_all_sock(c->sock_fd, iov, iovcnt, total_len) != 0)
        return -1;

    return (ssize_t)total_len;
}

ssize_t nex_tcp_readv(int fd, const struct iovec *iov, int iovcnt,
                      int apply_perf_model, bool wait_completion, int *slot_out,
                      uint32_t tag)
{
    if (iovcnt < 0 || (iovcnt > 0 && !iov)) {
        errno = EINVAL;
        return -1;
    }

    size_t total_len = 0;
    for (int i = 0; i < iovcnt; ++i) {
        if (SIZE_MAX - total_len < iov[i].iov_len) {
            errno = EOVERFLOW;
            return -1;
        }
        total_len += iov[i].iov_len;
    }
    if (total_len == 0)
        return 0;

    struct nex_tcp_conn *c = conn_get(fd);
    if (!c) {
        errno = EBADF;
        return -1;
    }

    (void)apply_perf_model;
    (void)wait_completion;
    (void)tag;
    if (slot_out)
        *slot_out = -1;

    if (readv_all_sock(c->sock_fd, iov, iovcnt, total_len) != 0)
        return -1;

    return (ssize_t)total_len;
}

int nex_tcp_close(int fd)
{
    struct nex_tcp_conn *c = conn_get(fd);
    if (!c)
        return EBADF;
    if (c->sock_fd >= 0)
        close(c->sock_fd);
    c->sock_fd = -1;
    conn_release(fd);
    return 0;
}

int nex_tcp_shutdown(int fd)
{
    struct nex_tcp_conn *c = conn_get(fd);
    if (!c)
        return EBADF;
    if (c->sock_fd >= 0)
        shutdown(c->sock_fd, SHUT_RDWR);
    return 0;
}
