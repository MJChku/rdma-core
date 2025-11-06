// nex_shm.c
#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <dlfcn.h>
#include <assert.h>
#include "nex_shm.h"

static int get_nex_id(void);

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

#define NEX_ERROR(fmt, ...) fprintf(stderr, "ERROR: nex (%d, %lu us): " fmt "\n", get_nex_id(), now_ns() / 1000, ##__VA_ARGS__)

#ifdef DEBUG
#define NEX_TRACE_TIMING(fmt, ...) fprintf(stderr, "nex (%d, %lu us): " fmt "\n", get_nex_id(), now_ns() / 1000, ##__VA_ARGS__)
#define NEX_TRACE(fmt, ...) fprintf(stderr, "nex (%d, %lu ms): " fmt "\n", get_nex_id(), now_ns() / 1000000, ##__VA_ARGS__)
#else
#define NEX_TRACE_TIMING(fmt, ...) do { } while (0)
#define NEX_TRACE(fmt, ...) do { } while (0)
#endif
struct accvm_symbols accvm_syms = {0};

static uint32_t parse_u32(const char* s)
{
    if (!s || !*s)
        return 0;
    errno = 0;
    unsigned long v = strtoul(s, NULL, 0);
    if (errno != 0)
        return 0;
    return (uint32_t)v;
}

static void* get_accvm_lib(void){
    void* handle = dlopen("accvm.so", RTLD_LAZY | RTLD_LOCAL);
    if (!handle) {
        NEX_ERROR("loading libaccvm.so: %s\n", dlerror());
        return NULL;
    }
    return handle;
}

int get_accvm_symbols(struct accvm_symbols* syms) {
    void* handle = get_accvm_lib();
    if (!handle) return -1;

    syms->compressT = (compressT_t)dlsym(handle, "compressT");
    if (!syms->compressT) {
        NEX_ERROR("getting compressT: %s\n", dlerror());
    }

    syms->jailbreakT = (jailbreakT_t)dlsym(handle, "jailbreakT");
    if (!syms->jailbreakT) {
        NEX_ERROR("getting jailbreakT: %s\n", dlerror());
    }

    syms->endJailbreakT = (end_jailbreakT_t)dlsym(handle, "endJailbreakT");
    if (!syms->endJailbreakT) {
        NEX_ERROR("getting endJailbreakT: %s\n", dlerror());
    }

    syms->changeEpoch = (changeEpoch_t)dlsym(handle, "changeEpoch");
    if (!syms->changeEpoch) {
        NEX_ERROR("getting changeEpoch: %s\n", dlerror());
    }

    syms->send_data_qp = (send_data_qp_t)dlsym(handle, "send_data_qp");
    if (!syms->send_data_qp) {
        NEX_ERROR("getting send_data_qp: %s\n", dlerror());
    }

    syms->recv_data_qp = (recv_data_qp_t)dlsym(handle, "recv_data_qp");
    if (!syms->recv_data_qp) {
        NEX_ERROR("getting recv_data_qp: %s\n", dlerror());
    }

    syms->wait_for_completion = (wait_for_completion_t)dlsym(handle, "wait_for_completion");
    if (!syms->wait_for_completion) {
        NEX_ERROR("getting wait_for_completion: %s\n", dlerror());
    }

    if (!syms->send_data_qp || !syms->recv_data_qp)
        return -1;
    return 0;
}

void yield(void){
  sched_yield();
  // nanosleep((const struct timespec[]){{0, 1000000}}, NULL);
}

void nex_fast_memcpy(void* dst, const void* src, size_t len) {
  // 6byte per nano second
  // 64byte 10 nano second
  // 300 ns for 2KB
  // 1 us for using virtual speedup
  // 32KB 5 us
  if(len >= 32768){
    memcpy(dst, src, len);
  }else{
    memcpy(dst, src, len);
  }
}

static int get_nex_id(void){
	static int initialized = 0;
	static int nex_id = 0;
	
	if(__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) return nex_id;
	//get env NEX_ID
	const char* env_p = getenv("NEX_ID");
	if(env_p == NULL){
		return nex_id;
	}
	nex_id = atoi(env_p);
	
	__atomic_thread_fence(__ATOMIC_RELEASE);

	__atomic_store_n(&initialized, 1, __ATOMIC_RELEASE);

	return nex_id;
}


// ---------- ring layout ----------
struct shm_ring_hdr {
  pthread_mutex_t lock;
  volatile uint64_t head;   // producer moves head forward
  volatile uint64_t tail;   // consumer moves tail forward
  volatile uint64_t size;   // power-of-two
  volatile uint64_t closed;   // 0=open, 1=closed
};

struct shm_ring {
  struct shm_ring_hdr* h;
  uint8_t*             buf;
  int                  fd;
  size_t               map_len;
};

// ---------- “fd” table ----------
struct nex_shm_conn {
  struct shm_ring rx;  // read from here (local <lid:qp>)
  struct shm_ring tx;  // write to here (remote <lid:qp>)
  int             in_use;
  uint32_t        local_lid;
  uint32_t        remote_lid;
  uint32_t        local_qp;
  uint32_t        remote_qp;
};

#ifndef NEX_SHM_MAX_CONN
#define NEX_SHM_MAX_CONN 4096
#endif

static struct nex_shm_conn g_conns[NEX_SHM_MAX_CONN];
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

// allocate a small integer “fd”
static int conn_alloc(void) {
  pthread_mutex_lock(&g_conn_mutex);
  for (int i = 0; i < NEX_SHM_MAX_CONN; ++i) {
    if (!g_conns[i].in_use) { 
      g_conns[i].in_use = 1; 
      pthread_mutex_unlock(&g_conn_mutex);
      return i; 
    }
  }
  pthread_mutex_unlock(&g_conn_mutex);
  errno = EMFILE;
  return -1;
}

static inline struct nex_shm_conn* conn_get(int fd) {
  pthread_mutex_lock(&g_conn_mutex);
  if (fd < 0 || fd >= NEX_SHM_MAX_CONN || !g_conns[fd].in_use) {
    pthread_mutex_unlock(&g_conn_mutex);
    return NULL;
  }
  pthread_mutex_unlock(&g_conn_mutex);
  return &g_conns[fd];
}

static size_t pow2_u64(size_t v) {
  // return nearest power-of-two >= v, min 64KB default
  if (v < 65536u) v = 65536u;
  v--; v |= v>>1; v |= v>>2; v |= v>>4; v |= v>>8; v |= v>>16; v |= v>>32; v++;
  return v;
}

static int shm_path_from_tuple(const char* lid, const char* qp, char* out, size_t outsz) {
  return snprintf(out, outsz, "%s:%s", lid, qp) >= (int)outsz ? -ENAMETOOLONG : 0;
}

// service_id format is:
//   "<local_lid>:<remote_lid>:<local_qp>:<remote_qp>"
static int parse_service_id(const char* service_id,
                            char** llid, char** lqp,
                            char** rlid, char** rqp,
                            char*  scratch, size_t scratch_len) {
  size_t n = strnlen(service_id, scratch_len);
  if (n == 0 || n >= scratch_len) return -EINVAL;
  memcpy(scratch, service_id, n+1);
  // split by ':'
  int parts = 0;
  char* tok = scratch;
  char* save = scratch;
  while (*save) { if (*save == ':') { *save = '\0'; parts++; } save++; }
  // parts is number of colons; must be 3 -> 4 tokens
  if (parts != 3) return -EINVAL;
  char* p0 = tok;            // local lid
  char* p1 = p0 + strlen(p0) + 1; // remote lid
  char* p2 = p1 + strlen(p1) + 1; // local qp
  char* p3 = p2 + strlen(p2) + 1; // remote qp
  if (!*p0 || !*p1 || !*p2 || !*p3) return -EINVAL;
  *llid = p0; *lqp = p2; *rlid = p1; *rqp = p3;
  return 0;
}

static int open_local_ring(const char* name, uint64_t bytes, struct shm_ring* out) {
  int created = 0;
  int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) {
    created = 1;
  } else if (errno == EEXIST) {
    NEX_TRACE("ERROR: open_local_ring existing name=%s", name);
    errno = EEXIST;
    return -errno;
  }

  if (fd < 0) return -errno;

  uint64_t sz = pow2_u64(bytes);
  size_t map_len = sizeof(struct shm_ring_hdr) + (size_t)sz;

  if (ftruncate(fd, (off_t)map_len) != 0) { int e = -errno; close(fd); return e; }

  void* p = mmap(NULL, map_len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) { int e = -errno; close(fd); if (created) shm_unlink(name); return e; }

  struct shm_ring_hdr* h = (struct shm_ring_hdr*)p;

  if (created) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&h->lock, &attr);
    pthread_mutexattr_destroy(&attr);
  }

  __atomic_store_n(&h->head, 0u, __ATOMIC_RELEASE);
  __atomic_store_n(&h->tail, 0u, __ATOMIC_RELEASE);
  __atomic_store_n(&h->closed, 0u, __ATOMIC_RELEASE);
  __atomic_thread_fence(__ATOMIC_RELEASE);
  __atomic_store_n(&h->size, sz, __ATOMIC_RELEASE);

  out->h = h;
  out->buf = (uint8_t*)(h + 1);
  out->fd = fd;
  out->map_len = map_len;

  return 0;
}


// open peer ring (wait until it exists)
static int open_remote_ring_wait(const char* name, uint64_t bytes, struct shm_ring* out) {
  int fd = -1;
  while (1) {
    fd = shm_open(name, O_RDWR | O_CLOEXEC, 0);
    if (fd >= 0) break;
    yield();
  }

  uint64_t sz = pow2_u64(bytes);
  size_t map_len = sizeof(struct shm_ring_hdr) + (size_t)sz;

  struct stat st;
  do{
    if (fstat(fd, &st) != 0) {
      NEX_TRACE("ERROR: fstat failed %d ", errno);
      int e = -errno; 
      close(fd); 
      return e; 
    }
    yield();
  }while(st.st_size != map_len);

  void* p = mmap(NULL, (size_t)map_len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) { 
    NEX_TRACE("ERROR: mmap failed %d ", errno);
    int e = -errno; 
    close(fd); 
    return e; 
  }

  struct shm_ring_hdr* h = (struct shm_ring_hdr*)p;
  // wait until producer published size
  while (true) {
    uint64_t s = __atomic_load_n(&h->size, __ATOMIC_ACQUIRE);
    if (s==sz) break;
    yield();
  }

  out->h = h;
  out->buf = (uint8_t*)(h + 1);
  out->fd  = fd;
  out->map_len = (size_t)st.st_size;
  return 0;
}


/* 
  create local shm named "<local_lid>:<local_qp>", 
  then wait for peer "<remote_lid>:<remote_qp>" to appear. 
  return a single “fd” (index). 
  read() pulls from rx (local),
  write() pushes to tx (remote). 
*/
int nex_shm_dial(const char* service_id, int* fd_out) {
  NEX_TRACE("nex_shm_dial service_id=%s; fd_out=%p", service_id, (void*)fd_out);
  if (!service_id || !fd_out) {
    NEX_TRACE("ERROR: nex_shm_dial invalid arguments");
    return EINVAL;
  }

  char scratch[256];
  char *llid, *lqp, *rlid, *rqp;
  int rc = parse_service_id(service_id, &llid, &lqp, &rlid, &rqp, scratch, sizeof(scratch));
  NEX_TRACE("nex_shm_dial service_id=%s parse=%d", service_id, rc);
  if (rc) {
    NEX_TRACE("ERROR: nex_shm_dial parse_service_id failed");
    return -rc;
  }

  char local_name[256], remote_name[256];
  if ((rc = shm_path_from_tuple(llid, lqp, local_name, sizeof(local_name))) != 0) {
    NEX_TRACE("ERROR: nex_shm_dial shm_path_from_tuple failed");
    return -rc;
  }
  if ((rc = shm_path_from_tuple(rlid, rqp, remote_name, sizeof(remote_name))) != 0) {
    NEX_TRACE("ERROR: nex_shm_dial shm_path_from_tuple failed");
    return -rc;
  }

  NEX_TRACE("nex_shm_dial local_name=%s remote_name=%s", local_name, remote_name);
  // allocate connection slot
  int fd = conn_alloc();
  if (fd < 0) {
    NEX_TRACE("ERROR: nex_shm_dial conn_alloc failed");
    return errno ? errno : EMFILE;
  }
  
  struct nex_shm_conn* c = conn_get(fd);
  c->local_lid = parse_u32(llid);
  c->remote_lid = parse_u32(rlid);
  c->local_qp = parse_u32(lqp);
  c->remote_qp = parse_u32(rqp);

  const uint32_t ring_bytes = 40 * 1024 * 1024; // 40MB per direction
  
  if ((rc = open_local_ring(local_name, ring_bytes, &c->rx)) != 0) {
    c->in_use = 0; 
    NEX_TRACE("ERROR: nex_shm_dial open_local_ring failed local_name=%s error=%d", local_name, rc);
    return -rc; 
  }

  NEX_TRACE("created/opened local shm %s (size=%lu)", local_name, c->rx.h->size);

  if ((rc = open_remote_ring_wait(remote_name, ring_bytes, &c->tx)) != 0) {
    // cleanup local on failure
    NEX_TRACE("ERROR: nex_shm_dial open_remote_ring_wait failed remote_name=%s error=%d", remote_name, rc);
    munmap(c->rx.h, c->rx.map_len);
    close(c->rx.fd);
    shm_unlink(local_name);
    c->in_use = 0;
    return -rc;
  }

  NEX_TRACE("connected to remote shm %s (size=%lu)", remote_name, c->tx.h->size);

  *fd_out = fd;
  return 0;
}


ssize_t nex_shm_read(int fd, void* buf, size_t len, int apply_perf_model) {
  // apply_perf_model = 0; // --- IGNORE ---
  int slot = 0;
 

  struct nex_shm_conn* c = conn_get(fd);
  if (!c) { errno = EBADF; return -1; }
  if (len == 0) return 0;

  if(apply_perf_model){
    slot = accvm_syms.recv_data_qp(c->remote_lid, c->local_lid, len,
                                   c->remote_qp, c->local_qp, 0u, true);
  }

  struct shm_ring_hdr* h = c->rx.h;
  size_t done = 0;
  int iter = 0;
  while (done < len) {

    // pthread_mutex_lock(&h->lock);

    volatile uint64_t size  = __atomic_load_n(&h->size, __ATOMIC_ACQUIRE);
    volatile uint64_t head  = __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);
    volatile uint64_t tail  = __atomic_load_n(&h->tail, __ATOMIC_ACQUIRE);
    volatile uint64_t avail = head - tail; 

    if (avail == 0) {
      if (__atomic_load_n(&h->closed, __ATOMIC_ACQUIRE)) {
        errno = EPIPE;
        // pthread_mutex_unlock(&h->lock);
        return -1;
      }
      // pthread_mutex_unlock(&h->lock);
      yield();
      continue;
    }

    iter++;
    NEX_TRACE_TIMING("nex_shm_read data (iter=%d) need=%lu done=%lu head=%lu tail=%lu", iter, (unsigned long)(len - done), (unsigned long)done, (unsigned long)head, (unsigned long)tail);

    size_t need = len - done;
    size_t to_read = (size_t)avail < need ? (size_t)avail : need;

    uint64_t t0 = tail & (size - 1);
    uint64_t first = size - t0;
    if (first >= to_read) first = (uint64_t)to_read;

    memcpy((uint8_t*)buf + done, c->rx.buf + t0, (size_t)first);
    if (first < to_read) {
      memcpy((uint8_t*)buf + done + first, c->rx.buf, to_read - (size_t)first);
    }

    __atomic_store_n(&h->tail, tail + (uint64_t)to_read, __ATOMIC_RELEASE);
    // pthread_mutex_unlock(&h->lock);
    done += to_read;
  }

  if (apply_perf_model) {
    accvm_syms.wait_for_completion(slot);
  }

  return (ssize_t)done; // == len
}

/* Block until exactly len bytes are written, or error. Returns len on success, -1 on error (errno set). */
ssize_t nex_shm_write(int fd, const void* buf, size_t len, int apply_perf_model) {
  
  struct nex_shm_conn* c = conn_get(fd);
  if (!c) { errno = EBADF; return -1; }
  if (len == 0) return 0;

  struct shm_ring_hdr* h = c->tx.h;
  int slot = 0;
  if(apply_perf_model){
    slot = accvm_syms.send_data_qp(c->local_lid, c->remote_lid, len,
                                   c->local_qp, c->remote_qp, 0u, true);
  }
  size_t done = 0;
  int iter = 0;
  while (done < len) {
    // pthread_mutex_lock(&h->lock);

    volatile uint64_t size = __atomic_load_n(&h->size, __ATOMIC_ACQUIRE);
    volatile uint64_t head = __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);
    volatile uint64_t tail = __atomic_load_n(&h->tail, __ATOMIC_ACQUIRE);
    volatile uint64_t used = head - tail;
    volatile uint64_t free_bytes = size - used;

    if (free_bytes == 0) {
      if (__atomic_load_n(&h->closed, __ATOMIC_ACQUIRE)) {
        errno = EPIPE;
        // pthread_mutex_unlock(&h->lock);
        return -1;
      }
      iter++;
      NEX_TRACE("nex_shm_write waiting for free space (iter=%d)", iter);
      // pthread_mutex_unlock(&h->lock);
      yield();
      continue;
    }

    NEX_TRACE_TIMING("nex_shm_write data (iter=%d) need=%lu done=%lu head=%lu tail=%lu", iter++, (unsigned long)(len - done), (unsigned long)done, (unsigned long)head, (unsigned long)tail);

    
    size_t need = len - done;
    size_t to_write = (size_t)free_bytes < need ? (size_t)free_bytes : need;

    uint64_t h0 = head & (size - 1);
    uint64_t first = size - h0;
    if (first >= to_write) first = (uint64_t)to_write;

    memcpy(c->tx.buf + h0, (const uint8_t*)buf + done, (size_t)first);
    if (first < to_write) {
      memcpy(c->tx.buf, (const uint8_t*)buf + done + first, to_write - (size_t)first);
    }

    __atomic_store_n(&h->head, head + (uint64_t)to_write, __ATOMIC_RELEASE);
    // pthread_mutex_unlock(&h->lock);
    done += to_write;
  }

  if(apply_perf_model){
    accvm_syms.wait_for_completion(slot);
  }
  
  return (ssize_t)done; // == len
}

static int nex_shm_copy_from_iov(const struct iovec *iov, int iovcnt,
                                 size_t *index, size_t *offset,
                                 uint8_t *dst, size_t len)
{
  size_t remaining = len;
  while (remaining > 0) {
    if (*index >= (size_t)iovcnt)
      return -1;
    const struct iovec *cur = &iov[*index];
    if (cur->iov_len == 0) {
      ++(*index);
      *offset = 0;
      continue;
    }
    if (*offset >= cur->iov_len) {
      ++(*index);
      *offset = 0;
      continue;
    }
    size_t avail = cur->iov_len - *offset;
    size_t chunk = avail < remaining ? avail : remaining;
    memcpy(dst, (const uint8_t *)cur->iov_base + *offset, chunk);
    dst += chunk;
    remaining -= chunk;
    *offset += chunk;
    if (*offset == cur->iov_len) {
      ++(*index);
      *offset = 0;
    }
  }
  return 0;
}

static int nex_shm_copy_to_iov(const uint8_t *src, size_t len,
                               const struct iovec *iov, int iovcnt,
                               size_t *index, size_t *offset)
{
  size_t remaining = len;
  while (remaining > 0) {
    if (*index >= (size_t)iovcnt)
      return -1;
    const struct iovec *cur = &iov[*index];
    if (cur->iov_len == 0) {
      ++(*index);
      *offset = 0;
      continue;
    }
    if (*offset >= cur->iov_len) {
      ++(*index);
      *offset = 0;
      continue;
    }
    size_t avail = cur->iov_len - *offset;
    size_t chunk = avail < remaining ? avail : remaining;
    memcpy((uint8_t *)cur->iov_base + *offset, src, chunk);
    src += chunk;
    remaining -= chunk;
    *offset += chunk;
    if (*offset == cur->iov_len) {
      ++(*index);
      *offset = 0;
    }
  }
  return 0;
}

ssize_t nex_shm_readv(int fd, const struct iovec *iov, int iovcnt,
                      int apply_perf_model, bool wait_completion, int *slot_out,
                      uint32_t tag)
{
  // apply_perf_model = 0; // --- IGNORE ---
  
  if (iovcnt < 0) {
    errno = EINVAL;
    return -1;
  }
  if (iovcnt > 0 && !iov) {
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

  if (wait_completion) {
    assert(apply_perf_model);
    assert(slot_out != NULL);
  }
  if (total_len == 0) return 0;

  struct nex_shm_conn* c = conn_get(fd);
  if (!c) { errno = EBADF; return -1; }

  int slot = -1;
  if (apply_perf_model) {
    slot = accvm_syms.recv_data_qp(c->remote_lid, c->local_lid, total_len,
                                   c->remote_qp, c->local_qp, tag, wait_completion);
    if (slot_out) *slot_out = slot;
    
    // has to wait here, otherwise, the application can read data directly before the perf model says its ready
    accvm_syms.wait_for_completion(slot);

  }

  struct shm_ring_hdr* h = c->rx.h;
  size_t done = 0;
  int iter = 0;
  size_t iov_index = 0;
  size_t iov_offset = 0;

  while (done < total_len) {
    volatile uint64_t size  = __atomic_load_n(&h->size, __ATOMIC_ACQUIRE);
    volatile uint64_t head  = __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);
    volatile uint64_t tail  = __atomic_load_n(&h->tail, __ATOMIC_ACQUIRE);
    volatile uint64_t avail = head - tail;

    if (avail == 0) {
      if (__atomic_load_n(&h->closed, __ATOMIC_ACQUIRE)) {
        errno = EPIPE;
        return -1;
      }
      NEX_TRACE("nex_shm_readv waiting for data (iter=%d)", iter++);
      yield();
      continue;
    }

    iter++;
    NEX_TRACE_TIMING("nex_shm_readv data (iter=%d) need=%lu done=%lu head=%lu tail=%lu",
                     iter, (unsigned long)(total_len - done), (unsigned long)done,
                     (unsigned long)head, (unsigned long)tail);

    size_t need = total_len - done;
    size_t to_read = (size_t)avail < need ? (size_t)avail : need;

    uint64_t t0 = tail & (size - 1);
    uint64_t first = size - t0;
    if (first >= to_read) first = (uint64_t)to_read;

    if (first) {
      if (nex_shm_copy_to_iov(c->rx.buf + t0, (size_t)first,
                              iov, iovcnt, &iov_index, &iov_offset)) {
        errno = EFAULT;
        return -1;
      }
    }
    if (first < to_read) {
      size_t remaining = to_read - (size_t)first;
      if (nex_shm_copy_to_iov(c->rx.buf, remaining,
                              iov, iovcnt, &iov_index, &iov_offset)) {
        errno = EFAULT;
        return -1;
      }
    }

    __atomic_store_n(&h->tail, tail + (uint64_t)to_read, __ATOMIC_RELEASE);
    done += to_read;
  }

  // Do not block here; caller (or upper wrapper) is responsible for waiting
  // using the returned slot if desired.
  return (ssize_t)done;
}
ssize_t nex_shm_writev(int fd, const struct iovec *iov, int iovcnt,
                       int apply_perf_model, bool wait_completion, int *slot_out,
                       uint32_t tag) {

  
  if (iovcnt < 0) {
    errno = EINVAL;
    return -1;
  }

  if (iovcnt > 0 && !iov) {
    errno = EINVAL;
    return -1;
  }

  if(wait_completion){
    assert(apply_perf_model);
    assert(slot_out != NULL);
  }

  // apply_perf_model = 0; // --- IGNORE ---
  
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
  int slot = -1;

  struct nex_shm_conn* c = conn_get(fd);
  if (!c) { errno = EBADF; return -1; }
  if (slot_out)
      *slot_out = -1;

  if(apply_perf_model){
    slot = accvm_syms.send_data_qp(c->local_lid, c->remote_lid, total_len,
                                   c->local_qp, c->remote_qp, tag, wait_completion);
    if (slot_out)
        *slot_out = slot;
  }

  struct shm_ring_hdr* h = c->tx.h;

  size_t done = 0;
  int iter = 0;
  size_t iov_index = 0;
  size_t iov_offset = 0;

  while (done < total_len) {
    volatile uint64_t size = __atomic_load_n(&h->size, __ATOMIC_ACQUIRE);
    volatile uint64_t head = __atomic_load_n(&h->head, __ATOMIC_ACQUIRE);
    volatile uint64_t tail = __atomic_load_n(&h->tail, __ATOMIC_ACQUIRE);
    volatile uint64_t used = head - tail;
    volatile uint64_t free_bytes = size - used;

    if (free_bytes == 0) {
      if (__atomic_load_n(&h->closed, __ATOMIC_ACQUIRE)) {
        errno = EPIPE;
        return -1;
      }
      NEX_TRACE("nex_shm_writev waiting for free space (iter=%d)", iter++);
      yield();
      continue;
    }

    iter++;
    NEX_TRACE_TIMING("nex_shm_writev data (iter=%d) need=%lu done=%lu head=%lu tail=%lu",
                     iter, (unsigned long)(total_len - done), (unsigned long)done,
                     (unsigned long)head, (unsigned long)tail);

    size_t need = total_len - done;
    size_t to_write = (size_t)free_bytes < need ? (size_t)free_bytes : need;

    uint64_t h0 = head & (size - 1);
    uint64_t first = size - h0;
    if (first >= to_write) first = (uint64_t)to_write;

    if (first) {
      if (nex_shm_copy_from_iov(iov, iovcnt, &iov_index, &iov_offset,
                                c->tx.buf + h0, (size_t)first)) {
        errno = EFAULT;
        return -1;
      }
    }
    if (first < to_write) {
      size_t remaining = to_write - (size_t)first;
      if (nex_shm_copy_from_iov(iov, iovcnt, &iov_index, &iov_offset,
                                c->tx.buf, remaining)) {
        errno = EFAULT;
        return -1;
      }
    }

    __atomic_store_n(&h->head, head + (uint64_t)to_write, __ATOMIC_RELEASE);
    done += to_write;
  }

  // do not wait here; the caller can await completion asynchronously

  return (ssize_t)done;
}

// optional cleanup if you need it
int nex_shm_close(int fd) {
  struct nex_shm_conn* c = conn_get(fd);
  if (!c) return EBADF;
  if (c->rx.h) munmap(c->rx.h, c->rx.map_len);
  if (c->tx.h) munmap(c->tx.h, c->tx.map_len);
  if (c->rx.fd >= 0) close(c->rx.fd);
  if (c->tx.fd >= 0) close(c->tx.fd);
  c->in_use = 0;
  return 0;
}

int nex_shm_shutdown(int fd) {
  struct nex_shm_conn* c = conn_get(fd);
  if (!c) return EBADF;

  NEX_TRACE("nex_shm_shutdown fd=%d", fd);
  __atomic_store_n(&c->tx.h->closed, 1, __ATOMIC_RELEASE);
  __atomic_store_n(&c->rx.h->closed, 1, __ATOMIC_RELEASE);

  // Optional nudge: advance head by 0 or write a 1-byte noop so an empty reader wakes
  // (usually not needed if it polls/yields)

  return 0;
}
