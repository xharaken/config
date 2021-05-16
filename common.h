#ifndef _common_
#define _common_
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <math.h>
#include <malloc.h>
#include <regex.h>
#include <libgen.h>
#include <time.h>
#include <utime.h>
#include <setjmp.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <bits/syscall.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef MAP_HALFPROC
#define MAP_HALFPROC 0x80
#endif
#ifndef HALFPROC_MMAP_BEGIN
#define HALFPROC_MMAP_BEGIN 0x3f8000000000ULL
#endif
#ifndef HALFPROC_MMAP_END
#define HALFPROC_MMAP_END 0x5f8000000000ULL
#endif
#ifndef CLONE_HALFPROC
#define CLONE_HALFPROC 0x00400000
#endif
#ifndef SYS_dmread
#define SYS_dmread -1
#endif
#ifndef SYS_dmwrite
#define SYS_dmwrite -1
#endif
#ifndef SYS_halfproc_getvma
#define SYS_halfproc_getvma -1
#endif

#ifdef USE_HALFPROC
#include "halfproc.h"
#endif

#define FALSE 0
#define TRUE 1
#define UNDEF -1
#define SUCCESS 0
#define FAILURE 1

#define PIPE_OUT 0
#define PIPE_IN 1

#define PI 3.14159265358979323846264338327950288
#define E 2.71828182845904523536028747135266249
#define EPS6 1e-6
#define EPS12 1e-12
#define FNAME_SIZE 256
#define PAGESIZE 4096
#define PROCNUM sysconf(_SC_NPROCESSORS_CONF)
#define PROCNUM2 (sysconf(_SC_NPROCESSORS_CONF) / 2)
#define PAGESIZE_ALIGN(addr) (((addr) + PAGESIZE - 1) / PAGESIZE * PAGESIZE)

#define SYS_MRAND_A 645
#define SYS_MRAND_B 1234567
#define SYS_MRAND_X0 137
#define SYS_MRAND_E32 (1.0 / (1 << 16) / (1 << 16))
#define SYS_MRAND_E64 (1.0 / (1 << 16) / (1 << 16) / (1 << 16) / (1 << 16))
#define SYS_LAP_TIME_MAX 128
#define SYS_MRAND_BUF_SIZE (sizeof(uint64_t) * 521 + sizeof(int8_t) + sizeof(int64_t) * 2)
#define SYS_TIME_BUF_SIZE (SYS_LAP_TIME_MAX * sizeof(double))

#define SET_TCP_NODELAY 1

#define IP_SIZE 128
#define SELF_IP "127.0.0.1"

#define CONTAINER_DEFAULT -1
#define VECTOR_INIT_CAPACITY 256
#define VECTOR_EXPAND_RATE 8.0
#define WRITEBUF_INIT_CAPACITY 4096
#define WRITEBUF_EXPAND_RATE 8.0
#define IDPOOL_INIT_CAPACITY 256
#define LEASE_INIT_CAPACITY CONTAINER_DEFAULT
#define LEASE_EXPAND_RATE CONTAINER_DEFAULT
#define DEQUE_INIT_CAPACITY 256
#define DEQUE_EXPAND_RATE 2.0

#define error() print_error(__FILE__, __LINE__)
#define throw(ret) if((ret) == FALSE) { printf("backtrace: %d @ %s\n", __LINE__, __FILE__); return (ret); }
#define catch(ret) if((ret) == FALSE) error()
#define MIN(x, y) (x) < (y) ? (x) : (y)
#define MAX(x, y) (x) > (y) ? (x) : (y)

typedef struct host_t
{
  char ip[IP_SIZE];
  uint16_t port;
}host_t;

typedef struct vector_t
{
  int32_t init_capacity;
  int32_t capacity;
  int32_t size;
  float expand_rate;
  void *undef_elem;
  void **buf;
}vector_t;

typedef struct xvector_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  vector_t *vector;
}xvector_t;

typedef struct readbuf_t
{
  int8_t *buf;
  int64_t offset;
  int64_t size;
}readbuf_t;

typedef struct xreadbuf_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  readbuf_t *readbuf;
}xreadbuf_t;

typedef struct writebuf_t
{
  int8_t *buf;
  int64_t size;
  int64_t capacity;
  float expand_rate;
}writebuf_t;

typedef struct xwritebuf_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  writebuf_t *writebuf;
}xwritebuf_t;

typedef struct idpool_t
{
  int32_t init_capacity;
  int32_t capacity;
  int32_t sp;
  int32_t size;
  int32_t *stack;
  int8_t *used_flag;
}idpool_t;

typedef struct xidpool_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  idpool_t *idpool;
}xidpool_t;

typedef struct lease_t
{
  int32_t init_capacity;
  float expand_rate;
  idpool_t *idpool;
  vector_t *vector;
}lease_t;

typedef struct xlease_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  lease_t *lease;
}xlease_t;

typedef struct deque_t
{
  int32_t capacity;
  int32_t init_capacity;
  int32_t head;
  int32_t tail;
  float expand_rate;
  void **buf;
}deque_t;

typedef struct xdeque_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  deque_t *deque;
}xdeque_t;

typedef struct taskque_t
{
  int8_t notify_flag;
  deque_t *deque;
  void *notify_elem;
#if USE_HALFPROC
  halfproc_cond_t cond;
  halfproc_mutex_t mutex;
#else
  pthread_cond_t cond;
  pthread_mutex_t mutex;
#endif
}taskque_t;

typedef struct cell_t
{
  void *elem;
  struct cell_t *prev;
  struct cell_t *next;
}cell_t;

typedef struct list_t
{
  int32_t size;
  int32_t pos;
  cell_t *head;
  cell_t *iter;
}list_t;

typedef struct xlist_t
{
#if USE_HALFPROC
  halfproc_mutex_t mutex;
#else
  pthread_mutex_t mutex;
#endif
  list_t *list;
}xlist_t;

static __thread double _tls_time_laps[SYS_LAP_TIME_MAX];
static __thread uint64_t _tls_mrand_x[521];
static __thread int8_t _tls_mrand_init_flag = FALSE;
static __thread uint64_t _tls_mrand_cur;
static __thread uint64_t _tls_mrand_cur2;

extern void* __attribute__((weak)) my_malloc_hook(int64_t size);
extern void* __attribute__((weak)) my_realloc_hook(void *old_p, int64_t size);
extern void __attribute__((weak)) my_free_hook(void *p);

/* basic */

static inline void print_error(const char *file, int line);
static inline void btrace(void);
static inline void out(const char *format, ...);
static inline void outn(const char *format, ...);
static inline void err(const char *format, ...);
static inline void errn(const char *format, ...);
static inline void* my_malloc(int64_t size);
static inline void* my_calloc(int64_t size);
static inline void* my_realloc(void *old_p, int64_t size);
static inline void my_free(void *p);
static inline void bind_to_cpu(int cpu);
static inline double get_time(void);
static inline void time_lap(int i);
static inline double time_ref(int i);
static inline double time_diff(int i);
static inline void time_snapshot(int8_t *buf);
static inline void time_resume(int8_t *buf);
static inline void mrand_init(int64_t x0);
static inline double mrand_01(void);
static inline void mrand_snapshot(int8_t *buf);
static inline void mrand_resume(int8_t *buf);
static inline int64_t mrand_int(int64_t inf, int64_t sup);
static inline void halt(double time);
static inline int32_t my_write(int fd, void *p, int32_t size);
static inline int32_t my_read(int fd, void *p, int32_t size);
static inline int64_t fsize(FILE *fp);

/* socket */

static inline int32_t sock_listen(uint16_t port, int32_t backlog);
static inline int32_t sock_accept(int listen_sock);
static inline void sock_close(int sock);
static inline int32_t sock_connect(char *ip, uint16_t port);
static inline int32_t sock_send(int sock, void *p, int32_t size);
static inline int32_t sock_recv(int sock, void *p, int32_t size);
static inline int32_t sock_create_udp(void);
static inline int32_t sock_bind_udp(uint16_t port);
static inline void sock_addr_udp(char *ip, uint16_t port, struct sockaddr_in *addr);
static inline int32_t sock_send_udp(int sock, void *p, int32_t size, struct sockaddr_in *addr);
static inline int32_t sock_recv_udp(int sock, void *p, int32_t size, struct sockaddr_in *addr);
static inline void sock_get_myhost(int sock, host_t *host);
static inline void sock_get_yourhost(int sock, host_t *host);
static inline void sock_print_myhost(int sock);
static inline void sock_print_yourhost(int sock);
static inline void fqdn_to_ip(char *fqdn, char *ip, int32_t size);
static inline int sock_create_epoll(int32_t size);
static inline void sock_add_epoll(int sock, int epoll);
static inline void sock_del_epoll(int sock, int epoll);
static inline uint64_t htonll(uint64_t ull);
static inline uint64_t ntohll(uint64_t n_ull);

/* vector */

static inline vector_t* vector_alloc(int32_t init_capacity, float expand_rate, void *undef_elem);
static inline void vector_free(vector_t *vector);
static inline void vector_clear(vector_t *vector);
static inline int32_t vector_isempty(vector_t *vector);
static inline int32_t vector_size(vector_t *vector);
static inline void vector_push(vector_t *vector, void *elem);
static inline void* vector_pop(vector_t *vector);
static inline void* vector_front(vector_t *vector);
static inline void* vector_back(vector_t *vector);
static inline void* vector_at(vector_t *vector, int32_t pos);
static inline void vector_assign(vector_t *vector, int32_t pos, void *elem);
static inline xvector_t* xvector_alloc(int32_t init_capacity, float expand_rate, void *undef_elem);
static inline void xvector_free(xvector_t *xvector);
static inline void xvector_clear(xvector_t *xvector);
static inline int32_t xvector_isempty(xvector_t *xvector);
static inline int32_t xvector_size(xvector_t *xvector);
static inline void xvector_push(xvector_t *xvector, void *elem);
static inline void* xvector_pop(xvector_t *xvector);
static inline void* xvector_front(xvector_t *xvector);
static inline void* xvector_back(xvector_t *xvector);
static inline void* xvector_at(xvector_t *xvector, int32_t pos);
static inline void xvector_assign(xvector_t *xvector, int32_t pos, void *elem);

/* readbuf */

static inline readbuf_t* readbuf_alloc(void *buf, int64_t size);
static inline void readbuf_free(readbuf_t *readbuf);
static inline void* readbuf_buf(readbuf_t *readbuf);
static inline int64_t readbuf_offset(readbuf_t *readbuf);
static inline void readbuf_copy(readbuf_t *readbuf, void *elem, int64_t elem_size);
static inline xreadbuf_t* xreadbuf_alloc(void *buf, int64_t size);
static inline void xreadbuf_free(xreadbuf_t *xreadbuf);
static inline void* xreadbuf_buf(xreadbuf_t *xreadbuf);
static inline int64_t xreadbuf_offset(xreadbuf_t *xreadbuf);
static inline void xreadbuf_copy(xreadbuf_t *xreadbuf, void *elem, int64_t elem_size);

/* writebuf */

static inline writebuf_t* writebuf_alloc(int64_t init_capacity, float expand_rate);
static inline void writebuf_free(writebuf_t *writebuf);
static inline int64_t writebuf_size(writebuf_t *writebuf);
static inline void* writebuf_buf(writebuf_t *writebuf);
static inline void writebuf_copy(writebuf_t *writebuf, void *elem, int64_t elem_size);
static inline int64_t writebuf_skip(writebuf_t *writebuf, int64_t size);
static inline void writebuf_seekcopy(writebuf_t *writebuf, int64_t offset, void *elem, int64_t elem_size);
static inline xwritebuf_t* xwritebuf_alloc(int64_t init_capacity, float expand_rate);
static inline void xwritebuf_free(xwritebuf_t *xwritebuf);
static inline int64_t xwritebuf_size(xwritebuf_t *xwritebuf);
static inline void* xwritebuf_buf(xwritebuf_t *xwritebuf);
static inline void xwritebuf_copy(xwritebuf_t *xwritebuf, void *elem, int64_t elem_size);
static inline int64_t xwritebuf_skip(xwritebuf_t *xwritebuf, int64_t size);
static inline void xwritebuf_seekcopy(xwritebuf_t *xwritebuf, int64_t offset, void *elem, int64_t elem_size);

/* idpool */

static inline idpool_t* idpool_alloc(int32_t init_capacity);
static inline void idpool_free(idpool_t *idpool);
static inline int32_t idpool_isempty(idpool_t *idpool);
static inline int32_t idpool_size(idpool_t *idpool);
static inline int32_t idpool_get(idpool_t *idpool);
static inline void idpool_put(idpool_t *idpool, int32_t id);
static inline xidpool_t* xidpool_alloc(int32_t init_capacity);
static inline void xidpool_free(xidpool_t *xidpool);
static inline int32_t xidpool_isempty(xidpool_t *xidpool);
static inline int32_t xidpool_size(xidpool_t *xidpool);
static inline int32_t xidpool_get(xidpool_t *xidpool);
static inline void xidpool_put(xidpool_t *xidpool, int32_t id);

/* lease */

static inline lease_t* lease_alloc(int32_t init_capacity, float expand_rate, void *undef_elem);
static inline void lease_free(lease_t *lease);
static inline int lease_isempty(lease_t *lease);
static inline int32_t lease_size(lease_t *lease);
static inline int32_t lease_putin(lease_t *lease, void *elem);
static inline void* lease_pickup(lease_t *lease, int32_t id);
static inline void* lease_at(lease_t *lease, int32_t pos);
static inline xlease_t* xlease_alloc(int32_t init_capacity, float expand_rate, void *undef_elem);
static inline void xlease_free(xlease_t *xlease);
static inline int xlease_isempty(xlease_t *xlease);
static inline int32_t xlease_size(xlease_t *xlease);
static inline int32_t xlease_putin(xlease_t *xlease, void *elem);
static inline void* xlease_pickup(xlease_t *xlease, int32_t id);
static inline void* xlease_at(xlease_t *xlease, int32_t pos);

/* deque */

static inline deque_t* deque_alloc(int32_t init_capacity, float expand_rate);
static inline void deque_free(deque_t *deque);
static inline void deque_clear(deque_t *deque);
static inline int32_t deque_isempty(deque_t *deque);
static inline int32_t deque_size(deque_t *deque);
static inline void* deque_front(deque_t *deque);
static inline void* deque_back(deque_t *deque);
static inline void deque_push(deque_t *deque, void *elem);
static inline void* deque_pop(deque_t *deque);
static inline void* deque_shift(deque_t *deque);
static inline void deque_unshift(deque_t *deque, void *elem);
static inline void* deque_at(deque_t *deque, int32_t pos);
static inline void deque_assign(deque_t *deque, int32_t pos, void *elem);
static inline xdeque_t* xdeque_alloc(int32_t init_capacity, float expand_rate);
static inline void xdeque_free(xdeque_t *xdeque);
static inline void xdeque_clear(xdeque_t *xdeque);
static inline int32_t xdeque_isempty(xdeque_t *xdeque);
static inline int32_t xdeque_size(xdeque_t *xdeque);
static inline void* xdeque_front(xdeque_t *xdeque);
static inline void* xdeque_back(xdeque_t *xdeque);
static inline void xdeque_push(xdeque_t *xdeque, void *elem);
static inline void* xdeque_pop(xdeque_t *xdeque);
static inline void* xdeque_shift(xdeque_t *xdeque);
static inline void xdeque_unshift(xdeque_t *xdeque, void *elem);
static inline void* xdeque_at(xdeque_t *xdeque, int32_t pos);
static inline void xdeque_assign(xdeque_t *xdeque, int32_t pos, void *elem);

/* taskque */

static inline taskque_t* taskque_alloc(int32_t init_capacity, float expand_rate, void *notify_elem);
static inline void taskque_free(taskque_t *taskque);
static inline int32_t taskque_isempty(taskque_t *taskque);
static inline int32_t taskque_size(taskque_t *taskque);
static inline void taskque_unshift(taskque_t *taskque, void *elem);
static inline void* taskque_pop(taskque_t *taskque);
static inline void* taskque_at(taskque_t *taskque, int32_t pos);
static inline void taskque_notify(taskque_t *taskque);

/* list */

static inline cell_t* cell_alloc(void *elem);
static inline void cell_free(cell_t *cell);
static inline list_t* list_alloc(void);
static inline void list_free(list_t *list);
static inline void list_clear(list_t *list);
static inline void list_head(list_t *list);
static inline void list_tail(list_t *list);
static inline int32_t list_isempty(list_t *list);
static inline int32_t list_size(list_t *list);
static inline void* list_curr(list_t *list);
static inline void* list_next(list_t *list);
static inline void* list_prev(list_t *list);
static inline int32_t list_hascurr(list_t *list);
static inline int32_t list_hasnext(list_t *list);
static inline int32_t list_hasprev(list_t *list);
static inline void list_push(list_t *list, void *elem);
static inline void* list_pop(list_t *list);
static inline void* list_shift(list_t *list);
static inline void list_unshift(list_t *list, void *elem);
static inline void list_insert(list_t *list, void *elem);
static inline void* list_remove(list_t *list);
static inline void list_move(list_t *list, int32_t pos);
static inline void* list_at(list_t *list, int32_t pos);
static inline void list_assign(list_t *list, int32_t pos, void *elem);
static inline xlist_t* xlist_alloc(void);
static inline void xlist_free(xlist_t *xlist);
static inline void xlist_clear(xlist_t *xlist);
static inline void xlist_head(xlist_t *xlist);
static inline void xlist_tail(xlist_t *xlist);
static inline int32_t xlist_isempty(xlist_t *xlist);
static inline int32_t xlist_size(xlist_t *xlist);
static inline void* xlist_curr(xlist_t *xlist);
static inline void* xlist_next(xlist_t *xlist);
static inline void* xlist_prev(xlist_t *xlist);
static inline int32_t xlist_hascurr(xlist_t *xlist);
static inline int32_t xlist_hasnext(xlist_t *xlist);
static inline int32_t xlist_hasprev(xlist_t *xlist);
static inline void xlist_push(xlist_t *xlist, void *elem);
static inline void* xlist_pop(xlist_t *xlist);
static inline void* xlist_shift(xlist_t *xlist);
static inline void xlist_unshift(xlist_t *xlist, void *elem);
static inline void xlist_insert(xlist_t *xlist, void *elem);
static inline void* xlist_remove(xlist_t *xlist);
static inline void xlist_move(xlist_t *xlist, int32_t pos);
static inline void* xlist_at(xlist_t *xlist, int32_t pos);
static inline void xlist_assign(xlist_t *xlist, int32_t pos, void *elem);


/* basic */

static inline void print_error(const char *file, int line)
{
  /*
  int32_t ret;
  */
  
  fprintf(stderr, "[error] %s @ %s : %d\n", strerror(errno), file, line);
  fflush(stdout);
  /*
  ret = kill(getpid(), SIGQUIT);
  if(ret < 0) exit(1);
  */
  exit(1);
  return;
}

static inline void btrace(void)
{
  int n;
  void *buf[4096];
  
  n = backtrace(buf, 4096);
  backtrace_symbols_fd(buf, n, 1);
  return;
}

static inline void out(const char *format, ...)
{
  va_list va_arg;
  
  va_start(va_arg, format);
  vprintf(format, va_arg);
  fflush(stdout);
  va_end(va_arg);
  return;
}

static inline void outn(const char *format, ...)
{
  va_list va_arg;
  
  va_start(va_arg, format);
  vprintf(format, va_arg);
  printf("\n");
  fflush(stdout);
  va_end(va_arg);
  return;
}

static inline void err(const char *format, ...)
{
  va_list va_arg;
  
  va_start(va_arg, format);
  vfprintf(stderr, format, va_arg);
  fflush(stderr);
  va_end(va_arg);
  return;
}

static inline void errn(const char *format, ...)
{
  va_list va_arg;
  
  va_start(va_arg, format);
  vfprintf(stderr, format, va_arg);
  fprintf(stderr, "\n");
  fflush(stderr);
  va_end(va_arg);
  return;
}

static inline void* my_malloc(int64_t size)
{
  void *p;
  
  if(my_malloc_hook)
    {
      p = my_malloc_hook(size);
    }
  else
    {
      p = malloc(size);
      /*p = calloc(size, 1);*/
    }
  if(size != 0 && p == NULL) error();
  return p;
}

static inline void* my_calloc(int64_t size)
{
  void *p;
  
  p = calloc(size, 1);
  if(size != 0 && p == NULL) error();
  return p;
}

static inline void* my_realloc(void *old_p, int64_t size)
{
  void *p;
  
  if(my_realloc_hook)
    {
      p = my_realloc_hook(old_p, size);
    }
  else
    {
      p = realloc(old_p, size);
    }
  if(size != 0 && p == NULL) error();
  return p;
}

static inline void my_free(void *p)
{
  if(my_free_hook)
    {
      my_free_hook(p);
    }
  else
    {
      free(p);
    }
  return;
}

static inline void bind_to_cpu(int cpu)
{
  cpu_set_t cpu_mask;
  int ret;
  
  CPU_ZERO(&cpu_mask);
  CPU_SET(cpu, &cpu_mask);
  ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_mask);
  if(ret < 0) error();
  return;
}

static inline double get_time(void)
{
  struct timeval tv;
  
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}

static inline void time_lap(int i)
{
  struct timeval tv;
  
  if(!(0 <= i && i < SYS_LAP_TIME_MAX)) error();
  gettimeofday(&tv, NULL);
  _tls_time_laps[i] = tv.tv_sec + tv.tv_usec * 1e-6;
  return;
}

static inline double time_ref(int i)
{
  if(!(0 <= i && i < SYS_LAP_TIME_MAX)) error();
  return _tls_time_laps[i];
}

static inline double time_diff(int i)
{
  struct timeval tv;
  
  if(!(0 <= i && i < SYS_LAP_TIME_MAX)) error();
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6 - _tls_time_laps[i];
}

static inline void time_snapshot(int8_t *buf)
{
  int32_t offset, size;
  
  offset = 0;
  size = SYS_LAP_TIME_MAX * sizeof(double);
  memcpy(buf + offset, _tls_time_laps, size);
  offset += size;
  return;
}

static inline void time_resume(int8_t *buf)
{
  int32_t offset, size;
  
  offset = 0;
  size = SYS_LAP_TIME_MAX * sizeof(double);
  memcpy(_tls_time_laps, buf + offset, size);
  offset += size;
  return;
}

static inline void mrand_init(int64_t x0)
{
  int64_t i;
  
  _tls_mrand_x[0] = SYS_MRAND_A * x0;
  for(i = 1; i < 521; i++)
    {
      _tls_mrand_x[i] = SYS_MRAND_A * _tls_mrand_x[i - 1] + SYS_MRAND_B;
    }
  _tls_mrand_init_flag = TRUE;
  _tls_mrand_cur = 0;
  _tls_mrand_cur2 = 521;
  return;
}

static inline double mrand_01(void)
{
  int64_t i;
  double d;
  
  if(_tls_mrand_init_flag == FALSE)
    {
      _tls_mrand_x[0] = SYS_MRAND_A * SYS_MRAND_X0;
      for(i = 1; i < 521; i++)
        {
          _tls_mrand_x[i] = SYS_MRAND_A * _tls_mrand_x[i - 1];
        }
      _tls_mrand_init_flag = TRUE;
      _tls_mrand_cur = 0;
      _tls_mrand_cur2 = 521;
    }
  
  _tls_mrand_x[_tls_mrand_cur] = _tls_mrand_x[_tls_mrand_cur] ^ _tls_mrand_x[_tls_mrand_cur2 - 32];
  d = _tls_mrand_x[_tls_mrand_cur] * SYS_MRAND_E64;
  _tls_mrand_cur++;
  _tls_mrand_cur2++;
  if(_tls_mrand_cur == 521)
    {
      _tls_mrand_cur = 0;
    }
  if(_tls_mrand_cur2 == 553)
    {
      _tls_mrand_cur2 = 32;
    }
  return d;
}

static inline int64_t mrand_int(int64_t inf, int64_t sup)
{
  return inf + (int64_t)(mrand_01() * (sup - inf + 1));
}

static inline void mrand_snapshot(int8_t *buf)
{
  int64_t offset, size;
  
  offset = 0;
  size = sizeof(int8_t);
  memcpy(buf + offset, &_tls_mrand_init_flag, size);
  offset += size;
  size = sizeof(int64_t);
  memcpy(buf + offset, &_tls_mrand_cur, size);
  offset += size;
  size = sizeof(int64_t);
  memcpy(buf + offset, &_tls_mrand_cur2, size);
  offset += size;
  size = 521 * sizeof(uint64_t);
  memcpy(buf + offset, _tls_mrand_x, size);
  offset += size;
  return;
}

static inline void mrand_resume(int8_t *buf)
{
  int64_t offset, size;
  
  offset = 0;
  size = sizeof(int8_t);
  memcpy(&_tls_mrand_init_flag, buf + offset, size);
  offset += size;
  size = sizeof(int64_t);
  memcpy(&_tls_mrand_cur, buf + offset, size);
  offset += size;
  size = sizeof(int64_t);
  memcpy(&_tls_mrand_cur2, buf + offset, size);
  offset += size;
  size = 521 * sizeof(uint64_t);
  memcpy(_tls_mrand_x, buf + offset, size);
  offset += size;
  return;
}

static inline void halt(double time)
{
  struct timespec spec;
  
  spec.tv_sec = (int)time;
  spec.tv_nsec = (int)((time - (int)time) * 1e9);
  nanosleep(&spec, NULL);
  return;
}

static inline int32_t my_write(int fd, void *p, int32_t size)
{
  int32_t ret;
  
  ret = write(fd, (int8_t*)p, size);
  if(ret != size) return -1;
  if(ret < 0) return ret;
  return ret;
}

static inline int32_t my_read(int fd, void *p, int32_t size)
{
  int32_t sum, ret;
  int8_t *tmp_p;
  
  tmp_p = (int8_t*)p;
  ret = 0;
  for(sum = 0; sum < size; sum += ret)
    {
      ret = read(fd, tmp_p + sum, size - sum);
      if(ret == 0) return ret;
      if(ret < 0) return ret;
    }
  return sum;
}

static inline int64_t fsize(FILE *fp)
{
  fpos_t fpos;
  int32_t ret;
  int64_t begin, end;
  
  ret = fgetpos(fp, &fpos);
  if(ret < 0) error();
  ret = fseek(fp, 0, SEEK_SET);
  if(ret < 0) error();
  begin = ftell(fp);
  ret = fseek(fp, 0, SEEK_END);
  if(ret < 0) error();
  end = ftell(fp);
  ret = fsetpos(fp, &fpos);
  if(ret < 0) error();
  return end - begin;
}

/* socket */

static inline int32_t sock_listen(uint16_t port, int32_t backlog)
{
  struct sockaddr_in addr;
  int listen_sock;
  int32_t ret, value;
  
  listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listen_sock < 0) error();
  
  value = 1;
  if(setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int32_t)) < 0) error();
  
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  
  ret = bind(listen_sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
  if(ret < 0) return ret;
  
  ret = listen(listen_sock, backlog);
  if(ret < 0) return ret;
  
  return listen_sock;
}

static inline int32_t sock_accept(int listen_sock)
{
  struct sockaddr_in addr;
  socklen_t addr_size;
  int sock;
  int32_t value;
  
  addr_size = sizeof(struct sockaddr);
  sock = accept(listen_sock, (struct sockaddr*)&addr, (socklen_t*)&addr_size);
  if(sock < 0) return sock;
  
#if SET_TCP_NODELAY
  value = 1;
  if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(int32_t)) < 0) error();
#endif
  
  return sock;
}

static inline void sock_close(int sock)
{
  int32_t ret;
  
  ret = close(sock);
  if(ret < 0) error();
  return;
}

static inline int32_t sock_connect(char *ip, uint16_t port)
{
  struct sockaddr_in addr;
  int sock;
  int32_t ret, value;
  
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock < 0) error();
  
#if SET_TCP_NODELAY
  value = 1;
  if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(int32_t)) < 0) error();
#endif
  
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);
  addr.sin_port = htons(port);
  
  ret = connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr));
  if(ret < 0) return ret;
  
  return sock;
}

static inline int32_t sock_send(int sock, void *p, int32_t size)
{
  int32_t ret;
  
  ret = send(sock, (int8_t*)p, size, 0);
  if(ret != size) return -1;
  if(ret < 0) return ret;
  return ret;
}

static inline int32_t sock_recv(int sock, void *p, int32_t size)
{
  int32_t sum, ret;
  int8_t *tmp_p;
  
  tmp_p = (int8_t*)p;
  ret = 0;
  for(sum = 0; sum < size; sum += ret)
    {
      ret = recv(sock, tmp_p + sum, size - sum, 0);
      if(ret == 0) return ret;
      if(ret < 0) return ret;
    }
  return sum;
}

static inline int32_t sock_create_udp(void)
{
  int sock;
  
  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(sock < 0) error();
  return sock;
}

static inline int32_t sock_bind_udp(uint16_t port)
{
  struct sockaddr_in addr;
  int sock;
  int32_t ret;
  
  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(sock < 0) error();
  
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  
  ret = bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
  if(ret < 0) return ret;
  return sock;
}

static inline void sock_addr_udp(char *ip, uint16_t port, struct sockaddr_in *addr)
{
  socklen_t addr_size;
  
  addr_size = sizeof(struct sockaddr_in);
  memset(addr, 0, addr_size);
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = inet_addr(ip);
  addr->sin_port = htons(port);
  return;
}

static inline int32_t sock_send_udp(int sock, void *p, int32_t size, struct sockaddr_in *addr)
{
  socklen_t addr_size;
  int32_t ret;
  
  addr_size = sizeof(struct sockaddr_in);
  ret = sendto(sock, p, size, 0, (struct sockaddr*)addr, addr_size);
  if(ret < 0) return ret;
  return ret;
}

static inline int32_t sock_recv_udp(int sock, void *p, int32_t size, struct sockaddr_in *addr)
{
  socklen_t addr_size;
  int32_t ret;
  
  addr_size = sizeof(struct sockaddr_in);
  ret = recvfrom(sock, p, size, 0, (struct sockaddr*)addr, &addr_size);
  if(ret < 0) return ret;
  return ret;
}

static inline void sock_get_myhost(int sock, host_t *host)
{
  struct sockaddr_in addr;
  socklen_t addr_size;
  int32_t ret;
  
  addr_size = sizeof(struct sockaddr_in);
  ret = getsockname(sock, (struct sockaddr*)&addr, (socklen_t*)&addr_size);
  if(ret < 0) error();
  strncpy(host->ip, inet_ntoa(addr.sin_addr), IP_SIZE);
  host->ip[IP_SIZE - 1] = 0;
  host->port = ntohs(addr.sin_port);
  return;
}

static inline void sock_get_yourhost(int sock, host_t *host)
{
  struct sockaddr_in addr;
  socklen_t addr_size;
  int32_t ret;
  
  addr_size = sizeof(struct sockaddr_in);
  ret = getpeername(sock, (struct sockaddr*)&addr, (socklen_t*)&addr_size);
  if(ret < 0) error();
  strncpy(host->ip, inet_ntoa(addr.sin_addr), IP_SIZE);
  host->ip[IP_SIZE - 1] = 0;
  host->port = ntohs(addr.sin_port);
  return;
}

static inline void sock_print_myhost(int sock)
{
  host_t host;
  
  sock_get_myhost(sock, &host);
  printf("local : %s @ %d\n", host.ip, (int32_t)host.port);
  return;
}

static inline void sock_print_yourhost(int sock)
{
  host_t host;
  
  sock_get_yourhost(sock, &host);
  printf("remote : %s @ %d\n", host.ip, (int32_t)host.port);
  return;
}

static inline void fqdn_to_ip(char *fqdn, char *ip, int32_t size)
{
  struct addrinfo hints;
  struct addrinfo *res;
  struct in_addr in;
  int32_t ret;
  
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  
  ret = getaddrinfo(fqdn, NULL, NULL, &res);
  if(ret < 0) error();
  in = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
  strncpy(ip, inet_ntoa(in), size);
  return;
}

static inline int sock_create_epoll(int32_t size)
{
  int epoll;
  
  epoll = epoll_create(size);
  if(epoll < 0) error();
  return epoll;
}

static inline void sock_add_epoll(int epoll, int sock)
{
  struct epoll_event new_event;
  int32_t ret;
  
  new_event.events = EPOLLIN;
  new_event.data.fd = sock;
  ret = epoll_ctl(epoll, EPOLL_CTL_ADD, sock, &new_event);
  if(ret < 0) error();
  return;
}

static inline void sock_del_epoll(int epoll, int sock)
{
  int32_t ret;
  
  ret = epoll_ctl(epoll, EPOLL_CTL_DEL, sock, NULL);
  if(ret < 0) error();
  return;
}

/* this is wrong */
static inline uint64_t htonll(uint64_t ull)
{
  uint64_t upper, lower, n_upper, n_lower, n_ull;
  
  upper = ull >> 32;
  lower = ull & 0xffffffffUL;
  n_upper = htonl(upper);
  n_lower = htonl(lower);
  n_ull = (n_upper << 32UL) | n_lower;
  return n_ull;
}

/* this is wrong */
static inline uint64_t ntohll(uint64_t n_ull)
{
  uint64_t upper, lower, n_upper, n_lower, ull;
  
  n_upper = n_ull >> 32;
  n_lower = n_ull & 0xffffffffUL;
  upper = ntohl(n_upper);
  lower = ntohl(n_lower);
  ull = (upper << 32UL) | lower;
  return ull;
}

/* vector */

static inline vector_t* vector_alloc(int32_t init_capacity, float expand_rate, void *undef_elem)
{
  vector_t *vector;
  
  if(init_capacity == CONTAINER_DEFAULT) init_capacity = VECTOR_INIT_CAPACITY;
  if(expand_rate == CONTAINER_DEFAULT) expand_rate = VECTOR_EXPAND_RATE;
  
  vector = (vector_t*)my_malloc(sizeof(vector_t));
  vector->init_capacity = init_capacity;
  vector->capacity = vector->init_capacity;
  vector->size = 0;
  vector->expand_rate = expand_rate;
  vector->undef_elem = undef_elem;
  vector->buf = (void**)my_malloc(vector->capacity * sizeof(void*));
  return vector;
}

static inline void vector_free(vector_t *vector)
{
  my_free(vector->buf);
  my_free(vector);
  return;
}

static inline void vector_clear(vector_t *vector)
{
  my_free(vector->buf);
  vector->capacity = vector->init_capacity;
  vector->buf = (void**)my_malloc(vector->capacity * sizeof(void*));
  vector->size = 0;
  return;
}

static inline int32_t vector_isempty(vector_t *vector)
{
  int32_t ret;
  
  ret = vector->size == 0 ? TRUE : FALSE;
  return ret;
}

static inline int32_t vector_size(vector_t *vector)
{
  int32_t size;
  
  size = vector->size;
  return size;
}

static inline void vector_push(vector_t *vector, void *elem)
{
  int32_t pos;
  
  pos = vector->size + 1;
  if(pos >= vector->capacity)
    {
      vector->capacity = pos;
      vector->capacity = vector->capacity * vector->expand_rate;
      vector->buf = (void**)my_realloc(vector->buf, vector->capacity * sizeof(void*));
    }
  vector->buf[vector->size++] = elem;
  return;
}

static inline void* vector_pop(vector_t *vector)
{
  void *elem;
  
  if(vector->size <= 0) error();
  
  elem = vector->buf[--vector->size];
  return elem;
}

static inline void* vector_front(vector_t *vector)
{
  void *elem;
  
  if(vector->size <= 0) error();
  
  elem = vector->buf[0];
  return elem;
}

static inline void* vector_back(vector_t *vector)
{
  void *elem;
  
  if(vector->size <= 0) error();
  
  elem = vector->buf[vector->size - 1];
  return elem;
}

static inline void* vector_at(vector_t *vector, int32_t pos)
{
  void *elem;
  
  if(0 <= pos && pos < vector->size)
    {
      elem = vector->buf[pos];
    }
  else
    {
      elem = vector->undef_elem;
    }
  return elem;
}

static inline void vector_assign(vector_t *vector, int32_t pos, void *elem)
{
  int32_t i;
  
  if(pos < 0) error();
  
  if(pos < vector->size)
    {
      vector->buf[pos] = elem;
    }
  else
    {
      vector->capacity = pos + 1;
      vector->capacity = vector->capacity * vector->expand_rate;
      vector->buf = (void**)my_realloc(vector->buf, sizeof(void*) * vector->capacity);
      for(i = vector->size; i < pos; i++)
        {
          vector->buf[i] = vector->undef_elem;
        }
      vector->buf[pos] = elem;
      vector->size = pos + 1;
    }
  return;
}

static inline xvector_t* xvector_alloc(int32_t init_capacity, float expand_rate, void *undef_elem)
{
  xvector_t *xvector;
  
  xvector = (xvector_t*)my_malloc(sizeof(xvector_t));
  xvector->vector = vector_alloc(init_capacity, expand_rate, undef_elem);
#if USE_HALFPROC
  halfproc_mutex_init(&xvector->mutex);
#else
  pthread_mutex_init(&xvector->mutex, NULL);
#endif
  return xvector;
}

static inline void xvector_free(xvector_t *xvector)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xvector->mutex);
#else
  pthread_mutex_destroy(&xvector->mutex);
#endif
  vector_free(xvector->vector);
  my_free(xvector);
  return;
}

static inline void xvector_clear(xvector_t *xvector)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  vector_clear(xvector->vector);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return;
}

static inline int32_t xvector_isempty(xvector_t *xvector)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  ret = vector_isempty(xvector->vector);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return ret;
}

static inline int32_t xvector_size(xvector_t *xvector)
{
  int32_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  size = vector_size(xvector->vector);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return size;
}

static inline void xvector_push(xvector_t *xvector, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  vector_push(xvector->vector, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return;
}

static inline void* xvector_pop(xvector_t *xvector)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  elem = vector_pop(xvector->vector);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return elem;
}

static inline void* xvector_front(xvector_t *xvector)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  elem = vector_front(xvector->vector);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return elem;
}

static inline void* xvector_back(xvector_t *xvector)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  elem = vector_back(xvector->vector);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return elem;
}

static inline void* xvector_at(xvector_t *xvector, int32_t pos)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  elem = vector_at(xvector->vector, pos);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return elem;
}

static inline void xvector_assign(xvector_t *xvector, int32_t pos, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xvector->mutex);
#else
  pthread_mutex_lock(&xvector->mutex);
#endif
  vector_assign(xvector->vector, pos, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xvector->mutex);
#else
  pthread_mutex_unlock(&xvector->mutex);
#endif
  return;
}

/* readbuf */

static inline readbuf_t* readbuf_alloc(void *buf, int64_t size)
{
  readbuf_t *readbuf;
  
  readbuf = (readbuf_t*)my_malloc(sizeof(readbuf_t));
  readbuf->offset = 0;
  readbuf->buf = buf;
  readbuf->size = size;
  return readbuf;
}

static inline void readbuf_free(readbuf_t *readbuf)
{
  my_free(readbuf);
  return;
}

static inline void* readbuf_buf(readbuf_t *readbuf)
{
  void *buf;
  
  buf = readbuf->buf + readbuf->offset;
  return buf;
}

static inline int64_t readbuf_offset(readbuf_t *readbuf)
{
  int64_t offset;
  
  offset = readbuf->offset;
  return offset;
}

static inline void readbuf_copy(readbuf_t *readbuf, void *elem, int64_t elem_size)
{
  if(readbuf->offset + elem_size > readbuf->size)
    {
      error();
    }
  
  memcpy(elem, readbuf->buf + readbuf->offset, elem_size);
  readbuf->offset += elem_size;
  return;
}

static inline xreadbuf_t* xreadbuf_alloc(void *buf, int64_t size)
{
  xreadbuf_t *xreadbuf;
  
  xreadbuf = (xreadbuf_t*)my_malloc(sizeof(xreadbuf_t));
  xreadbuf->readbuf = readbuf_alloc(buf, size);
#if USE_HALFPROC
  halfproc_mutex_init(&xreadbuf->mutex);
#else
  pthread_mutex_init(&xreadbuf->mutex, NULL);
#endif
  return xreadbuf;
}

static inline void xreadbuf_free(xreadbuf_t *xreadbuf)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xreadbuf->mutex);
#else
  pthread_mutex_destroy(&xreadbuf->mutex);
#endif
  readbuf_free(xreadbuf->readbuf);
  my_free(xreadbuf);
  return;
}

static inline void* xreadbuf_buf(xreadbuf_t *xreadbuf)
{
  void *buf;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xreadbuf->mutex);
#else
  pthread_mutex_lock(&xreadbuf->mutex);
#endif
  buf = readbuf_buf(xreadbuf->readbuf);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xreadbuf->mutex);
#else
  pthread_mutex_unlock(&xreadbuf->mutex);
#endif
  return buf;
}

static inline int64_t xreadbuf_offset(xreadbuf_t *xreadbuf)
{
  int64_t offset;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xreadbuf->mutex);
#else
  pthread_mutex_lock(&xreadbuf->mutex);
#endif
  offset = readbuf_offset(xreadbuf->readbuf);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xreadbuf->mutex);
#else
  pthread_mutex_unlock(&xreadbuf->mutex);
#endif
  return offset;
}

static inline void xreadbuf_copy(xreadbuf_t *xreadbuf, void *elem, int64_t elem_size)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xreadbuf->mutex);
#else
  pthread_mutex_lock(&xreadbuf->mutex);
#endif
  readbuf_copy(xreadbuf->readbuf, elem, elem_size);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xreadbuf->mutex);
#else
  pthread_mutex_unlock(&xreadbuf->mutex);
#endif
  return;
}

/* writebuf */

static inline writebuf_t* writebuf_alloc(int64_t init_capacity, float expand_rate)
{
  writebuf_t *writebuf;
  
  if(init_capacity == CONTAINER_DEFAULT) init_capacity = WRITEBUF_INIT_CAPACITY;
  if(expand_rate == CONTAINER_DEFAULT) expand_rate = WRITEBUF_EXPAND_RATE;
  
  writebuf = (writebuf_t*)my_malloc(sizeof(writebuf_t));
  writebuf->size = 0;
  writebuf->capacity = init_capacity;
  writebuf->buf = (int8_t*)my_malloc(writebuf->capacity);
  writebuf->expand_rate = expand_rate;
  return writebuf;
}

static inline void writebuf_free(writebuf_t *writebuf)
{
  my_free(writebuf->buf);
  my_free(writebuf);
  return;
}

static inline int64_t writebuf_size(writebuf_t *writebuf)
{
  int64_t size;
  
  size = writebuf->size;
  return size;
}

static inline void* writebuf_buf(writebuf_t *writebuf)
{
  void *buf;
  
  buf = writebuf->buf;
  return buf;
}

static inline void writebuf_copy(writebuf_t *writebuf, void *elem, int64_t elem_size)
{
  int64_t pos;
  
  pos = writebuf->size + elem_size;
  if(pos >= writebuf->capacity)
    {
      writebuf->capacity = pos;
      writebuf->capacity = writebuf->capacity * writebuf->expand_rate;
      writebuf->buf = (int8_t*)my_realloc(writebuf->buf, writebuf->capacity);
    }
  
  memcpy(writebuf->buf + writebuf->size, elem, elem_size);
  writebuf->size += elem_size;
  return;
}

static inline int64_t writebuf_skip(writebuf_t *writebuf, int64_t size)
{
  int64_t pos, offset;
  
  pos = writebuf->size + size;
  if(pos >= writebuf->capacity)
    {
      writebuf->capacity = pos;
      writebuf->capacity = writebuf->capacity * writebuf->expand_rate;
      writebuf->buf = (int8_t*)my_realloc(writebuf->buf, writebuf->capacity);
    }
  
  offset = writebuf->size;
  writebuf->size += size;
  return offset;
}

static inline void writebuf_seekcopy(writebuf_t *writebuf, int64_t offset, void *elem, int64_t elem_size)
{
  int64_t pos;
  
  pos = offset + elem_size;
  if(pos >= writebuf->capacity)
    {
      error();
    }
  
  memcpy(writebuf->buf + offset, elem, elem_size);
  return;
}

static inline xwritebuf_t* xwritebuf_alloc(int64_t init_capacity, float expand_rate)
{
  xwritebuf_t *xwritebuf;
  
  xwritebuf = (xwritebuf_t*)my_malloc(sizeof(xwritebuf_t));
  xwritebuf->writebuf = writebuf_alloc(init_capacity, expand_rate);
#if USE_HALFPROC
  halfproc_mutex_init(&xwritebuf->mutex);
#else
  pthread_mutex_init(&xwritebuf->mutex, NULL);
#endif
  return xwritebuf;
}

static inline void xwritebuf_free(xwritebuf_t *xwritebuf)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xwritebuf->mutex);
#else
  pthread_mutex_destroy(&xwritebuf->mutex);
#endif
  writebuf_free(xwritebuf->writebuf);
  my_free(xwritebuf);
  return;
}

static inline int64_t xwritebuf_size(xwritebuf_t *xwritebuf)
{
  int64_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xwritebuf->mutex);
#else
  pthread_mutex_lock(&xwritebuf->mutex);
#endif
  size = writebuf_size(xwritebuf->writebuf);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xwritebuf->mutex);
#else
  pthread_mutex_unlock(&xwritebuf->mutex);
#endif
  return size;
}

static inline void* xwritebuf_buf(xwritebuf_t *xwritebuf)
{
  void *buf;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xwritebuf->mutex);
#else
  pthread_mutex_lock(&xwritebuf->mutex);
#endif
  buf = writebuf_buf(xwritebuf->writebuf);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xwritebuf->mutex);
#else
  pthread_mutex_unlock(&xwritebuf->mutex);
#endif
  return buf;
}

static inline void xwritebuf_copy(xwritebuf_t *xwritebuf, void *elem, int64_t elem_size)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xwritebuf->mutex);
#else
  pthread_mutex_lock(&xwritebuf->mutex);
#endif
  writebuf_copy(xwritebuf->writebuf, elem, elem_size);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xwritebuf->mutex);
#else
  pthread_mutex_unlock(&xwritebuf->mutex);
#endif
  return;
}

static inline int64_t xwritebuf_skip(xwritebuf_t *xwritebuf, int64_t size)
{
  int64_t offset;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xwritebuf->mutex);
#else
  pthread_mutex_lock(&xwritebuf->mutex);
#endif
  offset = writebuf_skip(xwritebuf->writebuf, size);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xwritebuf->mutex);
#else
  pthread_mutex_unlock(&xwritebuf->mutex);
#endif
  return offset;
}

static inline void xwritebuf_seekcopy(xwritebuf_t *xwritebuf, int64_t offset, void *elem, int64_t elem_size)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xwritebuf->mutex);
#else
  pthread_mutex_lock(&xwritebuf->mutex);
#endif
  writebuf_seekcopy(xwritebuf->writebuf, offset, elem, elem_size);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xwritebuf->mutex);
#else
  pthread_mutex_unlock(&xwritebuf->mutex);
#endif
  return;
}

/* idpool */

static inline idpool_t* idpool_alloc(int32_t init_capacity)
{
  idpool_t *idpool;
  int32_t i;
  
  if(init_capacity == CONTAINER_DEFAULT) init_capacity = IDPOOL_INIT_CAPACITY;
  
  idpool = (idpool_t*)my_malloc(sizeof(idpool_t));
  idpool->size = 0;
  idpool->init_capacity = init_capacity;
  idpool->capacity = idpool->init_capacity;
  idpool->stack = (int32_t*)my_malloc(idpool->capacity * sizeof(int32_t));
  idpool->used_flag = (int8_t*)my_malloc(idpool->capacity * sizeof(int8_t));
  idpool->sp = 0;
  for(i = 0; i < idpool->init_capacity; i++)
    {
      idpool->stack[idpool->sp++] = idpool->capacity - i - 1;
      idpool->used_flag[idpool->capacity - i - 1] = FALSE;
    }
  return idpool;
}

static inline void idpool_free(idpool_t *idpool)
{
  my_free(idpool->stack);
  my_free(idpool->used_flag);
  my_free(idpool);
  return;
}

static inline int32_t idpool_isempty(idpool_t *idpool)
{
  int32_t ret;
  
  ret = idpool->size == 0 ? TRUE : FALSE;
  return ret;
}

static inline int32_t idpool_size(idpool_t *idpool)
{
  int32_t size;
  
  size = idpool->size;
  return size;
}

static inline int32_t idpool_get(idpool_t *idpool)
{
  int32_t i, id;
  
  if(idpool->sp == 0)
    {
      idpool->capacity += idpool->init_capacity;
      idpool->stack = (int32_t*)my_realloc(idpool->stack, idpool->capacity * sizeof(int32_t));
      idpool->used_flag = (int8_t*)my_realloc(idpool->used_flag, idpool->capacity * sizeof(int8_t));
      for(i = 0; i < idpool->init_capacity; i++)
        {
          idpool->stack[idpool->sp++] = idpool->capacity - i - 1;
          idpool->used_flag[idpool->capacity - i - 1] = FALSE;
        }
    }
  id = idpool->stack[--idpool->sp];
  idpool->used_flag[id] = TRUE;
  idpool->size++;
  return id;
}

static inline void idpool_put(idpool_t *idpool, int32_t id)
{
  if(!(0 <= id && id < idpool->capacity)) error();
  if(idpool->used_flag[id] == FALSE) error();
  
  idpool->stack[idpool->sp++] = id;
  idpool->used_flag[id] = FALSE;
  idpool->size--;
  return;
}

static inline xidpool_t* xidpool_alloc(int32_t init_capacity)
{
  xidpool_t *xidpool;
  
  xidpool = (xidpool_t*)my_malloc(sizeof(xidpool_t));
  xidpool->idpool = idpool_alloc(init_capacity);
#if USE_HALFPROC
  halfproc_mutex_init(&xidpool->mutex);
#else
  pthread_mutex_init(&xidpool->mutex, NULL);
#endif
  return xidpool;
}

static inline void xidpool_free(xidpool_t *xidpool)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xidpool->mutex);
#else
  pthread_mutex_destroy(&xidpool->mutex);
#endif
  idpool_free(xidpool->idpool);
  my_free(xidpool);
  return;
}

static inline int32_t xidpool_isempty(xidpool_t *xidpool)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xidpool->mutex);
#else
  pthread_mutex_lock(&xidpool->mutex);
#endif
  ret = idpool_isempty(xidpool->idpool);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xidpool->mutex);
#else
  pthread_mutex_unlock(&xidpool->mutex);
#endif
  return ret;
}

static inline int32_t xidpool_size(xidpool_t *xidpool)
{
  int32_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xidpool->mutex);
#else
  pthread_mutex_lock(&xidpool->mutex);
#endif
  size = idpool_size(xidpool->idpool);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xidpool->mutex);
#else
  pthread_mutex_unlock(&xidpool->mutex);
#endif
  return size;
}

static inline int32_t xidpool_get(xidpool_t *xidpool)
{
  int32_t id;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xidpool->mutex);
#else
  pthread_mutex_lock(&xidpool->mutex);
#endif
  id = idpool_get(xidpool->idpool);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xidpool->mutex);
#else
  pthread_mutex_unlock(&xidpool->mutex);
#endif
  return id;
}

static inline void xidpool_put(xidpool_t *xidpool, int32_t id)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xidpool->mutex);
#else
  pthread_mutex_lock(&xidpool->mutex);
#endif
  idpool_put(xidpool->idpool, id);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xidpool->mutex);
#else
  pthread_mutex_unlock(&xidpool->mutex);
#endif
  return;
}

/* lease */

static inline lease_t* lease_alloc(int32_t init_capacity, float expand_rate, void *undef_elem)
{
  lease_t *lease;
  
  if(init_capacity == CONTAINER_DEFAULT) init_capacity = LEASE_INIT_CAPACITY;
  if(expand_rate == CONTAINER_DEFAULT) expand_rate = LEASE_EXPAND_RATE;
  
  lease = (lease_t*)my_malloc(sizeof(lease_t));
  lease->init_capacity = init_capacity;
  lease->expand_rate = expand_rate;
  lease->vector = (vector_t*)vector_alloc(init_capacity, expand_rate, undef_elem);
  lease->idpool = (idpool_t*)idpool_alloc(init_capacity);
  return lease;
}

static inline void lease_free(lease_t *lease)
{
  vector_free(lease->vector);
  idpool_free(lease->idpool);
  my_free(lease);
  return;
}

static inline int lease_isempty(lease_t *lease)
{
  int ret;
  
  ret = idpool_isempty(lease->idpool);
  return ret;
}

static inline int32_t lease_size(lease_t *lease)
{
  int32_t size;
  
  size = idpool_size(lease->idpool);
  return size;
}

static inline int32_t lease_putin(lease_t *lease, void *elem)
{
  int32_t id;
  
  id = idpool_get(lease->idpool);
  vector_assign(lease->vector, id, elem);
  return id;
}

static inline void* lease_pickup(lease_t *lease, int32_t id)
{
  void *elem;
  
  idpool_put(lease->idpool, id);
  elem = vector_at(lease->vector, id);
  vector_assign(lease->vector, id, NULL);
  return elem;
}

static inline void* lease_at(lease_t *lease, int32_t pos)
{
  void *elem;
  
  elem = vector_at(lease->vector, pos);
  return elem;
}

static inline xlease_t* xlease_alloc(int32_t init_capacity, float expand_rate, void *undef_elem)
{
  xlease_t *xlease;
  
  xlease = (xlease_t*)my_malloc(sizeof(xlease_t));
  xlease->lease = lease_alloc(init_capacity, expand_rate, undef_elem);
#if USE_HALFPROC
  halfproc_mutex_init(&xlease->mutex);
#else
  pthread_mutex_init(&xlease->mutex, NULL);
#endif
  return xlease;
}

static inline void xlease_free(xlease_t *xlease)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xlease->mutex);
#else
  pthread_mutex_destroy(&xlease->mutex);
#endif
  lease_free(xlease->lease);
  my_free(xlease);
  return;
}

static inline int xlease_isempty(xlease_t *xlease)
{
  int ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlease->mutex);
#else
  pthread_mutex_lock(&xlease->mutex);
#endif
  ret = lease_isempty(xlease->lease);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlease->mutex);
#else
  pthread_mutex_unlock(&xlease->mutex);
#endif
  return ret;
}

static inline int32_t xlease_size(xlease_t *xlease)
{
  int32_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlease->mutex);
#else
  pthread_mutex_lock(&xlease->mutex);
#endif
  size = lease_size(xlease->lease);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlease->mutex);
#else
  pthread_mutex_unlock(&xlease->mutex);
#endif
  return size;
}

static inline int32_t xlease_putin(xlease_t *xlease, void *elem)
{
  int32_t id;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlease->mutex);
#else
  pthread_mutex_lock(&xlease->mutex);
#endif
  id = lease_putin(xlease->lease, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlease->mutex);
#else
  pthread_mutex_unlock(&xlease->mutex);
#endif
  return id;
}

static inline void* xlease_pickup(xlease_t *xlease, int32_t id)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlease->mutex);
#else
  pthread_mutex_lock(&xlease->mutex);
#endif
  elem = lease_pickup(xlease->lease, id);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlease->mutex);
#else
  pthread_mutex_unlock(&xlease->mutex);
#endif
  return elem;
}

static inline void* xlease_at(xlease_t *xlease, int32_t pos)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlease->mutex);
#else
  pthread_mutex_lock(&xlease->mutex);
#endif
  elem = lease_at(xlease->lease, pos);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlease->mutex);
#else
  pthread_mutex_unlock(&xlease->mutex);
#endif
  return elem;
}

/* deque */

static inline deque_t* deque_alloc(int32_t init_capacity, float expand_rate)
{
  deque_t *deque;
  
  if(init_capacity == CONTAINER_DEFAULT) init_capacity = DEQUE_INIT_CAPACITY;
  if(expand_rate == CONTAINER_DEFAULT) expand_rate = DEQUE_EXPAND_RATE;
  
  deque = (deque_t*)my_malloc(sizeof(deque_t));
  deque->expand_rate = expand_rate;
  deque->init_capacity = init_capacity + 1;
  deque->capacity = deque->init_capacity;
  deque->buf = (void**)my_malloc(deque->capacity * sizeof(void*));
  deque->head = 0;
  deque->tail = 0;
  return deque;
}

static inline void deque_free(deque_t *deque)
{
  my_free(deque->buf);
  my_free(deque);
  return;
}

static inline void deque_clear(deque_t *deque)
{
  my_free(deque->buf);
  deque->capacity = deque->init_capacity;
  deque->buf = (void**)my_malloc(deque->capacity * sizeof(void*));
  deque->head = 0;
  deque->tail = 0;
  return;
}

static inline int32_t deque_isempty(deque_t *deque)
{
  int32_t ret;
  
  ret = deque->head == deque->tail ? TRUE : FALSE;
  return ret;
}

static inline int32_t deque_size(deque_t *deque)
{
  int32_t size;
  
  size = (deque->tail - deque->head + deque->capacity) % deque->capacity;
  return size;
}

static inline void* deque_front(deque_t *deque)
{
  void *elem;
  
  if(deque->head == deque->tail) error();
  
  elem = deque->buf[(deque->head + 1) % deque->capacity];
  return elem;
}

static inline void* deque_back(deque_t *deque)
{
  void *elem;
  
  if(deque->head == deque->tail) error();
  
  elem = deque->buf[deque->tail];
  return elem;
}

static inline void deque_push(deque_t *deque, void *elem)
{
  int32_t old_capacity;
  
  if((deque->tail + 1) % deque->capacity == deque->head)
    {
      old_capacity = deque->capacity;
      deque->capacity = old_capacity * deque->expand_rate;
      deque->buf = (void**)my_realloc(deque->buf, deque->capacity * sizeof(void*));
      memcpy(deque->buf + old_capacity, deque->buf, deque->head * sizeof(void*));
      deque->tail = old_capacity + deque->head - 1;
    }
  
  deque->tail = (deque->tail + 1) % deque->capacity;
  deque->buf[deque->tail] = elem;
  return;
}

static inline void* deque_pop(deque_t *deque)
{
  void *elem;
  
  if(deque->head == deque->tail) error();
  
  elem = deque->buf[deque->tail];
  deque->tail = (deque->tail - 1 + deque->capacity) % deque->capacity;
  return elem;
}

static inline void* deque_shift(deque_t *deque)
{
  void *elem;
  
  if(deque->head == deque->tail) error();
  
  elem = deque->buf[(deque->head + 1) % deque->capacity];
  deque->head = (deque->head + 1) % deque->capacity;
  return elem;
}

static inline void deque_unshift(deque_t *deque, void *elem)
{
  int32_t old_capacity;
  
  if((deque->tail + 1) % deque->capacity == deque->head)
    {
      old_capacity = deque->capacity;
      deque->capacity = old_capacity * deque->expand_rate;
      deque->buf = (void**)my_realloc(deque->buf, deque->capacity * sizeof(void*));
      memcpy(deque->buf + old_capacity, deque->buf, deque->head * sizeof(void*));
      deque->tail = old_capacity + deque->head - 1;
    }
  
  deque->head = (deque->head - 1 + deque->capacity) % deque->capacity;
  deque->buf[(deque->head + 1) % deque->capacity] = elem;
  return;
}

static inline void* deque_at(deque_t *deque, int32_t pos)
{
  void *elem;
  
  if(!(0 <= pos && pos < deque_size(deque))) error();
  
  elem = deque->buf[(deque->head + pos + 1) % deque->capacity];
  return elem;
}

static inline void deque_assign(deque_t *deque, int32_t pos, void *elem)
{
  if(!(0 <= pos && pos < deque_size(deque))) error();
  
  deque->buf[(deque->head + pos + 1) % deque->capacity] = elem;
  return;
}

static inline xdeque_t* xdeque_alloc(int32_t init_capacity, float expand_rate)
{
  xdeque_t *xdeque;
  
  xdeque = (xdeque_t*)my_malloc(sizeof(xdeque_t));
  xdeque->deque = deque_alloc(init_capacity, expand_rate);
#if USE_HALFPROC
  halfproc_mutex_init(&xdeque->mutex);
#else
  pthread_mutex_init(&xdeque->mutex, NULL);
#endif
  return xdeque;
}

static inline void xdeque_free(xdeque_t *xdeque)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xdeque->mutex);
#else
  pthread_mutex_destroy(&xdeque->mutex);
#endif
  deque_free(xdeque->deque);
  my_free(xdeque);
  return;
}

static inline void xdeque_clear(xdeque_t *xdeque)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  deque_clear(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return;
}

static inline int32_t xdeque_isempty(xdeque_t *xdeque)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  ret = deque_isempty(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return ret;
}

static inline int32_t xdeque_size(xdeque_t *xdeque)
{
  int32_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  size = deque_size(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return size;
}

static inline void* xdeque_front(xdeque_t *xdeque)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  elem = deque_front(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return elem;
}

static inline void* xdeque_back(xdeque_t *xdeque)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  elem = deque_back(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return elem;
}

static inline void xdeque_push(xdeque_t *xdeque, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  deque_push(xdeque->deque, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return;
}

static inline void* xdeque_pop(xdeque_t *xdeque)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  elem = deque_pop(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return elem;
}

static inline void* xdeque_shift(xdeque_t *xdeque)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  elem = deque_shift(xdeque->deque);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return elem;
}

static inline void xdeque_unshift(xdeque_t *xdeque, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  deque_unshift(xdeque->deque, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return;
}

static inline void* xdeque_at(xdeque_t *xdeque, int32_t pos)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  elem = deque_at(xdeque->deque, pos);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return elem;
}

static inline void xdeque_assign(xdeque_t *xdeque, int32_t pos, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xdeque->mutex);
#else
  pthread_mutex_lock(&xdeque->mutex);
#endif
  deque_assign(xdeque->deque, pos, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xdeque->mutex);
#else
  pthread_mutex_unlock(&xdeque->mutex);
#endif
  return;
}

/* taskque */

static inline taskque_t* taskque_alloc(int32_t init_capacity, float expand_rate, void *notify_elem)
{
  taskque_t *taskque;
  
  taskque = (taskque_t*)my_malloc(sizeof(taskque_t));
  taskque->notify_flag = FALSE;
  taskque->deque = deque_alloc(init_capacity, expand_rate);
  taskque->notify_elem = notify_elem;
#if USE_HALFPROC
  halfproc_mutex_init(&taskque->mutex);
#else
  pthread_mutex_init(&taskque->mutex, NULL);
#endif
#if USE_HALFPROC
  halfproc_cond_init(&taskque->cond);
#else
  pthread_cond_init(&taskque->cond, NULL);
#endif
  return taskque;
}

static inline void taskque_free(taskque_t *taskque)
{
#if USE_HALFPROC
  halfproc_cond_destroy(&taskque->cond);
#else
  pthread_cond_destroy(&taskque->cond);
#endif
#if USE_HALFPROC
  halfproc_mutex_destroy(&taskque->mutex);
#else
  pthread_mutex_destroy(&taskque->mutex);
#endif
  deque_free(taskque->deque);
  my_free(taskque);
  return;
}

static inline int32_t taskque_isempty(taskque_t *taskque)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&taskque->mutex);
#else
  pthread_mutex_lock(&taskque->mutex);
#endif
  
  ret = deque_isempty(taskque->deque);
  
#if USE_HALFPROC
  halfproc_mutex_unlock(&taskque->mutex);
#else
  pthread_mutex_unlock(&taskque->mutex);
#endif
  return ret;
}

static inline int32_t taskque_size(taskque_t *taskque)
{
  int32_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&taskque->mutex);
#else
  pthread_mutex_lock(&taskque->mutex);
#endif
  
  size = deque_size(taskque->deque);
  
#if USE_HALFPROC
  halfproc_mutex_unlock(&taskque->mutex);
#else
  pthread_mutex_unlock(&taskque->mutex);
#endif
  return size;
}

static inline void taskque_unshift(taskque_t *taskque, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&taskque->mutex);
#else
  pthread_mutex_lock(&taskque->mutex);
#endif
  
  deque_unshift(taskque->deque, elem);

  //outn("taskque_unshift: before");
#if USE_HALFPROC
  halfproc_cond_broadcast(&taskque->cond);
#else
  pthread_cond_broadcast(&taskque->cond);
#endif
  //outn("taskque_unshift: after");
#if USE_HALFPROC
  halfproc_mutex_unlock(&taskque->mutex);
#else
  pthread_mutex_unlock(&taskque->mutex);
#endif
  return;
}

static inline void* taskque_pop(taskque_t *taskque)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&taskque->mutex);
#else
  pthread_mutex_lock(&taskque->mutex);
#endif
  
  while(deque_isempty(taskque->deque) == TRUE && taskque->notify_flag == FALSE)
    {
#if USE_HALFPROC
      halfproc_cond_wait(&taskque->cond, &taskque->mutex);
#else
      pthread_cond_wait(&taskque->cond, &taskque->mutex);
#endif
    }
  
  if(taskque->notify_flag == TRUE)
    {
      taskque->notify_flag = FALSE;
      elem = taskque->notify_elem;
    }
  else
    {
      elem = deque_pop(taskque->deque);
    }
  
#if USE_HALFPROC
  halfproc_mutex_unlock(&taskque->mutex);
#else
  pthread_mutex_unlock(&taskque->mutex);
#endif
  return elem;
}

static inline void* taskque_at(taskque_t *taskque, int32_t pos)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&taskque->mutex);
#else
  pthread_mutex_lock(&taskque->mutex);
#endif
  
  elem = deque_at(taskque->deque, pos);
  
#if USE_HALFPROC
  halfproc_mutex_unlock(&taskque->mutex);
#else
  pthread_mutex_unlock(&taskque->mutex);
#endif
  return elem;
}

static inline void taskque_notify(taskque_t *taskque)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&taskque->mutex);
#else
  pthread_mutex_lock(&taskque->mutex);
#endif
  
  taskque->notify_flag = TRUE;
  
  //outn("taskque_notify: before");
#if USE_HALFPROC
  halfproc_cond_broadcast(&taskque->cond);
#else
  pthread_cond_broadcast(&taskque->cond);
#endif
  //outn("taskque_notify: after");
#if USE_HALFPROC
  halfproc_mutex_unlock(&taskque->mutex);
#else
  pthread_mutex_unlock(&taskque->mutex);
#endif
  return;
}

/* list */

static inline cell_t* cell_alloc(void *elem)
{
  cell_t *cell;
  
  cell = (cell_t*)my_malloc(sizeof(cell_t));
  cell->elem = elem;
  cell->prev = NULL;
  cell->next = NULL;
  return cell;
}

static inline void cell_free(cell_t *cell)
{
  my_free(cell);
  return;
}

static inline list_t* list_alloc(void)
{
  list_t *list;
  
  list = (list_t*)my_malloc(sizeof(list_t));
  list->head = cell_alloc(NULL);
  list->head->prev = list->head;
  list->head->next = list->head;
  list->iter = list->head;
  list->size = 0;
  list->pos = -1;
  return list;
}

static inline void list_free(list_t *list)
{
  list_clear(list);
  cell_free(list->head);
  my_free(list);
  return;
}

static inline void list_clear(list_t *list)
{
  cell_t *curr_cell, *next_cell;
  
  curr_cell = list->head->next;
  while(curr_cell != list->head)
    {
      next_cell = curr_cell->next;
      cell_free(curr_cell);
      curr_cell = next_cell;
    }
  list->head->prev = list->head;
  list->head->next = list->head;
  list->iter = list->head;
  list->size = 0;
  list->pos = -1;
  return;
}

static inline void list_head(list_t *list)
{
  list->iter = list->head;
  list->pos = -1;
  return;
}

static inline void list_tail(list_t *list)
{
  list_head(list);
  return;
}

static inline int32_t list_isempty(list_t *list)
{
  int32_t ret;
  
  ret = list->size == 0 ? TRUE : FALSE;
  return ret;
}

static inline int32_t list_size(list_t *list)
{
  int32_t size;
  
  size = list->size;
  return size;
}

static inline void* list_curr(list_t *list)
{
  void *elem;
  
  if(list->iter == list->head) error();
  
  elem = list->iter->elem;
  return elem;
}

static inline void* list_next(list_t *list)
{
  void *elem;
  
  list->iter = list->iter->next;
  list->pos++;
  if(list->pos == list->size)
    {
      list->pos = -1;
    }
  elem = list->iter->elem;
  return elem;
}

static inline void* list_prev(list_t *list)
{
  void *elem;
  
  list->iter = list->iter->prev;
  list->pos--;
  if(list->pos == -2)
    {
      list->pos = list->size - 1;
    }
  elem = list->iter->elem;
  return elem;
}

static inline int32_t list_hascurr(list_t *list)
{
  int32_t ret;
  
  ret = list->iter != list->head ? TRUE : FALSE;
  return ret;
}

static inline int32_t list_hasnext(list_t *list)
{
  int32_t ret;
  
  ret = list->iter->next != list->head ? TRUE : FALSE;
  return ret;
}

static inline int32_t list_hasprev(list_t *list)
{
  int32_t ret;
  
  ret = list->iter->prev != list->head ? TRUE : FALSE;
  return ret;
}

static inline void list_push(list_t *list, void *elem)
{
  cell_t *cell;
  
  cell = cell_alloc(elem);
  cell->next = list->head;
  cell->prev = list->head->prev;
  list->head->prev->next = cell;
  list->head->prev = cell;
  list->size++;
  list->iter = list->head->prev;
  list->pos = list->size - 1;
  return;
}

static inline void* list_pop(list_t *list)
{
  cell_t *cell;
  void *elem;
  
  if(list->size <= 0) error();
  
  cell = list->head->prev;
  list->head->prev = cell->prev;
  cell->prev->next = list->head;
  elem = cell->elem;
  cell_free(cell);
  list->size--;
  list->iter = list->head->prev;
  list->pos = list->size - 1;
  return elem;
}

static inline void* list_shift(list_t *list)
{
  cell_t *cell;
  void *elem;
  
  if(list->size <= 0) error();
  
  cell = list->head->next;
  list->head->next = cell->next;
  cell->next->prev = list->head;
  elem = cell->elem;
  cell_free(cell);
  list->size--;
  list->iter = list->head->next;
  list->pos = 0;
  return elem;
}

static inline void list_unshift(list_t *list, void *elem)
{
  cell_t *cell;
  
  cell = cell_alloc(elem);
  cell->next = list->head->next;
  cell->prev = list->head;
  list->head->next->prev = cell;
  list->head->next = cell;
  list->size++;
  list->iter = list->head->next;
  list->pos = 0;
  return;
}

static inline void list_insert(list_t *list, void *elem)
{
  cell_t *cell;
  
  cell = cell_alloc(elem);
  cell->next = list->iter;
  cell->prev = list->iter->prev;
  list->iter->prev->next = cell;
  list->iter->prev = cell;
  list->size++;
  list->pos++;
  return;
}

static inline void* list_remove(list_t *list)
{
  cell_t *cell;
  void *elem;
  
  if(list->iter == list->head) error();
  
  list->iter->prev->next = list->iter->next;
  list->iter->next->prev = list->iter->prev;
  cell = list->iter;
  elem = cell->elem;
  list->iter = list->iter->next;
  cell_free(cell);
  list->size--;
  if(list->pos == list->size)
    {
      list->pos = -1;
    }
  return elem;
}

static inline void list_move(list_t *list, int32_t pos)
{
  int i, times;
  
  if(!(0 <= pos && pos < list->size)) error();
  
  if(list->pos <= pos)
    {
      times = pos - list->pos;
      for(i = 0; i < times; i++)
        {
          list_next(list);
        }
    }
  else
    {
      times = list->pos - pos;
      for(i = 0; i < times; i++)
        {
          list_prev(list);
        }
    }
  if(list->pos != pos) error();
  return;
}

static inline void* list_at(list_t *list, int32_t pos)
{
  void *elem;
  
  list_move(list, pos);
  elem = list->iter->elem;
  return elem;
}

static inline void list_assign(list_t *list, int32_t pos, void *elem)
{
  list_move(list, pos);
  list->iter->elem = elem;
  return;
}

static inline xlist_t* xlist_alloc(void)
{
  xlist_t *xlist;
  
  xlist = (xlist_t*)my_malloc(sizeof(xlist_t));
  xlist->list = list_alloc();
#if USE_HALFPROC
  halfproc_mutex_init(&xlist->mutex);
#else
  pthread_mutex_init(&xlist->mutex, NULL);
#endif
  return xlist;
}

static inline void xlist_free(xlist_t *xlist)
{
#if USE_HALFPROC
  halfproc_mutex_destroy(&xlist->mutex);
#else
  pthread_mutex_destroy(&xlist->mutex);
#endif
  list_free(xlist->list);
  my_free(xlist);
  return;
}

static inline void xlist_clear(xlist_t *xlist)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_clear(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline void xlist_head(xlist_t *xlist)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_head(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline void xlist_tail(xlist_t *xlist)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_tail(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline int32_t xlist_isempty(xlist_t *xlist)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  ret = list_isempty(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return ret;
}

static inline int32_t xlist_size(xlist_t *xlist)
{
  int32_t size;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  size = list_size(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return size;
}

static inline void* xlist_curr(xlist_t *xlist)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_curr(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline void* xlist_next(xlist_t *xlist)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_next(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline void* xlist_prev(xlist_t *xlist)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_prev(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline int32_t xlist_hascurr(xlist_t *xlist)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  ret = list_hascurr(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return ret;
}

static inline int32_t xlist_hasnext(xlist_t *xlist)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  ret = list_hasnext(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return ret;
}

static inline int32_t xlist_hasprev(xlist_t *xlist)
{
  int32_t ret;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  ret = list_hasprev(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return ret;
}

static inline void xlist_push(xlist_t *xlist, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_push(xlist->list, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline void* xlist_pop(xlist_t *xlist)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_pop(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline void* xlist_shift(xlist_t *xlist)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_shift(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline void xlist_unshift(xlist_t *xlist, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_unshift(xlist->list, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline void xlist_insert(xlist_t *xlist, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_insert(xlist->list, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline void* xlist_remove(xlist_t *xlist)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_remove(xlist->list);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline void xlist_move(xlist_t *xlist, int32_t pos)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_move(xlist->list, pos);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

static inline void* xlist_at(xlist_t *xlist, int32_t pos)
{
  void *elem;
  
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  elem = list_at(xlist->list, pos);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return elem;
}

static inline void xlist_assign(xlist_t *xlist, int32_t pos, void *elem)
{
#if USE_HALFPROC
  halfproc_mutex_lock(&xlist->mutex);
#else
  pthread_mutex_lock(&xlist->mutex);
#endif
  list_assign(xlist->list, pos, elem);
#if USE_HALFPROC
  halfproc_mutex_unlock(&xlist->mutex);
#else
  pthread_mutex_unlock(&xlist->mutex);
#endif
  return;
}

#endif
