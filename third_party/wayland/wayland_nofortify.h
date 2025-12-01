#ifndef WAYLAND_NOFORTIFY_H
#define WAYLAND_NOFORTIFY_H

/* Ensure the vendored Wayland build never depends on glibc fortify hooks. */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#define _FORTIFY_SOURCE 0

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

#define __memcpy_chk(dst, src, len, bsz) memcpy((dst), (src), (len))
#define __memmove_chk(dst, src, len, bsz) memmove((dst), (src), (len))
#define __memset_chk(dst, c, len, bsz) memset((dst), (c), (len))
#define __snprintf_chk(buf, sz, fl, bsz, fmt, ...) snprintf((buf), (sz), (fmt), __VA_ARGS__)
#define __vsnprintf_chk(buf, sz, fl, bsz, fmt, ap) vsnprintf((buf), (sz), (fmt), (ap))
#define __vfprintf_chk(stream, fl, fmt, ap) vfprintf((stream), (fmt), (ap))
#define __fprintf_chk(stream, fl, fmt, ...) fprintf((stream), (fmt), __VA_ARGS__)
#define __fputs_chk(str, stream, bsz) fputs((str), (stream))
#define __fwrite_chk(ptr, sz, nmemb, stream, bsz) fwrite((ptr), (sz), (nmemb), (stream))

#define mmap64(addr, length, prot, flags, fd, offset) mmap((addr), (length), (prot), (flags), (fd), (offset))

#define __fstat64_time64(fd, st) fstat((fd), (st))
#define __fxstat64(ver, fd, st)  fstat((fd), (st))

/* Define AT_FDCWD for openat() syscall compatibility */
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

/* macOS compatibility shims for Linux-specific APIs */
#ifdef __APPLE__

/* Ensure CLOCK_MONOTONIC is available */
#include <time.h>
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

/* BSD types for ucred compatibility */
#ifndef u_int
typedef unsigned int u_int;
#endif

/* Socket flags */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0x10000000
#endif

/* syscall wrapper */
#include <unistd.h>
#include <sys/syscall.h>
/* Explicitly declare syscall for macOS */
long syscall(long number, ...);


/* Socket control message flags */
#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0
#endif

/* Socket address families */
#include <sys/un.h>
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

/* File sealing (Linux-specific, stub for macOS) */
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif

/* Memory mapping flags */
#include <sys/mman.h>
#ifndef MAP_ANON
#define MAP_ANON 0x1000
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* File locking */
#include <sys/file.h>
#ifndef LOCK_EX
#define LOCK_EX 2
#endif
#ifndef LOCK_NB
#define LOCK_NB 4
#endif

/* eventfd stub - macOS doesn't have eventfd, provide minimal stub */
#ifndef _SYS_EVENTFD_H
#define _SYS_EVENTFD_H

#define EFD_CLOEXEC 0x80000
#define EFD_NONBLOCK 0x800
#define EFD_SEMAPHORE 0x1

typedef uint64_t eventfd_t;

static inline int eventfd(unsigned int initval, int flags) { return -1; }
static inline int eventfd_read(int fd, eventfd_t *value) { return -1; }
static inline int eventfd_write(int fd, eventfd_t value) { return -1; }

#endif /* _SYS_EVENTFD_H */

/* signalfd stub - macOS doesn't have signalfd, provide minimal stub */
#ifndef _SYS_SIGNALFD_H
#define _SYS_SIGNALFD_H

#include <signal.h>

#define SFD_CLOEXEC 0x80000
#define SFD_NONBLOCK 0x800

struct signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t ssi_errno;
    int32_t ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t ssi_status;
    int32_t ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint8_t pad[48];
};

static inline int signalfd(int fd, const sigset_t *mask, int flags) { return -1; }

#endif /* _SYS_SIGNALFD_H */

/* epoll stub - macOS doesn't have epoll, provide minimal stub */
#ifndef _SYS_EPOLL_H
#define _SYS_EPOLL_H

#define EPOLLIN    0x001
#define EPOLLOUT   0x004
#define EPOLLERR   0x008
#define EPOLLHUP   0x010
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};

static inline int epoll_create(int size) { return -1; }
static inline int epoll_create1(int flags) { return -1; }
static inline int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) { return -1; }
static inline int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) { return -1; }

#endif /* _SYS_EPOLL_H */

/* timerfd stub - macOS doesn't have timerfd, provide minimal stub */
#ifndef _SYS_TIMERFD_H
#define _SYS_TIMERFD_H

/* Ensure struct timespec and struct itimerspec are available */
#include <time.h>

/* Define struct itimerspec if not already defined */
#ifndef __itimerspec_defined
#define __itimerspec_defined 1
struct itimerspec {
    struct timespec it_interval;  /* Interval for periodic timer */
    struct timespec it_value;     /* Initial expiration */
};
#endif

#define TFD_CLOEXEC 0x80000
#define TFD_NONBLOCK 0x800
#define TFD_TIMER_ABSTIME 0x1

static inline int timerfd_create(int clockid, int flags) { return -1; }
static inline int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) { return -1; }
static inline int timerfd_gettime(int fd, struct itimerspec *curr_value) { return -1; }

#endif /* _SYS_TIMERFD_H */

/* Socket control message macros */
#include <sys/socket.h>
#ifndef CMSG_LEN
#define CMSG_LEN(len) (_CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif
#ifndef CMSG_SPACE
#define CMSG_SPACE(len) (_CMSG_ALIGN(sizeof(struct cmsghdr)) + _CMSG_ALIGN(len))
#endif
#ifndef CMSG_DATA
#define CMSG_DATA(cmsg) ((unsigned char *)(cmsg) + _CMSG_ALIGN(sizeof(struct cmsghdr)))
#endif
#ifndef _CMSG_ALIGN
#define _CMSG_ALIGN(len) (((len) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#endif

/* Socket flags */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x80
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Explicit flock declaration for macOS */
int flock(int fd, int operation);

#endif /* __APPLE__ */

#endif /* WAYLAND_NOFORTIFY_H */
