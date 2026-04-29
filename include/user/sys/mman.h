// SPDX-License-Identifier: MPL-2.0
//
// POSIX mmap(2) / mprotect(2) / msync(2) / shm_open(3) surface for
// Futura userland.  libwayland uses mmap for shm-backed surfaces and
// shm_open for cross-process buffer sharing.

#pragma once

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory protection */
#define PROT_NONE   0x00
#define PROT_READ   0x01
#define PROT_WRITE  0x02
#define PROT_EXEC   0x04

/* mmap flags (Linux-compatible bit layout) */
#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS
#define MAP_NORESERVE   0x4000
#define MAP_POPULATE    0x8000
#define MAP_FAILED      ((void *)-1)

/* msync flags */
#define MS_ASYNC        0x01
#define MS_INVALIDATE   0x02
#define MS_SYNC         0x04

/* madvise hints */
#define MADV_NORMAL      0
#define MADV_RANDOM      1
#define MADV_SEQUENTIAL  2
#define MADV_WILLNEED    3
#define MADV_DONTNEED    4
#define MADV_FREE        8

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int   munmap(void *addr, size_t length);
int   mprotect(void *addr, size_t len, int prot);
int   msync(void *addr, size_t length, int flags);
int   madvise(void *addr, size_t length, int advice);
int   mlock(const void *addr, size_t len);
int   munlock(const void *addr, size_t len);

/* POSIX shm */
int   shm_open(const char *name, int oflag, mode_t mode);
int   shm_unlink(const char *name);

/* Linux-specific memfd_create flags (libwayland may probe for these) */
#define MFD_CLOEXEC       0x0001U
#define MFD_ALLOW_SEALING 0x0002U
int   memfd_create(const char *name, unsigned int flags);

#ifdef __cplusplus
}
#endif
