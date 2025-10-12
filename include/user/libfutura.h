/* libfutura.h - User-Space Library for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Public API for Futura OS userland applications.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   String Functions
 * ============================================================ */

size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strcat(char *dest, const char *src);
char *strchr(const char *s, int c);

/* ============================================================
 *   Memory Functions
 * ============================================================ */

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memmove(void *dest, const void *src, size_t n);

/* ============================================================
 *   Memory Allocation
 * ============================================================ */

void heap_init(void *start, size_t size);
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void heap_stats(size_t *used, size_t *total);

/* ============================================================
 *   FIPC Functions
 * ============================================================ */

struct fut_fipc_channel;
struct fut_fipc_region;
struct fut_fipc_msg;

struct fut_fipc_channel *fipc_connect(const char *service_name);
void fipc_disconnect(struct fut_fipc_channel *channel);
int fipc_send_message(struct fut_fipc_channel *channel, uint32_t type,
                      const void *data, size_t size);
int fipc_recv_message(struct fut_fipc_channel *channel, struct fut_fipc_msg *msg,
                      size_t max_size);
int fipc_wait(struct fut_fipc_channel *channel, uint32_t timeout_ms);

int fipc_create_shared_region(size_t size, struct fut_fipc_region **region_out);
void *fipc_map_region(struct fut_fipc_region *region);
void fipc_unmap_region(struct fut_fipc_region *region);
void fipc_destroy_region(struct fut_fipc_region *region);

/* ============================================================
 *   POSIX Functions
 * ============================================================ */

/* Define ssize_t for POSIX functions */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

int posix_init(void);

/* File operations */
int open(const char *path, int flags, ...);
int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int unlink(const char *path);
int mkdir(const char *path, mode_t mode);
int rmdir(const char *path);

/* Directory operations */
typedef struct fut_dir fut_dir_t;

fut_dir_t *opendir(const char *path);
int closedir(fut_dir_t *dir);
struct fut_dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[POSIX_NAME_MAX + 1];
};
int readdir(fut_dir_t *dir, struct fut_dirent *entry);

/* Process operations */
int fork(void);
int execve(const char *path, char *const argv[], char *const envp[]);
int waitpid(int pid, int *status, int options);
int getpid(void);
int getppid(void);

/* Exit (implemented in crt0.S) */
void exit(int status) __attribute__((noreturn));

/* ============================================================
 *   Constants
 * ============================================================ */

/* File open flags */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_EXCL      0x0080
#define O_TRUNC     0x0200
#define O_APPEND    0x0400

/* Wait options */
#define WNOHANG     1
#define WUNTRACED   2

/* Standard file descriptors */
#define STDIN_FILENO    0
#define STDOUT_FILENO   1
#define STDERR_FILENO   2
