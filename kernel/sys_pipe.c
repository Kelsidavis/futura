/* sys_pipe.c - pipe() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX pipe() for inter-process communication.
 */

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Pipe buffer size */
#define PIPE_BUF_SIZE 4096

/* Pipe buffer structure */
struct pipe_buffer {
    uint8_t *data;          /* Buffer data */
    size_t size;            /* Buffer size (PIPE_BUF_SIZE) */
    size_t read_pos;        /* Read position */
    size_t write_pos;       /* Write position */
    size_t count;           /* Number of bytes in buffer */
    uint32_t refcount;      /* Reference count (read_end + write_end) */
    bool write_closed;      /* Write end closed */
    bool read_closed;       /* Read end closed */
};

/* File operations for pipe read/write ends */
struct fut_file_ops {
    int (*open)(void *inode, int flags, void **priv);
    int (*release)(void *inode, void *priv);
    ssize_t (*read)(void *inode, void *priv, void *buf, size_t len, off_t *pos);
    ssize_t (*write)(void *inode, void *priv, const void *buf, size_t len, off_t *pos);
    int (*ioctl)(void *inode, void *priv, unsigned long req, unsigned long arg);
    void *(*mmap)(void *inode, void *priv, void *addr, size_t len, int prot, int flags, off_t off);
};

/* Forward declarations */
static ssize_t pipe_read(void *inode, void *priv, void *buf, size_t len, off_t *pos);
static ssize_t pipe_write(void *inode, void *priv, const void *buf, size_t len, off_t *pos);
static int pipe_release_read(void *inode, void *priv);
static int pipe_release_write(void *inode, void *priv);

/* Pipe file operations */
static const struct fut_file_ops pipe_read_fops = {
    .open = NULL,
    .release = pipe_release_read,
    .read = pipe_read,
    .write = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

static const struct fut_file_ops pipe_write_fops = {
    .open = NULL,
    .release = pipe_release_write,
    .read = NULL,
    .write = pipe_write,
    .ioctl = NULL,
    .mmap = NULL,
};

/**
 * Create a new pipe buffer.
 */
static struct pipe_buffer *pipe_buffer_create(void) {
    struct pipe_buffer *pipe = fut_malloc(sizeof(struct pipe_buffer));
    if (!pipe) {
        return NULL;
    }

    pipe->data = fut_malloc(PIPE_BUF_SIZE);
    if (!pipe->data) {
        fut_free(pipe);
        return NULL;
    }

    pipe->size = PIPE_BUF_SIZE;
    pipe->read_pos = 0;
    pipe->write_pos = 0;
    pipe->count = 0;
    pipe->refcount = 2;  /* Read end + write end */
    pipe->write_closed = false;
    pipe->read_closed = false;

    return pipe;
}

/**
 * Destroy a pipe buffer (when refcount reaches 0).
 */
static void pipe_buffer_destroy(struct pipe_buffer *pipe) {
    if (!pipe) {
        return;
    }

    fut_free(pipe->data);
    fut_free(pipe);
}

/**
 * Read from pipe buffer.
 */
static ssize_t pipe_read(void *inode, void *priv, void *buf, size_t len, off_t *pos) {
    (void)inode;
    (void)pos;  /* Pipes don't use offset */

    struct pipe_buffer *pipe = (struct pipe_buffer *)priv;
    if (!pipe || !buf || len == 0) {
        return -EINVAL;
    }

    /* If pipe is empty and write end is closed, return EOF */
    if (pipe->count == 0 && pipe->write_closed) {
        return 0;  /* EOF */
    }

    /* If pipe is empty, for now just return EAGAIN (would block in real implementation) */
    if (pipe->count == 0) {
        return -EAGAIN;
    }

    /* Read up to len bytes from pipe */
    size_t to_read = (len < pipe->count) ? len : pipe->count;
    size_t bytes_read = 0;
    uint8_t *output = (uint8_t *)buf;

    while (bytes_read < to_read) {
        output[bytes_read] = pipe->data[pipe->read_pos];
        pipe->read_pos = (pipe->read_pos + 1) % pipe->size;
        bytes_read++;
    }

    pipe->count -= bytes_read;

    return (ssize_t)bytes_read;
}

/**
 * Write to pipe buffer.
 */
static ssize_t pipe_write(void *inode, void *priv, const void *buf, size_t len, off_t *pos) {
    (void)inode;
    (void)pos;  /* Pipes don't use offset */

    struct pipe_buffer *pipe = (struct pipe_buffer *)priv;
    if (!pipe || !buf || len == 0) {
        return -EINVAL;
    }

    /* If read end is closed, return EPIPE */
    if (pipe->read_closed) {
        return -EPIPE;
    }

    /* If pipe is full, for now return EAGAIN (would block in real implementation) */
    if (pipe->count >= pipe->size) {
        return -EAGAIN;
    }

    /* Write up to len bytes to pipe */
    size_t space = pipe->size - pipe->count;
    size_t to_write = (len < space) ? len : space;
    size_t bytes_written = 0;
    const uint8_t *input = (const uint8_t *)buf;

    while (bytes_written < to_write) {
        pipe->data[pipe->write_pos] = input[bytes_written];
        pipe->write_pos = (pipe->write_pos + 1) % pipe->size;
        bytes_written++;
    }

    pipe->count += bytes_written;

    return (ssize_t)bytes_written;
}

/**
 * Release read end of pipe.
 */
static int pipe_release_read(void *inode, void *priv) {
    (void)inode;

    struct pipe_buffer *pipe = (struct pipe_buffer *)priv;
    if (!pipe) {
        return 0;
    }

    pipe->read_closed = true;
    pipe->refcount--;

    if (pipe->refcount == 0) {
        pipe_buffer_destroy(pipe);
    }

    return 0;
}

/**
 * Release write end of pipe.
 */
static int pipe_release_write(void *inode, void *priv) {
    (void)inode;

    struct pipe_buffer *pipe = (struct pipe_buffer *)priv;
    if (!pipe) {
        return 0;
    }

    pipe->write_closed = true;
    pipe->refcount--;

    if (pipe->refcount == 0) {
        pipe_buffer_destroy(pipe);
    }

    return 0;
}

/**
 * Helper to allocate a file descriptor for a pipe end.
 * This mirrors the logic in fut_vfs.c for character devices.
 */
extern int chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv);

/**
 * pipe() syscall - Create a pipe for IPC.
 *
 * @param pipefd User-space array to receive two file descriptors
 *               pipefd[0] = read end
 *               pipefd[1] = write end
 *
 * Returns:
 *   - 0 on success (pipefd filled with read and write fds)
 *   - -errno on error
 */
long sys_pipe(int pipefd[2]) {
    /* Validate user pointer */
    if (!pipefd) {
        return -EINVAL;
    }

    /* TODO: Validate that pipefd is a valid userspace pointer */

    /* Create pipe buffer */
    struct pipe_buffer *pipe = pipe_buffer_create();
    if (!pipe) {
        return -ENOMEM;
    }

    /* Allocate read end file descriptor */
    int read_fd = chrdev_alloc_fd(&pipe_read_fops, NULL, pipe);
    if (read_fd < 0) {
        pipe_buffer_destroy(pipe);
        return read_fd;
    }

    /* Allocate write end file descriptor */
    int write_fd = chrdev_alloc_fd(&pipe_write_fops, NULL, pipe);
    if (write_fd < 0) {
        /* Close read fd to clean up */
        extern int fut_vfs_close(int fd);
        fut_vfs_close(read_fd);
        return write_fd;
    }

    /* Return file descriptors to userspace */
    pipefd[0] = read_fd;
    pipefd[1] = write_fd;

    fut_printf("[PIPE] Created pipe: read_fd=%d write_fd=%d\n", read_fd, write_fd);

    return 0;
}
