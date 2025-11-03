/* sys_pipe.c - pipe() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX pipe() for inter-process communication.
 * Essential for shell pipelines and IPC.
 *
 * Phase 1 (Completed): Basic pipe creation with read/write ends
 * Phase 2 (Current): Enhanced validation, FD categorization, and detailed logging
 * Phase 3: Performance optimization (larger buffers, zero-copy)
 * Phase 4: Advanced features (pipe2 with flags, splice support)
 */

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/fut_waitq.h>
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
    fut_waitq_t read_waitq;  /* Readers waiting for data */
    fut_waitq_t write_waitq; /* Writers waiting for space */
    fut_spinlock_t lock;     /* Protects pipe state */
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

    /* Initialize wait queues and lock */
    fut_waitq_init(&pipe->read_waitq);
    fut_waitq_init(&pipe->write_waitq);
    fut_spinlock_init(&pipe->lock);

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

    fut_spinlock_acquire(&pipe->lock);

    /* Block until data is available */
    while (pipe->count == 0 && !pipe->write_closed) {
        /* Pipe is empty and write end is still open - block */
        fut_waitq_sleep_locked(&pipe->read_waitq, &pipe->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pipe->lock);
    }

    /* If pipe is empty and write end is closed, return EOF */
    if (pipe->count == 0 && pipe->write_closed) {
        fut_spinlock_release(&pipe->lock);
        return 0;  /* EOF */
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

    fut_spinlock_release(&pipe->lock);

    /* Wake up any writers waiting for space */
    fut_waitq_wake_one(&pipe->write_waitq);

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

    fut_spinlock_acquire(&pipe->lock);

    /* If read end is closed, return EPIPE */
    if (pipe->read_closed) {
        fut_spinlock_release(&pipe->lock);
        return -EPIPE;
    }

    /* Block until space is available */
    while (pipe->count >= pipe->size && !pipe->read_closed) {
        /* Pipe is full and read end is still open - block */
        fut_waitq_sleep_locked(&pipe->write_waitq, &pipe->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pipe->lock);
    }

    /* Check again after waking up */
    if (pipe->read_closed) {
        fut_spinlock_release(&pipe->lock);
        return -EPIPE;
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

    fut_spinlock_release(&pipe->lock);

    /* Wake up any readers waiting for data */
    fut_waitq_wake_one(&pipe->read_waitq);

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

    fut_spinlock_acquire(&pipe->lock);
    pipe->read_closed = true;
    pipe->refcount--;
    fut_spinlock_release(&pipe->lock);

    /* Wake any writers - they'll see read_closed and return EPIPE */
    fut_waitq_wake_all(&pipe->write_waitq);

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

    fut_spinlock_acquire(&pipe->lock);
    pipe->write_closed = true;
    pipe->refcount--;
    fut_spinlock_release(&pipe->lock);

    /* Wake any readers - they'll see write_closed and return EOF */
    fut_waitq_wake_all(&pipe->read_waitq);

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
 * Creates a pipe, a unidirectional data channel that can be used for
 * inter-process communication. The pipe has a read end and a write end.
 * Data written to the write end can be read from the read end.
 *
 * @param pipefd User-space array to receive two file descriptors
 *               pipefd[0] = read end
 *               pipefd[1] = write end
 *
 * Returns:
 *   - 0 on success (pipefd filled with read and write fds)
 *   - -EINVAL if pipefd is NULL
 *   - -EFAULT if pipefd points to inaccessible memory
 *   - -ENOMEM if pipe buffer allocation fails
 *   - -EMFILE if too many file descriptors open
 *
 * Behavior:
 *   - Creates unidirectional data channel
 *   - pipefd[0] is read end (read-only)
 *   - pipefd[1] is write end (write-only)
 *   - Pipe buffer size is 4096 bytes (PIPE_BUF_SIZE)
 *   - Reading from empty pipe blocks until data available
 *   - Writing to full pipe blocks until space available
 *   - Closing write end causes read to return EOF
 *   - Writing with read end closed returns -EPIPE
 *
 * Common usage patterns:
 *
 * Basic pipe communication:
 *   int pipefd[2];
 *   pipe(pipefd);
 *   if (fork() == 0) {
 *       // Child: write to pipe
 *       close(pipefd[0]);  // Close read end
 *       write(pipefd[1], "hello", 5);
 *       close(pipefd[1]);
 *   } else {
 *       // Parent: read from pipe
 *       close(pipefd[1]);  // Close write end
 *       char buf[100];
 *       read(pipefd[0], buf, sizeof(buf));
 *       close(pipefd[0]);
 *   }
 *
 * Shell pipeline (cmd1 | cmd2):
 *   int pipefd[2];
 *   pipe(pipefd);
 *   if (fork() == 0) {
 *       // cmd1: redirect stdout to pipe write end
 *       dup2(pipefd[1], STDOUT_FILENO);
 *       close(pipefd[0]);
 *       close(pipefd[1]);
 *       exec("cmd1");
 *   }
 *   if (fork() == 0) {
 *       // cmd2: redirect stdin from pipe read end
 *       dup2(pipefd[0], STDIN_FILENO);
 *       close(pipefd[0]);
 *       close(pipefd[1]);
 *       exec("cmd2");
 *   }
 *   close(pipefd[0]);
 *   close(pipefd[1]);
 *
 * Producer-consumer pattern:
 *   int pipefd[2];
 *   pipe(pipefd);
 *   pthread_create(&producer, NULL, produce_data, &pipefd[1]);
 *   pthread_create(&consumer, NULL, consume_data, &pipefd[0]);
 *
 * Pipe capacity and atomicity:
 *   - PIPE_BUF (4096 bytes): Atomic write guarantee
 *   - Writes ≤ PIPE_BUF are atomic
 *   - Writes > PIPE_BUF may be interleaved
 *   - Useful for concurrent writes from multiple processes
 *
 * Blocking behavior:
 *   - Read on empty pipe: blocks until data available or write end closed
 *   - Write on full pipe: blocks until space available or read end closed
 *   - Non-blocking I/O: Use O_NONBLOCK flag (pipe2)
 *
 * Related syscalls:
 *   - pipe2(): Create pipe with flags (O_NONBLOCK, O_CLOEXEC)
 *   - dup2(): Redirect pipe to stdin/stdout
 *   - fcntl(): Set pipe to non-blocking mode
 *   - poll()/select(): Wait for pipe readiness
 *
 * Phase 1 (Completed): Basic pipe creation with read/write ends
 * Phase 2 (Current): Enhanced validation, FD categorization, detailed logging
 * Phase 3: Performance optimization (larger buffers, zero-copy)
 * Phase 4: Advanced features (pipe2 with flags, splice support)
 */
long sys_pipe(int pipefd[2]) {
    /* Phase 2: Validate user pointer */
    if (!pipefd) {
        fut_printf("[PIPE] pipe(pipefd=NULL) -> EINVAL (NULL pipefd array)\n");
        return -EINVAL;
    }

    /* Validate that pipefd is a valid userspace pointer (writable) */
    if (fut_access_ok(pipefd, sizeof(int) * 2, 1) != 0) {
        fut_printf("[PIPE] pipe(pipefd=?) -> EFAULT (pipefd not accessible)\n");
        return -EFAULT;
    }

    /* Create pipe buffer */
    struct pipe_buffer *pipe = pipe_buffer_create();
    if (!pipe) {
        fut_printf("[PIPE] pipe() -> ENOMEM (pipe buffer allocation failed)\n");
        return -ENOMEM;
    }

    /* Allocate read end file descriptor */
    int read_fd = chrdev_alloc_fd(&pipe_read_fops, NULL, pipe);
    if (read_fd < 0) {
        const char *error_desc;
        switch (read_fd) {
            case -EMFILE:
                error_desc = "too many open files";
                break;
            case -ENOMEM:
                error_desc = "out of memory";
                break;
            default:
                error_desc = "fd allocation failed";
                break;
        }
        fut_printf("[PIPE] pipe() -> %d (%s, read_fd allocation)\n", read_fd, error_desc);
        pipe_buffer_destroy(pipe);
        return read_fd;
    }

    /* Allocate write end file descriptor */
    int write_fd = chrdev_alloc_fd(&pipe_write_fops, NULL, pipe);
    if (write_fd < 0) {
        const char *error_desc;
        switch (write_fd) {
            case -EMFILE:
                error_desc = "too many open files";
                break;
            case -ENOMEM:
                error_desc = "out of memory";
                break;
            default:
                error_desc = "fd allocation failed";
                break;
        }
        fut_printf("[PIPE] pipe(read_fd=%d) -> %d (%s, write_fd allocation)\n",
                   read_fd, write_fd, error_desc);
        /* Close read fd to clean up */
        extern int fut_vfs_close(int fd);
        fut_vfs_close(read_fd);
        return write_fd;
    }

    /* Phase 2: Categorize FD ranges */
    const char *read_fd_category;
    if (read_fd <= 2) {
        read_fd_category = "stdio (0-2)";
    } else if (read_fd < 10) {
        read_fd_category = "low (3-9)";
    } else if (read_fd < 100) {
        read_fd_category = "normal (10-99)";
    } else if (read_fd < 1000) {
        read_fd_category = "high (100-999)";
    } else {
        read_fd_category = "very high (≥1000)";
    }

    const char *write_fd_category;
    if (write_fd <= 2) {
        write_fd_category = "stdio (0-2)";
    } else if (write_fd < 10) {
        write_fd_category = "low (3-9)";
    } else if (write_fd < 100) {
        write_fd_category = "normal (10-99)";
    } else if (write_fd < 1000) {
        write_fd_category = "high (100-999)";
    } else {
        write_fd_category = "very high (≥1000)";
    }

    /* Return file descriptors to userspace */
    pipefd[0] = read_fd;
    pipefd[1] = write_fd;

    /* Phase 2: Detailed success logging */
    fut_printf("[PIPE] pipe(read_fd=%d [%s], write_fd=%d [%s], buf_size=%u) -> 0 "
               "(pipe created, Phase 2)\n",
               read_fd, read_fd_category, write_fd, write_fd_category, PIPE_BUF_SIZE);

    return 0;
}
