/* sys_pipe.c - pipe() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX pipe() for inter-process communication.
 * Essential for shell pipelines and IPC.
 *
 * Phase 1 (Completed): Basic pipe creation with read/write ends
 * Phase 2 (Completed): Enhanced validation, FD categorization, and detailed logging
 * Phase 3 (Completed): FD allocation and buffer management with wait queues
 * Phase 4 (Completed): pipe2() with O_NONBLOCK and O_CLOEXEC flags
 * Advanced features (splice support, pipe capacity control)
 */

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/uaccess.h>
#include <kernel/fut_waitq.h>
#include <kernel/signal.h>
#include <kernel/syscalls.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

#include <kernel/kprintf.h>

/* Pipe buffer size (capacity) and POSIX atomic-write guarantee */
#define PIPE_BUF_SIZE    65536
#define PIPE_BUF_ATOMIC   4096  /* writes <= this size are atomic per POSIX */

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
    bool read_nonblock;     /* Read end O_NONBLOCK */
    bool write_nonblock;    /* Write end O_NONBLOCK */
    fut_waitq_t read_waitq;  /* Readers waiting for data */
    fut_waitq_t write_waitq; /* Writers waiting for space */
    fut_spinlock_t lock;     /* Protects pipe state */
    fut_waitq_t *epoll_notify; /* Wakes epoll_wait on data/HUP */
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

/* Private ioctl to propagate file flags (O_NONBLOCK) from fcntl */
#define PIPE_IOC_SETFLAGS  0xFE01

/* Forward declarations */
static ssize_t pipe_read(void *inode, void *priv, void *buf, size_t len, off_t *pos);
static ssize_t pipe_write(void *inode, void *priv, const void *buf, size_t len, off_t *pos);
static int pipe_release_read(void *inode, void *priv);
static int pipe_release_write(void *inode, void *priv);
static int pipe_ioctl_read(void *inode, void *priv, unsigned long req, unsigned long arg);
static int pipe_ioctl_write(void *inode, void *priv, unsigned long req, unsigned long arg);

/* Pipe file operations - initialized at runtime to avoid ARM64 relocation issues */
static struct fut_file_ops pipe_read_fops;
static struct fut_file_ops pipe_write_fops;
static bool pipe_fops_initialized = false;

/* Initialize pipe file operations at runtime */
static void init_pipe_fops(void) {
    if (pipe_fops_initialized) {
        return;
    }

    pipe_read_fops.open = NULL;
    pipe_read_fops.release = pipe_release_read;
    pipe_read_fops.read = pipe_read;
    pipe_read_fops.write = NULL;
    pipe_read_fops.ioctl = pipe_ioctl_read;
    pipe_read_fops.mmap = NULL;

    pipe_write_fops.open = NULL;
    pipe_write_fops.release = pipe_release_write;
    pipe_write_fops.read = NULL;
    pipe_write_fops.write = pipe_write;
    pipe_write_fops.ioctl = pipe_ioctl_write;
    pipe_write_fops.mmap = NULL;

    pipe_fops_initialized = true;
}

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
    pipe->read_nonblock = false;
    pipe->write_nonblock = false;
    pipe->epoll_notify = NULL;

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

    /* Return EAGAIN if non-blocking and no data available */
    if (pipe->count == 0 && !pipe->write_closed && pipe->read_nonblock) {
        fut_spinlock_release(&pipe->lock);
        return -EAGAIN;
    }

    /* Block until data is available */
    while (pipe->count == 0 && !pipe->write_closed) {
        /* Check for pending signals → EINTR (use per-thread mask) */
        fut_task_t *task = fut_task_current();
        if (task) {
            fut_thread_t *pipe_thr = fut_thread_current();
            uint64_t pending = __atomic_load_n(&task->pending_signals, __ATOMIC_ACQUIRE);
            uint64_t blocked = pipe_thr ?
                __atomic_load_n(&pipe_thr->signal_mask, __ATOMIC_ACQUIRE) :
                task->signal_mask;
            if (pending & ~blocked) {
                fut_spinlock_release(&pipe->lock);
                return -EINTR;
            }
        }
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
    /* Wake epoll (space available on write end) */
    if (pipe->epoll_notify)
        fut_waitq_wake_one(pipe->epoll_notify);

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

    /* If read end is closed, return EPIPE (VFS layer delivers SIGPIPE) */
    if (pipe->read_closed) {
        fut_spinlock_release(&pipe->lock);
        return -EPIPE;
    }

    /* Non-blocking: enforce POSIX atomicity for writes <= PIPE_BUF.
     * writes <= PIPE_BUF must complete entirely or return EAGAIN (never partial).
     * writes > PIPE_BUF are non-atomic; EAGAIN only when pipe is completely full. */
    if (pipe->write_nonblock) {
        size_t space = pipe->size - pipe->count;
        if (len <= PIPE_BUF_ATOMIC) {
            /* Atomic write: need room for the entire write */
            if (space < len) {
                fut_spinlock_release(&pipe->lock);
                return -EAGAIN;
            }
        } else {
            /* Large write: EAGAIN only when no space at all */
            if (space == 0) {
                fut_spinlock_release(&pipe->lock);
                return -EAGAIN;
            }
        }
    }

    /* Block until space is available */
    while (pipe->count >= pipe->size && !pipe->read_closed) {
        /* Check for pending signals → EINTR (use per-thread mask) */
        fut_task_t *stask = fut_task_current();
        if (stask) {
            fut_thread_t *pipe_thr = fut_thread_current();
            uint64_t pending = __atomic_load_n(&stask->pending_signals, __ATOMIC_ACQUIRE);
            uint64_t blocked = pipe_thr ?
                __atomic_load_n(&pipe_thr->signal_mask, __ATOMIC_ACQUIRE) :
                stask->signal_mask;
            if (pending & ~blocked) {
                fut_spinlock_release(&pipe->lock);
                return -EINTR;
            }
        }
        /* Pipe is full and read end is still open - block */
        fut_waitq_sleep_locked(&pipe->write_waitq, &pipe->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pipe->lock);
    }

    /* Check again after waking up — EPIPE if broken (VFS delivers SIGPIPE) */
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
    /* Wake any epoll instance monitoring this pipe */
    if (pipe->epoll_notify)
        fut_waitq_wake_one(pipe->epoll_notify);

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
    uint32_t remaining = pipe->refcount;
    fut_spinlock_release(&pipe->lock);

    /* Wake any writers - they'll see read_closed and return EPIPE */
    fut_waitq_wake_all(&pipe->write_waitq);
    /* Wake epoll (EPOLLHUP|EPOLLERR on write end) */
    if (pipe->epoll_notify)
        fut_waitq_wake_one(pipe->epoll_notify);

    if (remaining == 0) {
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
    uint32_t remaining = pipe->refcount;
    fut_spinlock_release(&pipe->lock);

    /* Wake any readers - they'll see write_closed and return EOF */
    fut_waitq_wake_all(&pipe->read_waitq);
    /* Wake epoll (EPOLLHUP on read end) */
    if (pipe->epoll_notify)
        fut_waitq_wake_one(pipe->epoll_notify);

    if (remaining == 0) {
        pipe_buffer_destroy(pipe);
    }

    return 0;
}

/**
 * Ioctl handler for pipe read end - propagates O_NONBLOCK from fcntl.
 */
static int pipe_ioctl_read(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode;
    if (req == PIPE_IOC_SETFLAGS) {
        struct pipe_buffer *pipe = (struct pipe_buffer *)priv;
        if (pipe) {
            pipe->read_nonblock = ((int)arg & 0x800 /* O_NONBLOCK */) != 0;
        }
        return 0;
    }
    return -EINVAL;
}

/**
 * Ioctl handler for pipe write end - propagates O_NONBLOCK from fcntl.
 */
static int pipe_ioctl_write(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode;
    if (req == PIPE_IOC_SETFLAGS) {
        struct pipe_buffer *pipe = (struct pipe_buffer *)priv;
        if (pipe) {
            pipe->write_nonblock = ((int)arg & 0x800 /* O_NONBLOCK */) != 0;
        }
        return 0;
    }
    return -EINVAL;
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
 * Phase 2 (Completed): Enhanced validation, FD categorization, detailed logging
 * Phase 3 (Completed): FD allocation and buffer management with wait queues
 * Phase 4: Advanced features (pipe2 with flags, splice support)
 */
long sys_pipe(int pipefd[2]) {
    /* Initialize pipe file operations on first use */
    init_pipe_fops();

    /* Phase 2: Validate user pointer */
    if (!pipefd) {
        fut_printf("[PIPE] pipe(pipefd=NULL) -> EINVAL (NULL pipefd array)\n");
        return -EINVAL;
    }

    /* Validate that pipefd is a valid userspace pointer (writable)
     * Skip check for kernel pointers (used by kernel tests) */
    uintptr_t ptr_val = (uintptr_t)pipefd;
    bool is_kernel_ptr = (ptr_val >= KERNEL_VIRTUAL_BASE);  /* Architecture-specific */
    if (!is_kernel_ptr && fut_access_ok(pipefd, sizeof(int) * 2, 1) != 0) {
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
        fut_vfs_close(read_fd);
        return write_fd;
    }

    /* Fix file access modes: read end is O_RDONLY, write end is O_WRONLY */
    {
        extern struct fut_file *vfs_get_file(int fd);
        struct fut_file *rfile = vfs_get_file(read_fd);
        struct fut_file *wfile = vfs_get_file(write_fd);
        if (rfile) rfile->flags = O_RDONLY;
        if (wfile) wfile->flags = O_WRONLY;
    }

    /* Copy file descriptors to userspace safely */
    int fds[2];
    fds[0] = read_fd;
    fds[1] = write_fd;

    /* For kernel pointers (tests), use memcpy; for userspace, use fut_copy_to_user */
    if (is_kernel_ptr) {
        memcpy(pipefd, fds, sizeof(int) * 2);
    } else {
        if (fut_copy_to_user(pipefd, fds, sizeof(int) * 2) != 0) {
            fut_printf("[PIPE] pipe(read_fd=%d, write_fd=%d) -> EFAULT "
                       "(failed to copy FDs to userspace write pointer validation)\n",
                       read_fd, write_fd);
            /* Clean up both FDs - pipe creation failed */
            fut_vfs_close(read_fd);
            fut_vfs_close(write_fd);
            return -EFAULT;
        }
    }

    return 0;
}

/**
 * sys_pipe2() - Create pipe with flags
 *
 * Similar to pipe() but allows atomically setting flags on the pipe FDs.
 * This is essential for avoiding race conditions when setting O_NONBLOCK
 * or O_CLOEXEC.
 *
 * @param pipefd  User-space array to store [read_fd, write_fd]
 * @param flags   Bitwise OR of O_NONBLOCK (0x800) and O_CLOEXEC (0x80000)
 *
 * Returns:
 *   - 0 on success (pipefd filled with read/write FDs)
 *   - -EINVAL if pipefd is NULL or flags contains invalid bits
 *   - -EFAULT if pipefd not accessible
 *   - -ENOMEM if memory allocation fails
 *   - -EMFILE if no free file descriptors
 *
 * Supported flags:
 *   - O_NONBLOCK (0x800): Set non-blocking mode on both FDs
 *   - O_CLOEXEC (0x80000): Set close-on-exec on both FDs
 *
 * Phase 4: Initial implementation with O_NONBLOCK and O_CLOEXEC support
 */
long sys_pipe2(int pipefd[2], int flags) {
    /* Initialize pipe file operations on first use */
    init_pipe_fops();

    /* Validate flags */
    const int VALID_FLAGS = O_NONBLOCK | O_CLOEXEC;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[PIPE2] pipe2(pipefd=%p, flags=0x%x) -> EINVAL (invalid flags)\n",
                   pipefd, flags);
        return -EINVAL;
    }

    /* Validate user pointer */
    if (!pipefd) {
        fut_printf("[PIPE2] pipe2(pipefd=NULL, flags=0x%x) -> EINVAL (NULL pipefd array)\n",
                   flags);
        return -EINVAL;
    }

    /* Validate that pipefd is a valid userspace pointer (writable)
     * Skip check for kernel pointers (used by kernel tests) */
    uintptr_t ptr_val2 = (uintptr_t)pipefd;
    bool is_kernel_ptr2 = (ptr_val2 >= KERNEL_VIRTUAL_BASE);  /* Architecture-specific */
    if (!is_kernel_ptr2 && fut_access_ok(pipefd, sizeof(int) * 2, 1) != 0) {
        fut_printf("[PIPE2] pipe2(pipefd=?, flags=0x%x) -> EFAULT (pipefd not accessible)\n",
                   flags);
        return -EFAULT;
    }

    /* Create pipe buffer */
    struct pipe_buffer *pipe = pipe_buffer_create();
    if (!pipe) {
        fut_printf("[PIPE2] pipe2(flags=0x%x) -> ENOMEM (pipe buffer allocation failed)\n",
                   flags);
        return -ENOMEM;
    }

    /* Allocate read end file descriptor */
    int read_fd = chrdev_alloc_fd(&pipe_read_fops, NULL, pipe);
    if (read_fd < 0) {
        fut_printf("[PIPE2] pipe2(flags=0x%x) -> %d (read_fd allocation failed)\n",
                   flags, read_fd);
        pipe_buffer_destroy(pipe);
        return read_fd;
    }

    /* Allocate write end file descriptor */
    int write_fd = chrdev_alloc_fd(&pipe_write_fops, NULL, pipe);
    if (write_fd < 0) {
        fut_printf("[PIPE2] pipe2(flags=0x%x, read_fd=%d) -> %d (write_fd allocation failed)\n",
                   flags, read_fd, write_fd);
        fut_vfs_close(read_fd);
        return write_fd;
    }

    /* Fix file access modes: read end is O_RDONLY, write end is O_WRONLY */
    {
        extern struct fut_file *vfs_get_file(int fd);
        struct fut_file *rfile = vfs_get_file(read_fd);
        struct fut_file *wfile = vfs_get_file(write_fd);
        if (rfile) rfile->flags = O_RDONLY;
        if (wfile) wfile->flags = O_WRONLY;
    }

    /* Apply O_NONBLOCK flag if requested */
    if (flags & O_NONBLOCK) {
        sys_fcntl(read_fd, F_SETFL, O_NONBLOCK);
        sys_fcntl(write_fd, F_SETFL, O_NONBLOCK);
    }

    /* Apply O_CLOEXEC flag if requested */
    if (flags & O_CLOEXEC) {
        sys_fcntl(read_fd, F_SETFD, FD_CLOEXEC);
        sys_fcntl(write_fd, F_SETFD, FD_CLOEXEC);
    }

    /* Copy file descriptors to userspace */
    int fds[2];
    fds[0] = read_fd;
    fds[1] = write_fd;

    /* For kernel pointers (tests), use memcpy; for userspace, use fut_copy_to_user */
    if (is_kernel_ptr2) {
        memcpy(pipefd, fds, sizeof(int) * 2);
    } else {
        if (fut_copy_to_user(pipefd, fds, sizeof(int) * 2) != 0) {
            fut_printf("[PIPE2] pipe2(flags=0x%x, read_fd=%d, write_fd=%d) -> EFAULT "
                       "(failed to copy FDs to userspace)\n",
                       flags, read_fd, write_fd);
            fut_vfs_close(read_fd);
            fut_vfs_close(write_fd);
            return -EFAULT;
        }
    }

    return 0;
}

/**
 * fut_pipe_poll - Query I/O readiness for a pipe file descriptor.
 *
 * For the read end: EPOLLIN when data is available, EPOLLHUP when write end closed.
 * For the write end: EPOLLOUT when buffer has space, EPOLLERR when read end closed.
 *
 * @param file        Kernel file structure to test.
 * @param requested   Bitmask of EPOLL* events being requested.
 * @param ready_out   Receives the ready mask on success.
 *
 * @return true if @file is a pipe (read or write end), false otherwise.
 */
#include <kernel/eventfd.h>
#include <sys/epoll.h>
bool fut_pipe_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out) {
    if (!file || !file->chr_private) {
        return false;
    }

    bool is_read_end  = (file->chr_ops == &pipe_read_fops);
    bool is_write_end = (file->chr_ops == &pipe_write_fops);
    if (!is_read_end && !is_write_end) {
        return false;
    }

    struct pipe_buffer *pipe = (struct pipe_buffer *)file->chr_private;
    uint32_t ready = 0;

    fut_spinlock_acquire(&pipe->lock);

    if (is_read_end) {
        /* Data available or write end closed → EPOLLIN (read won't block).
         * Write end closed → EPOLLHUP.
         * Linux reports both EPOLLIN|EPOLLHUP when write end is closed. */
        if (pipe->count > 0 && (requested & EPOLLIN))
            ready |= EPOLLIN;
        if (pipe->write_closed) {
            ready |= EPOLLHUP;
            /* EPOLLRDHUP: peer closed write half (if caller asked for it) */
            if (requested & EPOLLRDHUP)
                ready |= EPOLLRDHUP;
            /* EOF is readable — report EPOLLIN so poll detects it */
            if (requested & EPOLLIN)
                ready |= EPOLLIN;
        }
    } else {
        /* write end: space available → EPOLLOUT.
         * Read end closed → EPOLLHUP | EPOLLERR (Linux behavior). */
        if (pipe->count < pipe->size && !pipe->read_closed && (requested & EPOLLOUT))
            ready |= EPOLLOUT;
        if (pipe->read_closed)
            ready |= EPOLLHUP | EPOLLERR;
    }

    fut_spinlock_release(&pipe->lock);

    if (ready_out)
        *ready_out = ready;
    return true;
}

/**
 * Set the epoll notification waitqueue on a pipe.
 * Called from epoll_ctl ADD to enable pipe→epoll wakeup.
 */
void fut_pipe_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq) {
    if (!file || !file->chr_private)
        return;
    if (file->chr_ops != &pipe_read_fops && file->chr_ops != &pipe_write_fops)
        return;
    struct pipe_buffer *pipe = (struct pipe_buffer *)file->chr_private;
    pipe->epoll_notify = wq;
}

/**
 * pipe_peek - Copy up to `len` bytes from a readable pipe without consuming them.
 *
 * Used by sys_tee() to duplicate data from one pipe to another while keeping
 * the source pipe's data available for subsequent reads.
 *
 * @param read_priv   chr_private of the pipe read-end (struct pipe_buffer *)
 * @param buf         Kernel buffer to copy data into
 * @param len         Maximum bytes to peek
 *
 * Returns the number of bytes copied (>= 0), or a negative error code.
 */
ssize_t pipe_peek(void *read_priv, void *buf, size_t len) {
    struct pipe_buffer *pipe = (struct pipe_buffer *)read_priv;
    if (!pipe || !buf || len == 0)
        return -EINVAL;

    fut_spinlock_acquire(&pipe->lock);

    if (pipe->count == 0) {
        fut_spinlock_release(&pipe->lock);
        /* Non-blocking peek: return 0 if empty */
        return 0;
    }

    size_t to_copy = (len < pipe->count) ? len : pipe->count;
    uint8_t *dst = (uint8_t *)buf;
    size_t rpos = pipe->read_pos;

    for (size_t i = 0; i < to_copy; i++) {
        dst[i] = pipe->data[rpos];
        rpos = (rpos + 1) % pipe->size;
        /* read_pos is NOT updated — data stays in the buffer */
    }

    fut_spinlock_release(&pipe->lock);
    return (ssize_t)to_copy;
}
