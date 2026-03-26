/* kernel/pty.c - Pseudo-terminal (PTY) subsystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements Unix98-style PTY pairs via /dev/ptmx.
 *
 * Opening /dev/ptmx allocates a new master/slave pair and returns the master FD.
 * The slave number is retrieved via ioctl(TIOCGPTN) and opened at /dev/pts/<n>.
 * Data written to the master appears as input on the slave and vice versa.
 *
 * Supported ioctls:
 *   TIOCGPTN     - Get slave PTY number
 *   TIOCSPTLCK   - Lock/unlock slave
 *   TIOCGWINSZ   - Get window size
 *   TIOCSWINSZ   - Set window size
 *   TCGETS       - Get termios
 *   TCSETS        - Set termios
 *   FIONREAD     - Bytes available for read
 */

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_waitq.h>
#include <kernel/kprintf.h>
#include <kernel/pty.h>
#include <kernel/uaccess.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>

/* ioctl numbers */
#define TCGETS      0x5401
#define TCSETS      0x5402
#define TIOCGWINSZ  0x5413
#define TIOCSWINSZ  0x5414
#define TIOCGPTN    0x80045430  /* Get PTY number: ioctl(fd, TIOCGPTN, &n) */
#define TIOCSPTLCK  0x40045431  /* (Un)lock PTY: ioctl(fd, TIOCSPTLCK, &n) */
#define FIONREAD    0x541B

/* Limits */
#define PTY_MAX       64
#define PTY_BUF_SIZE  4096

/* Circular buffer */
struct pty_ring {
    char     buf[PTY_BUF_SIZE];
    uint32_t head;   /* write position */
    uint32_t tail;   /* read position */
};

static inline uint32_t ring_used(const struct pty_ring *r) {
    return (r->head - r->tail) % PTY_BUF_SIZE;
}
static inline uint32_t ring_free(const struct pty_ring *r) {
    return PTY_BUF_SIZE - 1 - ring_used(r);
}
static inline bool ring_empty(const struct pty_ring *r) {
    return r->head == r->tail;
}

static size_t ring_write(struct pty_ring *r, const void *data, size_t n) {
    const char *src = (const char *)data;
    size_t written = 0;
    while (written < n && ring_free(r) > 0) {
        r->buf[r->head % PTY_BUF_SIZE] = src[written++];
        r->head = (r->head + 1) % PTY_BUF_SIZE;
    }
    return written;
}

static size_t ring_read(struct pty_ring *r, void *data, size_t n) {
    char *dst = (char *)data;
    size_t nread = 0;
    while (nread < n && !ring_empty(r)) {
        dst[nread++] = r->buf[r->tail % PTY_BUF_SIZE];
        r->tail = (r->tail + 1) % PTY_BUF_SIZE;
    }
    return nread;
}

/* PTY pair state */
struct pty_pair {
    bool            active;
    uint32_t        master_refcnt;   /* number of open master fds (>0 = open) */
    uint32_t        slave_refcnt;    /* number of open slave fds (>0 = open) */
    bool            locked;          /* TIOCSPTLCK */
    int             index;           /* /dev/pts/<index> */

    struct pty_ring m2s;             /* master-write → slave-read */
    struct pty_ring s2m;             /* slave-write  → master-read */

    struct { uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel; } winsize;
    char            termios[60];     /* raw Linux termios layout */

    fut_spinlock_t  lock;
    fut_waitq_t     master_wq;       /* wake master on s2m data / slave close */
    fut_waitq_t     slave_wq;        /* wake slave on m2s data / master close */

    /* Epoll notification targets */
    fut_waitq_t    *master_epoll_wq;
    fut_waitq_t    *slave_epoll_wq;
};

static struct pty_pair g_ptys[PTY_MAX];
static fut_spinlock_t  g_pty_alloc_lock;

/* ============================================================
 *   PTY pair allocation
 * ============================================================ */

static struct pty_pair *pty_alloc(void) {
    fut_spinlock_acquire(&g_pty_alloc_lock);
    for (int i = 0; i < PTY_MAX; i++) {
        if (!g_ptys[i].active) {
            struct pty_pair *p = &g_ptys[i];
            memset(p, 0, sizeof(*p));
            p->active = true;
            p->index  = i;
            p->locked = true;  /* locked until TIOCSPTLCK(0) */
            fut_spinlock_init(&p->lock);
            fut_waitq_init(&p->master_wq);
            fut_waitq_init(&p->slave_wq);
            /* Default window size */
            p->winsize.ws_row = 24;
            p->winsize.ws_col = 80;
            /* Default termios: cooked mode with standard special characters.
             * Layout: c_iflag(4) c_oflag(4) c_cflag(4) c_lflag(4) c_line(1) c_cc[19] */
            memset(p->termios, 0, sizeof(p->termios));
            uint32_t iflag = 0x0500;  /* ICRNL | IXON */
            uint32_t oflag = 0x0005;  /* OPOST | ONLCR */
            uint32_t cflag = 0x00BF;  /* B38400 | CS8 | CREAD | HUPCL */
            uint32_t lflag = 0x8A3B;  /* ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | ICANON | ISIG | IEXTEN */
            memcpy(p->termios +  0, &iflag, 4);
            memcpy(p->termios +  4, &oflag, 4);
            memcpy(p->termios +  8, &cflag, 4);
            memcpy(p->termios + 12, &lflag, 4);
            /* c_line = 0 (N_TTY line discipline) at offset 16 — already 0 */
            /* c_cc[19] at offset 17: standard Linux special characters */
            static const unsigned char default_cc[19] = {
                3,   /* VINTR    = Ctrl-C */
                28,  /* VQUIT    = Ctrl-\ */
                127, /* VERASE   = DEL */
                21,  /* VKILL    = Ctrl-U */
                4,   /* VEOF     = Ctrl-D */
                0,   /* VTIME    = 0 */
                1,   /* VMIN     = 1 */
                0,   /* VSWTC    = 0 */
                17,  /* VSTART   = Ctrl-Q (XON) */
                19,  /* VSTOP    = Ctrl-S (XOFF) */
                26,  /* VSUSP    = Ctrl-Z */
                0,   /* VEOL     = 0 */
                18,  /* VREPRINT = Ctrl-R */
                15,  /* VDISCARD = Ctrl-O */
                23,  /* VWERASE  = Ctrl-W */
                22,  /* VLNEXT   = Ctrl-V */
                0,   /* VEOL2    = 0 */
                0, 0
            };
            memcpy(p->termios + 17, default_cc, 19);
            fut_spinlock_release(&g_pty_alloc_lock);
            return p;
        }
    }
    fut_spinlock_release(&g_pty_alloc_lock);
    return NULL;
}

/* ============================================================
 *   Master-side file operations
 * ============================================================ */

/* Private data tag so poll can identify master vs slave */
#define PTY_MASTER_TAG  0x50544D00U  /* 'PTM\0' */
#define PTY_SLAVE_TAG   0x50545300U  /* 'PTS\0' */

struct pty_priv {
    uint32_t         tag;
    struct pty_pair *pair;
};

static ssize_t ptmx_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)pos;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) return -EIO;
    struct pty_pair *p = pp->pair;

    fut_spinlock_acquire(&p->lock);
    /* If slave closed and buffer empty → EOF */
    if (p->slave_refcnt == 0 && ring_empty(&p->s2m)) {
        fut_spinlock_release(&p->lock);
        return 0;
    }
    if (ring_empty(&p->s2m)) {
        fut_spinlock_release(&p->lock);
        return -EAGAIN;  /* Non-blocking for now */
    }
    size_t got = ring_read(&p->s2m, buf, n);
    fut_spinlock_release(&p->lock);

    /* Wake slave writers waiting for space */
    fut_waitq_wake_all(&p->slave_wq);
    if (p->slave_epoll_wq)
        fut_waitq_wake_all(p->slave_epoll_wq);

    return (ssize_t)got;
}

static ssize_t ptmx_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)pos;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) return -EIO;
    struct pty_pair *p = pp->pair;

    fut_spinlock_acquire(&p->lock);
    if (p->slave_refcnt == 0) {
        fut_spinlock_release(&p->lock);
        return -EIO;
    }
    size_t wrote = ring_write(&p->m2s, buf, n);
    fut_spinlock_release(&p->lock);

    /* Wake slave readers */
    fut_waitq_wake_all(&p->slave_wq);
    if (p->slave_epoll_wq)
        fut_waitq_wake_all(p->slave_epoll_wq);

    return wrote > 0 ? (ssize_t)wrote : -EAGAIN;
}

static int ptmx_ioctl(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) return -EIO;
    struct pty_pair *p = pp->pair;

    switch (req) {
    case TIOCGPTN: {
        /* Return the slave PTY index */
        int idx = p->index;
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, &idx, sizeof(int));
        else if (fut_copy_to_user((void *)arg, &idx, sizeof(int)) != 0)
            return -EFAULT;
        return 0;
    }
    case TIOCSPTLCK: {
        int val = 0;
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy(&val, (void *)arg, sizeof(int));
        else if (fut_copy_from_user(&val, (void *)arg, sizeof(int)) != 0)
            return -EFAULT;
        fut_spinlock_acquire(&p->lock);
        p->locked = (val != 0);
        fut_spinlock_release(&p->lock);
        return 0;
    }
    case TIOCGWINSZ: {
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, &p->winsize, 8);
        else if (fut_copy_to_user((void *)arg, &p->winsize, 8) != 0)
            return -EFAULT;
        return 0;
    }
    case TIOCSWINSZ: {
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy(&p->winsize, (void *)arg, 8);
        else if (fut_copy_from_user(&p->winsize, (void *)arg, 8) != 0)
            return -EFAULT;
        /* Deliver SIGWINCH to the foreground process group (Linux behavior) */
        {
            extern long sys_kill(int pid, int sig);
            fut_task_t *task = fut_task_current();
            if (task && task->pgid)
                sys_kill(-(int)task->pgid, 28 /* SIGWINCH */);
        }
        return 0;
    }
    case TCGETS: {
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, p->termios, 60);
        else if (fut_copy_to_user((void *)arg, p->termios, 60) != 0)
            return -EFAULT;
        return 0;
    }
    case TCSETS: {
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy(p->termios, (void *)arg, 60);
        else if (fut_copy_from_user(p->termios, (void *)arg, 60) != 0)
            return -EFAULT;
        return 0;
    }
    case FIONREAD: {
        fut_spinlock_acquire(&p->lock);
        int avail = (int)ring_used(&p->s2m);
        fut_spinlock_release(&p->lock);
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, &avail, sizeof(int));
        else if (fut_copy_to_user((void *)arg, &avail, sizeof(int)) != 0)
            return -EFAULT;
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static int ptmx_release(void *inode, void *priv) {
    (void)inode;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) { fut_free(pp); return 0; }
    struct pty_pair *p = pp->pair;

    fut_spinlock_acquire(&p->lock);
    if (p->master_refcnt > 0) p->master_refcnt--;
    bool last_master = (p->master_refcnt == 0);
    fut_spinlock_release(&p->lock);

    if (last_master) {
        /* Wake slave so it sees HUP only when last master fd closes */
        fut_waitq_wake_all(&p->slave_wq);
        if (p->slave_epoll_wq)
            fut_waitq_wake_all(p->slave_epoll_wq);
    }

    /* If both sides fully closed, free the pair */
    fut_spinlock_acquire(&p->lock);
    if (p->master_refcnt == 0 && p->slave_refcnt == 0)
        p->active = false;
    fut_spinlock_release(&p->lock);

    fut_free(pp);
    return 0;
}

/* Runtime-initialized to avoid ARM64 static relocation issues */
static struct fut_file_ops ptmx_fops;

/* ============================================================
 *   /dev/ptmx open handler
 * ============================================================ */

static int ptmx_open(void *inode, int flags, void **private_data) {
    (void)inode; (void)flags;
    struct pty_pair *p = pty_alloc();
    if (!p) return -ENOSPC;

    struct pty_priv *pp = fut_malloc(sizeof(*pp));
    if (!pp) { p->active = false; return -ENOMEM; }
    pp->tag  = PTY_MASTER_TAG;
    pp->pair = p;
    p->master_refcnt++;

    *private_data = pp;
    return 0;
}

/* ============================================================
 *   Slave-side file operations
 * ============================================================ */

static ssize_t pts_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)pos;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) return -EIO;
    struct pty_pair *p = pp->pair;

    fut_spinlock_acquire(&p->lock);
    if (p->master_refcnt == 0 && ring_empty(&p->m2s)) {
        fut_spinlock_release(&p->lock);
        return 0;  /* EOF: master closed */
    }
    if (ring_empty(&p->m2s)) {
        fut_spinlock_release(&p->lock);
        return -EAGAIN;
    }
    size_t got = ring_read(&p->m2s, buf, n);
    fut_spinlock_release(&p->lock);

    /* Wake master writers */
    fut_waitq_wake_all(&p->master_wq);
    if (p->master_epoll_wq)
        fut_waitq_wake_all(p->master_epoll_wq);

    return (ssize_t)got;
}

static ssize_t pts_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)pos;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) return -EIO;
    struct pty_pair *p = pp->pair;

    fut_spinlock_acquire(&p->lock);
    if (p->master_refcnt == 0) {
        fut_spinlock_release(&p->lock);
        return -EIO;
    }
    size_t wrote = ring_write(&p->s2m, buf, n);
    fut_spinlock_release(&p->lock);

    /* Wake master readers */
    fut_waitq_wake_all(&p->master_wq);
    if (p->master_epoll_wq)
        fut_waitq_wake_all(p->master_epoll_wq);

    return wrote > 0 ? (ssize_t)wrote : -EAGAIN;
}

static int pts_ioctl(void *inode, void *priv, unsigned long req, unsigned long arg) {
    /* Slave supports the same ioctls as master (except TIOCGPTN/TIOCSPTLCK) */
    (void)inode;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) return -EIO;
    struct pty_pair *p = pp->pair;

    switch (req) {
    case TIOCGWINSZ:
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, &p->winsize, 8);
        else if (fut_copy_to_user((void *)arg, &p->winsize, 8) != 0)
            return -EFAULT;
        return 0;
    case TIOCSWINSZ:
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy(&p->winsize, (void *)arg, 8);
        else if (fut_copy_from_user(&p->winsize, (void *)arg, 8) != 0)
            return -EFAULT;
        /* Deliver SIGWINCH to the foreground process group */
        {
            extern long sys_kill(int pid, int sig);
            fut_task_t *task = fut_task_current();
            if (task && task->pgid)
                sys_kill(-(int)task->pgid, 28 /* SIGWINCH */);
        }
        return 0;
    case TCGETS:
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, p->termios, 60);
        else if (fut_copy_to_user((void *)arg, p->termios, 60) != 0)
            return -EFAULT;
        return 0;
    case TCSETS:
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy(p->termios, (void *)arg, 60);
        else if (fut_copy_from_user(p->termios, (void *)arg, 60) != 0)
            return -EFAULT;
        return 0;
    case FIONREAD: {
        fut_spinlock_acquire(&p->lock);
        int avail = (int)ring_used(&p->m2s);
        fut_spinlock_release(&p->lock);
        if ((uintptr_t)arg >= 0xFFFF800000000000ULL)
            memcpy((void *)arg, &avail, sizeof(int));
        else if (fut_copy_to_user((void *)arg, &avail, sizeof(int)) != 0)
            return -EFAULT;
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static int pts_release(void *inode, void *priv) {
    (void)inode;
    struct pty_priv *pp = (struct pty_priv *)priv;
    if (!pp || !pp->pair) { fut_free(pp); return 0; }
    struct pty_pair *p = pp->pair;

    fut_spinlock_acquire(&p->lock);
    int slave_idx = p->index;
    if (p->slave_refcnt > 0) p->slave_refcnt--;
    bool last_slave = (p->slave_refcnt == 0);
    fut_spinlock_release(&p->lock);

    if (last_slave) {
        /* Remove /dev/pts/<n> ramfs entry only when last slave fd closes */
        char pts_path[20];
        const char *pfx = "/dev/pts/";
        int pi = 0;
        while (pfx[pi]) { pts_path[pi] = pfx[pi]; pi++; }
        if (slave_idx >= 10) pts_path[pi++] = (char)('0' + slave_idx / 10);
        pts_path[pi++] = (char)('0' + slave_idx % 10);
        pts_path[pi] = '\0';
        extern int fut_vfs_unlink(const char *path);
        fut_vfs_unlink(pts_path);

        /* Wake master so it sees EOF */
        fut_waitq_wake_all(&p->master_wq);
        if (p->master_epoll_wq)
            fut_waitq_wake_all(p->master_epoll_wq);
    }

    /* If both sides fully closed, free the pair */
    fut_spinlock_acquire(&p->lock);
    if (p->master_refcnt == 0 && p->slave_refcnt == 0)
        p->active = false;
    fut_spinlock_release(&p->lock);

    fut_free(pp);
    return 0;
}

static struct fut_file_ops pts_fops;

/* ============================================================
 *   Opening /dev/pts/<n> via VFS
 * ============================================================ */

/* Called when VFS opens /dev/pts/<n>.  Returns an fd for the slave side. */
int pty_open_slave(int index) {
    if (index < 0 || index >= PTY_MAX) return -ENOENT;
    struct pty_pair *p = &g_ptys[index];

    fut_spinlock_acquire(&p->lock);
    if (!p->active || p->master_refcnt == 0) {
        fut_spinlock_release(&p->lock);
        return -ENOENT;
    }
    if (p->locked) {
        fut_spinlock_release(&p->lock);
        return -EIO;  /* Slave is locked */
    }
    p->slave_refcnt++;
    fut_spinlock_release(&p->lock);

    struct pty_priv *pp = fut_malloc(sizeof(*pp));
    if (!pp) { if (p->slave_refcnt > 0) p->slave_refcnt--; return -ENOMEM; }
    pp->tag  = PTY_SLAVE_TAG;
    pp->pair = p;

    int fd = chrdev_alloc_fd(&pts_fops, NULL, pp);
    if (fd < 0) {
        fut_free(pp);
        if (p->slave_refcnt > 0) p->slave_refcnt--;
        return fd;
    }

    /* Set file->path so /proc/self/fd/<n> readlink shows /dev/pts/<n> */
    extern struct fut_file *vfs_get_file(int fd);
    struct fut_file *file = vfs_get_file(fd);
    if (file) {
        char *path = fut_malloc(20);  /* "/dev/pts/" + up to 2 digits + NUL */
        if (path) {
            const char *pfx = "/dev/pts/";
            int pi = 0;
            while (pfx[pi]) { path[pi] = pfx[pi]; pi++; }
            if (index >= 10) path[pi++] = (char)('0' + index / 10);
            path[pi++] = (char)('0' + index % 10);
            path[pi] = '\0';
            file->path = path;
        }
    }

    /* Create /dev/pts/<n> ramfs entry so getdents64("/dev/pts/") lists it */
    if (file && file->path) {
        extern int fut_vfs_create_file(const char *path, uint32_t mode);
        fut_vfs_create_file(file->path, 0620);  /* crw--w---- like Linux pts */
    }

    /* Set controlling terminal on the opening task (Linux: MKDEV(136, n)) */
    fut_task_t *task = fut_task_current();
    if (task && task->tty_nr == 0)
        task->tty_nr = (136u << 8) | (uint32_t)index;

    return fd;
}

/* ============================================================
 *   Poll integration (called from sys_poll.c)
 * ============================================================ */

bool fut_pty_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out) {
    if (!file || !file->chr_private) return false;
    struct pty_priv *pp = (struct pty_priv *)file->chr_private;
    if (pp->tag != PTY_MASTER_TAG && pp->tag != PTY_SLAVE_TAG)
        return false;

    struct pty_pair *p = pp->pair;
    if (!p) return false;

    uint32_t ready = 0;
    fut_spinlock_acquire(&p->lock);

    if (pp->tag == PTY_MASTER_TAG) {
        /* Master: readable if s2m has data or slave closed */
        if (!ring_empty(&p->s2m) || p->slave_refcnt == 0)
            ready |= EPOLLIN | EPOLLRDNORM;
        /* Master: writable if m2s has space and slave open */
        if (ring_free(&p->m2s) > 0 && p->slave_refcnt > 0)
            ready |= EPOLLOUT | EPOLLWRNORM;
        /* HUP if slave closed */
        if (p->slave_refcnt == 0)
            ready |= EPOLLHUP;
    } else {
        /* Slave: readable if m2s has data or master closed */
        if (!ring_empty(&p->m2s) || p->master_refcnt == 0)
            ready |= EPOLLIN | EPOLLRDNORM;
        /* Slave: writable if s2m has space and master open */
        if (ring_free(&p->s2m) > 0 && p->master_refcnt > 0)
            ready |= EPOLLOUT | EPOLLWRNORM;
        /* HUP if master closed */
        if (p->master_refcnt == 0)
            ready |= EPOLLHUP;
    }

    fut_spinlock_release(&p->lock);

    *ready_out = ready & (requested | EPOLLHUP | EPOLLERR);
    return true;
}

void fut_pty_set_epoll_notify(struct fut_file *file, void *wq) {
    if (!file || !file->chr_private) return;
    struct pty_priv *pp = (struct pty_priv *)file->chr_private;
    if (!pp->pair) return;

    if (pp->tag == PTY_MASTER_TAG)
        pp->pair->master_epoll_wq = (fut_waitq_t *)wq;
    else if (pp->tag == PTY_SLAVE_TAG)
        pp->pair->slave_epoll_wq = (fut_waitq_t *)wq;
}

/* ============================================================
 *   Initialization
 * ============================================================ */

void pty_init(void) {
    fut_spinlock_init(&g_pty_alloc_lock);
    memset(g_ptys, 0, sizeof(g_ptys));

    /* Initialize master fops at runtime (ARM64 relocation safety) */
    ptmx_fops.open    = ptmx_open;
    ptmx_fops.read    = ptmx_read;
    ptmx_fops.write   = ptmx_write;
    ptmx_fops.ioctl   = ptmx_ioctl;
    ptmx_fops.release = ptmx_release;

    pts_fops.read    = pts_read;
    pts_fops.write   = pts_write;
    pts_fops.ioctl   = pts_ioctl;
    pts_fops.release = pts_release;

    /* Register /dev/ptmx: Linux uses (5, 2) */
    chrdev_register(5, 2, &ptmx_fops, "ptmx", NULL);
    devfs_create_chr("/dev/ptmx", 5, 2);

    /* Create /dev/pts/ directory */
    fut_vfs_mkdir("/dev/pts", 0755);

    fut_printf("[PTY] /dev/ptmx registered, /dev/pts/ created (%d max pairs)\n", PTY_MAX);
}
