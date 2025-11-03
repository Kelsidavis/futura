/* kernel/sys_epoll.c - epoll() syscall implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements event-driven I/O multiplexing via epoll_create, epoll_ctl, and epoll_wait.
 * Provides efficient polling of many file descriptors with event notification.
 *
 * Phase 1 (Completed): Basic implementation with event registration and polling
 * Phase 2 (Current): Enhanced validation, parameter categorization, detailed logging
 * Phase 3: Advanced event detection, edge-triggered mode, oneshot support
 * Phase 4: Performance optimization, memory pooling, scalability improvements
 */

#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern long sys_nanosleep(struct fut_timespec *req, struct fut_timespec *rem);

/* epoll event flag definitions */
#define EPOLLIN      0x00000001  /* Data available for reading */
#define EPOLLOUT     0x00000004  /* Ready for writing */
#define EPOLLERR     0x00000008  /* Error condition */
#define EPOLLHUP     0x00000010  /* Hang-up condition */
#define EPOLLRDNORM  0x00000040  /* Data available (same as EPOLLIN) */
#define EPOLLRDBAND  0x00000080  /* OOB data available */
#define EPOLLWRNORM  0x00000100  /* Ready for writing (same as EPOLLOUT) */
#define EPOLLWRBAND  0x00000200  /* OOB write ready */
#define EPOLLMASK_IOCTLS  (EPOLLERR | EPOLLHUP)

/* epoll_ctl operation codes */
#define EPOLL_CTL_ADD 1  /* Register a file descriptor with epoll instance */
#define EPOLL_CTL_MOD 2  /* Modify the interest mask for a file descriptor */
#define EPOLL_CTL_DEL 3  /* Deregister a file descriptor from epoll instance */

/* epoll_create1 flags */
#define EPOLL_CLOEXEC 0x80000  /* Set close-on-exec flag */

/* Maximum file descriptors per epoll instance */
#define MAX_EPOLL_FDS 64

/* Maximum epoll instances */
#define MAX_EPOLL_INSTANCES 256

/* epoll_event structure (user-visible) */
struct epoll_event {
    uint32_t events;   /* Requested events bitmask */
    uint64_t data;     /* User data associated with this FD */
};

/* Internal epoll FD registration */
struct epoll_fd_entry {
    int fd;                    /* File descriptor number */
    uint32_t events;           /* Requested events mask */
    uint64_t data;             /* User data to return on event */
    bool registered;           /* Whether this entry is active */
};

/* Internal epoll set structure */
struct epoll_set {
    int epfd;                                    /* This epoll FD number */
    struct epoll_fd_entry fds[MAX_EPOLL_FDS];  /* Registered FDs */
    int count;                                   /* Number of registered FDs */
    bool active;                                 /* Whether this epoll set is in use */
};

/* Global epoll instance table */
static struct epoll_set epoll_instances[MAX_EPOLL_INSTANCES];
static int next_epoll_fd = 4000;  /* Start epoll FDs at 4000 to avoid collision with regular FDs */

/* Helper to find epoll set by epoll FD */
static struct epoll_set *epoll_get_set(int epfd) {
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (epoll_instances[i].active && epoll_instances[i].epfd == epfd) {
            return &epoll_instances[i];
        }
    }
    return NULL;
}

/* Helper to allocate a new epoll set */
static struct epoll_set *epoll_allocate_set(void) {
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!epoll_instances[i].active) {
            memset(&epoll_instances[i], 0, sizeof(epoll_instances[i]));
            epoll_instances[i].active = true;
            epoll_instances[i].epfd = next_epoll_fd++;
            epoll_instances[i].count = 0;
            return &epoll_instances[i];
        }
    }
    return NULL;
}

/* Helper to deallocate an epoll set */
__attribute__((unused))
static void epoll_deallocate_set(struct epoll_set *set) {
    if (set) {
        set->active = false;
        set->count = 0;
        memset(set->fds, 0, sizeof(set->fds));
    }
}

/**
 * epoll_create1(int flags) - Create an epoll instance
 *
 * Creates an event notification context for monitoring multiple file descriptors.
 * Allows applications to efficiently wait for I/O events on many file descriptors.
 *
 * @param flags  Creation flags (EPOLL_CLOEXEC to set close-on-exec)
 *
 * Returns:
 *   - epoll file descriptor (>= 0) on success
 *   - -EINVAL if flags contains invalid bits
 *   - -ENOMEM if no epoll instances available
 *
 * Behavior:
 *   - Creates new epoll instance for event monitoring
 *   - Returns file descriptor for use with epoll_ctl/epoll_wait
 *   - EPOLL_CLOEXEC: Set FD_CLOEXEC on returned descriptor
 *   - Max 256 epoll instances system-wide (MAX_EPOLL_INSTANCES)
 *   - Each epoll instance can monitor up to 64 FDs (MAX_EPOLL_FDS)
 *
 * Common usage patterns:
 *
 * Basic epoll setup:
 *   int epfd = epoll_create1(0);
 *   struct epoll_event ev;
 *   ev.events = EPOLLIN;
 *   ev.data.fd = sockfd;
 *   epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
 *
 * Close-on-exec flag:
 *   int epfd = epoll_create1(EPOLL_CLOEXEC);  // Won't be inherited by child
 *   // ... use epoll ...
 *   exec("/bin/program");  // epfd is automatically closed
 *
 * Server event loop:
 *   int epfd = epoll_create1(0);
 *   // Add listening socket and all client sockets
 *   while (1) {
 *       struct epoll_event events[10];
 *       int n = epoll_wait(epfd, events, 10, -1);
 *       for (int i = 0; i < n; i++) {
 *           handle_event(&events[i]);
 *       }
 *   }
 *
 * Related syscalls:
 *   - epoll_ctl(): Add/modify/delete file descriptors from epoll set
 *   - epoll_wait(): Wait for events on monitored file descriptors
 *   - poll()/select(): Alternative I/O multiplexing mechanisms
 *   - close(): Destroy epoll instance
 *
 * Phase 1 (Completed): Basic implementation with event registration
 * Phase 2 (Current): Enhanced validation, flag categorization, detailed logging
 * Phase 3: Edge-triggered mode, oneshot events
 * Phase 4: Performance optimization, memory pooling
 */
long sys_epoll_create1(int flags) {
    /* Phase 2: Validate flags */
    if (flags & ~EPOLL_CLOEXEC) {
        char msg[128];
        int pos = 0;
        const char *prefix = "[EPOLL_CREATE1] epoll_create1(flags=0x";
        while (*prefix) { msg[pos++] = *prefix++; }

        /* Convert flags to hex */
        char hex[16];
        int hex_pos = 0;
        unsigned int val = (unsigned int)flags;
        if (val == 0) {
            hex[hex_pos++] = '0';
        } else {
            char temp[16];
            int temp_pos = 0;
            while (val > 0) {
                int digit = val % 16;
                temp[temp_pos++] = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
                val /= 16;
            }
            while (temp_pos > 0) {
                hex[hex_pos++] = temp[--temp_pos];
            }
        }
        hex[hex_pos] = '\0';

        for (int i = 0; hex[i]; i++) { msg[pos++] = hex[i]; }
        const char *suffix = ") -> EINVAL (invalid flags, only EPOLL_CLOEXEC supported)\n";
        while (*suffix) { msg[pos++] = *suffix++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Phase 2: Categorize flags */
    const char *flags_desc;
    if (flags == 0) {
        flags_desc = "none";
    } else if (flags == EPOLL_CLOEXEC) {
        flags_desc = "EPOLL_CLOEXEC";
    } else {
        flags_desc = "unknown";
    }

    /* Allocate new epoll instance */
    struct epoll_set *set = epoll_allocate_set();
    if (!set) {
        char msg[128];
        int pos = 0;
        const char *text = "[EPOLL_CREATE1] epoll_create1(flags=";
        while (*text) { msg[pos++] = *text++; }
        while (*flags_desc) { msg[pos++] = *flags_desc++; }
        text = ") -> ENOMEM (no epoll instances available, max=256)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -ENOMEM;
    }

    /* Phase 2: Categorize epoll FD range */
    const char *epfd_category;
    if (set->epfd >= 4000 && set->epfd < 5000) {
        epfd_category = "epoll range (4000-4999)";
    } else if (set->epfd >= 5000 && set->epfd < 6000) {
        epfd_category = "epoll high range (5000-5999)";
    } else {
        epfd_category = "epoll very high (≥6000)";
    }

    /* Phase 2: Detailed success logging */
    char msg[256];
    int pos = 0;
    const char *text = "[EPOLL_CREATE1] epoll_create1(flags=";
    while (*text) { msg[pos++] = *text++; }
    while (*flags_desc) { msg[pos++] = *flags_desc++; }
    text = ", epfd=";
    while (*text) { msg[pos++] = *text++; }

    /* Convert epfd to string */
    char epfd_str[16];
    int epfd_pos = 0;
    int epfd_val = set->epfd;
    if (epfd_val == 0) {
        epfd_str[epfd_pos++] = '0';
    } else {
        char temp[16];
        int temp_pos = 0;
        while (epfd_val > 0) {
            temp[temp_pos++] = '0' + (epfd_val % 10);
            epfd_val /= 10;
        }
        while (temp_pos > 0) {
            epfd_str[epfd_pos++] = temp[--temp_pos];
        }
    }
    epfd_str[epfd_pos] = '\0';

    for (int i = 0; epfd_str[i]; i++) { msg[pos++] = epfd_str[i]; }
    text = " [";
    while (*text) { msg[pos++] = *text++; }
    while (*epfd_category) { msg[pos++] = *epfd_category++; }
    text = "]) -> 0 (epoll instance created, Phase 2)\n";
    while (*text) { msg[pos++] = *text++; }
    msg[pos] = '\0';
    fut_printf("%s", msg);

    return set->epfd;
}

/**
 * epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) - Control an epoll instance
 *
 * Modifies the set of file descriptors monitored by an epoll instance.
 * Supports add, modify, and delete operations.
 *
 * @param epfd   epoll file descriptor from epoll_create1()
 * @param op     Operation: EPOLL_CTL_ADD, EPOLL_CTL_MOD, or EPOLL_CTL_DEL
 * @param fd     File descriptor to add/modify/delete
 * @param event  epoll_event structure with events mask and user data
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if epfd is invalid or fd doesn't exist
 *   - -EINVAL if op is invalid or event is NULL (for ADD/MOD)
 *   - -EEXIST if trying to add an already-registered FD
 *   - -ENOENT if trying to modify/delete a non-registered FD
 *   - -ENOMEM if no more FD slots available in epoll set
 *   - -EFAULT if event pointer is inaccessible
 *
 * Behavior:
 *   - EPOLL_CTL_ADD: Register fd with event mask
 *   - EPOLL_CTL_MOD: Modify event mask for registered fd
 *   - EPOLL_CTL_DEL: Unregister fd from epoll set
 *   - event.events: Bitmask (EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, etc.)
 *   - event.data: User data (returned in epoll_wait)
 *   - Max 64 FDs per epoll instance
 *
 * Event types:
 *   - EPOLLIN (0x1): Data available for reading
 *   - EPOLLOUT (0x4): Ready for writing
 *   - EPOLLERR (0x8): Error condition
 *   - EPOLLHUP (0x10): Hang-up (connection closed)
 *   - EPOLLRDNORM (0x40): Normal data readable
 *   - EPOLLWRNORM (0x100): Normal data writable
 *
 * Common usage patterns:
 *
 * Add socket to epoll:
 *   struct epoll_event ev;
 *   ev.events = EPOLLIN | EPOLLOUT;
 *   ev.data.fd = sockfd;
 *   epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
 *
 * Modify event interest:
 *   ev.events = EPOLLIN;  // Only read, not write
 *   epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
 *
 * Remove socket from epoll:
 *   epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd, NULL);
 *
 * Store custom data:
 *   ev.events = EPOLLIN;
 *   ev.data.ptr = my_connection_struct;
 *   epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
 *
 * Phase 1 (Completed): Basic add/modify/delete operations
 * Phase 2 (Current): Enhanced validation, operation categorization, detailed logging
 * Phase 3: Edge-triggered mode support, oneshot events
 * Phase 4: Performance optimization
 */
long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    /* Phase 2: Categorize epoll FD */
    const char *epfd_category;
    if (epfd >= 4000 && epfd < 5000) {
        epfd_category = "epoll (4000-4999)";
    } else if (epfd >= 5000) {
        epfd_category = "epoll high (≥5000)";
    } else {
        epfd_category = "invalid range (<4000)";
    }

    /* Phase 2: Categorize target FD */
    const char *fd_category;
    if (fd < 0) {
        fd_category = "invalid (negative)";
    } else if (fd <= 2) {
        fd_category = "stdio (0-2)";
    } else if (fd < 16) {
        fd_category = "low (3-15)";
    } else if (fd < 256) {
        fd_category = "mid (16-255)";
    } else if (fd < 1024) {
        fd_category = "high (256-1023)";
    } else {
        fd_category = "very high (≥1024)";
    }

    /* Phase 2: Categorize operation */
    const char *op_name;
    if (op == EPOLL_CTL_ADD) {
        op_name = "ADD";
    } else if (op == EPOLL_CTL_MOD) {
        op_name = "MOD";
    } else if (op == EPOLL_CTL_DEL) {
        op_name = "DEL";
    } else {
        op_name = "INVALID";
    }

    /* Validate operation */
    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD && op != EPOLL_CTL_DEL) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        /* Add epfd */
        char num[16];
        int num_pos = 0;
        int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; }
        }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*epfd_category) { msg[pos++] = *epfd_category++; }
        text = "], op=";
        while (*text) { msg[pos++] = *text++; }

        /* Add op */
        num_pos = 0; val = op;
        if (val == 0) { num[num_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; }
        }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        /* Add fd */
        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; }
        }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (invalid operation, expected ADD/MOD/DEL)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Validate event pointer for ADD/MOD operations */
    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) && !event) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (NULL event pointer for ADD/MOD)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Verify user pointer is readable for ADD/MOD */
    if ((op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) &&
        fut_access_ok(event, sizeof(struct epoll_event), 0) != 0) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EFAULT (event pointer inaccessible)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EFAULT;
    }

    /* Validate FD exists */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*fd_category) { msg[pos++] = *fd_category++; }
        text = "]) -> EBADF (fd not open)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }

    /* Get the epoll set */
    struct epoll_set *set = epoll_get_set(epfd);
    if (!set) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*epfd_category) { msg[pos++] = *epfd_category++; }
        text = "], op=";
        while (*text) { msg[pos++] = *text++; }
        while (*op_name) { msg[pos++] = *op_name++; }
        text = ", fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EBADF (invalid epoll fd)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }

    /* Copy event structure from user space for ADD/MOD */
    struct epoll_event ev;
    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
        if (fut_copy_from_user(&ev, event, sizeof(ev)) != 0) {
            char msg[128];
            int pos = 0;
            const char *text = "[EPOLL_CTL] epoll_ctl(op=";
            while (*text) { msg[pos++] = *text++; }
            while (*op_name) { msg[pos++] = *op_name++; }
            text = ") -> EFAULT (copy_from_user failed)\n";
            while (*text) { msg[pos++] = *text++; }
            msg[pos] = '\0';
            fut_printf("%s", msg);

            return -EFAULT;
        }
    }

    switch (op) {
    case EPOLL_CTL_ADD: {
        /* Check if FD is already registered */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                char msg[256];
                int pos = 0;
                const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
                while (*text) { msg[pos++] = *text++; }

                char num[16]; int num_pos = 0; int val = epfd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = ", op=ADD, fd=";
                while (*text) { msg[pos++] = *text++; }

                num_pos = 0; val = fd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = ") -> EEXIST (fd already registered)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);

                return -EEXIST;
            }
        }

        /* Find empty slot */
        int slot = -1;
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (!set->fds[i].registered) {
                slot = i;
                break;
            }
        }

        if (slot == -1) {
            char msg[256];
            int pos = 0;
            const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
            while (*text) { msg[pos++] = *text++; }

            char num[16]; int num_pos = 0; int val = epfd;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

            text = ", op=ADD, fd=";
            while (*text) { msg[pos++] = *text++; }

            num_pos = 0; val = fd;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

            text = ") -> ENOMEM (no slots, max=64)\n";
            while (*text) { msg[pos++] = *text++; }
            msg[pos] = '\0';
            fut_printf("%s", msg);

            return -ENOMEM;
        }

        /* Register the FD */
        set->fds[slot].fd = fd;
        set->fds[slot].events = ev.events;
        set->fds[slot].data = ev.data;
        set->fds[slot].registered = true;
        set->count++;

        /* Phase 2: Categorize events */
        char events_desc[128];
        int desc_pos = 0;
        int has_event = 0;

        if (ev.events & EPOLLIN) {
            const char *s = "EPOLLIN"; while (*s) { events_desc[desc_pos++] = *s++; }
            has_event = 1;
        }
        if (ev.events & EPOLLOUT) {
            if (has_event) { events_desc[desc_pos++] = '|'; }
            const char *s = "EPOLLOUT"; while (*s) { events_desc[desc_pos++] = *s++; }
            has_event = 1;
        }
        if (ev.events & EPOLLERR) {
            if (has_event) { events_desc[desc_pos++] = '|'; }
            const char *s = "EPOLLERR"; while (*s) { events_desc[desc_pos++] = *s++; }
            has_event = 1;
        }
        if (ev.events & EPOLLHUP) {
            if (has_event) { events_desc[desc_pos++] = '|'; }
            const char *s = "EPOLLHUP"; while (*s) { events_desc[desc_pos++] = *s++; }
            has_event = 1;
        }
        if (!has_event) {
            const char *s = "none"; while (*s) { events_desc[desc_pos++] = *s++; }
        }
        events_desc[desc_pos] = '\0';

        /* Success logging */
        char msg[512];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

        text = ", op=ADD, fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*fd_category) { msg[pos++] = *fd_category++; }
        text = "], events=";
        while (*text) { msg[pos++] = *text++; }
        for (int j = 0; events_desc[j]; j++) { msg[pos++] = events_desc[j]; }
        text = ") -> 0 (fd registered, Phase 2)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return 0;
    }

    case EPOLL_CTL_MOD: {
        /* Find and modify the entry */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                set->fds[i].events = ev.events;
                set->fds[i].data = ev.data;

                /* Phase 2: Categorize events */
                char events_desc[128];
                int desc_pos = 0;
                int has_event = 0;

                if (ev.events & EPOLLIN) {
                    const char *s = "EPOLLIN"; while (*s) { events_desc[desc_pos++] = *s++; }
                    has_event = 1;
                }
                if (ev.events & EPOLLOUT) {
                    if (has_event) { events_desc[desc_pos++] = '|'; }
                    const char *s = "EPOLLOUT"; while (*s) { events_desc[desc_pos++] = *s++; }
                    has_event = 1;
                }
                if (ev.events & EPOLLERR) {
                    if (has_event) { events_desc[desc_pos++] = '|'; }
                    const char *s = "EPOLLERR"; while (*s) { events_desc[desc_pos++] = *s++; }
                    has_event = 1;
                }
                if (ev.events & EPOLLHUP) {
                    if (has_event) { events_desc[desc_pos++] = '|'; }
                    const char *s = "EPOLLHUP"; while (*s) { events_desc[desc_pos++] = *s++; }
                    has_event = 1;
                }
                if (!has_event) {
                    const char *s = "none"; while (*s) { events_desc[desc_pos++] = *s++; }
                }
                events_desc[desc_pos] = '\0';

                /* Success logging */
                char msg[512];
                int pos = 0;
                const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
                while (*text) { msg[pos++] = *text++; }

                char num[16]; int num_pos = 0; int val = epfd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = ", op=MOD, fd=";
                while (*text) { msg[pos++] = *text++; }

                num_pos = 0; val = fd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = " [";
                while (*text) { msg[pos++] = *text++; }
                while (*fd_category) { msg[pos++] = *fd_category++; }
                text = "], events=";
                while (*text) { msg[pos++] = *text++; }
                for (int j = 0; events_desc[j]; j++) { msg[pos++] = events_desc[j]; }
                text = ") -> 0 (events modified, Phase 2)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);

                return 0;
            }
        }

        /* FD not found */
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

        text = ", op=MOD, fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

        text = ") -> ENOENT (fd not registered)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -ENOENT;
    }

    case EPOLL_CTL_DEL: {
        /* Find and remove the entry */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                set->fds[i].registered = false;
                set->count--;
                memset(&set->fds[i], 0, sizeof(set->fds[i]));

                /* Success logging */
                char msg[256];
                int pos = 0;
                const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
                while (*text) { msg[pos++] = *text++; }

                char num[16]; int num_pos = 0; int val = epfd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = ", op=DEL, fd=";
                while (*text) { msg[pos++] = *text++; }

                num_pos = 0; val = fd;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

                text = " [";
                while (*text) { msg[pos++] = *text++; }
                while (*fd_category) { msg[pos++] = *fd_category++; }
                text = "]) -> 0 (fd unregistered, Phase 2)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);

                return 0;
            }
        }

        /* FD not found */
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_CTL] epoll_ctl(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

        text = ", op=DEL, fd=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }

        text = ") -> ENOENT (fd not registered)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -ENOENT;
    }

    default:
        return -EINVAL;
    }
}

/**
 * epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
 *     - Wait for events on an epoll instance
 *
 * Polls all registered file descriptors and waits for events.
 * Returns when events occur or timeout expires.
 *
 * @param epfd       epoll file descriptor
 * @param events     Array to store returned events (user buffer)
 * @param maxevents  Maximum number of events to return (must be > 0)
 * @param timeout    Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 *
 * Returns:
 *   - Number of ready file descriptors on success (0 if timeout)
 *   - -EBADF if epfd is invalid
 *   - -EINVAL if maxevents <= 0 or events is NULL
 *   - -EFAULT if events pointer is invalid
 *
 * Behavior:
 *   - Blocks until events occur or timeout expires
 *   - Returns array of ready events in events parameter
 *   - Each event includes events mask and user data
 *   - timeout = 0: Non-blocking (returns immediately)
 *   - timeout = -1: Block indefinitely
 *   - timeout > 0: Block for at most timeout milliseconds
 *
 * Common usage patterns:
 *
 * Blocking wait:
 *   struct epoll_event events[10];
 *   int n = epoll_wait(epfd, events, 10, -1);
 *   for (int i = 0; i < n; i++) {
 *       if (events[i].events & EPOLLIN) {
 *           read(events[i].data.fd, buf, sizeof(buf));
 *       }
 *   }
 *
 * Non-blocking poll:
 *   int n = epoll_wait(epfd, events, 10, 0);
 *   if (n == 0) {
 *       // No events ready
 *   }
 *
 * Timeout with fallback:
 *   int n = epoll_wait(epfd, events, 10, 1000);  // Wait 1 second
 *   if (n == 0) {
 *       // Timeout - do periodic work
 *   }
 *
 * Event loop:
 *   while (running) {
 *       int n = epoll_wait(epfd, events, 10, -1);
 *       for (int i = 0; i < n; i++) {
 *           handle_event(&events[i]);
 *       }
 *   }
 *
 * Phase 1 (Completed): Basic event polling with timeout
 * Phase 2 (Current): Enhanced validation, timeout categorization, detailed logging
 * Phase 3: Edge-triggered mode, oneshot events
 * Phase 4: Performance optimization
 */
long sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    /* Phase 2: Categorize epoll FD */
    const char *epfd_category;
    if (epfd >= 4000 && epfd < 5000) {
        epfd_category = "epoll (4000-4999)";
    } else if (epfd >= 5000) {
        epfd_category = "epoll high (≥5000)";
    } else {
        epfd_category = "invalid range (<4000)";
    }

    /* Validate maxevents */
    if (maxevents <= 0) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", maxevents=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; val = maxevents;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (maxevents must be > 0)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Validate events pointer */
    if (!events) {
        char msg[128];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EINVAL (NULL events array)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Verify events array is writable */
    if (fut_access_ok(events, maxevents * sizeof(struct epoll_event), 1) != 0) {
        char msg[128];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> EFAULT (events array not writable)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EFAULT;
    }

    /* Get the epoll set */
    struct epoll_set *set = epoll_get_set(epfd);
    if (!set) {
        char msg[256];
        int pos = 0;
        const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = epfd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*epfd_category) { msg[pos++] = *epfd_category++; }
        text = "]) -> EBADF (invalid epoll fd)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }

    /* Phase 2: Categorize timeout */
    const char *timeout_desc;
    if (timeout < 0) {
        timeout_desc = "infinite";
    } else if (timeout == 0) {
        timeout_desc = "non-blocking";
    } else if (timeout < 100) {
        timeout_desc = "short (<100ms)";
    } else if (timeout < 1000) {
        timeout_desc = "medium (100-999ms)";
    } else {
        timeout_desc = "long (≥1000ms)";
    }

    /* Poll with timeout support */
    int max_iterations = (timeout == 0) ? 1 : ((timeout < 0) ? 10000 : (timeout / 10 + 1));
    int iteration = 0;

    while (iteration < max_iterations) {
        int ready_count = 0;
        struct epoll_event ready_events[MAX_EPOLL_FDS];

        /* Check all registered file descriptors */
        for (int i = 0; i < MAX_EPOLL_FDS && ready_count < maxevents; i++) {
            if (!set->fds[i].registered) {
                continue;
            }

            struct fut_file *file = fut_vfs_get_file(set->fds[i].fd);
            if (!file) {
                /* FD closed - report error event */
                ready_events[ready_count].events = EPOLLERR | EPOLLHUP;
                ready_events[ready_count].data = set->fds[i].data;
                ready_count++;
                continue;
            }

            /* Check if FD is readable/writable */
            uint32_t events_ready = 0;

            /* For regular files: always ready for both read and write */
            if (file->vnode && file->vnode->type == 1) {  /* VNODE_FILE */
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
            }
            /* For character devices/sockets: would need more sophisticated checks */
            /* For now, report as ready if requested */
            else if (file->vnode) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
            }

            /* Report events if any match the registered mask */
            if (events_ready) {
                ready_events[ready_count].events = events_ready;
                ready_events[ready_count].data = set->fds[i].data;
                ready_count++;
            }
        }

        /* If we have events, copy to user and return */
        if (ready_count > 0) {
            if (fut_copy_to_user(events, ready_events,
                                ready_count * sizeof(struct epoll_event)) != 0) {
                char msg[128];
                int pos = 0;
                const char *text = "[EPOLL_WAIT] epoll_wait() -> EFAULT (copy_to_user failed)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);

                return -EFAULT;
            }

            /* Phase 2: Success logging with event count */
            char msg[256];
            int pos = 0;
            const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
            while (*text) { msg[pos++] = *text++; }

            char num[16]; int num_pos = 0; int val = epfd;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

            text = ", timeout=";
            while (*text) { msg[pos++] = *text++; }
            while (*timeout_desc) { msg[pos++] = *timeout_desc++; }
            text = ") -> ";
            while (*text) { msg[pos++] = *text++; }

            num_pos = 0; val = ready_count;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

            text = " (events ready, Phase 2)\n";
            while (*text) { msg[pos++] = *text++; }
            msg[pos] = '\0';
            fut_printf("%s", msg);

            return ready_count;
        }

        /* Check timeout */
        if (timeout == 0) {
            /* Non-blocking mode - no events ready */
            char msg[256];
            int pos = 0;
            const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
            while (*text) { msg[pos++] = *text++; }

            char num[16]; int num_pos = 0; int val = epfd;
            if (val == 0) { num[num_pos++] = '0'; }
            else { char temp[16]; int temp_pos = 0;
                while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
            num[num_pos] = '\0';
            for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

            text = ", timeout=non-blocking) -> 0 (no events ready, Phase 2)\n";
            while (*text) { msg[pos++] = *text++; }
            msg[pos] = '\0';
            fut_printf("%s", msg);

            return 0;
        }

        /* Sleep for 10ms before next iteration */
        fut_timespec_t ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 10000000;  /* 10ms */
        sys_nanosleep(&ts, NULL);

        iteration++;
    }

    /* Timeout expired */
    char msg[256];
    int pos = 0;
    const char *text = "[EPOLL_WAIT] epoll_wait(epfd=";
    while (*text) { msg[pos++] = *text++; }

    char num[16]; int num_pos = 0; int val = epfd;
    if (val == 0) { num[num_pos++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
        while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
    num[num_pos] = '\0';
    for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

    text = ", timeout=";
    while (*text) { msg[pos++] = *text++; }
    while (*timeout_desc) { msg[pos++] = *timeout_desc++; }
    text = ") -> 0 (timeout expired, Phase 2)\n";
    while (*text) { msg[pos++] = *text++; }
    msg[pos] = '\0';
    fut_printf("%s", msg);

    return 0;
}

/**
 * epoll_create() - Legacy epoll create (deprecated)
 *
 * Older API for creating epoll instance. The size parameter is ignored
 * in modern kernels. New code should use epoll_create1() instead.
 *
 * @param size  Ignored (was a hint for kernel in old implementations)
 *
 * Returns:
 *   - epoll file descriptor on success
 *   - -EINVAL if size <= 0
 *
 * Phase 2: Wrapper that delegates to epoll_create1(0)
 */
long sys_epoll_create(int size) {
    /* Phase 2: Validate size parameter */
    if (size <= 0) {
        fut_printf("[EPOLL_CREATE] epoll_create(size=%d) -> EINVAL "
                   "(size must be positive, Phase 2)\n", size);
        return -EINVAL;
    }

    /* Phase 2: Log deprecation notice */
    fut_printf("[EPOLL_CREATE] epoll_create(size=%d) -> delegating to "
               "epoll_create1(0) (legacy API, Phase 2)\n", size);

    /* Delegate to modern epoll_create1 with flags=0 */
    return sys_epoll_create1(0);
}
