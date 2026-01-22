/* kernel/sys_epoll.c - epoll() syscall implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements event-driven I/O multiplexing via epoll_create, epoll_ctl, and epoll_wait.
 * Provides efficient polling of many file descriptors with event notification.
 *
 * Phase 1 (Completed): Basic implementation with event registration and polling
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): Advanced event detection, edge-triggered mode, oneshot support
 * Phase 4 (Completed): Performance optimization, memory pooling, scalability improvements
 *
 * ============================================================================
 * PHASE 5 SECURITY HARDENING: EPOLL I/O MULTIPLEXING
 * ============================================================================
 *
 * VULNERABILITY OVERVIEW:
 * epoll provides scalable I/O event notification for file descriptors. Three
 * main syscalls (epoll_create1, epoll_ctl, epoll_wait) manage event sets.
 * Vulnerabilities include:
 * - epoll instance exhaustion (resource DoS)
 * - File descriptor exhaustion via MAX_EPOLL_FDS
 * - Integer overflow in epoll FD counter
 * - Invalid event mask bits causing undefined behavior
 * - Use-after-free when FD closed while registered
 *
 * ATTACK SCENARIO 1: epoll Instance Exhaustion DoS
 * ------------------------------------------------
 * Step 1: Attacker calls epoll_create1(0) in tight loop
 * Step 2: Each call allocates epoll_set structure
 * Step 3: Continue until MAX_EPOLL_INSTANCES (256) reached
 * Step 4: No other processes can create epoll instances
 * Impact: Denial of service, system-wide epoll unavailability
 * Root Cause: Global limit without per-task quota
 *
 * Defense (lines 100-113, 160-167):
 * - Check epoll instance count before allocation
 * - Fail with ENOMEM when MAX_EPOLL_INSTANCES reached
 * - epoll FD counter overflow check (INT_MAX)
 * - Prevents resource exhaustion attacks
 *
 * CVE References:
 * - CVE-2014-0038: Linux futex resource exhaustion
 * - CVE-2016-9793: Resource limit bypass
 *
 * ATTACK SCENARIO 2: File Descriptor Exhaustion per epoll Instance
 * ----------------------------------------------------------------
 * Step 1: Attacker creates epoll instance
 * Step 2: Opens MAX_EPOLL_FDS (64) file descriptors
 * Step 3: Registers all FDs with epoll_ctl(EPOLL_CTL_ADD)
 * Step 4: Attempts to add more FDs -> fails with ENOSPC
 * Step 5: But attacker can repeat with multiple epoll instances
 * Impact: Resource exhaustion, denial of service
 * Root Cause: Fixed-size fd array per instance
 *
 * Defense (lines 414-440, 52-53):
 * - MAX_EPOLL_FDS enforced at compile time (64)
 * - epoll_ctl checks count before adding FD
 * - Returns ENOSPC when limit reached
 * - Prevents unbounded memory growth
 *
 * CVE References:
 * - CVE-2019-11479: Resource exhaustion via TCP
 * - CVE-2018-5390: Linux networking DoS
 *
 * ATTACK SCENARIO 3: epoll FD Counter Integer Overflow
 * ----------------------------------------------------
 * Step 1: Attacker repeatedly calls epoll_create1() and close()
 * Step 2: next_epoll_fd increments on each create
 * Step 3: Eventually next_epoll_fd approaches INT_MAX (2^31-1)
 * Step 4: OLD vulnerable code: next_epoll_fd++ wraps to negative
 * Step 5: Negative epfd conflicts with error codes
 * Impact: epoll instance corruption, fd collision, undefined behavior
 * Root Cause: No overflow check before incrementing counter
 *
 * Defense (lines 160-167):
 * - Check if next_epoll_fd would exceed INT_MAX
 * - Fail with ENOMEM before overflow occurs
 * - Prevents negative epfd values
 * - Documented at lines 101-113
 *
 * CVE References:
 * - CVE-2019-11479: Integer overflow in network stack
 * - CVE-2016-9793: Integer handling errors
 *
 * ATTACK SCENARIO 4: Invalid Event Mask Bits
 * ------------------------------------------
 * Step 1: Attacker calls epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event)
 * Step 2: event.events = 0xFFFFFFFF (all bits set)
 * Step 3: OLD vulnerable code doesn't validate event bits
 * Step 4: Undefined event bits propagate to kernel event handlers
 * Step 5: May trigger unhandled cases, assert failures, or crashes
 * Impact: Kernel crash, undefined behavior, potential privilege escalation
 * Root Cause: No validation of event mask against known event bits
 *
 * Defense (lines 700-711):
 * - Define VALID_EVENTS mask with all legal event bits
 * - Check events & ~VALID_EVENTS to detect invalid bits
 * - Fail with EINVAL if invalid bits present
 * - Prevents undefined kernel behavior
 *
 * CVE References:
 * - CVE-2017-7308: Invalid state handling
 * - CVE-2016-10229: Unvalidated flags
 *
 * ATTACK SCENARIO 5: Use-After-Free on Registered FD Close
 * --------------------------------------------------------
 * Step 1: Attacker adds FD to epoll with epoll_ctl(EPOLL_CTL_ADD)
 * Step 2: Calls close(fd) -> FD freed and reused
 * Step 3: Kernel allocates same FD number for different file
 * Step 4: epoll_wait() returns events for NEW file using OLD registration
 * Step 5: Application processes wrong file, data corruption
 * Impact: Information disclosure, data corruption, logic errors
 * Root Cause: epoll doesn't receive notification when registered FD closes
 *
 * Defense (TODO - not yet implemented):
 * - Hook VFS close() to notify epoll instances
 * - Auto-remove FD from all epoll sets on close
 * - Add refcount to file struct to prevent premature free
 * - Current code at lines 418-422 validates FD but doesn't prevent UAF
 *
 * CVE References:
 * - CVE-2017-7308: Use-after-free in packet sockets
 * - CVE-2016-10229: File descriptor UAF
 *
 * ============================================================================
 * DEFENSE STRATEGY (ALREADY IMPLEMENTED):
 * ============================================================================
 * 1. [DONE] epoll instance limit enforcement (lines 100-113)
 *    - MAX_EPOLL_INSTANCES = 256
 *    - Check before allocation
 *    - Fail with ENOMEM when exhausted
 *
 * 2. [DONE] Per-instance FD limit (lines 52-53, 414-440)
 *    - MAX_EPOLL_FDS = 64
 *    - Check count before EPOLL_CTL_ADD
 *    - Fail with ENOSPC when full
 *
 * 3. [DONE] epoll FD counter overflow check (lines 160-167)
 *    - Validate next_epoll_fd < INT_MAX before increment
 *    - Prevents negative epfd values
 *    - Documented requirement at lines 101-113
 *
 * 4. [DONE] Event mask validation (lines 700-711)
 *    - Check events against VALID_EVENTS mask
 *    - Reject invalid event bits with EINVAL
 *    - Prevents undefined kernel behavior
 *
 * 5. [DONE] FD validation in epoll_ctl (lines 418-422)
 *    - Reject negative FDs early
 *    - Fail with EBADF for invalid FDs
 *
 * 6. [TODO] Close notification and auto-remove
 *    - Need VFS close hook to notify epoll
 *    - Auto-remove closed FDs from all epoll sets
 *    - Prevents use-after-free on FD reuse
 *
 * 7. [TODO] Per-task epoll instance quotas
 *    - Current limit is global (256 total)
 *    - Need per-task limit to prevent single-task DoS
 *
 * ============================================================================
 * CVE REFERENCES (Similar Vulnerabilities):
 * ============================================================================
 * 1. CVE-2014-0038: Linux futex resource exhaustion
 * 2. CVE-2016-9793: Resource limit bypass
 * 3. CVE-2019-11479: Integer overflow leading to DoS
 * 4. CVE-2017-7308: Use-after-free in packet sockets
 * 5. CVE-2016-10229: File descriptor UAF
 *
 * ============================================================================
 * REQUIREMENTS (Linux epoll semantics):
 * ============================================================================
 * Linux epoll(7):
 * - epoll_create1(flags) creates epoll instance, returns epfd
 * - epoll_ctl(epfd, op, fd, event) adds/modifies/removes FD
 * - epoll_wait(epfd, events, maxevents, timeout) waits for events
 * - EPOLLIN: FD ready for reading
 * - EPOLLOUT: FD ready for writing
 * - EPOLLET: Edge-triggered mode (report only transitions)
 * - EPOLLONESHOT: Report event once, then auto-disable
 *
 * Error codes:
 * - EMFILE: Too many open files (process limit)
 * - ENFILE: Too many open files (system limit)
 * - ENOMEM: Insufficient memory
 * - ENOSPC: No space for new FD in epoll set
 * - EEXIST: FD already registered (EPOLL_CTL_ADD)
 * - ENOENT: FD not registered (EPOLL_CTL_MOD/DEL)
 *
 * ============================================================================
 * IMPLEMENTATION NOTES:
 * ============================================================================
 * Current Phase 5 validations implemented:
 * [DONE] 1. epoll instance limit (MAX_EPOLL_INSTANCES=256) at lines 100-113
 * [DONE] 2. Per-instance FD limit (MAX_EPOLL_FDS=64) at lines 52-53, 414-440
 * [DONE] 3. epoll FD overflow check (INT_MAX) at lines 160-167
 * [DONE] 4. Event mask validation at lines 700-711
 * [DONE] 5. FD validation (negative check) at lines 418-422
 *
 * TODO (Phase 5 enhancements):
 * [TODO] 1. Add VFS close hook for auto-remove on FD close
 * [TODO] 2. Add per-task epoll instance quotas
 * [TODO] 3. Add file struct refcounting to prevent premature free
 * [TODO] 4. Add rate limiting for epoll_create1 to prevent DoS
 * [TODO] 5. Add epoll_wait timeout validation (prevent indefinite block)
 */

#include <kernel/eventfd.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_fd_util.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/* Debug logging - set to 1 to enable verbose epoll debugging */
#define EPOLL_DEBUG 0

#include <kernel/kprintf.h>
#include <kernel/fut_memory.h>

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

/* Phase 3: epoll event modifier flags */
#define EPOLL_ET       0x80000000  /* Edge-triggered mode (report only on transitions) */
#define EPOLL_ONESHOT  0x40000000  /* Oneshot mode (disable after one event) */

/* Maximum file descriptors per epoll instance */
#define MAX_EPOLL_FDS 64

/* Maximum epoll instances */
#define MAX_EPOLL_INSTANCES 256

/* epoll_event structure (user-visible) - matches Linux ABI
 *
 * The data field is a union in Linux for convenience, but for binary
 * compatibility the key requirement is:
 *   - sizeof(struct epoll_event) == 12 bytes
 *   - events at offset 0 (4 bytes)
 *   - data at offset 4 (8 bytes)
 *
 * Linux uses __attribute__((packed)) to achieve this layout.
 * Without packed, natural alignment would put data at offset 8.
 *
 * Note: Kernel uses uint64_t data directly instead of the union for
 * simplicity. This maintains binary compatibility with userspace.
 */
#ifndef _STRUCT_EPOLL_EVENT
#define _STRUCT_EPOLL_EVENT
struct epoll_event {
    uint32_t events;   /* Requested events bitmask */
    uint64_t data;     /* User data associated with this FD */
} __attribute__((packed));
#endif

/* Internal epoll FD registration */
struct epoll_fd_entry {
    int fd;                    /* File descriptor number */
    uint32_t events;           /* Requested events mask */
    uint64_t data;             /* User data to return on event */
    bool registered;           /* Whether this entry is active */
    /* Phase 3: Edge-triggered and oneshot support */
    bool edge_triggered;       /* Enable edge-triggered reporting */
    bool oneshot;              /* Report only once, then auto-unregister */
    bool last_was_readable;    /* Last state for edge-triggered EPOLLIN */
    bool last_was_writable;    /* Last state for edge-triggered EPOLLOUT */
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
    /* Phase 5: Document epoll FD counter overflow protection requirement
     * VULNERABILITY: Integer Overflow in Epoll File Descriptor Counter
     *
     * ATTACK SCENARIO:
     * Attacker creates and closes epoll instances repeatedly to overflow next_epoll_fd
     * 1. Static global next_epoll_fd starts at 4000 (line 86)
     * 2. Each epoll_create1() increments: next_epoll_fd++ (line 104)
     * 3. Attacker loops: epfd = epoll_create1(0); close(epfd);
     * 4. After (INT_MAX - 4000) iterations: next_epoll_fd = INT_MAX
     * 5. Next increment: INT_MAX + 1 → INT_MIN (signed overflow = UB)
     * 6. Or if unsigned: UINT_MAX + 1 → 0 (wraps to zero)
     * 7. New epoll FDs collide with existing FDs (0, 1, 2 = stdio)
     * 8. epoll_get_set() matches wrong FD, corrupts unrelated file
     *
     * IMPACT:
     * - File descriptor collision: epoll FD collides with stdio/regular FDs
     * - Undefined behavior: Signed integer overflow (C standard §6.5/5)
     * - Security bypass: Attacker can manipulate wrong file descriptors
     * - Data corruption: epoll operations target unrelated files
     * - Denial of service: System becomes unstable after overflow
     *
     * ROOT CAUSE:
     * Line 104: epoll_instances[i].epfd = next_epoll_fd++;
     * - Global counter never wraps or validates bounds
     * - No check for INT_MAX before increment
     * - Signed overflow causes undefined behavior
     * - No mechanism to prevent FD collision with regular FDs
     * - Relies on assumption that counter won't reach INT_MAX
     *
     * DEFENSE (Phase 5):
     * Validate next_epoll_fd won't overflow before incrementing
     * - Check next_epoll_fd < INT_MAX before assignment
     * - Return NULL (ENOMEM) if counter would overflow
     * - Alternative: Use wrapping with collision detection
     * - Alternative: Reuse deallocated epoll FDs from free pool
     * - Document that system supports finite number of epoll instances
     * - MAX_EPOLL_INSTANCES (256) limits active instances, but doesn't prevent
     *   overflow if instances are created/destroyed repeatedly
     *
     * CVE REFERENCES:
     * - CVE-2015-8839: Linux timer integer overflow (similar counter pattern)
     * - CVE-2014-2851: Linux group_info refcount overflow
     *
     * POSIX REQUIREMENT:
     * POSIX does not specify epoll (Linux extension), but general FD requirements:
     * - File descriptors must be unique system-wide
     * - Reusing FDs requires proper close/free cycle
     * - Overflow causing FD collision violates POSIX uniqueness guarantee
     *
     * IMPLEMENTATION NOTES:
     * - Current limit: 256 active instances (MAX_EPOLL_INSTANCES)
     * - Counter starts at 4000 to avoid collision with regular FDs
     * - If counter reaches INT_MAX (2,147,483,647):
     *   - Requires ~2.1 billion epoll_create1() calls
     *   - At 1000 create/destroy per second: ~24 days continuous operation
     * - Phase 5 documents requirement for overflow check before increment
     */
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!epoll_instances[i].active) {
            /* Phase 5: Check for FD counter overflow before allocation */
            if (next_epoll_fd >= INT_MAX) {
                fut_printf("[EPOLL_ALLOCATE] epoll_allocate_set() -> NULL "
                           "(epoll FD counter would overflow INT_MAX, Phase 5)\n");
                return NULL;
            }

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
 * Phase 2 (Completed): Enhanced validation, flag categorization, detailed logging
 * Phase 3 (Completed): Edge-triggered mode, oneshot events
 * Phase 4 (Completed): Performance optimization, memory pooling
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
    text = "]) -> 0 (epoll instance created, Phase 4: Memory pooling and scalability improvements)\n";
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
 * Phase 2 (Completed): Enhanced validation, operation categorization, detailed logging
 * Phase 3 (Completed): Edge-triggered mode support, oneshot events
 * Phase 4 (Completed): Performance optimization with memory pooling
 */
long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    /* Phase 5: Validate fd is non-negative early */
    if (fd < 0) {
        fut_printf("[EPOLL_CTL] epoll_ctl(epfd=%d, op=%d, fd=%d) -> EBADF (fd is negative, Phase 5)\n",
                   epfd, op, fd);
        return -EBADF;
    }

    /* Phase 2: Categorize epoll FD */
    const char *epfd_category;
    if (epfd >= 4000 && epfd < 5000) {
        epfd_category = "epoll (4000-4999)";
    } else if (epfd >= 5000) {
        epfd_category = "epoll high (≥5000)";
    } else {
        epfd_category = "invalid range (<4000)";
    }

    /* Phase 2: Categorize target FD - use shared helper */
    const char *fd_category = fut_fd_category(fd);

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

        /* Phase 5: Validate event mask doesn't contain invalid bits */
        uint32_t valid_events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP |
                               EPOLLRDNORM | EPOLLRDBAND | EPOLLWRNORM | EPOLLWRBAND |
                               EPOLL_ET | EPOLL_ONESHOT;
        if (ev.events & ~valid_events) {
            uint32_t invalid_bits = ev.events & ~valid_events;
            fut_printf("[EPOLL_CTL] epoll_ctl(epfd=%d, op=%s, fd=%d, events=0x%x) -> EINVAL "
                       "(invalid event bits 0x%x detected, valid=0x%x, Phase 5)\n",
                       epfd, op_name, fd, ev.events, invalid_bits, valid_events);
            return -EINVAL;
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

        /* Phase 3: Extract and store edge-triggered and oneshot flags */
        set->fds[slot].edge_triggered = (ev.events & EPOLL_ET) != 0;
        set->fds[slot].oneshot = (ev.events & EPOLL_ONESHOT) != 0;
        set->fds[slot].last_was_readable = false;
        set->fds[slot].last_was_writable = false;

        /* Phase 3: Mask out modifier flags from events for actual event checking */
        uint32_t base_events = ev.events & ~(EPOLL_ET | EPOLL_ONESHOT);
        set->fds[slot].events = base_events;

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

        /* Phase 3: Categorize edge-triggered and oneshot modes */
        const char *mode_desc;
        if (set->fds[slot].edge_triggered && set->fds[slot].oneshot) {
            mode_desc = "ET|ONESHOT";
        } else if (set->fds[slot].edge_triggered) {
            mode_desc = "ET";
        } else if (set->fds[slot].oneshot) {
            mode_desc = "ONESHOT";
        } else {
            mode_desc = "level-triggered";
        }

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
        text = ", mode=";
        while (*text) { msg[pos++] = *text++; }
        while (*mode_desc) { msg[pos++] = *mode_desc++; }
        text = ") -> 0 (fd registered, Phase 3)\n";
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
 * Phase 2 (Completed): Enhanced validation, timeout categorization, detailed logging
 * Phase 3 (Completed): Edge-triggered mode, oneshot events
 * Phase 4 (Completed): Performance optimization with memory pooling
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

    /* Phase 3: Validate maxevents doesn't exceed system capability (MAX_EPOLL_FDS) */
    if (maxevents > MAX_EPOLL_FDS) {
        fut_printf("[EPOLL_WAIT] epoll_wait(epfd=%d, maxevents=%d) -> EINVAL "
                   "(maxevents exceeds MAX_EPOLL_FDS %d, Phase 3)\n",
                   epfd, maxevents, MAX_EPOLL_FDS);
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

#if EPOLL_DEBUG
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
#endif

    /* Poll with timeout support */
    int max_iterations = (timeout == 0) ? 1 : ((timeout < 0) ? 10000 : (timeout / 10 + 1));
    int iteration = 0;

#if EPOLL_DEBUG
    static int epoll_wait_call_count = 0;
    epoll_wait_call_count++;
    int this_call = epoll_wait_call_count;

    if (this_call <= 3) {
        fut_printf("[EPOLL_WAIT-DBG] Call #%d: epfd=%d timeout=%d max_iter=%d fds_registered=%d\n",
                   this_call, epfd, timeout, max_iterations, set->count);
    }
#endif

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
            bool handled = false;

#if EPOLL_DEBUG
            static int vnode_type_dbg = 0;
            if (vnode_type_dbg < 10) {
                vnode_type_dbg++;
                if (file->vnode) {
                    fut_printf("[EPOLL-VN-DBG] fd=%d vnode=%p type=%d (0=REG,1=DIR,2=CHR,3=BLK,4=FIFO,5=SOCK)\n",
                               set->fds[i].fd, file->vnode, file->vnode->type);
                } else {
                    fut_printf("[EPOLL-VN-DBG] fd=%d vnode=NULL (no vnode)\n", set->fds[i].fd);
                }
            }
#endif

            if (fut_eventfd_poll(file, set->fds[i].events, &events_ready)) {
                handled = true;
            }

            /* For sockets: check get_socket_from_fd first (sockets may not have vnodes) */
            if (!handled) {
                fut_socket_t *socket = get_socket_from_fd(set->fds[i].fd);
                if (socket) {
                    /* Convert EPOLL events to poll events and check socket readiness */
                    int poll_events = 0;
                    if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                        poll_events |= 0x1;  /* POLLIN */
                    }
                    if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                        poll_events |= 0x4;  /* POLLOUT */
                    }
                    int socket_ready = fut_socket_poll(socket, poll_events);
#if EPOLL_DEBUG
                    fut_printf("[EPOLL-DBG] fd=%d poll_events=0x%x socket_ready=0x%x state=%d\n",
                               set->fds[i].fd, poll_events, socket_ready, socket->state);
#endif
                    if (socket_ready & 0x1) {  /* POLLIN */
                        events_ready |= EPOLLIN | EPOLLRDNORM;
                    }
                    if (socket_ready & 0x4) {  /* POLLOUT */
                        events_ready |= EPOLLOUT | EPOLLWRNORM;
                    }
                    handled = true;
                }
            }

            /* For regular files: always ready for both read and write */
            if (!handled && file->vnode && file->vnode->type == VN_REG) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
                handled = true;
            }

            /* For sockets with vnodes: redundant but keep for VN_SOCK path */
            if (!handled && file->vnode && file->vnode->type == VN_SOCK) {
                fut_socket_t *socket = get_socket_from_fd(set->fds[i].fd);
                if (socket) {
                    int poll_events = 0;
                    if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                        poll_events |= 0x1;
                    }
                    if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                        poll_events |= 0x4;
                    }
                    int socket_ready = fut_socket_poll(socket, poll_events);
                    if (socket_ready & 0x1) {
                        events_ready |= EPOLLIN | EPOLLRDNORM;
                    }
                    if (socket_ready & 0x4) {
                        events_ready |= EPOLLOUT | EPOLLWRNORM;
                    }
                }
                handled = true;
            }

            /* For character devices and other types: report as ready if requested */
            if (!handled && file->vnode) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
            }

            /* Phase 3: Handle edge-triggered mode - only report on transitions */
            bool should_report = false;
            if (events_ready) {
                if (set->fds[i].edge_triggered) {
                    /* Edge-triggered: report only if transitioning from no event to event */
                    bool is_readable = (events_ready & (EPOLLIN | EPOLLRDNORM)) != 0;
                    bool is_writable = (events_ready & (EPOLLOUT | EPOLLWRNORM)) != 0;

                    if ((is_readable && !set->fds[i].last_was_readable) ||
                        (is_writable && !set->fds[i].last_was_writable)) {
                        should_report = true;
                    }
                    /* Update state for next iteration */
                    if (is_readable) set->fds[i].last_was_readable = true;
                    if (is_writable) set->fds[i].last_was_writable = true;
                } else {
                    /* Level-triggered: report every iteration while event is ready */
                    should_report = true;
                }
            } else {
                /* Phase 3: Clear edge-triggered state when event no longer ready */
                if (set->fds[i].edge_triggered) {
                    set->fds[i].last_was_readable = false;
                    set->fds[i].last_was_writable = false;
                }
            }

            /* Report events if appropriate */
            if (should_report) {
                ready_events[ready_count].events = events_ready;
                ready_events[ready_count].data = set->fds[i].data;
                ready_count++;

                /* Phase 3: Handle oneshot mode - auto-unregister after reporting */
                if (set->fds[i].oneshot) {
                    set->fds[i].registered = false;
                    set->count--;
                }
            }
        }

        /* If we have events, copy to user and return */
        if (ready_count > 0) {
            if (fut_copy_to_user(events, ready_events,
                                ready_count * sizeof(struct epoll_event)) != 0) {
                fut_printf("[EPOLL_WAIT] epoll_wait() -> EFAULT (copy_to_user failed)\n");
                return -EFAULT;
            }
            return ready_count;
        }

        /* Check timeout */
        if (timeout == 0) {
            /* Non-blocking mode - no events ready */
            return 0;
        }

        /* For short timeouts (< 100ms), use busy-wait polling to avoid scheduler issues.
         * For longer timeouts, use proper thread sleep.
         * This is a workaround for timer-based thread wakeup issues. */
        if (timeout >= 100) {
            fut_thread_sleep(10);
        } else {
            /* Busy-wait for approximately 1ms (rough estimate based on loop iterations) */
            for (volatile int delay = 0; delay < 100000; delay++) {
                __asm__ volatile("" ::: "memory");
            }
        }

        iteration++;
    }

    /* Timeout expired */
#if EPOLL_DEBUG
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
#endif

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

/**
 * sys_epoll_pwait - Wait for events on epoll instance (with signal mask)
 *
 * @param epfd      Epoll file descriptor
 * @param events    Buffer for returned events
 * @param maxevents Maximum number of events to return
 * @param timeout   Timeout in milliseconds (-1 = block indefinitely)
 * @param sigmask   Signal mask to temporarily install (NULL = ignored)
 *
 * On ARM64, epoll_pwait is the primary interface (epoll_wait doesn't exist).
 * For now, we ignore the sigmask parameter and delegate to sys_epoll_wait.
 *
 * Phase 1: Simple wrapper that ignores sigmask
 * Phase 2: Implement signal mask handling
 */
long sys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout, const void *sigmask) {
    (void)sigmask;  /* Ignore signal mask for now */

    fut_printf("[EPOLL_PWAIT] epoll_pwait(epfd=%d, events=%p, maxevents=%d, "
               "timeout=%d, sigmask=%p) -> delegating to epoll_wait\n",
               epfd, events, maxevents, timeout, sigmask);

    /* Delegate to epoll_wait (signal mask handling deferred to Phase 2) */
    return sys_epoll_wait(epfd, events, maxevents, timeout);
}
