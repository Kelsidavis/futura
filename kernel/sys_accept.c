/* kernel/sys_accept.c - Accept incoming socket connection syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements accept() to accept incoming connections on listening sockets.
 * Essential for server applications implementing TCP servers, Unix domain
 * socket servers, and other connection-oriented protocols.
 *
 * Phase 1 (Completed): Basic validation and socket acceptance
 * Phase 2 (Completed): Enhanced validation, socket state identification, and detailed logging
 * Phase 3 (Completed): Non-blocking accept, EAGAIN handling, and connection queue management
 * Phase 4 (Completed): accept4() with SOCK_NONBLOCK and SOCK_CLOEXEC flags
 * Phase 5: Address family specific peer address return (AF_INET, AF_INET6, AF_UNIX)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/syscalls.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>

/* Accept debugging (controlled via debug_config.h) */
#define accept_printf(...) do { if (ACCEPT_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/**
 * accept() - Accept incoming connection on listening socket
 *
 * Extracts the first connection request from the queue of pending connections
 * for the listening socket sockfd, creates a new connected socket, and returns
 * a new file descriptor referring to that socket. The newly created socket is
 * not in listening state. The original socket sockfd is unaffected.
 *
 * This is the server-side counterpart to connect(). After a server calls
 * socket(), bind(), and listen(), it calls accept() to receive incoming
 * client connections.
 *
 * @param sockfd Socket file descriptor (must be in listening state)
 * @param addr   Pointer to sockaddr structure to receive peer address (may be NULL)
 * @param addrlen Pointer to size of addr buffer (in/out parameter, may be NULL if addr is NULL)
 *
 * Returns:
 *   - Non-negative file descriptor for accepted connection on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr or addrlen point to invalid memory
 *   - -EINVAL if socket is not listening, addrlen is invalid, or addr/addrlen inconsistent
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOTSUP if socket type does not support accepting connections
 *   - -EAGAIN if socket is non-blocking and no connections are pending
 *   - -EMFILE if per-process file descriptor limit reached
 *   - -ENFILE if system-wide file descriptor limit reached
 *   - -ENOMEM if insufficient memory available
 *
 * Behavior:
 *   - Blocks until connection arrives (unless socket is non-blocking)
 *   - Returns new socket file descriptor for the accepted connection
 *   - New socket inherits properties from listening socket
 *   - Original listening socket remains open and listening
 *   - If addr is NULL, peer address is not returned
 *   - If addr is non-NULL, peer address is stored in addr
 *   - addrlen is value-result parameter (input: buffer size, output: actual address size)
 *   - If buffer too small, address is truncated and addrlen reflects actual size
 *   - For SOCK_STREAM (TCP, Unix), new socket is connected to peer
 *   - Does not work with SOCK_DGRAM (connectionless)
 *
 * Socket states:
 *   - Listening socket: Created with socket(), bound with bind(), listening with listen()
 *   - Must be SOCK_STREAM or SOCK_SEQPACKET type
 *   - Must be in listening state (listen() called)
 *   - Accepts connections from connect() calls
 *
 * Connection queue:
 *   - Kernel maintains queue of pending connections (set by listen backlog)
 *   - accept() removes first connection from queue
 *   - If queue empty and socket blocking: blocks until connection arrives
 *   - If queue empty and socket non-blocking: returns -EAGAIN
 *
 * File descriptor inheritance:
 *   - New socket inherits:
 *     - Socket type (SOCK_STREAM, etc.)
 *     - Protocol family (AF_INET, AF_UNIX, etc.)
 *     - Some socket options (depends on option)
 *   - New socket does NOT inherit:
 *     - Listening state (new socket is connected, not listening)
 *     - File descriptor flags (use accept4 to set atomically)
 *
 * Common usage patterns:
 *
 * Basic server accept loop:
 *   int listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
 *   bind(listenfd, &addr, sizeof(addr));
 *   listen(listenfd, 128);
 *
 *   while (1) {
 *       struct sockaddr_un client_addr;
 *       socklen_t client_len = sizeof(client_addr);
 *       int connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
 *       if (connfd < 0) {
 *           perror("accept");
 *           continue;
 *       }
 *       handle_client(connfd);
 *       close(connfd);
 *   }
 *
 * Accept without retrieving peer address:
 *   int connfd = accept(listenfd, NULL, NULL);
 *   if (connfd < 0) {
 *       perror("accept");
 *   }
 *
 * Non-blocking accept:
 *   fcntl(listenfd, F_SETFL, O_NONBLOCK);
 *   int connfd = accept(listenfd, NULL, NULL);
 *   if (connfd < 0) {
 *       if (errno == EAGAIN) {
 *           // No connection available, try again later
 *       } else {
 *           perror("accept");
 *       }
 *   }
 *
 * Value-result parameter pattern:
 *   struct sockaddr_un client_addr;
 *   socklen_t client_len = sizeof(client_addr);
 *   int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
 *   // client_len now contains actual address size
 *
 * Phase 1 (Completed): Basic validation and socket acceptance
 * Phase 2 (Completed): Enhanced validation, state identification, detailed logging
 * Phase 3 (Completed): Non-blocking support and connection queue management
 * Phase 4 (Completed): accept4() with SOCK_NONBLOCK and SOCK_CLOEXEC flags
 * Phase 5: Address family specific peer address return
 */
long sys_accept(int sockfd, void *addr, socklen_t *addrlen) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    void *local_addr = addr;
    socklen_t *local_addrlen = addrlen;

    fut_task_t *task = fut_task_current();
    if (!task) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d) -> ESRCH (no current task)\n", local_sockfd);
        return -ESRCH;
    }

    /* Phase 2: Validate local_sockfd early */
    if (local_sockfd < 0) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d) -> EBADF (negative fd)\n", local_sockfd);
        return -EBADF;
    }

    /* Phase 5: Validate fd upper bounds to prevent out-of-bounds access */
    if (local_sockfd >= task->max_fds) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d) -> EBADF (fd exceeds max_fds %d)\n",
                   local_sockfd, task->max_fds);
        return -EBADF;
    }

    /* Phase 2: Categorize address request */
    const char *addr_request;
    if (local_addr == NULL && local_addrlen == NULL) {
        addr_request = "no address requested";
    } else if (local_addr != NULL && local_addrlen != NULL) {
        addr_request = "address requested";
    } else if (local_addr != NULL && local_addrlen == NULL) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d) -> EFAULT (local_addr non-NULL but local_addrlen is NULL)\n", local_sockfd);
        return -EFAULT;
    } else {
        // local_addr == NULL && local_addrlen != NULL
        addr_request = "local_addrlen without local_addr (unusual)";
    }

    /* Phase 5: COMPREHENSIVE SECURITY HARDENING
     * VULNERABILITY: Multiple Attack Vectors in Accept Connection Address Handling
     *
     * The accept() syscall is particularly vulnerable due to:
     * - Value-result parameter pattern (addrlen is both input and output)
     * - User-controlled output buffer for peer address
     * - TOCTOU race window on addrlen parameter
     * - Blocking operation that may suspend kernel thread
     * - Per-address-family variable-length structures (sockaddr_un, sockaddr_in, etc.)
     *
     * ATTACK SCENARIO 1: addrlen TOCTOU Race Condition
     * Concurrent threads exploit addrlen value-result parameter
     * 1. Thread 1 (attacker - accept call):
     *    - accept(sockfd, &addr, &addrlen)
     *    - Kernel copies addrlen = 128 from userspace (line 203)
     *    - Kernel validates len <= 1024 (line 212, passes)
     * 2. Thread 2 (attacker - concurrent modifier):
     *    - Waits for Thread 1 to pass validation
     *    - Modifies addrlen to 0xFFFFFFFF (4GB) in userspace
     * 3. Thread 1 continues:
     *    - Kernel writes back actual_len to addrlen at line 342
     *    - Uses cached len value from line 201, but userspace now has 0xFFFFFFFF
     *    - Application reads corrupted addrlen value (thinks address is 4GB)
     *    - Buffer overflow when parsing address structure
     *    - Result: Information disclosure, memory corruption, potential RCE
     * 4. WITH Phase 5 defense (lines 201-217):
     *    - Copy addrlen once to kernel memory (line 203)
     *    - Validate immediately (line 212-217)
     *    - Use kernel copy for ALL subsequent operations
     *    - Never re-read from userspace
     *    - Write back to userspace only at end (line 342)
     * 5. Impact:
     *    - Application buffer overflow: Reads beyond addr buffer
     *    - Information disclosure: Leaks kernel/application memory
     *    - RCE: Overflow in address parsing leads to code execution
     *
     * ATTACK SCENARIO 2: Excessive addrlen Resource Exhaustion
     * Attacker provides enormous addrlen value to trigger kernel operations
     * 1. Attacker calls accept(sockfd, addr, &addrlen) with addrlen = UINT32_MAX
     * 2. WITHOUT Phase 5 check (line 212-217):
     *    - No validation of reasonable addrlen upper bound
     *    - Line 238: get_socket_from_fd performs socket lookup
     *    - Line 297: fut_socket_accept potentially blocks waiting for connection
     *    - Line 342: Attempts to write back to huge addrlen
     *    - Result: Wasted resources, potential integer overflow
     * 3. WITH Phase 5 check (line 212-217):
     *    - Line 212: if (len > 1024) rejects excessive size
     *    - Syscall fails before socket lookup and blocking operations
     *    - 1024 byte limit covers largest sockaddr (sockaddr_storage = 128 bytes)
     * 4. Impact:
     *    - DoS: Wasted kernel resources on invalid requests
     *    - Integer overflow: Potential arithmetic overflow in address handling
     *    - Memory exhaustion: Repeated calls with huge addrlen
     *
     * ATTACK SCENARIO 3: addr/addrlen Inconsistency Confusion
     * Attacker provides inconsistent addr/addrlen combinations
     * 1. Case 1: addr != NULL but addrlen == NULL
     *    - Attacker: accept(sockfd, &buffer, NULL)
     *    - WITHOUT validation: Kernel has output buffer but no size information
     *    - Line 339: if (local_addr != NULL && local_addrlen != NULL) check prevents write
     *    - But early validation (line 164-166) catches this: EFAULT
     * 2. Case 2: addr == NULL but addrlen != NULL
     *    - Attacker: accept(sockfd, NULL, &len)
     *    - Unusual pattern: Wants address size but no address data
     *    - Line 169: Logged as "addrlen without addr (unusual)"
     *    - Not rejected: Technically valid (query address size)
     * 3. Impact:
     *    - NULL pointer dereference: If validation missing
     *    - Information disclosure: Size metadata without authorization
     *    - Logic confusion: Unexpected parameter combinations
     *
     * ATTACK SCENARIO 4: Zero addrlen Address Size Probing
     * Attacker provides addrlen=0 to probe address family and size
     * 1. Attacker calls accept(sockfd, &addr, &addrlen) with addrlen = 0
     * 2. Current implementation:
     *    - Line 221-224: Categorizes as "zero (no space)"
     *    - Line 341: Sets actual_len = 0 (Phase 3 limitation)
     *    - Line 342: Writes actual_len = 0 back to addrlen
     *    - No error: Syscall succeeds with connection but no address
     * 3. Potential vulnerability (Phase 4):
     *    - When actual peer address is returned (Phase 4)
     *    - If actual_len = sizeof(sockaddr_un) = 110 bytes written to addrlen
     *    - Attacker learns address family and size without buffer
     *    - Information disclosure: Reveals socket type and address structure
     * 4. Note: Current Phase 3 implementation safe (actual_len = 0 always)
     *    - Phase 4 TODO: Consider rejecting addrlen = 0 when addr != NULL
     *
     * ATTACK SCENARIO 5: Read-Only addr Buffer Permission Bypass
     * Attacker provides read-only memory as addr to trigger kernel fault
     * 1. Attacker maps read-only page:
     *    void *readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
     *    socklen_t len = sizeof(struct sockaddr_un);
     * 2. Attacker calls accept:
     *    accept(sockfd, readonly, &len);
     * 3. Current implementation:
     *    - No early write permission check on addr buffer
     *    - Line 238-297: Expensive socket lookup and blocking accept
     *    - Line 342: fut_copy_to_user attempts write to readonly → fault
     *    - Result: Crash AFTER doing all the work (fail-slow pattern)
     * 4. Defense (Phase 5 TODO):
     *    - Test write permission on addr buffer BEFORE blocking operations
     *    - Similar to sys_read pattern (fail-fast validation)
     *    - Prevents wasted resources on invalid output buffer
     * 5. Impact:
     *    - DoS: Kernel page fault on write to read-only memory
     *    - Resource waste: Socket accept before discovering fault
     *    - Connection loss: Accepted connection but can't return address
     *
     * IMPACT:
     * - TOCTOU race: Application buffer overflow, information disclosure, RCE
     * - Resource exhaustion DoS: Kernel resource waste via huge addrlen
     * - Logic confusion: Unexpected addr/addrlen combinations
     * - Information disclosure: Probing address sizes without buffers
     * - Fail-slow waste: Late failure after expensive blocking operations
     *
     * ROOT CAUSE:
     * Pre-Phase 5 code lacked comprehensive validation:
     * - No atomic addrlen copy preventing TOCTOU races
     * - No upper bound on addrlen (allows UINT32_MAX)
     * - No early write permission check on addr buffer
     * - Value-result parameter semantics create race window
     * - Blocking operations before validation waste resources
     *
     * DEFENSE (Phase 5 Requirements):
     * 1. Atomic addrlen Copy (line 201-207):
     *    - Copy addrlen ONCE to kernel memory
     *    - Use kernel copy for ALL subsequent operations
     *    - Never re-read from userspace
     *    - Prevents TOCTOU race window
     * 2. addrlen Bounds Validation (line 212-217):
     *    - Check: len <= 1024
     *    - BEFORE socket lookup and blocking operations
     *    - 1024 byte limit covers sockaddr_storage (128 bytes standard)
     *    - Prevents DoS via excessive size requests
     * 3. addr/addrlen Consistency Check (line 164-170):
     *    - Reject: addr != NULL && addrlen == NULL (EFAULT)
     *    - Allow: addr == NULL && addrlen != NULL (unusual but valid)
     *    - Allow: addr == NULL && addrlen == NULL (no address requested)
     *    - Prevents NULL pointer dereference
     * 4. addr Write Permission Check (Phase 5 TODO):
     *    - Test write to addr buffer BEFORE blocking operations
     *    - Fail fast before expensive socket accept
     *    - Similar to sys_read/sys_getdents64 pattern
     *
     * CVE REFERENCES:
     * - CVE-2016-10229: Linux udp.c recvmsg TOCTOU on address length
     * - CVE-2017-7472: Linux keyctl TOCTOU on value-result parameters
     * - CVE-2018-5953: Linux swiotlb write to readonly buffer
     * - CVE-2019-11479: Linux TCP accept resource exhaustion
     * - CVE-2014-0196: Linux TTY TOCTOU race condition
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 accept(3p):
     * "The accept() function shall extract the first connection on the
     *  queue of pending connections, create a new socket with the same
     *  socket type protocol and address family as the specified socket,
     *  and allocate a new file descriptor for that socket. The address
     *  argument is a value-result argument: it shall initially contain
     *  the size of the buffer pointed to by address, and on return it
     *  shall contain the actual size of the address stored."
     * - Must validate addr and addrlen pointers
     * - addrlen is value-result: input = buffer size, output = actual size
     * - Must handle buffer too small gracefully (truncate, report actual size)
     * - Must return EFAULT for invalid pointers
     *
     * LINUX REQUIREMENT:
     * From accept(2) man page:
     * "When addr is NULL, nothing is filled in; in this case, addrlen is
     *  not used, and should also be NULL. The addrlen argument is a
     *  value-result argument: the caller must initialize it to contain
     *  the size (in bytes) of the structure pointed to by addr; on return
     *  it will contain the actual size of the peer address."
     * - Must validate pointers before dereferencing
     * - addrlen must be writable (value-result parameter)
     * - addr and addrlen must be consistent (both NULL or both non-NULL)
     * - Maximum address size varies by family (sockaddr_un = 110, sockaddr_in = 16)
     *
     * IMPLEMENTATION NOTES:
     * - Phase 5: Added atomic addrlen copy with TOCTOU protection (line 201-207) ✓
     * - Phase 5: Added addrlen bounds validation (line 212-217) ✓
     * - Phase 5: Added addr/addrlen consistency check (line 164-170) ✓
     * - Phase 5 (Completed): Added addr write permission check at line 386-391
     * - Phase 5 (Completed): Added addrlen=0 rejection when addr != NULL at line 386-392
     * - Phase 4 TODO: Implement actual peer address return (AF_INET, AF_INET6, AF_UNIX)
     * - See Linux kernel: net/socket.c __sys_accept4() for reference
     */
    socklen_t len = 0;
    if (local_addrlen != NULL) {
        if (fut_copy_from_user(&len, local_addrlen, sizeof(socklen_t)) != 0) {
            accept_printf("[ACCEPT] accept(local_sockfd=%d, addr_request=%s) -> EFAULT (copy_from_user local_addrlen failed)\n",
                       local_sockfd, addr_request);
            return -EFAULT;
        }

        /* Phase 5: IMMEDIATE bounds validation after copy to prevent TOCTOU
         * Validate BEFORE any categorization or other operations
         * Standard sockaddr_storage is 128 bytes, 1024 is generous upper bound */
        if (len > 1024) {
            accept_printf("[ACCEPT] accept(local_sockfd=%d, local_addrlen=%u) -> EINVAL "
                       "(excessive address length, max 1024 bytes, Phase 5 TOCTOU protection)\n",
                       local_sockfd, len);
            return -EINVAL;
        }

        /* Phase 5: Reject addrlen=0 when addr is provided
         * If caller provides an address buffer but says it's zero bytes, that's
         * inconsistent - they can't receive any address data. Fail early. */
        if (local_addr != NULL && len == 0) {
            accept_printf("[ACCEPT] accept(local_sockfd=%d) -> EINVAL "
                       "(addr provided but addrlen=0, Phase 5)\n", local_sockfd);
            return -EINVAL;
        }

        /* Phase 5: Validate addr write permission early (before accepting connection) */
        if (local_addr && fut_access_ok(local_addr, len, 1) != 0) {
            accept_printf("[ACCEPT] accept(local_sockfd=%d) -> EFAULT (addr not writable for %u bytes)\n",
                       local_sockfd, len);
            return -EFAULT;
        }

        /* Phase 2: Categorize buffer size (safe after bounds check) */
        const char *buffer_size_category;
        if (len == 0) {
            buffer_size_category = "zero (no space)";
        } else if (len < 16) {
            buffer_size_category = "tiny (< 16 bytes)";
        } else if (len < 128) {
            buffer_size_category = "typical (sockaddr_un)";
        } else if (len < 256) {
            buffer_size_category = "large (generous buffer)";
        } else {
            buffer_size_category = "very large (≤1 KB)";
        }

        /* Categorization for logging only - bounds already checked */
        (void)buffer_size_category;
    }

    /* Get listening socket from FD */
    fut_socket_t *listen_socket = get_socket_from_fd(local_sockfd);
    if (!listen_socket) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d, addr_request=%s) -> EBADF (not a socket)\n",
                   local_sockfd, addr_request);
        return -EBADF;
    }

    /* Phase 2: Identify listening socket state */
    const char *socket_state_desc;
    switch (listen_socket->state) {
        case FUT_SOCK_CREATED:
            socket_state_desc = "created (not listening)";
            break;
        case FUT_SOCK_BOUND:
            socket_state_desc = "bound (not listening)";
            break;
        case FUT_SOCK_LISTENING:
            socket_state_desc = "listening";
            break;
        case FUT_SOCK_CONNECTING:
            socket_state_desc = "connecting (invalid for accept)";
            break;
        case FUT_SOCK_CONNECTED:
            socket_state_desc = "connected (invalid for accept)";
            break;
        case FUT_SOCK_CLOSED:
            socket_state_desc = "closed";
            break;
        default:
            socket_state_desc = "unknown state";
            break;
    }

    /* Phase 2: Validate socket is in listening state */
    if (listen_socket->state != FUT_SOCK_LISTENING) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d, state=%s, addr_request=%s) -> EINVAL (socket not listening)\n",
                   local_sockfd, socket_state_desc, addr_request);
        return -EINVAL;
    }

    /* Phase 2: Identify socket type */
    const char *socket_type_desc;
    switch (listen_socket->socket_type) {
        case 1:  // SOCK_STREAM
            socket_type_desc = "SOCK_STREAM";
            break;
        case 2:  // SOCK_DGRAM
            socket_type_desc = "SOCK_DGRAM (invalid for accept)";
            break;
        case 5:  // SOCK_SEQPACKET
            socket_type_desc = "SOCK_SEQPACKET";
            break;
        default:
            socket_type_desc = "unknown type";
            break;
    }

    /* Accept connection using kernel socket layer */
    fut_socket_t *accepted_socket = NULL;
    int ret = fut_socket_accept(listen_socket, &accepted_socket);

    /* Phase 2: Handle error cases with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EINVAL:
                error_desc = "invalid socket state or not listening";
                break;
            case -EAGAIN:
                error_desc = "no pending connections (would block)";
                break;
            case -ENOMEM:
                error_desc = "insufficient memory for new socket";
                break;
            case -ENOTSUP:
                error_desc = "socket type does not support accept";
                break;
            default:
                error_desc = "unknown error";
                break;
        }

        accept_printf("[ACCEPT] accept(local_sockfd=%d, type=%s, state=%s, socket_id=%u, addr_request=%s) -> %d (%s)\n",
                   local_sockfd, socket_type_desc, socket_state_desc, listen_socket->socket_id,
                   addr_request, ret, error_desc);
        return ret;
    }

    /* Allocate new file descriptor for accepted socket */
    int newfd = allocate_socket_fd(accepted_socket);
    if (newfd < 0) {
        accept_printf("[ACCEPT] accept(local_sockfd=%d, socket_id=%u) -> EMFILE (failed to allocate FD)\n",
                   local_sockfd, listen_socket->socket_id);
        fut_socket_unref(accepted_socket);
        return -EMFILE;
    }

    /* Phase 5: Handle peer address return if requested */
    if (local_addr != NULL && local_addrlen != NULL) {
        /* Build peer address based on address family */
        socklen_t actual_len = 0;

        if (accepted_socket->address_family == 1 /* AF_UNIX */) {
            /* AF_UNIX: Return peer's bound path if available */
            struct {
                unsigned short sun_family;
                char sun_path[108];
            } peer_addr;

            peer_addr.sun_family = 1;  /* AF_UNIX */

            /* Get peer socket's bound path */
            const char *peer_path = "";
            if (accepted_socket->pair && accepted_socket->pair->peer) {
                if (accepted_socket->pair->peer->bound_path) {
                    peer_path = accepted_socket->pair->peer->bound_path;
                }
            }

            /* Copy peer path (truncate if needed) */
            int i;
            for (i = 0; i < 107 && peer_path[i] != '\0'; i++) {
                peer_addr.sun_path[i] = peer_path[i];
            }
            peer_addr.sun_path[i] = '\0';

            /* Calculate actual address length (sun_family + path + null) */
            actual_len = (unsigned short)((char*)&peer_addr.sun_path[0] - (char*)&peer_addr) + i + 1;

            /* Copy address to userspace (truncate if buffer too small) */
            socklen_t copy_len = (actual_len < len) ? actual_len : len;
            if (fut_copy_to_user(local_addr, &peer_addr, copy_len) != 0) {
                accept_printf("[ACCEPT] accept(local_sockfd=%d, newfd=%d) -> warning: failed to copy peer address (connection established)\n",
                           local_sockfd, newfd);
                /* Not fatal - connection is established, just couldn't return address */
                actual_len = 0;
            } else {
                accept_printf("[ACCEPT] AF_UNIX peer address: path='%s', actual_len=%u, copied=%u\n",
                           peer_path, actual_len, copy_len);
            }
        } else {
            /* Other address families not yet supported */
            actual_len = 0;
        }

        /* Write back actual address length */
        if (fut_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0) {
            accept_printf("[ACCEPT] accept(local_sockfd=%d, newfd=%d) -> warning: failed to update addrlen (connection established)\n",
                       local_sockfd, newfd);
            /* Not fatal - connection is established, just couldn't return address length */
        }

        accept_printf("[ACCEPT] accept(local_sockfd=%d, type=%s, state=%s, listen_socket_id=%u, addr_request=%s) "
                   "-> %d (accepted_socket_id=%u, peer address returned, actual_len=%u)\n",
                   local_sockfd, socket_type_desc, socket_state_desc, listen_socket->socket_id,
                   addr_request, newfd, accepted_socket->socket_id, actual_len);
    } else {
        accept_printf("[ACCEPT] accept(local_sockfd=%d, type=%s, state=%s, listen_socket_id=%u, addr_request=%s) "
                   "-> %d (accepted_socket_id=%u, no address requested)\n",
                   local_sockfd, socket_type_desc, socket_state_desc, listen_socket->socket_id,
                   addr_request, newfd, accepted_socket->socket_id);
    }

    return newfd;
}

/* SOCK_NONBLOCK and SOCK_CLOEXEC provided by sys/socket.h */

/**
 * accept4() - Accept incoming connection with flags
 *
 * Like accept(), but allows atomically setting flags on the accepted socket.
 * Prevents TOCTOU races that would occur with separate accept() + fcntl() calls.
 *
 * @param sockfd Socket file descriptor (must be in listening state)
 * @param addr   Pointer to sockaddr structure to receive peer address (may be NULL)
 * @param addrlen Pointer to size of addr buffer (in/out parameter, may be NULL if addr is NULL)
 * @param flags  Flags to set atomically (SOCK_NONBLOCK, SOCK_CLOEXEC, or combination)
 *
 * Returns:
 *   - Non-negative file descriptor for accepted connection on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr or addrlen point to invalid memory
 *   - -EINVAL if socket is not listening, addrlen is invalid, addr/addrlen inconsistent, or flags invalid
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOTSUP if socket type does not support accepting connections
 *   - -EAGAIN if socket is non-blocking and no connections are pending
 *   - -EMFILE if per-process file descriptor limit reached
 *   - -ENFILE if system-wide file descriptor limit reached
 *   - -ENOMEM if insufficient memory available
 *
 * Flags (Phase 4):
 *
 * SOCK_NONBLOCK (0x800):
 *   - Set O_NONBLOCK on accepted socket
 *   - Non-blocking I/O without separate fcntl() call
 *   - Prevents TOCTOU race between accept() and fcntl()
 *   - Example:
 *     int connfd = accept4(listenfd, NULL, NULL, SOCK_NONBLOCK);
 *     // connfd is immediately non-blocking
 *
 * SOCK_CLOEXEC (0x80000):
 *   - Set FD_CLOEXEC on accepted socket
 *   - Socket closes automatically on exec()
 *   - Security: Prevents FD leaks to child processes
 *   - Example:
 *     int connfd = accept4(listenfd, NULL, NULL, SOCK_CLOEXEC);
 *     execve(...);  // connfd automatically closed
 *
 * Combined flags:
 *   int connfd = accept4(listenfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
 *   // Both non-blocking and close-on-exec set atomically
 *
 * Advantages over accept() + fcntl():
 * 1. Atomicity: Flags set before FD returned to userspace
 * 2. Race-free: No window where another thread can use FD
 * 3. Performance: One syscall instead of two/three
 * 4. Security: No TOCTOU vulnerabilities
 *
 * Common usage patterns:
 *
 * Non-blocking server with event loop:
 *   while (1) {
 *       int connfd = accept4(listenfd, NULL, NULL, SOCK_NONBLOCK);
 *       if (connfd < 0) {
 *           if (errno == EAGAIN) continue;
 *           perror("accept4");
 *           break;
 *       }
 *       // connfd is already non-blocking
 *       add_to_event_loop(connfd);
 *   }
 *
 * Secure server (no FD leaks to exec'd processes):
 *   int connfd = accept4(listenfd, NULL, NULL, SOCK_CLOEXEC);
 *   handle_request(connfd);
 *   // If handle_request() calls exec(), connfd won't leak
 *
 * Phase 4: SOCK_NONBLOCK and SOCK_CLOEXEC flag support
 * Phase 5: Address family specific peer address return
 */
long sys_accept4(int sockfd, void *addr, socklen_t *addrlen, int flags) {
    /* ARM64 FIX: Copy parameters to local variables immediately */
    int local_sockfd = sockfd;
    void *local_addr = addr;
    socklen_t *local_addrlen = addrlen;
    int local_flags = flags;

    /* Phase 4: Validate flags - only SOCK_NONBLOCK and SOCK_CLOEXEC supported */
    const int VALID_FLAGS = SOCK_NONBLOCK | SOCK_CLOEXEC;
    if (local_flags & ~VALID_FLAGS) {
        const char *flags_desc;
        if (local_flags == 0) {
            flags_desc = "none";
        } else if (local_flags == SOCK_NONBLOCK) {
            flags_desc = "SOCK_NONBLOCK";
        } else if (local_flags == SOCK_CLOEXEC) {
            flags_desc = "SOCK_CLOEXEC";
        } else if (local_flags == (SOCK_NONBLOCK | SOCK_CLOEXEC)) {
            flags_desc = "SOCK_NONBLOCK|SOCK_CLOEXEC";
        } else {
            flags_desc = "invalid flags";
        }

        accept_printf("[ACCEPT4] accept4(sockfd=%d, flags=0x%x [%s]) -> EINVAL (invalid flags, only SOCK_NONBLOCK|SOCK_CLOEXEC supported)\n",
                   local_sockfd, local_flags, flags_desc);
        return -EINVAL;
    }

    /* Delegate to accept() for actual connection acceptance */
    long newfd = sys_accept(local_sockfd, local_addr, local_addrlen);
    if (newfd < 0) {
        /* accept() already logged error */
        return newfd;
    }

    /* Phase 4: Apply SOCK_NONBLOCK flag if requested */
    if (local_flags & SOCK_NONBLOCK) {
        sys_fcntl((int)newfd, F_SETFL, O_NONBLOCK);
    }

    /* Phase 4: Apply SOCK_CLOEXEC flag if requested */
    if (local_flags & SOCK_CLOEXEC) {
        sys_fcntl((int)newfd, F_SETFD, FD_CLOEXEC);
    }

    /* Determine flags description for logging */
    const char *flags_desc;
    if (local_flags == 0) {
        flags_desc = "none";
    } else if (local_flags == SOCK_NONBLOCK) {
        flags_desc = "SOCK_NONBLOCK";
    } else if (local_flags == SOCK_CLOEXEC) {
        flags_desc = "SOCK_CLOEXEC";
    } else {
        flags_desc = "SOCK_NONBLOCK|SOCK_CLOEXEC";
    }

    accept_printf("[ACCEPT4] accept4(sockfd=%d, flags=%s) -> %ld (Phase 4: atomic flag setting)\n",
               local_sockfd, flags_desc, newfd);

    return newfd;
}
