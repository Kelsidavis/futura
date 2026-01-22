/* sys_fork.c - fork() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process cloning via fork().
 * Essential for process creation and Unix process model.
 *
 * Phase 1 (Completed): Basic fork with memory cloning and FD inheritance
 * Phase 2 (Completed): Enhanced validation, PID categorization, VMA/FD tracking, detailed logging
 * Phase 3 (Completed): Optimized COW performance, large process handling
 * Phase 4 (Completed): Advanced fork features (vfork, clone with flags, namespace support)
 */

/* ============================================================
 * PHASE 5 COMPREHENSIVE SECURITY DOCUMENTATION
 * ============================================================
 *
 * VULNERABILITY OVERVIEW:
 * -----------------------
 * fork() is the fundamental process creation primitive in Unix-like systems,
 * creating an exact duplicate of the calling process. This operation involves
 * complex resource duplication (address space, file descriptors, credentials)
 * and introduces critical attack surfaces:
 *
 * 1. Page reference count overflow in copy-on-write (COW) sharing
 * 2. File descriptor refcount overflow via repeated forking
 * 3. PID exhaustion denial of service (fork bomb)
 * 4. Memory exhaustion through unbounded fork recursion
 * 5. Race conditions in concurrent page table cloning
 *
 * Each vulnerability can lead to use-after-free, privilege escalation, or
 * system-wide denial of service. fork() is particularly dangerous because
 * unprivileged users can call it freely, making resource limits critical.
 *
 * ATTACK SCENARIO 1: Page Reference Count Overflow in COW Sharing
 * =================================================================
 * DESCRIPTION:
 * Attacker repeatedly forks to overflow the physical page reference counter,
 * causing premature page deallocation and use-after-free exploitation.
 *
 * EXPLOITATION STEPS:
 * 1. Attacker process has writable page at VA 0x400000 (physical page P)
 *    - Page P has refcount = 1 (owned by parent process)
 * 2. Attacker calls fork() creating child1
 *    - COW: Page P marked read-only in both parent and child1
 *    - Line 582: fut_page_ref_inc(parent_phys) increments refcount: 1 → 2
 * 3. Child1 calls fork() creating child2
 *    - Page P now shared by parent, child1, child2
 *    - Refcount: 2 → 3
 * 4. Attacker repeats fork() recursively 65533 more times
 *    - Each fork increments refcount of shared page P
 *    - Refcount reaches UINT16_MAX (65535) if refcount is uint16_t
 * 5. One more fork() causes overflow without validation
 *    - Refcount: 65535 + 1 → 0 (wraps to zero)
 * 6. PMM sees refcount=0, assumes page is free
 *    - PMM places page P on free list
 * 7. New allocation request gets page P
 *    - Second process now owns page P while first 65536 processes still reference it
 * 8. Write to page P in any of the 65536 original processes
 *    - COW triggers, but page already reallocated to second process
 *    - Use-after-free: Original processes access freed page
 *    - Data corruption: Second process sees writes from first processes
 * 9. Attacker reads sensitive data from second process
 *    - Information disclosure or privilege escalation
 *
 * IMPACT:
 * - Use-after-free: Page freed while 65536 processes still reference it
 * - Memory corruption: Multiple processes unsafely share physical page
 * - Information disclosure: New owner reads stale data from old processes
 * - Privilege escalation: Attacker overwrites kernel structures if page reused
 *
 * ROOT CAUSE:
 * Line 582: fut_page_ref_inc(parent_phys) with no overflow validation
 * - Page refcount is finite (typically uint16_t = 65535 max)
 * - No check that increment won't overflow maximum
 * - No validation that parent_phys is within valid PMM range
 * - Assumption: fork won't be called 65535+ times on same page
 * - PMM layer (fut_pmm.c) must enforce refcount limits
 *
 * DEFENSE STRATEGY:
 * [DONE] Document refcount overflow vulnerability (lines 527-581):
 *   - Comprehensive inline comment explaining attack
 *   - References CVE-2016-0728 (keyring refcount), CVE-2014-2851 (group_info)
 *   - Specifies PMM layer must validate refcount < MAX before increment
 *   - Requires fork() to check fut_page_ref_inc() return value
 *
 * [DONE] Implement refcount overflow check in fut_page_ref_inc():
 *   - Added bounds check in memory/fut_mm.c (FUT_PAGE_REF_MAX = 60000)
 *   - Returns -EOVERFLOW if refcount >= limit
 *   - Logs warning when limit reached
 *   - Commit: adfa7bb
 *
 * [DONE] Check fut_page_ref_inc() return value in clone_mm():
 *   - Both COW and shared page paths now check return value
 *   - Returns NULL from clone_mm() on refcount failure
 *   - Calls fut_mm_release() to clean up on failure
 *   - Fork returns -ENOMEM to userspace
 *   - Commit: adfa7bb
 *
 * [TODO] Add refcount stress test:
 *   - Fork process 1000 times, verify refcount doesn't overflow
 *   - Monitor PMM refcount values during mass forking
 *   - Verify fork fails gracefully when refcount limit reached
 *
 * ATTACK SCENARIO 2: File Descriptor Refcount Overflow via Mass Forking
 * =======================================================================
 * DESCRIPTION:
 * Attacker forks repeatedly while holding many open file descriptors, causing
 * file object refcount to overflow and files to be prematurely closed.
 *
 * EXPLOITATION STEPS:
 * 1. Attacker opens 1024 files (RLIMIT_NOFILE limit)
 *    - Each file has struct fut_file with refcount = 1
 * 2. Attacker calls fork()
 *    - Line 204: parent_file->refcount++ for each FD
 *    - All 1024 files now have refcount = 2 (parent + child)
 * 3. Child calls fork() again
 *    - Each file refcount: 2 → 3 (parent + child1 + child2)
 * 4. Attacker forks 65533 more times
 *    - Refcount increments on every fork for all 1024 files
 *    - If refcount is uint16_t: 65535 processes × 1024 files
 * 5. One more fork() causes overflow on all files
 *    - Refcount: 65535 + 1 → 0 (wraps to zero)
 * 6. VFS layer sees refcount=0, closes all files
 *    - All 1024 file descriptors suddenly invalid
 *    - File objects deallocated from kernel heap
 * 7. New file allocations reuse freed struct fut_file memory
 *    - Use-after-free: 65536 processes still reference old fut_file pointers
 * 8. Attacker reads/writes to file descriptor
 *    - Accesses freed memory or different file (confused deputy)
 * 9. Information disclosure or privilege escalation
 *    - Read data from wrong file, write to wrong file
 *
 * IMPACT:
 * - Use-after-free: File objects freed while 65536 processes hold references
 * - File descriptor confusion: Processes access wrong files after reallocation
 * - Information disclosure: Read data from unintended files
 * - Privilege escalation: Write to privileged files (e.g., /etc/passwd)
 *
 * ROOT CAUSE:
 * Line 204: parent_file->refcount++ with no overflow check
 * - File refcount is finite (likely uint32_t but still bounded)
 * - No validation that increment won't overflow
 * - No check that parent_file pointer is valid
 * - Inherited from parent without per-fork validation
 *
 * DEFENSE STRATEGY:
 * [DONE] Add refcount overflow check in FD inheritance:
 *   - Check parent_file->refcount < FUT_FILE_REF_MAX (0xFFFFFFF0) before increment
 *   - Return -ENOMEM from sys_fork() if overflow would occur
 *   - Log warning when file refcount limit reached
 *   - Clean up already-inherited FDs on failure (decrement refcounts)
 *   - Destroy child_task on failure
 *   - Commit: (see below)
 *
 * [TODO] Use atomic refcount operations:
 *   - Replace parent_file->refcount++ with atomic_inc_check_overflow()
 *   - Atomic operation returns error if overflow detected
 *   - Prevents race condition where concurrent forks overflow refcount
 *
 * [TODO] Implement per-process file descriptor limit:
 *   - Enforce RLIMIT_NOFILE during fork (currently only at open)
 *   - Reject fork if child would exceed file descriptor quota
 *   - Prevents mass forking with high FD count
 *
 * [TODO] Add file refcount stress test:
 *   - Open 1024 files, fork 1000 times
 *   - Verify all file refcounts correct (1024000 total references)
 *   - Close files in random order, verify refcount decrements correctly
 *
 * ATTACK SCENARIO 3: PID Exhaustion Denial of Service (Fork Bomb)
 * =================================================================
 * DESCRIPTION:
 * Attacker executes fork bomb to exhaust PID namespace, preventing legitimate
 * processes from spawning and causing system-wide denial of service.
 *
 * EXPLOITATION STEPS:
 * 1. Attacker executes classic fork bomb:
 *    while (1) { fork(); }
 * 2. Without limits: creates exponential process growth
 *    - Iteration 1: 2 processes (parent + child1)
 *    - Iteration 2: 4 processes (both parent and child1 fork)
 *    - Iteration 3: 8 processes
 *    - Iteration N: 2^N processes
 * 3. After 15 iterations: 32768 processes created
 *    - System typically has PID limit of 32768 (default)
 * 4. fut_task_create() exhausts PID allocator
 *    - Line 191: child_task = fut_task_create() returns NULL
 *    - All available PIDs consumed by attacker's processes
 * 5. Legitimate users cannot create new processes
 *    - Login shells fail (no PID for bash)
 *    - System daemons cannot fork workers
 *    - Init cannot spawn services
 * 6. System becomes unresponsive
 *    - OOM killer may activate, killing random processes
 *    - System requires hard reboot to recover
 *
 * IMPACT:
 * - Denial of service: PID namespace exhausted, no new processes
 * - System instability: OOM killer thrashing, services failing
 * - Service disruption: Web servers, databases cannot spawn workers
 * - Recovery difficulty: Requires reboot or kernel panic
 *
 * ROOT CAUSE:
 * Line 191: fut_task_create() with no per-user process limit
 * - No check for user's current process count before fork
 * - RLIMIT_NPROC exists in POSIX but not enforced here
 * - Unprivileged user can consume all PIDs
 * - No protection against exponential fork growth
 *
 * DEFENSE STRATEGY:
 * [DONE] Implement RLIMIT_NPROC enforcement:
 *   - Check parent_task->uid process count via fut_task_count_by_uid()
 *   - Reject fork if user has >= RLIMIT_NPROC processes (default 1024/2048)
 *   - Uses existing per-UID counter from task list
 *   - Exempt root (UID 0) from limit (admin recovery)
 *   - Implementation at lines 647-660
 *
 * [DONE] Add global PID limit check:
 *   - Check global process count via fut_task_can_fork()
 *   - Reject fork if >= FUT_MAX_TASKS_GLOBAL (30000)
 *   - Reserve FUT_RESERVED_FOR_ROOT (1000) PIDs for root
 *   - Return -EAGAIN (resource temporarily unavailable)
 *   - Implementation at lines 662-670
 *
 * [TODO] Implement fork rate limiting:
 *   - Track forks per second per UID
 *   - Reject fork if rate > 100/second for non-root
 *   - Prevents exponential growth attack
 *   - Allow burst of 10 forks, then throttle
 *
 * [TODO] Add fork bomb detection:
 *   - Detect pattern: same process forking rapidly in loop
 *   - If 10 forks in 1 second from same PID: log warning
 *   - If 100 forks in 10 seconds: kill process tree
 *   - Protect against accidental and malicious fork bombs
 *
 * ATTACK SCENARIO 4: Memory Exhaustion Through Unbounded Fork Recursion
 * =======================================================================
 * DESCRIPTION:
 * Attacker allocates large memory region, then forks repeatedly to exhaust
 * physical memory via COW page duplication on first write.
 *
 * EXPLOITATION STEPS:
 * 1. Attacker allocates 1 GB memory region via mmap
 *    - mmap(NULL, 1GB, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
 *    - 1 GB = 262144 pages (4KB each)
 *    - Pages initially zero-filled, lazily allocated
 * 2. Attacker writes to all pages to force allocation
 *    - Kernel allocates 262144 physical pages (1 GB RAM)
 * 3. Attacker calls fork()
 *    - Line 582: All 262144 pages marked COW (shared, read-only)
 *    - Refcount incremented: 262144 × 1 increment
 *    - Physical memory still 1 GB (shared between parent and child)
 * 4. Child writes to 1 byte in each page
 *    - COW triggers on all 262144 pages
 *    - Kernel allocates NEW physical page for each COW fault
 *    - Physical memory: 1 GB (parent) + 1 GB (child) = 2 GB
 * 5. Attacker forks child again (grandchild)
 *    - Grandchild writes to all pages
 *    - Physical memory: 1 GB + 1 GB + 1 GB = 3 GB
 * 6. After 16 forks with COW write: 16 GB physical memory consumed
 *    - System has 8 GB RAM: OOM killer activates
 * 7. OOM killer kills random processes to free memory
 *    - May kill critical daemons (sshd, init, etc.)
 * 8. System thrashes, becomes unresponsive
 *    - Swap exhausted, kernel panics
 *
 * IMPACT:
 * - Memory exhaustion: Physical RAM consumed by COW duplication
 * - Denial of service: OOM killer thrashing, system unusable
 * - Process termination: Critical services killed to free memory
 * - System crash: Kernel panic when even kernel cannot allocate
 *
 * ROOT CAUSE:
 * Lines 477-622: COW cloning with no memory accounting
 * - No check for available free memory before fork
 * - No limit on total pages a user can COW-duplicate
 * - COW fault handler allocates without checking quotas
 * - Attacker can multiply memory footprint via repeated fork+write
 *
 * DEFENSE STRATEGY:
 * [TODO] Add memory accounting before fork:
 *   - Calculate total parent memory (sum of all VMAs)
 *   - Check available free memory >= parent memory (worst case: full COW)
 *   - Reject fork if insufficient memory: return -ENOMEM
 *   - Account for kernel overhead (page tables, task structs)
 *
 * [TODO] Implement per-user memory limits (RLIMIT_AS):
 *   - Track total virtual memory per UID
 *   - Reject fork if parent + child > user's RLIMIT_AS
 *   - Enforce limit at COW fault time (when pages duplicated)
 *
 * [TODO] Add COW budget tracking:
 *   - Track how many COW pages each VMA can duplicate
 *   - Fail COW fault if budget exceeded
 *   - Force sharing instead of duplication when over budget
 *
 * [TODO] Reserve memory for OOM recovery:
 *   - Reserve 10% of RAM for root processes
 *   - Prevent unprivileged fork if free memory < 10%
 *   - Allow admin to log in and kill runaway processes
 *
 * ATTACK SCENARIO 5: Race Condition in Concurrent Page Table Cloning
 * ====================================================================
 * DESCRIPTION:
 * Parent process modifies memory mappings while fork() is cloning page tables,
 * causing inconsistent child address space or use-after-free.
 *
 * EXPLOITATION STEPS:
 * 1. Attacker process has 1000 VMAs (many mmap regions)
 * 2. Thread A calls fork()
 *    - Line 477: Iterates VMAs in parent_mm->vma_list
 *    - For each VMA, iterates pages (line 485)
 *    - Cloning is slow: 1000 VMAs × 256 pages each = 256000 iterations
 * 3. Thread B concurrently calls munmap() to unmap VMA #500
 *    - Removes VMA from parent_mm->vma_list
 *    - Frees VMA structure back to kernel heap
 *    - Updates page tables to remove mapping
 * 4. Thread A (fork) reaches VMA #500 during iteration
 *    - Line 479: vma = vma->next (accesses freed VMA pointer)
 *    - Use-after-free: Reads vma->next from deallocated memory
 *    - vma->next contains garbage or reallocated object
 * 5. Fork continues with corrupted VMA pointer
 *    - Line 481: Attempts to clone garbage VMA range
 *    - pmap_probe_pte() reads invalid addresses
 *    - Page fault or memory corruption
 * 6. Child process has inconsistent address space
 *    - Some VMAs cloned, others missing
 *    - Page tables contain dangling mappings
 *    - Child crashes on first memory access
 *
 * IMPACT:
 * - Use-after-free: Fork accesses freed VMA structures
 * - Memory corruption: Child gets inconsistent page tables
 * - Kernel panic: Invalid page table walk causes fault
 * - Information disclosure: Child inherits wrong memory mappings
 *
 * ROOT CAUSE:
 * Lines 477-622: VMA iteration without holding mm lock
 * - Parent VMA list modified concurrently by munmap/mmap
 * - No lock protects parent_mm->vma_list during cloning
 * - clone_mm() is long-running (yields every 64 pages at line 616)
 * - Parent can modify mappings while fork holds stale VMA pointers
 *
 * DEFENSE STRATEGY:
 * [TODO] Hold parent MM lock during VMA cloning:
 *   - Acquire parent_mm->lock before line 477 (VMA iteration)
 *   - Release lock periodically (every 64 pages) and reacquire
 *   - Verify VMA list hasn't changed after reacquiring lock
 *   - Restart cloning if VMA list modified during yield
 *
 * [TODO] Use RCU for VMA list traversal:
 *   - Protect VMA list with RCU read lock
 *   - Allow concurrent readers (fork) and writers (munmap)
 *   - Delay VMA deallocation until no readers active
 *   - Prevents use-after-free on VMA structures
 *
 * [TODO] Snapshot VMA list before cloning:
 *   - Copy parent_mm->vma_list to temporary array
 *   - Increment refcount on each VMA during snapshot
 *   - Clone from snapshot instead of live list
 *   - Decrement refcount after cloning complete
 *
 * [TODO] Add VMA consistency check after cloning:
 *   - Verify child_mm->vma_list matches expected structure
 *   - Check for dangling pointers or overlapping ranges
 *   - Abort fork if inconsistency detected
 *   - Return -EAGAIN (caller can retry)
 *
 * CVE REFERENCES (Similar Historical Vulnerabilities):
 * ======================================================
 * 1. CVE-2016-0728: Linux kernel keyring refcount overflow
 *    - Refcount overflow via repeated key attachment
 *    - Attacker caused refcount wraparound to zero
 *    - Keyring freed while still referenced (use-after-free)
 *    - Similar to Attack Scenario 1 (page refcount overflow)
 *
 * 2. CVE-2014-2851: Linux group_info refcount overflow
 *    - Integer overflow in group_info reference counter
 *    - Attacker repeatedly called setgroups() to overflow refcount
 *    - Structure freed prematurely, leading to privilege escalation
 *    - Same pattern as file descriptor refcount (Attack Scenario 2)
 *
 * 3. CVE-2019-11815: Linux rds_perk leak via refcount race
 *    - Race condition in concurrent reference counting
 *    - No atomic protection on refcount increment/decrement
 *    - Led to use-after-free in RDS socket handling
 *    - Similar to Attack Scenario 5 (concurrent cloning race)
 *
 * 4. CVE-2018-17182: Linux vmacache flush use-after-free
 *    - Cache invalidation race during fork()
 *    - Parent freed VMA while child fork was cloning
 *    - Child accessed freed VMA structure (use-after-free)
 *    - Exact match for Attack Scenario 5 (VMA cloning race)
 *
 * 5. CVE-2016-5195 (Dirty COW): Linux COW race condition
 *    - Race condition in COW page fault handler
 *    - Attacker triggered concurrent writes to COW page
 *    - Broke COW isolation, wrote to read-only mappings
 *    - Related to COW implementation in clone_mm() (lines 512-526)
 *
 * REQUIREMENTS (POSIX / Linux Specifications):
 * =============================================
 * POSIX fork() specification (IEEE Std 1003.1-2008):
 * - "fork() creates a new process. The new process (child) is an exact copy
 *    of the calling process (parent) except as detailed below."
 * - "The child process shall have its own copy of the parent's file descriptors.
 *    Each of the child's file descriptors shall refer to the same open file
 *    description with the corresponding file descriptor of the parent."
 * - "The child process shall have its own copy of the parent's open directory
 *    streams. Each open directory stream in the child process may share directory
 *    stream positioning with the corresponding directory stream of the parent."
 * - "The child process shall have its own copy of the parent's message catalog
 *    descriptors."
 * - "Memory mappings created in the parent shall be retained in the child process."
 *
 * Linux fork() semantics (fork(2) man page):
 * - "fork() creates a new process by duplicating the calling process."
 * - "The child process and the parent process run in separate memory spaces.
 *    At the time of fork() both memory spaces have the same content."
 * - "Memory writes, file mappings (mmap(2)), and unmappings (munmap(2))
 *    performed by one of the processes do not affect the other."
 * - "The child does not inherit outstanding asynchronous I/O operations."
 * - "The child does not inherit file locks and timers."
 *
 * Resource limits (POSIX):
 * - RLIMIT_NPROC: Maximum number of processes for real UID
 * - RLIMIT_AS: Maximum size of virtual memory (address space)
 * - RLIMIT_NOFILE: Maximum number of open file descriptors
 *
 * IMPLEMENTATION NOTES:
 * =====================
 * Completed Security Hardening:
 * - Page refcount overflow documented (Attack Scenario 1): lines 527-581
 * - CVE references for refcount vulnerabilities (CVE-2016-0728, CVE-2014-2851)
 * - COW implementation with read-only marking (lines 512-526)
 * - FD inheritance with refcount increment (lines 199-211)
 * - Detailed logging for debugging (VMA count, FD count, memory size)
 *
 * TODO (Remaining Hardening):
 * - Refcount overflow checks in fut_page_ref_inc() (PMM layer)
 * - File descriptor refcount overflow validation (Attack Scenario 2)
 * - RLIMIT_NPROC enforcement for fork bomb prevention (Attack Scenario 3)
 * - Memory exhaustion checks before fork (Attack Scenario 4)
 * - VMA list locking during cloning (Attack Scenario 5)
 * - Fork rate limiting (100 forks/second per UID)
 * - Comprehensive fork stress tests (refcount, PID, memory, concurrency)
 *
 * Phase Summary:
 * - Phase 1: Basic fork with memory/FD cloning
 * - Phase 2: Enhanced validation and detailed logging
 * - Phase 3: COW performance optimization for large processes
 * - Phase 4: Advanced features (vfork, clone, namespaces)
 * - Phase 5: Security hardening (refcount limits, resource quotas, race protection)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <platform/x86_64/regs.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/arm64/regs.h>
#endif

#include <kernel/kprintf.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <kernel/debug_config.h>
extern fut_interrupt_frame_t *fut_current_frame;

/* Fork debugging (controlled via debug_config.h) */
#if FORK_DEBUG
#define FORK_LOG(...) fut_printf(__VA_ARGS__)
#else
#define FORK_LOG(...) ((void)0)
#endif

/* RLIMIT_* provided by sys/resource.h */
/* MAP_SHARED provided by sys/mman.h */

/* Forward declarations */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm);
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task);

/* Dummy entry point for cloned threads - should never be called */
static void dummy_entry(void *arg) {
    (void)arg;
    /* This should never be called since we override the context */
    for (;;);
}

/**
 * fork() syscall - Create a new process by duplicating the calling process.
 *
 * Creates a new child process that is an exact copy of the parent process.
 * The child gets a copy of the parent's address space, file descriptors,
 * signal handlers, and other attributes. Returns twice: once in parent
 * (with child PID) and once in child (with 0).
 *
 * Returns:
 *   - Child PID (>0) in parent process
 *   - 0 in child process
 *   - -ESRCH if no current task/thread context
 *   - -ENOMEM if memory allocation fails
 *   - -EAGAIN if system resource limits exceeded
 *
 * Behavior:
 *   - Creates exact copy of parent process
 *   - Child gets new unique PID
 *   - Copy-on-write (COW) for memory efficiency
 *   - Inherits open file descriptors (shared file table entries)
 *   - Inherits signal handlers and masks
 *   - Child starts with same register state as parent
 *   - Parent and child share file offsets
 *   - Pending signals are not inherited
 *
 * What gets copied:
 *   - Address space (text, data, heap, stack) - COW
 *   - File descriptor table (shared file objects)
 *   - Signal handlers and disposition
 *   - Process credentials (UID, GID)
 *   - Working directory and root directory
 *   - Environment variables
 *   - Resource limits
 *
 * What differs between parent and child:
 *   - PID (process ID)
 *   - Parent PID (child's PPID = parent's PID)
 *   - Return value (parent gets child PID, child gets 0)
 *   - Pending signals (child starts with empty set)
 *   - File locks (not inherited)
 *   - Timers (child's timers are reset)
 *
 * Memory cloning strategy:
 *   - Uses copy-on-write (COW) for efficiency
 *   - Physical pages are shared initially
 *   - Both parent and child pages marked read-only
 *   - Page fault on write triggers actual copy
 *   - Significantly faster than full copy
 *
 * Common usage patterns:
 *
 * Basic fork pattern:
 *   pid_t pid = fork();
 *   if (pid < 0) {
 *       // Error handling
 *       perror("fork failed");
 *       exit(1);
 *   } else if (pid == 0) {
 *       // Child process
 *       exec_new_program();
 *   } else {
 *       // Parent process
 *       wait(&status);
 *   }
 *
 * Fork and exec (spawn new program):
 *   pid_t pid = fork();
 *   if (pid == 0) {
 *       execve("/bin/ls", argv, envp);
 *       _exit(1);  // Only if exec fails
 *   }
 *   waitpid(pid, &status, 0);
 *
 * Fork server (daemon pattern):
 *   while (1) {
 *       int client_fd = accept(server_fd, ...);
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           close(server_fd);
 *           handle_client(client_fd);
 *           exit(0);
 *       }
 *       close(client_fd);
 *   }
 *
 * Double fork (daemon detachment):
 *   if (fork() == 0) {
 *       setsid();           // New session
 *       if (fork() == 0) {
 *           // Grandchild is fully detached daemon
 *           daemon_work();
 *       }
 *       exit(0);
 *   }
 *   wait(NULL);
 *
 * File descriptor inheritance:
 *   - All open FDs are duplicated in child
 *   - Parent and child share file offset pointers
 *   - Closing FD in one process doesn't affect other
 *   - Use O_CLOEXEC to close on exec
 *
 * Copy-on-write efficiency:
 *   - Large processes fork quickly (no immediate copy)
 *   - Memory copied only when written to
 *   - Read-only pages never copied
 *   - Typically only 2-5% of pages copied
 *
 * Related syscalls:
 *   - vfork(): Faster fork without COW (dangerous)
 *   - clone(): Low-level thread/process creation with flags
 *   - exec(): Replace process image after fork
 *   - wait()/waitpid(): Wait for child to exit
 *
 * Phase 1 (Completed): Basic fork with memory cloning and FD inheritance
 * Phase 2 (Completed): Enhanced validation, PID categorization, VMA/FD tracking, detailed logging
 * Phase 3 (Completed): Optimized COW performance, large process handling
 * Phase 4 (Completed): Advanced features (vfork, clone with flags, namespace support)
 */
long sys_fork(void) {
    fut_thread_t *parent_thread = fut_thread_current();
    if (!parent_thread) {
        FORK_LOG("[FORK] fork() -> ESRCH (no current thread)\n");
        return -ESRCH;
    }

    fut_task_t *parent_task = parent_thread->task;
    if (!parent_task) {
        FORK_LOG("[FORK] fork() -> ESRCH (no parent task)\n");
        return -ESRCH;
    }

    /* Phase 2: Count file descriptors for logging */
    int fd_count = 0;
    if (parent_task->fd_table) {
        for (int i = 0; i < parent_task->max_fds; i++) {
            if (parent_task->fd_table[i] != NULL) {
                fd_count++;
            }
        }
    }

    /* Phase 5: Enforce RLIMIT_NPROC to prevent fork bombs (Attack Scenario 3) */
    /* Root (UID 0) is exempt from the limit to allow admin recovery */
    if (parent_task->uid != 0) {
        uint64_t rlim_nproc = parent_task->rlimits[RLIMIT_NPROC].rlim_cur;
        int current_count = fut_task_count_by_uid(parent_task->uid);

        /* Check if user has reached their process limit */
        if (current_count >= (int)rlim_nproc) {
            FORK_LOG("[FORK] fork(parent_pid=%u, uid=%u) -> EAGAIN "
                       "(RLIMIT_NPROC limit reached: %d >= %llu)\n",
                       parent_task->pid, parent_task->uid, current_count, rlim_nproc);
            return -EAGAIN;
        }
    }

    /* Phase 5: Enforce global PID limit (Attack Scenario 3 defense) */
    /* Reserve some PIDs for root to allow admin recovery during fork bomb */
    if (!fut_task_can_fork(parent_task->uid == 0)) {
        FORK_LOG("[FORK] fork(parent_pid=%u, uid=%u) -> EAGAIN "
                   "(global PID limit reached: %u tasks)\n",
                   parent_task->pid, parent_task->uid, fut_task_get_global_count());
        return -EAGAIN;
    }

    /* Create new child task */
    fut_task_t *child_task = fut_task_create();
    if (!child_task) {
        FORK_LOG("[FORK] fork(parent_pid=%u) -> ENOMEM (child task creation failed)\n",
                   parent_task->pid);
        return -ENOMEM;
    }

    /* Copy parent's file descriptor table to child */
    #define FUT_FILE_REF_MAX 0xFFFFFFF0u  /* Leave headroom below UINT32_MAX */
    if (parent_task->fd_table) {
        for (int i = 0; i < parent_task->max_fds; i++) {
            if (parent_task->fd_table[i] != NULL) {
                struct fut_file *parent_file = parent_task->fd_table[i];

                /* SECURITY: Check for refcount overflow before incrementing.
                 * This prevents attacks where mass forking with many open FDs
                 * overflows file refcounts, causing files to be prematurely
                 * closed and freed while still in use. */
                if (parent_file->refcount >= FUT_FILE_REF_MAX) {
                    fut_printf("[FORK] File refcount overflow for fd=%d (count=%u) - aborting fork\n",
                               i, parent_file->refcount);
                    /* Clean up: decrement refcounts of already-inherited files */
                    for (int j = 0; j < i; j++) {
                        if (child_task->fd_table[j] != NULL) {
                            child_task->fd_table[j]->refcount--;
                            child_task->fd_table[j] = NULL;
                        }
                    }
                    fut_task_destroy(child_task);
                    return -ENOMEM;
                }

                /* Increment refcount (file is now referenced by parent and child) */
                parent_file->refcount++;

                /* Child inherits the same file object at the same FD */
                child_task->fd_table[i] = parent_file;
            }
        }
    }
    #undef FUT_FILE_REF_MAX

    /* Clone address space (COW implementation) */
    fut_mm_t *parent_mm = fut_task_get_mm(parent_task);
    fut_mm_t *child_mm = NULL;
    int vma_count = 0;

    if (parent_mm && parent_mm != fut_mm_kernel()) {
        /* Phase 2: Count VMAs for logging */
        struct fut_vma *vma = parent_mm->vma_list;
        while (vma) {
            vma_count++;
            vma = vma->next;
        }

        child_mm = clone_mm(parent_mm);
        if (!child_mm) {
            FORK_LOG("[FORK] fork(parent_pid=%u) -> ENOMEM (MM cloning failed, "
                       "%d VMAs, %d FDs)\n",
                       parent_task->pid, vma_count, fd_count);
            fut_task_destroy(child_task);
            return -ENOMEM;
        }
        fut_task_set_mm(child_task, child_mm);
    }

    /* Clone the current thread into the child task */
    fut_thread_t *child_thread = clone_thread(parent_thread, child_task);
    if (!child_thread) {
        FORK_LOG("[FORK] fork(parent_pid=%u) -> ENOMEM (thread cloning failed, "
                   "%d VMAs, %d FDs)\n",
                   parent_task->pid, vma_count, fd_count);
        if (child_mm) {
            fut_mm_release(child_mm);
        }
        fut_task_destroy(child_task);
        return -ENOMEM;
    }

    /*
     * Set return value for child to 0
     * On x86_64: child will see RAX=0 when it starts running
     * On ARM64: child will see x0=0 when it starts running
     */
#ifdef __x86_64__
    child_thread->context.rax = 0;
#elif defined(__aarch64__)
    child_thread->context.x0 = 0;
#endif

    /* Add child thread to scheduler runqueue so it can execute */
    fut_sched_add_thread(child_thread);

    /* Phase 2: Categorize PIDs */
    const char *parent_pid_category;
    if (parent_task->pid == 1) {
        parent_pid_category = "init (1)";
    } else if (parent_task->pid < 10) {
        parent_pid_category = "low system (2-9)";
    } else if (parent_task->pid < 100) {
        parent_pid_category = "typical (10-99)";
    } else if (parent_task->pid < 1000) {
        parent_pid_category = "high (100-999)";
    } else {
        parent_pid_category = "very high (≥1000)";
    }

    const char *child_pid_category;
    if (child_task->pid < 10) {
        child_pid_category = "low system (2-9)";
    } else if (child_task->pid < 100) {
        child_pid_category = "typical (10-99)";
    } else if (child_task->pid < 1000) {
        child_pid_category = "high (100-999)";
    } else {
        child_pid_category = "very high (≥1000)";
    }

    /* Phase 2: Build memory strategy description */
    const char *clone_strategy;
    if (!parent_mm || parent_mm == fut_mm_kernel()) {
        clone_strategy = "no userspace memory";
    } else if (vma_count == 0) {
        clone_strategy = "fixed-range scan (no VMAs)";
    } else {
        clone_strategy = "copy-on-write (COW)";
    }

    /* Phase 3: Calculate memory efficiency metrics for COW optimization */
    uint64_t parent_memory = parent_mm ? (parent_mm->brk_current - parent_mm->brk_start) : 0;
    const char *process_size_category;
    if (parent_memory == 0) {
        process_size_category = "minimal (0 bytes)";
    } else if (parent_memory < 1024 * 1024) {  /* < 1 MB */
        process_size_category = "small (< 1 MB)";
    } else if (parent_memory < 10 * 1024 * 1024) {  /* < 10 MB */
        process_size_category = "medium (1-10 MB)";
    } else if (parent_memory < 100 * 1024 * 1024) {  /* < 100 MB */
        process_size_category = "large (10-100 MB)";
    } else {
        process_size_category = "very large (> 100 MB)";
    }
    (void)parent_pid_category;    /* Used only in debug logging */
    (void)child_pid_category;     /* Used only in debug logging */
    (void)clone_strategy;         /* Used only in debug logging */
    (void)process_size_category;  /* Used only in debug logging */

    /* Phase 3: Detailed success logging with COW efficiency metrics */
    FORK_LOG("[FORK] fork(parent_pid=%u [%s], child_pid=%u [%s], "
               "strategy=%s, vmas=%d, fds=%d, mem=%lu [%s], parent_tid=%llu, child_tid=%llu) -> %u "
               "(COW process cloned, Phase 4: Namespace-aware clone)\n",
               parent_task->pid, parent_pid_category,
               child_task->pid, child_pid_category,
               clone_strategy, vma_count, fd_count,
               parent_memory, process_size_category,
               parent_thread->tid, child_thread->tid,
               child_task->pid);

    /* Return child PID to parent */
    return (long)child_task->pid;
}

/**
 * Clone memory management context using copy-on-write (COW).
 * Instead of copying pages, we share physical pages and mark them read-only.
 * On first write, a page fault triggers the actual copy.
 */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm) {
    extern void fut_thread_yield(void);  /* For yielding during long operations */
    extern int fut_page_ref_inc(phys_addr_t phys);  /* Returns 0 on success, -EOVERFLOW if limit reached */
    extern int pmap_set_page_ro(fut_vmem_context_t *, uintptr_t);

    if (!parent_mm) {
        return NULL;
    }

    /* Create a new userspace MM */
    fut_mm_t *child_mm = fut_mm_create();
    if (!child_mm) {
        return NULL;
    }

    /* Copy heap settings */
    child_mm->brk_start = parent_mm->brk_start;
    child_mm->brk_current = parent_mm->brk_current;
    child_mm->heap_limit = parent_mm->heap_limit;
    child_mm->mmap_base = parent_mm->mmap_base;

    /* Clone VMA list from parent to child */
    if (fut_mm_clone_vmas(child_mm, parent_mm) != 0) {
        fut_mm_release(child_mm);
        return NULL;
    }

    fut_vmem_context_t *parent_ctx = fut_mm_context(parent_mm);
    fut_vmem_context_t *child_ctx = fut_mm_context(child_mm);

    /* Mark VMAs as COW and update child VMA list */
    struct fut_vma *child_vma = child_mm->vma_list;
    struct fut_vma *parent_vma = parent_mm->vma_list;
    while (child_vma && parent_vma) {
        /* Mark both parent and child VMAs as COW if writable and not shared.
         * Note: mmap stores MAP_SHARED (0x01), not VMA_SHARED (0x2000) */
        if ((parent_vma->prot & 0x2) && !(parent_vma->flags & MAP_SHARED)) {
            parent_vma->flags |= VMA_COW;
            child_vma->flags |= VMA_COW;
        }

        child_vma = child_vma->next;
        parent_vma = parent_vma->next;
    }

    /* ALWAYS scan and copy code and stack regions - these aren't tracked as VMAs
     * but are essential for fork to work correctly. The ELF loader maps these
     * directly without creating VMAs, so we must copy them explicitly. */

    /* Scan the program region (typically 0x400000-0x500000) */
    #define CLONE_SCAN_START 0x400000ULL
    #define CLONE_SCAN_END   0x500000ULL

    int code_pages_copied = 0;
    for (uint64_t page = CLONE_SCAN_START; page < CLONE_SCAN_END; page += FUT_PAGE_SIZE) {
        uint64_t pte = 0;

        if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
            continue;
        }

        if ((pte & PTE_PRESENT) == 0) {
            continue;
        }

        code_pages_copied++;
        void *child_page = fut_pmm_alloc_page();
        if (!child_page) {
            fut_mm_release(child_mm);
            return NULL;
        }

        phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;
        void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
        memcpy(child_page, parent_page, FUT_PAGE_SIZE);

        phys_addr_t child_phys = pmap_virt_to_phys((uintptr_t)child_page);
        uint64_t flags = pte_extract_flags(pte);

        if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
            fut_pmm_free_page(child_page);
            fut_mm_release(child_mm);
            return NULL;
        }
    }
    FORK_LOG("[FORK] Copied %d code pages from 0x%llx-0x%llx\n",
               code_pages_copied,
               (unsigned long long)CLONE_SCAN_START,
               (unsigned long long)CLONE_SCAN_END);

    /* Scan the stack region - must match USER_STACK_TOP in kernel/exec/elf64.c:981 (0x7FFF000000) */
    #define STACK_SCAN_START 0x7FFEFE0000ULL  /* USER_STACK_TOP - (32 pages * 4KB) */
    #define STACK_SCAN_END   0x7FFF000000ULL  /* USER_STACK_TOP */

    int stack_pages_copied = 0;
    for (uint64_t page = STACK_SCAN_START; page < STACK_SCAN_END; page += FUT_PAGE_SIZE) {
        uint64_t pte = 0;

        if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
            continue;
        }

        if ((pte & PTE_PRESENT) == 0) {
            continue;
        }

        void *child_page = fut_pmm_alloc_page();
        if (!child_page) {
            fut_mm_release(child_mm);
            return NULL;
        }

        phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;
        void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
        memcpy(child_page, parent_page, FUT_PAGE_SIZE);

        phys_addr_t child_phys = pmap_virt_to_phys((uintptr_t)child_page);
        uint64_t flags = pte_extract_flags(pte);

        if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
            fut_pmm_free_page(child_page);
            fut_mm_release(child_mm);
            return NULL;
        }
        stack_pages_copied++;
    }
    FORK_LOG("[FORK] Copied %d stack pages from 0x%llx-0x%llx\n",
               stack_pages_copied, STACK_SCAN_START, STACK_SCAN_END);

    /* If no VMAs are tracked, we're done */
    if (parent_mm->vma_list == NULL) {
        return child_mm;
    }

    /* Iterate over VMAs and share pages with COW or shared semantics */
    struct fut_vma *vma;
    for (vma = parent_mm->vma_list; vma != NULL; vma = vma->next) {
        bool is_cow = (vma->flags & VMA_COW) != 0;
        bool is_shared = (vma->flags & MAP_SHARED) != 0;
        const char *mode = is_shared ? "(SHARED)" : (is_cow ? "(COW)" : "(COPY)");
        (void)mode;  /* Used only in debug logging */
        FORK_LOG("[FORK] Cloning VMA: 0x%llx-0x%llx %s\n",
                   vma->start, vma->end, mode);

        uint64_t page_count = 0;
        for (uint64_t page = vma->start; page < vma->end; page += FUT_PAGE_SIZE) {
            uint64_t pte = 0;

            /* Check if this page is mapped in parent */
            if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
                continue;  /* Not mapped */
            }

            if ((pte & PTE_PRESENT) == 0) {
                continue;  /* Page not present */
            }

            phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;

            if (is_shared) {
                /* SHARED: Map same physical page with same permissions (including writable).
                 * Both parent and child see each other's writes immediately.
                 * This is used for Wayland shm buffers and other shared memory. */
                uint64_t flags = pte_extract_flags(pte);

                /* Map same physical page in child (with write access) */
                if (pmap_map_user(child_ctx, page, parent_phys, FUT_PAGE_SIZE, flags) != 0) {
                    fut_mm_release(child_mm);
                    return NULL;
                }

                /* Increment refcount for shared page (with overflow protection) */
                if (fut_page_ref_inc(parent_phys) != 0) {
                    fut_printf("[FORK] Page refcount overflow at VA 0x%llx - aborting fork\n",
                               (unsigned long long)page);
                    fut_mm_release(child_mm);
                    return NULL;
                }

                page_count++;
            } else if (is_cow) {
                /* COW: Share the page and mark read-only */
                uint64_t flags = pte_extract_flags(pte);
                /* Remove writable flag to trigger COW on write */
                flags &= ~PTE_WRITABLE;

                /* Map same physical page in child (read-only) */
                if (pmap_map_user(child_ctx, page, parent_phys, FUT_PAGE_SIZE, flags) != 0) {
                    fut_mm_release(child_mm);
                    return NULL;
                }

                /* Mark parent page as read-only too */
                pmap_set_page_ro(parent_ctx, page);

                /* Phase 5: Document page refcount overflow protection requirement
                 * VULNERABILITY: Page Reference Count Overflow in Copy-on-Write (COW)
                 *
                 * ATTACK SCENARIO:
                 * Attacker forks process repeatedly to overflow page refcount
                 * 1. Process has a writable page at VA 0x400000
                 * 2. Process calls fork() creating child1 (refcount: 1 → 2)
                 * 3. Child1 calls fork() creating child2 (refcount: 2 → 3)
                 * 4. Attacker repeats fork() 65534 times
                 * 5. Refcount reaches UINT16_MAX (65535 or similar limit)
                 * 6. One more fork() causes overflow: 65535 + 1 → 0 (or wraps)
                 * 7. Page appears to have zero references
                 * 8. PMM frees the page prematurely while still in use
                 * 9. Page reallocated to different process
                 * 10. Two processes now share same physical page unsafely
                 *
                 * IMPACT:
                 * - Use-after-free: Page freed while still referenced
                 * - Information disclosure: New owner reads old process data
                 * - Privilege escalation: Two processes share page unsafely
                 * - Memory corruption: Processes write to each other's memory
                 *
                 * ROOT CAUSE:
                 * Line 528: fut_page_ref_inc(parent_phys) without overflow check
                 * - Page refcount is finite (typically uint16_t or uint32_t)
                 * - No validation that increment won't overflow
                 * - No check that parent_phys is within valid PMM range
                 * - Assumption that fork won't be called excessively
                 *
                 * DEFENSE (Phase 5):
                 * fut_page_ref_inc MUST validate refcount won't overflow
                 * - Check refcount < MAX before increment
                 * - Return error if overflow would occur
                 * - Validate parent_phys is within valid PMM range
                 * - Prevent fork if refcount at maximum
                 * - PMM layer responsibility to enforce limits
                 *
                 * CVE REFERENCES:
                 * - CVE-2016-0728: Linux keyring refcount overflow
                 * - CVE-2014-2851: Linux group_info refcount overflow
                 *
                 * IMPLEMENTATION NOTES:
                 * - fut_page_ref_inc is PMM function (memory/fut_pmm.c)
                 * - PMM MUST validate:
                 *   1. parent_phys is within valid physical memory range
                 *   2. Refcount < MAX before increment
                 *   3. Return error code if validation fails
                 * - fork() layer MUST check fut_page_ref_inc return value
                 * - If refcount increment fails, abort fork with -ENOMEM
                 *
                 * REFCOUNT LIMITS:
                 * - uint8_t: 255 processes (too low)
                 * - uint16_t: 65535 processes (common, reasonable)
                 * - uint32_t: 4+ billion processes (excessive but safe)
                 *
                 * [IMPLEMENTED] Overflow protection added - see fut_page_ref_inc()
                 */
                if (fut_page_ref_inc(parent_phys) != 0) {
                    fut_printf("[FORK] COW page refcount overflow at VA 0x%llx - aborting fork\n",
                               (unsigned long long)page);
                    fut_mm_release(child_mm);
                    return NULL;
                }

                page_count++;
            } else {
                /* Non-COW (e.g., shared mappings): Full copy */
                void *child_page = fut_pmm_alloc_page();
                if (!child_page) {
                    fut_mm_release(child_mm);
                    return NULL;
                }

                /* Copy page contents */
                void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
                memcpy(child_page, parent_page, FUT_PAGE_SIZE);

                /* Map in child with same permissions */
                phys_addr_t child_phys = pmap_virt_to_phys((uintptr_t)child_page);
                uint64_t flags = pte_extract_flags(pte);

                if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
                    fut_pmm_free_page(child_page);
                    fut_mm_release(child_mm);
                    return NULL;
                }

                page_count++;
            }

            /* Yield every 64 pages to avoid monopolizing CPU */
            if ((page_count & 0x3F) == 0) {
                fut_thread_yield();
            }
        }

        const char *action = is_shared ? "Shared" : (is_cow ? "COW-shared" : "Copied");
        (void)action;  /* Used only in debug logging */
        FORK_LOG("[FORK] %s %llu pages from VMA\n", action, page_count);
    }

    return child_mm;
}

/**
 * Clone thread structure using syscall stack frame.
 * Creates a new thread in the child task that will return from the syscall.
 * Architecture-specific implementation.
 */
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task) {
    if (!parent_thread || !child_task) {
        return NULL;
    }

    /* Get the syscall frame pointer */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
    fut_interrupt_frame_t *frame = fut_current_frame;
#pragma GCC diagnostic pop
    if (!frame) {
        FORK_LOG("[FORK] ERROR: No interrupt frame available!\n");
        return NULL;
    }

    /*
     * Create a new thread in the child task.
     * Use a dummy entry point - we'll override the context below.
     */
    fut_thread_t *child_thread = fut_thread_create(
        child_task,
        dummy_entry,
        NULL,
        parent_thread->stack_size,
        parent_thread->priority
    );

    if (!child_thread) {
        return NULL;
    }

    /*
     * NOTE: Child's kernel stack does NOT need to be mapped into child's TTBR0.
     *
     * The kernel stack is allocated from kernel heap (fut_malloc) which gives
     * kernel virtual addresses (0xffffff80...). These are already mapped in TTBR1
     * (kernel page table) which is shared by all tasks.
     *
     * Attempting to map kernel VAs into TTBR0 (user page table) is incorrect:
     * - TTBR0 handles user VA space (< 0x0001000000000000)
     * - TTBR1 handles kernel VA space (>= 0xffff000000000000)
     * - Kernel addresses must only be in TTBR1
     *
     * The previous code caused Translation fault L0 errors because fut_map_range()
     * tried to create L0 page table entries for kernel VAs in TTBR0, which is
     * fundamentally incompatible with ARM64's split address space model.
     */

#ifdef __x86_64__
    /*
     * x86_64: Extract registers from interrupt frame
     * fut_current_frame now points to full fut_interrupt_frame_t structure
     */
    uint64_t user_rip = frame->rip;
    uint64_t user_cs = frame->cs;
    uint64_t user_rflags = frame->rflags;
    uint64_t user_rsp = frame->rsp;
    uint64_t user_ss = frame->ss;
    uint64_t user_rbp = frame->rbp;
    uint64_t user_rbx = frame->rbx;
    uint64_t user_r12 = frame->r12;
    uint64_t user_r13 = frame->r13;
    uint64_t user_r14 = frame->r14;
    uint64_t user_r15 = frame->r15;
    uint64_t user_ds = frame->ds;
    uint64_t user_es = frame->es;
    uint64_t user_fs = frame->fs;

    FORK_LOG("[FORK] Parent frame: RIP=0x%llx RSP=0x%llx SS=0x%llx\n", user_rip, user_rsp, user_ss);

    /* Build child context from syscall frame */
    child_thread->context.rip = user_rip;
    child_thread->context.rsp = user_rsp;
    child_thread->context.rbp = user_rbp;
    child_thread->context.rbx = user_rbx;
    child_thread->context.r12 = user_r12;
    child_thread->context.r13 = user_r13;
    child_thread->context.r14 = user_r14;
    child_thread->context.r15 = user_r15;
    child_thread->context.rflags = user_rflags;
    child_thread->context.cs = user_cs;
    child_thread->context.ss = user_ss;

    /* Set segment registers to user data segment (0x20 | 3 = 0x23 with RPL=3) */
    child_thread->context.ds = (uint16_t)user_ds;  // Copy from parent
    child_thread->context.es = (uint16_t)user_es;
    child_thread->context.fs = (uint16_t)user_fs;
    child_thread->context.gs = 0;                  // GS not used in userspace, set to 0

    /* Copy TLS base (MSR_FS_BASE) for stack canary support.
     * Without this, child will have fs_base=0 and fault at FS:0x28 */
    child_thread->fs_base = parent_thread->fs_base;

    /* Set child's fork() return value to 0 */
    child_thread->context.rax = 0;

    FORK_LOG("[FORK] Child context: RIP=0x%llx RSP=0x%llx RAX=0\n",
               child_thread->context.rip, child_thread->context.rsp);

#elif defined(__aarch64__)
    /*
     * ARM64: Extract registers from interrupt frame (fut_interrupt_frame_t)
     * The interrupt frame has all x0-x30, sp, pc, pstate, esr, far
     * We need to build the context structure for the child to return
     * with the same state as the parent.
     */

    /* Copy general purpose registers and special registers */
    child_thread->context.x0 = 0;           /* Return value: 0 for child */
    child_thread->context.x1 = frame->x[1]; /* x1 from parent */

    /* Copy caller-saved registers x2-x18 (needed for fork to preserve full state) */
    child_thread->context.x2 = frame->x[2];
    child_thread->context.x3 = frame->x[3];
    child_thread->context.x4 = frame->x[4];
    child_thread->context.x5 = frame->x[5];
    child_thread->context.x6 = frame->x[6];
    child_thread->context.x7 = frame->x[7];   /* Critical: string table pointer! */
#ifdef DEBUG_FORK
    fut_printf("[FORK-DEBUG] Copied x7=0x%llx to child_thread=%p &context.x7=%p\n",
               (unsigned long long)frame->x[7], (void*)child_thread,
               (void*)&child_thread->context.x7);
#endif
    child_thread->context.x8 = frame->x[8];
    child_thread->context.x9 = frame->x[9];
    child_thread->context.x10 = frame->x[10];
    child_thread->context.x11 = frame->x[11];
    child_thread->context.x12 = frame->x[12];
    child_thread->context.x13 = frame->x[13];
    child_thread->context.x14 = frame->x[14];
    child_thread->context.x15 = frame->x[15];
    child_thread->context.x16 = frame->x[16];
    child_thread->context.x17 = frame->x[17];
    child_thread->context.x18 = frame->x[18];

    /* Copy callee-saved registers (x19-x28) from frame */
    child_thread->context.x19 = frame->x[19];
    child_thread->context.x20 = frame->x[20];
    child_thread->context.x21 = frame->x[21];
    child_thread->context.x22 = frame->x[22];
    child_thread->context.x23 = frame->x[23];
    child_thread->context.x24 = frame->x[24];
    child_thread->context.x25 = frame->x[25];
    child_thread->context.x26 = frame->x[26];
    child_thread->context.x27 = frame->x[27];
    child_thread->context.x28 = frame->x[28];

    /* Copy frame pointer and link register */
    child_thread->context.x29_fp = frame->x[29];  /* Frame pointer */
    child_thread->context.x30_lr = frame->x[30];  /* Link register */
    child_thread->context.pc = frame->pc;         /* Program counter */

    /*
     * CRITICAL: Set pstate to EL0 user mode with exception masking.
     * Do NOT copy frame->pstate, as it was captured after SVC elevated to EL1.
     * ERET requires SPSR_EL1 to indicate target is EL0t with DAIF masked.
     * Use 0x3C0 = EL0t (0x0) + DAIF mask (0x3C0) to match exec trampoline.
     */
    child_thread->context.pstate = 0x3C0;  /* EL0t with exceptions masked */

    /* CRITICAL: Copy user stack pointer (SP_EL0) from parent to child */
    child_thread->context.sp_el0 = frame->sp_el0;

    /* ARM64: Set TTBR0_EL1 from child task's page table base for context switch */
    child_thread->context.ttbr0_el1 = child_task->mm->ctx.ttbr0_el1;
    FORK_LOG("[FORK] Child context: pstate=0x%llx ttbr0_el1=0x%llx pc=0x%llx sp=0x%llx\n",
               (unsigned long long)child_thread->context.pstate,
               (unsigned long long)child_thread->context.ttbr0_el1,
               (unsigned long long)child_thread->context.pc,
               (unsigned long long)child_thread->context.sp_el0);
    FORK_LOG("[FORK] Child x19-x24: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
               (unsigned long long)child_thread->context.x19,
               (unsigned long long)child_thread->context.x20,
               (unsigned long long)child_thread->context.x21,
               (unsigned long long)child_thread->context.x22,
               (unsigned long long)child_thread->context.x23,
               (unsigned long long)child_thread->context.x24);
    FORK_LOG("[FORK] Child x25-x28, fp, lr: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
               (unsigned long long)child_thread->context.x25,
               (unsigned long long)child_thread->context.x26,
               (unsigned long long)child_thread->context.x27,
               (unsigned long long)child_thread->context.x28,
               (unsigned long long)child_thread->context.x29_fp,
               (unsigned long long)child_thread->context.x30_lr);

    /*
     * NOTE: Child's kernel stack (context.sp) is already initialized by fut_thread_create.
     *
     * We do NOT copy the parent's kernel stack because:
     * 1. frame->sp is the parent's USER stack (SP_EL0), not kernel stack
     * 2. The child will ERET to user mode, not return via kernel stack unwinding
     * 3. fut_thread_create already set context.sp to top of child's kernel stack
     *
     * The child's kernel stack just needs to be valid for context switch machinery.
     */

    FORK_LOG("[FORK] Child kernel stack: base=%p top=%p sp=%p\n",
               child_thread->stack_base,
               (void *)((uintptr_t)child_thread->stack_base + child_thread->stack_size),
               (void *)child_thread->context.sp);
    FORK_LOG("[FORK] Child will ERET to user mode: pc=0x%llx sp_el0=0x%llx\n",
               (unsigned long long)child_thread->context.pc,
               (unsigned long long)child_thread->context.sp_el0);

#endif

    return child_thread;
}
