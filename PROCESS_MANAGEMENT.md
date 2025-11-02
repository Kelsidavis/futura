# Futura OS Kernel Process Management and ELF Loading - Complete Analysis

## Executive Summary

Futura OS implements a modern process management subsystem with:
- Task-based process containers supporting multi-threading
- Full ELF64 executable loading with proper address space setup
- fork() and execve() syscalls for process creation and execution
- Copy-on-Write (CoW) memory management for fork efficiency
- x86-64 and ARM64 architecture support

---

## 1. TASK MANAGEMENT (kernel/threading/fut_task.c)

### Core Structure: `fut_task_t`

```c
struct fut_task {
    uint64_t pid;                      // 64-bit Process ID
    struct fut_mm *mm;                 // Address space (memory management context)
    
    // Process tree management
    struct fut_task *parent;           // Parent task
    struct fut_task *first_child;      // Child list head
    struct fut_task *sibling;          // Next sibling in parent list
    fut_waitq_t child_waiters;         // Wait queue for waitpid() callers
    
    // Process state
    enum {
        FUT_TASK_RUNNING = 0,
        FUT_TASK_ZOMBIE,
    } state;
    int exit_code;                     // Exit status (8-bit in low byte)
    int term_signal;                   // Terminating signal (0 if normal exit)
    
    // Thread management
    fut_thread_t *threads;             // Linked list of threads
    uint64_t thread_count;             // Number of threads in task
    
    // Process credentials
    uint32_t uid;                      // User ID (effective UID)
    uint32_t gid;                      // Group ID (effective GID)
    uint32_t ruid;                     // Real UID (for future use)
    uint32_t rgid;                     // Real GID (for future use)
    
    // Signal handling
    sighandler_t signal_handlers[31];  // Signal handlers (index 1-30)
    uint64_t signal_mask;              // Mask of currently blocked signals
    uint64_t signal_handler_masks[31]; // Per-handler masks
    int signal_handler_flags[31];      // Per-handler flags (SA_RESTART, etc.)
    uint64_t pending_signals;          // Bitmask of pending signals
    
    // File system context
    uint64_t current_dir_ino;          // Current working directory inode (root=1)
    
    // File descriptor table (per-task isolation)
    struct fut_file **fd_table;        // Array of file pointers
    int max_fds;                       // Allocated size of fd_table
    int next_fd;                       // Next FD index to allocate
    
    fut_task_t *next;                  // Next task in system list
};
```

### Task Management Functions

#### Task Creation and Destruction

```c
/**
 * Create a new task (process container).
 * Initializes PID, parent/child relationships, signal handlers, and FD table.
 * 
 * @return Task handle, or NULL on failure
 */
fut_task_t *fut_task_create(void);

/**
 * Destroy a task and all its threads.
 * Releases all threads, closes file descriptors, releases address space.
 * 
 * @param task  Task to destroy
 */
void fut_task_destroy(fut_task_t *task);
```

#### Thread Management Within Tasks

```c
/**
 * Add a thread to a task's thread list.
 * Called during thread creation to establish the thread-task relationship.
 * 
 * @param task    Task to add thread to
 * @param thread  Thread to add
 */
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Remove a thread from a task's thread list.
 * Called during thread termination.
 * 
 * @param task    Task to remove thread from
 * @param thread  Thread to remove
 */
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread);
```

#### Address Space Management

```c
/**
 * Assign an address space to a task.
 * Retains reference count on the MM context.
 */
void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm);

/**
 * Fetch the address space associated with a task.
 * 
 * @param task Task (NULL returns NULL)
 * @return Memory management context or NULL
 */
struct fut_mm *fut_task_get_mm(const fut_task_t *task);
```

#### Process Lifecycle

```c
/**
 * Get the current task (from the running thread).
 * 
 * @return Current task or NULL if no task is running
 */
fut_task_t *fut_task_current(void);

/**
 * Exit the current task with status code.
 * Marks task as ZOMBIE and releases address space.
 * 
 * @param status  Exit status (8-bit value)
 */
void fut_task_exit_current(int status);

/**
 * Exit current task due to signal termination.
 * Marks task as ZOMBIE with signal field set.
 * 
 * @param signal  Signal number that caused termination
 */
void fut_task_signal_exit(int signal);

/**
 * Wait for a child task to exit (waitpid syscall implementation).
 * Blocks on wait queue until child enters ZOMBIE state.
 * 
 * @param pid           Process ID to wait for (-1 for any)
 * @param status_out    Pointer to receive exit status
 * @return Child PID or -ECHILD if no children
 */
int fut_task_waitpid(int pid, int *status_out);
```

#### Credentials Management

```c
/**
 * Get the effective UID of a task.
 * 
 * @param task Task (NULL for current task)
 * @return Effective UID
 */
uint32_t fut_task_get_uid(fut_task_t *task);

/**
 * Get the effective GID of a task.
 * 
 * @param task Task (NULL for current task)
 * @return Effective GID
 */
uint32_t fut_task_get_gid(fut_task_t *task);

/**
 * Set the effective UID and GID of a task.
 * 
 * @param task Task to modify (NULL for current task)
 * @param uid  New effective UID
 * @param gid  New effective GID
 */
void fut_task_set_credentials(fut_task_t *task, uint32_t uid, uint32_t gid);
```

---

## 2. THREAD MANAGEMENT (kernel/threading/fut_thread.c)

### Core Structure: `fut_thread_t`

```c
struct fut_thread {
    uint64_t tid;                         // Thread ID (64-bit)
    fut_task_t *task;                     // Parent task
    
    // Stack management
    void *stack_base;                     // Stack allocation pointer
    size_t stack_size;                    // Stack size in bytes
    void *alloc_base;                     // Original malloc pointer (for proper free)
    uint64_t _padding;                    // Padding to align context to 16 bytes
    
    // CPU context (16-byte aligned for FXSAVE/FXRSTOR)
    fut_cpu_context_t context;            // Saved CPU context (x86_64/ARM64 specific)
    fut_interrupt_frame_t *irq_frame;     // Saved interrupt frame for IRQ switches
    
    // Thread state
    enum fut_thread_state state;          // READY, RUNNING, SLEEPING, BLOCKED, TERMINATED
    int priority;                         // Effective priority (0-255)
    int base_priority;                    // Base priority (restored after PI)
    int pi_saved_priority;                // Saved priority when boosted
    bool pi_boosted;                      // Priority inheritance active
    uint64_t deadline_tick;               // Absolute deadline tick (0 = none)
    uint64_t wake_time;                   // Wake tick for sleeping threads
    
    // CPU Affinity
    uint64_t cpu_affinity_mask;           // Bitmask of allowed CPUs
    uint32_t preferred_cpu;               // Primary CPU preference
    bool hard_affinity;                   // Hard pin vs soft preference
    
    fut_thread_stats_t stats;             // Performance instrumentation
    
    // Scheduling linkage
    fut_thread_t *next;                   // Next in ready queue
    fut_thread_t *prev;                   // Previous in ready queue
    fut_thread_t *wait_next;              // Next in wait queue
    fut_thread_t *global_next;            // Next in global thread list
};
```

### Thread Management Functions

#### Thread Creation

```c
/**
 * Create a new thread within a task.
 * 
 * Initializes:
 * - Stack with page-aligned size
 * - CPU context with proper alignment for FXSAVE/FXRSTOR
 * - Entry point in RIP/PC
 * - Stack pointer at top (grows downward)
 * - Adds to task's thread list
 * - Adds to scheduler ready queue
 * 
 * @param task         Parent task
 * @param entry        Thread entry point function
 * @param arg          Argument passed to entry function
 * @param stack_size   Stack size in bytes
 * @param priority     Priority level (0-255)
 * @return Thread handle, or NULL on failure
 */
[[nodiscard]] fut_thread_t *fut_thread_create(
    fut_task_t *task,
    void (*entry)(void *),
    void *arg,
    size_t stack_size,
    int priority
);
```

#### Thread Lifecycle

```c
/**
 * Voluntarily yield CPU to another thread.
 */
void fut_thread_yield(void);

/**
 * Exit the current thread (does not return).
 * Triggers scheduler to switch to another thread.
 */
[[noreturn]] void fut_thread_exit(void);

/**
 * Sleep for specified milliseconds.
 * Places thread in sleep queue until wake time.
 */
void fut_thread_sleep(uint64_t millis);

/**
 * Get current running thread.
 * 
 * @return Current thread, or NULL if none
 */
fut_thread_t *fut_thread_current(void);

/**
 * Mark per-CPU data as safe to access (called after initialization).
 */
void fut_thread_mark_percpu_safe(void);
```

#### Thread Context Management

```c
/**
 * Set current thread (internal scheduler use only).
 * 
 * @param thread  Thread to set as current
 */
void fut_thread_set_current(fut_thread_t *thread);

/**
 * Find thread by TID.
 * 
 * @param tid Thread ID to find
 * @return Thread pointer or NULL
 */
fut_thread_t *fut_thread_find(uint64_t tid);

/**
 * Set deadline for current thread.
 * 
 * @param abs_tick Absolute tick deadline
 */
void fut_thread_set_deadline(uint64_t abs_tick);

/**
 * Get deadline for current thread.
 * 
 * @return Absolute tick deadline
 */
uint64_t fut_thread_get_deadline(void);
```

#### Priority Management

```c
/**
 * Raise thread priority (priority inheritance).
 * Saves original priority for restoration.
 * 
 * @param thread       Thread to boost
 * @param new_priority New priority
 * @return 0 on success, -errno on failure
 */
int fut_thread_priority_raise(fut_thread_t *thread, int new_priority);

/**
 * Restore thread to base priority.
 * 
 * @param thread Thread to restore
 * @return 0 on success, -errno on failure
 */
int fut_thread_priority_restore(fut_thread_t *thread);
```

#### CPU Affinity Management

```c
/**
 * Set thread affinity to a specific CPU.
 * 
 * @param thread Thread to pin
 * @param cpu_id CPU ID
 * @return 0 on success, -errno on failure
 */
int fut_thread_set_affinity(fut_thread_t *thread, uint32_t cpu_id);

/**
 * Set thread affinity mask (multiple CPUs allowed).
 * 
 * @param thread Thread to set
 * @param mask   Bitmask of allowed CPUs
 * @return 0 on success, -errno on failure
 */
int fut_thread_set_affinity_mask(fut_thread_t *thread, uint64_t mask);

/**
 * Get thread affinity mask.
 * 
 * @param thread Thread to query
 * @return Affinity mask
 */
uint64_t fut_thread_get_affinity_mask(fut_thread_t *thread);

/**
 * Get preferred CPU for thread.
 * 
 * @param thread Thread to query
 * @return Preferred CPU ID
 */
uint32_t fut_thread_get_preferred_cpu(fut_thread_t *thread);

/**
 * Set hard affinity (hard pin vs soft preference).
 * 
 * @param thread    Thread to set
 * @param hard_pin  True for hard pin, false for soft preference
 */
void fut_thread_set_hard_affinity(fut_thread_t *thread, bool hard_pin);
```

---

## 3. FORK SYSCALL (kernel/sys_fork.c)

### Implementation: `sys_fork()`

```c
/**
 * fork() syscall - Create a new process by duplicating the calling process.
 * 
 * Returns:
 *   - Child PID in parent process
 *   - 0 in child process
 *   - -errno on error
 */
long sys_fork(void);
```

### Fork Process Flow

1. **Parent Validation**
   - Get current thread → current task (parent)

2. **Child Task Creation**
   - Create new task via `fut_task_create()`
   - Automatically assigned new PID and parent/child relationships

3. **File Descriptor Inheritance**
   ```c
   for (int i = 0; i < parent_task->max_fds; i++) {
       if (parent_task->fd_table[i] != NULL) {
           struct fut_file *parent_file = parent_task->fd_table[i];
           parent_file->refcount++;  // Both parent and child share FD
           child_task->fd_table[i] = parent_file;
       }
   }
   ```

4. **Address Space Cloning**
   - If parent has user MM: `clone_mm(parent_mm)` creates child MM
   - If parent is kernel-only: child gets NULL MM

5. **Thread Cloning**
   - `clone_thread()` duplicates parent thread in child task
   - Copies entire CPU context from parent's register state
   - Sets child's return value (RAX/x0) to 0

### Memory Cloning Strategy: Copy-on-Write (CoW)

#### CoW Mechanism

```c
static fut_mm_t *clone_mm(fut_mm_t *parent_mm);
```

**Process:**
1. Create new child MM with fresh page tables
2. Copy heap settings (brk_start, brk_current)
3. Clone VMA list from parent
4. Mark VMAs with `VMA_COW` flag
5. For each mapped page:
   - Share physical page (don't copy yet)
   - Mark both parent and child page as read-only
   - Increment page reference count
   - On write fault: allocate new page and copy

**Fallback Strategy:**
- If VMAs not tracked: scan fixed regions
  - Program region: 0x400000-0x500000
  - Stack region: 0x7FFFFFF00000-0x7FFFFFF00000 + 1MB
- For each mapped page: full copy (non-CoW)

#### Page Reference Counting

```c
void fut_page_ref_init(void);           // Initialize ref count tracking
void fut_page_ref_inc(phys_addr_t phys); // Increment reference count
int fut_page_ref_dec(phys_addr_t phys);  // Decrement and return new count
int fut_page_ref_get(phys_addr_t phys);  // Get current reference count
```

### Thread Cloning Details

```c
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task);
```

**x86-64 Implementation:**
```c
// Extract from interrupt frame (saved syscall registers)
uint64_t user_rip = frame_ptr[0];
uint64_t user_rsp = frame_ptr[3];
uint64_t user_rbp = frame_ptr[-3];
// ... RBX, R12-R15 extracted similarly

// Build child context
child_thread->context.rip = user_rip;
child_thread->context.rsp = user_rsp;
// ... copy all general purpose registers
child_thread->context.rax = 0;  // Fork return value
```

**ARM64 Implementation:**
```c
// Copy from interrupt frame to child context
child_thread->context.x0 = 0;           // Return value for child
child_thread->context.x29_fp = frame->x[29];  // Frame pointer
child_thread->context.x30_lr = frame->x[30];  // Link register
child_thread->context.sp = frame->sp;
child_thread->context.pc = frame->pc;
// ... copy callee-saved registers (x19-x28)
```

---

## 4. EXECVE SYSCALL (kernel/sys_execve.c)

### Implementation: `sys_execve()`

```c
/**
 * execve() syscall - Execute a program.
 * 
 * @param pathname  Path to executable file
 * @param argv      Argument vector (NULL-terminated array)
 * @param envp      Environment vector (NULL-terminated array)
 * 
 * Returns:
 *   - Does not return on success (current process is replaced)
 *   - -errno on error
 */
long sys_execve(const char *pathname, char *const argv[], char *const envp[]);
```

### Execve Process Flow

1. **Input Validation**
   - Check pathname pointer validity
   - Check argv pointer validity
   - Check envp pointer validity

2. **File Descriptor Processing**
   - Close all FDs marked with `FD_CLOEXEC` flag
   - Other FDs remain open

3. **ELF Loading**
   - Call `fut_exec_elf(pathname, argv, envp)`
   - Returns only on error; on success, process never returns

---

## 5. ELF EXECUTABLE LOADING (kernel/exec/elf64.c)

### Main Function: `fut_exec_elf()`

```c
/**
 * Load and execute an ELF64 binary.
 * 
 * Creates new task, memory context, loads segments, sets up stack,
 * and creates a thread that will run at the ELF entry point.
 * 
 * @param path  Path to ELF binary
 * @param argv  Argument vector
 * @param envp  Environment vector
 * @return 0 on success, -errno on error (never returns on success)
 */
int fut_exec_elf(const char *path, char *const argv[], char *const envp[]);
```

### ELF Loading Process

#### 1. ELF Header Validation

```c
typedef struct __attribute__((packed)) {
    uint8_t  e_ident[16];    // Magic number 0x7F,'E','L','F'
    uint16_t e_type;         // Executable type
    uint16_t e_machine;      // Machine type (0x3E=x86-64, 0xB7=ARM64)
    uint32_t e_version;      // Version
    uint64_t e_entry;        // Entry point address
    uint64_t e_phoff;        // Program header offset
    uint64_t e_shoff;        // Section header offset
    uint32_t e_flags;        // Flags
    uint16_t e_ehsize;       // ELF header size
    uint16_t e_phentsize;    // Program header entry size
    uint16_t e_phnum;        // Number of program headers
    uint16_t e_shentsize;    // Section header entry size
    uint16_t e_shnum;        // Number of section headers
    uint16_t e_shstrndx;     // String table index
} elf64_ehdr_t;

// Validation checks:
// - Magic: e_ident[0:4] == 0x7F,'E','L','F'
// - Class: e_ident[4] == 0x02 (64-bit)
// - Data: e_ident[5] == 0x01 (little-endian)
// - phentsize == sizeof(elf64_phdr_t)
// - phnum > 0
```

#### 2. Program Header Reading

```c
typedef struct __attribute__((packed)) {
    uint32_t p_type;    // Segment type (0x1=PT_LOAD, 0x4=PT_NOTE, etc.)
    uint32_t p_flags;   // Segment flags (1=PF_X, 2=PF_W, 4=PF_R)
    uint64_t p_offset;  // Offset in file
    uint64_t p_vaddr;   // Virtual address
    uint64_t p_paddr;   // Physical address (for loaders)
    uint64_t p_filesz;  // Size in file
    uint64_t p_memsz;   // Size in memory (may be > filesz for .bss)
    uint64_t p_align;   // Alignment requirement
} elf64_phdr_t;
```

#### 3. Task and Memory Context Creation

```c
// Create new task
fut_task_t *task = fut_task_create();

// Create new memory context (clean page tables)
fut_mm_t *mm = fut_mm_create();

// Attach MM to task
fut_task_set_mm(task, mm);
```

#### 4. Segment Mapping

```c
static int map_segment(fut_mm_t *mm, int fd, const elf64_phdr_t *phdr);
```

**For each PT_LOAD segment:**

1. **Calculate page boundaries**
   ```c
   uint64_t seg_start = phdr->p_vaddr & ~(PAGE_SIZE - 1ULL);
   uint64_t seg_offset = phdr->p_vaddr - seg_start;
   uint64_t seg_end = (phdr->p_vaddr + phdr->p_memsz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
   size_t page_count = (seg_end - seg_start) / PAGE_SIZE;
   ```

2. **Convert ELF flags to PTE flags**
   ```c
   uint64_t flags = PTE_PRESENT | PTE_USER;
   if (phdr->p_flags & PF_W) {      // Writable
       flags |= PTE_WRITABLE;
   }
   if ((phdr->p_flags & PF_X) == 0) { // Not executable
       flags |= PTE_NX;              // No-execute flag
   }
   ```

3. **Allocate physical pages**
   ```c
   for (size_t i = 0; i < page_count; ++i) {
       uint8_t *page = fut_pmm_alloc_page();  // 4KB physical page
       if (!page) { /* error handling */ }
       memset(page, 0, PAGE_SIZE);            // Zero-fill
   ```

4. **Map into user address space**
   ```c
       phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
       int rc = pmap_map_user(mm_context(mm),
                              seg_start + i * PAGE_SIZE,
                              phys,
                              PAGE_SIZE,
                              flags);
   }
   ```

5. **Load file content into pages**
   ```c
   // Read file data into temporary buffer
   uint8_t *buffer = fut_malloc(phdr->p_filesz);
   fut_vfs_lseek(fd, phdr->p_offset, SEEK_SET);
   read_exact(fd, buffer, phdr->p_filesz);
   
   // Copy buffer content into mapped user pages
   size_t remaining = phdr->p_filesz;
   size_t page_index = 0;
   size_t page_offset = seg_offset;
   uint8_t *src = buffer;
   
   while (remaining > 0 && page_index < page_count) {
       size_t chunk = PAGE_SIZE - page_offset;
       if (chunk > remaining) chunk = remaining;
       memcpy(pages[page_index] + page_offset, src, chunk);
       src += chunk;
       remaining -= chunk;
       page_index++;
       page_offset = 0;
   }
   
   // Ensure all writes visible before execution
   __asm__ volatile("mfence" ::: "memory");
   ```

6. **Track heap base**
   ```c
   uint64_t seg_end = phdr->p_vaddr + phdr->p_memsz;
   if (seg_end > heap_base_candidate) {
       heap_base_candidate = seg_end;
   }
   ```

#### 5. Heap Setup

```c
// Set heap base to first available address after last segment
uintptr_t default_heap = 0x00400000ULL;
uintptr_t heap_base = heap_base_candidate ? 
                      PAGE_ALIGN_UP(heap_base_candidate) : 
                      default_heap;
heap_base += PAGE_SIZE;  // Add one page gap
fut_mm_set_heap_base(mm, heap_base, 0);
```

#### 6. User Stack Setup

```c
static int stage_stack_pages(fut_mm_t *mm, uint64_t *out_stack_top);
```

**Stack Layout (x86-64):**
- Top: `0x00007FFFFFFFE000ULL` (standard Linux user stack)
- Size: 16 pages (64KB)
- Pages: Read-write (RW), No-execute (NX)

**Stack Layout (ARM64):**
- Top: `0x00007FFFFFFFE000ULL`
- Size: 32 pages (128KB)
- Pages: Read-write (RW), No-execute (NX)

#### 7. Build User Stack

```c
static int build_user_stack(fut_mm_t *mm,
                            const char *const argv_in[],
                            size_t argc_in,
                            const char *const envp_in[],
                            size_t envc_in,
                            uint64_t *out_rsp,
                            uint64_t *out_argv,
                            uint64_t *out_argc);
```

**Stack Layout (from high to low address):**

```
Stack Top (0x7FFFFFFFE000)
  │
  ├─ [Environment variable strings]      (read from envp array)
  ├─ [Argument strings]                   (read from argv array)
  ├─ [16-byte alignment]
  ├─ [NULL terminator for envp]
  ├─ [Environment variable pointers]
  ├─ [NULL terminator for argv]
  ├─ [Argument pointers]                  ←─ argv (in RSI on x86, pointer value on stack)
  ├─ [16-byte alignment/padding]
  └─ [argc]                               ←─ rsp (stack pointer at entry)

Key Requirements:
- Strings copied from kernel space to user space via exec_copy_to_user()
- All pointers are 64-bit (8 bytes each)
- Stack must be 16-byte aligned after pushing return address (already done by RSP setup)
- NULL terminators mark end of argv and envp arrays
```

**Key Function: `exec_copy_to_user()`**

```c
static int exec_copy_to_user(fut_mm_t *mm, uint64_t dest, 
                             const void *src, size_t len);
```

- Probes PTE to verify user page is mapped
- Extracts physical address from PTE
- Converts physical → kernel virtual address
- Performs kernel memcpy (no privilege escalation needed)
- Returns -EFAULT if page not mapped

#### 8. Thread Creation

```c
struct fut_user_entry {
    uint64_t entry;       // ELF entry point
    uint64_t stack;       // User RSP value
    uint64_t argc;        // Argument count
    uint64_t argv_ptr;    // Pointer to argv array on user stack
    fut_task_t *task;     // Task pointer for CR3 switching
};

fut_thread_t *thread = fut_thread_create(task,
                                        fut_user_trampoline,
                                        entry_struct,
                                        16 * 1024,  // Kernel stack
                                        FUT_DEFAULT_PRIORITY);
```

#### 9. User-Mode Trampoline (x86-64)

```c
[[noreturn]] __attribute__((optimize("O0"))) 
static void fut_user_trampoline(void *arg);
```

**Process:**
1. Extract values from user_entry struct BEFORE any printf (printf triggers CR3 switches)
2. Verify task and MM are valid
3. Ensure CR3 is set to task's page table root
4. Call pure assembly `fut_do_user_iretq()` to transition to user mode
5. Never returns (IRETQ in user mode)

**`fut_do_user_iretq()` (assembly in platform/x86_64/)**
```asm
mov rdi, entry    ; RDI = entry point
mov rsi, stack    ; RSI = user RSP
mov rdx, argc     ; RDX = argc
mov rcx, argv_ptr ; RCX = argv pointer

; Set up IRETQ frame on user stack
mov rax, [rsp + 40]  ; Get SS from frame
mov [rsi - 8], rax   ; Push SS
mov rax, [rsp + 32]  ; Get RSP from frame
mov [rsi - 16], rax  ; Push RSP
mov rax, [rsp + 24]  ; Get RFLAGS from frame
mov [rsi - 24], rax  ; Push RFLAGS
mov rax, [rsp + 16]  ; Get CS from frame
mov [rsi - 32], rax  ; Push CS
mov rax, entry       ; RIP = entry point
mov [rsi - 40], rax  ; Push RIP

; Switch to user stack
sub rsi, 40
mov rsp, rsi

; Clear segment registers (optional)
xor rax, rax
mov es, rax
mov ds, rax

; Jump to user mode via IRETQ
iretq
```

**x86-64 System V ABI Compliance:**
- RAX/RDX: Return value of main() (prepared but not used by startup code)
- RBP: Frame pointer initialized (stack alignment preserved)
- RSP % 16 == 0 after CALL (entry point expects misaligned RSP)

#### 10. User-Mode Trampoline (ARM64)

```c
[[noreturn]] __attribute__((optimize("O0"))) 
static void fut_user_trampoline_arm64(void *arg);
```

**Process:**
1. Extract values from user_entry_arm64 struct
2. Set SP_EL0 to user stack pointer
3. Set ELR_EL1 to entry point address
4. Set SPSR_EL1 to EL0t mode (user mode)
5. Set x0 to argc (ARM64 calling convention)
6. Execute ERET to drop to EL0

**Assembly:**
```asm
msr sp_el0, x0      ; Set user stack pointer
msr elr_el1, x1     ; Set entry point
mov x2, #0x00       ; EL0t mode
msr spsr_el1, x2    ; Set processor state
mov x0, x2          ; x0 = argc
isb                 ; Instruction sync barrier
eret                ; Return to user mode
```

---

## 6. MEMORY MANAGEMENT (kernel/memory/fut_mm.c)

### Core Structure: `fut_mm_t`

```c
typedef struct fut_mm {
    fut_vmem_context_t ctx;         // Architecture-specific MMU context
    atomic_uint_fast64_t refcnt;    // Reference count (for sharing)
    uint32_t flags;                 // FUT_MM_KERNEL or FUT_MM_USER
    uintptr_t brk_start;            // Initial heap base
    uintptr_t brk_current;          // Current heap break (sys_brk)
    uintptr_t heap_limit;           // Maximum heap limit
    uintptr_t heap_mapped_end;      // Highest mapped heap page
    uintptr_t mmap_base;            // Base for mmap allocations
    struct fut_vma *vma_list;       // Virtual Memory Area list
} fut_mm_t;
```

### Virtual Memory Area (VMA)

```c
struct fut_vma {
    uintptr_t start;              // Start address (page-aligned)
    uintptr_t end;                // End address (page-aligned, exclusive)
    int prot;                     // Protection: PROT_READ, PROT_WRITE, PROT_EXEC
    int flags;                    // Flags: VMA_COW, VMA_SHARED, etc.
    
    struct fut_vnode *vnode;      // Backing file (NULL for anonymous)
    uint64_t file_offset;         // Offset into backing file
    
    struct fut_vma *next;         // Next VMA in list
};

#define VMA_COW       0x1000      // Copy-on-write pages
#define VMA_SHARED    0x2000      // Shared mapping
```

### MM Management Functions

#### Initialization and Lifecycle

```c
/**
 * Initialize the kernel memory manager.
 * Sets up kernel MM with kernel page tables.
 * Called once at boot.
 */
void fut_mm_system_init(void);

/**
 * Get the kernel memory manager.
 * 
 * @return Kernel MM context
 */
fut_mm_t *fut_mm_kernel(void);

/**
 * Create a new user memory manager.
 * Allocates fresh page tables and initializes VMA list.
 * 
 * @return New MM context or NULL on failure
 */
fut_mm_t *fut_mm_create(void);

/**
 * Increment reference count on MM.
 * Used when MM is shared between tasks.
 * 
 * @param mm Memory manager to retain
 */
void fut_mm_retain(fut_mm_t *mm);

/**
 * Decrement reference count and destroy if zero.
 * Unmaps all pages and frees page tables when refcount reaches zero.
 * 
 * @param mm Memory manager to release
 */
void fut_mm_release(fut_mm_t *mm);
```

#### MM Switching

```c
/**
 * Switch to a different memory context.
 * Writes new CR3 (x86) or TTBR0_EL1 (ARM64) to load new page tables.
 * Performed during thread context switch.
 * 
 * @param mm Memory manager to switch to (NULL = kernel MM)
 */
void fut_mm_switch(fut_mm_t *mm);

/**
 * Get the current memory manager.
 * Derives from current thread's task.
 * 
 * @return Current MM context
 */
fut_mm_t *fut_mm_current(void);

/**
 * Get the VMU context (page tables) for an MM.
 * 
 * @param mm Memory manager
 * @return Virtual memory context
 */
fut_vmem_context_t *fut_mm_context(fut_mm_t *mm);
```

#### Heap Management (sys_brk)

```c
/**
 * Set the initial heap base and limit.
 * Called by ELF loader to establish heap.
 * 
 * @param mm     Memory manager
 * @param base   Heap base address
 * @param limit  Heap limit (0 = default to USER_VMA_MAX)
 */
void fut_mm_set_heap_base(fut_mm_t *mm, uintptr_t base, uintptr_t limit);

/**
 * Get current heap break value.
 * 
 * @param mm Memory manager
 * @return Current brk value
 */
uintptr_t fut_mm_brk_current(const fut_mm_t *mm);

/**
 * Get heap limit.
 * 
 * @param mm Memory manager
 * @return Heap limit
 */
uintptr_t fut_mm_brk_limit(const fut_mm_t *mm);

/**
 * Set current heap break.
 * Called by sys_brk().
 * 
 * @param mm      Memory manager
 * @param current New brk value
 */
void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current);
```

#### Memory Mapping

```c
/**
 * Map anonymous memory (malloc backing).
 * 
 * @param mm     Memory manager
 * @param hint   Address hint (NULL = auto-allocate)
 * @param len    Size in bytes
 * @param prot   Protection: PROT_READ, PROT_WRITE, PROT_EXEC
 * @param flags  Flags: MAP_FIXED, MAP_ANONYMOUS, etc.
 * @return Virtual address or error code as pointer
 */
void *fut_mm_map_anonymous(fut_mm_t *mm, uintptr_t hint, size_t len, 
                           int prot, int flags);

/**
 * Map file-backed memory (mmap with file).
 * 
 * @param mm           Memory manager
 * @param vnode        File vnode
 * @param hint         Address hint
 * @param len          Size to map
 * @param prot         Protection flags
 * @param flags        Mapping flags
 * @param file_offset  Offset in file
 * @return Virtual address or error code as pointer
 */
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                      size_t len, int prot, int flags, uint64_t file_offset);

/**
 * Unmap memory region.
 * 
 * @param mm   Memory manager
 * @param addr Address to unmap
 * @param len  Length to unmap
 * @return 0 on success, -errno on error
 */
int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len);
```

#### VMA Management

```c
/**
 * Add a VMA to the MM's VMA list.
 * Used during fork to track copied regions.
 * 
 * @param mm    Memory manager
 * @param start VMA start address
 * @param end   VMA end address
 * @param prot  Protection flags
 * @param flags VMA flags
 * @return 0 on success, -errno on error
 */
int fut_mm_add_vma(fut_mm_t *mm, uintptr_t start, uintptr_t end, 
                   int prot, int flags);

/**
 * Clone VMAs from source to destination MM.
 * Used by fork() to duplicate VMA tracking.
 * 
 * @param dest_mm Destination MM
 * @param src_mm  Source MM
 * @return 0 on success, -errno on error
 */
int fut_mm_clone_vmas(fut_mm_t *dest_mm, fut_mm_t *src_mm);
```

#### Page Reference Counting (for CoW)

```c
/**
 * Initialize page reference counting.
 * Called at boot to set up tracking.
 */
void fut_page_ref_init(void);

/**
 * Increment reference count for a physical page.
 * Called when a page is shared via CoW.
 * 
 * @param phys Physical address of page
 */
void fut_page_ref_inc(phys_addr_t phys);

/**
 * Decrement reference count for a physical page.
 * Returns new count (0 means page can be freed).
 * 
 * @param phys Physical address of page
 * @return New reference count
 */
int fut_page_ref_dec(phys_addr_t phys);

/**
 * Get current reference count for a physical page.
 * 
 * @param phys Physical address of page
 * @return Current reference count
 */
int fut_page_ref_get(phys_addr_t phys);
```

---

## 7. PROCESS MANAGEMENT SYSCALLS

### Syscall Numbers (include/user/sysnums.h)

```c
#define SYS_fork        57
#define SYS_execve      59
#define SYS_exit        60
#define SYS_wait4       61
#define SYS_waitpid     61  /* Alias for wait4 */
#define SYS_kill        62
```

### Syscall Implementations

#### fork() - SYS_fork (57)

**File:** `kernel/sys_fork.c`
**Signature:** `long sys_fork(void)`
**Returns:**
- Parent: Child PID (>0)
- Child: 0
- Error: -errno

#### execve() - SYS_execve (59)

**File:** `kernel/sys_execve.c`
**Signature:** `long sys_execve(const char *pathname, char *const argv[], char *const envp[])`
**Returns:**
- Success: Never returns (process replaced)
- Error: -errno

#### exit() - SYS_exit (60)

**Related:** `fut_task_exit_current(int status)`
**Behavior:** Terminates current task, releases resources, marks as ZOMBIE

#### waitpid()/wait4() - SYS_waitpid/SYS_wait4 (61)

**Related:** `int fut_task_waitpid(int pid, int *status_out)`
**Behavior:** Blocks until child exits, returns child PID and status

#### kill() - SYS_kill (62)

**File:** `kernel/sys_signal.c` (signal handling)
**Behavior:** Send signal to process (related to signal_exit)

---

## 8. ARCHITECTURE-SPECIFIC CONTEXT STRUCTURES

### x86-64 Context (platform/x86_64/regs.h)

```c
typedef struct {
    // General purpose registers
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    
    // Segment registers
    uint16_t cs, ss, ds, es, fs, gs;
    
    // Control registers (implicit, not saved)
    uint64_t rip;      // Instruction pointer
    uint64_t rflags;   // Processor flags
    
    // FPU/XMM state (FXSAVE format, 512 bytes)
    uint8_t fx_area[512];
} fut_cpu_context_t;
```

**Calling Convention at Thread Entry:**
- RDI = entry function pointer
- RSI = argument pointer
- RSP aligned to 16-byte boundary minus 8 (CALL pushes RIP)

**Calling Convention at User Entry (IRETQ):**
- RAX = entry point (from RIP)
- RBP = frame pointer
- RSP = user stack
- Other registers preserved

### ARM64 Context (platform/arm64/regs.h)

```c
typedef struct {
    // General purpose registers
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint64_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint64_t x16, x17, x18, x19, x20, x21, x22, x23;
    uint64_t x24, x25, x26, x27, x28;
    
    // Special registers
    uint64_t x29_fp;    // Frame pointer
    uint64_t x30_lr;    // Link register
    uint64_t sp;        // Stack pointer
    uint64_t pc;        // Program counter
    uint64_t pstate;    // Processor state
} fut_cpu_context_t;
```

**Calling Convention at Thread Entry:**
- X19 = entry function pointer (callee-saved)
- X20 = argument pointer (callee-saved)

**Calling Convention at User Entry (ERET):**
- X0 = argc
- SP = user stack pointer
- PC = entry point (from ELR_EL1)

---

## 9. EXECUTION FLOW SUMMARY

### Fork Execution Flow

```
sys_fork()
  ├─ Get current thread → current task (parent)
  ├─ fut_task_create()
  │  ├─ Allocate task structure
  │  ├─ Initialize signal handlers
  │  ├─ Allocate FD table (64 FDs initially)
  │  ├─ Assign PID
  │  ├─ Set parent/child relationships
  │  └─ Add to global task list
  ├─ Copy FD table (increment refcounts)
  ├─ clone_mm() if user space
  │  ├─ fut_mm_create()
  │  ├─ Copy heap settings
  │  ├─ fut_mm_clone_vmas()
  │  ├─ For each VMA:
  │  │  ├─ If CoW: share page, mark read-only, increment refcount
  │  │  └─ If non-CoW: allocate new page, copy contents
  │  └─ Return child MM
  ├─ clone_thread()
  │  ├─ fut_thread_create() with dummy entry
  │  ├─ Extract registers from syscall frame
  │  ├─ Set child RAX/x0 to 0 (fork return value for child)
  │  └─ Add to scheduler
  └─ Return child PID to parent
```

### Execve Execution Flow

```
sys_execve(path, argv, envp)
  ├─ Validate inputs (pointers in user space)
  ├─ Get current task
  ├─ Close all FD_CLOEXEC FDs
  └─ fut_exec_elf(path, argv, envp)
     ├─ Open file
     ├─ Read and validate ELF header
     ├─ Read program headers
     ├─ fut_task_create() (new task)
     ├─ fut_mm_create() (new address space)
     ├─ For each PT_LOAD segment:
     │  ├─ Calculate page boundaries
     │  ├─ Allocate physical pages
     │  ├─ Map into user address space
     │  └─ Load file content
     ├─ Set heap base
     ├─ stage_stack_pages() (allocate 16/32 pages)
     ├─ build_user_stack()
     │  ├─ Copy environment strings
     │  ├─ Copy argument strings
     │  ├─ Push pointers and terminators
     │  └─ Align stack
     ├─ Allocate user_entry structure
     ├─ fut_thread_create() with fut_user_trampoline
     └─ Return (never on success)

fut_user_trampoline()
  ├─ Extract entry point and stack from user_entry
  ├─ Set CR3 to task's page table (if needed)
  └─ fut_do_user_iretq()
     ├─ Load RDI = entry, RSI = stack
     ├─ Prepare IRETQ frame on user stack
     ├─ Switch to user stack
     └─ IRETQ to user mode
```

---

## 10. KEY DESIGN DECISIONS

### 1. Per-Task Memory Contexts
- Each task has independent `fut_mm_t` with separate page tables
- Enables true process isolation
- CoW makes fork() efficient

### 2. Copy-on-Write Implementation
- Shared physical pages initially (post-fork)
- Pages marked read-only until first write
- Page fault handler allocates copy on write
- Useful for workloads where child process exits quickly

### 3. Two-Level Process Management
- **Tasks** = Process containers with address spaces
- **Threads** = Execution units within tasks
- Each thread has saved CPU context for preemptive switching
- File descriptor table per-task (standard POSIX)

### 4. Unified ELF Loader
- x86-64 and ARM64 share ELF parsing logic
- Architecture-specific only for:
  - User-mode trampoline (IRETQ vs ERET)
  - Stack/register setup
  - PTE flag mapping

### 5. Direct Kernel-Space Copy
- ELF loader copies to user pages without switching CR3
- Uses PTE probing to get physical address
- Converts physical → kernel virtual address
- Avoids MMU context switches during critical section

### 6. Signal Support (Partial)
- Signal handlers array per-task
- Signal masking per-task and per-handler
- Pending signals tracked as bitmask
- Full delivery mechanism not yet implemented

---

## 11. LIMITATIONS AND TODOs

### Current Limitations

1. **No actual fork() CoW write-protect handler**
   - Pages marked read-only, but page fault handler not yet attached
   - Fallback: full copy if no VMAs tracked

2. **Signal delivery not fully implemented**
   - Handlers stored but not called on signal receipt
   - Pending signals tracked but not checked at return points

3. **No real-time process management**
   - Priority inheritance partial (structure exists, not fully wired)
   - No PREEMPT_RT scheduling

4. **VMA tracking optional**
   - Fork falls back to fixed-range scanning if VMAs not tracked
   - sys_mmap and sys_munmap don't create/remove VMAs yet

5. **ARM64 support incomplete**
   - ELF loader scaffolding exists
   - No actual ARM64 boot or context switch

### Future Work

1. Implement CoW page fault handler
2. Complete signal delivery pipeline
3. Wire up VMA creation in sys_mmap
4. Finish ARM64 architecture support
5. Add real-time scheduling enhancements
6. Implement POSIX clone() syscall
7. Add process accounting and statistics

---

## CONCLUSION

Futura OS provides a well-structured process management subsystem with:
- Clean separation of tasks (processes) and threads
- Efficient fork() via copy-on-write
- Proper ELF executable loading with user-mode setup
- Architecture-independent design with x86-64 primary support

The codebase emphasizes code clarity and maintainability through:
- Extensive comments explaining architectural decisions
- Architecture-specific code clearly segregated
- Consistent naming conventions
- Minimal dependencies between subsystems

