# Futura OS Process Management - Quick Reference

## File Locations

| Component | File(s) |
|-----------|---------|
| Task Management | `/home/k/futura/kernel/threading/fut_task.c` |
| Task Header | `/home/k/futura/include/kernel/fut_task.h` |
| Thread Management | `/home/k/futura/kernel/threading/fut_thread.c` |
| Thread Header | `/home/k/futura/include/kernel/fut_thread.h` |
| Fork Syscall | `/home/k/futura/kernel/sys_fork.c` |
| Execve Syscall | `/home/k/futura/kernel/sys_execve.c` |
| ELF Loader | `/home/k/futura/kernel/exec/elf64.c` |
| ELF Header | `/home/k/futura/include/kernel/exec.h` |
| Memory Mgmt | `/home/k/futura/kernel/memory/fut_mm.c` |
| Memory Header | `/home/k/futura/include/kernel/fut_mm.h` |
| Syscall Nums | `/home/k/futura/include/user/sysnums.h` |

## Key Functions Quick Lookup

### Task Management (fut_task.c)

```c
fut_task_t *fut_task_create(void)
void fut_task_destroy(fut_task_t *task)
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread)
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread)
void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm)
struct fut_mm *fut_task_get_mm(const fut_task_t *task)
fut_task_t *fut_task_current(void)
void fut_task_exit_current(int status)
void fut_task_signal_exit(int signal)
int fut_task_waitpid(int pid, int *status_out)
uint32_t fut_task_get_uid(fut_task_t *task)
uint32_t fut_task_get_gid(fut_task_t *task)
void fut_task_set_credentials(fut_task_t *task, uint32_t uid, uint32_t gid)
```

### Thread Management (fut_thread.c)

```c
fut_thread_t *fut_thread_create(fut_task_t *task, void (*entry)(void *), 
                                void *arg, size_t stack_size, int priority)
void fut_thread_yield(void)
[[noreturn]] void fut_thread_exit(void)
void fut_thread_sleep(uint64_t millis)
fut_thread_t *fut_thread_current(void)
void fut_thread_set_current(fut_thread_t *thread)
fut_thread_t *fut_thread_find(uint64_t tid)
void fut_thread_set_deadline(uint64_t abs_tick)
uint64_t fut_thread_get_deadline(void)
int fut_thread_priority_raise(fut_thread_t *thread, int new_priority)
int fut_thread_priority_restore(fut_thread_t *thread)
int fut_thread_set_affinity(fut_thread_t *thread, uint32_t cpu_id)
int fut_thread_set_affinity_mask(fut_thread_t *thread, uint64_t mask)
uint64_t fut_thread_get_affinity_mask(fut_thread_t *thread)
uint32_t fut_thread_get_preferred_cpu(fut_thread_t *thread)
void fut_thread_set_hard_affinity(fut_thread_t *thread, bool hard_pin)
```

### Process Syscalls

```c
long sys_fork(void)                    // SYS_fork (57)
long sys_execve(const char *pathname, char *const argv[], 
                char *const envp[])    // SYS_execve (59)
long sys_exit(int status)              // SYS_exit (60)
long sys_waitpid(int pid, int *u_status, int flags)  // SYS_waitpid (61)
```

### ELF Loading (elf64.c)

```c
int fut_exec_elf(const char *path, char *const argv[], char *const envp[])
int fut_stage_fbtest_binary(void)
int fut_stage_shell_binary(void)
int fut_stage_winsrv_binary(void)
int fut_stage_winstub_binary(void)
int fut_stage_init_stub_binary(void)
int fut_stage_second_stub_binary(void)
int fut_stage_wayland_compositor_binary(void)
int fut_stage_wayland_client_binary(void)
int fut_stage_wayland_color_client_binary(void)
```

### Memory Management (fut_mm.c)

```c
void fut_mm_system_init(void)
fut_mm_t *fut_mm_kernel(void)
fut_mm_t *fut_mm_create(void)
void fut_mm_retain(fut_mm_t *mm)
void fut_mm_release(fut_mm_t *mm)
void fut_mm_switch(fut_mm_t *mm)
fut_mm_t *fut_mm_current(void)
fut_vmem_context_t *fut_mm_context(fut_mm_t *mm)
void fut_mm_set_heap_base(fut_mm_t *mm, uintptr_t base, uintptr_t limit)
uintptr_t fut_mm_brk_current(const fut_mm_t *mm)
uintptr_t fut_mm_brk_limit(const fut_mm_t *mm)
void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current)
void *fut_mm_map_anonymous(fut_mm_t *mm, uintptr_t hint, size_t len, 
                           int prot, int flags)
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                      size_t len, int prot, int flags, uint64_t file_offset)
int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len)
int fut_mm_add_vma(fut_mm_t *mm, uintptr_t start, uintptr_t end, 
                   int prot, int flags)
int fut_mm_clone_vmas(fut_mm_t *dest_mm, fut_mm_t *src_mm)
void fut_page_ref_init(void)
void fut_page_ref_inc(phys_addr_t phys)
int fut_page_ref_dec(phys_addr_t phys)
int fut_page_ref_get(phys_addr_t phys)
```

## Key Data Structures

### Task Structure (fut_task_t)
- **PID**: 64-bit process ID
- **MM**: Memory management context
- **Parent/Child**: Process tree relationships
- **Threads**: Linked list of threads in task
- **FD Table**: Per-task file descriptor table (initially 64 FDs)
- **Signal Handlers**: Array of signal handlers and masks
- **Credentials**: UID/GID

### Thread Structure (fut_thread_t)
- **TID**: 64-bit thread ID
- **Task**: Parent task pointer
- **Stack**: Kernel stack (grows downward)
- **Context**: Saved CPU context for context switching
- **State**: READY, RUNNING, SLEEPING, BLOCKED, TERMINATED
- **Priority**: Effective priority (0-255)
- **Affinity**: CPU affinity mask and preferred CPU

### Memory Context (fut_mm_t)
- **Context**: Architecture-specific MMU context
- **Heap**: Heap base, current break, limit
- **VMA List**: Virtual Memory Areas (regions)
- **Reference Count**: For sharing between processes
- **Flags**: KERNEL or USER

## Critical Design Points

1. **Fork creates new task + thread**
   - Duplicates address space via CoW
   - Copies file descriptors (shared references)
   - Returns child PID to parent, 0 to child

2. **Execve loads new ELF binary**
   - Preserves task and file descriptors
   - Replaces memory context completely
   - Never returns on success

3. **Copy-on-Write (CoW)**
   - Shares physical pages after fork
   - Both parent and child marked read-only
   - Page fault handler copies on write (TODO: implement)

4. **Stack Layout (User Mode)**
   ```
   [argc]                      ← RSP at entry
   [NULL]                      ← RSI points here
   [argv pointers...]
   [argv/environ strings]
   [unused]
   ...
   0x7FFFFFFFE000 (top)
   ```

5. **User Mode Transition**
   - x86-64: IRETQ (interrupt return)
   - ARM64: ERET (exception return)

## Process Creation Flow

```
Parent                  Child
   │
   ├─ fork()
   │  ├─ Create new task
   │  ├─ Clone MM (CoW)
   │  ├─ Clone thread
   │  │  └─ Copy all registers
   │  │  └─ Set RAX/x0 = 0
   │  └─ Add to scheduler
   │
   ├─ Continue with RAX = child PID
   └─ Child scheduled by scheduler
      ├─ Starts with saved context
      ├─ Returns from fork() with RAX = 0
      └─ Continues execution
```

## ELF Loading Flow

```
execve(path, argv, envp)
   │
   ├─ Open ELF file
   ├─ Read & validate ELF header
   ├─ Read program headers
   │
   ├─ Create new task
   ├─ Create new MM
   │
   ├─ For each PT_LOAD segment:
   │  ├─ Allocate physical pages
   │  ├─ Map to user address space
   │  └─ Load file content
   │
   ├─ Set heap base
   ├─ Allocate stack pages
   ├─ Build user stack (argc, argv, environ)
   │
   ├─ Create thread with user_trampoline
   └─ (never returns)
      │
      └─ fut_user_trampoline()
         ├─ Set CR3 to task's MM
         └─ IRETQ to user mode
            └─ Start at ELF entry point
```

## Address Space Regions (x86-64)

```
0xFFFFFFFF80000000  ↑─────────────────────────
                    │ Kernel Space (higher half)
0x0000000000000000  ├─────────────────────────
                    │ User Code/Data
                    ├─────────────────────────
                    │ Heap (grows upward)
                    ├─────────────────────────
                    │ Mmap Allocations
                    ├─────────────────────────
                    │ User Stack (grows downward)
0x00007FFFFFFFE000  ├─ Stack Top
```

## Common Patterns

### Creating a Task with a Thread

```c
// Create task
fut_task_t *task = fut_task_create();
if (!task) return -ENOMEM;

// Create MM (if user space)
fut_mm_t *mm = fut_mm_create();
if (!mm) { fut_task_destroy(task); return -ENOMEM; }
fut_task_set_mm(task, mm);

// Create thread
fut_thread_t *thread = fut_thread_create(task, entry_func, arg, 
                                         16*1024, FUT_DEFAULT_PRIORITY);
if (!thread) { fut_task_destroy(task); return -ENOMEM; }
```

### Accessing Current Task/Thread

```c
fut_thread_t *thread = fut_thread_current();
if (!thread) { /* No thread running */ }

fut_task_t *task = thread->task;
if (!task) { /* Thread has no task */ }

fut_mm_t *mm = fut_task_get_mm(task);
if (!mm) { /* Task has no user MM (kernel thread) */ }
```

### Switching Address Spaces

```c
fut_mm_t *mm = fut_task_get_mm(task);
if (mm) {
    fut_mm_switch(mm);  // Loads new CR3 (x86) or TTBR0_EL1 (ARM64)
}
```

## Return Values

### sys_fork()
- Parent: Child PID (> 0)
- Child: 0
- Error: -errno (ENOMEM, ESRCH, etc.)

### sys_execve()
- Success: Never returns (process replaced)
- Error: -errno (ENOENT, EACCES, ENOEXEC, ENOMEM, etc.)

### sys_exit()
- Never returns (thread exits)

### sys_waitpid()
- Success: Child PID
- Error: -ECHILD (no children), -EINTR (interrupted)

## Testing Commands (from CLAUDE.md)

```bash
make kernel              # Build kernel
make test                # Build ISO and boot with GRUB
make iso                 # Build bootable ISO only

# Single test with debug flags
make CFLAGS+=-DDEBUG_VFS kernel

# ELF loading is tested automatically at boot
# Check for "[EXEC]" prefixed log messages
```

