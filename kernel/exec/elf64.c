// SPDX-License-Identifier: MPL-2.0
/*
 * elf64.c - Minimal ELF64 loader and user process bootstrap
 */

#ifdef __x86_64__

#include <kernel/exec.h>
#include <generated/feature_flags.h>

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/kprintf.h>

#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <arch/x86_64/msr.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* MSR for FS segment base (Thread Local Storage) */
#define MSR_FS_BASE     0xC0000100

/* Set to 1 to enable verbose ELF exec debug logging */
#define ELF_DEBUG 0
#if ELF_DEBUG
#define ELF_LOG(...) fut_printf(__VA_ARGS__)
#else
#define ELF_LOG(...) ((void)0)
#endif

/* TLS block address - placed below stack in user address space */
#define USER_TLS_BASE   0x00007FFE000000ULL
#define TLS_SIZE        PAGE_SIZE

/* Stack canary offset in TLS (matches glibc/gcc convention) */
#define TLS_STACK_CANARY_OFFSET 0x28

/* External assembly function for IRETQ to userspace
 * NOTE: Don't use noreturn attribute - it may cause bad codegen */
extern void fut_do_user_iretq(uint64_t entry, uint64_t stack, uint64_t argc, uint64_t argv);

/* Debug output macro for verbose exec/staging logs */
#ifdef DEBUG_EXEC
#define EXEC_DEBUG(...) fut_printf(__VA_ARGS__)
#else
#define EXEC_DEBUG(...) do {} while (0)
#endif

/* Debug output for user trampoline serial output (U1234567A characters) */
/* #define DEBUG_USER_TRAMPOLINE */

/* Disable verbose STACK debugging for performance */
#define STACK_DEBUG 0
#define stack_printf(...) do { if (STACK_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/* Disable verbose EXEC-DEBUG (unconditional) for performance */
#define EXECDBG_VERBOSE 0
#define execdbg_printf(...) do { if (EXECDBG_VERBOSE) fut_printf(__VA_ARGS__); } while(0)

#define ELF_MAGIC       0x464C457FULL
#define ELF_CLASS_64    0x02
#define ELF_DATA_LE     0x01

#define PT_LOAD         0x00000001u

#define PF_X            0x00000001u
#define PF_W            0x00000002u
#define PF_R            0x00000004u

/* With GDT layout: user data at 0x18, user code at 0x20 (for SYSRET compatibility) */
#define USER_CODE_SELECTOR  (0x20u | 0x3u)  /* 0x23 */
#define USER_DATA_SELECTOR  (0x18u | 0x3u)  /* 0x1B */

#define USER_STACK_TOP      0x00007FFF000000ULL  /* Stack within 39-bit VA space (T0SZ=25) */
#define USER_STACK_PAGES    16u  /* Increase stack pages from 4 to 16 (64KB) */

typedef struct __attribute__((packed)) {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct __attribute__((packed)) {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

struct fut_user_entry {
    uint64_t entry;
    uint64_t stack;
    uint64_t argc;
    uint64_t argv_ptr;
    fut_task_t *task;  /* Task pointer to access mm */
};

/* Copy data to user memory in the target MM context.
 * This directly accesses mapped pages through their kernel virtual addresses
 * rather than switching contexts, avoiding issues with fut_mm_current(). */
static int exec_copy_to_user(fut_mm_t *mm, uint64_t dest, const void *src, size_t len) {
    fut_vmem_context_t *vmem = fut_mm_context(mm);
    const uint8_t *src_bytes = (const uint8_t *)src;
    size_t remaining = len;
    uint64_t vaddr = dest;

    while (remaining > 0) {
        /* Get page offset and calculate bytes to copy in this page */
        uint64_t page_offset = vaddr & 0xFFF;
        size_t chunk_size = PAGE_SIZE - page_offset;
        if (chunk_size > remaining) {
            chunk_size = remaining;
        }

        /* Probe PTE for current page */
        uint64_t pte = 0;
        if (pmap_probe_pte(vmem, vaddr, &pte) != 0) {
            return -EFAULT;
        }

        /* Extract physical address from PTE and add page offset */
        phys_addr_t phys = (pte & 0xFFFFFFFFF000ULL) + page_offset;

        /* Convert to kernel virtual address and copy */
        void *kern_addr = (void *)pmap_phys_to_virt(phys);
        memcpy(kern_addr, src_bytes, chunk_size);

        /* Advance pointers */
        src_bytes += chunk_size;
        vaddr += chunk_size;
        remaining -= chunk_size;
    }

    return 0;
}

static size_t kstrlen(const char *s) {
    if (!s) {
        return 0;
    }
    const char *p = s;
    while (*p) {
        ++p;
    }
    return (size_t)(p - s);
}

static inline fut_vmem_context_t *mm_context(fut_mm_t *mm) {
    return fut_mm_context(mm);
}

/* REMOVED: Duplicate definition - see line 1049 for active implementation */

static int read_exact(int fd, void *buf, size_t len) {
    size_t done = 0;
    uint8_t *out = buf ? (uint8_t *)buf : NULL;
    while (done < len) {
        ssize_t rd = fut_vfs_read(fd, out ? out + done : NULL, len - done);
        if (rd < 0) {
            return (int)rd;
        }
        if (rd == 0) {
            return -EIO;
        }
        done += (size_t)rd;
    }
    return 0;
}

static int map_segment(fut_mm_t *mm, int fd, const elf64_phdr_t *phdr) {
    if (phdr->p_memsz == 0) {
        return 0;
    }

    uint64_t seg_start = phdr->p_vaddr & ~(PAGE_SIZE - 1ULL);
    uint64_t seg_offset = phdr->p_vaddr - seg_start;
    uint64_t seg_end = (phdr->p_vaddr + phdr->p_memsz + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL);
    size_t page_count = (size_t)((seg_end - seg_start) / PAGE_SIZE);

    EXEC_DEBUG("[EXEC][MAP-SEGMENT] vaddr=0x%llx memsz=0x%llx filesz=0x%llx page_count=%llu\n",
               (unsigned long long)phdr->p_vaddr,
               (unsigned long long)phdr->p_memsz,
               (unsigned long long)phdr->p_filesz,
               (unsigned long long)page_count);

    uint64_t flags = PTE_PRESENT | PTE_USER;
    if (phdr->p_flags & PF_W) {
        flags |= PTE_WRITABLE;
    }
    if ((phdr->p_flags & PF_X) == 0) {
        flags |= PTE_NX;
    }
    EXEC_DEBUG("[EXEC][MAP-SEGMENT] phdr->p_flags=0x%x (R=%d W=%d X=%d) -> flags=0x%llx (NX=%d)\n",
               (unsigned)phdr->p_flags,
               (int)((phdr->p_flags & PF_R) != 0),
               (int)((phdr->p_flags & PF_W) != 0),
               (int)((phdr->p_flags & PF_X) != 0),
               (unsigned long long)flags,
               (int)((flags & PTE_NX) != 0));

    size_t pages_array_size = page_count * sizeof(uint8_t *);
    EXEC_DEBUG("[EXEC][MAP-SEGMENT] Allocating pages array: %llu bytes\n",
               (unsigned long long)pages_array_size);
    uint8_t **pages = fut_malloc(pages_array_size);
    if (!pages) {
        EXEC_DEBUG("[EXEC][MAP-SEGMENT] FAILED: pages array malloc returned NULL\n");
        return -ENOMEM;
    }
    EXEC_DEBUG("[EXEC][MAP-SEGMENT] pages array allocated at %p\n", (void*)pages);

    for (size_t i = 0; i < page_count; ++i) {
        EXEC_DEBUG("[EXEC][MAP-SEGMENT] Allocating physical page %llu/%llu\n",
                   (unsigned long long)i, (unsigned long long)page_count);
        uint8_t *page = fut_pmm_alloc_page();
        if (!page) {
            EXEC_DEBUG("[EXEC][MAP-SEGMENT] FAILED: PMM alloc_page returned NULL at iteration %llu/%llu\n",
                       (unsigned long long)i, (unsigned long long)page_count);
            for (size_t j = 0; j < i; ++j) {
                fut_unmap_range(mm_context(mm), seg_start + j * PAGE_SIZE, PAGE_SIZE);
                fut_pmm_free_page(pages[j]);
            }
            fut_free(pages);
            return -ENOMEM;
        }

        memset(page, 0, PAGE_SIZE);

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        int rc = pmap_map_user(mm_context(mm),
                               seg_start + (uint64_t)i * PAGE_SIZE,
                               phys,
                               PAGE_SIZE,
                               flags);
        if (rc != 0) {
            fut_pmm_free_page(page);
            for (size_t j = 0; j < i; ++j) {
                fut_unmap_range(mm_context(mm), seg_start + j * PAGE_SIZE, PAGE_SIZE);
                fut_pmm_free_page(pages[j]);
            }
            fut_free(pages);
            return rc;
        }

        pages[i] = page;

        uint64_t pte = 0;
        if (pmap_probe_pte(mm_context(mm), seg_start + (uint64_t)i * PAGE_SIZE, &pte) == 0) {
            EXEC_DEBUG("[EXEC][MAP] vaddr=0x%llx pte=0x%llx flags=0x%llx NX=%d\n",
                       (unsigned long long)(seg_start + (uint64_t)i * PAGE_SIZE),
                       (unsigned long long)pte,
                       (unsigned long long)fut_pte_flags(pte),
                       (int)((pte >> 63) & 1));
        }
    }

    if (phdr->p_filesz > 0) {
        /* Disable interrupts during file copy to prevent timer IRQs from
         * corrupting state mid-operation */
        __asm__ volatile("cli");

        EXEC_DEBUG("[EXEC][MAP-SEGMENT] Allocating file buffer: %llu bytes\n",
                   (unsigned long long)phdr->p_filesz);
        uint8_t *buffer = fut_malloc((size_t)phdr->p_filesz);
        if (!buffer) {
            EXEC_DEBUG("[EXEC][MAP-SEGMENT] FAILED: file buffer malloc returned NULL\n");
            __asm__ volatile("sti");  /* Re-enable interrupts before error return */
            fut_free(pages);
            return -ENOMEM;
        }
        EXEC_DEBUG("[EXEC][MAP-SEGMENT] file buffer allocated at %p\n", (void*)buffer);

        int64_t off = fut_vfs_lseek(fd, (int64_t)phdr->p_offset, SEEK_SET);
        if (off < 0) {
            __asm__ volatile("sti");  /* Re-enable interrupts before error return */
            fut_free(buffer);
            fut_free(pages);
            return (int)off;
        }

        int rc = read_exact(fd, buffer, (size_t)phdr->p_filesz);
        if (rc != 0) {
            __asm__ volatile("sti");  /* Re-enable interrupts before error return */
            fut_free(buffer);
            fut_free(pages);
            return rc;
        }

        size_t remaining = (size_t)phdr->p_filesz;
        size_t page_index = 0;
        size_t page_offset = (size_t)seg_offset;
        uint8_t *src = buffer;

        EXEC_DEBUG("[MAP-SEG] Starting copy loop: remaining=%zu pages=%zu offset=%zu\n",
                   remaining, page_count, page_offset);
        while (remaining > 0 && page_index < page_count) {
            size_t chunk = PAGE_SIZE - page_offset;
            if (chunk > remaining) {
                chunk = remaining;
            }
            /* Sanity check: pages[page_index] must be a kernel address */
            uint8_t *dest = pages[page_index];
            EXEC_DEBUG("[MAP-SEG] Loop: idx=%zu dest=%p chunk=%zu\n",
                       page_index, (void*)dest, chunk);
            if ((uintptr_t)dest < KERNEL_VIRTUAL_BASE) {
                fut_printf("[MAP-SEG] FATAL: pages[%zu]=%p is USER addr, not kernel!\n",
                           page_index, (void*)dest);
                fut_printf("[MAP-SEG] page_count=%zu seg_start=0x%llx\n",
                           page_count, (unsigned long long)seg_start);
                /* Don't crash - return error */
                __asm__ volatile("sti");  /* Re-enable interrupts before error return */
                fut_free(buffer);
                fut_free(pages);
                return -EFAULT;
            }
            EXEC_DEBUG("[MAP-SEG] About to memcpy to %p\n", (void*)(dest + page_offset));
            memcpy(dest + page_offset, src, chunk);
            EXEC_DEBUG("[MAP-SEG] memcpy done\n");
            src += chunk;
            remaining -= chunk;
            page_index++;
            page_offset = 0;
        }

        /* Ensure all writes are visible before we execute this code */
        __asm__ volatile("mfence" ::: "memory");

        EXEC_DEBUG("[EXEC][MAP-SEGMENT] Copied %llu bytes to pages, memory barrier done\n",
                   (unsigned long long)phdr->p_filesz);

        fut_free(buffer);

        /* NOTE: Interrupts stay disabled - they are disabled at the start of
         * fut_exec_elf and re-enabled when transitioning to user mode via IRET.
         * This prevents timer interrupts from corrupting forked children. */
    }

    fut_free(pages);
    return 0;
}

static int build_user_stack(fut_mm_t *mm,
                            const char *const argv_in[],
                            size_t argc_in,
                            const char *const envp_in[],
                            size_t envc_in,
                            uint64_t *out_rsp,
                            uint64_t *out_argv,
                            uint64_t *out_argc) {
    if (!out_rsp || !out_argv || !out_argc) {
        return -EINVAL;
    }

    size_t argc = argc_in;
    const char *const *argv = argv_in;

    if (!argv) {
        static const char *default_argv[2] = { "fbtest", NULL };
        argv = default_argv;
        argc = 1;
    } else if (argc == 0) {
        while (argv[argc]) {
            argc++;
        }
        if (argc == 0) {
            static const char *default_argv[2] = { "fbtest", NULL };
            argv = default_argv;
            argc = 1;
        }
    }

    /* Count environment variables if not provided */
    size_t envc = envc_in;
    const char *const *envp = envp_in;
    if (envp) {
        if (envc == 0) {
            while (envp[envc]) {
                envc++;
            }
        }
#ifdef DEBUG_EXEC
        execdbg_printf("[EXEC-DEBUG] build_user_stack: envc=%zu\n", envc);
        for (size_t i = 0; i < envc; i++) {
            execdbg_printf("[EXEC-DEBUG]   envp[%zu]='%s'\n", i, envp[i]);
        }
#endif
    }

    /* Allocate string pointers for both argv and envp */
    uint8_t **string_ptrs = fut_malloc(sizeof(uint8_t *) * (argc + envc));
    if (!string_ptrs) {
        return -ENOMEM;
    }

    uint64_t sp = USER_STACK_TOP;

    /* Copy environment variable strings first (highest addresses) */
    stack_printf("[STACK-DEBUG] Copying %zu envp strings, envp=%p\n", envc, envp);
    for (size_t i = envc; i-- > 0;) {
        /* Debug: Read the pointer value from the array */
        const char *ptr = envp[i];
        uintptr_t ptr_val = (uintptr_t)ptr;
        stack_printf("[STACK-DEBUG] envp[%zu]=%p (0x%016lx) kernel=%d\n",
                   i, ptr, ptr_val, ptr_val >= 0xFFFF800000000000ULL);
        size_t len = kstrlen(ptr) + 1;
        stack_printf("[STACK-DEBUG] envp[%zu] len=%zu\n", i, len);
        sp -= len;
        if (exec_copy_to_user(mm, sp, envp[i], len) != 0) {
            fut_free(string_ptrs);
            return -EFAULT;
        }
        string_ptrs[argc + i] = (uint8_t *)(uintptr_t)sp;
    }

    /* Copy argument strings */
    for (size_t i = argc; i-- > 0;) {
        size_t len = kstrlen(argv[i]) + 1;
        sp -= len;
        if (exec_copy_to_user(mm, sp, argv[i], len) != 0) {
            fut_free(string_ptrs);
            return -EFAULT;
        }
        string_ptrs[i] = (uint8_t *)(uintptr_t)sp;
    }

    sp &= ~0xFULL;

    uint64_t zero = 0;

    /* Push envp terminator (NULL pointer) */
    sp -= sizeof(uint64_t);
    if (exec_copy_to_user(mm, sp, &zero, sizeof(zero)) != 0) {
        fut_free(string_ptrs);
        return -EFAULT;
    }

    /* Push environment variable pointers in reverse order */
    for (size_t i = envc; i-- > 0;) {
        uint64_t ptr = (uint64_t)(uintptr_t)string_ptrs[argc + i];
        sp -= sizeof(uint64_t);
        if (exec_copy_to_user(mm, sp, &ptr, sizeof(ptr)) != 0) {
            fut_free(string_ptrs);
            return -EFAULT;
        }
    }

    /* Note: envp_ptr would be sp here - pointer to environment variables array */

    /* Push argv terminator (NULL pointer) */
    sp -= sizeof(uint64_t);
    if (exec_copy_to_user(mm, sp, &zero, sizeof(zero)) != 0) {
        fut_free(string_ptrs);
        return -EFAULT;
    }

    /* Push argument pointers in reverse order */
    for (size_t i = argc; i-- > 0;) {
        uint64_t ptr = (uint64_t)(uintptr_t)string_ptrs[i];
        sp -= sizeof(uint64_t);
        if (exec_copy_to_user(mm, sp, &ptr, sizeof(ptr)) != 0) {
            fut_free(string_ptrs);
            return -EFAULT;
        }
    }

    uint64_t argv_ptr = sp;

    if (((sp - sizeof(uint64_t)) & 0xFULL) != 0) {
        sp -= sizeof(uint64_t);
        if (exec_copy_to_user(mm, sp, &zero, sizeof(zero)) != 0) {
            fut_free(string_ptrs);
            return -EFAULT;
        }
    }

    uint64_t argc_val = (uint64_t)argc;
    sp -= sizeof(uint64_t);
    if (exec_copy_to_user(mm, sp, &argc_val, sizeof(argc_val)) != 0) {
        fut_free(string_ptrs);
        return -EFAULT;
    }

    *out_rsp = sp;
    *out_argv = argv_ptr;
    *out_argc = argc_val;

    fut_free(string_ptrs);
    return 0;
}

[[noreturn]] __attribute__((optimize("O0"))) static void fut_user_trampoline(void *arg) {
    /* CRITICAL: Disable interrupts IMMEDIATELY to prevent timer interrupts from
     * corrupting our state during the transition to user mode! */
    __asm__ volatile("cli");

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print 'U' to indicate we reached fut_user_trampoline */
    __asm__ volatile(
        "pushq %%rax\n"
        "pushq %%rdx\n"
        "movw $0x3F8, %%dx\n"
        "movb $'U', %%al\n"
        "outb %%al, %%dx\n"
        "popq %%rdx\n"
        "popq %%rax\n"
        ::: "memory"
    );
#endif

    if (!arg) {
        __asm__ volatile("sti");  /* Re-enable before exit */
        extern void fut_thread_exit(void);
        fut_thread_exit();
    }

    /* Extract values from the user entry structure BEFORE freeing it */
    struct fut_user_entry *info = (struct fut_user_entry *)arg;

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '1' after casting - must use DX form for ports > 255 */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'1', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    uint64_t entry = info->entry;

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '2' after reading entry */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'2', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    uint64_t stack = info->stack;
    uint64_t argc = info->argc;
    uint64_t argv_ptr = info->argv_ptr;
    fut_task_t *task = info->task;

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '3' after reading task */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'3', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    /* Get the mm from the task */
    fut_mm_t *mm = task ? task->mm : NULL;

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '4' after getting mm */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'4', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    if (!task || !mm) {
#ifdef DEBUG_USER_TRAMPOLINE
        __asm__ volatile("movw $0x3F8, %%dx; movb $'X', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif
        __asm__ volatile("sti");  /* Re-enable before exit */
        extern void fut_thread_exit(void);
        fut_thread_exit();
    }

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '5' after task/mm check */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'5', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    /* Verify we're using the task's CR3, not the kernel CR3 */
    extern uint64_t fut_read_cr3(void);
    uint64_t current_cr3 = fut_read_cr3();

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '6' after reading CR3 */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'6', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    uint64_t expected_cr3 = mm_context(mm)->cr3_value;

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '7' after getting expected_cr3 */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'7', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    if (current_cr3 != expected_cr3) {
#ifdef DEBUG_USER_TRAMPOLINE
        /* Debug: Print '8' before CR3 write */
        __asm__ volatile("movw $0x3F8, %%dx; movb $'8', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif
        extern void fut_write_cr3(uint64_t);
        fut_write_cr3(expected_cr3);
#ifdef DEBUG_USER_TRAMPOLINE
        /* Debug: Print '9' after CR3 write */
        __asm__ volatile("movw $0x3F8, %%dx; movb $'9', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif
    }

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print 'A' before fut_do_user_iretq */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'A', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    /* NO DEBUG OUTPUT ALLOWED HERE - printf triggers CR3 switches that break IRETQ! */

    /* Optionally verify mappings without printf (for debugging with debugger):
     * uint64_t test_pte = 0;
     * pmap_probe_pte(mm_context(mm), stack, &test_pte);  // Check stack mapping
     * pmap_probe_pte(mm_context(mm), entry, &test_pte);  // Check entry mapping
     */

    /* Set FS_BASE for TLS (Thread Local Storage) support
     * Required for stack canary checking in code compiled with -fstack-protector
     * The stack canary is read from %fs:0x28 */
    wrmsr(MSR_FS_BASE, USER_TLS_BASE);

    /* Store fs_base in thread structure so scheduler can restore it after context switch */
    fut_thread_t *cur_thread = fut_thread_current();
    if (cur_thread) {
        cur_thread->fs_base = USER_TLS_BASE;
        /* Set user segment selectors in context so scheduler can construct valid
         * IRETQ frames after irq_frame is cleared. Without this, the context has
         * kernel segments (0x10) from thread creation, causing crashes when the
         * scheduler constructs a frame from context for a user thread. */
        cur_thread->context.ds = USER_DATA_SELECTOR;  /* 0x1B */
        cur_thread->context.es = USER_DATA_SELECTOR;
        cur_thread->context.fs = USER_DATA_SELECTOR;  /* FS base set via MSR */
        cur_thread->context.gs = USER_DATA_SELECTOR;
        cur_thread->context.cs = USER_CODE_SELECTOR;  /* 0x23 */
        cur_thread->context.ss = USER_DATA_SELECTOR;  /* 0x1B */
        /* Also update RIP and RSP to user values. If irq_frame is cleared and
         * scheduler constructs a frame from context, it needs valid user addresses.
         * Without this, context.rip has kernel trampoline addr causing page fault. */
        cur_thread->context.rip = entry;
        cur_thread->context.rsp = stack;
        cur_thread->context.rflags = 0x202;  /* IF=1, reserved bit 1 set */
    }

    /* Call the pure assembly function to perform IRETQ to userspace
     * This function never returns */
    fut_do_user_iretq(entry, stack, argc, argv_ptr);

    /* Should NEVER reach here */
    extern void fut_platform_panic(const char *);
    fut_platform_panic("[FATAL] fut_do_user_iretq returned - this should never happen!");
    while (1) { __asm__ volatile("hlt"); }
}

static int stage_stack_pages(fut_mm_t *mm, uint64_t *out_stack_top) {
    uint64_t base = USER_STACK_TOP - (uint64_t)USER_STACK_PAGES * PAGE_SIZE;
    uint8_t *pages[USER_STACK_PAGES];
    for (size_t i = 0; i < USER_STACK_PAGES; ++i) {
        pages[i] = NULL;
    }

    for (size_t i = 0; i < USER_STACK_PAGES; ++i) {
        uint8_t *page = fut_pmm_alloc_page();
        if (!page) {
            for (size_t j = 0; j < i; ++j) {
                fut_unmap_range(mm_context(mm), base + (uint64_t)j * PAGE_SIZE, PAGE_SIZE);
                if (pages[j]) {
                    fut_pmm_free_page(pages[j]);
                }
            }
            return -ENOMEM;
        }

        memset(page, 0, PAGE_SIZE);
        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);

        pages[i] = page;
        EXEC_DEBUG("[EXEC] stage_stack page[%u]=%p\n", (unsigned)i, (void *)page);

        int rc = pmap_map_user(mm_context(mm),
                               base + (uint64_t)i * PAGE_SIZE,
                               phys,
                               PAGE_SIZE,
                               PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX);
        if (rc != 0) {
            fut_pmm_free_page(page);
            /* Note: Use j < i (not j <= i) because pages[i] points to the same
             * memory as 'page' which was already freed above. Using j <= i would
             * cause a double-free of the current page. */
            for (size_t j = 0; j < i; ++j) {
                fut_unmap_range(mm_context(mm), base + (uint64_t)j * PAGE_SIZE, PAGE_SIZE);
                if (pages[j]) {
                    fut_pmm_free_page(pages[j]);
                }
            }
            return rc;
        }
    }

    *out_stack_top = USER_STACK_TOP;
    return 0;
}

/**
 * stage_tls_page - Allocate and map TLS block for userspace
 *
 * Sets up Thread Local Storage for stack canary support required by
 * code compiled with -fstack-protector. The stack canary is read from
 * %fs:0x28 by gcc-generated code.
 *
 * @mm: Memory map for the process
 * @out_tls_base: Output pointer to receive the TLS base address
 * @return: 0 on success, negative errno on failure
 */
static int stage_tls_page(fut_mm_t *mm, uint64_t *out_tls_base) {
    /* Allocate a page for TLS */
    uint8_t *page = fut_pmm_alloc_page();
    if (!page) {
        return -ENOMEM;
    }

    /* Zero the page */
    memset(page, 0, PAGE_SIZE);

    /* Initialize stack canary at offset 0x28
     * Use TSC directly for entropy (avoid fut_get_time_ns which may hang) */
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
    uint64_t canary = (((uint64_t)hi << 32) | lo) ^ 0xDEADBEEFCAFEBABEULL ^ (uintptr_t)page;
    /* Ensure canary has a null byte to help detect string overflows */
    canary &= ~0xFFULL;
    *(uint64_t *)(page + TLS_STACK_CANARY_OFFSET) = canary;

    /* Map to userspace */
    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    int rc = pmap_map_user(mm_context(mm),
                           USER_TLS_BASE,
                           phys,
                           PAGE_SIZE,
                           PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX);
    if (rc != 0) {
        fut_pmm_free_page(page);
        return rc;
    }

    *out_tls_base = USER_TLS_BASE;
    return 0;
}

/* Framebuffer diagnostics (optional) */
#if ENABLE_FB_DIAGNOSTICS
extern const uint8_t _binary_build_bin_x86_64_user_fbtest_start[];
extern const uint8_t _binary_build_bin_x86_64_user_fbtest_end[];
#endif
extern const uint8_t _binary_build_bin_x86_64_user_shell_start[];
extern const uint8_t _binary_build_bin_x86_64_user_shell_end[];
extern const uint8_t _binary_build_bin_x86_64_user_init_stub_start[];
extern const uint8_t _binary_build_bin_x86_64_user_init_stub_end[];
extern const uint8_t _binary_build_bin_x86_64_user_second_start[];
extern const uint8_t _binary_build_bin_x86_64_user_second_end[];
/* Core Wayland binaries (production) */
extern const uint8_t _binary_build_bin_x86_64_user_futura_wayland_start[];
extern const uint8_t _binary_build_bin_x86_64_user_futura_wayland_end[];
extern const uint8_t _binary_build_bin_x86_64_user_futura_shell_start[];
extern const uint8_t _binary_build_bin_x86_64_user_futura_shell_end[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_term_start[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_term_end[];
/* Test clients (optional) */
#if ENABLE_WAYLAND_TEST_CLIENTS
extern const uint8_t _binary_build_bin_x86_64_user_wl_simple_start[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_simple_end[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_colorwheel_start[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_colorwheel_end[];
#endif

#if ENABLE_FB_DIAGNOSTICS
int fut_stage_fbtest_binary(void) {
    EXEC_DEBUG("[STAGE] fut_stage_fbtest_binary start\n");

    EXEC_DEBUG("[STAGE] calculating binary size\n");
    size_t size = (size_t)(_binary_build_bin_x86_64_user_fbtest_end - _binary_build_bin_x86_64_user_fbtest_start);
    EXEC_DEBUG("[STAGE] binary size = %llu bytes\n", (unsigned long long)size);
    if (size == 0) {
        return -EINVAL;
    }

    EXEC_DEBUG("[STAGE] calling fut_vfs_mkdir\n");
    (void)fut_vfs_mkdir("/bin", 0755);

    EXEC_DEBUG("[STAGE] calling fut_vfs_open\n");
    int fd = fut_vfs_open("/bin/fbtest", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    EXEC_DEBUG("[STAGE] fut_vfs_open returned fd=%d\n", fd);
    if (fd < 0) {
        return fd;
    }

    EXEC_DEBUG("[STAGE] entering write loop, size=%llu\n", (unsigned long long)size);
    size_t offset = 0;
    while (offset < size) {
        EXEC_DEBUG("[STAGE] loop iteration: offset=%llu size=%llu\n",
                   (unsigned long long)offset, (unsigned long long)size);
        size_t chunk = size - offset;
        EXEC_DEBUG("[STAGE] calculated chunk=%llu\n", (unsigned long long)chunk);
        if (chunk > 4096) {
            chunk = 4096;
        }
        EXEC_DEBUG("[STAGE] limited chunk=%llu\n", (unsigned long long)chunk);

        EXEC_DEBUG("[STAGE] calling fut_vfs_write fd=%d chunk=%llu\n",
                   fd, (unsigned long long)chunk);
        ssize_t wr = fut_vfs_write(fd,
                                   _binary_build_bin_x86_64_user_fbtest_start + offset,
                                   chunk);
        EXEC_DEBUG("[STAGE] fut_vfs_write returned %lld\n", (long long)wr);
        if (wr < 0) {
            fut_vfs_close(fd);
            return (int)wr;
        }
        offset += (size_t)wr;
    }

    EXEC_DEBUG("[STAGE] calling fut_vfs_close\n");
    fut_vfs_close(fd);
    EXEC_DEBUG("[STAGE] fut_stage_fbtest_binary complete\n");
    return 0;
}
#endif

static int stage_blob(const uint8_t *start,
                      const uint8_t *end,
                      const char *path) {
    EXEC_DEBUG("[stage_blob] enter path=%s\n", path);
    size_t size = (size_t)(end - start);
    EXEC_DEBUG("[stage_blob] size calculated\n");
    if (!start || !end || size == 0) {
        fut_printf("[stage_blob] invalid params\n");
        return -EINVAL;
    }

    EXEC_DEBUG("[stage_blob] calling fut_vfs_open\n");
    int fd = fut_vfs_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    EXEC_DEBUG("[stage_blob] fut_vfs_open returned fd=%d\n", fd);
    if (fd < 0) {
        fut_printf("[stage_blob] open failed\n");
        return fd;
    }

    EXEC_DEBUG("[stage_blob] entering write loop\n");
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > 4096) {
            chunk = 4096;
        }
        EXEC_DEBUG("[stage_blob] calling fut_vfs_write offset=%llu chunk=%llu\n", (unsigned long long)offset, (unsigned long long)chunk);
        ssize_t wr = fut_vfs_write(fd, start + offset, chunk);
        EXEC_DEBUG("[stage_blob] fut_vfs_write returned wr=%zd\n", wr);
        if (wr < 0) {
            fut_printf("[stage_blob] write error, closing fd\n");
            fut_vfs_close(fd);
            return (int)wr;
        }
        offset += (size_t)wr;
    }

    EXEC_DEBUG("[stage_blob] all writes complete, closing fd=%d\n", fd);
    (void)fut_vfs_close(fd);
    EXEC_DEBUG("[stage_blob] returning success\n");
    return 0;
}

#ifndef FUTURA_MACOS_HOST_BUILD
int fut_stage_shell_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_shell_start,
                      _binary_build_bin_x86_64_user_shell_end,
                      "/bin/shell");
}
#else
int fut_stage_shell_binary(void) {
    return -ENOSYS;  /* Shell binary not available on macOS host builds */
}
#endif

#ifdef __x86_64__
int fut_stage_init_stub_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_init_stub_start,
                      _binary_build_bin_x86_64_user_init_stub_end,
                      "/sbin/init_stub");
}

int fut_stage_second_stub_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_second_start,
                      _binary_build_bin_x86_64_user_second_end,
                      "/sbin/second");
}
#else /* !__x86_64__ */
#include <kernel/errno.h>

int fut_stage_init_stub_binary(void) {
    return -ENOSYS;  /* Not implemented for non-x86_64 platforms */
}

int fut_stage_second_stub_binary(void) {
    return -ENOSYS;  /* Not implemented for non-x86_64 platforms */
}
#endif /* __x86_64__ */

/* Core Wayland binaries (production - always built) */
#ifndef FUTURA_MACOS_HOST_BUILD
int fut_stage_wayland_compositor_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);

    size_t wayland_size = (size_t)(_binary_build_bin_x86_64_user_futura_wayland_end - _binary_build_bin_x86_64_user_futura_wayland_start);
    EXEC_DEBUG("[STAGE] Wayland binary: start=%p end=%p size=%llu\n",
               (void*)_binary_build_bin_x86_64_user_futura_wayland_start,
               (void*)_binary_build_bin_x86_64_user_futura_wayland_end,
               (unsigned long long)wayland_size);
    (void)wayland_size;  /* Used in EXEC_DEBUG macro, may be unused if debug disabled */

    return stage_blob(_binary_build_bin_x86_64_user_futura_wayland_start,
                      _binary_build_bin_x86_64_user_futura_wayland_end,
                      "/sbin/futura-wayland");
}

int fut_stage_wl_term_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_wl_term_start,
                      _binary_build_bin_x86_64_user_wl_term_end,
                      "/bin/wl-term");
}

int fut_stage_futura_shell_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_futura_shell_start,
                      _binary_build_bin_x86_64_user_futura_shell_end,
                      "/bin/futura-shell");
}
#else
int fut_stage_wayland_compositor_binary(void) {
    return -ENOSYS;  /* Wayland not available on macOS host builds */
}

int fut_stage_wl_term_binary(void) {
    return -ENOSYS;  /* Wayland not available on macOS host builds */
}

int fut_stage_futura_shell_binary(void) {
    return -ENOSYS;  /* futura-shell not available on macOS host builds */
}
#endif

/* Test client binaries (optional - only built with ENABLE_WAYLAND_TEST_CLIENTS) */
#if ENABLE_WAYLAND_TEST_CLIENTS
int fut_stage_wayland_client_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_wl_simple_start,
                      _binary_build_bin_x86_64_user_wl_simple_end,
                      "/bin/wl-simple");
}

int fut_stage_wayland_color_client_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_wl_colorwheel_start,
                      _binary_build_bin_x86_64_user_wl_colorwheel_end,
                      "/bin/wl-colorwheel");
}
#else
int fut_stage_wayland_client_binary(void) {
    return -ENOSYS;
}

int fut_stage_wayland_color_client_binary(void) {
    return -ENOSYS;
}
#endif

int fut_exec_elf(const char *path, char *const argv[], char *const envp[]) {
    ELF_LOG("[EXEC-ELF] ENTER: path=%s argv=%p envp=%p\n", path ? path : "(null)", argv, envp);

    if (!path) {
        return -EINVAL;
    }

    /* CRITICAL: Disable interrupts for the ENTIRE exec operation.
     * When a forked child calls exec, its thread->context still contains
     * user-mode values (user RIP, user CS) from fork(). If a timer interrupt
     * fires during exec and the scheduler constructs a frame from the stale
     * user-mode context, IRET will jump to a user address in the just-replaced
     * address space - resulting in GPF or page faults.
     * Interrupts will be re-enabled when transitioning to user mode via IRET. */
    __asm__ volatile("cli");

    /* CRITICAL: Copy argv and envp to kernel memory BEFORE creating new MM.
     * If argv/envp point to userspace, a context switch during exec could
     * cause the old address space to become inaccessible, leading to page faults.
     *
     * SMAP FIX: Detect if argv/envp are kernel or userspace pointers.
     * sys_execve may pass kernel arrays (kernel_argv/kernel_envp) that are already
     * safe kernel copies. Only use fut_copy_from_user for userspace pointers. */
    size_t argc = 0;
    size_t envc = 0;
    char **kargv = NULL;
    char **kenvp = NULL;

    /* Check if argv is a kernel pointer (high half of address space on x86_64) */
    int argv_is_kernel = (argv && (uintptr_t)argv >= 0xFFFF800000000000ULL);
    int envp_is_kernel = (envp && (uintptr_t)envp >= 0xFFFF800000000000ULL);
    int kargv_needs_free = 0;  /* Track if we allocated kargv */
    int kenvp_needs_free = 0;  /* Track if we allocated kenvp */

    ELF_LOG("[EXEC-ELF] argv_is_kernel=%d envp_is_kernel=%d\n", argv_is_kernel, envp_is_kernel);

    if (argv && !argv_is_kernel) {
        /* SMAP FIX: Count arguments using safe userspace copy */
        char *ptr = NULL;
        while (argc < 1000) {
            if (fut_copy_from_user(&ptr, &argv[argc], sizeof(char *)) != 0) {
                break;  /* Access error */
            }
            if (ptr == NULL) {
                break;  /* NULL terminator */
            }
            argc++;
        }
        if (argc > 0) {
            kargv = fut_malloc((argc + 1) * sizeof(char *));
            kargv_needs_free = 1;
            if (!kargv) { __asm__ volatile("sti"); return -ENOMEM; }
            for (size_t i = 0; i < argc; i++) {
                /* SMAP FIX: Read argv[i] pointer safely */
                const char *arg_ptr = NULL;
                if (fut_copy_from_user((void *)&arg_ptr, &argv[i], sizeof(char *)) != 0) {
                    for (size_t j = 0; j < i; j++) fut_free(kargv[j]);
                    fut_free(kargv);
                    __asm__ volatile("sti");
                    return -EFAULT;
                }
                /* SMAP FIX: Calculate string length safely */
                size_t len = 0;
                char ch = 1;
                while (len < 4096) {
                    if (fut_copy_from_user(&ch, arg_ptr + len, 1) != 0) {
                        break;
                    }
                    if (ch == '\0') {
                        break;
                    }
                    len++;
                }
                len++;  /* Include null terminator */
                kargv[i] = fut_malloc(len);
                if (!kargv[i]) {
                    for (size_t j = 0; j < i; j++) fut_free(kargv[j]);
                    fut_free(kargv);
                    __asm__ volatile("sti");
                    return -ENOMEM;
                }
                /* SMAP FIX: Copy string safely */
                if (fut_copy_from_user(kargv[i], arg_ptr, len) != 0) {
                    for (size_t j = 0; j <= i; j++) fut_free(kargv[j]);
                    fut_free(kargv);
                    __asm__ volatile("sti");
                    return -EFAULT;
                }
            }
            kargv[argc] = NULL;
        }
    } else if (argv && argv_is_kernel) {
        /* argv is a kernel pointer - count entries first */
        const char *const *src_argv = (const char *const *)argv;
        while (src_argv[argc]) argc++;

        /* IMPORTANT: Must COPY strings even from kernel pointers!
         * See envp comment below - CR3 switch makes old allocations inaccessible. */
        if (argc > 0) {
            kargv = fut_malloc((argc + 1) * sizeof(char *));
            kargv_needs_free = 1;
            if (!kargv) { __asm__ volatile("sti"); return -ENOMEM; }
            for (size_t i = 0; i < argc; i++) {
                size_t len = kstrlen(src_argv[i]) + 1;
                kargv[i] = fut_malloc(len);
                if (!kargv[i]) {
                    for (size_t j = 0; j < i; j++) fut_free(kargv[j]);
                    fut_free(kargv);
                    __asm__ volatile("sti");
                    return -ENOMEM;
                }
                extern void *memcpy(void *, const void *, size_t);
                memcpy(kargv[i], src_argv[i], len);
            }
            kargv[argc] = NULL;
        }
    }

    if (envp && !envp_is_kernel) {
        /* SMAP FIX: Count environment variables using safe userspace copy */
        char *ptr = NULL;
        while (envc < 1000) {
            if (fut_copy_from_user(&ptr, &envp[envc], sizeof(char *)) != 0) {
                break;  /* Access error */
            }
            if (ptr == NULL) {
                break;  /* NULL terminator */
            }
            envc++;
        }
        if (envc > 0) {
            kenvp = fut_malloc((envc + 1) * sizeof(char *));
            kenvp_needs_free = 1;
            if (!kenvp) {
                if (kargv && kargv_needs_free) {
                    for (size_t i = 0; i < argc; i++) fut_free(kargv[i]);
                    fut_free(kargv);
                }
                __asm__ volatile("sti");
                return -ENOMEM;
            }
            for (size_t i = 0; i < envc; i++) {
                /* SMAP FIX: Read envp[i] pointer safely */
                const char *env_ptr = NULL;
                if (fut_copy_from_user((void *)&env_ptr, &envp[i], sizeof(char *)) != 0) {
                    for (size_t j = 0; j < i; j++) fut_free(kenvp[j]);
                    fut_free(kenvp);
                    if (kargv && kargv_needs_free) {
                        for (size_t j = 0; j < argc; j++) fut_free(kargv[j]);
                        fut_free(kargv);
                    }
                    __asm__ volatile("sti");
                    return -EFAULT;
                }
                /* SMAP FIX: Calculate string length safely */
                size_t len = 0;
                char ch = 1;
                while (len < 4096) {
                    if (fut_copy_from_user(&ch, env_ptr + len, 1) != 0) {
                        break;
                    }
                    if (ch == '\0') {
                        break;
                    }
                    len++;
                }
                len++;  /* Include null terminator */
                kenvp[i] = fut_malloc(len);
                if (!kenvp[i]) {
                    for (size_t j = 0; j < i; j++) fut_free(kenvp[j]);
                    fut_free(kenvp);
                    if (kargv && kargv_needs_free) {
                        for (size_t j = 0; j < argc; j++) fut_free(kargv[j]);
                        fut_free(kargv);
                    }
                    __asm__ volatile("sti");
                    return -ENOMEM;
                }
                /* SMAP FIX: Copy string safely */
                if (fut_copy_from_user(kenvp[i], env_ptr, len) != 0) {
                    for (size_t j = 0; j <= i; j++) fut_free(kenvp[j]);
                    fut_free(kenvp);
                    if (kargv && kargv_needs_free) {
                        for (size_t j = 0; j < argc; j++) fut_free(kargv[j]);
                        fut_free(kargv);
                    }
                    __asm__ volatile("sti");
                    return -EFAULT;
                }
            }
            kenvp[envc] = NULL;
        }
    } else if (envp && envp_is_kernel) {
        /* envp is a kernel pointer - count entries first */
        const char *const *src_envp = (const char *const *)envp;
        while (src_envp[envc]) envc++;

        /* IMPORTANT: Even though envp is a kernel pointer, we must COPY the strings!
         * The strings were allocated in the OLD address space. When we call fut_mm_create()
         * below, it will switch CR3, making those allocations inaccessible. We need fresh
         * copies that will survive the CR3 switch. */
        if (envc > 0) {
            kenvp = fut_malloc((envc + 1) * sizeof(char *));
            kenvp_needs_free = 1;
            if (!kenvp) { __asm__ volatile("sti"); return -ENOMEM; }
            for (size_t i = 0; i < envc; i++) {
                /* Use kstrlen since source is kernel memory */
                size_t len = kstrlen(src_envp[i]) + 1;
                kenvp[i] = fut_malloc(len);
                if (!kenvp[i]) {
                    for (size_t j = 0; j < i; j++) fut_free(kenvp[j]);
                    fut_free(kenvp);
                    __asm__ volatile("sti");
                    return -ENOMEM;
                }
                /* Use memcpy since both are kernel pointers */
                extern void *memcpy(void *, const void *, size_t);
                memcpy(kenvp[i], src_envp[i], len);
            }
            kenvp[envc] = NULL;
        }
    }

    int fd = fut_vfs_open(path, O_RDONLY, 0);
    if (fd < 0) {
        if (kargv && kargv_needs_free) {
            for (size_t i = 0; i < argc; i++) {
                fut_free(kargv[i]);
            }
            fut_free(kargv);
        }
        if (kenvp && kenvp_needs_free) {
            for (size_t i = 0; i < envc; i++) {
                fut_free(kenvp[i]);
            }
            fut_free(kenvp);
        }
        __asm__ volatile("sti");
        return fd;
    }

    ELF_LOG("[EXEC-ELF] argc=%zu envc=%zu, about to read ELF header\n", argc, envc);
    fut_vfs_check_root_canary("fut_exec_elf:enter");

    /* Helper macro for cleanup - also re-enables interrupts since we
     * disabled them at the start of fut_exec_elf */
    #define EXEC_CLEANUP_KARGS() do { \
        if (kargv && kargv_needs_free) { \
            for (size_t _i = 0; _i < argc; _i++) fut_free(kargv[_i]); \
            fut_free(kargv); \
        } \
        if (kenvp && kenvp_needs_free) { \
            for (size_t _i = 0; _i < envc; _i++) fut_free(kenvp[_i]); \
            fut_free(kenvp); \
        } \
        __asm__ volatile("sti"); \
    } while (0)

    elf64_ehdr_t ehdr;
    int rc = read_exact(fd, &ehdr, sizeof(ehdr));
    if (rc != 0) {
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return rc;
    }

    EXEC_DEBUG("[EXEC] Read ELF header: magic=0x%08x class=%d data=%d\n",
               *(uint32_t *)ehdr.e_ident, ehdr.e_ident[4], ehdr.e_ident[5]);
    EXEC_DEBUG("[EXEC] ELF header: type=%d machine=%d version=%d entry=0x%llx\n",
               ehdr.e_type, ehdr.e_machine, ehdr.e_version,
               (unsigned long long)ehdr.e_entry);
    EXEC_DEBUG("[EXEC] Program headers: phoff=%llu phentsize=%d phnum=%d\n",
               (unsigned long long)ehdr.e_phoff, ehdr.e_phentsize, ehdr.e_phnum);

    if (*(uint32_t *)ehdr.e_ident != ELF_MAGIC) {
        EXEC_DEBUG("[EXEC] FAIL: Bad ELF magic 0x%08x (expected 0x%08x)\n",
                   *(uint32_t *)ehdr.e_ident, ELF_MAGIC);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -EINVAL;
    }

    if (ehdr.e_ident[4] != ELF_CLASS_64) {
        EXEC_DEBUG("[EXEC] FAIL: Bad ELF class %d (expected %d)\n",
                   ehdr.e_ident[4], ELF_CLASS_64);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -EINVAL;
    }

    if (ehdr.e_ident[5] != ELF_DATA_LE) {
        EXEC_DEBUG("[EXEC] FAIL: Bad ELF data %d (expected %d)\n",
                   ehdr.e_ident[5], ELF_DATA_LE);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -EINVAL;
    }

    if (ehdr.e_phentsize != sizeof(elf64_phdr_t)) {
        EXEC_DEBUG("[EXEC] FAIL: Bad phentsize %d (expected %zu)\n",
                   ehdr.e_phentsize, sizeof(elf64_phdr_t));
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -EINVAL;
    }

    if (ehdr.e_phnum == 0) {
        EXEC_DEBUG("[EXEC] FAIL: No program headers (phnum=0)\n");
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -EINVAL;
    }

    size_t ph_size = (size_t)ehdr.e_phnum * sizeof(elf64_phdr_t);
    elf64_phdr_t *phdrs = fut_malloc(ph_size);
    if (!phdrs) {
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOMEM;
    }

    int64_t seek_rc = fut_vfs_lseek(fd, (int64_t)ehdr.e_phoff, SEEK_SET);
    if (seek_rc < 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return (int)seek_rc;
    }

    rc = read_exact(fd, phdrs, ph_size);
    if (rc != 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return rc;
    }

    EXEC_DEBUG("[EXEC] Creating task...\n");
    fut_task_t *task = fut_task_create();
    if (!task) {
        EXEC_DEBUG("[EXEC] FAILED: fut_task_create returned NULL\n");
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOMEM;
    }
    EXEC_DEBUG("[EXEC] Task created at %p\n", (void*)task);

    EXEC_DEBUG("[EXEC] Creating memory manager...\n");
    fut_mm_t *mm = fut_mm_create();
    if (!mm) {
        EXEC_DEBUG("[EXEC] FAILED: fut_mm_create returned NULL\n");
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOMEM;
    }
    EXEC_DEBUG("[EXEC] MM created at %p\n", (void*)mm);
    /* NOTE: We do NOT call fut_task_set_mm here - task->mm must remain NULL
     * until all pages are mapped. If a timer IRQ fires and the scheduler
     * switches CR3 to an incomplete MM, we'll get page faults.
     * The task->mm is set only after build_user_stack completes. */

    uintptr_t heap_base_candidate = 0;

    EXEC_DEBUG("[EXEC] Mapping %u segments...\n", ehdr.e_phnum);
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        /* Cache p_type locally to prevent potential compiler optimization issues
         * when checking non-PT_LOAD segments (fixes GPF during shell exec). */
        uint32_t p_type = phdrs[i].p_type;
        if (p_type != PT_LOAD) {
            EXEC_DEBUG("[EXEC] Segment %u: not PT_LOAD (type=%u), skipping\n", i, p_type);
            continue;
        }
        EXEC_DEBUG("[EXEC] Segment %u: PT_LOAD, calling map_segment...\n", i);
        rc = map_segment(mm, fd, &phdrs[i]);
        if (rc != 0) {
            EXEC_DEBUG("[EXEC] FAILED: map_segment returned %d for segment %u\n", rc, i);
            fut_mm_release(mm);  /* mm not attached to task yet */
            fut_task_destroy(task);
            fut_free(phdrs);
            fut_vfs_close(fd);
            EXEC_CLEANUP_KARGS();
            return rc;
        }
        EXEC_DEBUG("[EXEC] Segment %u: map_segment succeeded\n", i);
        uint64_t seg_end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (seg_end > heap_base_candidate) {
            heap_base_candidate = (uintptr_t)seg_end;
        }
    }

    uintptr_t default_heap = 0x00400000ULL;
    uintptr_t heap_base = heap_base_candidate ? PAGE_ALIGN_UP(heap_base_candidate) : default_heap;
    heap_base += PAGE_SIZE;
    fut_mm_set_heap_base(mm, heap_base, 0);

    ELF_LOG("[EXEC-ELF] About to stage stack pages\n");
    uint64_t stack_top = 0;
    rc = stage_stack_pages(mm, &stack_top);
    if (rc != 0) {
        ELF_LOG("[EXEC-ELF] stage_stack_pages failed: %d\n", rc);
        fut_mm_release(mm);  /* mm not attached to task yet */
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return rc;
    }
    ELF_LOG("[EXEC-ELF] Stack pages staged, top=0x%llx\n", (unsigned long long)stack_top);

    /* Set up TLS for stack canary support */
    uint64_t tls_base = 0;
    rc = stage_tls_page(mm, &tls_base);
    if (rc != 0) {
        ELF_LOG("[EXEC-ELF] stage_tls_page failed: %d\n", rc);
        fut_mm_release(mm);
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return rc;
    }

    fut_vfs_check_root_canary("fut_exec_elf:after_stage_stack");

    uint64_t user_rsp = 0;
    uint64_t user_argv = 0;
    uint64_t user_argc = 0;
    /* Use the kernel copies of argv/envp that we made at the start */
    execdbg_printf("[EXEC-DEBUG] About to build_user_stack: argc=%zu envc=%zu kargv=%p kenvp=%p\n",
               argc, envc, kargv, kenvp);
    if (kargv && argc > 0) {
        execdbg_printf("[EXEC-DEBUG] kargv[0]=%p (content:'%.20s')\n", kargv[0], kargv[0] ? kargv[0] : "(null)");
    }
    rc = build_user_stack(mm, (const char *const *)kargv, argc, (const char *const *)kenvp, envc, &user_rsp, &user_argv, &user_argc);
    if (rc != 0) {
        fut_mm_release(mm);  /* mm not attached to task yet */
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        if (kargv && kargv_needs_free) {
            for (size_t i = 0; i < argc; i++) fut_free(kargv[i]);
            fut_free(kargv);
        }
        if (kenvp && kenvp_needs_free) {
            for (size_t i = 0; i < envc; i++) fut_free(kenvp[i]);
            fut_free(kenvp);
        }
        return rc;
    }

    /* NOW it's safe to attach mm to task - all user pages are mapped */
    fut_task_set_mm(task, mm);

    /* Open stdin/stdout/stderr for the new task (x86_64 path).
     * Temporarily make the new task current so fut_vfs_open attaches to it. */
#if defined(__x86_64__)
    fut_thread_t *cur = fut_thread_current();
    fut_task_t *saved_task = NULL;
    if (cur) {
        saved_task = cur->task;
        cur->task = task;
    }

    int stdio_fd0 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int stdio_fd1 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int stdio_fd2 = fut_vfs_open("/dev/console", O_RDWR, 0);

    if (cur) {
        cur->task = saved_task;
    }

    if (stdio_fd0 != 0 || stdio_fd1 != 1 || stdio_fd2 != 2) {
        fut_printf("[EXEC-X86] WARNING: Failed to open stdio (got %d/%d/%d)\n",
                   stdio_fd0, stdio_fd1, stdio_fd2);
    }
#endif

    struct fut_user_entry *entry = fut_malloc(sizeof(*entry));
    if (!entry) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOMEM;
    }

    entry->entry = ehdr.e_entry;
    entry->stack = user_rsp;
    entry->argc = user_argc;
    entry->argv_ptr = user_argv;
    entry->task = task;

    /* CRITICAL: Disable interrupts to prevent race condition.
     * fut_thread_create() adds the thread to the scheduler queue with fs_base=0.
     * If a timer fires before we set fs_base, the scheduler will save MSR=0
     * back to the thread, permanently corrupting fs_base.
     * By disabling interrupts, we ensure fs_base is set before any timer fires. */
    __asm__ volatile("cli" ::: "memory");

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_user_trampoline,
                                             entry,
                                             16 * 1024,
                                             FUT_DEFAULT_PRIORITY);
    if (!thread) {
        __asm__ volatile("sti" ::: "memory");
        fut_free(entry);
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        if (kargv && kargv_needs_free) {
            for (size_t i = 0; i < argc; i++) fut_free(kargv[i]);
            fut_free(kargv);
        }
        if (kenvp && kenvp_needs_free) {
            for (size_t i = 0; i < envc; i++) fut_free(kenvp[i]);
            fut_free(kenvp);
        }
        return -ENOMEM;
    }

    /* Set fs_base for TLS support BEFORE re-enabling interrupts.
     * This ensures the scheduler will always see the correct fs_base value.
     *
     * NOTE: Do NOT set context.cs/ss here! The context.rip points to the kernel
     * trampoline. If we set cs to user mode, the scheduler would construct a
     * user-mode return to kernel address, causing SMEP violation.
     * The trampoline sets cs/ss/rip/rsp to user values right before IRETQ. */
    thread->fs_base = USER_TLS_BASE;
    __asm__ volatile("" ::: "memory");  /* Ensure store is visible */
    __asm__ volatile("sti" ::: "memory");
    fut_free(phdrs);
    fut_vfs_close(fd);

    /* Free the kernel copies of argv/envp - they've been copied to user stack */
    if (kargv && kargv_needs_free) {
        for (size_t i = 0; i < argc; i++) fut_free(kargv[i]);
        fut_free(kargv);
    }
    if (kenvp && kenvp_needs_free) {
        for (size_t i = 0; i < envc; i++) fut_free(kenvp[i]);
        fut_free(kenvp);
    }

    fut_vfs_check_root_canary("fut_exec_elf:exit");

    (void)thread;
    return 0;
}

#elif defined(__aarch64__)

/* ARM64 ELF64 loader implementation */

#include <kernel/exec.h>
#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/kprintf.h>
#include <platform/arm64/regs.h>
#include <platform/arm64/context.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/arm64/memory/paging.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>

/* Debug output macro for verbose exec/staging logs */
#ifdef DEBUG_EXEC
#define EXEC_DEBUG(...) fut_printf(__VA_ARGS__)
#else
#define EXEC_DEBUG(...) do {} while (0)
#endif

/* PROT_* flags provided by sys/mman.h */

#define ELF_MAGIC       0x464C457FULL
#define ELF_CLASS_64    0x02
#define ELF_DATA_LE     0x01
#define PT_LOAD         0x00000001u
#define PF_X            0x00000001u
#define PF_W            0x00000002u
#define PF_R            0x00000004u

/* ARM64 user mode stack location (high address, 128KB stack) */
/* Stack must be within 39-bit VA space (T0SZ=25) - max 0x7FFFFFFFFF */
#define USER_STACK_TOP      0x00007FFF000000ULL
#define USER_STACK_PAGES    32u

typedef struct __attribute__((packed)) {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct __attribute__((packed)) {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

struct fut_user_entry_arm64 {
    uint64_t entry;
    uint64_t stack;
    uint64_t argc;
    uint64_t argv_ptr;
    fut_task_t *task;
};

static size_t kstrlen(const char *s) {
    if (!s) return 0;
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

static int read_exact(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = fut_vfs_read(fd, (uint8_t *)buf + total, len - total);
        if (n <= 0) {
            return -EIO;
        }
        total += (size_t)n;
    }
    return 0;
}

static int exec_copy_to_user(fut_mm_t *mm, uint64_t dest, const void *src, size_t len) {
    /* For ELF loading during exec, we need to write to pages in the NEW process's
     * address space. Since we're still running with the OLD process's CR3, we must
     * temporarily switch to the target MM context to access those pages via SMAP. */

    extern fut_mm_t *fut_mm_current(void);
    extern void fut_mm_switch(fut_mm_t *mm);

    /* Save current MM context */
    fut_mm_t *saved_mm = fut_mm_current();

    /* Switch to target MM context so we can access the new pages */
    fut_mm_switch(mm);

    /* Use standard fut_copy_to_user which handles SMAP correctly */
    int result = fut_copy_to_user((void *)dest, src, len);

    /* Restore original MM context */
    fut_mm_switch(saved_mm);

    return result;
}

/* Map a single LOAD segment from file */
static int map_segment(fut_mm_t *mm, int fd, const elf64_phdr_t *phdr) {

    if (phdr->p_memsz == 0) return 0;
    if (phdr->p_vaddr == 0) return -EINVAL;

    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uintptr_t addr = PAGE_ALIGN_DOWN(phdr->p_vaddr);
    size_t pages_needed = (phdr->p_vaddr + phdr->p_memsz - addr + PAGE_SIZE - 1) / PAGE_SIZE;

#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] vaddr=0x%llx memsz=0x%llx filesz=0x%llx pages=%llu prot=%d\n",
               (unsigned long long)phdr->p_vaddr,
               (unsigned long long)phdr->p_memsz,
               (unsigned long long)phdr->p_filesz,
               (unsigned long long)pages_needed, prot);
#endif

    for (size_t i = 0; i < pages_needed; i++) {
        uint64_t page_addr = addr + (i * PAGE_SIZE);

        /* Check if this page is already mapped (happens when segments overlap) */
        uint64_t existing_pte = 0;
        if (pmap_probe_pte(vmem, page_addr, &existing_pte) == 0) {
            /* Page already mapped, skip allocation/mapping but verify it's present */
            fut_printf("[MAP-SEG-ARM64] Page %llu at 0x%llx already mapped (overlapping segment), skipping\n",
                       (unsigned long long)i, (unsigned long long)page_addr);
            continue;
        }

        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_printf("[MAP-SEG-ARM64] ERROR: PMM alloc failed at page %llu/%llu\n",
                       (unsigned long long)i, (unsigned long long)pages_needed);
            return -ENOMEM;
        }

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
#ifdef DEBUG_ELF
        fut_printf("[MAP-SEG-ARM64] Page %llu: vaddr=0x%llx phys=0x%llx prot=%d\n",
                   (unsigned long long)i, (unsigned long long)page_addr, (unsigned long long)phys, prot);
#endif

        if (pmap_map_user(vmem, page_addr, phys, PAGE_SIZE, prot) != 0) {
            fut_printf("[MAP-SEG-ARM64] ERROR: pmap_map_user failed for page %llu\n",
                       (unsigned long long)i);
            fut_pmm_free_page(page);
            return -EFAULT;
        }
    }

#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] Successfully mapped %llu pages\n", (unsigned long long)pages_needed);
#endif

    /* Read file data into mapped pages */
#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] Seeking to file offset 0x%llx\n", (unsigned long long)phdr->p_offset);
#endif
    int64_t seek_pos = fut_vfs_lseek(fd, (int64_t)phdr->p_offset, SEEK_SET);
    if (seek_pos < 0) {
        fut_printf("[MAP-SEG-ARM64] ERROR: lseek failed with %lld\n", (long long)seek_pos);
        return (int)seek_pos;
    }

#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] Allocating buffer for %llu bytes\n", (unsigned long long)phdr->p_filesz);
#endif
    uint8_t *buf = fut_malloc(phdr->p_filesz);
    if (!buf) {
        fut_printf("[MAP-SEG-ARM64] ERROR: malloc failed for buffer\n");
        return -ENOMEM;
    }

#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] Reading %llu bytes from file\n", (unsigned long long)phdr->p_filesz);
#endif
    int rc = read_exact(fd, buf, phdr->p_filesz);
    if (rc != 0) {
        fut_printf("[MAP-SEG-ARM64] ERROR: read_exact failed with %d\n", rc);
        fut_free(buf);
        return rc;
    }

#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] Copying data to user space at 0x%llx\n", (unsigned long long)phdr->p_vaddr);
#endif
    if (exec_copy_to_user(mm, phdr->p_vaddr, buf, phdr->p_filesz) != 0) {
        fut_printf("[MAP-SEG-ARM64] ERROR: exec_copy_to_user failed\n");
        fut_free(buf);
        return -EFAULT;
    }

#ifdef DEBUG_ELF
    fut_printf("[MAP-SEG-ARM64] Segment load complete\n");
#endif
    __asm__ volatile("dmb sy" ::: "memory");
    fut_free(buf);
    return 0;
}

/* Stage stack pages for user mode */
static int stage_stack_pages(fut_mm_t *mm, uint64_t *out_stack_top) {
    if (!out_stack_top) return -EINVAL;

    extern void fut_serial_puts(const char *);
#ifdef DEBUG_ELF
    fut_serial_puts("[STACK] stage_stack_pages() called\n");
#endif

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uint64_t stack_addr = USER_STACK_TOP - (USER_STACK_PAGES * PAGE_SIZE);

#ifdef DEBUG_ELF
    fut_printf("[STACK] Mapping stack: start=0x%llx end=0x%llx pages=%d\n",
               (unsigned long long)stack_addr, (unsigned long long)USER_STACK_TOP, (int)USER_STACK_PAGES);
#endif

    for (size_t i = 0; i < USER_STACK_PAGES; i++) {
        uint64_t page_addr = stack_addr + (i * PAGE_SIZE);
        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_serial_puts("[STACK] Failed to allocate page!\n");
            return -ENOMEM;
        }

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        if (pmap_map_user(vmem, page_addr, phys, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
            fut_printf("[STACK] Failed to map page: vaddr=0x%llx phys=0x%llx\n",
                       (unsigned long long)page_addr, (unsigned long long)phys);
            fut_pmm_free_page(page);
            return -EFAULT;
        }

        if (i == 0 || i == USER_STACK_PAGES - 1) {
#ifdef DEBUG_ELF
            fut_printf("[STACK] Mapped page %d: vaddr=0x%llx phys=0x%llx\n",
                       (int)i, (unsigned long long)page_addr, (unsigned long long)phys);
#endif
        }
    }

#ifdef DEBUG_ELF
    fut_printf("[STACK] Successfully staged %d stack pages, stack_top=0x%llx\n",
               (int)USER_STACK_PAGES, (unsigned long long)USER_STACK_TOP);
#endif

    *out_stack_top = USER_STACK_TOP;
    return 0;
}

/* Build user stack with argc, argv, envp */
static int build_user_stack(fut_mm_t *mm,
                            const char *const argv_in[],
                            size_t argc_in,
                            const char *const envp_in[] __attribute__((unused)),
                            size_t envc_in __attribute__((unused)),
                            uint64_t *out_sp) {
    if (!out_sp) return -EINVAL;

    size_t argc = argc_in;
    const char *const *argv = argv_in;

    if (!argv || argc == 0) {
        static const char *default_argv[2] = { "app", NULL };
        argv = default_argv;
        argc = 1;
    }

    uint64_t sp = USER_STACK_TOP;

    /* Copy argument strings (working backwards) */
    uint8_t **argv_ptrs = fut_malloc(sizeof(uint8_t *) * argc);
    if (!argv_ptrs) return -ENOMEM;

    for (size_t i = argc; i-- > 0;) {
        /* Defensive: Check for NULL argv entry */
        if (!argv[i]) {
            fut_free(argv_ptrs);
            return -EINVAL;
        }
        size_t len = kstrlen(argv[i]) + 1;
        sp -= len;
        if (exec_copy_to_user(mm, sp, argv[i], len) != 0) {
            fut_free(argv_ptrs);
            return -EFAULT;
        }
        argv_ptrs[i] = (uint8_t *)(uintptr_t)sp;
    }

    /* Handle environment variables - copy strings first */
    size_t envc = envc_in;
    const char *const *envp = envp_in;
    uint8_t **envp_ptrs = NULL;

    if (envp && envc > 0) {
        envp_ptrs = fut_malloc(sizeof(uint8_t *) * envc);
        if (!envp_ptrs) {
            fut_free(argv_ptrs);
            return -ENOMEM;
        }

        /* Copy environment strings */
        for (size_t i = envc; i-- > 0;) {
            /* Defensive: Check for NULL envp entry */
            stack_printf("[STACK-DEBUG] envp[%zu]=%p\n", i, envp[i]);
            if (!envp[i]) {
                fut_free(envp_ptrs);
                fut_free(argv_ptrs);
                return -EINVAL;
            }
            size_t len = kstrlen(envp[i]) + 1;
            sp -= len;
            if (exec_copy_to_user(mm, sp, envp[i], len) != 0) {
                fut_free(envp_ptrs);
                fut_free(argv_ptrs);
                return -EFAULT;
            }
            envp_ptrs[i] = (uint8_t *)(uintptr_t)sp;
        }
    }

    /* Align stack to 16-byte boundary for ARM64 ABI */
    sp &= ~0xFULL;

    /* Build stack layout (working backwards from high to low addresses):
     * [sp] = argc
     * [sp+8] = argv[0]
     * [sp+16] = NULL (argv terminator)
     * [sp+24] = envp[0]
     * [sp+32] = envp[1] (if present)
     * [sp+...] = NULL (envp terminator)
     * [sp+...] = strings...
     */

    uint64_t zero = 0;

    /* Push envp terminator */
    sp -= sizeof(uint64_t);
    if (exec_copy_to_user(mm, sp, &zero, sizeof(zero)) != 0) {
        if (envp_ptrs) fut_free(envp_ptrs);
        fut_free(argv_ptrs);
        return -EFAULT;
    }

    /* Push envp pointers (reverse order so envp[0] is first) */
    if (envp && envc > 0) {
        for (size_t i = envc; i-- > 0;) {
            uint64_t ptr = (uint64_t)(uintptr_t)envp_ptrs[i];
            sp -= sizeof(uint64_t);
            if (exec_copy_to_user(mm, sp, &ptr, sizeof(ptr)) != 0) {
                fut_free(envp_ptrs);
                fut_free(argv_ptrs);
                return -EFAULT;
            }
        }
        fut_free(envp_ptrs);
    }

    /* Push argv terminator */
    sp -= sizeof(uint64_t);
    if (exec_copy_to_user(mm, sp, &zero, sizeof(zero)) != 0) {
        fut_free(argv_ptrs);
        return -EFAULT;
    }

    /* Push argv pointers (reverse order so argv[0] is first) */
    for (size_t i = argc; i-- > 0;) {
        uint64_t ptr = (uint64_t)(uintptr_t)argv_ptrs[i];
        sp -= sizeof(uint64_t);
        if (exec_copy_to_user(mm, sp, &ptr, sizeof(ptr)) != 0) {
            fut_free(argv_ptrs);
            return -EFAULT;
        }
    }

    /* Push argc onto stack */
    uint64_t argc_val = argc;
    sp -= sizeof(uint64_t);
    if (exec_copy_to_user(mm, sp, &argc_val, sizeof(argc_val)) != 0) {
        fut_free(argv_ptrs);
        return -EFAULT;
    }

    /* ARM64 process startup: [sp] = argc, [sp+8] = argv[0], ..., [sp+X] = envp[0], ... */
    *out_sp = sp;

    fut_free(argv_ptrs);
    return 0;
}

/* ARM64 user mode entry trampoline */
[[noreturn]] __attribute__((optimize("O0"))) static void fut_user_trampoline_arm64(void *arg) {
    struct fut_user_entry_arm64 *info = (struct fut_user_entry_arm64 *)arg;
    uint64_t entry = info->entry;
    uint64_t sp = info->stack;
    fut_task_t *task = info->task;

    fut_printf("[TRAMPOLINE] Received: arg=%p info=%p entry=0x%llx sp=0x%llx task=%p\n",
               arg, info,
               (unsigned long long)entry,
               (unsigned long long)sp,
               task);

    /* Get the PGD physical address from the task's memory manager */
    fut_mm_t *mm = task->mm;
    uint64_t pgd_phys = pmap_virt_to_phys((uintptr_t)mm->ctx.pgd);

    /* Verify entry point is mapped and code is present */
    extern int pmap_probe_pte(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t *pte_out);
    extern uint64_t fut_pte_to_phys(uint64_t pte);
    /* pmap_phys_to_virt is static inline from pmap.h */
    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uint64_t entry_pte = 0;
    if (pmap_probe_pte(vmem, entry, &entry_pte) != 0) {
        extern void fut_serial_puts(const char *);
        fut_serial_puts("[TRAMPOLINE] ERROR: Entry point not mapped!\n");
        for (;;) __asm__ volatile("wfi");
    }

    /* Read first instruction at entry point to verify it loaded correctly */
    phys_addr_t entry_phys = fut_pte_to_phys(entry_pte) + (entry & 0xFFF);
    uint32_t *entry_code = (uint32_t *)pmap_phys_to_virt(entry_phys);
    uint32_t first_insn = *entry_code;

    /* Different compilers generate different entry sequences, so just check for invalid */
    if (first_insn == 0 || first_insn == 0xffffffff) {
        extern void fut_serial_puts(const char *);
        fut_serial_puts("[TRAMPOLINE] WARNING: Entry code looks invalid!\n");
    }

    /* Prepare to transition to EL0 (user mode)
     * We need to:
     * 1. Switch to user page table (TTBR0_EL1)
     * 2. Set ELR_EL1 to entry point
     * 3. Set SPSR_EL1 for EL0t mode
     * 4. Set SP_EL0 to user stack (pointing to argc)
     * 5. Clear registers (let _start initialize from stack)
     * 6. Execute ERET to drop to EL0
     */

    __asm__ volatile(
        /* Set TTBR0_EL1 to user page table */
        "msr ttbr0_el1, %0\n\t"
        /* Invalidate ALL TLB entries (both TTBR0 and TTBR1) - inner shareable */
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        /* Also invalidate by ASID for TTBR0 specifically */
        "tlbi aside1is, xzr\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        /* Set SP_EL0 (user mode stack pointer) - points to argc at [sp] */
        "msr sp_el0, %1\n\t"
        :
        : "r"(pgd_phys), "r"(sp)
        : "memory"
    );

    /* Ensure all page table writes are visible to MMU before ERET */
    /* Use DSB ISH (all operations) instead of ISH ST (stores only) to ensure */
    /* page table updates are visible to the hardware page table walker */
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");

    fut_printf("[TRAMPOLINE] About to ERET to entry=0x%llx with sp=0x%llx pgd_phys=0x%llx\n",
               (unsigned long long)entry,
               (unsigned long long)sp,
               (unsigned long long)pgd_phys);

    __asm__ volatile(
        /* Set ELR_EL1 (return address for ERET) */
        "msr elr_el1, %0\n\t"
        /* Set SPSR_EL1 for EL0t mode (user mode with thread SP) */
        /* SPSR_EL1[3:0] = 0b0000 = EL0t (M[4]=0 means use SP_EL0) */
        /* SPSR_EL1[9:6] = 0b1111 = Mask D,A,I,F (all interrupts/exceptions) */
        "mov x10, #0x3C0\n\t"   /* 0x3C0 = DAIF mask bits */
        "msr spsr_el1, x10\n\t"
        /* Synchronize before ERET */
        "isb\n\t"
        /* Return to user mode */
        "eret\n\t"
        :
        : "r"(entry)
        : "x10", "memory"
    );

    /* Never reached */
    for (;;) __asm__ volatile("wfi");
}

/* Map a single LOAD segment from memory buffer */
static int map_segment_from_memory(fut_mm_t *mm, const void *elf_data, const elf64_phdr_t *phdr) {

    if (phdr->p_memsz == 0) return 0;
    if (phdr->p_vaddr == 0) return -EINVAL;

    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uintptr_t addr = PAGE_ALIGN_DOWN(phdr->p_vaddr);
    size_t pages_needed = (phdr->p_vaddr + phdr->p_memsz - addr + PAGE_SIZE - 1) / PAGE_SIZE;

    fut_printf("[MAP-SEG] vaddr=0x%llx memsz=%llu pages=%zu prot=%d\n",
               (unsigned long long)phdr->p_vaddr, (unsigned long long)phdr->p_memsz,
               pages_needed, prot);

    /* Allocate and map pages */
    for (size_t i = 0; i < pages_needed; i++) {
        uint64_t page_addr = addr + (i * PAGE_SIZE);
        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_printf("[MAP-SEG] ERROR: failed to allocate page %zu\n", i);
            return -ENOMEM;
        }

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        fut_printf("[MAP-SEG] Mapping page %zu: vaddr=0x%llx phys=0x%llx\n",
                   i, (unsigned long long)page_addr, (unsigned long long)phys);

        int map_result = pmap_map_user(vmem, page_addr, phys, PAGE_SIZE, prot);
        if (map_result != 0) {
            fut_printf("[MAP-SEG] ERROR: pmap_map_user failed with %d\n", map_result);
            fut_pmm_free_page(page);
            return -EFAULT;
        }
    }

    fut_printf("[MAP-SEG] Successfully mapped %zu pages\n", pages_needed);

    /* Copy file data from memory buffer into mapped pages */
    if (phdr->p_filesz > 0) {
        const uint8_t *src = (const uint8_t *)elf_data + phdr->p_offset;
        if (exec_copy_to_user(mm, phdr->p_vaddr, src, phdr->p_filesz) != 0) {
            return -EFAULT;
        }
    }

    /* Zero BSS section (MemSiz > FileSiz) */
    if (phdr->p_memsz > phdr->p_filesz) {
        uint64_t bss_start = phdr->p_vaddr + phdr->p_filesz;
        uint64_t bss_size = phdr->p_memsz - phdr->p_filesz;

        /* Zero BSS by writing zeros */
        uint8_t zero_buf[256];
        memset(zero_buf, 0, sizeof(zero_buf));

        uint64_t remaining = bss_size;
        uint64_t offset = 0;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(zero_buf) ? sizeof(zero_buf) : remaining;
            if (exec_copy_to_user(mm, bss_start + offset, zero_buf, chunk) != 0) {
                return -EFAULT;
            }
            offset += chunk;
            remaining -= chunk;
        }
    }

    /* Clean data cache and invalidate instruction cache for executable segments */
    if (phdr->p_flags & PF_X) {
        fut_vmem_context_t *vmem = fut_mm_context(mm);
        uint64_t start_addr = PAGE_ALIGN_DOWN(phdr->p_vaddr);
        uint64_t end_addr = PAGE_ALIGN_UP(phdr->p_vaddr + phdr->p_memsz);

        /* Do cache maintenance on physical addresses (accessible from EL1) */
        for (uint64_t vaddr = start_addr; vaddr < end_addr; vaddr += PAGE_SIZE) {
            uint64_t pte = 0;
            if (pmap_probe_pte(vmem, vaddr, &pte) == 0) {
                phys_addr_t phys_page = fut_pte_to_phys(pte);
                void *phys_ptr = (void *)pmap_phys_to_virt(phys_page);

                /* Clean and invalidate cache for this page (64-byte cache lines) */
                for (uintptr_t offset = 0; offset < PAGE_SIZE; offset += 64) {
                    uintptr_t cache_addr = (uintptr_t)phys_ptr + offset;
                    __asm__ volatile("dc cvau, %0" :: "r"(cache_addr) : "memory");
                }
            }
        }

        /* Data synchronization barrier */
        __asm__ volatile("dsb ish" ::: "memory");

        /* Invalidate instruction cache by virtual address range */
        for (uint64_t vaddr = start_addr; vaddr < end_addr; vaddr += PAGE_SIZE) {
            uint64_t pte = 0;
            if (pmap_probe_pte(vmem, vaddr, &pte) == 0) {
                phys_addr_t phys_page = fut_pte_to_phys(pte);
                void *phys_ptr = (void *)pmap_phys_to_virt(phys_page);

                for (uintptr_t offset = 0; offset < PAGE_SIZE; offset += 64) {
                    uintptr_t cache_addr = (uintptr_t)phys_ptr + offset;
                    __asm__ volatile("ic ivau, %0" :: "r"(cache_addr) : "memory");
                }
            }
        }

        /* Data synchronization barrier */
        __asm__ volatile("dsb ish" ::: "memory");
        /* Instruction synchronization barrier */
        __asm__ volatile("isb" ::: "memory");
    }

    return 0;
}

/* Execute ELF from memory buffer (for embedded binaries) */
int fut_exec_elf_memory(const void *elf_data, size_t elf_size, char *const argv[], char *const envp[]) {
    if (!elf_data || elf_size < sizeof(elf64_ehdr_t)) {
        return -EINVAL;
    }

    const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)elf_data;

    /* Verify ELF header */
    extern void fut_serial_puts(const char *);
    if (*(uint32_t *)ehdr->e_ident != ELF_MAGIC ||
        ehdr->e_ident[4] != ELF_CLASS_64 ||
        ehdr->e_ident[5] != ELF_DATA_LE ||
        ehdr->e_machine != 0xB7) {  /* EM_AARCH64 = 0xB7 */
        fut_serial_puts("[EXEC-MEM] ERROR: Invalid ELF or not ARM64\n");
        return -EINVAL;
    }

    /* Verify program headers are within bounds */
    size_t ph_size = (size_t)ehdr->e_phnum * sizeof(elf64_phdr_t);
    if (ehdr->e_phoff + ph_size > elf_size) {
        fut_serial_puts("[EXEC-MEM] ERROR: Program headers out of bounds\n");
        return -EINVAL;
    }

    const elf64_phdr_t *phdrs = (const elf64_phdr_t *)((const uint8_t *)elf_data + ehdr->e_phoff);

    /* Get current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_serial_puts("[EXEC-MEM] ERROR: No current task\n");
        return -ESRCH;
    }

    /* Create new memory manager */
    fut_mm_t *new_mm = fut_mm_create();
    if (!new_mm) {
        fut_serial_puts("[EXEC-MEM] ERROR: Failed to create memory manager\n");
        return -ENOMEM;
    }

    /* Load program segments */
    uintptr_t heap_base_candidate = 0;
    fut_serial_puts("[EXEC-MEM] Loading segments\n");
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;

        /* Verify segment is within bounds */
        if (phdrs[i].p_offset + phdrs[i].p_filesz > elf_size) {
            fut_serial_puts("[EXEC-MEM] ERROR: Segment out of bounds\n");
            /* Memory manager will be cleaned up by task destroy */
            return -EINVAL;
        }

        int rc = map_segment_from_memory(new_mm, elf_data, &phdrs[i]);
        if (rc != 0) {
            fut_serial_puts("[EXEC-MEM] ERROR: Failed to map segment\n");
            /* Memory manager will be cleaned up by task destroy */
            return rc;
        }

        uint64_t seg_end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (seg_end > heap_base_candidate) {
            heap_base_candidate = (uintptr_t)seg_end;
        }
    }
    fut_serial_puts("[EXEC-MEM] Segments mapped\n");

    /* Set heap base */
    uintptr_t heap_base = heap_base_candidate ? PAGE_ALIGN_UP(heap_base_candidate) : 0x400000ULL;
    heap_base += PAGE_SIZE;
    fut_mm_set_heap_base(new_mm, heap_base, 0);
    fut_serial_puts("[EXEC-MEM] Heap base set\n");

    /* Stage stack pages */
    uint64_t stack_top = 0;
    int rc = stage_stack_pages(new_mm, &stack_top);
    if (rc != 0) {
        fut_serial_puts("[EXEC-MEM] ERROR: Failed to stage stack\n");
        /* Memory manager will be cleaned up by task destroy */
        return rc;
    }
    fut_serial_puts("[EXEC-MEM] Stack pages staged\n");

    /* Build user stack with arguments */
    uint64_t user_sp = 0;
    size_t argc = 0;
    size_t envc = 0;
    if (argv) {
        while (argv[argc]) argc++;
    }
    if (envp) {
        while (envp[envc]) envc++;
    }

    fut_serial_puts("[EXEC-MEM] Building user stack\n");
    rc = build_user_stack(new_mm, (const char *const *)argv, argc,
                         (const char *const *)envp, envc, &user_sp);
    if (rc != 0) {
        fut_serial_puts("[EXEC-MEM] ERROR: Failed to build user stack\n");
        /* Memory manager will be cleaned up by task destroy */
        return rc;
    }
    fut_serial_puts("[EXEC-MEM] User stack built\n");

    /* Replace task's memory manager */
    fut_mm_t *old_mm = task->mm;
    task->mm = new_mm;
    /* Old memory manager cleanup is handled elsewhere */
    (void)old_mm;
    fut_serial_puts("[EXEC-MEM] Memory manager replaced\n");

    /* Prepare for userspace jump */
    struct fut_user_entry_arm64 info = {
        .entry = ehdr->e_entry,
        .stack = user_sp,
        .argc = argc,
        .argv_ptr = user_sp,
        .task = task
    };

    fut_serial_puts("[EXEC-MEM] About to call trampoline\n");

    /* Jump to userspace immediately - never returns on success */
    fut_user_trampoline_arm64(&info);

    /* Should never reach here */
    return -EFAULT;
}

int fut_exec_elf(const char *path, char *const argv[], char *const envp[]) {
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] ENTER: path=%s\n", path ? path : "(null)");
#endif

    if (!path) return -EINVAL;

    int fd = fut_vfs_open(path, O_RDONLY, 0);
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] fut_vfs_open returned fd=%d\n", fd);
#endif
    if (fd < 0) return fd;

    elf64_ehdr_t ehdr;
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to read ELF header (%llu bytes)\n", (unsigned long long)sizeof(ehdr));
#endif
    int rc = read_exact(fd, &ehdr, sizeof(ehdr));
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] read_exact returned rc=%d\n", rc);
#endif
    if (rc != 0) {
        fut_vfs_close(fd);
        return rc;
    }

#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] Verifying ELF header...\n");
#endif
    /* Verify ELF header */
    if (*(uint32_t *)ehdr.e_ident != ELF_MAGIC ||
        ehdr.e_ident[4] != ELF_CLASS_64 ||
        ehdr.e_ident[5] != ELF_DATA_LE ||
        ehdr.e_machine != 0xB7) {  /* EM_AARCH64 = 0xB7 */
#ifdef DEBUG_ELF
        ELF_LOG("[EXEC-ELF] ELF header invalid\n");
#endif
        fut_vfs_close(fd);
        return -EINVAL;
    }

#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] ELF header valid, phnum=%d\n", ehdr.e_phnum);
#endif
    size_t ph_size = (size_t)ehdr.e_phnum * sizeof(elf64_phdr_t);
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to allocate %llu bytes for program headers\n", (unsigned long long)ph_size);
#endif
    elf64_phdr_t *phdrs = fut_malloc(ph_size);
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] fut_malloc returned %p\n", phdrs);
#endif
    if (!phdrs) {
        fut_vfs_close(fd);
        return -ENOMEM;
    }

#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to lseek to phoff=0x%llx\n", (unsigned long long)ehdr.e_phoff);
#endif
    int64_t seek_rc = fut_vfs_lseek(fd, (int64_t)ehdr.e_phoff, SEEK_SET);
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] lseek returned %lld\n", (long long)seek_rc);
#endif
    if (seek_rc < 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return (int)seek_rc;
    }

#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to read %llu bytes of program headers\n", (unsigned long long)ph_size);
#endif
    rc = read_exact(fd, phdrs, ph_size);
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] read_exact for phdrs returned rc=%d\n", rc);
#endif
    if (rc != 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    /* Create task and memory manager */
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to create task\n");
#endif
    fut_task_t *task = fut_task_create();
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] fut_task_create returned %p\n", task);
#endif
    if (!task) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to create mm\n");
#endif
    fut_mm_t *mm = fut_mm_create();
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] fut_mm_create returned %p\n", mm);
#endif
    if (!mm) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to set mm on task\n");
#endif
    fut_task_set_mm(task, mm);
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] Task mm set\n");
#endif

#ifdef __aarch64__
    /* ARM64: For the spawner thread running exec, we need to update ITS context
     * with the new task's TTBR0. Normally fut_task_set_mm only updates if
     * current->task == task, but exec creates a NEW task so we must handle manually. */
    fut_thread_t *cur_thread = fut_thread_current();
    if (cur_thread) {
        cur_thread->context.ttbr0_el1 = mm->ctx.ttbr0_el1;
#ifdef DEBUG_ELF
        ELF_LOG("[EXEC-ELF] ARM64: Updated cur_thread %p context.ttbr0_el1=0x%llx\n",
                   cur_thread, (unsigned long long)mm->ctx.ttbr0_el1);
#endif

        /* Load TTBR0 now so map_segment can access user space */
        __asm__ volatile("msr ttbr0_el1, %0" :: "r"(mm->ctx.ttbr0_el1));
        __asm__ volatile("isb" ::: "memory");                    /* Ensure TTBR0 write completes */
        __asm__ volatile("tlbi vmalle1is" ::: "memory");         /* Invalidate all EL0/EL1 TLB entries */
        __asm__ volatile("dsb ish" ::: "memory");                /* Data synchronization barrier */
        __asm__ volatile("isb" ::: "memory");                    /* Instruction synchronization barrier */
#ifdef DEBUG_ELF
        ELF_LOG("[EXEC-ELF] ARM64: Loaded TTBR0 and invalidated TLB\n");
#endif
    }
#endif

    /* Map LOAD segments */
    uintptr_t heap_base_candidate = 0;
#ifdef DEBUG_ELF
    ELF_LOG("[EXEC-ELF] About to map %d program headers\n", ehdr.e_phnum);
#endif
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
#ifdef DEBUG_ELF
            ELF_LOG("[EXEC-ELF] phdr[%d]: type=%d (skipping non-LOAD)\n", i, phdrs[i].p_type);
#endif
            continue;
        }

#ifdef DEBUG_ELF
        ELF_LOG("[EXEC-ELF] Mapping segment %d: vaddr=0x%llx memsz=0x%llx filesz=0x%llx offset=0x%llx\n",
                   i, (unsigned long long)phdrs[i].p_vaddr, (unsigned long long)phdrs[i].p_memsz,
                   (unsigned long long)phdrs[i].p_filesz, (unsigned long long)phdrs[i].p_offset);
#else
        /* Always log segment mapping for ARM64 ELF debugging */
        ELF_LOG("[EXEC-ELF] Mapping segment %d: vaddr=0x%llx memsz=0x%llx filesz=0x%llx offset=0x%llx\n",
                   i, (unsigned long long)phdrs[i].p_vaddr, (unsigned long long)phdrs[i].p_memsz,
                   (unsigned long long)phdrs[i].p_filesz, (unsigned long long)phdrs[i].p_offset);
#endif
        rc = map_segment(mm, fd, &phdrs[i]);
#ifdef DEBUG_ELF
        ELF_LOG("[EXEC-ELF] map_segment returned rc=%d\n", rc);
#endif
        if (rc != 0) {
            fut_task_destroy(task);
            fut_free(phdrs);
            fut_vfs_close(fd);
            return rc;
        }

        uint64_t seg_end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (seg_end > heap_base_candidate) {
            heap_base_candidate = (uintptr_t)seg_end;
        }
    }

    /* Set heap base */
    uintptr_t heap_base = heap_base_candidate ? PAGE_ALIGN_UP(heap_base_candidate) : 0x400000ULL;
    heap_base += PAGE_SIZE;
    fut_mm_set_heap_base(mm, heap_base, 0);

    /* Stage stack pages */
    uint64_t stack_top = 0;
    rc = stage_stack_pages(mm, &stack_top);
    if (rc != 0) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    /* Build user stack */
    uint64_t user_sp = 0;
    size_t argc = 0;
    if (argv) {
        while (argv[argc]) argc++;
    }
    EXEC_DEBUG("[EXEC] Before build_user_stack: task=%p task->threads=%p\n", task, task->threads);
    rc = build_user_stack(mm, (const char *const *)argv, argc, (const char *const *)envp, 0, &user_sp);
    EXEC_DEBUG("[EXEC] After build_user_stack: task=%p task->threads=%p user_sp=0x%llx\n",
               task, task->threads, (unsigned long long)user_sp);
    if (rc != 0) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    /* Create user entry structure */
    struct fut_user_entry_arm64 *entry = fut_malloc(sizeof(*entry));
    if (!entry) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    entry->entry = ehdr.e_entry;
    entry->stack = user_sp;
    entry->argc = argc;
    entry->argv_ptr = user_sp;
    entry->task = task;

#ifdef DEBUG_ELF
    fut_printf("[EXEC-ARM64] Set entry structure: entry=0x%llx stack=0x%llx argc=%llu\n",
               (unsigned long long)entry->entry,
               (unsigned long long)entry->stack,
               (unsigned long long)entry->argc);
#endif

    /* Open stdin/stdout/stderr for the new task.
     * We temporarily switch the current thread's task pointer so that
     * fut_vfs_open operates on the new task's fd table. */
    fut_thread_t *current = fut_thread_current();
    fut_task_t *saved_task = current->task;
    current->task = task;

    int stdio_fd0 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int stdio_fd1 = fut_vfs_open("/dev/console", O_RDWR, 0);
    int stdio_fd2 = fut_vfs_open("/dev/console", O_RDWR, 0);

    current->task = saved_task;

    if (stdio_fd0 != 0 || stdio_fd1 != 1 || stdio_fd2 != 2) {
        fut_printf("[EXEC-ARM64] WARNING: Failed to open stdio (got %d/%d/%d)\n",
                   stdio_fd0, stdio_fd1, stdio_fd2);
    }

    /* Create thread with trampoline */
#ifdef DEBUG_ELF
    fut_printf("[EXEC-ARM64] About to create thread: trampoline=%p entry_struct=%p user_entry=0x%llx\n",
               (void*)fut_user_trampoline_arm64, (void*)entry, (unsigned long long)entry->entry);
#endif

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_user_trampoline_arm64,
                                             entry,
                                             16 * 1024,
                                             FUT_DEFAULT_PRIORITY);
    if (!thread) {
        fut_free(entry);
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    fut_free(phdrs);
    fut_vfs_close(fd);

    (void)thread;
    return 0;
}

#else  /* Other architectures */

#include <kernel/errno.h>

int fut_exec_elf(const char *path, char *const argv[], char *const envp[]) {
    (void)path;
    (void)argv;
    (void)envp;
    return -ENOSYS;
}

#endif  /* Architecture-specific ELF loader */
