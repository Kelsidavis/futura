// SPDX-License-Identifier: MPL-2.0
/*
 * elf64.c - Minimal ELF64 loader and user process bootstrap
 */

#ifdef __x86_64__

#include <kernel/exec.h>
#include <generated/feature_flags.h>
#include <config/futura_config.h>

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
#include <platform/x86_64/gdt.h>
#include <platform/x86_64/interrupt/lapic.h>
#include <platform/x86_64/regs.h>
#include <arch/x86_64/msr.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* MSR for FS segment base (Thread Local Storage) */
#define MSR_FS_BASE     0xC0000100

/* FD_CLOEXEC - close-on-exec flag for file descriptors.
 * Cannot include <fcntl.h> here because it conflicts with fut_vfs.h O_* defines. */
#ifndef FD_CLOEXEC
#define FD_CLOEXEC      1
#endif

#include <kernel/debug_config.h>

/* TLS block address - placed below stack in user address space */
#define USER_TLS_BASE   0x00007FFE000000ULL
#define TLS_SIZE        PAGE_SIZE

/* Diagnostic: mask the LAPIC timer across the first userspace handoff so we can
 * separate "dies in transition" from "dies on the first post-entry timer IRQ".
 * Now OFF by default — masking the timer freezes the entire scheduler after
 * init starts, so the periodic klog→SD flusher thread can never wake up to
 * capture what init actually does. The original "dies on first IRQ" question
 * is moot now that we have the SD-flusher capturing arbitrary post-IRETQ
 * state. */
static bool g_bisect_mask_timer_before_first_user = false;
/* Diagnostic: briefly execute under the target CR3, then restore the original
 * CR3 and report the result. This avoids depending on the console path while
 * the target CR3 is active. Now ON by default — we need to know whether the
 * CR3 swap itself is the cliff or something downstream of it. The probe does:
 *   1. mov target_cr3 -> %cr3
 *   2. mov %cr3 -> %rax  (read back)
 *   3. nop; nop
 *   4. mov original_cr3 -> %cr3
 * Then prints "[BISECT-KCR3] roundtrip survived ..." and panics. If we see
 * that print, CR3 swap is fine and init/IRETQ is the actual problem. If we
 * see no print and the box still hangs at "CR3 swap+iretq", the CR3 swap
 * itself faults (kernel-half not mapped, etc.). */
static bool g_bisect_probe_kernel_cr3_roundtrip = false;
/* Diagnostic: replace the real ELF entry with a synthetic userspace
 * probe (`ud2`) so we can tell whether the CPU retires even a single user
 * instruction on hardware. Now off by default — combined with the post-CR3
 * waypoints in this file, we get enough visibility to chase a real-init
 * hang without the probe getting in the way. */
static bool g_bisect_user_ud2_probe = false;

#define BISECT_USER_INT3_VA 0x0000000000500000ULL

static void bisect_walk_target_va(const char *tag, uint64_t root_cr3, uint64_t va) {
    uint64_t *pml4 = (uint64_t *)((root_cr3 & ~0xFFFULL) | KERNEL_VIRTUAL_BASE);
    uint64_t pml4e = pml4[PML4_INDEX(va)];
    fut_printf("[%s] va=0x%llx pml4e=0x%llx U=%d NX=%d\n",
               tag,
               (unsigned long long)va,
               (unsigned long long)pml4e,
               (int)((pml4e & PTE_USER) != 0),
               (int)((pml4e & PTE_NX) != 0));
    if (!(pml4e & PTE_PRESENT)) {
        return;
    }

    uint64_t *pdpt = (uint64_t *)((pml4e & PTE_PHYS_ADDR_MASK) | KERNEL_VIRTUAL_BASE);
    uint64_t pdpte = pdpt[PDPT_INDEX(va)];
    fut_printf("[%s] pdpte=0x%llx U=%d NX=%d PS=%d\n",
               tag,
               (unsigned long long)pdpte,
               (int)((pdpte & PTE_USER) != 0),
               (int)((pdpte & PTE_NX) != 0),
               (int)((pdpte & PTE_LARGE_PAGE) != 0));
    if (!(pdpte & PTE_PRESENT) || (pdpte & PTE_LARGE_PAGE)) {
        return;
    }

    uint64_t *pd = (uint64_t *)((pdpte & PTE_PHYS_ADDR_MASK) | KERNEL_VIRTUAL_BASE);
    uint64_t pde = pd[PD_INDEX(va)];
    fut_printf("[%s] pde=0x%llx U=%d NX=%d PS=%d\n",
               tag,
               (unsigned long long)pde,
               (int)((pde & PTE_USER) != 0),
               (int)((pde & PTE_NX) != 0),
               (int)((pde & PTE_LARGE_PAGE) != 0));
    if (!(pde & PTE_PRESENT) || (pde & PTE_LARGE_PAGE)) {
        return;
    }

    uint64_t *pt = (uint64_t *)((pde & PTE_PHYS_ADDR_MASK) | KERNEL_VIRTUAL_BASE);
    uint64_t pte = pt[PT_INDEX(va)];
    fut_printf("[%s] pte=0x%llx U=%d W=%d NX=%d\n",
               tag,
               (unsigned long long)pte,
               (int)((pte & PTE_USER) != 0),
               (int)((pte & PTE_WRITABLE) != 0),
               (int)((pte & PTE_NX) != 0));
}

/* Stack canary offset in TLS (matches glibc/gcc convention) */
#define TLS_STACK_CANARY_OFFSET 0x28

/* Resume a fully-formed interrupt frame using the validated x86_64 restore path
 * from context_switch.S. */
extern void fut_resume_user_frame(fut_interrupt_frame_t *frame, fut_thread_t *thread);
extern void fut_platform_panic(const char *);

/* Debug output macro for verbose exec/staging logs */
#ifdef DEBUG_EXEC
#define EXEC_DEBUG(...) fut_printf(__VA_ARGS__)
#else
#define EXEC_DEBUG(...) do {} while (0)
#endif

/* Debug output for user trampoline serial output (U1234567A characters) */
#define DEBUG_USER_TRAMPOLINE   /* enabled to trace bare-metal init exec */

/* Stack debugging (controlled via debug_config.h) */
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
#define USER_STACK_PAGES    64u  /* 256KB stack for deep call chains */

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

static int stage_bisect_user_ud2_page(fut_mm_t *mm, uint64_t *out_entry) {
    uint8_t *page = fut_pmm_alloc_page();
    if (!page) {
        return -ENOMEM;
    }

    memset(page, 0x90, PAGE_SIZE);
    page[0] = 0x0F; /* ud2 */
    page[1] = 0x0B;
    page[2] = 0xEB; /* jmp . */
    page[3] = 0xFE;

    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    int rc = pmap_map_user(mm_context(mm),
                           BISECT_USER_INT3_VA,
                           phys,
                           PAGE_SIZE,
                           PTE_PRESENT | PTE_USER);
    if (rc != 0) {
        fut_pmm_free_page(page);
        return rc;
    }

    *out_entry = BISECT_USER_INT3_VA;
    return 0;
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

    /* Overflow check: p_vaddr + p_memsz must not wrap around 64-bit address space */
    if (phdr->p_memsz > UINT64_MAX - phdr->p_vaddr) {
        return -EINVAL;
    }

    /* p_filesz must not exceed p_memsz (file content cannot exceed segment size) */
    if (phdr->p_filesz > phdr->p_memsz) {
        return -EINVAL;
    }

    uint64_t seg_start = phdr->p_vaddr & ~(PAGE_SIZE - 1ULL);
    uint64_t seg_offset = phdr->p_vaddr - seg_start;
    uint64_t seg_end = (phdr->p_vaddr + phdr->p_memsz + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL);
    size_t page_count = (size_t)((seg_end - seg_start) / PAGE_SIZE);

    /* SECURITY: Reject segments that overlap kernel address space.
     * A crafted ELF could specify p_vaddr >= KERNEL_VIRTUAL_BASE to
     * trick the loader into mapping user pages over kernel memory. */
#ifdef KERNEL_VIRTUAL_BASE
    if (seg_start >= KERNEL_VIRTUAL_BASE || seg_end >= KERNEL_VIRTUAL_BASE ||
        seg_end < seg_start /* overflow */) {
        fut_printf("[EXEC] SECURITY: PT_LOAD segment 0x%llx-0x%llx overlaps kernel space — REJECTED\n",
                   (unsigned long long)seg_start, (unsigned long long)seg_end);
        return -EINVAL;
    }
#endif

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

/* ELF metadata for auxiliary vector — set by exec code before build_user_stack */
static uint64_t g_exec_entry = 0;
static uint64_t g_exec_phdr = 0;
static uint16_t g_exec_phent = 0;
static uint16_t g_exec_phnum = 0;
static uint64_t g_exec_interp_base = 0;   /* AT_BASE: interpreter load address */
static uint64_t g_exec_interp_entry = 0;  /* Interpreter entry point (replaces main entry) */

/* Default base address for loading the ELF interpreter (ld-linux.so).
 * Placed high in the lower-half address space to avoid overlap with main binary. */
#define INTERP_LOAD_BASE  0x7f0000000ULL

/*
 * load_elf_interpreter — Load the ELF interpreter (PT_INTERP target) into
 * the process address space at INTERP_LOAD_BASE.
 *
 * On success, sets g_exec_interp_base and g_exec_interp_entry.
 * Returns 0 on success, negative errno on failure.
 */
static int load_elf_interpreter(fut_mm_t *mm, const char *interp_path) {
    extern int fut_vfs_open(const char *, int, int);
    extern long fut_vfs_read(int, void *, size_t);
    extern long fut_vfs_lseek(int, long, int);
    extern int fut_vfs_close(int);

    g_exec_interp_base = 0;
    g_exec_interp_entry = 0;

    int ifd = fut_vfs_open(interp_path, 0 /* O_RDONLY */, 0);
    if (ifd < 0) {
        return 0;  /* Not fatal — fall back to direct execution (static PIE) */
    }

    /* Read ELF header */
    elf64_ehdr_t ihdr;
    long nr = fut_vfs_read(ifd, &ihdr, sizeof(ihdr));
    if (nr < (long)sizeof(ihdr)) {
        fut_vfs_close(ifd);
        return 0;
    }

    /* Validate ELF magic */
    uint32_t magic = 0;
    __builtin_memcpy(&magic, ihdr.e_ident, 4);
    if (magic != ELF_MAGIC || ihdr.e_ident[4] != ELF_CLASS_64) {
        fut_vfs_close(ifd);
        return 0;
    }

    /* Read program headers */
    if (ihdr.e_phnum == 0 || ihdr.e_phnum > 64) {
        fut_vfs_close(ifd);
        return 0;
    }

    size_t phsz = (size_t)ihdr.e_phnum * ihdr.e_phentsize;
    elf64_phdr_t *iphdrs = fut_malloc(phsz);
    if (!iphdrs) { fut_vfs_close(ifd); return -ENOMEM; }

    fut_vfs_lseek(ifd, (long)ihdr.e_phoff, 0 /* SEEK_SET */);
    nr = fut_vfs_read(ifd, iphdrs, phsz);
    if (nr < (long)phsz) {
        fut_free(iphdrs);
        fut_vfs_close(ifd);
        return 0;
    }

    /* The interpreter is typically ET_DYN (shared object). Apply a load bias
     * so its segments don't overlap with the main binary. */
    uint64_t interp_bias = INTERP_LOAD_BASE;

    /* Find the lowest vaddr in PT_LOAD segments to compute bias correctly */
    uint64_t lowest_vaddr = UINT64_MAX;
    for (uint16_t i = 0; i < ihdr.e_phnum; i++) {
        if (iphdrs[i].p_type == PT_LOAD && iphdrs[i].p_vaddr < lowest_vaddr)
            lowest_vaddr = iphdrs[i].p_vaddr;
    }
    if (lowest_vaddr != UINT64_MAX && ihdr.e_type == 3 /* ET_DYN */) {
        /* ET_DYN: bias = desired_base - lowest_segment_vaddr */
        interp_bias = INTERP_LOAD_BASE - (lowest_vaddr & ~(PAGE_SIZE - 1ULL));
    } else if (ihdr.e_type == 2 /* ET_EXEC */) {
        interp_bias = 0;  /* Static interpreter — load at its own addresses */
    }

    /* Apply bias to all PT_LOAD segments and map them */
    for (uint16_t i = 0; i < ihdr.e_phnum; i++) {
        if (iphdrs[i].p_type != PT_LOAD) continue;
        iphdrs[i].p_vaddr += interp_bias;

        int rc = map_segment(mm, ifd, &iphdrs[i]);
        if (rc != 0) {
            fut_free(iphdrs);
            fut_vfs_close(ifd);
            return rc;
        }
    }

    g_exec_interp_base = interp_bias + (lowest_vaddr != UINT64_MAX ? lowest_vaddr : 0);
    g_exec_interp_entry = ihdr.e_entry + interp_bias;


    fut_free(iphdrs);
    fut_vfs_close(ifd);
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

    /* Save argv[0] address for AT_EXECFN (program invocation name) */
    uint64_t execfn_addr = (argc > 0) ? (uint64_t)(uintptr_t)string_ptrs[0] : 0;

    sp &= ~0xFULL;

    uint64_t zero = 0;

    /* Push 16 random bytes for AT_RANDOM (used by musl for stack canary).
     * Place them above the auxv so we know the address before building auxv. */
    uint8_t random_bytes[16];
    {
        extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
        sys_getrandom(random_bytes, 16, 0);
    }
    sp -= 16;
    uint64_t random_addr = sp;
    exec_copy_to_user(mm, sp, random_bytes, 16);

    /* Push AT_PLATFORM string — CPU architecture name used by glibc for
     * ifunc resolution and getauxval(AT_PLATFORM) queries. */
#ifdef __x86_64__
    static const char platform_str[] = "x86_64";
#elif defined(__aarch64__)
    static const char platform_str[] = "aarch64";
#else
    static const char platform_str[] = "unknown";
#endif
    sp -= sizeof(platform_str);  /* includes NUL */
    uint64_t platform_addr = sp;
    exec_copy_to_user(mm, sp, platform_str, sizeof(platform_str));

    /* Re-establish 16-byte alignment. sizeof(platform_str) is 7 on
     * x86_64 ("x86_64\0") which broke the sp & ~0xFULL baseline above.
     * After this, the only 16-flip risk is the final pushes:
     *   8 (envp NULL) + 8*envc + 8 (argv NULL) + 8*argc + 8 (argc)
     * = 24 + 8*(envc+argc), which is a multiple of 16 iff
     * (envc+argc) is odd (since 24 % 16 == 8). Insert an 8-byte
     * padding slot when that's not the case so the final RSP at
     * process entry satisfies RSP % 16 == 0 per the x86_64 psABI. */
    sp &= ~0xFULL;
    if (((argc + envc) & 1) == 0) {
        sp -= 8;
        uint64_t pad = 0;
        exec_copy_to_user(mm, sp, &pad, sizeof(pad));
    }

    /* AT_HWCAP: CPU feature flags. On x86_64, use CPUID leaf 1 EDX. */
    uint64_t hwcap_val = 0;
#ifdef __x86_64__
    {
        uint32_t eax_c, ebx_c, ecx_c, edx_c;
        __asm__ volatile("cpuid" : "=a"(eax_c), "=b"(ebx_c), "=c"(ecx_c), "=d"(edx_c) : "a"(1));
        hwcap_val = edx_c;  /* FPU, SSE, SSE2, etc. */
    }
#elif defined(__aarch64__)
    hwcap_val = 0x3;  /* HWCAP_FP | HWCAP_ASIMD — baseline AArch64 */
#endif

    /* Push ELF auxiliary vector (auxv) — highest address, after envp NULL.
     * musl and glibc read these to discover page size, UID, etc. */
    {
        fut_task_t *auxv_task = fut_task_current();
        uint64_t uid  = auxv_task ? auxv_task->ruid : 0;
        uint64_t euid = auxv_task ? auxv_task->uid  : 0;
        uint64_t gid  = auxv_task ? auxv_task->rgid : 0;
        uint64_t egid = auxv_task ? auxv_task->gid  : 0;
        uint64_t secure = (uid != euid || gid != egid) ? 1 : 0;

        struct { uint64_t key; uint64_t val; } auxv[] = {
            { 6 /* AT_PAGESZ */, PAGE_SIZE },
            { 9 /* AT_ENTRY */,  g_exec_entry },
            { 3 /* AT_PHDR */,   g_exec_phdr },
            { 4 /* AT_PHENT */,  g_exec_phent },
            { 5 /* AT_PHNUM */,  g_exec_phnum },
            { 25 /* AT_RANDOM */, random_addr },
            { 17 /* AT_CLKTCK */, 100 },
            { 31 /* AT_EXECFN */, execfn_addr },
            { 15 /* AT_PLATFORM */, platform_addr },
            { 11 /* AT_UID */,   uid },
            { 12 /* AT_EUID */,  euid },
            { 13 /* AT_GID */,   gid },
            { 14 /* AT_EGID */,  egid },
            { 23 /* AT_SECURE */, secure },
            { 16 /* AT_HWCAP */,  hwcap_val },
            { 7 /* AT_BASE */,   g_exec_interp_base },  /* interpreter load address */
            { 8 /* AT_FLAGS */,  0 },  /* ELF flags (always 0) */
            { 0 /* AT_NULL */,   0 },
        };
        for (int ai = (int)(sizeof(auxv)/sizeof(auxv[0])) - 1; ai >= 0; ai--) {
            sp -= sizeof(uint64_t);
            exec_copy_to_user(mm, sp, &auxv[ai].val, sizeof(uint64_t));
            sp -= sizeof(uint64_t);
            exec_copy_to_user(mm, sp, &auxv[ai].key, sizeof(uint64_t));
        }

        /* Save a copy of the auxv in the task struct for /proc/<pid>/auxv */
        if (auxv_task) {
            size_t auxv_bytes = sizeof(auxv);
            if (auxv_task->auxv) fut_free(auxv_task->auxv);
            auxv_task->auxv = fut_malloc(auxv_bytes);
            if (auxv_task->auxv) {
                __builtin_memcpy(auxv_task->auxv, auxv, auxv_bytes);
                auxv_task->auxv_size = auxv_bytes;
            } else {
                auxv_task->auxv_size = 0;
            }
        }
    }

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

    /* Push argc immediately before argv[0]. crt0 pops argc, then finds
     * argv at RSP and envp at argv + (argc+1)*8. No padding between
     * argc and argv — crt0's and $-16,%rsp handles alignment. */
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
    /* Print BEFORE CLI so the print path's I/O is unaffected. */
    fut_printf("[BISECT-TRAMP] entered, arg=%p\n", arg);

    /* CRITICAL: Disable interrupts IMMEDIATELY to prevent timer interrupts from
     * corrupting our state during the transition to user mode! */
    __asm__ volatile("cli");

    if (!arg) {
        __asm__ volatile("sti");  /* Re-enable before exit */
        extern void fut_thread_exit(void);
        fut_thread_exit();
    }

    /* Extract values from the user entry structure BEFORE freeing it.
     * fb_console_present's BLT path is MMIO-only (no IRQs), so
     * fut_printf still works after CLI on the i915-accelerated boot. */
    struct fut_user_entry *info = (struct fut_user_entry *)arg;
    fut_printf("[BISECT-TRAMP] info=%p\n", (void *)info);

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

    if (g_bisect_user_ud2_probe) {
        uint64_t probe_entry = 0;
        int probe_rc = stage_bisect_user_ud2_page(mm, &probe_entry);
        if (probe_rc != 0) {
            fut_printf("[BISECT-UD2] failed to stage probe page rc=%d\n", probe_rc);
            fut_platform_panic("[BISECT-UD2] unable to install synthetic user probe");
        }
        entry = probe_entry;
        fut_printf("[BISECT-UD2] synthetic user entry armed at 0x%llx\n",
                   (unsigned long long)entry);
    }

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '5' after task/mm check */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'5', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    fut_printf("[BISECT-TRAMP] entry=0x%llx stack=0x%llx argc=%llu argv=0x%llx task=%p mm=%p\n",
               (unsigned long long)entry, (unsigned long long)stack,
               (unsigned long long)argc, (unsigned long long)argv_ptr,
               (void *)task, (void *)mm);

    /* Verify we're using the task's CR3, not the kernel CR3 */
    extern uint64_t fut_read_cr3(void);
    uint64_t current_cr3 = fut_read_cr3();

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '6' after reading CR3 */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'6', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    uint64_t expected_cr3 = mm_context(mm)->cr3_value;
    fut_printf("[BISECT-TRAMP] current_cr3=0x%llx expected_cr3=0x%llx\n",
               (unsigned long long)current_cr3,
               (unsigned long long)expected_cr3);

    /* Sanity-check that the new pml4 has the same kernel-half
     * (entries 256..511) as the running kernel's pml4. We previously
     * spot-checked [256], [510], [511] — extend to a full sweep
     * because copy_kernel_half ran at fut_mm_create time, and any
     * kernel mapping added to boot_pml4 since then (e.g. dynamically
     * mapped MMIO, lazy direct-map extensions) would NOT be in the
     * new mm.
     *
     * Read each entry via phys+KERNEL_VIRTUAL_BASE direct mapping. */
    {
        uint64_t cur_pml4_phys  = current_cr3  & ~0xFFFULL;
        uint64_t new_pml4_phys  = expected_cr3 & ~0xFFFULL;
        uint64_t *cur_pml4 = (uint64_t *)(cur_pml4_phys  | KERNEL_VIRTUAL_BASE);
        uint64_t *new_pml4 = (uint64_t *)(new_pml4_phys  | KERNEL_VIRTUAL_BASE);
        int diff_count = 0;
        for (int i = 256; i < 512; i++) {
            if (cur_pml4[i] != new_pml4[i]) {
                fut_printf("[BISECT-TRAMP] pml4[%d] DIFF cur=0x%llx new=0x%llx\n",
                           i,
                           (unsigned long long)cur_pml4[i],
                           (unsigned long long)new_pml4[i]);
                diff_count++;
                if (diff_count >= 16) {  /* clamp output */
                    fut_printf("[BISECT-TRAMP] (stopping after 16 diffs)\n");
                    break;
                }
            }
        }
        fut_printf("[BISECT-TRAMP] pml4 kernel-half diff_count=%d\n", diff_count);
    }

    /* Dump the new address space's entry-point page-table chain so we can
     * tell whether 0x400000 is missing USER, marked NX, or otherwise wrong
     * before we actually load CR3 and attempt IRETQ. */
    bisect_walk_target_va("BISECT-TRAMP", expected_cr3, entry);

    /* Also report the trampoline's own stack/return-address so we can
     * confirm both are in pml4[511]'s range (above 0xFFFFFFFF80000000).
     * If either is in a different kernel-half slot we need to verify
     * THAT slot matches between cur/new pml4. */
    {
        uintptr_t cur_rsp;
        __asm__ volatile("mov %%rsp, %0" : "=r"(cur_rsp));
        fut_printf("[BISECT-TRAMP] tramp_fn=0x%lx ret_addr=0x%lx kernel_rsp=0x%lx do_iretq=0x%lx\n",
                   (unsigned long)(uintptr_t)&fut_user_trampoline,
                   (unsigned long)(uintptr_t)__builtin_return_address(0),
                   (unsigned long)cur_rsp,
                   (unsigned long)(uintptr_t)&fut_resume_user_frame);

        /* If IRETQ faults before the CPL transition completes, the CPU will
         * take that exception on the CURRENT ring-0 stack, not TSS.rsp0.
         * Validate the active trampoline stack in the target CR3 as well. */
        bisect_walk_target_va("BISECT-CRSP", expected_cr3, (uint64_t)cur_rsp - 8);
    }

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print '7' after getting expected_cr3 */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'7', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    /* Do the per-thread/per-task struct updates BEFORE the CR3 swap,
     * AND program TSS.RSP0 to this thread's kernel stack top.
     *
     * The TSS.RSP0 update is critical: the direct-trampoline path
     * doesn't go through the scheduler, so the scheduler's normal
     * fut_tss_set_kernel_stack call from select_next_thread()
     * never fires. Without this, TSS.RSP0 is left at whatever
     * fut_tss_init set during early platform boot — the BSP's
     * RSP at that moment, on a tiny static boot stack that is
     * almost certainly no longer in use. The very first ring-3
     * → ring-0 transition (a timer IRQ shortly after IRETQ)
     * pushes the interrupt frame to that stale RSP0 and either
     * lands in unrelated kernel data (silent corruption then
     * eventual hang) or off-the-end of mapped memory (silent
     * #DF → hang). Either way the boot freezes with no further
     * console output, exactly matching what we see. */
    fut_thread_t *handoff_thread = fut_thread_current();
    uint64_t handoff_stack_top = 0;
    {
        fut_thread_t *cur_thread = handoff_thread;
        if (cur_thread) {
            cur_thread->fs_base = USER_TLS_BASE;
            cur_thread->context.ds = USER_DATA_SELECTOR;
            cur_thread->context.es = USER_DATA_SELECTOR;
            cur_thread->context.fs = USER_DATA_SELECTOR;
            cur_thread->context.gs = USER_DATA_SELECTOR;
            cur_thread->context.cs = USER_CODE_SELECTOR;
            cur_thread->context.ss = USER_DATA_SELECTOR;
            cur_thread->context.rip = entry;
            cur_thread->context.rsp = stack;
            cur_thread->context.rflags = 0x202;

            /* Diagnostic: remove FS_BASE/TLS from the first-user handoff.
             * If HP only dies when wrmsr(MSR_FS_BASE) participates in the
             * transition, forcing fs_base=0 and skipping the restore path
             * should change the failure signature. */
            cur_thread->fs_base = 0;
            fut_printf("[BISECT-FS] forcing fs_base=0 and skipping first-user FS_BASE restore\n");

            if (cur_thread->stack_base && cur_thread->stack_size) {
                uintptr_t stack_top = (uintptr_t)cur_thread->stack_base
                                    + cur_thread->stack_size;
                extern void fut_tss_set_kernel_stack(uint64_t);
                fut_tss_set_kernel_stack((uint64_t)stack_top);
                handoff_stack_top = (uint64_t)stack_top;
                fut_printf("[BISECT-TRAMP] TSS.rsp0 set to 0x%lx (kernel stack top)\n",
                           (unsigned long)stack_top);

                /* The first ring-3 -> ring-0 transition will push onto
                 * TSS.rsp0-8, so validate that address in the target CR3. */
                bisect_walk_target_va("BISECT-KSTACK", expected_cr3, (uint64_t)stack_top - 8);
            } else {
                fut_printf("[BISECT-TRAMP] WARNING: cur_thread has no stack_base/size — TSS.rsp0 left stale!\n");
            }
        }
    }
    if (handoff_stack_top == 0) {
        extern uint64_t fut_tss_get_kernel_stack(void);
        handoff_stack_top = fut_tss_get_kernel_stack();
        fut_printf("[BISECT-TRAMP] fallback handoff_stack_top=0x%llx from TSS\n",
                   (unsigned long long)handoff_stack_top);
    }

    /* Verify the live GDT/GDTR seen by this CPU right before the user-mode
     * transition. The selector constants are internally consistent, so the
     * next question is whether the loaded descriptors on this machine are
     * actually the expected user data/code entries. */
    {
        struct {
            uint16_t limit;
            uint64_t base;
        } __attribute__((packed)) gdtr;
        struct {
            uint16_t limit;
            uint64_t base;
        } __attribute__((packed)) idtr;
        uint16_t tr_sel = 0;
        __asm__ volatile("sgdt %0" : "=m"(gdtr));
        __asm__ volatile("sidt %0" : "=m"(idtr));
        __asm__ volatile("str %0" : "=r"(tr_sel));

        uint64_t *gdt = (uint64_t *)(uintptr_t)gdtr.base;
        uint64_t user_data_desc = gdt ? gdt[3] : 0;
        uint64_t user_code_desc = gdt ? gdt[4] : 0;
        uint64_t tss_base = 0;
        if (gdt && (tr_sel >> 3) < 7) {
            uint64_t low = gdt[tr_sel >> 3];
            uint64_t high = gdt[(tr_sel >> 3) + 1];
            tss_base =
                ((low >> 16) & 0xFFFFFFULL) |
                ((low >> 32) & 0xFF000000ULL) |
                ((high & 0xFFFFFFFFULL) << 32);
        }

        fut_printf("[BISECT-GDT] gdtr.base=0x%llx limit=0x%x\n",
                   (unsigned long long)gdtr.base,
                   (unsigned)gdtr.limit);
        fut_printf("[BISECT-IDT] idtr.base=0x%llx limit=0x%x\n",
                   (unsigned long long)idtr.base,
                   (unsigned)idtr.limit);
        fut_printf("[BISECT-TSS] tr=0x%x base=0x%llx end=0x%llx\n",
                   (unsigned)tr_sel,
                   (unsigned long long)tss_base,
                   (unsigned long long)(tss_base ? (tss_base + sizeof(tss_t) - 1) : 0));
        fut_printf("[BISECT-GDT] user_data sel=0x%x desc=0x%llx\n",
                   USER_DATA_SELECTOR,
                   (unsigned long long)user_data_desc);
        fut_printf("[BISECT-GDT] user_code sel=0x%x desc=0x%llx\n",
                   USER_CODE_SELECTOR,
                   (unsigned long long)user_code_desc);
        bisect_walk_target_va("BISECT-GDTMAP", expected_cr3, gdtr.base);
        bisect_walk_target_va("BISECT-IDTMAP", expected_cr3, idtr.base);
        if (tss_base) {
            bisect_walk_target_va("BISECT-TSSMAP", expected_cr3, tss_base);
            bisect_walk_target_va("BISECT-TSSMAP", expected_cr3, tss_base + sizeof(tss_t) - 1);
        }
    }

    /* Print boot_seq so we can tell whether a "same hang" across
     * iterations is actually a triple-fault reboot loop. boot_seq
     * lives in the persistent ring buffer at phys 0x10000000 and
     * survives warm resets on this hardware. If iter N+1 prints
     * boot_seq=K and iter N+2 prints boot_seq=K+1 across the same
     * powered session, we have a loop. The +0x18 offset matches
     * the boot_seq field in struct klog_persist_t. */
    {
        volatile uint32_t *boot_seq_p =
            (volatile uint32_t *)(0xFFFFFFFF80000000ULL + 0x10000000ULL + 12);
        fut_printf("[BISECT-TRAMP] klog boot_seq=%u (single boot if value stays low)\n",
                   *boot_seq_p);
    }

    /* Log BEFORE the CR3 swap — we have no diagnostic prints between
     * here and fut_do_user_iretq. Last-visible-line tells us where
     * in {fut_write_cr3, wrmsr, fut_do_user_iretq} we faulted. */
    fut_printf("[BISECT-IRETQ] frame ss=0x%llx rsp=0x%llx rflags=0x%llx cs=0x%llx rip=0x%llx\n",
               (unsigned long long)USER_DATA_SELECTOR,
               (unsigned long long)stack,
               (unsigned long long)0x202ULL,
               (unsigned long long)USER_CODE_SELECTOR,
               (unsigned long long)entry);
    if (g_bisect_mask_timer_before_first_user) {
        fut_printf("[BISECT-TIMER] masking LAPIC timer before first user handoff\n");
        lapic_timer_disable();
        g_bisect_mask_timer_before_first_user = false;
    }
    fut_printf("[BISECT-TRAMP] CR3 swap+iretq: cur=0x%llx new=0x%llx\n",
               (unsigned long long)current_cr3,
               (unsigned long long)expected_cr3);
    const bool debug_skip_user_cr3_swap = false;
    if (!debug_skip_user_cr3_swap && current_cr3 != expected_cr3) {
        extern void fut_write_cr3(uint64_t);
        fut_write_cr3(expected_cr3);
    } else if (debug_skip_user_cr3_swap) {
        fut_printf("[BISECT-TRAMP] DEBUG: skipping CR3 switch on purpose; expect immediate user fetch fault if trap path works\n");
    }

    /* DIAGNOSTIC: print waypoints after CR3 swap so we can tell exactly
     * where execution dies if the box hangs. The historical comment
     * said "no prints after CR3" — but that assumption hides which
     * step actually faults. Each of these prints uses kernel-half code
     * + data + klog ring + fb_console; if any of those isn't mapped in
     * the new CR3 we'll know which is the first to break. */
    fut_printf("[BISECT-A] post-CR3 fetch+printf OK (cr3=0x%llx)\n",
               (unsigned long long)fut_read_cr3());

    /* The BIG SURPRISE on HP Chromebook real hardware: the SECOND
     * fut_printf after CR3 swap hangs, even though the first one
     * (BISECT-A above) completes. The first printf's full path —
     * serial-LSR-poll, fb_console scroll, klog_write, klog_persist_write
     * — all completed fine. State that changed between calls: klog
     * cursor advanced, klog_at_line_start now 1 (so the next call will
     * inject a timestamp), fb_console cursor advanced past EOL, possibly
     * a scroll on next char.
     *
     * Bisect by NOT calling fut_printf for the immediate next step.
     * Instead use bypass mechanisms: a direct fb_poke_corner_marker
     * (touches g_fb_virt only) and raw inline-asm outb to serial port
     * 0x3F8 (no LSR poll, no fb_console_putc, no klog_write). If we see
     * the corner marker but no further fut_printf, the cliff is inside
     * fut_printf's klog/fb_console/serial path. */
    extern void fb_poke_corner_marker(int n);
    fb_poke_corner_marker(8);  /* 8-pixel yellow marker — direct FB write */
    __asm__ volatile(
        "movw $0x3F8, %%dx\n\t"
        "movb $'A', %%al\n\t"
        "outb %%al, %%dx\n\t"
        "movb $'0', %%al\n\t"
        "outb %%al, %%dx\n\t"
        "movb $'.', %%al\n\t"
        "outb %%al, %%dx\n\t"
        "movb $'1', %%al\n\t"
        "outb %%al, %%dx\n\t"
        "movb $'\\n', %%al\n\t"
        "outb %%al, %%dx\n\t"
        ::: "rax", "rdx", "memory");
    fb_poke_corner_marker(16);  /* 16-pixel marker — past the raw serial */

    fut_printf("[BISECT-A0.3] second-fut_printf after CR3 — hang point?\n");
    fb_poke_corner_marker(24); /* 24-pixel marker — printf returned */

    __asm__ volatile("cli" ::: "memory");
    fut_printf("[BISECT-A0.5] after cli\n");
    fb_poke_corner_marker(32);

    fut_printf("[BISECT-A1] survived the post-CR3 printf, about to compute handoff_frame\n");
    fb_poke_corner_marker(40);

    if (g_bisect_probe_kernel_cr3_roundtrip) {
        uint64_t original_cr3 = current_cr3;
        uint64_t observed_cr3 = 0;
        __asm__ volatile(
            "mov %1, %%cr3\n\t"
            "mov %%cr3, %0\n\t"
            "nop\n\t"
            "nop\n\t"
            "mov %2, %%cr3\n\t"
            : "=r"(observed_cr3)
            : "r"(expected_cr3), "r"(original_cr3)
            : "memory");
        fut_printf("[BISECT-KCR3] roundtrip survived observed=0x%llx restored=0x%llx\n",
                   (unsigned long long)observed_cr3,
                   (unsigned long long)fut_read_cr3());
        fut_platform_panic("[BISECT-KCR3] stopping after kernel-mode CR3 roundtrip probe");
    }

#ifdef DEBUG_USER_TRAMPOLINE
    /* Debug: Print 'A' before fut_do_user_iretq */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'A', %%al; outb %%al, %%dx" ::: "al", "dx", "memory");
#endif

    /* (post-CR3 PTE probe removed for this iter — it was a fb_console
     *  print and so subject to the same possible cliff as the CR3
     *  follow-up print we removed above.) */

    /* Build a real interrupt frame on the handoff stack and resume it through
     * the validated context-switch restore path instead of the bespoke
     * user_iretq.S transition. */
    fut_printf("[BISECT-A2] before handoff_frame compute, handoff_stack_top=0x%llx\n",
               (unsigned long long)handoff_stack_top);
    fut_interrupt_frame_t *handoff_frame =
        (fut_interrupt_frame_t *)(uintptr_t)(handoff_stack_top - sizeof(fut_interrupt_frame_t));
    fut_printf("[BISECT-B] handoff_frame=0x%llx (about to memset)\n",
               (unsigned long long)(uintptr_t)handoff_frame);
    __builtin_memset(handoff_frame, 0, sizeof(*handoff_frame));
    fut_printf("[BISECT-C] memset done, populating frame\n");
    handoff_frame->ds = USER_DATA_SELECTOR;
    handoff_frame->es = USER_DATA_SELECTOR;
    handoff_frame->vector = 32;
    handoff_frame->error_code = 0;
    handoff_frame->rip = entry;
    handoff_frame->cs = USER_CODE_SELECTOR;
    handoff_frame->rflags = 0x202;
    handoff_frame->rsp = stack;
    handoff_frame->ss = USER_DATA_SELECTOR;
    fut_printf("[BISECT-D] frame populated, calling fut_resume_user_frame\n");

    fut_resume_user_frame(handoff_frame, handoff_thread);

    /* Should NEVER reach here */
    extern void fut_platform_panic(const char *);
    fut_platform_panic("[FATAL] fut_do_user_iretq returned - this should never happen!");
    while (1) { __asm__ volatile("hlt"); }
}

/* PT_GNU_STACK: when true, stack pages are mapped without PTE_NX (executable) */
static bool g_stack_exec = false;

static int stage_stack_pages(fut_mm_t *mm, uint64_t *out_stack_top) {
    /* Enforce RLIMIT_STACK: use the task's soft stack limit to determine
     * stack size, capped at USER_STACK_PAGES * PAGE_SIZE.  A minimum of
     * 4 pages (16 KB) is always allocated so the process can start. */
    size_t stack_pages = USER_STACK_PAGES;
    fut_task_t *stask = fut_task_current();
    if (stask) {
        uint64_t rlim_stack = stask->rlimits[3].rlim_cur; /* RLIMIT_STACK = 3 */
        if (rlim_stack != (uint64_t)-1 && rlim_stack > 0) {
            size_t rlim_pages = (size_t)((rlim_stack + PAGE_SIZE - 1) / PAGE_SIZE);
            if (rlim_pages < 4) rlim_pages = 4;  /* Minimum 4 pages */
            if (rlim_pages < stack_pages)
                stack_pages = rlim_pages;
        }
    }

    uint64_t base = USER_STACK_TOP - (uint64_t)stack_pages * PAGE_SIZE;
    uint8_t *pages[USER_STACK_PAGES];  /* max-sized array for stack */
    for (size_t i = 0; i < stack_pages; ++i) {
        pages[i] = NULL;
    }

    for (size_t i = 0; i < stack_pages; ++i) {
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

        uint64_t sflags = PTE_PRESENT | PTE_USER | PTE_WRITABLE;
        if (!g_stack_exec) sflags |= PTE_NX;  /* PT_GNU_STACK controls NX */
        int rc = pmap_map_user(mm_context(mm),
                               base + (uint64_t)i * PAGE_SIZE,
                               phys,
                               PAGE_SIZE,
                               sflags);
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

    /* Register the stack VMA so it appears as [stack] in /proc/pid/maps.
     * Use integer constants (3 = PROT_READ|PROT_WRITE) since sys/mman.h
     * is not included in this compilation unit's include set. */
    fut_mm_add_vma(mm, base, USER_STACK_TOP, 3 /* PROT_READ|PROT_WRITE */, VMA_STACK | VMA_GROWSDOWN);

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
    /* Allocate a page for __thread variables (accessed at negative offsets
     * from the TCB). This page is mapped just below USER_TLS_BASE. */
    uint8_t *tls_data_page = fut_pmm_alloc_page();
    if (!tls_data_page) {
        return -ENOMEM;
    }
    memset(tls_data_page, 0, PAGE_SIZE);

    /* Allocate a page for the TCB (Thread Control Block) at USER_TLS_BASE.
     * Contains the self-pointer at offset 0 and stack canary at offset 0x28. */
    uint8_t *tcb_page = fut_pmm_alloc_page();
    if (!tcb_page) {
        fut_pmm_free_page(tls_data_page);
        return -ENOMEM;
    }
    memset(tcb_page, 0, PAGE_SIZE);

    /* Write TLS self-pointer at offset 0 (x86_64 TLS ABI requirement).
     * GCC __thread variables are accessed via %fs:0 -> self-pointer,
     * then negative offsets from the TCB. */
    *(uint64_t *)(tcb_page) = USER_TLS_BASE;

    /* Initialize stack canary at offset 0x28
     * Use TSC directly for entropy (avoid fut_get_time_ns which may hang) */
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
    uint64_t canary = (((uint64_t)hi << 32) | lo) ^ 0xDEADBEEFCAFEBABEULL ^ (uintptr_t)tcb_page;
    /* Ensure canary has a null byte to help detect string overflows */
    canary &= ~0xFFULL;
    *(uint64_t *)(tcb_page + TLS_STACK_CANARY_OFFSET) = canary;

    /* Map TLS data page at USER_TLS_BASE - PAGE_SIZE (for __thread vars) */
    phys_addr_t tls_data_phys = pmap_virt_to_phys((uintptr_t)tls_data_page);
    int rc = pmap_map_user(mm_context(mm),
                           USER_TLS_BASE - PAGE_SIZE,
                           tls_data_phys,
                           PAGE_SIZE,
                           PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX);
    if (rc != 0) {
        fut_pmm_free_page(tls_data_page);
        fut_pmm_free_page(tcb_page);
        return rc;
    }

    /* Map TCB page at USER_TLS_BASE (self-pointer + canary) */
    phys_addr_t tcb_phys = pmap_virt_to_phys((uintptr_t)tcb_page);
    rc = pmap_map_user(mm_context(mm),
                       USER_TLS_BASE,
                       tcb_phys,
                       PAGE_SIZE,
                       PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX);
    if (rc != 0) {
        fut_pmm_free_page(tls_data_page);
        fut_pmm_free_page(tcb_page);
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
extern const uint8_t _binary_build_bin_x86_64_user_init_start[];
extern const uint8_t _binary_build_bin_x86_64_user_init_end[];
extern const uint8_t _binary_build_bin_x86_64_user_second_start[];
extern const uint8_t _binary_build_bin_x86_64_user_second_end[];
/* Rust user-space CLIs — staged independently of Wayland. */
#if ENABLE_RUST_USERLAND
extern const uint8_t _binary_build_bin_x86_64_user_rust_hello_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_hello_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_uname_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_uname_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_pwd_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_pwd_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_ls_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_ls_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_mkdir_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_mkdir_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_touch_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_touch_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_rm_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_rm_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cat_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cat_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_wc_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_wc_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_true_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_true_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_false_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_false_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_env_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_env_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_head_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_head_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tail_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tail_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_grep_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_grep_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_sleep_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_sleep_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_date_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_date_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_settings_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_settings_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tree_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tree_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_wallpaper_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_wallpaper_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cp_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cp_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_mv_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_mv_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_basename_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_basename_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_dirname_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_dirname_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_clear_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_clear_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_which_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_which_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_readlink_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_readlink_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_ln_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_ln_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tee_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tee_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_yes_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_yes_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_uniq_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_uniq_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_realpath_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_realpath_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cmp_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cmp_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_nl_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_nl_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_rev_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_rev_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_od_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_od_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_printenv_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_printenv_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_whoami_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_whoami_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_id_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_id_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_chmod_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_chmod_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_hostname_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_hostname_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_arch_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_arch_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_kill_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_kill_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_rmdir_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_rmdir_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_sync_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_sync_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_fold_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_fold_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tac_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tac_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_strings_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_strings_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cut_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_cut_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_seq_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_seq_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tr_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tr_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_base64_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_base64_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_mktemp_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_mktemp_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_uptime_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_uptime_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_truncate_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_truncate_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_stat_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_stat_end[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tty_start[];
extern const uint8_t _binary_build_bin_x86_64_user_rust_tty_end[];
#endif
/* Core Wayland binaries (production) */
#if ENABLE_WAYLAND
extern const uint8_t _binary_build_bin_x86_64_user_futura_wayland_start[];
extern const uint8_t _binary_build_bin_x86_64_user_futura_wayland_end[];
extern const uint8_t _binary_build_bin_x86_64_user_futura_shell_start[];
extern const uint8_t _binary_build_bin_x86_64_user_futura_shell_end[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_term_start[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_term_end[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_panel_start[];
extern const uint8_t _binary_build_bin_x86_64_user_wl_panel_end[];
#endif
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

/* Startup sound: bundled as both the original MP3 (preserved as source-
 * of-truth for future MP3-decoder work) and a 10-second/22.05 kHz/stereo
 * S16LE PCM clip with a 1-second fade-out at the tail (decode-free, can
 * be handed straight to whichever audio backend comes up first). Staged
 * at /usr/share/sounds/ following the XDG-ish layout the userland shell
 * uses for other assets. */
extern const uint8_t _binary_assets_sounds_startup_mp3_start[];
extern const uint8_t _binary_assets_sounds_startup_mp3_end[];
extern const uint8_t _binary_assets_sounds_startup_pcm_start[];
extern const uint8_t _binary_assets_sounds_startup_pcm_end[];

int fut_stage_startup_sound(void) {
    (void)fut_vfs_mkdir("/usr", 0755);
    (void)fut_vfs_mkdir("/usr/share", 0755);
    (void)fut_vfs_mkdir("/usr/share/sounds", 0755);
    int mp3_rc = stage_blob(_binary_assets_sounds_startup_mp3_start,
                            _binary_assets_sounds_startup_mp3_end,
                            "/usr/share/sounds/startup.mp3");
    int pcm_rc = stage_blob(_binary_assets_sounds_startup_pcm_start,
                            _binary_assets_sounds_startup_pcm_end,
                            "/usr/share/sounds/startup.pcm");
    return (mp3_rc < 0) ? mp3_rc : pcm_rc;
}

#if ENABLE_RUST_USERLAND
int fut_stage_rust_hello_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_hello_start,
                      _binary_build_bin_x86_64_user_rust_hello_end,
                      "/bin/hello");
}

int fut_stage_rust_uname_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_uname_start,
                      _binary_build_bin_x86_64_user_rust_uname_end,
                      "/bin/uname");
}

int fut_stage_rust_pwd_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_pwd_start,
                      _binary_build_bin_x86_64_user_rust_pwd_end,
                      "/bin/pwd");
}

int fut_stage_rust_ls_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_ls_start,
                      _binary_build_bin_x86_64_user_rust_ls_end,
                      "/bin/ls");
}

int fut_stage_rust_mkdir_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_mkdir_start,
                      _binary_build_bin_x86_64_user_rust_mkdir_end,
                      "/bin/mkdir");
}

int fut_stage_rust_touch_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_touch_start,
                      _binary_build_bin_x86_64_user_rust_touch_end,
                      "/bin/touch");
}

int fut_stage_rust_rm_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_rm_start,
                      _binary_build_bin_x86_64_user_rust_rm_end,
                      "/bin/rm");
}

int fut_stage_rust_cat_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_cat_start,
                      _binary_build_bin_x86_64_user_rust_cat_end,
                      "/bin/cat");
}

int fut_stage_rust_wc_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_wc_start,
                      _binary_build_bin_x86_64_user_rust_wc_end,
                      "/bin/wc");
}

int fut_stage_rust_true_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_true_start,
                      _binary_build_bin_x86_64_user_rust_true_end,
                      "/bin/true");
}

int fut_stage_rust_false_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_false_start,
                      _binary_build_bin_x86_64_user_rust_false_end,
                      "/bin/false");
}

int fut_stage_rust_env_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_env_start,
                      _binary_build_bin_x86_64_user_rust_env_end,
                      "/bin/env");
}

int fut_stage_rust_head_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_head_start,
                      _binary_build_bin_x86_64_user_rust_head_end,
                      "/bin/head");
}

int fut_stage_rust_tail_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_tail_start,
                      _binary_build_bin_x86_64_user_rust_tail_end,
                      "/bin/tail");
}

int fut_stage_rust_grep_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_grep_start,
                      _binary_build_bin_x86_64_user_rust_grep_end,
                      "/bin/grep");
}

int fut_stage_rust_sleep_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_sleep_start,
                      _binary_build_bin_x86_64_user_rust_sleep_end,
                      "/bin/sleep");
}

int fut_stage_rust_date_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_date_start,
                      _binary_build_bin_x86_64_user_rust_date_end,
                      "/bin/date");
}

int fut_stage_rust_settings_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_settings_start,
                      _binary_build_bin_x86_64_user_rust_settings_end,
                      "/bin/settings");
}

int fut_stage_rust_tree_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_tree_start,
                      _binary_build_bin_x86_64_user_rust_tree_end,
                      "/bin/tree");
}

int fut_stage_rust_wallpaper_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_wallpaper_start,
                      _binary_build_bin_x86_64_user_rust_wallpaper_end,
                      "/bin/wallpaper");
}

int fut_stage_rust_cp_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_cp_start,
                      _binary_build_bin_x86_64_user_rust_cp_end,
                      "/bin/cp");
}

int fut_stage_rust_mv_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_mv_start,
                      _binary_build_bin_x86_64_user_rust_mv_end,
                      "/bin/mv");
}

int fut_stage_rust_basename_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_basename_start,
                      _binary_build_bin_x86_64_user_rust_basename_end,
                      "/bin/basename");
}

int fut_stage_rust_dirname_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_dirname_start,
                      _binary_build_bin_x86_64_user_rust_dirname_end,
                      "/bin/dirname");
}

int fut_stage_rust_clear_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_clear_start,
                      _binary_build_bin_x86_64_user_rust_clear_end,
                      "/bin/clear");
}

int fut_stage_rust_which_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_which_start,
                      _binary_build_bin_x86_64_user_rust_which_end,
                      "/bin/which");
}

int fut_stage_rust_readlink_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_readlink_start,
                      _binary_build_bin_x86_64_user_rust_readlink_end,
                      "/bin/readlink");
}

int fut_stage_rust_ln_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_ln_start,
                      _binary_build_bin_x86_64_user_rust_ln_end,
                      "/bin/ln");
}

int fut_stage_rust_tee_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_tee_start,
                      _binary_build_bin_x86_64_user_rust_tee_end,
                      "/bin/tee");
}

int fut_stage_rust_yes_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_yes_start,
                      _binary_build_bin_x86_64_user_rust_yes_end,
                      "/bin/yes");
}

int fut_stage_rust_uniq_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_uniq_start,
                      _binary_build_bin_x86_64_user_rust_uniq_end,
                      "/bin/uniq");
}

int fut_stage_rust_realpath_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_realpath_start,
                      _binary_build_bin_x86_64_user_rust_realpath_end,
                      "/bin/realpath");
}

int fut_stage_rust_cmp_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_cmp_start,
                      _binary_build_bin_x86_64_user_rust_cmp_end,
                      "/bin/cmp");
}

int fut_stage_rust_nl_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_nl_start,
                      _binary_build_bin_x86_64_user_rust_nl_end,
                      "/bin/nl");
}

int fut_stage_rust_rev_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_rev_start,
                      _binary_build_bin_x86_64_user_rust_rev_end,
                      "/bin/rev");
}

int fut_stage_rust_od_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_od_start,
                      _binary_build_bin_x86_64_user_rust_od_end,
                      "/bin/od");
}

int fut_stage_rust_printenv_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_printenv_start,
                      _binary_build_bin_x86_64_user_rust_printenv_end,
                      "/bin/printenv");
}

int fut_stage_rust_whoami_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_whoami_start,
                      _binary_build_bin_x86_64_user_rust_whoami_end,
                      "/bin/whoami");
}

int fut_stage_rust_id_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_id_start,
                      _binary_build_bin_x86_64_user_rust_id_end,
                      "/bin/id");
}

int fut_stage_rust_chmod_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_chmod_start,
                      _binary_build_bin_x86_64_user_rust_chmod_end,
                      "/bin/chmod");
}

int fut_stage_rust_hostname_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_hostname_start,
                      _binary_build_bin_x86_64_user_rust_hostname_end,
                      "/bin/hostname");
}

int fut_stage_rust_arch_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_arch_start,
                      _binary_build_bin_x86_64_user_rust_arch_end,
                      "/bin/arch");
}

int fut_stage_rust_kill_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_kill_start,
                      _binary_build_bin_x86_64_user_rust_kill_end,
                      "/bin/kill");
}

int fut_stage_rust_rmdir_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_rmdir_start,
                      _binary_build_bin_x86_64_user_rust_rmdir_end,
                      "/bin/rmdir");
}

int fut_stage_rust_sync_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_sync_start,
                      _binary_build_bin_x86_64_user_rust_sync_end,
                      "/bin/sync");
}

int fut_stage_rust_fold_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_fold_start,
                      _binary_build_bin_x86_64_user_rust_fold_end,
                      "/bin/fold");
}

int fut_stage_rust_tac_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_tac_start,
                      _binary_build_bin_x86_64_user_rust_tac_end,
                      "/bin/tac");
}

int fut_stage_rust_strings_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_strings_start,
                      _binary_build_bin_x86_64_user_rust_strings_end,
                      "/bin/strings");
}

int fut_stage_rust_cut_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_cut_start,
                      _binary_build_bin_x86_64_user_rust_cut_end,
                      "/bin/cut");
}

int fut_stage_rust_seq_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_seq_start,
                      _binary_build_bin_x86_64_user_rust_seq_end,
                      "/bin/seq");
}

int fut_stage_rust_tr_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_tr_start,
                      _binary_build_bin_x86_64_user_rust_tr_end,
                      "/bin/tr");
}

int fut_stage_rust_base64_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_base64_start,
                      _binary_build_bin_x86_64_user_rust_base64_end,
                      "/bin/base64");
}

int fut_stage_rust_mktemp_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_mktemp_start,
                      _binary_build_bin_x86_64_user_rust_mktemp_end,
                      "/bin/mktemp");
}

int fut_stage_rust_uptime_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_uptime_start,
                      _binary_build_bin_x86_64_user_rust_uptime_end,
                      "/bin/uptime");
}

int fut_stage_rust_truncate_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_truncate_start,
                      _binary_build_bin_x86_64_user_rust_truncate_end,
                      "/bin/truncate");
}

int fut_stage_rust_stat_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_stat_start,
                      _binary_build_bin_x86_64_user_rust_stat_end,
                      "/bin/stat");
}

int fut_stage_rust_tty_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_rust_tty_start,
                      _binary_build_bin_x86_64_user_rust_tty_end,
                      "/bin/tty");
}
#else
int fut_stage_rust_hello_binary(void) { return -ENOSYS; }
int fut_stage_rust_uname_binary(void) { return -ENOSYS; }
int fut_stage_rust_pwd_binary(void)   { return -ENOSYS; }
int fut_stage_rust_ls_binary(void)    { return -ENOSYS; }
int fut_stage_rust_mkdir_binary(void) { return -ENOSYS; }
int fut_stage_rust_touch_binary(void) { return -ENOSYS; }
int fut_stage_rust_rm_binary(void)    { return -ENOSYS; }
int fut_stage_rust_cat_binary(void)   { return -ENOSYS; }
int fut_stage_rust_wc_binary(void)    { return -ENOSYS; }
int fut_stage_rust_true_binary(void)  { return -ENOSYS; }
int fut_stage_rust_false_binary(void) { return -ENOSYS; }
int fut_stage_rust_env_binary(void)   { return -ENOSYS; }
int fut_stage_rust_head_binary(void)  { return -ENOSYS; }
int fut_stage_rust_tail_binary(void)  { return -ENOSYS; }
int fut_stage_rust_grep_binary(void)  { return -ENOSYS; }
int fut_stage_rust_sleep_binary(void) { return -ENOSYS; }
int fut_stage_rust_date_binary(void)  { return -ENOSYS; }
int fut_stage_rust_settings_binary(void) { return -ENOSYS; }
int fut_stage_rust_tree_binary(void)     { return -ENOSYS; }
int fut_stage_rust_wallpaper_binary(void) { return -ENOSYS; }
int fut_stage_rust_cp_binary(void)        { return -ENOSYS; }
int fut_stage_rust_mv_binary(void)        { return -ENOSYS; }
int fut_stage_rust_basename_binary(void)  { return -ENOSYS; }
int fut_stage_rust_dirname_binary(void)   { return -ENOSYS; }
int fut_stage_rust_clear_binary(void)     { return -ENOSYS; }
int fut_stage_rust_which_binary(void)     { return -ENOSYS; }
int fut_stage_rust_readlink_binary(void)  { return -ENOSYS; }
int fut_stage_rust_ln_binary(void)        { return -ENOSYS; }
int fut_stage_rust_tee_binary(void)       { return -ENOSYS; }
int fut_stage_rust_yes_binary(void)       { return -ENOSYS; }
int fut_stage_rust_uniq_binary(void)      { return -ENOSYS; }
int fut_stage_rust_realpath_binary(void)  { return -ENOSYS; }
int fut_stage_rust_cmp_binary(void)       { return -ENOSYS; }
int fut_stage_rust_nl_binary(void)        { return -ENOSYS; }
int fut_stage_rust_rev_binary(void)       { return -ENOSYS; }
int fut_stage_rust_od_binary(void)        { return -ENOSYS; }
int fut_stage_rust_printenv_binary(void)  { return -ENOSYS; }
int fut_stage_rust_whoami_binary(void)    { return -ENOSYS; }
int fut_stage_rust_id_binary(void)        { return -ENOSYS; }
int fut_stage_rust_chmod_binary(void)     { return -ENOSYS; }
int fut_stage_rust_hostname_binary(void)  { return -ENOSYS; }
int fut_stage_rust_arch_binary(void)      { return -ENOSYS; }
int fut_stage_rust_kill_binary(void)      { return -ENOSYS; }
int fut_stage_rust_rmdir_binary(void)     { return -ENOSYS; }
int fut_stage_rust_sync_binary(void)      { return -ENOSYS; }
int fut_stage_rust_fold_binary(void)      { return -ENOSYS; }
int fut_stage_rust_tac_binary(void)       { return -ENOSYS; }
int fut_stage_rust_strings_binary(void)   { return -ENOSYS; }
int fut_stage_rust_cut_binary(void)       { return -ENOSYS; }
int fut_stage_rust_seq_binary(void)       { return -ENOSYS; }
int fut_stage_rust_tr_binary(void)        { return -ENOSYS; }
int fut_stage_rust_base64_binary(void)    { return -ENOSYS; }
int fut_stage_rust_mktemp_binary(void)    { return -ENOSYS; }
int fut_stage_rust_uptime_binary(void)    { return -ENOSYS; }
int fut_stage_rust_truncate_binary(void)  { return -ENOSYS; }
int fut_stage_rust_stat_binary(void)      { return -ENOSYS; }
int fut_stage_rust_tty_binary(void)       { return -ENOSYS; }
#endif
#else
int fut_stage_shell_binary(void) {
    return -ENOSYS;  /* Shell binary not available on macOS host builds */
}

int fut_stage_rust_hello_binary(void) {
    return -ENOSYS;  /* rust-hello not available on macOS host builds */
}

int fut_stage_rust_uname_binary(void) {
    return -ENOSYS;  /* rust-uname not available on macOS host builds */
}

int fut_stage_rust_pwd_binary(void) {
    return -ENOSYS;  /* rust-pwd not available on macOS host builds */
}

int fut_stage_rust_ls_binary(void) {
    return -ENOSYS;  /* rust-ls not available on macOS host builds */
}

int fut_stage_rust_mkdir_binary(void) {
    return -ENOSYS;  /* rust-mkdir not available on macOS host builds */
}

int fut_stage_rust_touch_binary(void) {
    return -ENOSYS;  /* rust-touch not available on macOS host builds */
}

int fut_stage_rust_rm_binary(void) {
    return -ENOSYS;  /* rust-rm not available on macOS host builds */
}

int fut_stage_rust_cat_binary(void) {
    return -ENOSYS;  /* rust-cat not available on macOS host builds */
}

int fut_stage_rust_wc_binary(void) {
    return -ENOSYS;  /* rust-wc not available on macOS host builds */
}

int fut_stage_rust_true_binary(void) {
    return -ENOSYS;  /* rust-true not available on macOS host builds */
}

int fut_stage_rust_false_binary(void) {
    return -ENOSYS;  /* rust-false not available on macOS host builds */
}

int fut_stage_rust_env_binary(void) {
    return -ENOSYS;  /* rust-env not available on macOS host builds */
}

int fut_stage_rust_head_binary(void) {
    return -ENOSYS;  /* rust-head not available on macOS host builds */
}

int fut_stage_rust_tail_binary(void) {
    return -ENOSYS;  /* rust-tail not available on macOS host builds */
}

int fut_stage_rust_grep_binary(void) {
    return -ENOSYS;  /* rust-grep not available on macOS host builds */
}

int fut_stage_rust_sleep_binary(void) {
    return -ENOSYS;  /* rust-sleep not available on macOS host builds */
}

int fut_stage_rust_date_binary(void) {
    return -ENOSYS;  /* rust-date not available on macOS host builds */
}

int fut_stage_rust_settings_binary(void) {
    return -ENOSYS;  /* rust-settings not available on macOS host builds */
}

int fut_stage_rust_tree_binary(void) {
    return -ENOSYS;  /* rust-tree not available on macOS host builds */
}

int fut_stage_rust_wallpaper_binary(void) {
    return -ENOSYS;  /* rust-wallpaper not available on macOS host builds */
}

int fut_stage_rust_cp_binary(void) {
    return -ENOSYS;  /* rust-cp not available on macOS host builds */
}

int fut_stage_rust_mv_binary(void) {
    return -ENOSYS;  /* rust-mv not available on macOS host builds */
}

int fut_stage_rust_basename_binary(void) {
    return -ENOSYS;  /* rust-basename not available on macOS host builds */
}

int fut_stage_rust_dirname_binary(void) {
    return -ENOSYS;  /* rust-dirname not available on macOS host builds */
}

int fut_stage_rust_clear_binary(void) {
    return -ENOSYS;  /* rust-clear not available on macOS host builds */
}

int fut_stage_rust_which_binary(void) {
    return -ENOSYS;  /* rust-which not available on macOS host builds */
}

int fut_stage_rust_readlink_binary(void) {
    return -ENOSYS;  /* rust-readlink not available on macOS host builds */
}

int fut_stage_rust_ln_binary(void) {
    return -ENOSYS;  /* rust-ln not available on macOS host builds */
}

int fut_stage_rust_tee_binary(void) {
    return -ENOSYS;  /* rust-tee not available on macOS host builds */
}

int fut_stage_rust_yes_binary(void) {
    return -ENOSYS;  /* rust-yes not available on macOS host builds */
}

int fut_stage_rust_uniq_binary(void) {
    return -ENOSYS;  /* rust-uniq not available on macOS host builds */
}

int fut_stage_rust_realpath_binary(void) {
    return -ENOSYS;  /* rust-realpath not available on macOS host builds */
}

int fut_stage_rust_cmp_binary(void) {
    return -ENOSYS;  /* rust-cmp not available on macOS host builds */
}

int fut_stage_rust_nl_binary(void) {
    return -ENOSYS;  /* rust-nl not available on macOS host builds */
}

int fut_stage_rust_rev_binary(void) {
    return -ENOSYS;  /* rust-rev not available on macOS host builds */
}

int fut_stage_rust_od_binary(void) {
    return -ENOSYS;  /* rust-od not available on macOS host builds */
}

int fut_stage_rust_printenv_binary(void) {
    return -ENOSYS;  /* rust-printenv not available on macOS host builds */
}

int fut_stage_rust_whoami_binary(void) {
    return -ENOSYS;  /* rust-whoami not available on macOS host builds */
}

int fut_stage_rust_id_binary(void) {
    return -ENOSYS;  /* rust-id not available on macOS host builds */
}

int fut_stage_rust_chmod_binary(void) {
    return -ENOSYS;  /* rust-chmod not available on macOS host builds */
}

int fut_stage_rust_hostname_binary(void) {
    return -ENOSYS;  /* rust-hostname not available on macOS host builds */
}

int fut_stage_rust_arch_binary(void) {
    return -ENOSYS;  /* rust-arch not available on macOS host builds */
}

int fut_stage_rust_kill_binary(void) {
    return -ENOSYS;  /* rust-kill not available on macOS host builds */
}

int fut_stage_rust_rmdir_binary(void) {
    return -ENOSYS;  /* rust-rmdir not available on macOS host builds */
}

int fut_stage_rust_sync_binary(void) {
    return -ENOSYS;  /* rust-sync not available on macOS host builds */
}

int fut_stage_rust_fold_binary(void) {
    return -ENOSYS;  /* rust-fold not available on macOS host builds */
}

int fut_stage_rust_tac_binary(void) {
    return -ENOSYS;  /* rust-tac not available on macOS host builds */
}

int fut_stage_rust_strings_binary(void) {
    return -ENOSYS;  /* rust-strings not available on macOS host builds */
}

int fut_stage_rust_cut_binary(void) {
    return -ENOSYS;  /* rust-cut not available on macOS host builds */
}

int fut_stage_rust_seq_binary(void) {
    return -ENOSYS;  /* rust-seq not available on macOS host builds */
}

int fut_stage_rust_tr_binary(void) {
    return -ENOSYS;  /* rust-tr not available on macOS host builds */
}

int fut_stage_rust_base64_binary(void) {
    return -ENOSYS;  /* rust-base64 not available on macOS host builds */
}

int fut_stage_rust_mktemp_binary(void) {
    return -ENOSYS;  /* rust-mktemp not available on macOS host builds */
}

int fut_stage_rust_uptime_binary(void) {
    return -ENOSYS;  /* rust-uptime not available on macOS host builds */
}

int fut_stage_rust_truncate_binary(void) {
    return -ENOSYS;  /* rust-truncate not available on macOS host builds */
}

int fut_stage_rust_stat_binary(void) {
    return -ENOSYS;  /* rust-stat not available on macOS host builds */
}

int fut_stage_rust_tty_binary(void) {
    return -ENOSYS;  /* rust-tty not available on macOS host builds */
}
#endif

#ifdef __x86_64__
int fut_stage_init_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_init_start,
                      _binary_build_bin_x86_64_user_init_end,
                      "/sbin/init");
}

int fut_stage_second_stub_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_second_start,
                      _binary_build_bin_x86_64_user_second_end,
                      "/sbin/second");
}
#else /* !__x86_64__ */
#include <kernel/errno.h>

int fut_stage_init_binary(void) {
    return -ENOSYS;  /* Not implemented for non-x86_64 platforms */
}

int fut_stage_second_stub_binary(void) {
    return -ENOSYS;  /* Not implemented for non-x86_64 platforms */
}
#endif /* __x86_64__ */

/* Core Wayland binaries (production - only when ENABLE_WAYLAND=1) */
#if ENABLE_WAYLAND && !defined(FUTURA_MACOS_HOST_BUILD)
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

int fut_stage_wl_panel_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_wl_panel_start,
                      _binary_build_bin_x86_64_user_wl_panel_end,
                      "/bin/wl-panel");
}

int fut_stage_futura_shell_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_x86_64_user_futura_shell_start,
                      _binary_build_bin_x86_64_user_futura_shell_end,
                      "/bin/futura-shell");
}
#else
int fut_stage_wayland_compositor_binary(void) {
    return -ENOSYS;  /* Wayland not available */
}

int fut_stage_wl_term_binary(void) {
    return -ENOSYS;  /* Wayland not available */
}

int fut_stage_wl_panel_binary(void) {
    return -ENOSYS;  /* Wayland not available */
}

int fut_stage_futura_shell_binary(void) {
    return -ENOSYS;  /* Wayland not available */
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
        fut_printf("[EXEC] corrupt ELF: bad magic 0x%08x '%s'\n",
                   *(uint32_t *)ehdr.e_ident, path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    if (ehdr.e_ident[4] != ELF_CLASS_64) {
        fut_printf("[EXEC] corrupt ELF: bad class %d (need ELF64) '%s'\n",
                   ehdr.e_ident[4], path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    if (ehdr.e_ident[5] != ELF_DATA_LE) {
        fut_printf("[EXEC] corrupt ELF: bad data encoding %d (need LE) '%s'\n",
                   ehdr.e_ident[5], path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    /* Validate ELF version: must be EV_CURRENT (1) */
    if (ehdr.e_version != 1) {
        fut_printf("[EXEC] corrupt ELF: bad version %u (need 1) '%s'\n",
                   ehdr.e_version, path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    /* Validate ELF type: must be ET_EXEC (2) or ET_DYN (3) */
    if (ehdr.e_type != 2 && ehdr.e_type != 3) {
        fut_printf("[EXEC] corrupt ELF: bad type %d (need ET_EXEC=2 or ET_DYN=3) '%s'\n",
                   ehdr.e_type, path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    /* Validate machine type: must be EM_X86_64 (0x3E) */
    if (ehdr.e_machine != 0x3E) {
        fut_printf("[EXEC] corrupt ELF: bad machine 0x%x (need EM_X86_64=0x3E) '%s'\n",
                   ehdr.e_machine, path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    if (ehdr.e_phentsize != sizeof(elf64_phdr_t)) {
        fut_printf("[EXEC] corrupt ELF: bad phentsize %d (need %zu) '%s'\n",
                   ehdr.e_phentsize, sizeof(elf64_phdr_t), path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    if (ehdr.e_phnum == 0) {
        fut_printf("[EXEC] corrupt ELF: no program headers '%s'\n", path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    /* Reject unreasonable e_phnum to prevent excessive allocation */
    if (ehdr.e_phnum > 256) {
        fut_printf("[EXEC] corrupt ELF: too many program headers (%d, max=256) '%s'\n",
                   ehdr.e_phnum, path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    /* Validate e_phoff: must be within the ELF header size at minimum,
     * and the program header table must not overflow 64-bit arithmetic */
    size_t ph_size = (size_t)ehdr.e_phnum * sizeof(elf64_phdr_t);
    if (ehdr.e_phoff < sizeof(elf64_ehdr_t) ||
        ph_size > UINT64_MAX - ehdr.e_phoff) {
        fut_printf("[EXEC] corrupt ELF: program header offset 0x%llx out of bounds '%s'\n",
                   (unsigned long long)ehdr.e_phoff, path);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ENOEXEC;
    }

    /* Validate section header table bounds if present */
    if (ehdr.e_shoff != 0 && ehdr.e_shnum != 0) {
        uint64_t sh_size = (uint64_t)ehdr.e_shnum * ehdr.e_shentsize;
        if (ehdr.e_shentsize == 0 || sh_size / ehdr.e_shentsize != ehdr.e_shnum ||
            sh_size > UINT64_MAX - ehdr.e_shoff) {
            fut_printf("[EXEC] corrupt ELF: section header table overflow '%s'\n", path);
            fut_vfs_close(fd);
            EXEC_CLEANUP_KARGS();
            return -ENOEXEC;
        }
    }

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

    /* Set task->comm from the binary filename (basename of path) */
    {
        const char *basename = path;
        for (const char *p = path; *p; p++) {
            if (*p == '/') basename = p + 1;
        }
        size_t clen = 0;
        while (basename[clen] && clen < sizeof(task->comm) - 1) clen++;
        for (size_t i = 0; i < clen; i++) task->comm[i] = basename[i];
        task->comm[clen] = '\0';
    }

    /* Record full argv for /proc/self/cmdline (null-separated Linux format) */
    {
        char *dst = task->proc_cmdline;
        size_t cap = sizeof(task->proc_cmdline);
        size_t pos = 0;
        if (kargv) {
            for (size_t i = 0; i < argc && pos < cap - 1; i++) {
                const char *arg = kargv[i];
                while (*arg && pos < cap - 1)
                    dst[pos++] = *arg++;
                dst[pos++] = '\0';
            }
        }
        task->proc_cmdline_len = (uint16_t)(pos < cap ? pos : cap);
    }

    /* Record full envp for /proc/self/environ (null-separated Linux format) */
    {
        char *dst = task->proc_environ;
        size_t cap = sizeof(task->proc_environ);
        size_t pos = 0;
        if (kenvp) {
            for (size_t i = 0; i < envc && pos < cap - 1; i++) {
                const char *env = kenvp[i];
                while (*env && pos < cap - 1)
                    dst[pos++] = *env++;
                dst[pos++] = '\0';
            }
        }
        task->proc_environ_len = (uint16_t)(pos < cap ? pos : cap);
    }

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

    /* PIE (ET_DYN) load bias: position-independent executables have 0-based
     * p_vaddr values; we must relocate them to a non-zero base address.
     * Linux uses 0x555555554000 (with ASLR) or a fixed base.  We use
     * 0x400000 which is the traditional x86_64 exec base. */
    uint64_t load_bias = 0;
    if (ehdr.e_type == 3 /* ET_DYN */) {
        load_bias = 0x400000ULL;
        EXEC_DEBUG("[EXEC] ET_DYN (PIE): applying load_bias=0x%llx\n",
                   (unsigned long long)load_bias);
        for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
            if (phdrs[i].p_type == 1 /* PT_LOAD */ ||
                phdrs[i].p_type == 6 /* PT_PHDR */) {
                phdrs[i].p_vaddr += load_bias;
            }
        }
    }

    /* PT_GNU_STACK: controls stack executability (default: NX).
     * If PF_X is set, the binary needs an executable stack (libffi, nested funcs).
     * PT_GNU_RELRO: region to mark read-only after relocation.
     * NOTE: PT_GNU_RELRO p_vaddr is NOT biased by the ET_DYN loop above (which
     * only adjusts PT_LOAD and PT_PHDR), so we must add load_bias manually. */
    bool stack_exec = false;
    uint64_t relro_start = 0, relro_end = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == 0x6474e551 /* PT_GNU_STACK */) {
            stack_exec = (phdrs[i].p_flags & PF_X) != 0;
            EXEC_DEBUG("[EXEC] PT_GNU_STACK: %s stack\n",
                       stack_exec ? "executable" : "non-executable");
        }
        if (phdrs[i].p_type == 0x6474e552 /* PT_GNU_RELRO */) {
            relro_start = phdrs[i].p_vaddr + load_bias;  /* apply bias for ET_DYN */
            relro_end = relro_start + phdrs[i].p_memsz;
            EXEC_DEBUG("[EXEC] PT_GNU_RELRO: 0x%llx-0x%llx\n",
                       (unsigned long long)relro_start, (unsigned long long)relro_end);
        }
    }

    /* Detect overlapping PT_LOAD segments: a crafted ELF could specify two
     * LOAD segments that map the same virtual pages, leading to undefined
     * behavior or security issues.  O(n^2) but n <= 256 and typically < 10. */
    {
        bool overlap_found = false;
        for (uint16_t i = 0; i < ehdr.e_phnum && !overlap_found; i++) {
            if (phdrs[i].p_type != PT_LOAD || phdrs[i].p_memsz == 0) continue;
            uint64_t a_start = phdrs[i].p_vaddr & ~(PAGE_SIZE - 1ULL);
            uint64_t a_end = (phdrs[i].p_vaddr + phdrs[i].p_memsz + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL);
            for (uint16_t j = i + 1; j < ehdr.e_phnum; j++) {
                if (phdrs[j].p_type != PT_LOAD || phdrs[j].p_memsz == 0) continue;
                uint64_t b_start = phdrs[j].p_vaddr & ~(PAGE_SIZE - 1ULL);
                uint64_t b_end = (phdrs[j].p_vaddr + phdrs[j].p_memsz + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL);
                if (a_start < b_end && b_start < a_end) {
                    fut_printf("[EXEC] corrupt ELF: overlapping PT_LOAD segments %u [0x%llx-0x%llx] and %u [0x%llx-0x%llx] '%s'\n",
                               i, (unsigned long long)a_start, (unsigned long long)a_end,
                               j, (unsigned long long)b_start, (unsigned long long)b_end, path);
                    overlap_found = true;
                    break;
                }
            }
        }
        if (overlap_found) {
            fut_mm_release(mm);
            fut_task_destroy(task);
            fut_free(phdrs);
            fut_vfs_close(fd);
            EXEC_CLEANUP_KARGS();
            return -ENOEXEC;
        }
    }

    /* Reset interpreter state for this exec */
    g_exec_interp_base = 0;
    g_exec_interp_entry = 0;

    /* PT_INTERP: dynamic linker path. If present, the binary requires a
     * dynamic linker (e.g., /lib/ld-linux-x86-64.so.2). Load the
     * interpreter ELF into the process address space so it can perform
     * dynamic linking before jumping to the main binary. */
    {
        char interp_path[256] = {0};
        for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
            if (phdrs[i].p_type == 3 /* PT_INTERP */ && phdrs[i].p_filesz > 0 &&
                phdrs[i].p_filesz < sizeof(interp_path)) {
                off_t saved = 0;
                extern long fut_vfs_lseek(int fd, long offset, int whence);
                saved = fut_vfs_lseek(fd, 0, 1 /* SEEK_CUR */);
                fut_vfs_lseek(fd, (long)phdrs[i].p_offset, 0 /* SEEK_SET */);
                long nr = fut_vfs_read(fd, interp_path, (size_t)phdrs[i].p_filesz);
                if (nr > 0) interp_path[nr < 255 ? nr : 255] = '\0';
                /* Strip trailing newline/whitespace */
                for (int k = (int)nr - 1; k >= 0; k--) {
                    if (interp_path[k] == '\n' || interp_path[k] == '\r' ||
                        interp_path[k] == ' ' || interp_path[k] == '\0')
                        interp_path[k] = '\0';
                    else break;
                }
                fut_vfs_lseek(fd, saved, 0 /* SEEK_SET */);
                break;
            }
        }
        /* Load interpreter if found — sets g_exec_interp_base/entry */
        if (interp_path[0]) {
            int irc = load_elf_interpreter(mm, interp_path);
            if (irc < 0) {
            }
        }
    }

    /* Resolve the file vnode for the ELF binary so PT_LOAD VMAs can be
     * recorded as file-backed (shown with pathname in /proc/<pid>/maps). */
    struct fut_vnode *elf_vnode = NULL;
    {
        struct fut_file *elf_file = fut_vfs_get_file(fd);
        if (elf_file) elf_vnode = elf_file->vnode;
    }

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

        /* Create a VMA for this PT_LOAD segment so /proc/<pid>/maps shows it
         * with the correct permissions, file offset, and pathname. */
        {
            /* PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4 */
            int vprot = 0;
            if (phdrs[i].p_flags & PF_R) vprot |= 1;
            if (phdrs[i].p_flags & PF_W) vprot |= 2;
            if (phdrs[i].p_flags & PF_X) vprot |= 4;
            uint64_t vma_start = phdrs[i].p_vaddr & ~(PAGE_SIZE - 1);
            uint64_t vma_end = (seg_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            uint64_t foff = phdrs[i].p_offset & ~(PAGE_SIZE - 1);
            fut_mm_add_vma_file(mm, vma_start, vma_end, vprot, 0,
                                elf_vnode, foff);
        }
    }

    /* PT_GNU_RELRO: mprotect the relocation-read-only region to PROT_READ.
     * This makes .got, .init_array, etc. read-only after loading, preventing
     * GOT overwrite attacks. Only applies if the region was loaded. */
    if (relro_start && relro_end > relro_start) {
        uintptr_t rs = relro_start & ~(PAGE_SIZE - 1ULL);
        uintptr_t re = (relro_end + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL);
        extern long sys_mprotect(void *addr, size_t len, int prot);
        /* PROT_READ = 1 */
        (void)sys_mprotect((void *)rs, (size_t)(re - rs), 1);
        EXEC_DEBUG("[EXEC] PT_GNU_RELRO: mprotect 0x%llx-0x%llx PROT_READ\n",
                   (unsigned long long)rs, (unsigned long long)re);
    }

    uintptr_t default_heap = 0x00400000ULL;
    uintptr_t heap_base = heap_base_candidate ? PAGE_ALIGN_UP(heap_base_candidate) : default_heap;
    heap_base += PAGE_SIZE;
    fut_mm_set_heap_base(mm, heap_base, 0);

    g_stack_exec = stack_exec;  /* Pass PT_GNU_STACK to stage_stack_pages */
    uint64_t stack_top = 0;
    rc = stage_stack_pages(mm, &stack_top);
    if (rc != 0) {
        fut_mm_release(mm);  /* mm not attached to task yet */
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return rc;
    }

    /* Set up TLS for stack canary support */
    uint64_t tls_base = 0;
    rc = stage_tls_page(mm, &tls_base);
    if (rc != 0) {
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
    /* Set ELF metadata globals for auxv in build_user_stack.
     * For PIE (ET_DYN), the entry point and phdr already include the
     * load_bias via the adjusted phdrs[].p_vaddr above. */
    g_exec_entry = ehdr.e_entry + load_bias;
    g_exec_phent = ehdr.e_phentsize;
    g_exec_phnum = ehdr.e_phnum;
    /* Find PT_PHDR or compute phdr address from first PT_LOAD.
     * Note: phdrs[].p_vaddr already includes load_bias for ET_DYN. */
    g_exec_phdr = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == 6 /* PT_PHDR */) {
            g_exec_phdr = phdrs[i].p_vaddr;  /* already biased */
            break;
        }
    }
    if (g_exec_phdr == 0 && ehdr.e_phnum > 0) {
        /* Fallback: first loadable segment vaddr + phoff */
        for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
            if (phdrs[i].p_type == 1 /* PT_LOAD */) {
                g_exec_phdr = phdrs[i].p_vaddr + ehdr.e_phoff - phdrs[i].p_offset;
                break;
            }
        }
    }

    /* Use the kernel copies of argv/envp that we made at the start */
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

    /* Inherit non-CLOEXEC file descriptors from the calling task, then fill
     * any missing stdio fds (0, 1, 2) with /dev/console.  POSIX requires
     * execve to preserve open file descriptors (minus those with FD_CLOEXEC).
     * The calling task's CLOEXEC fds were already closed by sys_execve.
     * NOTE: Only for x86_64 — ARM64 uses the second fut_exec_elf (line ~2583). */
#if defined(__x86_64__)
    {
        fut_thread_t *cur = fut_thread_current();
        fut_task_t *caller_task = cur ? cur->task : NULL;

        /* Copy non-CLOEXEC fds from caller to new task (per-FD flags) */
        if (caller_task && caller_task->fd_table && task->fd_table) {
            int max = caller_task->max_fds;
            if (max > (int)task->max_fds) max = (int)task->max_fds;
            int inherited = 0;
            for (int i = 0; i < max; i++) {
                struct fut_file *f = caller_task->fd_table[i];
                int cloexec = (caller_task->fd_flags && (caller_task->fd_flags[i] & FD_CLOEXEC));
                if (f && !cloexec) {
                    vfs_file_ref(f);
                    task->fd_table[i] = f;
                    if (task->fd_flags) task->fd_flags[i] = 0;
                    inherited++;
                }
            }
        } else {
        }

        /* Close epoll instances marked EPOLL_CLOEXEC */
        if (caller_task) {
            extern void epoll_close_cloexec(uint64_t pid);
            epoll_close_cloexec(caller_task->pid);
        }

        /* Open /dev/console only for stdio fds that are still unset */
        fut_task_t *saved_task = cur ? cur->task : NULL;
        if (cur) cur->task = task;

        for (int stdio_fd = 0; stdio_fd < 3; stdio_fd++) {
            if (!task->fd_table || !task->fd_table[stdio_fd]) {
                int got = fut_vfs_open("/dev/console", O_RDWR, 0);
                if (got >= 0 && got != stdio_fd) {
                    fut_printf("[EXEC-X86] WARNING: stdio fd %d opened as %d\n",
                               stdio_fd, got);
                }
            } else {
            }
        }

        if (cur) cur->task = saved_task;
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

    /* If interpreter was loaded, start at its entry point instead of main binary's.
     * The interpreter (ld-linux.so) will use AT_ENTRY and AT_PHDR from auxv
     * to find and jump to the main binary after dynamic linking. */
    if (g_exec_interp_entry != 0) {
        entry->entry = g_exec_interp_entry;
    } else {
        entry->entry = ehdr.e_entry + load_bias;
    }
    entry->stack = user_rsp;
    entry->argc = user_argc;
    entry->argv_ptr = user_argv;
    entry->task = task;

    /* DIRECT TRAMPOLINE PATH (bare-metal bring-up).
     *
     * The IRQ-driven thread-switch path silently triple-faults on the
     * Chromebook somewhere between STI and the new thread reaching its
     * first print. As a workaround, skip creating a separate kernel
     * thread for the user-trampoline. Instead repurpose the *bootstrap*
     * thread (the one that called fut_exec_elf) into PID 1 — which is
     * how most kernels actually do it.
     *
     * Sequence:
     *   - Re-point cur->task at the new task (mm already attached above).
     *   - Set fs_base on the current thread for TLS.
     *   - Free kernel-side parsing allocations (we won't get to free
     *     them after the IRETQ).
     *   - Call fut_user_trampoline directly — it does CR3 swap and
     *     IRETQs to user mode. Never returns.
     *
     * fut_exec_elf does NOT return on success in this mode. The caller
     * (kernel_main) won't see "Init process launched successfully". */

    fut_thread_t *cur = fut_thread_current();
    if (!cur) {
        fut_free(entry);
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        EXEC_CLEANUP_KARGS();
        return -ESRCH;
    }
    cur->task = task;
    cur->fs_base = USER_TLS_BASE;

    /* Free kernel-side allocations now — once IRETQ happens we can't. */
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

    fut_vfs_check_root_canary("fut_exec_elf:before_trampoline");

    fut_printf("[BISECT] direct-trampoline: entry=0x%llx stack=0x%llx argc=%u argv=0x%llx\n",
               (unsigned long long)entry->entry,
               (unsigned long long)entry->stack,
               (unsigned)entry->argc,
               (unsigned long long)entry->argv_ptr);
    fut_printf("[BISECT] cur_thread=%p cur->task=%p mm=%p fs_base=0x%llx\n",
               (void *)cur, (void *)cur->task,
               (void *)(cur->task ? cur->task->mm : NULL),
               (unsigned long long)cur->fs_base);
    fut_printf("[BISECT] calling fut_user_trampoline\n");

    fut_user_trampoline(entry);

    /* unreachable */
    extern void fut_platform_panic(const char *);
    fut_platform_panic("fut_user_trampoline returned in direct-trampoline path");
    while (1) { __asm__ volatile("hlt"); }
}

#elif defined(__aarch64__)

/* ARM64 ELF64 loader implementation */

#include <kernel/exec.h>
#include <config/futura_config.h>
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

/* Logging macros disabled for clean boot */
#undef ELF_LOG
/* ELF_LOG: gated diagnostic output for the exec path.
 *
 * Set CONFIG_DEBUG_EXEC=1 (e.g. via -DCONFIG_DEBUG_EXEC=1 in the
 * Makefile) to route every ELF_LOG call through fut_printf. Off by
 * default — exec is on the critical boot-time path and the log is
 * very noisy.
 *
 * Was unconditionally on while we bisected the bare-metal init-launch
 * hang in iter-25..iter-35. Now that the symptom is narrowed to the
 * post-STI scheduler context-switch path, the trace points are quiet
 * by default but trivial to flip back on. */
#ifndef CONFIG_DEBUG_EXEC
#define CONFIG_DEBUG_EXEC 0
#endif
#if CONFIG_DEBUG_EXEC
#define ELF_LOG(...) fut_printf(__VA_ARGS__)
#else
#define ELF_LOG(...) do {} while(0)
#endif
#define stack_printf(...) do {} while(0)

/* ELF metadata for auxiliary vector (also defined in x86_64 section) */
static uint64_t g_exec_entry = 0;
static uint64_t g_exec_phdr = 0;
static uint16_t g_exec_phent = 0;
static uint16_t g_exec_phnum = 0;
static uint64_t g_exec_interp_base = 0;
static uint64_t g_exec_interp_entry = 0;

/* FD_CLOEXEC - close-on-exec flag for file descriptors. */
#ifndef FD_CLOEXEC
#define FD_CLOEXEC      1
#endif

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
    /* Copy data to user memory by walking the page table to find the physical
     * address, then writing via the kernel virtual address. This avoids TTBR0
     * switching which is unreliable during exec context setup. */
    fut_vmem_context_t *vmem = fut_mm_context(mm);
    const uint8_t *src_bytes = (const uint8_t *)src;
    size_t remaining = len;
    uint64_t vaddr = dest;

    while (remaining > 0) {
        uint64_t page_offset = vaddr & 0xFFF;
        size_t chunk_size = 0x1000 - page_offset;
        if (chunk_size > remaining) chunk_size = remaining;

        uint64_t pte = 0;
        extern int pmap_probe_pte(fut_vmem_context_t *, uint64_t, uint64_t *);
        if (pmap_probe_pte(vmem, vaddr, &pte) != 0) {
            return -EFAULT;
        }

        uint64_t phys = (pte & 0xFFFFFFFFF000ULL) + page_offset;
        void *kern_addr = (void *)pmap_phys_to_virt(phys);
        memcpy(kern_addr, src_bytes, chunk_size);

        src_bytes += chunk_size;
        vaddr += chunk_size;
        remaining -= chunk_size;
    }
    return 0;
}

/* Map a single LOAD segment from file */
static int map_segment(fut_mm_t *mm, int fd, const elf64_phdr_t *phdr) {

    if (phdr->p_memsz == 0) return 0;
    if (phdr->p_vaddr == 0) return -EINVAL;

    /* Overflow check: p_vaddr + p_memsz must not wrap around 64-bit address space */
    if (phdr->p_memsz > UINT64_MAX - phdr->p_vaddr) {
        return -EINVAL;
    }

    /* p_filesz must not exceed p_memsz (file content cannot exceed segment size) */
    if (phdr->p_filesz > phdr->p_memsz) {
        return -EINVAL;
    }

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

    /* Allocate pages, map them, and record kernel VAs for direct copy */
    void **pages = fut_malloc(pages_needed * sizeof(void *));
    if (!pages) return -ENOMEM;

    for (size_t i = 0; i < pages_needed; i++) {
        uint64_t page_addr = addr + (i * PAGE_SIZE);

        /* Check if this page is already mapped (happens when segments overlap) */
        uint64_t existing_pte = 0;
        if (pmap_probe_pte(vmem, page_addr, &existing_pte) == 0) {
            if (prot & PROT_WRITE) {
                phys_addr_t existing_phys = existing_pte & 0xFFFFFFFFF000ULL;
                pmap_map_user(vmem, page_addr, existing_phys, PAGE_SIZE, prot);
            }
            /* Use the existing page's kernel VA for copying */
            phys_addr_t ep = existing_pte & 0xFFFFFFFFF000ULL;
            pages[i] = pmap_phys_to_virt(ep);
            continue;
        }

        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_free(pages);
            return -ENOMEM;
        }
        memset(page, 0, PAGE_SIZE);

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        if (pmap_map_user(vmem, page_addr, phys, PAGE_SIZE, prot) != 0) {
            fut_pmm_free_page(page);
            fut_free(pages);
            return -EFAULT;
        }
        pages[i] = page;
    }

    /* Read file data into a kernel buffer */
    int64_t seek_pos = fut_vfs_lseek(fd, (int64_t)phdr->p_offset, SEEK_SET);
    if (seek_pos < 0) { fut_free(pages); return (int)seek_pos; }

    uint8_t *buf = fut_malloc(phdr->p_filesz ? phdr->p_filesz : 1);
    if (!buf) { fut_free(pages); return -ENOMEM; }

    int rc = 0;
    if (phdr->p_filesz > 0) {
        rc = read_exact(fd, buf, phdr->p_filesz);
        if (rc != 0) { fut_free(buf); fut_free(pages); return rc; }
    }

    /* Copy data DIRECTLY to the allocated pages using kernel VAs.
     * This avoids exec_copy_to_user's PTE walk which had issues with
     * page table coherence on ARM64. */
    {
        size_t remaining = (size_t)phdr->p_filesz;
        size_t page_index = 0;
        size_t page_offset = (size_t)(phdr->p_vaddr - addr);  /* offset within first page */
        uint8_t *src = buf;

        while (remaining > 0 && page_index < pages_needed) {
            size_t chunk = PAGE_SIZE - page_offset;
            if (chunk > remaining) chunk = remaining;
            memcpy((uint8_t *)pages[page_index] + page_offset, src, chunk);
            src += chunk;
            remaining -= chunk;
            page_index++;
            page_offset = 0;
        }
    }

    fut_free(buf);

    /* D-cache clean + I-cache invalidation for executable segments */
    if (phdr->p_flags & PF_X) {
        for (size_t i = 0; i < pages_needed; i++) {
            for (uintptr_t off = 0; off < PAGE_SIZE; off += 64) {
                uintptr_t a = (uintptr_t)pages[i] + off;
                __asm__ volatile("dc cvau, %0" :: "r"(a) : "memory");
            }
        }
        __asm__ volatile("dsb ish" ::: "memory");
        __asm__ volatile("ic iallu" ::: "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        __asm__ volatile("isb" ::: "memory");
    }

    fut_free(pages);
    __asm__ volatile("dmb sy" ::: "memory");
    /* (buf was already freed above at the start of the cache-flush block;
     * the second fut_free(buf) here was a refactor leftover that was the
     * source of the recurring per-exec '[SLAB-FREE] Double-free detected
     * (cache_size=...) caller=map_segment+0x...' warnings on ARM64.) */
    return 0;
}

/* Default base address for loading the ELF interpreter on ARM64 */
#define INTERP_LOAD_BASE  0x7f0000000ULL

/* Load ELF interpreter — ARM64 version (mirrors x86_64 implementation) */
static int load_elf_interpreter(fut_mm_t *mm, const char *interp_path) {
    extern int fut_vfs_open(const char *, int, int);
    extern long fut_vfs_read(int, void *, size_t);
    extern long fut_vfs_lseek(int, long, int);
    extern int fut_vfs_close(int);

    g_exec_interp_base = 0;
    g_exec_interp_entry = 0;

    int ifd = fut_vfs_open(interp_path, 0, 0);
    if (ifd < 0) return 0;  /* Not fatal */

    elf64_ehdr_t ihdr;
    long nr = fut_vfs_read(ifd, &ihdr, sizeof(ihdr));
    if (nr < (long)sizeof(ihdr)) { fut_vfs_close(ifd); return 0; }

    uint32_t magic = 0;
    __builtin_memcpy(&magic, ihdr.e_ident, 4);
    if (magic != 0x464C457FU || ihdr.e_ident[4] != 2 /* ELFCLASS64 */) {
        fut_vfs_close(ifd); return 0;
    }
    if (ihdr.e_phnum == 0 || ihdr.e_phnum > 64) { fut_vfs_close(ifd); return 0; }

    size_t phsz = (size_t)ihdr.e_phnum * ihdr.e_phentsize;
    elf64_phdr_t *iphdrs = fut_malloc(phsz);
    if (!iphdrs) { fut_vfs_close(ifd); return -ENOMEM; }

    fut_vfs_lseek(ifd, (long)ihdr.e_phoff, 0);
    nr = fut_vfs_read(ifd, iphdrs, phsz);
    if (nr < (long)phsz) { fut_free(iphdrs); fut_vfs_close(ifd); return 0; }

    uint64_t interp_bias = INTERP_LOAD_BASE;
    uint64_t lowest_vaddr = UINT64_MAX;
    for (uint16_t i = 0; i < ihdr.e_phnum; i++)
        if (iphdrs[i].p_type == PT_LOAD && iphdrs[i].p_vaddr < lowest_vaddr)
            lowest_vaddr = iphdrs[i].p_vaddr;

    if (lowest_vaddr != UINT64_MAX && ihdr.e_type == 3 /* ET_DYN */)
        interp_bias = INTERP_LOAD_BASE - (lowest_vaddr & ~(PAGE_SIZE - 1ULL));
    else if (ihdr.e_type == 2 /* ET_EXEC */)
        interp_bias = 0;

    for (uint16_t i = 0; i < ihdr.e_phnum; i++) {
        if (iphdrs[i].p_type != PT_LOAD) continue;
        iphdrs[i].p_vaddr += interp_bias;
        int rc = map_segment(mm, ifd, &iphdrs[i]);
        if (rc != 0) { fut_free(iphdrs); fut_vfs_close(ifd); return rc; }
    }

    g_exec_interp_base = interp_bias + (lowest_vaddr != UINT64_MAX ? lowest_vaddr : 0);
    g_exec_interp_entry = ihdr.e_entry + interp_bias;

    fut_free(iphdrs);
    fut_vfs_close(ifd);
    return 0;
}

/* Stage stack pages for user mode */
static int stage_stack_pages(fut_mm_t *mm, uint64_t *out_stack_top) {
    if (!out_stack_top) return -EINVAL;

    extern void fut_serial_puts(const char *);
#ifdef DEBUG_ELF
    fut_serial_puts("[STACK] stage_stack_pages() called\n");
#endif

    /* Enforce RLIMIT_STACK: use the task's soft stack limit to determine
     * stack size, capped at USER_STACK_PAGES * PAGE_SIZE.  A minimum of
     * 4 pages is always allocated so the process can start. */
    size_t stack_pages = USER_STACK_PAGES;
    fut_task_t *stask = fut_task_current();
    if (stask) {
        uint64_t rlim_stack = stask->rlimits[3].rlim_cur; /* RLIMIT_STACK = 3 */
        if (rlim_stack != (uint64_t)-1 && rlim_stack > 0) {
            size_t rlim_pages = (size_t)((rlim_stack + PAGE_SIZE - 1) / PAGE_SIZE);
            if (rlim_pages < 4) rlim_pages = 4;  /* Minimum 4 pages */
            if (rlim_pages < stack_pages)
                stack_pages = rlim_pages;
        }
    }

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uint64_t stack_addr = USER_STACK_TOP - (stack_pages * PAGE_SIZE);

#ifdef DEBUG_ELF
    fut_printf("[STACK] Mapping stack: start=0x%llx end=0x%llx pages=%zu\n",
               (unsigned long long)stack_addr, (unsigned long long)USER_STACK_TOP, stack_pages);
#endif

    for (size_t i = 0; i < stack_pages; i++) {
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

        if (i == 0 || i == stack_pages - 1) {
#ifdef DEBUG_ELF
            fut_printf("[STACK] Mapped page %zu: vaddr=0x%llx phys=0x%llx\n",
                       i, (unsigned long long)page_addr, (unsigned long long)phys);
#endif
        }
    }

#ifdef DEBUG_ELF
    fut_printf("[STACK] Successfully staged %zu stack pages, stack_top=0x%llx\n",
               stack_pages, (unsigned long long)USER_STACK_TOP);
#endif

    /* Register the stack VMA so it appears as [stack] in /proc/pid/maps */
    fut_mm_add_vma(mm, stack_addr, USER_STACK_TOP, PROT_READ | PROT_WRITE, VMA_STACK | VMA_GROWSDOWN);

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

    /* Count environment variables if caller passed envc=0 */
    if (envp && envc == 0) {
        while (envp[envc]) envc++;
    }

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

    /* Save argv[0] address for AT_EXECFN */
    uint64_t execfn_addr = (argc > 0) ? (uint64_t)(uintptr_t)argv_ptrs[0] : 0;

    /* Align stack to 16-byte boundary for ARM64 ABI */
    sp &= ~0xFULL;

    /* Build stack layout (working backwards from high to low addresses):
     * [sp] = argc
     * [sp+8] = argv[0] ... argv[n-1]
     * [...] = NULL (argv terminator)
     * [...] = envp[0] ... envp[m-1]
     * [...] = NULL (envp terminator)
     * [...] = auxv entries (key, value pairs)
     * [...] = AT_NULL, 0 (auxv terminator)
     * [...] = strings...
     *
     * We push in reverse order (auxv first, then envp, then argv, then argc).
     */

    uint64_t zero = 0;

    /* Push ELF auxiliary vector (auxv).
     * musl and glibc read these to discover page size, UID, etc.
     * Pushed FIRST because it's at the highest address (after envp NULL). */
    #define AT_NULL   0
    #define AT_PHDR   3   /* Program headers address */
    #define AT_PHENT  4   /* Size of program header entry */
    #define AT_PHNUM  5   /* Number of program headers */
    #define AT_PAGESZ 6   /* System page size */
    #define AT_ENTRY  9   /* Program entry point */
    #define AT_UID    11  /* Real UID */
    #define AT_EUID   12  /* Effective UID */
    #define AT_GID    13  /* Real GID */
    #define AT_EGID   14  /* Effective GID */
    #define AT_SECURE 23  /* Secure mode (setuid) */
    #define AT_RANDOM 25  /* Address of 16 random bytes */
    #define AT_HWCAP  16  /* Machine-dependent hints */

    /* Push 16 random bytes for AT_RANDOM (stack canary seed) */
    uint8_t rand_bytes[16];
    {
        extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
        sys_getrandom(rand_bytes, 16, 0);
    }
    sp -= 16;
    uint64_t rand_addr = sp;
    exec_copy_to_user(mm, sp, rand_bytes, 16);

    /* Push AT_PLATFORM string */
#ifdef __aarch64__
    static const char arm64_platform[] = "aarch64";
#else
    static const char arm64_platform[] = "x86_64";
#endif
    sp -= sizeof(arm64_platform);
    uint64_t arm64_platform_addr = sp;
    exec_copy_to_user(mm, sp, arm64_platform, sizeof(arm64_platform));

    /* AT_HWCAP for ARM64: HWCAP_FP | HWCAP_ASIMD (baseline) */
    uint64_t arm64_hwcap = 0x3;

    struct { uint64_t key; uint64_t val; } auxv_entries[] = {
        { AT_PAGESZ, PAGE_SIZE },
        { AT_ENTRY,  g_exec_entry },
        { AT_PHDR,   g_exec_phdr },
        { AT_PHENT,  g_exec_phent },
        { AT_PHNUM,  g_exec_phnum },
        { AT_RANDOM, rand_addr },
        { 17 /* AT_CLKTCK */, 100 },
        { 31 /* AT_EXECFN */, execfn_addr },
        { 15 /* AT_PLATFORM */, arm64_platform_addr },
        { AT_UID,    0 },  /* root */
        { AT_EUID,   0 },
        { AT_GID,    0 },
        { AT_EGID,   0 },
        { AT_SECURE, 0 },
        { AT_HWCAP,  arm64_hwcap },
        { 7 /* AT_BASE */,  g_exec_interp_base },  /* interpreter load address */
        { 8 /* AT_FLAGS */, 0 },
        { AT_NULL,   0 },  /* Terminator */
    };
    size_t auxv_count = sizeof(auxv_entries) / sizeof(auxv_entries[0]);

    /* Push auxv in reverse (AT_NULL goes to highest address) */
    for (size_t i = auxv_count; i-- > 0;) {
        sp -= sizeof(uint64_t);
        if (exec_copy_to_user(mm, sp, &auxv_entries[i].val, sizeof(uint64_t)) != 0) {
            if (envp_ptrs) fut_free(envp_ptrs);
            fut_free(argv_ptrs);
            return -EFAULT;
        }
        sp -= sizeof(uint64_t);
        if (exec_copy_to_user(mm, sp, &auxv_entries[i].key, sizeof(uint64_t)) != 0) {
            if (envp_ptrs) fut_free(envp_ptrs);
            fut_free(argv_ptrs);
            return -EFAULT;
        }
    }

    /* Save a copy of the auxv in the task struct for /proc/<pid>/auxv */
    {
        fut_task_t *auxv_task = fut_task_current();
        if (auxv_task) {
            size_t auxv_bytes = auxv_count * sizeof(auxv_entries[0]);
            if (auxv_task->auxv) fut_free(auxv_task->auxv);
            auxv_task->auxv = fut_malloc(auxv_bytes);
            if (auxv_task->auxv) {
                __builtin_memcpy(auxv_task->auxv, auxv_entries, auxv_bytes);
                auxv_task->auxv_size = auxv_bytes;
            } else {
                auxv_task->auxv_size = 0;
            }
        }
    }

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

    (void)arg; /* Suppress unused warning */

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

    /* Process starting at entry with sp */

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

    /* Overflow check: p_vaddr + p_memsz must not wrap around 64-bit address space */
    if (phdr->p_memsz > UINT64_MAX - phdr->p_vaddr) {
        return -EINVAL;
    }

    /* p_filesz must not exceed p_memsz (file content cannot exceed segment size) */
    if (phdr->p_filesz > phdr->p_memsz) {
        return -EINVAL;
    }

    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uintptr_t addr = PAGE_ALIGN_DOWN(phdr->p_vaddr);
    size_t pages_needed = (phdr->p_vaddr + phdr->p_memsz - addr + PAGE_SIZE - 1) / PAGE_SIZE;

    /* Verbose logging disabled for clean boot */

    /* Allocate and map pages */
    for (size_t i = 0; i < pages_needed; i++) {
        uint64_t page_addr = addr + (i * PAGE_SIZE);
        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_printf("[MAP-SEG] ERROR: failed to allocate page %zu\n", i);
            return -ENOMEM;
        }

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        /* fut_printf("[MAP-SEG] page %zu: 0x%llx -> 0x%llx\n", i, page_addr, phys); */

        int map_result = pmap_map_user(vmem, page_addr, phys, PAGE_SIZE, prot);
        if (map_result != 0) {
            fut_printf("[MAP-SEG] ERROR: pmap_map_user failed with %d\n", map_result);
            fut_pmm_free_page(page);
            return -EFAULT;
        }
    }

    /* Pages mapped successfully */

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

        /* Invalidate the ENTIRE instruction cache.  IC IVAU operates by VA,
         * but the user will access these pages at a different VA than the kernel.
         * On VIPT I-caches (Cortex-A53), different VAs index different cache
         * sets, so per-VA invalidation at the kernel VA misses the user's
         * stale entries.  IC IALLU flushes all I-cache entries, ensuring the
         * user process fetches the newly loaded instructions. */
        __asm__ volatile("ic iallu" ::: "memory");
        __asm__ volatile("dsb ish" ::: "memory");
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
        ehdr->e_machine != 0xB7 ||  /* EM_AARCH64 = 0xB7 */
        (ehdr->e_type != 2 && ehdr->e_type != 3)) {  /* ET_EXEC or ET_DYN */
        fut_serial_puts("[EXEC-MEM] ERROR: Invalid ELF or not ARM64\n");
        return -EINVAL;
    }

    /* Reject unreasonable e_phnum to prevent excessive allocation */
    if (ehdr->e_phnum > 256) {
        fut_serial_puts("[EXEC-MEM] ERROR: Too many program headers\n");
        return -EINVAL;
    }

    /* Verify program headers are within bounds (overflow-safe check) */
    size_t ph_size = (size_t)ehdr->e_phnum * sizeof(elf64_phdr_t);
    if (ehdr->e_phoff > elf_size || ph_size > elf_size - ehdr->e_phoff) {
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

        /* Verify segment is within bounds (overflow-safe check) */
        if (phdrs[i].p_offset > elf_size || phdrs[i].p_filesz > elf_size - phdrs[i].p_offset) {
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

    /* Record full argv for /proc/self/cmdline (null-separated Linux format) */
    {
        char *dst = task->proc_cmdline;
        size_t cap = sizeof(task->proc_cmdline);
        size_t pos = 0;
        if (argv) {
            for (size_t i = 0; i < argc && pos < cap - 1; i++) {
                const char *arg = argv[i];
                while (*arg && pos < cap - 1)
                    dst[pos++] = *arg++;
                dst[pos++] = '\0';
            }
        }
        task->proc_cmdline_len = (uint16_t)(pos < cap ? pos : cap);
    }

    /* Record full envp for /proc/self/environ (null-separated Linux format) */
    {
        char *dst = task->proc_environ;
        size_t cap = sizeof(task->proc_environ);
        size_t pos = 0;
        if (envp) {
            for (size_t i = 0; i < envc && pos < cap - 1; i++) {
                const char *env = envp[i];
                while (*env && pos < cap - 1)
                    dst[pos++] = *env++;
                dst[pos++] = '\0';
            }
        }
        task->proc_environ_len = (uint16_t)(pos < cap ? pos : cap);
    }

    /* Set ELF metadata for auxv */
    g_exec_entry = ehdr->e_entry;
    g_exec_phent = ehdr->e_phentsize;
    g_exec_phnum = ehdr->e_phnum;
    g_exec_phdr = 0;

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
#endif

    if (!path) return -EINVAL;

    int fd = fut_vfs_open(path, O_RDONLY, 0);
#ifdef DEBUG_ELF
#endif
    if (fd < 0) return fd;

    elf64_ehdr_t ehdr;
#ifdef DEBUG_ELF
#endif
    int rc = read_exact(fd, &ehdr, sizeof(ehdr));
#ifdef DEBUG_ELF
#endif
    if (rc != 0) {
        fut_vfs_close(fd);
        return rc;
    }

#ifdef DEBUG_ELF
#endif
    /* Verify ELF header */
    if (*(uint32_t *)ehdr.e_ident != ELF_MAGIC ||
        ehdr.e_ident[4] != ELF_CLASS_64 ||
        ehdr.e_ident[5] != ELF_DATA_LE ||
        ehdr.e_machine != 0xB7 ||  /* EM_AARCH64 = 0xB7 */
        (ehdr.e_type != 2 && ehdr.e_type != 3)) {  /* ET_EXEC or ET_DYN */
#ifdef DEBUG_ELF
#endif
        fut_vfs_close(fd);
        return -EINVAL;
    }

#ifdef DEBUG_ELF
#endif

    /* Reject unreasonable e_phnum to prevent excessive allocation */
    if (ehdr.e_phnum > 256) {
#ifdef DEBUG_ELF
#endif
        fut_vfs_close(fd);
        return -EINVAL;
    }

    size_t ph_size = (size_t)ehdr.e_phnum * sizeof(elf64_phdr_t);
#ifdef DEBUG_ELF
#endif
    elf64_phdr_t *phdrs = fut_malloc(ph_size);
#ifdef DEBUG_ELF
#endif
    if (!phdrs) {
        fut_vfs_close(fd);
        return -ENOMEM;
    }

#ifdef DEBUG_ELF
#endif
    int64_t seek_rc = fut_vfs_lseek(fd, (int64_t)ehdr.e_phoff, SEEK_SET);
#ifdef DEBUG_ELF
#endif
    if (seek_rc < 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return (int)seek_rc;
    }

#ifdef DEBUG_ELF
#endif
    rc = read_exact(fd, phdrs, ph_size);
#ifdef DEBUG_ELF
#endif
    if (rc != 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    /* Create task and memory manager */
#ifdef DEBUG_ELF
#endif
    fut_task_t *task = fut_task_create();
#ifdef DEBUG_ELF
#endif
    if (!task) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    /* Set task->comm from the binary filename (basename of path).
     * This shows in /proc/<pid>/status Name: and /proc/<pid>/comm. */
    {
        const char *basename = path;
        for (const char *p = path; *p; p++) {
            if (*p == '/') basename = p + 1;
        }
        size_t clen = 0;
        while (basename[clen] && clen < sizeof(task->comm) - 1) clen++;
        for (size_t i = 0; i < clen; i++) task->comm[i] = basename[i];
        task->comm[clen] = '\0';
    }

    /* Record full argv for /proc/self/cmdline (null-separated Linux format) */
    {
        char *dst = task->proc_cmdline;
        size_t cap = sizeof(task->proc_cmdline);
        size_t pos = 0;
        if (argv) {
            for (int i = 0; argv[i] && pos < cap - 1; i++) {
                const char *arg = argv[i];
                while (*arg && pos < cap - 1)
                    dst[pos++] = *arg++;
                dst[pos++] = '\0';
            }
        }
        task->proc_cmdline_len = (uint16_t)(pos < cap ? pos : cap);
    }

    /* Record full envp for /proc/self/environ (null-separated Linux format) */
    {
        char *dst = task->proc_environ;
        size_t cap = sizeof(task->proc_environ);
        size_t pos = 0;
        if (envp) {
            for (int i = 0; envp[i] && pos < cap - 1; i++) {
                const char *env = envp[i];
                while (*env && pos < cap - 1)
                    dst[pos++] = *env++;
                dst[pos++] = '\0';
            }
        }
        task->proc_environ_len = (uint16_t)(pos < cap ? pos : cap);
    }

#ifdef DEBUG_ELF
#endif
    fut_mm_t *mm = fut_mm_create();
#ifdef DEBUG_ELF
#endif
    if (!mm) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

#ifdef DEBUG_ELF
#endif
    fut_task_set_mm(task, mm);
#ifdef DEBUG_ELF
#endif

#ifdef __aarch64__
    /* ARM64: For the spawner thread running exec, we need to update ITS context
     * with the new task's TTBR0. Normally fut_task_set_mm only updates if
     * current->task == task, but exec creates a NEW task so we must handle manually. */
    fut_thread_t *cur_thread = fut_thread_current();
    if (cur_thread) {
        cur_thread->context.ttbr0_el1 = mm->ctx.ttbr0_el1;
#ifdef DEBUG_ELF
#endif

        /* Load TTBR0 now so map_segment can access user space */
        __asm__ volatile("msr ttbr0_el1, %0" :: "r"(mm->ctx.ttbr0_el1));
        __asm__ volatile("isb" ::: "memory");                    /* Ensure TTBR0 write completes */
        __asm__ volatile("tlbi vmalle1is" ::: "memory");         /* Invalidate all EL0/EL1 TLB entries */
        __asm__ volatile("dsb ish" ::: "memory");                /* Data synchronization barrier */
        __asm__ volatile("isb" ::: "memory");                    /* Instruction synchronization barrier */
#ifdef DEBUG_ELF
#endif
    }
#endif

    /* PIE (ET_DYN) load bias for position-independent executables */
    uint64_t load_bias = 0;
    if (ehdr.e_type == 3 /* ET_DYN */) {
        load_bias = 0x400000ULL;
        for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
            if (phdrs[i].p_type == 1 /* PT_LOAD */ || phdrs[i].p_type == 6 /* PT_PHDR */)
                phdrs[i].p_vaddr += load_bias;
        }
    }

    /* PT_GNU_STACK / PT_GNU_RELRO parsing.
     * NOTE: PT_GNU_RELRO p_vaddr is NOT biased by the ET_DYN loop above
     * (which only adjusts PT_LOAD and PT_PHDR), so add load_bias manually. */
    bool stack_exec = false;
    uint64_t relro_start = 0, relro_end = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == 0x6474e551 /* PT_GNU_STACK */)
            stack_exec = (phdrs[i].p_flags & 1 /* PF_X */) != 0;
        if (phdrs[i].p_type == 0x6474e552 /* PT_GNU_RELRO */) {
            relro_start = phdrs[i].p_vaddr + load_bias;  /* apply bias for ET_DYN */
            relro_end = relro_start + phdrs[i].p_memsz;
        }
    }
    (void)stack_exec; /* ARM64 stack setup is in a different function */

    /* Reset interpreter state */
    g_exec_interp_base = 0;
    g_exec_interp_entry = 0;

    /* PT_INTERP: dynamic linker path — load interpreter if present */
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == 3 /* PT_INTERP */ && phdrs[i].p_filesz > 0 &&
            phdrs[i].p_filesz < 256) {
            char interp[256] = {0};
            extern long fut_vfs_lseek(int fd, long offset, int whence);
            off_t saved = fut_vfs_lseek(fd, 0, 1);
            fut_vfs_lseek(fd, (long)phdrs[i].p_offset, 0);
            long nr = fut_vfs_read(fd, interp, (size_t)phdrs[i].p_filesz);
            if (nr > 0) interp[nr < 255 ? nr : 255] = '\0';
            /* Strip trailing whitespace */
            for (int k = (int)nr - 1; k >= 0; k--) {
                if (interp[k] == '\n' || interp[k] == '\r' ||
                    interp[k] == ' ' || interp[k] == '\0')
                    interp[k] = '\0';
                else break;
            }
            fut_vfs_lseek(fd, saved, 0);
            if (interp[0])
                load_elf_interpreter(mm, interp);
            break;
        }
    }

    /* Resolve the file vnode for the ELF binary so PT_LOAD VMAs can be
     * recorded as file-backed (shown with pathname in /proc/<pid>/maps). */
    struct fut_vnode *elf_vnode_arm = NULL;
    {
        struct fut_file *elf_file = fut_vfs_get_file(fd);
        if (elf_file) elf_vnode_arm = elf_file->vnode;
    }

    /* Map LOAD segments */
    uintptr_t heap_base_candidate = 0;
#ifdef DEBUG_ELF
#endif
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
#ifdef DEBUG_ELF
#endif
            continue;
        }

#ifdef DEBUG_ELF
#else
        /* Always log segment mapping for ARM64 ELF debugging */
#endif
        rc = map_segment(mm, fd, &phdrs[i]);
#ifdef DEBUG_ELF
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

        /* Create a VMA for this segment so /proc/<pid>/maps shows it
         * with the correct permissions, file offset, and pathname. */
        {
            int vprot = 0;
            if (phdrs[i].p_flags & PF_R) vprot |= PROT_READ;
            if (phdrs[i].p_flags & PF_W) vprot |= PROT_WRITE;
            if (phdrs[i].p_flags & PF_X) vprot |= PROT_EXEC;
            uint64_t vma_start = phdrs[i].p_vaddr & ~(PAGE_SIZE - 1);
            uint64_t vma_end = (seg_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            uint64_t foff = phdrs[i].p_offset & ~(PAGE_SIZE - 1);
            fut_mm_add_vma_file(mm, vma_start, vma_end, vprot, 0,
                                elf_vnode_arm, foff);
        }
    }

    /* PT_GNU_RELRO: mprotect the relocation-read-only region to PROT_READ.
     * This makes .got, .init_array, etc. read-only after loading, preventing
     * GOT overwrite attacks. Only applies if the region was loaded. */
    if (relro_start && relro_end > relro_start) {
        uintptr_t rs = relro_start & ~(PAGE_SIZE - 1ULL);
        uintptr_t re = (relro_end + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL);
        extern long sys_mprotect(void *addr, size_t len, int prot);
        (void)sys_mprotect((void *)rs, (size_t)(re - rs), PROT_READ);
        EXEC_DEBUG("[EXEC] PT_GNU_RELRO: mprotect 0x%llx-0x%llx PROT_READ\n",
                   (unsigned long long)rs, (unsigned long long)re);
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
    /* Set ELF metadata globals for auxv in build_user_stack.
     * For PIE (ET_DYN), phdrs already include load_bias. */
    g_exec_entry = ehdr.e_entry + load_bias;
    g_exec_phent = ehdr.e_phentsize;
    g_exec_phnum = ehdr.e_phnum;
    g_exec_phdr = 0;
    for (uint16_t pi = 0; pi < ehdr.e_phnum; pi++) {
        if (phdrs[pi].p_type == 6 /* PT_PHDR */) {
            g_exec_phdr = phdrs[pi].p_vaddr;  /* already biased */
            break;
        }
    }
    if (g_exec_phdr == 0 && ehdr.e_phnum > 0) {
        for (uint16_t pi = 0; pi < ehdr.e_phnum; pi++) {
            if (phdrs[pi].p_type == 1 /* PT_LOAD */) {
                g_exec_phdr = phdrs[pi].p_vaddr + ehdr.e_phoff - phdrs[pi].p_offset;
                break;
            }
        }
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

    /* If interpreter was loaded, start at its entry point */
    if (g_exec_interp_entry != 0) {
        entry->entry = g_exec_interp_entry;
    } else {
        entry->entry = ehdr.e_entry + load_bias;
    }
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

    /* Close the ELF binary fd BEFORE inheriting fds to the child.
     * Otherwise the child inherits the binary file as an open fd. */
    fut_vfs_close(fd);
    fd = -1;

    /* Inherit non-CLOEXEC fds from caller, fill missing stdio with /dev/console */
    {
        fut_thread_t *current = fut_thread_current();
        fut_task_t *caller_task = current ? current->task : NULL;

        if (caller_task && caller_task->fd_table && task->fd_table) {
            int max = caller_task->max_fds;
            if (max > (int)task->max_fds) max = (int)task->max_fds;
            for (int i = 0; i < max; i++) {
                struct fut_file *f = caller_task->fd_table[i];
                int cloexec = (caller_task->fd_flags && (caller_task->fd_flags[i] & FD_CLOEXEC));
                if (f && !cloexec) {
                    vfs_file_ref(f);
                    task->fd_table[i] = f;
                    if (task->fd_flags) task->fd_flags[i] = 0;
                }
            }
        }

        /* Close epoll instances marked EPOLL_CLOEXEC */
        if (caller_task) {
            extern void epoll_close_cloexec(uint64_t pid);
            epoll_close_cloexec(caller_task->pid);
        }

        fut_task_t *saved_task = current ? current->task : NULL;
        if (current) current->task = task;

        for (int stdio_fd = 0; stdio_fd < 3; stdio_fd++) {
            if (!task->fd_table || !task->fd_table[stdio_fd]) {
                int got = fut_vfs_open("/dev/console", O_RDWR, 0);
                if (got >= 0 && got != stdio_fd) {
                    fut_printf("[EXEC-ARM64] WARNING: stdio fd %d opened as %d\n",
                               stdio_fd, got);
                }
            }
        }

        if (current) current->task = saved_task;
    }

    /* Create thread with trampoline */
#ifdef DEBUG_ELF
    fut_printf("[EXEC-ARM64] About to create thread: trampoline=%p entry_struct=%p user_entry=0x%llx\n",
               (void*)fut_user_trampoline_arm64, (void*)entry, (unsigned long long)entry->entry);
#endif

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_user_trampoline_arm64,
                                             entry,
                                             CONFIG_KERNEL_STACK_SIZE,
                                             FUT_DEFAULT_PRIORITY);
    if (!thread) {
        fut_free(entry);
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    fut_free(phdrs);
    if (fd >= 0) fut_vfs_close(fd);

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
