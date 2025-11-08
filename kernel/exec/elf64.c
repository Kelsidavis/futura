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

#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* External assembly function for IRETQ to userspace
 * NOTE: Don't use noreturn attribute - it may cause bad codegen */
extern void fut_do_user_iretq(uint64_t entry, uint64_t stack, uint64_t argc, uint64_t argv);

#define ELF_MAGIC       0x464C457FULL
#define ELF_CLASS_64    0x02
#define ELF_DATA_LE     0x01

#define PT_LOAD         0x00000001u

#define PF_X            0x00000001u
#define PF_W            0x00000002u
#define PF_R            0x00000004u

#define USER_CODE_SELECTOR  (0x18u | 0x3u)
#define USER_DATA_SELECTOR  (0x20u | 0x3u)

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

static int exec_copy_to_user(fut_mm_t *mm, uint64_t dest, const void *src, size_t len) {
    /* For ELF loading during exec, we map user pages into kernel address space,
     * so we can write directly without switching memory contexts.
     * Since pages are already kernel-accessible (allocated via fut_pmm_alloc_page()),
     * we perform a direct kernel-space copy instead of switching MM and risking
     * instruction encoding issues with inline assembly in privileged instructions. */

    /* Get the PTE to extract physical address */
    uint64_t pte = 0;
    if (pmap_probe_pte(mm_context(mm), dest, &pte) != 0) {
        return -EFAULT;
    }

    /* Extract physical address from PTE (bits 12-51) */
    phys_addr_t phys = pte & 0xFFFFFFFFF000ULL;

    /* Convert physical to kernel virtual address */
    uint8_t *kern_addr = (uint8_t *)pmap_phys_to_virt(phys);

    /* Simple kernel-space memcpy (no privilege escalation or memory context switches) */
    memcpy(kern_addr, src, len);
    return 0;
}

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

    extern void fut_printf(const char *, ...);
    fut_printf("[EXEC][MAP-SEGMENT] vaddr=0x%llx memsz=0x%llx filesz=0x%llx page_count=%llu\n",
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
    fut_printf("[EXEC][MAP-SEGMENT] phdr->p_flags=0x%x (R=%d W=%d X=%d) -> flags=0x%llx (NX=%d)\n",
               (unsigned)phdr->p_flags,
               (int)((phdr->p_flags & PF_R) != 0),
               (int)((phdr->p_flags & PF_W) != 0),
               (int)((phdr->p_flags & PF_X) != 0),
               (unsigned long long)flags,
               (int)((flags & PTE_NX) != 0));

    size_t pages_array_size = page_count * sizeof(uint8_t *);
    fut_printf("[EXEC][MAP-SEGMENT] Allocating pages array: %llu bytes\n",
               (unsigned long long)pages_array_size);
    uint8_t **pages = fut_malloc(pages_array_size);
    if (!pages) {
        fut_printf("[EXEC][MAP-SEGMENT] FAILED: pages array malloc returned NULL\n");
        return -ENOMEM;
    }
    fut_printf("[EXEC][MAP-SEGMENT] pages array allocated at %p\n", (void*)pages);

    for (size_t i = 0; i < page_count; ++i) {
        fut_printf("[EXEC][MAP-SEGMENT] Allocating physical page %llu/%llu\n",
                   (unsigned long long)i, (unsigned long long)page_count);
        uint8_t *page = fut_pmm_alloc_page();
        if (!page) {
            fut_printf("[EXEC][MAP-SEGMENT] FAILED: PMM alloc_page returned NULL at iteration %llu/%llu\n",
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
            fut_printf("[EXEC][MAP] vaddr=0x%llx pte=0x%llx flags=0x%llx NX=%d\n",
                       (unsigned long long)(seg_start + (uint64_t)i * PAGE_SIZE),
                       (unsigned long long)pte,
                       (unsigned long long)fut_pte_flags(pte),
                       (int)((pte >> 63) & 1));
        }
    }

    if (phdr->p_filesz > 0) {
        fut_printf("[EXEC][MAP-SEGMENT] Allocating file buffer: %llu bytes\n",
                   (unsigned long long)phdr->p_filesz);
        uint8_t *buffer = fut_malloc((size_t)phdr->p_filesz);
        if (!buffer) {
            fut_printf("[EXEC][MAP-SEGMENT] FAILED: file buffer malloc returned NULL\n");
            fut_free(pages);
            return -ENOMEM;
        }
        fut_printf("[EXEC][MAP-SEGMENT] file buffer allocated at %p\n", (void*)buffer);

        int64_t off = fut_vfs_lseek(fd, (int64_t)phdr->p_offset, SEEK_SET);
        if (off < 0) {
            fut_free(buffer);
            fut_free(pages);
            return (int)off;
        }

        int rc = read_exact(fd, buffer, (size_t)phdr->p_filesz);
        if (rc != 0) {
            fut_free(buffer);
            fut_free(pages);
            return rc;
        }

        size_t remaining = (size_t)phdr->p_filesz;
        size_t page_index = 0;
        size_t page_offset = (size_t)seg_offset;
        uint8_t *src = buffer;

        while (remaining > 0 && page_index < page_count) {
            size_t chunk = PAGE_SIZE - page_offset;
            if (chunk > remaining) {
                chunk = remaining;
            }
            memcpy(pages[page_index] + page_offset, src, chunk);
            src += chunk;
            remaining -= chunk;
            page_index++;
            page_offset = 0;
        }

        /* Ensure all writes are visible before we execute this code */
        __asm__ volatile("mfence" ::: "memory");

        fut_printf("[EXEC][MAP-SEGMENT] Copied %llu bytes to pages, memory barrier done\n",
                   (unsigned long long)phdr->p_filesz);

        fut_free(buffer);
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
    }

    /* Allocate string pointers for both argv and envp */
    uint8_t **string_ptrs = fut_malloc(sizeof(uint8_t *) * (argc + envc));
    if (!string_ptrs) {
        return -ENOMEM;
    }

    uint64_t sp = USER_STACK_TOP;

    /* Copy environment variable strings first (highest addresses) */
    for (size_t i = envc; i-- > 0;) {
        size_t len = kstrlen(envp[i]) + 1;
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
    extern void fut_printf(const char *, ...);
    fut_printf("[USER-TRAMPOLINE] Called with arg=%p\n", arg);

    if (!arg) {
        fut_printf("[USER-TRAMPOLINE] ERROR: NULL arg!\n");
        extern void fut_thread_exit(void);
        fut_thread_exit();
    }

    /* Extract values from the user entry structure BEFORE freeing it */
    /* CRITICAL: Extract ALL values BEFORE any printf! Printf can trigger CR3 switches! */
    struct fut_user_entry *info = (struct fut_user_entry *)arg;
    uint64_t entry = info->entry;
    uint64_t stack = info->stack;
    uint64_t argc = info->argc;
    uint64_t argv_ptr = info->argv_ptr;
    fut_task_t *task = info->task;

    /* Now safe to printf - values are in local variables */
    fut_printf("[EXTRACT] entry=0x%llx stack=0x%llx argc=%llu argv=0x%llx\n",
               entry, stack, argc, argv_ptr);

    /* Don't free the arg structure - we never return from IRETQ anyway
     * and freeing might corrupt something */

    /* Get the mm from the task (task already extracted above) */
    fut_mm_t *mm = task ? task->mm : NULL;

    if (!task || !mm) {
        extern void fut_printf(const char *, ...);
        fut_printf("[USER-TRAMPOLINE] FATAL: No task (%p) or mm (%p)\n", (void*)task, (void*)mm);
        extern void fut_thread_exit(void);
        fut_thread_exit();
    }

    /* Verify we're using the task's CR3, not the kernel CR3 */
    extern uint64_t fut_read_cr3(void);
    uint64_t current_cr3 = fut_read_cr3();
    uint64_t expected_cr3 = mm_context(mm)->cr3_value;

    if (current_cr3 != expected_cr3) {
        extern void fut_write_cr3(uint64_t);
        fut_write_cr3(expected_cr3);
    }

    /* NO DEBUG OUTPUT ALLOWED HERE - printf triggers CR3 switches that break IRETQ! */

    /* Optionally verify mappings without printf (for debugging with debugger):
     * uint64_t test_pte = 0;
     * pmap_probe_pte(mm_context(mm), stack, &test_pte);  // Check stack mapping
     * pmap_probe_pte(mm_context(mm), entry, &test_pte);  // Check entry mapping
     */

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
        fut_printf("[EXEC] stage_stack page[%u]=%p\n", (unsigned)i, (void *)page);

        int rc = pmap_map_user(mm_context(mm),
                               base + (uint64_t)i * PAGE_SIZE,
                               phys,
                               PAGE_SIZE,
                               PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX);
        if (rc != 0) {
            fut_pmm_free_page(page);
            for (size_t j = 0; j <= i; ++j) {
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

extern const uint8_t _binary_build_bin_user_fbtest_start[];
extern const uint8_t _binary_build_bin_user_fbtest_end[];
extern const uint8_t _binary_build_bin_user_shell_start[];
extern const uint8_t _binary_build_bin_user_shell_end[];
extern const uint8_t _binary_build_bin_user_winsrv_start[];
extern const uint8_t _binary_build_bin_user_winsrv_end[];
extern const uint8_t _binary_build_bin_user_winstub_start[];
extern const uint8_t _binary_build_bin_user_winstub_end[];
extern const uint8_t _binary_build_bin_user_init_stub_start[];
extern const uint8_t _binary_build_bin_user_init_stub_end[];
extern const uint8_t _binary_build_bin_user_second_start[];
extern const uint8_t _binary_build_bin_user_second_end[];
#if ENABLE_WAYLAND_DEMO
extern const uint8_t _binary_build_bin_user_futura_wayland_start[];
extern const uint8_t _binary_build_bin_user_futura_wayland_end[];
extern const uint8_t _binary_build_bin_user_wl_simple_start[];
extern const uint8_t _binary_build_bin_user_wl_simple_end[];
extern const uint8_t _binary_build_bin_user_wl_colorwheel_start[];
extern const uint8_t _binary_build_bin_user_wl_colorwheel_end[];
extern const uint8_t _binary_build_bin_user_futura_shell_start[];
extern const uint8_t _binary_build_bin_user_futura_shell_end[];
#endif

int fut_stage_fbtest_binary(void) {
    fut_printf("[STAGE] fut_stage_fbtest_binary start\n");

    fut_printf("[STAGE] calculating binary size\n");
    size_t size = (size_t)(_binary_build_bin_user_fbtest_end - _binary_build_bin_user_fbtest_start);
    fut_printf("[STAGE] binary size = %llu bytes\n", (unsigned long long)size);
    if (size == 0) {
        return -EINVAL;
    }

    fut_printf("[STAGE] calling fut_vfs_mkdir\n");
    (void)fut_vfs_mkdir("/bin", 0755);

    fut_printf("[STAGE] calling fut_vfs_open\n");
    int fd = fut_vfs_open("/bin/fbtest", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    fut_printf("[STAGE] fut_vfs_open returned fd=%d\n", fd);
    if (fd < 0) {
        return fd;
    }

    fut_printf("[STAGE] entering write loop, size=%llu\n", (unsigned long long)size);
    size_t offset = 0;
    while (offset < size) {
        fut_printf("[STAGE] loop iteration: offset=%llu size=%llu\n",
                   (unsigned long long)offset, (unsigned long long)size);
        size_t chunk = size - offset;
        fut_printf("[STAGE] calculated chunk=%llu\n", (unsigned long long)chunk);
        if (chunk > 4096) {
            chunk = 4096;
        }
        fut_printf("[STAGE] limited chunk=%llu\n", (unsigned long long)chunk);

        fut_printf("[STAGE] calling fut_vfs_write fd=%d chunk=%llu\n",
                   fd, (unsigned long long)chunk);
        ssize_t wr = fut_vfs_write(fd,
                                   _binary_build_bin_user_fbtest_start + offset,
                                   chunk);
        fut_printf("[STAGE] fut_vfs_write returned %lld\n", (long long)wr);
        if (wr < 0) {
            fut_vfs_close(fd);
            return (int)wr;
        }
        offset += (size_t)wr;
    }

    fut_printf("[STAGE] calling fut_vfs_close\n");
    fut_vfs_close(fd);
    fut_printf("[STAGE] fut_stage_fbtest_binary complete\n");
    return 0;
}

static int stage_blob(const uint8_t *start,
                      const uint8_t *end,
                      const char *path) {
    fut_printf("[stage_blob] enter path=%s\n", path);
    size_t size = (size_t)(end - start);
    fut_printf("[stage_blob] size calculated\n");
    if (!start || !end || size == 0) {
        fut_printf("[stage_blob] invalid params\n");
        return -EINVAL;
    }

    fut_printf("[stage_blob] calling fut_vfs_open\n");
    int fd = fut_vfs_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    fut_printf("[stage_blob] fut_vfs_open returned fd=%d\n", fd);
    if (fd < 0) {
        fut_printf("[stage_blob] open failed\n");
        return fd;
    }

    fut_printf("[stage_blob] entering write loop\n");
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > 4096) {
            chunk = 4096;
        }
        fut_printf("[stage_blob] calling fut_vfs_write offset=%llu chunk=%llu\n", (unsigned long long)offset, (unsigned long long)chunk);
        ssize_t wr = fut_vfs_write(fd, start + offset, chunk);
        fut_printf("[stage_blob] fut_vfs_write returned wr=%zd\n", wr);
        if (wr < 0) {
            fut_printf("[stage_blob] write error, closing fd\n");
            fut_vfs_close(fd);
            return (int)wr;
        }
        offset += (size_t)wr;
    }

    fut_printf("[stage_blob] all writes complete, closing fd=%d\n", fd);
    int close_ret = fut_vfs_close(fd);
    fut_printf("[stage_blob] fut_vfs_close returned %d\n", close_ret);
    fut_printf("[stage_blob] returning success\n");
    return 0;
}

/* Shell binary is staged as a file in initramfs, not embedded as a blob.
 * For now, provide a stub that returns success without actually staging.
 * The shell binary (futura-shell) requires Wayland dependencies that may not
 * be built. This allows the kernel to boot without shell support.
 */
int fut_stage_shell_binary(void) {
    /* Shell binary not available - return success to allow kernel to boot */
    return 0;
}

#if ENABLE_WINSRV_DEMO
int fut_stage_winsrv_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_user_winsrv_start,
                      _binary_build_bin_user_winsrv_end,
                      "/sbin/winsrv");
}

int fut_stage_winstub_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_user_winstub_start,
                      _binary_build_bin_user_winstub_end,
                      "/bin/winstub");
}
#else
int fut_stage_winsrv_binary(void) {
    return 0;
}

int fut_stage_winstub_binary(void) {
    return 0;
}
#endif

#ifdef __x86_64__
int fut_stage_init_stub_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_user_init_stub_start,
                      _binary_build_bin_user_init_stub_end,
                      "/sbin/init_stub");
}

int fut_stage_second_stub_binary(void) {
    (void)fut_vfs_mkdir("/sbin", 0755);
    return stage_blob(_binary_build_bin_user_second_start,
                      _binary_build_bin_user_second_end,
                      "/sbin/second");
}
#else /* !__x86_64__ */
int fut_stage_init_stub_binary(void) {
    return -1;
}

int fut_stage_second_stub_binary(void) {
    return -1;
}
#endif /* __x86_64__ */

#if ENABLE_WAYLAND_DEMO
int fut_stage_wayland_compositor_binary(void) {
    extern void fut_printf(const char *, ...);
    (void)fut_vfs_mkdir("/sbin", 0755);

    size_t wayland_size = (size_t)(_binary_build_bin_user_futura_wayland_end - _binary_build_bin_user_futura_wayland_start);
    fut_printf("[STAGE] Wayland binary: start=%p end=%p size=%llu\n",
               (void*)_binary_build_bin_user_futura_wayland_start,
               (void*)_binary_build_bin_user_futura_wayland_end,
               (unsigned long long)wayland_size);

    return stage_blob(_binary_build_bin_user_futura_wayland_start,
                      _binary_build_bin_user_futura_wayland_end,
                      "/sbin/futura-wayland");
}

int fut_stage_wayland_client_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_user_wl_simple_start,
                      _binary_build_bin_user_wl_simple_end,
                      "/bin/wl-simple");
}

int fut_stage_wayland_color_client_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_user_wl_colorwheel_start,
                      _binary_build_bin_user_wl_colorwheel_end,
                      "/bin/wl-colorwheel");
}
#else
int fut_stage_wayland_compositor_binary(void) {
    return -ENOSYS;
}

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

    int fd = fut_vfs_open(path, O_RDONLY, 0);
    if (fd < 0) {
        return fd;
    }

    fut_vfs_check_root_canary("fut_exec_elf:enter");

    elf64_ehdr_t ehdr;
    int rc = read_exact(fd, &ehdr, sizeof(ehdr));
    if (rc != 0) {
        fut_vfs_close(fd);
        return rc;
    }

    fut_printf("[EXEC] Read ELF header: magic=0x%08x class=%d data=%d\n",
               *(uint32_t *)ehdr.e_ident, ehdr.e_ident[4], ehdr.e_ident[5]);
    fut_printf("[EXEC] ELF header: type=%d machine=%d version=%d entry=0x%llx\n",
               ehdr.e_type, ehdr.e_machine, ehdr.e_version,
               (unsigned long long)ehdr.e_entry);
    fut_printf("[EXEC] Program headers: phoff=%llu phentsize=%d phnum=%d\n",
               (unsigned long long)ehdr.e_phoff, ehdr.e_phentsize, ehdr.e_phnum);

    if (*(uint32_t *)ehdr.e_ident != ELF_MAGIC) {
        fut_printf("[EXEC] FAIL: Bad ELF magic 0x%08x (expected 0x%08x)\n",
                   *(uint32_t *)ehdr.e_ident, ELF_MAGIC);
        fut_vfs_close(fd);
        return -EINVAL;
    }

    if (ehdr.e_ident[4] != ELF_CLASS_64) {
        fut_printf("[EXEC] FAIL: Bad ELF class %d (expected %d)\n",
                   ehdr.e_ident[4], ELF_CLASS_64);
        fut_vfs_close(fd);
        return -EINVAL;
    }

    if (ehdr.e_ident[5] != ELF_DATA_LE) {
        fut_printf("[EXEC] FAIL: Bad ELF data %d (expected %d)\n",
                   ehdr.e_ident[5], ELF_DATA_LE);
        fut_vfs_close(fd);
        return -EINVAL;
    }

    if (ehdr.e_phentsize != sizeof(elf64_phdr_t)) {
        fut_printf("[EXEC] FAIL: Bad phentsize %d (expected %zu)\n",
                   ehdr.e_phentsize, sizeof(elf64_phdr_t));
        fut_vfs_close(fd);
        return -EINVAL;
    }

    if (ehdr.e_phnum == 0) {
        fut_printf("[EXEC] FAIL: No program headers (phnum=0)\n");
        fut_vfs_close(fd);
        return -EINVAL;
    }

    size_t ph_size = (size_t)ehdr.e_phnum * sizeof(elf64_phdr_t);
    elf64_phdr_t *phdrs = fut_malloc(ph_size);
    if (!phdrs) {
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    int64_t seek_rc = fut_vfs_lseek(fd, (int64_t)ehdr.e_phoff, SEEK_SET);
    if (seek_rc < 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return (int)seek_rc;
    }

    rc = read_exact(fd, phdrs, ph_size);
    if (rc != 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    extern void fut_printf(const char *, ...);
    fut_printf("[EXEC] Creating task...\n");
    fut_task_t *task = fut_task_create();
    if (!task) {
        fut_printf("[EXEC] FAILED: fut_task_create returned NULL\n");
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }
    fut_printf("[EXEC] Task created at %p\n", (void*)task);

    fut_printf("[EXEC] Creating memory manager...\n");
    fut_mm_t *mm = fut_mm_create();
    if (!mm) {
        fut_printf("[EXEC] FAILED: fut_mm_create returned NULL\n");
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }
    fut_printf("[EXEC] MM created at %p\n", (void*)mm);

    fut_task_set_mm(task, mm);

    uintptr_t heap_base_candidate = 0;

    fut_printf("[EXEC] Mapping %u segments...\n", ehdr.e_phnum);
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
            fut_printf("[EXEC] Segment %u: not PT_LOAD (type=%u), skipping\n", i, phdrs[i].p_type);
            continue;
        }
        fut_printf("[EXEC] Segment %u: PT_LOAD, calling map_segment...\n", i);
        rc = map_segment(mm, fd, &phdrs[i]);
        if (rc != 0) {
            fut_printf("[EXEC] FAILED: map_segment returned %d for segment %u\n", rc, i);
            fut_task_destroy(task);
            fut_free(phdrs);
            fut_vfs_close(fd);
            return rc;
        }
        fut_printf("[EXEC] Segment %u: map_segment succeeded\n", i);
        uint64_t seg_end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (seg_end > heap_base_candidate) {
            heap_base_candidate = (uintptr_t)seg_end;
        }
    }

    uintptr_t default_heap = 0x00400000ULL;
    uintptr_t heap_base = heap_base_candidate ? PAGE_ALIGN_UP(heap_base_candidate) : default_heap;
    heap_base += PAGE_SIZE;
    fut_mm_set_heap_base(mm, heap_base, 0);

    uint64_t stack_top = 0;
    rc = stage_stack_pages(mm, &stack_top);
    if (rc != 0) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    fut_vfs_check_root_canary("fut_exec_elf:after_stage_stack");

    uint64_t user_rsp = 0;
    uint64_t user_argv = 0;
    uint64_t user_argc = 0;
    size_t argc = 0;
    if (argv) {
        while (argv[argc]) {
            argc++;
        }
    }
    rc = build_user_stack(mm, (const char *const *)argv, argc, (const char *const *)envp, 0, &user_rsp, &user_argv, &user_argc);
    if (rc != 0) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    struct fut_user_entry *entry = fut_malloc(sizeof(*entry));
    if (!entry) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    entry->entry = ehdr.e_entry;
    entry->stack = user_rsp;
    entry->argc = user_argc;
    entry->argv_ptr = user_argv;
    entry->task = task;

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_user_trampoline,
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
#include <platform/arm64/regs.h>
#include <platform/arm64/context.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/arm64/memory/paging.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* PROT flags for ARM64 */
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

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
    /* For ELF loading, map user pages and write directly */
    /* Handle page boundaries by copying one page at a time */
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
            extern void fut_printf(const char *, ...);
            fut_printf("[COPY-TO-USER] pmap_probe_pte FAILED for vaddr=0x%llx\n",
                      (unsigned long long)vaddr);
            return -EFAULT;
        }

        /* Extract physical address and add page offset */
        phys_addr_t phys = fut_pte_to_phys(pte) + page_offset;
        void *virt = (void *)pmap_phys_to_virt(phys);

        /* Debug: log probe results for first copy */
        if (vaddr == dest) {
            extern void fut_printf(const char *, ...);
            fut_printf("[COPY-TO-USER] First probe: vaddr=0x%llx page_off=0x%llx pte=0x%llx phys=0x%llx virt=%p\n",
                      (unsigned long long)vaddr, (unsigned long long)page_offset,
                      (unsigned long long)pte, (unsigned long long)phys, virt);
        }

        /* Copy chunk to this page */
        memcpy(virt, src_bytes, chunk_size);

        /* ARM64: Clean data cache and invalidate instruction cache for code pages
         * This is critical because ARM64 has separate instruction and data caches.
         * After writing instructions via data cache, we must:
         * 1. DC CVAU - Clean data cache to point of unification (write to memory)
         * 2. IC IVAU - Invalidate instruction cache (discard stale instructions)
         * 3. ISB - Instruction synchronization barrier (wait for completion)
         *
         * IMPORTANT: Must use the KERNEL virtual address where we wrote (virt),
         * not the user virtual address (vaddr), since we're in kernel mode!
         */
        uint8_t *kern_start = (uint8_t *)virt;
        uint8_t *kern_end = kern_start + chunk_size;
        for (uint8_t *addr = kern_start; addr < kern_end; addr += 64) {
            __asm__ volatile("dc cvau, %0" :: "r"(addr) : "memory");
        }
        __asm__ volatile("dsb ish" ::: "memory");  /* Ensure DC completes */

        for (uint8_t *addr = kern_start; addr < kern_end; addr += 64) {
            __asm__ volatile("ic ivau, %0" :: "r"(addr) : "memory");
        }
        __asm__ volatile("dsb ish" ::: "memory");  /* Ensure IC completes */
        __asm__ volatile("isb" ::: "memory");      /* Synchronize pipeline */

        /* Advance pointers */
        src_bytes += chunk_size;
        vaddr += chunk_size;
        remaining -= chunk_size;
    }

    return 0;
}

/* Map a single LOAD segment from file */
static int map_segment(fut_mm_t *mm, int fd, const elf64_phdr_t *phdr) {
    extern void fut_printf(const char *, ...);

    if (phdr->p_memsz == 0) return 0;
    if (phdr->p_vaddr == 0) return -EINVAL;

    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uintptr_t addr = PAGE_ALIGN_DOWN(phdr->p_vaddr);
    size_t pages_needed = (phdr->p_vaddr + phdr->p_memsz - addr + PAGE_SIZE - 1) / PAGE_SIZE;

    fut_printf("[MAP-SEG-ARM64] vaddr=0x%llx memsz=0x%llx filesz=0x%llx pages=%llu prot=%d\n",
               (unsigned long long)phdr->p_vaddr,
               (unsigned long long)phdr->p_memsz,
               (unsigned long long)phdr->p_filesz,
               (unsigned long long)pages_needed, prot);

    for (size_t i = 0; i < pages_needed; i++) {
        uint64_t page_addr = addr + (i * PAGE_SIZE);
        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_printf("[MAP-SEG-ARM64] ERROR: PMM alloc failed at page %llu/%llu\n",
                       (unsigned long long)i, (unsigned long long)pages_needed);
            return -ENOMEM;
        }

        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        fut_printf("[MAP-SEG-ARM64] Page %llu: vaddr=0x%llx phys=0x%llx prot=%d\n",
                   (unsigned long long)i, (unsigned long long)page_addr, (unsigned long long)phys, prot);

        if (pmap_map_user(vmem, page_addr, phys, PAGE_SIZE, prot) != 0) {
            fut_printf("[MAP-SEG-ARM64] ERROR: pmap_map_user failed for page %llu\n",
                       (unsigned long long)i);
            fut_pmm_free_page(page);
            return -EFAULT;
        }
    }

    fut_printf("[MAP-SEG-ARM64] Successfully mapped %llu pages\n", (unsigned long long)pages_needed);

    /* Read file data into mapped pages */
    fut_printf("[MAP-SEG-ARM64] Seeking to file offset 0x%llx\n", (unsigned long long)phdr->p_offset);
    int64_t seek_pos = fut_vfs_lseek(fd, (int64_t)phdr->p_offset, SEEK_SET);
    if (seek_pos < 0) {
        fut_printf("[MAP-SEG-ARM64] ERROR: lseek failed with %lld\n", (long long)seek_pos);
        return (int)seek_pos;
    }

    fut_printf("[MAP-SEG-ARM64] Allocating buffer for %llu bytes\n", (unsigned long long)phdr->p_filesz);
    uint8_t *buf = fut_malloc(phdr->p_filesz);
    if (!buf) {
        fut_printf("[MAP-SEG-ARM64] ERROR: malloc failed for buffer\n");
        return -ENOMEM;
    }

    fut_printf("[MAP-SEG-ARM64] Reading %llu bytes from file\n", (unsigned long long)phdr->p_filesz);
    int rc = read_exact(fd, buf, phdr->p_filesz);
    if (rc != 0) {
        fut_printf("[MAP-SEG-ARM64] ERROR: read_exact failed with %d\n", rc);
        fut_free(buf);
        return rc;
    }

    fut_printf("[MAP-SEG-ARM64] Copying data to user space at 0x%llx\n", (unsigned long long)phdr->p_vaddr);
    if (exec_copy_to_user(mm, phdr->p_vaddr, buf, phdr->p_filesz) != 0) {
        fut_printf("[MAP-SEG-ARM64] ERROR: exec_copy_to_user failed\n");
        fut_free(buf);
        return -EFAULT;
    }

    fut_printf("[MAP-SEG-ARM64] Segment load complete\n");
    __asm__ volatile("dmb sy" ::: "memory");
    fut_free(buf);
    return 0;
}

/* Stage stack pages for user mode */
static int stage_stack_pages(fut_mm_t *mm, uint64_t *out_stack_top) {
    if (!out_stack_top) return -EINVAL;

    extern void fut_serial_puts(const char *);
    fut_serial_puts("[STACK] stage_stack_pages() called\n");

    fut_vmem_context_t *vmem = fut_mm_context(mm);
    uint64_t stack_addr = USER_STACK_TOP - (USER_STACK_PAGES * PAGE_SIZE);

    fut_printf("[STACK] Mapping stack: start=0x%llx end=0x%llx pages=%d\n",
               (unsigned long long)stack_addr, (unsigned long long)USER_STACK_TOP, (int)USER_STACK_PAGES);

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
            fut_printf("[STACK] Mapped page %d: vaddr=0x%llx phys=0x%llx\n",
                       (int)i, (unsigned long long)page_addr, (unsigned long long)phys);
        }
    }

    fut_printf("[STACK] Successfully staged %d stack pages, stack_top=0x%llx\n",
               (int)USER_STACK_PAGES, (unsigned long long)USER_STACK_TOP);

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

    extern void fut_printf(const char *, ...);

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
    extern void fut_printf(const char *, ...);

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
    if (!path) return -EINVAL;

    int fd = fut_vfs_open(path, O_RDONLY, 0);
    if (fd < 0) return fd;

    elf64_ehdr_t ehdr;
    int rc = read_exact(fd, &ehdr, sizeof(ehdr));
    if (rc != 0) {
        fut_vfs_close(fd);
        return rc;
    }

    /* Verify ELF header */
    if (*(uint32_t *)ehdr.e_ident != ELF_MAGIC ||
        ehdr.e_ident[4] != ELF_CLASS_64 ||
        ehdr.e_ident[5] != ELF_DATA_LE ||
        ehdr.e_machine != 0xB7) {  /* EM_AARCH64 = 0xB7 */
        fut_vfs_close(fd);
        return -EINVAL;
    }

    size_t ph_size = (size_t)ehdr.e_phnum * sizeof(elf64_phdr_t);
    elf64_phdr_t *phdrs = fut_malloc(ph_size);
    if (!phdrs) {
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    int64_t seek_rc = fut_vfs_lseek(fd, (int64_t)ehdr.e_phoff, SEEK_SET);
    if (seek_rc < 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return (int)seek_rc;
    }

    rc = read_exact(fd, phdrs, ph_size);
    if (rc != 0) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return rc;
    }

    /* Create task and memory manager */
    fut_task_t *task = fut_task_create();
    if (!task) {
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    fut_mm_t *mm = fut_mm_create();
    if (!mm) {
        fut_task_destroy(task);
        fut_free(phdrs);
        fut_vfs_close(fd);
        return -ENOMEM;
    }

    fut_task_set_mm(task, mm);

    /* Map LOAD segments */
    uintptr_t heap_base_candidate = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) continue;

        rc = map_segment(mm, fd, &phdrs[i]);
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
    rc = build_user_stack(mm, (const char *const *)argv, argc, (const char *const *)envp, 0, &user_sp);
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
        extern void fut_printf(const char *, ...);
        fut_printf("[EXEC-ARM64] WARNING: Failed to open stdio (got %d/%d/%d)\n",
                   stdio_fd0, stdio_fd1, stdio_fd2);
    }

    /* Create thread with trampoline */
    extern void fut_printf(const char *, ...);
    fut_printf("[EXEC-ARM64] About to create thread: trampoline=%p entry_struct=%p user_entry=0x%llx\n",
               (void*)fut_user_trampoline_arm64, (void*)entry, (unsigned long long)entry->entry);

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
