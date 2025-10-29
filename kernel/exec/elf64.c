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

#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>

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

#define USER_STACK_TOP      0x00007FFFFFFFE000ULL  /* Standard Linux user stack location */
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

int fut_stage_shell_binary(void) {
    (void)fut_vfs_mkdir("/bin", 0755);
    return stage_blob(_binary_build_bin_user_shell_start,
                      _binary_build_bin_user_shell_end,
                      "/bin/shell");
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

#else  /* !__x86_64__ */

/* ARM64 and other non-x86_64 architectures: ELF64 execution stubs */
/* TODO: Implement ARM64-specific ELF64 loader and user process bootstrap */

#include <kernel/errno.h>

int fut_exec_elf(const char *path, char *const argv[], char *const envp[]) {
    (void)path;
    (void)argv;
    return -ENOSYS;  /* Not implemented on this architecture */
}

#endif  /* __x86_64__ */
