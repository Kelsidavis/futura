// SPDX-License-Identifier: MPL-2.0
/*
 * fb_user_smoke.c - Simulated userspace framebuffer smoke test
 */

#include <stdint.h>
#include <stddef.h>

#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/fut_memory.h>
#include <kernel/fb_ioctl.h>
#include <kernel/errno.h>

#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>

#include <subsystems/posix_syscall.h>

extern void fut_printf(const char *fmt, ...);
extern uintptr_t g_user_lo;

static uintptr_t map_user_page(uintptr_t uaddr) {
    void *page = fut_pmm_alloc_page();
    if (!page) {
        return 0;
    }
    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    if (pmap_map(uaddr, phys, PAGE_SIZE, PTE_PRESENT | PTE_WRITABLE | PTE_USER) != 0) {
        return 0;
    }
    return uaddr;
}

#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_ioctl       16
#define SYS_mmap        9

#define O_RDWR          0x0002
#define PROT_WRITE      0x2
#define MAP_SHARED      0x1

void fut_fb_userspace_smoke(void) {
    static int already_run = 0;
    if (already_run) {
        return;
    }
    already_run = 1;

    uintptr_t user_base = g_user_lo + 0x2000;
    uintptr_t user_path = user_base;
    if (!map_user_page(user_path)) {
        fut_printf("[FB-USER] unable to map user_path page\n");
        return;
    }

    const char path_value[] = "/dev/fb0";
    for (size_t i = 0; i < sizeof(path_value); ++i) {
        ((char *)user_path)[i] = path_value[i];
    }

    uintptr_t user_fix = user_base + PAGE_SIZE;
    uintptr_t user_var = user_base + (2 * PAGE_SIZE);
    if (!map_user_page(user_fix) || !map_user_page(user_var)) {
        fut_printf("[FB-USER] unable to map info pages\n");
        return;
    }

    long fd = syscall_entry_c(SYS_open, user_path, O_RDWR, 0, 0, 0, 0);
    if (fd < 0) {
        fut_printf("[FB-USER] open failed: %ld\n", fd);
        return;
    }

    long ret = syscall_entry_c(SYS_ioctl, (uint64_t)fd, FBIOGET_FSCREENINFO, user_fix, 0, 0, 0);
    if (ret < 0) {
        fut_printf("[FB-USER] FBIOGET_FSCREENINFO failed: %ld\n", ret);
        return;
    }

    ret = syscall_entry_c(SYS_ioctl, (uint64_t)fd, FBIOGET_VSCREENINFO, user_var, 0, 0, 0);
    if (ret < 0) {
        fut_printf("[FB-USER] FBIOGET_VSCREENINFO failed: %ld\n", ret);
        return;
    }

    struct fb_fix_screeninfo fix_info;
    struct fb_var_screeninfo var_info;
    if (fut_copy_from_user(&fix_info, (const void *)user_fix, sizeof(fix_info)) != 0 ||
        fut_copy_from_user(&var_info, (const void *)user_var, sizeof(var_info)) != 0) {
        fut_printf("[FB-USER] failed to copy fb info\n");
        return;
    }

    uintptr_t user_fb = user_base + (3 * PAGE_SIZE);
    uintptr_t mapped_fb = (uintptr_t)syscall_entry_c(SYS_mmap, user_fb,
                                                    fix_info.smem_len,
                                                    PROT_WRITE,
                                                    MAP_SHARED,
                                                    (uint64_t)fd,
                                                    0);
    if ((long)mapped_fb < 0) {
        fut_printf("[FB-USER] mmap failed: %ld\n", (long)mapped_fb);
        return;
    }

    uint32_t stride = fix_info.line_length / 4;
    uint32_t *fb = (uint32_t *)mapped_fb;
    uint32_t width = var_info.xres;
    uint32_t height = var_info.yres;
    if (height > 64) {
        height = 64;
    }
    if (width > 128) {
        width = 128;
    }

    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            fb[y * stride + x] = (x << 16) | (y << 8) | 0x40u;
        }
    }

    syscall_entry_c(SYS_close, (uint64_t)fd, 0, 0, 0, 0, 0);
    fut_printf("[FB-USER] smoke completed (fd=%ld, stride=%u)\n", fd, stride);
}
