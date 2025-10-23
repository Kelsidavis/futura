// SPDX-License-Identifier: MPL-2.0
/*
 * fb_smoke.c - Kernel-side framebuffer smoke test
 *
 * Exercises the /dev/fb0 character device by issuing the new FBIOGET_INFO
 * ioctl, mmapping the front buffer into the emulated user address space,
 * and drawing a simple gradient across the top rows. The goal is to prove
 * the plumbing without relying on a full userspace stack.
 */

#include <stdint.h>
#include <stddef.h>

#include <futura/fb_ioctl.h>
#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_vfs.h>
#include <subsystems/posix_syscall.h>

#if defined(__x86_64__)
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif

#include <tests/test_api.h>

extern void fut_printf(const char *fmt, ...);
extern uintptr_t g_user_lo;

#define O_RDWR          0x0002
#define PROT_WRITE      0x2
#define PROT_READ       0x1
#define MAP_SHARED      0x1

/* Syscall numbers (POSIX subset) */
#ifndef SYS_read
#define SYS_read        0
#endif
#ifndef SYS_write
#define SYS_write       1
#endif
#ifndef SYS_open
#define SYS_open        2
#endif
#ifndef SYS_close
#define SYS_close       3
#endif
#ifndef SYS_ioctl
#define SYS_ioctl       16
#endif
#ifndef SYS_mmap
#define SYS_mmap        9
#endif

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

void fut_fb_smoke(void) {
    static int already_run = 0;
    if (already_run) {
        return;
    }
    already_run = 1;

    uintptr_t user_base = g_user_lo + 0x4000;
    uintptr_t user_path = user_base;
    if (!map_user_page(user_path)) {
        fut_printf("[FB-TEST] skipped (failed to map path page)\n");
        return;
    }

    const char dev_path[] = "/dev/fb0";
    for (size_t i = 0; i < sizeof(dev_path); ++i) {
        ((char *)user_path)[i] = dev_path[i];
    }

    uintptr_t user_info = user_base + PAGE_SIZE;
    if (!map_user_page(user_info)) {
        fut_printf("[FB-TEST] skipped (failed to map info page)\n");
        return;
    }

    long fd = syscall_entry_c(SYS_open, user_path, O_RDWR, 0, 0, 0, 0);
    if (fd < 0) {
        fut_printf("[FB-TEST] open failed: %ld\n", fd);
        return;
    }

    long ret = syscall_entry_c(SYS_ioctl, (uint64_t)fd, FBIOGET_INFO, user_info, 0, 0, 0);
    if (ret < 0) {
        fut_printf("[FB-TEST] FBIOGET_INFO failed: %ld\n", ret);
        syscall_entry_c(SYS_close, (uint64_t)fd, 0, 0, 0, 0, 0);
        return;
    }

    struct fut_fb_info fb_info = {0};
    if (fut_copy_from_user(&fb_info, (const void *)user_info, sizeof(fb_info)) != 0) {
        fut_printf("[FB-TEST] copy fb info failed\n");
        syscall_entry_c(SYS_close, (uint64_t)fd, 0, 0, 0, 0, 0);
        return;
    }

    fut_printf("[FB-TEST] info %ux%ux%u pitch=%u flags=0x%x OK\n",
               fb_info.width, fb_info.height, fb_info.bpp,
               fb_info.pitch, fb_info.flags);

    uintptr_t user_fb = user_base + (2 * PAGE_SIZE);
    uintptr_t mapped_fb = (uintptr_t)syscall_entry_c(SYS_mmap,
                                                    user_fb,
                                                    (uint64_t)fb_info.pitch * fb_info.height,
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_SHARED,
                                                    (uint64_t)fd,
                                                    0);
    if ((long)mapped_fb < 0) {
        fut_printf("[FB-TEST] mmap failed: %ld\n", (long)mapped_fb);
        syscall_entry_c(SYS_close, (uint64_t)fd, 0, 0, 0, 0, 0);
        return;
    }

    uint32_t stride_px = fb_info.pitch / (fb_info.bpp / 8u);
    uint32_t height = fb_info.height;
    if (height > 64) {
        height = 64;
    }
    uint32_t width = fb_info.width;
    if (width > 256) {
        width = 256;
    }

    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            uint32_t r = (x * 255u) / (width ? width : 1u);
            uint32_t g = (y * 255u) / (height ? height : 1u);
            uint32_t b = 0x80u;
            uint32_t pixel = (r << 16) | (g << 8) | b;
            ((uint32_t *)mapped_fb)[y * stride_px + x] = pixel;
        }
    }

    fut_printf("[FB-TEST] draw OK\n");
    syscall_entry_c(SYS_close, (uint64_t)fd, 0, 0, 0, 0, 0);
    fut_test_pass();
}
