// SPDX-License-Identifier: MPL-2.0
/*
 * echo_smoke.c - Minimal self-test for sys_echo/uaccess path
 */

#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>

#if defined(__x86_64__)
#include <arch/x86_64/pmap.h>
#endif

#include <string.h>

extern void fut_printf(const char *fmt, ...);

void fut_echo_selftest(void) {
    static int already_ran = 0;
    if (already_ran) {
        return;
    }
    already_ran = 1;

    void *page_in = fut_pmm_alloc_page();
    void *page_out = fut_pmm_alloc_page();
    if (!page_in || !page_out) {
        fut_printf("[ECHO] skipped (no pages available)\n");
        return;
    }

    phys_addr_t phys_in = pmap_virt_to_phys((uintptr_t)page_in);
    phys_addr_t phys_out = pmap_virt_to_phys((uintptr_t)page_out);

    uintptr_t user_in = g_user_lo;
    uintptr_t user_out = g_user_lo + PAGE_SIZE;

    int rc = pmap_map(user_in, phys_in, PAGE_SIZE, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    if (rc != 0) {
        fut_printf("[ECHO] map in failed: %d\n", rc);
        return;
    }

    rc = pmap_map(user_out, phys_out, PAGE_SIZE, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    if (rc != 0) {
        fut_printf("[ECHO] map out failed: %d\n", rc);
        return;
    }

    static const char input_pattern[] = "AbCdEfGh";
    size_t len = sizeof(input_pattern);
    memcpy((void *)user_in, input_pattern, len);
    memset((void *)user_out, 0, len);

    ssize_t ret = sys_echo((const char *)user_in, (char *)user_out, len);
    if (ret < 0) {
        fut_printf("[ECHO] sys_echo failed: %lld\n", (long long)ret);
        return;
    }

    char buffer[sizeof(input_pattern)];
    memcpy(buffer, (const void *)user_out, len);
    fut_printf("[ECHO] input=\"%s\" output=\"%s\" bytes=%lld\n",
               input_pattern, buffer, (long long)ret);
}
