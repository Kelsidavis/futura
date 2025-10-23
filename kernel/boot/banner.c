// SPDX-License-Identifier: MPL-2.0

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <kernel/boot_banner.h>
#include <kernel/fut_memory.h>
#include <generated/version.h>

#ifdef __x86_64__
#include <arch/x86_64/cpu.h>
#endif

extern void fut_printf(const char *fmt, ...);

#ifdef __x86_64__

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                         uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(subleaf));
}

static void get_cpu_brand(char brand[49]) {
    memset(brand, 0, 49);

    uint32_t max_ext = 0, ebx = 0, ecx = 0, edx = 0;
    cpuid(0x80000000u, 0, &max_ext, &ebx, &ecx, &edx);
    if (max_ext < 0x80000004u) {
        return;
    }

    char *p = brand;
    for (uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
        uint32_t a, b, c, d;
        cpuid(leaf, 0, &a, &b, &c, &d);
        memcpy(p, &a, sizeof(a)); p += sizeof(a);
        memcpy(p, &b, sizeof(b)); p += sizeof(b);
        memcpy(p, &c, sizeof(c)); p += sizeof(c);
        memcpy(p, &d, sizeof(d)); p += sizeof(d);
    }
    brand[48] = '\0';

    size_t len = 0;
    while (len < 48 && brand[len] != '\0') {
        ++len;
    }
    size_t idx = 0;
    while (idx < len && brand[idx] == ' ') {
        idx++;
    }
    if (idx > 0 && idx < len) {
        memmove(brand, brand + idx, len - idx + 1);
    } else if (idx == len) {
        brand[0] = '\0';
    }
}

#else  /* !__x86_64__ */

static void get_cpu_brand(char brand[49]) {
    /* For non-x86_64 architectures, we don't query CPU brand via CPUID */
    brand[0] = '\0';
}

#endif  /* __x86_64__ */

void fut_boot_banner(void) {
#ifdef __x86_64__
    const fut_cpu_features_t *feat = cpu_features_get();
#endif

    char cpu_brand[49] = {0};
    get_cpu_brand(cpu_brand);

    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages = fut_pmm_free_pages();
    uintptr_t base_phys = fut_pmm_base_phys();

    const uint64_t page_bytes = FUT_PAGE_SIZE;
    uint64_t total_mib = (total_pages * page_bytes) >> 20;
    uint64_t free_mib = (free_pages * page_bytes) >> 20;

    fut_printf("\n");
    fut_printf("-------------------------------\n");
    fut_printf("   ____     __                 \n");
    fut_printf("  / __/_ __/ /___ _________ _  \n");
    fut_printf(" / _// // / __/ // / __/ _ `/  \n");
    fut_printf("/_/  \\_,_/\\__\\_,_/_/  \\_,_/   \n");
    fut_printf("-------------------------------\n");
    fut_printf(" %s\n", FUT_VERSION_STR);
    fut_printf(" Build: %s  by %s@%s\n", FUT_BUILD_DATE, FUT_BUILD_USER, FUT_BUILD_HOST);

    fut_printf("\n[CPU] %s\n", (cpu_brand[0] != '\0') ? cpu_brand : "Unknown CPU");
#ifdef __x86_64__
    fut_printf("[CPU] NX=%u OSXSAVE=%u SSE=%u AVX=%u FSGSBASE=%u PGE=%u\n",
               feat->nx, feat->osxsave, feat->sse, feat->avx, feat->fsgsbase, feat->pge);
#endif

    fut_printf("\n[MEM] Physical: total=%llu MiB  free=%llu MiB  base=0x%llx\n",
               (unsigned long long)total_mib,
               (unsigned long long)free_mib,
               (unsigned long long)base_phys);
    fut_printf("[MEM] Map:\n");
    fut_mmap_dump();
    fut_printf("=======================================================\n\n");
}
