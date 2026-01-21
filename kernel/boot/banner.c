// SPDX-License-Identifier: MPL-2.0

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <kernel/boot_banner.h>
#include <kernel/fut_memory.h>
#include <generated/version.h>

#ifdef __x86_64__
#include <platform/x86_64/cpu.h>
#endif

extern void fut_printf(const char *fmt, ...);

/* CPU brand string buffer size (48 chars + null terminator) */
#define CPU_BRAND_BUFFER_SIZE 49
#define CPU_BRAND_MAX_LEN     (CPU_BRAND_BUFFER_SIZE - 1)  /* 48 chars */

#ifdef __x86_64__

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                         uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(subleaf));
}

static void get_cpu_brand(char brand[CPU_BRAND_BUFFER_SIZE]) {
    memset(brand, 0, CPU_BRAND_BUFFER_SIZE);

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
    brand[CPU_BRAND_MAX_LEN] = '\0';

    size_t len = 0;
    while (len < CPU_BRAND_MAX_LEN && brand[len] != '\0') {
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

#elif defined(__aarch64__)

/* ARM64 CPU detection via MIDR_EL1 register */
static void get_cpu_brand(char brand[CPU_BRAND_BUFFER_SIZE]) {
    uint64_t midr;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));

    uint32_t implementer = (midr >> 24) & 0xFF;
    uint32_t variant = (midr >> 20) & 0xF;
    uint32_t partnum = (midr >> 4) & 0xFFF;
    uint32_t revision = midr & 0xF;

    const char *cpu_name = "ARM CPU";

    /* ARM implementer codes */
    if (implementer == 0x41) {  /* ARM Limited */
        switch (partnum) {
            case 0xD03: cpu_name = "Cortex-A53"; break;
            case 0xD04: cpu_name = "Cortex-A35"; break;
            case 0xD05: cpu_name = "Cortex-A55"; break;
            case 0xD07: cpu_name = "Cortex-A57"; break;
            case 0xD08: cpu_name = "Cortex-A72"; break;
            case 0xD09: cpu_name = "Cortex-A73"; break;
            case 0xD0A: cpu_name = "Cortex-A75"; break;
            case 0xD0B: cpu_name = "Cortex-A76"; break;
            case 0xD0C: cpu_name = "Neoverse N1"; break;
            case 0xD0D: cpu_name = "Cortex-A77"; break;
            case 0xD0E: cpu_name = "Cortex-A76AE"; break;
            case 0xD40: cpu_name = "Neoverse V1"; break;
            case 0xD41: cpu_name = "Cortex-A78"; break;
            case 0xD44: cpu_name = "Cortex-X1"; break;
            case 0xD46: cpu_name = "Cortex-A510"; break;
            case 0xD47: cpu_name = "Cortex-A710"; break;
            case 0xD48: cpu_name = "Cortex-X2"; break;
            case 0xD49: cpu_name = "Neoverse N2"; break;
            case 0xD4A: cpu_name = "Neoverse E1"; break;
            case 0xD4B: cpu_name = "Cortex-A78AE"; break;
            case 0xD4C: cpu_name = "Cortex-X1C"; break;
            case 0xD4D: cpu_name = "Cortex-A715"; break;
            case 0xD4E: cpu_name = "Cortex-X3"; break;
            default: break;
        }
    } else if (implementer == 0x61) {  /* Apple */
        cpu_name = "Apple Silicon";
    } else if (implementer == 0x51) {  /* Qualcomm */
        cpu_name = "Qualcomm Kryo";
    }

    /* Format: "CPU Name r<variant>p<revision>" */
    size_t len = 0;
    while (cpu_name[len] != '\0' && len < 40) {
        brand[len] = cpu_name[len];
        len++;
    }

    /* Append variant and revision manually */
    if (len < 45) {
        brand[len++] = ' ';
        brand[len++] = 'r';
        brand[len++] = '0' + variant;
        brand[len++] = 'p';
        brand[len++] = '0' + revision;
        brand[len] = '\0';
    } else {
        brand[len] = '\0';
    }
}

#else  /* Other architectures */

static void get_cpu_brand(char brand[CPU_BRAND_BUFFER_SIZE]) {
    brand[0] = '\0';
}

#endif  /* Architecture selection */

void fut_boot_banner(void) {
#ifdef __x86_64__
    const fut_cpu_features_t *feat = cpu_features_get();
#endif

    char cpu_brand[CPU_BRAND_BUFFER_SIZE] = {0};
    get_cpu_brand(cpu_brand);

    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages = fut_pmm_free_pages();
#ifndef __aarch64__
    uintptr_t base_phys = fut_pmm_base_phys();
#endif

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

#ifdef __aarch64__
    /* ARM64: Use simple printf calls to avoid format string bugs */
    fut_printf("\n[MEM] Physical: total=%llu MiB  free=%llu MiB\n",
               (unsigned long long)total_mib,
               (unsigned long long)free_mib);
    fut_printf("[MEM] Map:\n");
    fut_mmap_dump();
    fut_printf("=======================================================\n\n");
#else
    fut_printf("\n[MEM] Physical: total=%llu MiB  free=%llu MiB  base=0x%llx\n",
               (unsigned long long)total_mib,
               (unsigned long long)free_mib,
               (unsigned long long)base_phys);
    fut_printf("[MEM] Map:\n");
    fut_mmap_dump();
    fut_printf("=======================================================\n\n");
#endif
}
