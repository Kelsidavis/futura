/* SPDX-License-Identifier: MPL-2.0
 * klog_persist.c — fixed-physical-address ring buffer for crash diagnostics.
 *
 * Lives at a known phys addr (KLOG_PERSIST_PHYS) so it can survive a warm
 * reboot. On entry, fut_platform_init calls klog_persist_init(): if the
 * magic header matches, the previous boot's log is dumped to fut_printf
 * (which goes to fb_console + serial + the BSS klog_buf), then the
 * sequence number is bumped and the buffer cleared. Every subsequent
 * klog_write also mirrors here, so a fault that survives long enough to
 * reset the box leaves a forensic trail.
 *
 * Caveats:
 *  - phys 0x10000000 (256 MB) is in the boot identity map (covered by
 *    PDPT[0..3]) AND in the higher-half mirror (PDPT[510..511] cover
 *    phys 0-2 GB). Any kernel access works either way.
 *  - The PMM eventually owns this phys range. Once the kernel allocates
 *    something there, the buffer gets overwritten in-flight. That's fine
 *    for the use case ("see why the kernel just panicked") because at
 *    panic time we dump immediately. The cross-reboot survival window
 *    closes the moment the PMM hands out a page at this phys.
 *    A proper fix is to mark the range reserved in the multiboot2 mmap
 *    (mirroring Linux's ramoops). TODO.
 *  - DRAM contents are preserved across warm resets on most x86 hardware
 *    (incl. coreboot/SeaBIOS Chromebooks). Cold boot zeroes memory.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <kernel/kprintf.h>

/* Phys 256 MB. Above the kernel image, below 2 GB so it's in the
 * higher-half mirror. */
#define KLOG_PERSIST_PHYS    0x10000000ULL
/* Total size: 256 KB. Header eats the first 64 bytes, the rest is data. */
#define KLOG_PERSIST_SIZE    (256ULL * 1024ULL)

/* Higher-half virt: phys + KERNEL_VIRTUAL_BASE. Boot.S maps this. */
#define KLOG_PERSIST_VIRT    (0xFFFFFFFF80000000ULL + KLOG_PERSIST_PHYS)

/* "FUTRALOG" little-endian. Picked to be unlikely to occur as random
 * memory garbage. */
#define KLOG_PERSIST_MAGIC   0x474F4C415254554FULL  /* "OUTRALOG" */

typedef struct {
    uint64_t magic;          /* KLOG_PERSIST_MAGIC when valid */
    uint32_t version;        /* Header schema version */
    uint32_t boot_seq;       /* Increments each boot */
    uint64_t total_written;  /* Bytes ever written this boot (may exceed
                              * data area size if we wrapped) */
    uint32_t cursor;         /* Next write index in data[] (0..size-1) */
    uint32_t reserved;
    uint8_t  data[];         /* size = KLOG_PERSIST_SIZE - sizeof(header) */
} klog_persist_t;

#define KLOG_PERSIST_DATA_SIZE  (KLOG_PERSIST_SIZE - sizeof(klog_persist_t))

static volatile klog_persist_t *g_klog =
    (volatile klog_persist_t *)KLOG_PERSIST_VIRT;

static atomic_int g_klog_initialized = 0;

/* Dump the previous-boot data to the current console. Caller must have
 * already verified the magic. */
static void klog_persist_dump_previous(void) {
    uint64_t total = g_klog->total_written;
    uint32_t data_size = KLOG_PERSIST_DATA_SIZE;
    uint32_t cursor = g_klog->cursor;
    uint32_t boot_seq = g_klog->boot_seq;

    fut_printf("\n");
    fut_printf("================================================================\n");
    fut_printf("[KLOG-PERSIST] Recovered log from previous boot (seq=%u)\n", boot_seq);
    fut_printf("[KLOG-PERSIST] %llu bytes written%s\n",
               (unsigned long long)total,
               total > data_size ? " (wrapped)" : "");
    fut_printf("================================================================\n");

    if (total == 0 || cursor >= data_size) {
        fut_printf("[KLOG-PERSIST] (empty or corrupt cursor)\n");
        return;
    }

    if (total <= data_size) {
        /* Didn't wrap — data[0..cursor] is the log. */
        for (uint32_t i = 0; i < cursor; i++) {
            extern void fut_serial_putc(char c);
            fut_serial_putc((char)g_klog->data[i]);
        }
    } else {
        /* Wrapped — start at cursor (oldest), read all data_size bytes. */
        for (uint32_t i = 0; i < data_size; i++) {
            uint32_t pos = (cursor + i) % data_size;
            extern void fut_serial_putc(char c);
            fut_serial_putc((char)g_klog->data[pos]);
        }
    }

    fut_printf("\n================================================================\n");
    fut_printf("[KLOG-PERSIST] End of recovered log\n");
    fut_printf("================================================================\n\n");
}

void klog_persist_init(void) {
    bool valid_previous = (g_klog->magic == KLOG_PERSIST_MAGIC) &&
                          (g_klog->version == 1) &&
                          (g_klog->cursor < KLOG_PERSIST_DATA_SIZE);
    uint32_t prev_seq = valid_previous ? g_klog->boot_seq : 0;

    /* The auto-dump of the previous boot's log was confusing during
     * normal iteration: every boot scrolled last boot's banner /
     * build line / driver-init log onto this boot's screen, looking
     * for all the world like the *current* kernel had a duplicate
     * banner and a stale build tag. The recording infrastructure
     * still runs (we keep writing to the ring), so the data is
     * recoverable later via a debug hook — just not splashed onto
     * the framebuffer at startup. */
    if (valid_previous) {
        fut_printf("[KLOG-PERSIST] Previous-boot log present (seq=%u, %llu bytes); not auto-dumped\n",
                   prev_seq,
                   (unsigned long long)g_klog->total_written);
    } else {
        fut_printf("[KLOG-PERSIST] No previous log (magic=0x%llx) — fresh start\n",
                   (unsigned long long)g_klog->magic);
    }
    /* Keep the dump function reachable for a future debug hook so the
     * symbol isn't DCE'd. */
    if (0) klog_persist_dump_previous();

    /* Reset header for this boot. Do magic LAST so a partially-written
     * header from this point onward doesn't get mistaken for valid by
     * the next boot. */
    g_klog->version = 1;
    g_klog->boot_seq = prev_seq + 1;
    g_klog->total_written = 0;
    g_klog->cursor = 0;
    g_klog->reserved = 0;
    g_klog->magic = KLOG_PERSIST_MAGIC;

    atomic_store_explicit(&g_klog_initialized, 1, memory_order_release);

    /* Read back boot_seq immediately as a sanity check. If the persist
     * region's phys page isn't actually backing this VA — e.g. it's been
     * unmapped or PMM stomped it — the readback will show a different
     * value (often 0xFFFFFFFF when DRAM uninitialized). The trampoline's
     * boot_seq print has shown 0xFFFFFFFF on the HP Chromebook even though
     * we wrote (prev_seq + 1) here. Surfacing the mismatch points at the
     * bug rather than letting it look like the trampoline is reading the
     * wrong field. */
    uint32_t readback = g_klog->boot_seq;
    if (readback != prev_seq + 1) {
        fut_printf("[KLOG-PERSIST] WARN: wrote boot_seq=%u but readback=%u — persist region not sticky\n",
                   prev_seq + 1, readback);
    }

    fut_printf("[KLOG-PERSIST] Initialized at phys=0x%llx size=%llu boot_seq=%u\n",
               (unsigned long long)KLOG_PERSIST_PHYS,
               (unsigned long long)KLOG_PERSIST_SIZE,
               g_klog->boot_seq);
}

void klog_persist_write(const char *data, size_t len) {
    if (atomic_load_explicit(&g_klog_initialized, memory_order_acquire) == 0) {
        return;
    }
    if (!data || len == 0) {
        return;
    }

    /* Single-CPU boot for now (SMP disabled), so plain reads/writes are
     * fine. When SMP is re-enabled this needs an atomic cursor bump or
     * a per-CPU sub-buffer. */
    uint32_t cursor = g_klog->cursor;
    for (size_t i = 0; i < len; i++) {
        g_klog->data[cursor] = (uint8_t)data[i];
        cursor++;
        if (cursor >= KLOG_PERSIST_DATA_SIZE) {
            cursor = 0;
        }
    }
    g_klog->cursor = cursor;
    g_klog->total_written += len;
}

/* Copy up to `max` bytes of the current boot's log into `out`, unwrapped
 * (oldest bytes first, newest last). Returns the number of bytes copied.
 *
 * If total_written <= data_size, the log hasn't wrapped: contents live
 * in g_klog->data[0..total_written) and we just copy that. If it has
 * wrapped, oldest bytes start at `cursor` and continue through the end,
 * then wrap to [0..cursor). */
size_t klog_persist_read(char *out, size_t max) {
    if (atomic_load_explicit(&g_klog_initialized, memory_order_acquire) == 0) {
        return 0;
    }
    if (!out || max == 0) {
        return 0;
    }
    uint64_t total = g_klog->total_written;
    uint32_t data_size = KLOG_PERSIST_DATA_SIZE;
    uint32_t cursor = g_klog->cursor;
    if (total == 0) {
        return 0;
    }
    if (total <= (uint64_t)data_size) {
        /* No wrap. Bytes are [0 .. cursor). */
        size_t n = (size_t)cursor;
        if (n > max) {
            n = max;
        }
        for (size_t i = 0; i < n; i++) {
            out[i] = (char)g_klog->data[i];
        }
        return n;
    }
    /* Wrapped. Oldest bytes start at cursor and wrap. */
    size_t produced = 0;
    /* tail: [cursor .. data_size) */
    for (uint32_t i = cursor; i < data_size && produced < max; i++) {
        out[produced++] = (char)g_klog->data[i];
    }
    /* head: [0 .. cursor) */
    for (uint32_t i = 0; i < cursor && produced < max; i++) {
        out[produced++] = (char)g_klog->data[i];
    }
    return produced;
}

uint32_t klog_persist_boot_seq(void) {
    if (atomic_load_explicit(&g_klog_initialized, memory_order_acquire) == 0) {
        return 0;
    }
    return g_klog->boot_seq;
}
