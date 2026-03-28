/* kernel/dev_null.c - /dev/null and /dev/zero character devices
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * /dev/null: write discards all data, read returns EOF (0 bytes)
 * /dev/zero: write discards all data, read returns zero bytes
 *
 * These are essential pseudo-devices used by virtually all Unix programs.
 */

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <sys/mman.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* /dev/null: read returns 0 (EOF), write succeeds */
static ssize_t null_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)n; (void)pos;
    return 0;  /* EOF */
}

static ssize_t null_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)pos;
    return (ssize_t)n;  /* Accept and discard all data */
}

/* Runtime-initialized to avoid ARM64 static const relocation issues */
static struct fut_file_ops null_fops;

/* /dev/zero: read returns zero bytes, write succeeds */
static ssize_t zero_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    memset(buf, 0, n);
    return (ssize_t)n;
}

/* /dev/zero mmap: create an anonymous mapping backed by zeroed pages.
 * This allows programs to use open("/dev/zero") + mmap() as an alternative
 * to MAP_ANONYMOUS for creating zero-filled private or shared mappings.
 * Offset is ignored (all of /dev/zero appears as zeroed infinite storage). */
static void *zero_mmap_op(void *inode, void *priv, void *u_addr, size_t len,
                           off_t off, int prot, int flags) {
    (void)inode; (void)priv; (void)off;
    fut_task_t *task = fut_task_current();
    if (!task) return (void *)(intptr_t)(-ESRCH);

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) mm = fut_mm_current();
    if (!mm) return (void *)(intptr_t)(-ENOMEM);

    /* Force MAP_ANONYMOUS: /dev/zero is equivalent to an anonymous mapping */
    int anon_flags = flags | MAP_ANONYMOUS;
    return fut_mm_map_anonymous(mm, (uintptr_t)u_addr, len, prot, anon_flags);
}

static struct fut_file_ops zero_fops;

/* /dev/urandom: read returns random bytes (from getrandom), write succeeds */
static ssize_t urandom_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
    long ret = sys_getrandom(buf, n, 0);
    return (ret < 0) ? ret : (ssize_t)ret;
}

static struct fut_file_ops urandom_fops;

/* /dev/full: read returns zero bytes (like /dev/zero), write returns ENOSPC */
static ssize_t full_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)n; (void)pos;
    return -28;  /* -ENOSPC: No space left on device */
}

static struct fut_file_ops full_fops;

#ifdef __x86_64__
/* Check if RDRAND is supported via CPUID.01H:ECX.RDRAND[bit 30] */
static int hwrng_has_rdrand(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    return (ecx >> 30) & 1;
}
#endif

/* /dev/hwrng: hardware random number generator backed by RDRAND (x86_64) */
static ssize_t hwrng_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    uint8_t *out = (uint8_t *)buf;
    size_t filled = 0;
#ifdef __x86_64__
    if (!hwrng_has_rdrand()) {
        /* Fallback: use xorshift from getrandom() */
        extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
        long r = sys_getrandom(buf, n, 0);
        return r > 0 ? r : 0;
    }
    /* Use RDRAND instruction for true hardware entropy */
    while (filled + 8 <= n) {
        uint64_t val;
        unsigned char ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
        if (ok) {
            __builtin_memcpy(out + filled, &val, 8);
            filled += 8;
        } else {
            break;  /* RDRAND failed — return what we have */
        }
    }
    /* Handle remaining bytes */
    if (filled < n) {
        uint64_t val;
        unsigned char ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
        if (ok) {
            size_t remain = n - filled;
            if (remain > 8) remain = 8;
            __builtin_memcpy(out + filled, &val, remain);
            filled += remain;
        }
    }
#else
    /* ARM64 fallback: use timer counter as entropy source */
    uint64_t cnt;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(cnt));
    uint64_t state = cnt ^ 0x6A09E667F3BCC908ULL;
    while (filled < n) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        size_t chunk = n - filled;
        if (chunk > 8) chunk = 8;
        __builtin_memcpy(out + filled, &state, chunk);
        filled += chunk;
    }
#endif
    return (ssize_t)filled;
}

/**
 * Initialize /dev/null, /dev/zero, /dev/full, and /dev/urandom devices.
 * Call from kernel_main during boot.
 */
/* ============================================================
 *   /dev/kmsg — Kernel Log Buffer Access
 * ============================================================ */

/* External kernel log buffer (defined in sys_syslog.c) */
extern char klog_buf[];
extern size_t klog_head;
extern size_t klog_tail;
extern size_t klog_write_pos;
extern size_t klog_count;
extern size_t klog_read_buffer(char *dst, size_t len);

#define KLOG_BUF_SIZE (64 * 1024)

/* Read from kernel log buffer (like `dmesg`).
 * Uses file offset (via pos) to track how much has been consumed.
 * On first read (pos=0), reads from the oldest data in the ring. */
static ssize_t kmsg_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv;
    if (!buf || n == 0 || klog_count == 0) return 0;

    /* How many bytes have already been consumed */
    size_t consumed = pos ? (size_t)*pos : 0;
    if (consumed >= klog_count) return 0;  /* All data read */

    /* Data available = total - consumed */
    size_t available = klog_count - consumed;

    /* Calculate read position: oldest data (klog_head) + consumed */
    size_t read_from = (klog_head + consumed) % KLOG_BUF_SIZE;

    size_t to_read = (n < available) ? n : available;
    char *dst = (char *)buf;
    for (size_t i = 0; i < to_read; i++)
        dst[i] = klog_buf[(read_from + i) % KLOG_BUF_SIZE];

    if (pos) *pos += (off_t)to_read;
    return (ssize_t)to_read;
}

/* Write to kernel log (inject message into ring buffer) */
static ssize_t kmsg_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    if (!buf || n == 0) return 0;

    /* Write the message to the kernel log via klog_write */
    extern void klog_write(const char *data, size_t len);
    klog_write((const char *)buf, n);
    return (ssize_t)n;
}

/* ── /dev/rtc0 — Real-time clock ── */

/* RTC ioctl numbers (Linux ABI) */
#define RTC_RD_TIME     0x80247009  /* Read RTC time */
#define RTC_SET_TIME    0x4024700A  /* Set RTC time */
#define RTC_ALM_READ    0x80247008  /* Read alarm time */
#define RTC_ALM_SET     0x40247007  /* Set alarm time */
#define RTC_IRQP_READ   0x8008700B  /* Read IRQ rate */
#define RTC_IRQP_SET    0x4008700C  /* Set IRQ rate */

struct rtc_time {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

static void epoch_to_rtc_time(uint64_t epoch_sec, struct rtc_time *tm) {
    /* Convert epoch seconds to broken-down time (simplified, no leap seconds) */
    uint64_t days = epoch_sec / 86400;
    uint32_t tod = (uint32_t)(epoch_sec % 86400);
    tm->tm_sec = (int)(tod % 60);
    tm->tm_min = (int)((tod / 60) % 60);
    tm->tm_hour = (int)(tod / 3600);
    tm->tm_wday = (int)((days + 4) % 7); /* Jan 1 1970 was Thursday */

    /* Year calculation */
    int y = 1970;
    while (1) {
        int leap = ((y % 4 == 0) && (y % 100 != 0 || y % 400 == 0)) ? 1 : 0;
        uint32_t ydays = 365 + (uint32_t)leap;
        if (days < ydays) break;
        days -= ydays;
        y++;
    }
    tm->tm_year = y - 1900;
    tm->tm_yday = (int)days;

    /* Month calculation */
    static const int mdays[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    int leap = ((y % 4 == 0) && (y % 100 != 0 || y % 400 == 0)) ? 1 : 0;
    int m;
    for (m = 0; m < 12; m++) {
        int md = mdays[m] + (m == 1 ? leap : 0);
        if ((int)days < md) break;
        days -= (uint64_t)md;
    }
    tm->tm_mon = m;
    tm->tm_mday = (int)days + 1;
    tm->tm_isdst = 0;
}

static ssize_t rtc_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    if (n < sizeof(struct rtc_time)) return -EINVAL;

    extern int64_t g_realtime_offset_sec;
    extern uint64_t fut_get_ticks(void);
    uint64_t now = fut_get_ticks() / 100 + (uint64_t)g_realtime_offset_sec;

    struct rtc_time tm;
    epoch_to_rtc_time(now, &tm);
    memcpy(buf, &tm, sizeof(tm));
    return sizeof(struct rtc_time);
}

static int rtc_ioctl(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode; (void)priv;

    extern int64_t g_realtime_offset_sec;
    extern uint64_t fut_get_ticks(void);

    switch (req) {
    case RTC_RD_TIME: {
        struct rtc_time *tm = (struct rtc_time *)(uintptr_t)arg;
        if (!tm) return -EFAULT;
        uint64_t now = fut_get_ticks() / 100 + (uint64_t)g_realtime_offset_sec;
        epoch_to_rtc_time(now, tm);
        return 0;
    }
    case RTC_SET_TIME: {
        /* Accept but don't change system time from RTC ioctl */
        return 0;
    }
    case RTC_ALM_READ:
    case RTC_ALM_SET:
        return 0; /* Alarm: accept silently */
    case RTC_IRQP_READ: {
        unsigned long *rate = (unsigned long *)(uintptr_t)arg;
        if (rate) *rate = 1024;
        return 0;
    }
    default:
        return -EINVAL;
    }
}

void dev_null_init(void) {
    /* Initialize file ops at runtime (ARM64 relocation safety) */
    null_fops.read = null_read;
    null_fops.write = null_write;
    zero_fops.read = zero_read;
    zero_fops.write = null_write;
    zero_fops.mmap = zero_mmap_op;
    urandom_fops.read = urandom_read;
    urandom_fops.write = null_write;
    full_fops.read = zero_read;
    full_fops.write = full_write;

    /* Linux device numbers: /dev/null = (1,3), /dev/zero = (1,5) */
    chrdev_register(1, 3, &null_fops, "null", NULL);
    devfs_create_chr("/dev/null", 1, 3);

    chrdev_register(1, 5, &zero_fops, "zero", NULL);
    devfs_create_chr("/dev/zero", 1, 5);

    /* /dev/full = (1,7): like /dev/zero but write returns ENOSPC */
    chrdev_register(1, 7, &full_fops, "full", NULL);
    devfs_create_chr("/dev/full", 1, 7);

    /* /dev/urandom = (1,9), /dev/random = (1,8) — both use same PRNG */
    chrdev_register(1, 9, &urandom_fops, "urandom", NULL);
    devfs_create_chr("/dev/urandom", 1, 9);

    chrdev_register(1, 8, &urandom_fops, "random", NULL);
    devfs_create_chr("/dev/random", 1, 8);

    /* /dev/kmsg = (1,11) — kernel log ring buffer access (systemd-journald, dmesg)
     * Reading returns log messages; writing injects messages into the log. */
    static struct fut_file_ops kmsg_fops;
    kmsg_fops.read = kmsg_read;
    kmsg_fops.write = kmsg_write;
    chrdev_register(1, 11, &kmsg_fops, "kmsg", NULL);
    devfs_create_chr("/dev/kmsg", 1, 11);

    /* /dev/hwrng = (10,183) — hardware random number generator.
     * On x86_64, backed by RDRAND instruction for true hardware entropy.
     * On ARM64, falls back to CNTVCT-seeded PRNG. */
    static struct fut_file_ops hwrng_fops;
    hwrng_fops.read = hwrng_read;
    hwrng_fops.write = null_write;
    chrdev_register(10, 183, &hwrng_fops, "hwrng", NULL);
    devfs_create_chr("/dev/hwrng", 10, 183);

    /* /dev/rtc0 = (252,0) — Real-time clock device.
     * Supports read() for time and RTC_RD_TIME/RTC_SET_TIME ioctls.
     * Used by hwclock, systemd-timesyncd, and ntpd. */
    static struct fut_file_ops rtc_fops;
    rtc_fops.read = rtc_read;
    rtc_fops.ioctl = rtc_ioctl;
    chrdev_register(252, 0, &rtc_fops, "rtc0", NULL);
    devfs_create_chr("/dev/rtc0", 252, 0);
    devfs_create_chr("/dev/rtc", 252, 0); /* symlink-like alias */

    /* /dev/mem = (1,1) — Physical memory access (read-only stub).
     * Returns zeroes for all reads. Programs like dmidecode and
     * firmware scanners check for this device's existence. */
    static struct fut_file_ops mem_fops;
    mem_fops.read = zero_read;   /* Read returns zeroes */
    mem_fops.write = null_write; /* Write discards */
    chrdev_register(1, 1, &mem_fops, "mem", NULL);
    devfs_create_chr("/dev/mem", 1, 1);

    fut_printf("[DEV] /dev/null, /dev/zero, /dev/full, /dev/urandom, /dev/random, "
               "/dev/kmsg, /dev/hwrng, /dev/rtc0, /dev/mem registered\n");
}
