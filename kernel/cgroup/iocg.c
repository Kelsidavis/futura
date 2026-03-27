/* kernel/cgroup/iocg.c - Cgroup v2 I/O controller
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Per-cgroup block I/O bandwidth limits:
 *   io.max: "MAJ:MIN rbps=N wbps=N riops=N wiops=N"
 *   io.stat: per-device I/O statistics (bytes_read, bytes_written, ios)
 *
 * Docker/Podman flags that use this controller:
 *   --device-read-bps    → io.max rbps=N
 *   --device-write-bps   → io.max wbps=N
 *   --device-read-iops   → io.max riops=N
 *   --device-write-iops  → io.max wiops=N
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <stdint.h>
#include <string.h>

#define IOCG_MAX 16

struct iocg_group {
    bool     active;
    char     name[32];
    uint64_t rbps_max;      /* Read bytes/sec limit (0 = unlimited) */
    uint64_t wbps_max;      /* Write bytes/sec limit */
    uint64_t riops_max;     /* Read IOPS limit */
    uint64_t wiops_max;     /* Write IOPS limit */
    uint64_t bytes_read;    /* Cumulative read bytes */
    uint64_t bytes_written; /* Cumulative write bytes */
    uint64_t ios_read;      /* Cumulative read operations */
    uint64_t ios_written;   /* Cumulative write operations */
};

static struct iocg_group g_iocg[IOCG_MAX];

void iocg_init(void) {
    memset(g_iocg, 0, sizeof(g_iocg));
    g_iocg[0].active = true;
    g_iocg[0].name[0] = '/'; g_iocg[0].name[1] = '\0';
    fut_printf("[IOCG] Cgroup v2 I/O controller initialized\n");
}

static int iocg_find(const char *path) {
    for (int i = 0; i < IOCG_MAX; i++) {
        if (!g_iocg[i].active) continue;
        const char *a = g_iocg[i].name, *b = path;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == '\0' && *b == '\0') return i;
    }
    return -1;
}

int iocg_create(const char *path) {
    if (!path) return -EINVAL;
    if (iocg_find(path) >= 0) return -EEXIST;
    for (int i = 1; i < IOCG_MAX; i++) {
        if (!g_iocg[i].active) {
            g_iocg[i].active = true;
            size_t pl = 0;
            while (path[pl] && pl < 31) { g_iocg[i].name[pl] = path[pl]; pl++; }
            g_iocg[i].name[pl] = '\0';
            g_iocg[i].rbps_max = 0;
            g_iocg[i].wbps_max = 0;
            g_iocg[i].riops_max = 0;
            g_iocg[i].wiops_max = 0;
            g_iocg[i].bytes_read = 0;
            g_iocg[i].bytes_written = 0;
            g_iocg[i].ios_read = 0;
            g_iocg[i].ios_written = 0;
            return 0;
        }
    }
    return -ENOSPC;
}

/**
 * iocg_set_max — Set I/O limits for a cgroup.
 * Called when writing to io.max: "MAJ:MIN rbps=N wbps=N riops=N wiops=N"
 * For simplicity, we accept any line and parse key=value pairs.
 */
int iocg_set_max(const char *path, uint64_t rbps, uint64_t wbps,
                 uint64_t riops, uint64_t wiops) {
    int idx = iocg_find(path);
    if (idx < 0) {
        /* Auto-create for root cgroup writes */
        if (path[0] == '\0') idx = 0;
        else return -ENOENT;
    }
    g_iocg[idx].rbps_max = rbps;
    g_iocg[idx].wbps_max = wbps;
    g_iocg[idx].riops_max = riops;
    g_iocg[idx].wiops_max = wiops;
    fut_printf("[IOCG] Set io.max for '%s': rbps=%llu wbps=%llu riops=%llu wiops=%llu\n",
               g_iocg[idx].name,
               (unsigned long long)rbps, (unsigned long long)wbps,
               (unsigned long long)riops, (unsigned long long)wiops);
    return 0;
}

/**
 * iocg_get_max — Format io.max for reading.
 * Returns bytes written to buf. Format: "MAJ:MIN rbps=N wbps=N riops=N wiops=N\n"
 * Uses 8:0 as the device (virtual root device).
 */
int iocg_get_max(const char *path, char *buf, size_t bufsz) {
    int idx = iocg_find(path);
    if (idx < 0) idx = 0;  /* Default to root */

    /* If no limits set, return empty (Linux convention) */
    if (g_iocg[idx].rbps_max == 0 && g_iocg[idx].wbps_max == 0 &&
        g_iocg[idx].riops_max == 0 && g_iocg[idx].wiops_max == 0) {
        if (bufsz > 0) buf[0] = '\0';
        return 0;
    }

    /* Format: "8:0 rbps=N wbps=N riops=N wiops=N\n" */
    int pos = 0;
    const char *pfx = "8:0 rbps=";
    while (*pfx && pos < (int)bufsz - 1) buf[pos++] = *pfx++;

    /* Helper: append uint64 */
    #define APPEND_U64(v) do { \
        char tmp[20]; int tp = 0; uint64_t _v = (v); \
        if (_v == 0) { tmp[tp++] = '0'; } \
        else { char rev[20]; int rp = 0; \
            while (_v > 0) { rev[rp++] = '0' + (char)(_v % 10); _v /= 10; } \
            while (rp > 0) tmp[tp++] = rev[--rp]; } \
        for (int i = 0; i < tp && pos < (int)bufsz - 1; i++) buf[pos++] = tmp[i]; \
    } while(0)

    APPEND_U64(g_iocg[idx].rbps_max);
    if (pos < (int)bufsz - 8) { const char *s = " wbps="; while (*s) buf[pos++] = *s++; }
    APPEND_U64(g_iocg[idx].wbps_max);
    if (pos < (int)bufsz - 9) { const char *s = " riops="; while (*s) buf[pos++] = *s++; }
    APPEND_U64(g_iocg[idx].riops_max);
    if (pos < (int)bufsz - 9) { const char *s = " wiops="; while (*s) buf[pos++] = *s++; }
    APPEND_U64(g_iocg[idx].wiops_max);
    if (pos < (int)bufsz - 1) buf[pos++] = '\n';
    buf[pos] = '\0';

    #undef APPEND_U64
    return pos;
}

/**
 * iocg_get_stat — Format io.stat for reading.
 * Format: "8:0 rbytes=N wbytes=N rios=N wios=N\n"
 */
int iocg_get_stat(const char *path, char *buf, size_t bufsz) {
    int idx = iocg_find(path);
    if (idx < 0) idx = 0;

    int pos = 0;
    const char *pfx = "8:0 rbytes=";
    while (*pfx && pos < (int)bufsz - 1) buf[pos++] = *pfx++;

    #define APPEND_U64(v) do { \
        char tmp[20]; int tp = 0; uint64_t _v = (v); \
        if (_v == 0) { tmp[tp++] = '0'; } \
        else { char rev[20]; int rp = 0; \
            while (_v > 0) { rev[rp++] = '0' + (char)(_v % 10); _v /= 10; } \
            while (rp > 0) tmp[tp++] = rev[--rp]; } \
        for (int i = 0; i < tp && pos < (int)bufsz - 1; i++) buf[pos++] = tmp[i]; \
    } while(0)

    APPEND_U64(g_iocg[idx].bytes_read);
    if (pos < (int)bufsz - 9) { const char *s = " wbytes="; while (*s) buf[pos++] = *s++; }
    APPEND_U64(g_iocg[idx].bytes_written);
    if (pos < (int)bufsz - 7) { const char *s = " rios="; while (*s) buf[pos++] = *s++; }
    APPEND_U64(g_iocg[idx].ios_read);
    if (pos < (int)bufsz - 7) { const char *s = " wios="; while (*s) buf[pos++] = *s++; }
    APPEND_U64(g_iocg[idx].ios_written);
    if (pos < (int)bufsz - 1) buf[pos++] = '\n';
    buf[pos] = '\0';

    #undef APPEND_U64
    return pos;
}

/**
 * iocg_account_read — Track a read I/O operation for the root cgroup.
 * Called from VFS read paths to accumulate I/O statistics.
 */
void iocg_account_read(uint64_t bytes) {
    g_iocg[0].bytes_read += bytes;
    g_iocg[0].ios_read++;
}

/**
 * iocg_account_write — Track a write I/O operation for the root cgroup.
 * Called from VFS write paths to accumulate I/O statistics.
 */
void iocg_account_write(uint64_t bytes) {
    g_iocg[0].bytes_written += bytes;
    g_iocg[0].ios_written++;
}
