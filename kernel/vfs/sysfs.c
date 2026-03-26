/* kernel/vfs/sysfs.c - Minimal /sys virtual filesystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides a read-only sysfs skeleton so that programs which probe /sys
 * (Python, Docker, systemd, udev, lsblk, ip, libvirt …) do not abort
 * with ENOENT or ENODEV.  No real hardware is exposed; the goal is
 * Linux-ABI compatibility.
 *
 * Directory tree:
 *   /sys/
 *     class/  net/lo/{ifindex,operstate,type,mtu,address,flags}  block/  tty/
 *     bus/    pci/devices/  usb/devices/  platform/devices/
 *     devices/
 *     kernel/ mm/ transparent_hugepage/{enabled,defrag,use_zero_pages}
 *             profiling
 *     fs/     cgroup/
 *     block/
 *     power/  state
 *     module/
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_lock.h>
#include <kernel/errno.h>
#include <futura/netif.h>
#include <kernel/fut_blockdev.h>
#include <kernel/pci.h>
#include <stddef.h>
#include <stdint.h>

/* ============================================================
 *   Node kinds
 * ============================================================ */

enum sysfs_kind {
    SYSFS_ROOT = 0,
    /* /sys/class/ */
    SYSFS_CLASS_DIR,
    SYSFS_CLASS_NET_DIR,
    SYSFS_CLASS_BLOCK_DIR,
    SYSFS_CLASS_TTY_DIR,
    /* /sys/class/net/lo/ */
    SYSFS_CLASS_NET_LO_DIR,
    SYSFS_NET_LO_IFINDEX,       /* file */
    SYSFS_NET_LO_OPERSTATE,     /* file */
    SYSFS_NET_LO_TYPE,          /* file */
    SYSFS_NET_LO_MTU,           /* file */
    SYSFS_NET_LO_ADDRESS,       /* file */
    SYSFS_NET_LO_FLAGS,         /* file */
    /* /sys/bus/ */
    SYSFS_BUS_DIR,
    SYSFS_BUS_PCI_DIR,
    SYSFS_BUS_PCI_DEV_DIR,
    SYSFS_BUS_USB_DIR,
    SYSFS_BUS_USB_DEV_DIR,
    SYSFS_BUS_PLATFORM_DIR,
    SYSFS_BUS_PLATFORM_DEV_DIR,
    /* /sys/devices/ */
    SYSFS_DEVICES_DIR,
    /* /sys/devices/system/ */
    SYSFS_DEVICES_SYSTEM_DIR,
    /* /sys/devices/system/cpu/ */
    SYSFS_CPU_DIR,
    SYSFS_CPU_ONLINE,           /* file: "0\n" */
    SYSFS_CPU_POSSIBLE,         /* file: "0\n" */
    SYSFS_CPU_PRESENT,          /* file: "0\n" */
    SYSFS_CPU_KERNEL_MAX,       /* file: "0\n" */
    /* /sys/devices/system/cpu/cpu0/ */
    SYSFS_CPU0_DIR,
    SYSFS_CPU0_ONLINE,          /* file: "1\n" (CPU 0 is always online) */
    /* /sys/devices/system/cpu/cpu0/topology/ */
    SYSFS_CPU0_TOPOLOGY_DIR,
    SYSFS_CPU0_CORE_ID,         /* file: "0\n" */
    SYSFS_CPU0_PKG_ID,          /* file: "0\n" */
    SYSFS_CPU0_CORE_SIBLINGS,   /* file: "1\n" */
    SYSFS_CPU0_THREAD_SIBLINGS, /* file: "1\n" */
    /* /sys/kernel/ */
    SYSFS_KERNEL_DIR,
    SYSFS_KERNEL_MM_DIR,
    SYSFS_KERNEL_MM_THP_DIR,
    SYSFS_THP_ENABLED,          /* file */
    SYSFS_THP_DEFRAG,           /* file */
    SYSFS_THP_ZERO_PAGES,       /* file */
    SYSFS_KERNEL_PROFILING,     /* file */
    /* /sys/fs/ */
    SYSFS_FS_DIR,
    SYSFS_FS_CGROUP_DIR,
    /* /sys/block/ */
    SYSFS_BLOCK_DIR,
    /* /sys/power/ */
    SYSFS_POWER_DIR,
    SYSFS_POWER_STATE,          /* file */
    /* /sys/module/ */
    SYSFS_MODULE_DIR,
};

typedef struct {
    enum sysfs_kind kind;
} sysfs_node_t;

/* ============================================================
 *   Inode numbers (fixed, well away from procfs range)
 * ============================================================ */

#define SYSFS_INO_ROOT              500ULL
#define SYSFS_INO_CLASS             501ULL
#define SYSFS_INO_CLASS_NET         502ULL
#define SYSFS_INO_CLASS_BLOCK       503ULL
#define SYSFS_INO_CLASS_TTY         504ULL
#define SYSFS_INO_BUS               505ULL
#define SYSFS_INO_BUS_PCI           506ULL
#define SYSFS_INO_BUS_PCI_DEV       507ULL
#define SYSFS_INO_BUS_USB           508ULL
#define SYSFS_INO_BUS_USB_DEV       509ULL
#define SYSFS_INO_BUS_PLATFORM      510ULL
#define SYSFS_INO_BUS_PLATFORM_DEV  511ULL
#define SYSFS_INO_DEVICES           512ULL
#define SYSFS_INO_KERNEL            513ULL
#define SYSFS_INO_KERNEL_MM         514ULL
#define SYSFS_INO_KERNEL_MM_THP     515ULL
#define SYSFS_INO_THP_ENABLED       516ULL
#define SYSFS_INO_THP_DEFRAG        517ULL
#define SYSFS_INO_THP_ZERO_PAGES    518ULL
#define SYSFS_INO_KERNEL_PROFILING  519ULL
#define SYSFS_INO_FS                520ULL
#define SYSFS_INO_FS_CGROUP         521ULL
#define SYSFS_INO_BLOCK             522ULL
#define SYSFS_INO_POWER             523ULL
#define SYSFS_INO_POWER_STATE       524ULL
#define SYSFS_INO_MODULE            525ULL
#define SYSFS_INO_DEVICES_SYSTEM    533ULL
#define SYSFS_INO_CPU               534ULL
#define SYSFS_INO_CPU_ONLINE        535ULL
#define SYSFS_INO_CPU_POSSIBLE      536ULL
#define SYSFS_INO_CPU_PRESENT       537ULL
#define SYSFS_INO_CPU_KERNEL_MAX    538ULL
#define SYSFS_INO_CPU0              539ULL
#define SYSFS_INO_CPU0_ONLINE       540ULL
#define SYSFS_INO_CPU0_TOPOLOGY     541ULL
#define SYSFS_INO_CPU0_CORE_ID      542ULL
#define SYSFS_INO_CPU0_PKG_ID       543ULL
#define SYSFS_INO_CPU0_CORE_SIB     544ULL
#define SYSFS_INO_CPU0_THREAD_SIB   545ULL
#define SYSFS_INO_CLASS_NET_LO      526ULL
#define SYSFS_INO_NET_LO_IFINDEX    527ULL
#define SYSFS_INO_NET_LO_OPERSTATE  528ULL
#define SYSFS_INO_NET_LO_TYPE       529ULL
#define SYSFS_INO_NET_LO_MTU        530ULL
#define SYSFS_INO_NET_LO_ADDRESS    531ULL
#define SYSFS_INO_NET_LO_FLAGS      532ULL

/* ============================================================
 *   Forward declarations
 * ============================================================ */

static struct fut_vnode_ops sysfs_dir_ops;
static struct fut_vnode_ops sysfs_file_ops;

/* ============================================================
 *   Vnode allocation
 * ============================================================ */

static struct fut_vnode *sysfs_alloc_vnode(struct fut_mount *mount,
                                            enum fut_vnode_type type,
                                            uint64_t ino, uint32_t mode,
                                            enum sysfs_kind kind) {
    struct fut_vnode *v = fut_malloc(sizeof(struct fut_vnode));
    if (!v) return NULL;
    sysfs_node_t *n = fut_malloc(sizeof(sysfs_node_t));
    if (!n) { fut_free(v); return NULL; }

    n->kind = kind;

    v->type     = type;
    v->ino      = ino;
    v->mode     = mode;
    v->uid      = 0;
    v->gid      = 0;
    v->size     = 0;
    v->nlinks   = (type == VN_DIR) ? 2 : 1;
    v->mount    = mount;
    v->fs_data  = n;
    v->refcount = 1;
    v->parent   = NULL;
    v->name     = NULL;
    v->ops      = (type == VN_DIR) ? &sysfs_dir_ops : &sysfs_file_ops;

    fut_vnode_lock_init(v);
    return v;
}

/* ============================================================
 *   File content generators
 * ============================================================ */

/* Static string copy, returns bytes written */
static size_t sysfs_gen_str(char *buf, size_t cap, const char *s) {
    size_t n = 0;
    while (s[n] && n < cap) { buf[n] = s[n]; n++; }
    return n;
}

static ssize_t sysfs_file_read(struct fut_vnode *vnode, void *buf,
                                size_t size, uint64_t offset) {
    if (!vnode || !buf || !size) return -EINVAL;
    sysfs_node_t *n = (sysfs_node_t *)vnode->fs_data;
    if (!n) return -EIO;

    char tmp[128];
    size_t total = 0;

    switch (n->kind) {
        case SYSFS_THP_ENABLED:
            /* Report THP as disabled; Python's multiprocessing checks this */
            total = sysfs_gen_str(tmp, sizeof(tmp),
                                  "always madvise [never]\n");
            break;
        case SYSFS_THP_DEFRAG:
            total = sysfs_gen_str(tmp, sizeof(tmp),
                                  "always defer defer+madvise madvise [never]\n");
            break;
        case SYSFS_THP_ZERO_PAGES:
            total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");
            break;
        case SYSFS_KERNEL_PROFILING:
            total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");
            break;
        case SYSFS_POWER_STATE:
            /* Expose the standard sleep states without actually supporting them */
            total = sysfs_gen_str(tmp, sizeof(tmp), "freeze mem standby disk\n");
            break;
        /* /sys/class/net/lo/ attribute files — read real data from netif registry */
        case SYSFS_NET_LO_IFINDEX: {
            struct net_iface *lo = netif_by_name("lo");
            char ibuf[16]; int pos = 0;
            int v = lo ? lo->index : 1;
            if (v >= 10) ibuf[pos++] = '0' + v / 10;
            ibuf[pos++] = '0' + v % 10;
            ibuf[pos++] = '\n'; ibuf[pos] = '\0';
            total = sysfs_gen_str(tmp, sizeof(tmp), ibuf);
            break;
        }
        case SYSFS_NET_LO_OPERSTATE: {
            struct net_iface *lo = netif_by_name("lo");
            total = sysfs_gen_str(tmp, sizeof(tmp),
                (lo && (lo->flags & 0x0040)) ? "up\n" : "down\n");
            break;
        }
        case SYSFS_NET_LO_TYPE:
            total = sysfs_gen_str(tmp, sizeof(tmp), "772\n");
            break;
        case SYSFS_NET_LO_MTU: {
            struct net_iface *lo = netif_by_name("lo");
            char mbuf[16]; int pos = 0;
            uint32_t mtu = lo ? lo->mtu : 65536;
            if (mtu == 0) { mbuf[pos++] = '0'; }
            else { char t[12]; int ti = 0; while (mtu > 0) { t[ti++] = '0' + mtu%10; mtu /= 10; } while (ti > 0) mbuf[pos++] = t[--ti]; }
            mbuf[pos++] = '\n'; mbuf[pos] = '\0';
            total = sysfs_gen_str(tmp, sizeof(tmp), mbuf);
            break;
        }
        case SYSFS_NET_LO_ADDRESS:
            total = sysfs_gen_str(tmp, sizeof(tmp), "00:00:00:00:00:00\n");
            break;
        case SYSFS_NET_LO_FLAGS: {
            struct net_iface *lo = netif_by_name("lo");
            uint32_t flags = lo ? lo->flags : 0x10;
            char fbuf[16]; int pos = 0;
            fbuf[pos++] = '0'; fbuf[pos++] = 'x';
            static const char hex[] = "0123456789abcdef";
            if (flags >= 0x1000) fbuf[pos++] = hex[(flags >> 12) & 0xF];
            if (flags >= 0x100) fbuf[pos++] = hex[(flags >> 8) & 0xF];
            if (flags >= 0x10) fbuf[pos++] = hex[(flags >> 4) & 0xF];
            fbuf[pos++] = hex[flags & 0xF];
            fbuf[pos++] = '\n'; fbuf[pos] = '\0';
            total = sysfs_gen_str(tmp, sizeof(tmp), fbuf);
            break;
        }
        /* /sys/devices/system/cpu/ attribute files */
        case SYSFS_CPU_ONLINE:      total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");   break;
        case SYSFS_CPU_POSSIBLE:    total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");   break;
        case SYSFS_CPU_PRESENT:     total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");   break;
        case SYSFS_CPU_KERNEL_MAX:  total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");   break;
        case SYSFS_CPU0_ONLINE:     total = sysfs_gen_str(tmp, sizeof(tmp), "1\n");   break;
        case SYSFS_CPU0_CORE_ID:    total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");   break;
        case SYSFS_CPU0_PKG_ID:     total = sysfs_gen_str(tmp, sizeof(tmp), "0\n");   break;
        case SYSFS_CPU0_CORE_SIBLINGS:   total = sysfs_gen_str(tmp, sizeof(tmp), "1\n"); break;
        case SYSFS_CPU0_THREAD_SIBLINGS: total = sysfs_gen_str(tmp, sizeof(tmp), "1\n"); break;
        default:
            return -EINVAL;
    }

    if (offset >= total) return 0;
    size_t avail = total - (size_t)offset;
    size_t copy  = avail < size ? avail : size;
    __builtin_memcpy(buf, tmp + offset, copy);
    return (ssize_t)copy;
}

static ssize_t sysfs_file_write(struct fut_vnode *vnode, const void *buf,
                                 size_t size, uint64_t offset) {
    (void)vnode; (void)buf; (void)size; (void)offset;
    return -EROFS;
}

static int sysfs_file_open(struct fut_vnode *vnode, int flags) {
    (void)vnode; (void)flags; return 0;
}
static int sysfs_file_close(struct fut_vnode *vnode) {
    (void)vnode; return 0;
}

/* sysfs_file_ops — runtime initialized in sysfs_mount */

/* ============================================================
 *   Directory operations
 * ============================================================ */

#define STREQ(a, b) (__builtin_strcmp((a),(b))==0)

/* Helper: fill one dirent and advance cookie */
static int sysfs_emit_de(struct fut_vdirent *de, uint64_t *cookie,
                          uint64_t idx, uint64_t ino, uint8_t dtype,
                          const char *name) {
    de->d_ino    = ino;
    de->d_off    = idx + 1;
    de->d_reclen = sizeof(*de);
    de->d_type   = dtype;
    size_t nl = 0;
    while (name[nl]) nl++;
    if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
    __builtin_memcpy(de->d_name, name, nl);
    de->d_name[nl] = '\0';
    *cookie = idx + 1;
    return 0;
}

/* Per-directory fixed-entry tables ---------------------------------- */

typedef struct { const char *name; uint64_t ino; uint8_t dtype; enum sysfs_kind kind; } sysfs_de_t;

#define DE_DIR(nm, ino, k) { (nm), (ino), FUT_VDIR_TYPE_DIR, (k) }
#define DE_REG(nm, ino, k) { (nm), (ino), FUT_VDIR_TYPE_REG, (k) }

static const sysfs_de_t root_entries[] = {
    DE_DIR(".",        SYSFS_INO_ROOT,    SYSFS_ROOT),
    DE_DIR("..",       SYSFS_INO_ROOT,    SYSFS_ROOT),
    DE_DIR("class",    SYSFS_INO_CLASS,   SYSFS_CLASS_DIR),
    DE_DIR("bus",      SYSFS_INO_BUS,     SYSFS_BUS_DIR),
    DE_DIR("devices",  SYSFS_INO_DEVICES, SYSFS_DEVICES_DIR),
    DE_DIR("kernel",   SYSFS_INO_KERNEL,  SYSFS_KERNEL_DIR),
    DE_DIR("fs",       SYSFS_INO_FS,      SYSFS_FS_DIR),
    DE_DIR("block",    SYSFS_INO_BLOCK,   SYSFS_BLOCK_DIR),
    DE_DIR("power",    SYSFS_INO_POWER,   SYSFS_POWER_DIR),
    DE_DIR("module",   SYSFS_INO_MODULE,  SYSFS_MODULE_DIR),
};
#define ROOT_N (sizeof(root_entries)/sizeof(root_entries[0]))

static const sysfs_de_t class_entries[] = {
    DE_DIR(".",      SYSFS_INO_CLASS,       SYSFS_CLASS_DIR),
    DE_DIR("..",     SYSFS_INO_ROOT,        SYSFS_ROOT),
    DE_DIR("net",    SYSFS_INO_CLASS_NET,   SYSFS_CLASS_NET_DIR),
    DE_DIR("block",  SYSFS_INO_CLASS_BLOCK, SYSFS_CLASS_BLOCK_DIR),
    DE_DIR("tty",    SYSFS_INO_CLASS_TTY,   SYSFS_CLASS_TTY_DIR),
};
#define CLASS_N (sizeof(class_entries)/sizeof(class_entries[0]))

static const sysfs_de_t class_net_entries[] = {
    DE_DIR(".",   SYSFS_INO_CLASS_NET,    SYSFS_CLASS_NET_DIR),
    DE_DIR("..",  SYSFS_INO_CLASS,        SYSFS_CLASS_DIR),
    DE_DIR("lo",  SYSFS_INO_CLASS_NET_LO, SYSFS_CLASS_NET_LO_DIR),
};
#define CLASS_NET_N (sizeof(class_net_entries)/sizeof(class_net_entries[0]))

static const sysfs_de_t lo_entries[] = {
    DE_DIR(".",         SYSFS_INO_CLASS_NET_LO,    SYSFS_CLASS_NET_LO_DIR),
    DE_DIR("..",        SYSFS_INO_CLASS_NET,        SYSFS_CLASS_NET_DIR),
    DE_REG("ifindex",   SYSFS_INO_NET_LO_IFINDEX,  SYSFS_NET_LO_IFINDEX),
    DE_REG("operstate", SYSFS_INO_NET_LO_OPERSTATE,SYSFS_NET_LO_OPERSTATE),
    DE_REG("type",      SYSFS_INO_NET_LO_TYPE,     SYSFS_NET_LO_TYPE),
    DE_REG("mtu",       SYSFS_INO_NET_LO_MTU,      SYSFS_NET_LO_MTU),
    DE_REG("address",   SYSFS_INO_NET_LO_ADDRESS,  SYSFS_NET_LO_ADDRESS),
    DE_REG("flags",     SYSFS_INO_NET_LO_FLAGS,    SYSFS_NET_LO_FLAGS),
};
#define LO_N (sizeof(lo_entries)/sizeof(lo_entries[0]))

static const sysfs_de_t bus_entries[] = {
    DE_DIR(".",        SYSFS_INO_BUS,          SYSFS_BUS_DIR),
    DE_DIR("..",       SYSFS_INO_ROOT,         SYSFS_ROOT),
    DE_DIR("pci",      SYSFS_INO_BUS_PCI,      SYSFS_BUS_PCI_DIR),
    DE_DIR("usb",      SYSFS_INO_BUS_USB,      SYSFS_BUS_USB_DIR),
    DE_DIR("platform", SYSFS_INO_BUS_PLATFORM, SYSFS_BUS_PLATFORM_DIR),
};
#define BUS_N (sizeof(bus_entries)/sizeof(bus_entries[0]))

/* PCI, USB, platform bus dirs: just ".", "..", "devices/" */
static const sysfs_de_t pci_entries[] = {
    DE_DIR(".",       SYSFS_INO_BUS_PCI,     SYSFS_BUS_PCI_DIR),
    DE_DIR("..",      SYSFS_INO_BUS,         SYSFS_BUS_DIR),
    DE_DIR("devices", SYSFS_INO_BUS_PCI_DEV, SYSFS_BUS_PCI_DEV_DIR),
};
static const sysfs_de_t usb_entries[] = {
    DE_DIR(".",       SYSFS_INO_BUS_USB,     SYSFS_BUS_USB_DIR),
    DE_DIR("..",      SYSFS_INO_BUS,         SYSFS_BUS_DIR),
    DE_DIR("devices", SYSFS_INO_BUS_USB_DEV, SYSFS_BUS_USB_DEV_DIR),
};
static const sysfs_de_t platform_entries[] = {
    DE_DIR(".",       SYSFS_INO_BUS_PLATFORM,     SYSFS_BUS_PLATFORM_DIR),
    DE_DIR("..",      SYSFS_INO_BUS,              SYSFS_BUS_DIR),
    DE_DIR("devices", SYSFS_INO_BUS_PLATFORM_DEV, SYSFS_BUS_PLATFORM_DEV_DIR),
};
#define PCI_N      (sizeof(pci_entries)/sizeof(pci_entries[0]))
#define USB_N      (sizeof(usb_entries)/sizeof(usb_entries[0]))
#define PLATFORM_N (sizeof(platform_entries)/sizeof(platform_entries[0]))

static const sysfs_de_t kernel_entries[] = {
    DE_DIR(".",         SYSFS_INO_KERNEL,           SYSFS_KERNEL_DIR),
    DE_DIR("..",        SYSFS_INO_ROOT,             SYSFS_ROOT),
    DE_DIR("mm",        SYSFS_INO_KERNEL_MM,        SYSFS_KERNEL_MM_DIR),
    DE_REG("profiling", SYSFS_INO_KERNEL_PROFILING, SYSFS_KERNEL_PROFILING),
};
#define KERNEL_N (sizeof(kernel_entries)/sizeof(kernel_entries[0]))

static const sysfs_de_t mm_entries[] = {
    DE_DIR(".",                    SYSFS_INO_KERNEL_MM,     SYSFS_KERNEL_MM_DIR),
    DE_DIR("..",                   SYSFS_INO_KERNEL,        SYSFS_KERNEL_DIR),
    DE_DIR("transparent_hugepage", SYSFS_INO_KERNEL_MM_THP, SYSFS_KERNEL_MM_THP_DIR),
};
#define MM_N (sizeof(mm_entries)/sizeof(mm_entries[0]))

static const sysfs_de_t thp_entries[] = {
    DE_DIR(".",              SYSFS_INO_KERNEL_MM_THP,  SYSFS_KERNEL_MM_THP_DIR),
    DE_DIR("..",             SYSFS_INO_KERNEL_MM,      SYSFS_KERNEL_MM_DIR),
    DE_REG("enabled",        SYSFS_INO_THP_ENABLED,    SYSFS_THP_ENABLED),
    DE_REG("defrag",         SYSFS_INO_THP_DEFRAG,     SYSFS_THP_DEFRAG),
    DE_REG("use_zero_pages", SYSFS_INO_THP_ZERO_PAGES, SYSFS_THP_ZERO_PAGES),
};
#define THP_N (sizeof(thp_entries)/sizeof(thp_entries[0]))

static const sysfs_de_t fs_entries[] = {
    DE_DIR(".",      SYSFS_INO_FS,         SYSFS_FS_DIR),
    DE_DIR("..",     SYSFS_INO_ROOT,       SYSFS_ROOT),
    DE_DIR("cgroup", SYSFS_INO_FS_CGROUP,  SYSFS_FS_CGROUP_DIR),
};
#define FS_N (sizeof(fs_entries)/sizeof(fs_entries[0]))

static const sysfs_de_t power_entries[] = {
    DE_DIR(".",     SYSFS_INO_POWER,       SYSFS_POWER_DIR),
    DE_DIR("..",    SYSFS_INO_ROOT,        SYSFS_ROOT),
    DE_REG("state", SYSFS_INO_POWER_STATE, SYSFS_POWER_STATE),
};
#define POWER_N (sizeof(power_entries)/sizeof(power_entries[0]))

/* /sys/devices/ → system/ */
static const sysfs_de_t devices_entries[] = {
    DE_DIR(".",      SYSFS_INO_DEVICES,        SYSFS_DEVICES_DIR),
    DE_DIR("..",     SYSFS_INO_ROOT,           SYSFS_ROOT),
    DE_DIR("system", SYSFS_INO_DEVICES_SYSTEM, SYSFS_DEVICES_SYSTEM_DIR),
};
#define DEVICES_N (sizeof(devices_entries)/sizeof(devices_entries[0]))

/* /sys/devices/system/ → cpu/ */
static const sysfs_de_t system_entries[] = {
    DE_DIR(".",   SYSFS_INO_DEVICES_SYSTEM, SYSFS_DEVICES_SYSTEM_DIR),
    DE_DIR("..",  SYSFS_INO_DEVICES,        SYSFS_DEVICES_DIR),
    DE_DIR("cpu", SYSFS_INO_CPU,            SYSFS_CPU_DIR),
};
#define SYSTEM_N (sizeof(system_entries)/sizeof(system_entries[0]))

/* /sys/devices/system/cpu/ */
static const sysfs_de_t cpu_entries[] = {
    DE_DIR(".",         SYSFS_INO_CPU,           SYSFS_CPU_DIR),
    DE_DIR("..",        SYSFS_INO_DEVICES_SYSTEM, SYSFS_DEVICES_SYSTEM_DIR),
    DE_REG("online",    SYSFS_INO_CPU_ONLINE,    SYSFS_CPU_ONLINE),
    DE_REG("possible",  SYSFS_INO_CPU_POSSIBLE,  SYSFS_CPU_POSSIBLE),
    DE_REG("present",   SYSFS_INO_CPU_PRESENT,   SYSFS_CPU_PRESENT),
    DE_REG("kernel_max",SYSFS_INO_CPU_KERNEL_MAX,SYSFS_CPU_KERNEL_MAX),
    DE_DIR("cpu0",      SYSFS_INO_CPU0,          SYSFS_CPU0_DIR),
};
#define CPU_N (sizeof(cpu_entries)/sizeof(cpu_entries[0]))

/* /sys/devices/system/cpu/cpu0/ */
static const sysfs_de_t cpu0_entries[] = {
    DE_DIR(".",        SYSFS_INO_CPU0,        SYSFS_CPU0_DIR),
    DE_DIR("..",       SYSFS_INO_CPU,         SYSFS_CPU_DIR),
    DE_REG("online",   SYSFS_INO_CPU0_ONLINE, SYSFS_CPU0_ONLINE),
    DE_DIR("topology", SYSFS_INO_CPU0_TOPOLOGY,SYSFS_CPU0_TOPOLOGY_DIR),
};
#define CPU0_N (sizeof(cpu0_entries)/sizeof(cpu0_entries[0]))

/* /sys/devices/system/cpu/cpu0/topology/ */
static const sysfs_de_t cpu0_topology_entries[] = {
    DE_DIR(".",                     SYSFS_INO_CPU0_TOPOLOGY,  SYSFS_CPU0_TOPOLOGY_DIR),
    DE_DIR("..",                    SYSFS_INO_CPU0,           SYSFS_CPU0_DIR),
    DE_REG("core_id",               SYSFS_INO_CPU0_CORE_ID,   SYSFS_CPU0_CORE_ID),
    DE_REG("physical_package_id",   SYSFS_INO_CPU0_PKG_ID,    SYSFS_CPU0_PKG_ID),
    DE_REG("core_siblings",         SYSFS_INO_CPU0_CORE_SIB,  SYSFS_CPU0_CORE_SIBLINGS),
    DE_REG("thread_siblings",       SYSFS_INO_CPU0_THREAD_SIB,SYSFS_CPU0_THREAD_SIBLINGS),
};
#define CPU0_TOPO_N (sizeof(cpu0_topology_entries)/sizeof(cpu0_topology_entries[0]))

/* Generic "empty dir" readdir: just "." and ".." */
static int sysfs_empty_readdir(struct fut_vnode *dir, uint64_t *cookie,
                                struct fut_vdirent *de) {
    sysfs_node_t *n = (sysfs_node_t *)dir->fs_data;
    uint64_t idx = *cookie;
    if (idx == 0)
        return sysfs_emit_de(de, cookie, 0, dir->ino,
                             FUT_VDIR_TYPE_DIR, ".");
    if (idx == 1)
        return sysfs_emit_de(de, cookie, 1, dir->ino,
                             FUT_VDIR_TYPE_DIR, "..");
    (void)n;
    return -ENOENT;
}

/* Generic table-driven readdir */
static int sysfs_table_readdir(const sysfs_de_t *tbl, size_t tbl_n,
                                uint64_t *cookie, struct fut_vdirent *de) {
    uint64_t idx = *cookie;
    if (idx >= tbl_n) return -ENOENT;
    return sysfs_emit_de(de, cookie, idx,
                         tbl[idx].ino, tbl[idx].dtype, tbl[idx].name);
}

static int sysfs_dir_readdir(struct fut_vnode *dir, uint64_t *cookie,
                              struct fut_vdirent *de) {
    if (!dir || !cookie || !de) return -EINVAL;
    sysfs_node_t *n = (sysfs_node_t *)dir->fs_data;
    if (!n) return -EIO;

    switch (n->kind) {
        case SYSFS_ROOT:             return sysfs_table_readdir(root_entries,      ROOT_N,      cookie, de);
        case SYSFS_CLASS_DIR:        return sysfs_table_readdir(class_entries,    CLASS_N,    cookie, de);
        case SYSFS_CLASS_NET_DIR: {
            /* First 2 entries: . and .. (from static table) */
            uint64_t idx = *cookie;
            if (idx < 2)
                return sysfs_table_readdir(class_net_entries, CLASS_NET_N, cookie, de);
            /* Dynamic entries: enumerate all active interfaces */
            int iface_idx = (int)(idx - 2);
            int seen = 0;
            for (int i = 1; i <= 16; i++) {
                struct net_iface *iface = netif_by_index(i);
                if (iface && iface->active) {
                    if (seen == iface_idx) {
                        de->d_ino = SYSFS_INO_CLASS_NET_LO + (uint64_t)i * 100;
                        de->d_off = (int64_t)(idx + 1);
                        de->d_type = FUT_VDIR_TYPE_DIR;
                        de->d_reclen = sizeof(*de);
                        size_t nlen = 0;
                        while (nlen < 15 && iface->name[nlen]) nlen++;
                        __builtin_memcpy(de->d_name, iface->name, nlen);
                        de->d_name[nlen] = '\0';
                        *cookie = idx + 1;
                        return 1;
                    }
                    seen++;
                }
            }
            return -ENOENT;
        }
        case SYSFS_CLASS_BLOCK_DIR: {
            /* Dynamic entries: enumerate registered block devices */
            uint64_t idx = *cookie;
            if (idx == 0) {
                de->d_ino = SYSFS_INO_CLASS_BLOCK;
                de->d_off = 1; de->d_type = FUT_VDIR_TYPE_DIR;
                de->d_reclen = sizeof(*de);
                de->d_name[0] = '.'; de->d_name[1] = '\0';
                *cookie = 1; return 1;
            }
            if (idx == 1) {
                de->d_ino = SYSFS_INO_CLASS;
                de->d_off = 2; de->d_type = FUT_VDIR_TYPE_DIR;
                de->d_reclen = sizeof(*de);
                de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
                *cookie = 2; return 1;
            }
            /* Walk block device list */
            extern struct fut_blockdev *fut_blockdev_first(void);
            int target = (int)(idx - 2);
            int seen = 0;
            for (struct fut_blockdev *bd = fut_blockdev_first(); bd; bd = bd->next) {
                if (seen == target) {
                    de->d_ino = SYSFS_INO_CLASS_BLOCK + 100 + (uint64_t)seen;
                    de->d_off = (int64_t)(idx + 1);
                    de->d_type = FUT_VDIR_TYPE_DIR;
                    de->d_reclen = sizeof(*de);
                    size_t nlen = 0;
                    while (nlen < 31 && bd->name[nlen]) nlen++;
                    __builtin_memcpy(de->d_name, bd->name, nlen);
                    de->d_name[nlen] = '\0';
                    *cookie = idx + 1;
                    return 1;
                }
                seen++;
            }
            return -ENOENT;
        }
        case SYSFS_BUS_PCI_DEV_DIR: {
            /* Dynamic: enumerate real PCI devices from pci.c */
            uint64_t idx = *cookie;
            if (idx == 0) {
                de->d_ino = SYSFS_INO_BUS_PCI_DEV;
                de->d_off = 1; de->d_type = FUT_VDIR_TYPE_DIR;
                de->d_reclen = sizeof(*de);
                de->d_name[0] = '.'; de->d_name[1] = '\0';
                *cookie = 1; return 1;
            }
            if (idx == 1) {
                de->d_ino = SYSFS_INO_BUS_PCI;
                de->d_off = 2; de->d_type = FUT_VDIR_TYPE_DIR;
                de->d_reclen = sizeof(*de);
                de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
                *cookie = 2; return 1;
            }
            extern int pci_device_count(void);
            extern const struct pci_device *pci_get_device(int index);
            int target = (int)(idx - 2);
            if (target < pci_device_count()) {
                const struct pci_device *pd = pci_get_device(target);
                if (pd) {
                    de->d_ino = SYSFS_INO_BUS_PCI_DEV + 10 + (uint64_t)target;
                    de->d_off = (int64_t)(idx + 1);
                    de->d_type = FUT_VDIR_TYPE_DIR;
                    de->d_reclen = sizeof(*de);
                    /* Format: DDDD:BB:DD.F (domain:bus:dev.func) */
                    static const char hex[] = "0123456789abcdef";
                    char *n = de->d_name;
                    n[0] = '0'; n[1] = '0'; n[2] = '0'; n[3] = '0'; n[4] = ':';
                    n[5] = hex[(pd->bus >> 4) & 0xF]; n[6] = hex[pd->bus & 0xF]; n[7] = ':';
                    n[8] = hex[(pd->dev >> 4) & 0xF]; n[9] = hex[pd->dev & 0xF]; n[10] = '.';
                    n[11] = (char)('0' + pd->func); n[12] = '\0';
                    *cookie = idx + 1;
                    return 1;
                }
            }
            return -ENOENT;
        }
        case SYSFS_CLASS_NET_LO_DIR: return sysfs_table_readdir(lo_entries,       LO_N,       cookie, de);
        case SYSFS_BUS_DIR:          return sysfs_table_readdir(bus_entries,      BUS_N,      cookie, de);
        case SYSFS_BUS_PCI_DIR:      return sysfs_table_readdir(pci_entries,      PCI_N,      cookie, de);
        case SYSFS_BUS_USB_DIR:      return sysfs_table_readdir(usb_entries,      USB_N,      cookie, de);
        case SYSFS_BUS_PLATFORM_DIR: return sysfs_table_readdir(platform_entries, PLATFORM_N, cookie, de);
        case SYSFS_KERNEL_DIR:       return sysfs_table_readdir(kernel_entries,   KERNEL_N,   cookie, de);
        case SYSFS_KERNEL_MM_DIR:    return sysfs_table_readdir(mm_entries,       MM_N,       cookie, de);
        case SYSFS_KERNEL_MM_THP_DIR:return sysfs_table_readdir(thp_entries,      THP_N,      cookie, de);
        case SYSFS_FS_DIR:           return sysfs_table_readdir(fs_entries,       FS_N,       cookie, de);
        case SYSFS_POWER_DIR:        return sysfs_table_readdir(power_entries,    POWER_N,    cookie, de);
        case SYSFS_DEVICES_DIR:      return sysfs_table_readdir(devices_entries,  DEVICES_N,  cookie, de);
        case SYSFS_DEVICES_SYSTEM_DIR: return sysfs_table_readdir(system_entries, SYSTEM_N,   cookie, de);
        case SYSFS_CPU_DIR:          return sysfs_table_readdir(cpu_entries,      CPU_N,      cookie, de);
        case SYSFS_CPU0_DIR:         return sysfs_table_readdir(cpu0_entries,     CPU0_N,     cookie, de);
        case SYSFS_CPU0_TOPOLOGY_DIR:return sysfs_table_readdir(cpu0_topology_entries, CPU0_TOPO_N, cookie, de);
        default:
            return sysfs_empty_readdir(dir, cookie, de);
    }
}

/* Lookup child by name in a table */
static int sysfs_table_lookup(struct fut_mount *mount,
                               const sysfs_de_t *tbl, size_t tbl_n,
                               const char *name, struct fut_vnode **result) {
    for (size_t i = 0; i < tbl_n; i++) {
        if (STREQ(tbl[i].name, ".") || STREQ(tbl[i].name, "..")) continue;
        if (STREQ(tbl[i].name, name)) {
            enum fut_vnode_type vtype =
                (tbl[i].dtype == FUT_VDIR_TYPE_DIR) ? VN_DIR : VN_REG;
            uint32_t mode = (vtype == VN_DIR) ? 0040555 : 0100444;
            *result = sysfs_alloc_vnode(mount, vtype, tbl[i].ino,
                                        mode, tbl[i].kind);
            return *result ? 0 : -ENOMEM;
        }
    }
    return -ENOENT;
}

static int sysfs_dir_lookup(struct fut_vnode *dir, const char *name,
                             struct fut_vnode **result) {
    if (!dir || !name || !result) return -EINVAL;
    sysfs_node_t *n = (sysfs_node_t *)dir->fs_data;
    if (!n) return -EIO;
    struct fut_mount *mnt = dir->mount;

    switch (n->kind) {
        case SYSFS_ROOT:
            return sysfs_table_lookup(mnt, root_entries, ROOT_N, name, result);
        case SYSFS_CLASS_DIR:
            return sysfs_table_lookup(mnt, class_entries, CLASS_N, name, result);
        case SYSFS_CLASS_NET_DIR: {
            /* First check static table (has ".", "..", "lo") */
            int rc = sysfs_table_lookup(mnt, class_net_entries, CLASS_NET_N, name, result);
            if (rc == 0) return 0;
            /* Dynamic lookup: any registered interface by name */
            struct net_iface *iface = netif_by_name(name);
            if (iface && iface->active) {
                /* Use a synthetic inode and the lo_entries kind for attributes.
                 * We reuse SYSFS_CLASS_NET_LO_DIR kind — the read handler uses
                 * the interface name from the vnode path context. */
                *result = sysfs_alloc_vnode(mnt, VN_DIR,
                    SYSFS_INO_CLASS_NET_LO + (uint64_t)iface->index * 100,
                    0040555, SYSFS_CLASS_NET_LO_DIR);
                return *result ? 0 : -ENOMEM;
            }
            return -ENOENT;
        }
        case SYSFS_CLASS_NET_LO_DIR:
            return sysfs_table_lookup(mnt, lo_entries, LO_N, name, result);
        case SYSFS_BUS_DIR:
            return sysfs_table_lookup(mnt, bus_entries, BUS_N, name, result);
        case SYSFS_BUS_PCI_DIR:
            return sysfs_table_lookup(mnt, pci_entries, PCI_N, name, result);
        case SYSFS_BUS_USB_DIR:
            return sysfs_table_lookup(mnt, usb_entries, USB_N, name, result);
        case SYSFS_BUS_PLATFORM_DIR:
            return sysfs_table_lookup(mnt, platform_entries, PLATFORM_N, name, result);
        case SYSFS_KERNEL_DIR:
            return sysfs_table_lookup(mnt, kernel_entries, KERNEL_N, name, result);
        case SYSFS_KERNEL_MM_DIR:
            return sysfs_table_lookup(mnt, mm_entries, MM_N, name, result);
        case SYSFS_KERNEL_MM_THP_DIR:
            return sysfs_table_lookup(mnt, thp_entries, THP_N, name, result);
        case SYSFS_FS_DIR:
            return sysfs_table_lookup(mnt, fs_entries, FS_N, name, result);
        case SYSFS_POWER_DIR:
            return sysfs_table_lookup(mnt, power_entries, POWER_N, name, result);
        case SYSFS_DEVICES_DIR:
            return sysfs_table_lookup(mnt, devices_entries, DEVICES_N, name, result);
        case SYSFS_DEVICES_SYSTEM_DIR:
            return sysfs_table_lookup(mnt, system_entries, SYSTEM_N, name, result);
        case SYSFS_CPU_DIR:
            return sysfs_table_lookup(mnt, cpu_entries, CPU_N, name, result);
        case SYSFS_CPU0_DIR:
            return sysfs_table_lookup(mnt, cpu0_entries, CPU0_N, name, result);
        case SYSFS_CPU0_TOPOLOGY_DIR:
            return sysfs_table_lookup(mnt, cpu0_topology_entries, CPU0_TOPO_N, name, result);
        default:
            /* Empty directories: no children beyond . and .. */
            return -ENOENT;
    }
}

static int sysfs_dir_open(struct fut_vnode *vnode, int flags) {
    (void)vnode; (void)flags; return 0;
}
static int sysfs_dir_close(struct fut_vnode *vnode) {
    (void)vnode; return 0;
}
static ssize_t sysfs_dir_read(struct fut_vnode *v, void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EISDIR;
}
static ssize_t sysfs_dir_write(struct fut_vnode *v, const void *b, size_t s, uint64_t o) {
    (void)v; (void)b; (void)s; (void)o; return -EISDIR;
}

/* sysfs_dir_ops — runtime initialized in sysfs_mount */

/* ============================================================
 *   Mount / Unmount
 * ============================================================ */

static int sysfs_mount(const char *device, int flags, void *data,
                       fut_handle_t block_device_handle,
                       struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)block_device_handle;

    /* Runtime-init vnode ops (ARM64 relocation safety) */
    if (!sysfs_file_ops.read) {
        sysfs_file_ops.open = sysfs_file_open;
        sysfs_file_ops.close = sysfs_file_close;
        sysfs_file_ops.read = sysfs_file_read;
        sysfs_file_ops.write = sysfs_file_write;
        sysfs_dir_ops.open = sysfs_dir_open;
        sysfs_dir_ops.close = sysfs_dir_close;
        sysfs_dir_ops.read = sysfs_dir_read;
        sysfs_dir_ops.write = sysfs_dir_write;
        sysfs_dir_ops.readdir = sysfs_dir_readdir;
        sysfs_dir_ops.lookup = sysfs_dir_lookup;
    }

    struct fut_mount *mount = fut_malloc(sizeof(struct fut_mount));
    if (!mount) return -ENOMEM;

    struct fut_vnode *root = sysfs_alloc_vnode(mount, VN_DIR,
                                                SYSFS_INO_ROOT, 0040555,
                                                SYSFS_ROOT);
    if (!root) { fut_free(mount); return -ENOMEM; }
    root->mount = mount;

    mount->device              = NULL;
    mount->mountpoint          = NULL;
    mount->fs                  = NULL;
    mount->root                = root;
    mount->flags               = flags;
    mount->fs_data             = NULL;
    mount->next                = NULL;
    mount->block_device_handle = block_device_handle;

    *mount_out = mount;
    return 0;
}

static int sysfs_unmount(struct fut_mount *mount) {
    if (!mount) return -EINVAL;
    if (mount->root) {
        sysfs_node_t *n = (sysfs_node_t *)mount->root->fs_data;
        if (n) fut_free(n);
        fut_free(mount->root);
    }
    fut_free(mount);
    return 0;
}

/* ============================================================
 *   Registration
 * ============================================================ */

static struct fut_fs_type sysfs_type;

void fut_sysfs_init(void) {
    sysfs_type.name    = "sysfs";
    sysfs_type.mount   = sysfs_mount;
    sysfs_type.unmount = sysfs_unmount;
    fut_vfs_register_fs(&sysfs_type);
}
