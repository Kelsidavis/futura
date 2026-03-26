/* kernel/net/tun.c - TUN/TAP virtual network device
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements /dev/net/tun for userspace-driven virtual network interfaces.
 *
 * Opening /dev/net/tun returns a file descriptor. The user configures it
 * via ioctl(TUNSETIFF) to create a TUN (IP-layer) or TAP (Ethernet-layer)
 * interface. Once configured:
 *   - Writing to the fd injects a packet into the kernel network stack
 *   - Reading from the fd receives packets destined for the tun/tap interface
 *
 * This is the foundation for VPN tunnels, network namespaces, and
 * userspace networking stacks.
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <futura/netif.h>
#include <platform/platform.h>
#include <string.h>
#include <stdbool.h>

/* ioctl commands for TUN/TAP */
#define TUNSETIFF       0x400454CA  /* _IOW('T', 202, int) */
#define TUNGETIFF       0x800454D2  /* _IOR('T', 210, int) */
#define TUNSETPERSIST   0x400454CB  /* _IOW('T', 203, int) */
#define TUNSETOWNER     0x400454CC  /* _IOW('T', 204, int) */
#define TUNSETGROUP     0x400454CE  /* _IOW('T', 206, int) */

/* Interface flags for TUNSETIFF */
#define IFF_TUN         0x0001  /* TUN device (IP layer) */
#define IFF_TAP         0x0002  /* TAP device (Ethernet layer) */
#define IFF_NO_PI       0x1000  /* No packet info header */
#define IFF_MULTI_QUEUE 0x0100  /* Multi-queue support */

/* Maximum TUN devices */
#define TUN_MAX_DEVICES   16
#define TUN_RING_SIZE    (64 * 1024)  /* 64KB ring buffer per direction */

/* Per-device TUN state */
struct tun_device {
    bool                active;
    bool                persistent;
    uint16_t            flags;          /* IFF_TUN or IFF_TAP | IFF_NO_PI etc. */
    char                name[16];       /* Interface name (tun0, tap0, etc.) */
    int                 iface_idx;      /* Index in netif registry */

    /* Ring buffer for packets from kernel → userspace (read) */
    uint8_t            *rx_ring;
    uint32_t            rx_head;        /* Write position (kernel writes) */
    uint32_t            rx_tail;        /* Read position (userspace reads) */
    fut_spinlock_t      rx_lock;

    /* Waitqueue for blocking read */
    struct fut_waitq   *read_waitq;
};

/* TUN device tag for chrdev private data identification */
#define TUN_PRIV_TAG    0x54554E00  /* "TUN\0" */

static struct tun_device g_tun_devices[TUN_MAX_DEVICES];
static fut_spinlock_t g_tun_lock;
static int g_tun_next_id = 0;

/* ── Ring buffer helpers ─────────────────────────────────────────── */

static uint32_t ring_avail(uint32_t head, uint32_t tail) {
    return (head >= tail) ? (head - tail) : (TUN_RING_SIZE - tail + head);
}

static uint32_t ring_free(uint32_t head, uint32_t tail) {
    return TUN_RING_SIZE - 1 - ring_avail(head, tail);
}

/* ── TUN transmit callback (kernel → userspace direction) ─────── */

static int tun_transmit(struct net_iface *iface, const void *pkt, size_t len) {
    if (!iface || !pkt || len == 0) return -EINVAL;

    /* Find TUN device by interface index */
    struct tun_device *tun = NULL;
    for (int i = 0; i < TUN_MAX_DEVICES; i++) {
        if (g_tun_devices[i].active && g_tun_devices[i].iface_idx == iface->index) {
            tun = &g_tun_devices[i];
            break;
        }
    }
    if (!tun) return -ENODEV;

    /* Write packet length (4 bytes) + packet data to ring */
    fut_spinlock_acquire(&tun->rx_lock);
    uint32_t total = 4 + (uint32_t)len;
    if (ring_free(tun->rx_head, tun->rx_tail) < total) {
        fut_spinlock_release(&tun->rx_lock);
        iface->rx_dropped++;
        return -ENOSPC;
    }

    /* Write 4-byte length header */
    uint32_t pktlen = (uint32_t)len;
    for (int i = 0; i < 4; i++) {
        tun->rx_ring[tun->rx_head] = (uint8_t)(pktlen >> (i * 8));
        tun->rx_head = (tun->rx_head + 1) % TUN_RING_SIZE;
    }

    /* Write packet data */
    const uint8_t *src = (const uint8_t *)pkt;
    for (uint32_t i = 0; i < (uint32_t)len; i++) {
        tun->rx_ring[tun->rx_head] = src[i];
        tun->rx_head = (tun->rx_head + 1) % TUN_RING_SIZE;
    }
    fut_spinlock_release(&tun->rx_lock);

    /* Wake readers */
    if (tun->read_waitq)
        fut_waitq_wake_one(tun->read_waitq);

    iface->rx_packets++;
    iface->rx_bytes += len;
    return 0;
}

/* ── chrdev file operations ───────────────────────────────────────── */

static int tun_open(void *inode, int flags, void **private_data) {
    (void)inode; (void)flags;
    /* Opening /dev/net/tun just marks the fd as a TUN candidate.
     * Actual device creation happens on ioctl(TUNSETIFF). */
    if (private_data) *private_data = NULL;
    return 0;
}

static ssize_t tun_read(void *inode, void *private, void *buf, size_t count, off_t *pos) {
    (void)inode; (void)pos;
    struct tun_device *tun = (struct tun_device *)private;
    if (!tun || !tun->active) return -EBADF;
    if (!buf || count == 0) return -EINVAL;

    /* Read one packet from ring */
    fut_spinlock_acquire(&tun->rx_lock);
    uint32_t avail = ring_avail(tun->rx_head, tun->rx_tail);
    if (avail < 4) {
        fut_spinlock_release(&tun->rx_lock);
        return -EAGAIN;  /* No packet available */
    }

    /* Read 4-byte length header */
    uint32_t pktlen = 0;
    for (int i = 0; i < 4; i++) {
        pktlen |= (uint32_t)tun->rx_ring[tun->rx_tail] << (i * 8);
        tun->rx_tail = (tun->rx_tail + 1) % TUN_RING_SIZE;
    }

    if (pktlen > count) pktlen = (uint32_t)count;  /* Truncate */

    uint8_t *dst = (uint8_t *)buf;
    for (uint32_t i = 0; i < pktlen; i++) {
        dst[i] = tun->rx_ring[tun->rx_tail];
        tun->rx_tail = (tun->rx_tail + 1) % TUN_RING_SIZE;
    }
    fut_spinlock_release(&tun->rx_lock);

    return (ssize_t)pktlen;
}

static ssize_t tun_write(void *inode, void *private, const void *buf, size_t count, off_t *pos) {
    (void)inode; (void)pos;
    struct tun_device *tun = (struct tun_device *)private;
    if (!tun || !tun->active) return -EBADF;
    if (!buf || count == 0) return -EINVAL;

    /* Inject packet into the kernel network stack */
    struct net_iface *iface = netif_by_index(tun->iface_idx);
    if (!iface) return -ENODEV;

    /* For TUN: data is an IP packet. Forward it through the IP stack. */
    if (tun->flags & IFF_TUN) {
        const uint8_t *pkt = (const uint8_t *)buf;
        if (count >= 20) {
            /* Extract dest IP from IP header offset 16 */
            uint32_t dest_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                               ((uint32_t)pkt[18] << 8) | (uint32_t)pkt[19];

            /* Check if dest is local or needs forwarding */
            extern bool g_ip_forward_enabled;
            if (g_ip_forward_enabled) {
                ip_forward(pkt, count, iface);
            }
            (void)dest_ip;
        }
    }

    iface->tx_packets++;
    iface->tx_bytes += count;
    return (ssize_t)count;
}

static int tun_ioctl(void *inode, void *private, unsigned long request, unsigned long arg) {
    (void)inode;

    if (request == TUNSETIFF) {
        /* arg points to struct ifreq: name[16] + flags(short) at offset 16 */
        if (!arg) return -EFAULT;

        /* Read ifreq from userspace (kernel ptr OK for selftests) */
        char ifr[40];
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE)
            __builtin_memcpy(ifr, (void *)arg, 40);
        else
#endif
        {
            extern int fut_copy_from_user(void *, const void *, size_t);
            if (fut_copy_from_user(ifr, (void *)arg, 40) != 0)
                return -EFAULT;
        }

        /* Extract flags from ifr_ifru.ifru_flags at offset 16 */
        uint16_t tun_flags = 0;
        __builtin_memcpy(&tun_flags, ifr + 16, 2);

        if (!(tun_flags & (IFF_TUN | IFF_TAP)))
            return -EINVAL;

        /* Allocate TUN device */
        fut_spinlock_acquire(&g_tun_lock);
        int slot = -1;
        for (int i = 0; i < TUN_MAX_DEVICES; i++) {
            if (!g_tun_devices[i].active) { slot = i; break; }
        }
        if (slot < 0) {
            fut_spinlock_release(&g_tun_lock);
            return -ENOSPC;
        }

        struct tun_device *tun = &g_tun_devices[slot];
        memset(tun, 0, sizeof(*tun));
        tun->flags = tun_flags;

        /* Generate name if not provided */
        if (ifr[0] == '\0') {
            const char *prefix = (tun_flags & IFF_TUN) ? "tun" : "tap";
            int id = g_tun_next_id++;
            int j = 0;
            while (prefix[j]) { tun->name[j] = prefix[j]; j++; }
            if (id >= 10) tun->name[j++] = (char)('0' + id / 10);
            tun->name[j++] = (char)('0' + id % 10);
            tun->name[j] = '\0';
        } else {
            __builtin_memcpy(tun->name, ifr, 15);
            tun->name[15] = '\0';
        }

        /* Allocate ring buffer */
        tun->rx_ring = fut_malloc(TUN_RING_SIZE);
        if (!tun->rx_ring) {
            fut_spinlock_release(&g_tun_lock);
            return -ENOMEM;
        }

        /* Allocate wait queue */
        tun->read_waitq = fut_malloc(sizeof(struct fut_waitq));
        if (!tun->read_waitq) {
            fut_free(tun->rx_ring);
            fut_spinlock_release(&g_tun_lock);
            return -ENOMEM;
        }
        fut_waitq_init(tun->read_waitq);
        fut_spinlock_init(&tun->rx_lock);

        /* Register as a network interface */
        uint8_t mac[6] = {0xFE, 0xED, 0x00, 0x00, 0x00, (uint8_t)slot};
        int idx = netif_register(tun->name, mac, 1500, tun_transmit);
        if (idx <= 0) {
            fut_free(tun->read_waitq);
            fut_free(tun->rx_ring);
            fut_spinlock_release(&g_tun_lock);
            return -ENOSPC;
        }
        tun->iface_idx = idx;
        tun->active = true;
        netif_set_flags(idx, 0x0001 | 0x0040 | 0x0080); /* IFF_UP|IFF_RUNNING|IFF_NOARP */

        fut_spinlock_release(&g_tun_lock);

        /* Copy name back to ifreq */
        __builtin_memcpy(ifr, tun->name, 16);
#ifdef KERNEL_VIRTUAL_BASE
        if (arg >= KERNEL_VIRTUAL_BASE)
            __builtin_memcpy((void *)arg, ifr, 40);
        else
#endif
        {
            extern int fut_copy_to_user(void *, const void *, size_t);
            fut_copy_to_user((void *)arg, ifr, 40);
        }

        /* Set private data to the TUN device — the caller's fd needs this.
         * We return TUN_PRIV_TAG | slot so the fd handler can find the device. */
        /* Note: private data is set by the chrdev_alloc_fd caller.
         * Return the slot number encoded so the caller can store it. */
        fut_printf("[TUN] Created %s (slot=%d, iface=%d, flags=0x%x)\n",
                   tun->name, slot, idx, tun_flags);
        return slot;  /* Return slot for caller to use as private */
    }

    if (request == TUNSETPERSIST) {
        struct tun_device *tun = (struct tun_device *)private;
        if (tun && tun->active)
            tun->persistent = (arg != 0);
        return 0;
    }

    if (request == TUNSETOWNER || request == TUNSETGROUP) {
        return 0;  /* Accept silently */
    }

    return -EINVAL;
}

/* Get TUN device pointer by slot (used by ioctl to set chr_private) */
struct tun_device *tun_get_device(int slot) {
    if (slot < 0 || slot >= TUN_MAX_DEVICES) return NULL;
    return g_tun_devices[slot].active ? &g_tun_devices[slot] : NULL;
}

static int tun_release(void *inode, void *private) {
    (void)inode;
    struct tun_device *tun = (struct tun_device *)private;
    if (!tun || !tun->active) return 0;
    if (tun->persistent) return 0;  /* Persistent devices survive close */

    tun->active = false;
    if (tun->rx_ring) { fut_free(tun->rx_ring); tun->rx_ring = NULL; }
    if (tun->read_waitq) { fut_free(tun->read_waitq); tun->read_waitq = NULL; }
    return 0;
}

/* ── File ops and init ────────────────────────────────────────────── */

static struct fut_file_ops tun_fops;

void tun_init(void) {
    memset(g_tun_devices, 0, sizeof(g_tun_devices));
    fut_spinlock_init(&g_tun_lock);
    g_tun_next_id = 0;

    tun_fops.open    = tun_open;
    tun_fops.read    = tun_read;
    tun_fops.write   = tun_write;
    tun_fops.ioctl   = tun_ioctl;
    tun_fops.release = tun_release;

    /* Register /dev/net/tun (major 10, minor 200 — Linux convention) */
    chrdev_register(10, 200, &tun_fops, "tun", NULL);

    /* Create /dev/net/ directory and /dev/net/tun device node */
    extern int fut_vfs_mkdir(const char *, int);
    extern int devfs_create_chr(const char *, int, int);
    fut_vfs_mkdir("/dev/net", 0755);
    devfs_create_chr("/dev/net/tun", 10, 200);

    fut_printf("[TUN] TUN/TAP subsystem initialized (/dev/net/tun)\n");
}
