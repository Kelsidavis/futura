/* hci.h - Bluetooth Host Controller Interface (HCI) core
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Minimal in-kernel HCI registry.  Bluetooth transports (BCM4378
 * PCIe BT function, BCM43455 UART on RPi, virtio-bt for QEMU)
 * register a `fut_hci_dev` here; consumers call into HCI through
 * the device's `send_cmd` callback.  Events flow back via
 * fut_hci_dispatch_event from the transport's IRQ/poll path.
 *
 * Scope: this is bring-up scaffolding.  We deliberately don't model
 * the full Bluetooth stack (L2CAP, RFCOMM, GATT, profiles) — that
 * lives on top of this layer when there's an actual transport
 * working.
 */

#ifndef __FUTURA_HCI_H__
#define __FUTURA_HCI_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FUT_HCI_NAME_MAX        16
#define FUT_HCI_MAX_DEVICES     4
#define FUT_HCI_CMD_PKT_MAX     258  /* 3-byte header + 255-byte param */
#define FUT_HCI_EVT_PKT_MAX     258
#define FUT_HCI_ACL_PKT_MAX     1027 /* 4-byte header + 1023-byte payload */

/* HCI packet types — first byte of every HCI packet on the wire */
#define FUT_HCI_CMD_PKT         0x01
#define FUT_HCI_ACL_PKT         0x02
#define FUT_HCI_SCO_PKT         0x03
#define FUT_HCI_EVT_PKT         0x04
#define FUT_HCI_ISO_PKT         0x05

/* HCI device types — informational, lets a future consumer pick a
 * specific transport (e.g. UART vs PCIe).  Not used for dispatch. */
typedef enum {
    FUT_HCI_TYPE_UNKNOWN = 0,
    FUT_HCI_TYPE_USB     = 1,
    FUT_HCI_TYPE_UART    = 2,
    FUT_HCI_TYPE_PCIE    = 3,
    FUT_HCI_TYPE_VIRTIO  = 4,
} fut_hci_dev_type_t;

/* Transport callbacks.  All are required.  `cookie` is the value
 * passed to fut_hci_register and is forwarded to every callback. */
typedef struct {
    /* Send an HCI command (CMD packet, leading 0x01 byte assumed
     * already prepended by caller).  Returns 0 on success or a
     * negative errno. */
    int (*send_cmd)(void *cookie, const uint8_t *pkt, size_t len);

    /* Send an HCI ACL data packet (leading 0x02 byte already
     * prepended).  Returns 0 on success or negative errno. */
    int (*send_acl)(void *cookie, const uint8_t *pkt, size_t len);

    /* Bring the transport up (power-on + sync).  Called after
     * register and again any time we recover from a transport-level
     * failure.  Returns 0 on success or negative errno. */
    int (*open)(void *cookie);

    /* Tear the transport down (power-off).  Always succeeds. */
    void (*close)(void *cookie);
} fut_hci_ops_t;

/* Event sink — installed by the HCI core consumer.  The transport
 * calls fut_hci_dispatch_event when a packet arrives; we route to
 * the installed sink.  Sink callbacks must be re-entrant and may
 * run from interrupt context. */
typedef int (*fut_hci_event_sink_t)(void *cookie,
                                    uint8_t pkt_type,
                                    const uint8_t *pkt,
                                    size_t len);

typedef struct fut_hci_dev {
    char                 name[FUT_HCI_NAME_MAX];
    fut_hci_dev_type_t   type;
    const fut_hci_ops_t *ops;
    void                *cookie;
    bool                 open;          /* true after ops->open succeeded */
    fut_hci_event_sink_t event_sink;
    void                *sink_cookie;
} fut_hci_dev_t;

/* Register a new HCI transport.  Returns the assigned device index
 * (>=0) on success, or a negative errno (-ENOMEM if the table is
 * full, -EINVAL on bad args).  `name` is copied into the dev
 * structure. */
int fut_hci_register(const char *name,
                     fut_hci_dev_type_t type,
                     const fut_hci_ops_t *ops,
                     void *cookie);

/* Unregister an HCI transport by index.  Idempotent on already-
 * unregistered slots; -EINVAL on out-of-range index. */
int fut_hci_unregister(int dev_index);

/* Number of registered devices (zero or more). */
int fut_hci_dev_count(void);

/* Borrow a pointer to the dev at `idx`, or NULL on out-of-range /
 * unregistered.  The pointer is stable for the lifetime of the
 * registration. */
const fut_hci_dev_t *fut_hci_dev_get(int dev_index);

/* Bring up the transport — calls ops->open under the hood and
 * marks the device as ready for traffic. */
int fut_hci_dev_open(int dev_index);

/* Tear down the transport. */
int fut_hci_dev_close(int dev_index);

/* Send an HCI command to a specific device.  Returns 0 on success,
 * -ENODEV if the device isn't open, -EINVAL for bad args. */
int fut_hci_send_cmd(int dev_index, const uint8_t *pkt, size_t len);

/* Install an event sink for a device.  Returns 0 on success.  A
 * NULL sink disables event delivery for that device. */
int fut_hci_set_event_sink(int dev_index,
                           fut_hci_event_sink_t sink,
                           void *sink_cookie);

/* Called by transport when an event/ACL/SCO packet has arrived.
 * Forwards to the installed event sink (if any).  Returns whatever
 * the sink returned, or 0 if no sink is installed (packet dropped). */
int fut_hci_dispatch_event(int dev_index,
                           uint8_t pkt_type,
                           const uint8_t *pkt,
                           size_t len);

/* Wipe the registry — primarily for tests. */
void fut_hci_reset(void);

/* Iterate every registered device, call ops->open, and log the
 * outcome.  Intended to run once after all transports register
 * during platform init.  Failures (including -ENOSYS from stub
 * transports) are non-fatal — they're informational so the boot
 * log shows which radios are ready and which are pending. */
void fut_hci_open_all(void);

/* ============================================================
 *   HCI opcodes + packet construction
 * ============================================================
 *
 * Opcodes are 16-bit values split into OCF (Opcode Command Field,
 * low 10 bits) and OGF (Opcode Group Field, high 6 bits).  The
 * standard groups we care about for bring-up:
 *
 *   OGF 0x01  Link Control commands         (Inquiry, etc.)
 *   OGF 0x03  Controller & Baseband cmds    (Reset, Read Local Name)
 *   OGF 0x04  Informational Parameters      (Read Local Version)
 *   OGF 0x08  LE Controller commands        (LE Set Scan Params, etc.)
 */

#define FUT_HCI_OPCODE(ogf, ocf)  ((uint16_t)((((ogf) & 0x3F) << 10) | ((ocf) & 0x3FF)))

#define FUT_HCI_OP_RESET                FUT_HCI_OPCODE(0x03, 0x0003)
#define FUT_HCI_OP_READ_LOCAL_NAME      FUT_HCI_OPCODE(0x03, 0x0014)
#define FUT_HCI_OP_READ_LOCAL_VERSION   FUT_HCI_OPCODE(0x04, 0x0001)
#define FUT_HCI_OP_READ_BD_ADDR         FUT_HCI_OPCODE(0x04, 0x0009)
#define FUT_HCI_OP_LE_SET_SCAN_PARAMS   FUT_HCI_OPCODE(0x08, 0x000B)
#define FUT_HCI_OP_LE_SET_SCAN_ENABLE   FUT_HCI_OPCODE(0x08, 0x000C)

/* HCI event codes (first byte of the parameter portion of an
 * incoming event packet). */
#define FUT_HCI_EVT_CMD_COMPLETE        0x0E
#define FUT_HCI_EVT_CMD_STATUS          0x0F
#define FUT_HCI_EVT_HARDWARE_ERROR      0x10
#define FUT_HCI_EVT_LE_META             0x3E

/* Build an HCI command packet into `out_buf`.  Layout:
 *   byte 0   : opcode low
 *   byte 1   : opcode high
 *   byte 2   : parameter length
 *   bytes 3+ : params (copied from `params`, `param_len` bytes)
 *
 * Returns the total packet length on success, -EINVAL if the buffer
 * is too small or parameters won't fit.  `out_buf` must hold at
 * least 3 + param_len bytes; recommended size FUT_HCI_CMD_PKT_MAX. */
int fut_hci_build_cmd(uint16_t opcode,
                      const uint8_t *params,
                      uint8_t param_len,
                      uint8_t *out_buf,
                      size_t out_cap);

#endif /* __FUTURA_HCI_H__ */
