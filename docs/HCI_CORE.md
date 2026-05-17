# Bluetooth HCI Core (`kernel/hci.c`)

**Status (2026-05-17)**: Core registry in tree with 20 unit tests; no real transport wired yet. The `apple_bcm` BT function registers a stub transport whose callbacks return `-ENOSYS` pending radio bring-up.

## Layering

The HCI core is the thinnest possible abstraction over a Bluetooth Host Controller Interface — the layer that sits between transport-specific code (UART, USB, PCIe msgbuf) and the rest of the Bluetooth stack (L2CAP / RFCOMM / GATT / profiles).

```
┌───────────────────────────────────────────┐
│  Profiles / L2CAP / GATT  (not yet)       │
└───────────────────────────────────────────┘
                ↑ events ↓ commands
┌───────────────────────────────────────────┐
│  HCI core   (kernel/hci.c — this file)    │
│  • fut_hci_register / unregister          │
│  • fut_hci_dev_open / close               │
│  • fut_hci_send_cmd                       │
│  • fut_hci_set_event_sink                 │
│  • fut_hci_dispatch_event                 │
│  • fut_hci_build_cmd (packet builder)     │
└───────────────────────────────────────────┘
                ↑ ops ↓ ops
┌───────────────────────────────────────────┐
│  Transports                                │
│  • apple_bcm BT  (PCIe msgbuf, stub today) │
│  • (future) BCM43455 UART on RPi           │
│  • (future) virtio-bt on QEMU              │
└───────────────────────────────────────────┘
```

## Public API

| Function                       | Purpose                                                  |
|--------------------------------|----------------------------------------------------------|
| `fut_hci_register`             | Add a transport.  Returns assigned index (`>=0`).        |
| `fut_hci_unregister`           | Remove a transport.  Idempotent on already-free slots.   |
| `fut_hci_dev_count`            | Number of registered devices.                            |
| `fut_hci_dev_get`              | Borrow `const fut_hci_dev_t*` by index.                  |
| `fut_hci_dev_find`             | Resolve a name to an index (e.g. lookup `"hci0"`).       |
| `fut_hci_dev_open`             | Bring up the transport (calls `ops->open`).              |
| `fut_hci_dev_close`            | Tear down the transport.                                 |
| `fut_hci_send_cmd`             | Hand an HCI command packet to the transport.             |
| `fut_hci_set_event_sink`       | Install a callback for inbound events.                   |
| `fut_hci_dispatch_event`       | Transport calls this when a packet arrives from chip.    |
| `fut_hci_build_cmd`            | Pack `[opcode_lo, opcode_hi, plen, params...]`.          |
| `fut_hci_open_all`             | Open every registered device (boot-time helper).         |
| `fut_hci_reset`                | Wipe the registry (tests only).                          |

## Transport ops

A transport implements four callbacks:

```c
typedef struct {
    int  (*send_cmd)(void *cookie, const uint8_t *pkt, size_t len);
    int  (*send_acl)(void *cookie, const uint8_t *pkt, size_t len);
    int  (*open)(void *cookie);
    void (*close)(void *cookie);
} fut_hci_ops_t;
```

`send_cmd` / `send_acl` take packets without the leading 1-byte HCI indicator (the indicator is `pkt_type` separately when dispatching events back). Returning `-ENOSYS` from any of them means "transport not implemented yet" — the HCI core treats this distinctly in `fut_hci_open_all`'s log output.

## Packet types

Per Bluetooth Core Specification §5.4:

| Indicator | Constant              | Direction       | Purpose                  |
|-----------|-----------------------|-----------------|--------------------------|
| 0x01      | `FUT_HCI_CMD_PKT`     | Host → ctrl     | HCI commands             |
| 0x02      | `FUT_HCI_ACL_PKT`     | Both            | ACL data                 |
| 0x03      | `FUT_HCI_SCO_PKT`     | Both            | Synchronous voice        |
| 0x04      | `FUT_HCI_EVT_PKT`     | Ctrl → host     | HCI events               |
| 0x05      | `FUT_HCI_ISO_PKT`     | Both            | LE isochronous           |

`fut_hci_dispatch_event` rejects pkt_type outside this range with `-EINVAL`.

## Opcode constants

Convenience constants for the commands a bring-up sequence typically issues:

| Constant                          | Opcode | Purpose                          |
|-----------------------------------|--------|----------------------------------|
| `FUT_HCI_OP_RESET`                | 0x0C03 | HCI Reset                        |
| `FUT_HCI_OP_READ_LOCAL_NAME`      | 0x0C14 | Read Local Name                  |
| `FUT_HCI_OP_READ_LOCAL_VERSION`   | 0x1001 | Read Local Version Information   |
| `FUT_HCI_OP_READ_BD_ADDR`         | 0x1009 | Read BD_ADDR                     |
| `FUT_HCI_OP_LE_SET_SCAN_PARAMS`   | 0x200B | LE Set Scan Parameters           |
| `FUT_HCI_OP_LE_SET_SCAN_ENABLE`   | 0x200C | LE Set Scan Enable               |

`FUT_HCI_OPCODE(ogf, ocf)` encodes the 16-bit opcode at compile time.

## Registering a transport — pattern

```c
static int my_send_cmd(void *cookie, const uint8_t *pkt, size_t len)  { ... }
static int my_send_acl(void *cookie, const uint8_t *pkt, size_t len)  { ... }
static int my_open(void *cookie)                                       { ... }
static void my_close(void *cookie)                                     { ... }

static const fut_hci_ops_t my_ops = {
    .send_cmd = my_send_cmd,
    .send_acl = my_send_acl,
    .open     = my_open,
    .close    = my_close,
};

int idx = fut_hci_register("my-transport", FUT_HCI_TYPE_PCIE,
                            &my_ops, my_cookie);
if (idx < 0) { /* registration failed */ }
```

When a packet arrives from the controller, the transport's IRQ / poll handler calls:

```c
fut_hci_dispatch_event(idx, FUT_HCI_EVT_PKT, evt_buf, evt_len);
```

The HCI core forwards to whatever sink the consumer installed via `fut_hci_set_event_sink`.

## Building commands

```c
uint8_t pkt[FUT_HCI_CMD_PKT_MAX];
int len = fut_hci_build_cmd(FUT_HCI_OP_RESET, NULL, 0,
                             pkt, sizeof(pkt));
if (len > 0) {
    fut_hci_send_cmd(idx, pkt, (size_t)len);
}
```

For commands with parameters, pass `params` and `param_len` directly — `fut_hci_build_cmd` packs them after the 3-byte header.

## Limits

| Setting                 | Value | Notes                                     |
|-------------------------|-------|-------------------------------------------|
| `FUT_HCI_MAX_DEVICES`   | 4     | Max concurrently registered transports    |
| `FUT_HCI_NAME_MAX`      | 16    | Max transport name length (incl. NUL)     |
| `FUT_HCI_CMD_PKT_MAX`   | 258   | HCI command packet (3 hdr + 255 param)    |
| `FUT_HCI_EVT_PKT_MAX`   | 258   | Symmetric event packet ceiling            |
| `FUT_HCI_ACL_PKT_MAX`   | 1027  | ACL (4 hdr + 1023 payload)                |

## What's not here

- L2CAP / RFCOMM / SCO / ISO upper layers
- Address management (BD_ADDR pinning, LE address types)
- HCI event parser (decoding `cmd_complete`, `cmd_status`, etc.)
- Connection state machine
- Bluez-style sockets

All of those land on top of this layer when there's a working transport to validate against.

## Tests

`kernel/tests/hci_tests.c` runs 20 tests via the kernel sequential test runner:

| # | Coverage                                            |
|---|-----------------------------------------------------|
| T1-T2  | Registration input validation                  |
| T3-T4  | Basic register + `dev_count`                   |
| T5     | `send_cmd` before `open` → `-ENODEV`           |
| T6-T7  | `dev_open` + `send_cmd` routes to transport    |
| T8     | Event sink delivery                            |
| T9     | Dispatch with no sink silently drops           |
| T10    | `dev_close` clears `open` flag                 |
| T11    | `send_cmd` oversized rejected                  |
| T12-T13 | `unregister` + idempotency                    |
| T14-T16 | `build_cmd` opcode + payload + buffer check   |
| T17    | `dispatch_event` rejects invalid `pkt_type`    |
| T18-T20 | `dev_find` lookup (match / unknown / NULL)    |

The whole suite contributes 20 to the kernel test counter.

## Code pointers

- Header:        `include/kernel/hci.h`
- Implementation: `kernel/hci.c`
- Tests:         `kernel/tests/hci_tests.c`
- First consumer: `platform/arm64/drivers/apple_bcm.c` (stub BT transport)
