# FIPC Specification — Futura Inter-Process Communication
**Project:** Futura OS  
**Status:** Core Transport Layer — Stable API  
**Author:** Kelsi Davis  
**Date:** October 2025  
**License:** MPL 2.0  

---

## 🛰️ Overview
**FIPC (Futura Inter-Process Communication)** is the unified event and messaging system of the Futura OS kernel.  
It provides a zero-copy, shared-memory transport for messages, signals, and events between processes, subsystems,  
and userland daemons.  

FIPC replaces traditional UNIX pipes, sockets, and signals with a single, high-performance channel system.  
Everything—syscalls, file events, compositor updates—flows through FIPC.

---

## ✳️ Design Principles
| Principle | Description |
|------------|-------------|
| **Zero-Copy Messaging** | All data is exchanged via shared memory buffers to avoid redundant kernel/user copies. |
| **Unified Event Model** | Interrupts, IPC, and GUI input share a common packet structure. |
| **Capability-Based Security** | Each process has explicit FIPC channel capabilities; no global namespace. |
| **Architecture-Neutral** | Identical protocol on x86-64, ARM64, and future platforms. |
| **Deterministic & Traceable** | Every message includes timestamp and CRC metadata for logging and replay. |

---

## 🧩 Core Structures
```c
typedef struct {
    uint32_t type;        // SYS, FS, UI, NET, USER, etc.
    uint32_t length;      // Payload length
    uint64_t timestamp;   // Kernel tick counter
    uint32_t src_pid;     // Source process ID
    uint32_t dst_pid;     // Destination process ID
    uint64_t capability;  // Channel or permission token
    uint8_t  payload[];   // Flexible payload
} fipc_msg_t;
```

---

## 🔁 Channel Model
- Channels are circular ring buffers in shared memory.  
- Each has atomic read/write cursors managed by the kernel.  
- Endpoints may be:
  - **Point-to-Point** – standard IPC  
  - **Broadcast** – compositor events, system notifications  
  - **System** – kernel → userland events  

---

## 🌐 Remote Transport
Remote channels reuse the same message layout while sending frames over UDP.
Every remote `fipc_msg_t` is wrapped by a 16-byte network header:

| Field | Size | Description |
|-------|------|-------------|
| `channel_id` | 64-bit | Destination channel ID on the receiving node |
| `payload_len` | 32-bit | Total bytes of the serialized `fipc_msg_t` |
| `crc` | 32-bit | CRC32 (poly 0xEDB88320) over the serialized payload |

**Pipeline overview**
- `fipc_send()` packages the message header + payload, enforces MTU, and invokes
  the registered transport ops.
- `netd` publishes the frame as a UDP datagram using the endpoint metadata
  (loopback harness maps `node_id` → UDP port on 127.0.0.1).
- Incoming frames are verified by netd (CRC, length, capability) before they are
  injected into the destination channel with `fipc_channel_inject()`.
- Capability tokens stay authoritative on both sides—messages with mismatched
  capabilities are dropped with `FIPC_EINVAL`.

**Service discovery**
- `svc_registryd` records service → channel mappings and optional remote
  endpoints.  
- `libfutura` keeps a local cache via
  `fipc_register_remote_service()` / `fipc_lookup_service_id()` so userland can
  connect without synchronous RPCs.

**Diagnostics**
- `netd` logs CRC failures, unknown channel IDs, and transport errors.
- Loopback mode allows single-host testing: both endpoints can share a UDP port
  while exercising the remote path.

---

## ⚙️ Core API
| Function | Purpose |
|-----------|----------|
| `fipc_open(channel_id)` | Open or attach to a channel. |
| `fipc_send(channel, msg, len)` | Enqueue message to destination endpoint. |
| `fipc_recv(channel, buf, len)` | Receive next available message. |
| `fipc_map_shared(channel)` | Map channel’s shared memory region. |
| `fipc_close(channel)` | Release capability and unmap region. |

---

## 🧠 Message Lifecycle
1. **Channel Allocation** — Kernel creates shared memory region and assigns capability.  
2. **Send** — Sender writes `fipc_msg_t` into ring buffer.  
3. **Signal** — Kernel updates event counters or uses interrupt vector.  
4. **Receive** — Receiver reads message and advances read cursor.  
5. **Ack/Reuse** — Channel reused for subsequent messages without kernel re-entry.

---

## 🚦 Synchronization
- Uses atomic counters and memory barriers.  
- Optional spin-wait or event-FD for blocking operations.  
- No heavy locks; all operations are O(1).  

---

## 🛡️ Security Model
- Capabilities verified on send/receive.  
- Each message stamped with capability ID and sender PID.  
- Unauthorized send attempts cause `FIPC_ERR_CAP`.  

---

## 📊 Performance Targets
| Metric | Target |
|---------|---------|
| Average latency | < 2 µs (intra-process) |
| Throughput | > 2 GB/s on shared memory transport |
| Max endpoints | 256 per process |
| Max channel size | 4 MB default (configurable) |

---

## 🧪 Testing
Use the **remote loopback** suite (covers CRC + latency):  
```bash
make tests/fipc_remote_loopback
./build/tests/fipc_remote_loopback --net=127.0.0.1:49500
```

---

## 🧭 Integration
FIPC is the backbone for:
- POSIX syscall bridging  
- VFS notifications  
- Network stack (WireGuard / QUIC)  
- FuturaWay compositor channels  

---

## 🔚 Summary
FIPC transforms internal OS communication into a **deterministic message fabric**.  
It enables true modularity, cross-architecture compatibility, and high-speed data exchange  
without kernel bottlenecks.
