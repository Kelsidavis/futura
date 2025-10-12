# Futura OS Architecture (Updated Oct 12 2025)

## Layered View

```
┌──────────────────────────────────────────────────────────────┐
│                         User Dials                           │
│  Applications, tests, host tooling, mkfutfs                  │
└───────────────▲───────────────────────┬──────────────────────┘
                │ FIPC channels & handles│
┌───────────────┴──────────────────────┐ │
│        Userland Services             │ │
│  init · fsd · posixd · futurawayd    │ │
│  libfutura runtime + subsystem libs  │ │
└───────────────▲────────┬─────────────┘ │
                │        │               │
      Capability handles │               │
┌───────────────┴────────▼──────────────┴──────────────────────┐
│                     Futura Kernel                           │
│  - Object table & rights (fut_object.c)                     │
│  - Scheduler + wait queues                                  │
│  - Virtual memory (fut_mm)                                  │
│  - Syscall bridge (int 0x80)                                │
│  - FIPC core & transport                                    │
│  - VFS + block core (virtio-blk, AHCI, log FS bridge)       │
└───────────────▲──────────────────────────────────────────────┘
                │ Platform HAL (PCI, MMIO, traps, timers)
┌───────────────┴──────────────────────────────────────────────┐
│         Hardware / Virtual hardware (QEMU)                   │
└──────────────────────────────────────────────────────────────┘
```

## Object Model & Rights

Futura OS treats every shareable resource—channels, tasks, block devices, inode
handles—as an object managed by `fut_object.c`. Each object is tagged with a
rights bitmap that mirrors Zircon’s handle model. The async block core extends
this pattern: `fut_blk_acquire()` grants a handle whose rights (read, write,
admin) are enforced on every I/O submission, while `fut_blk_open()` lets privileged
callers map a capability back to the device object without revalidating rights. The new log-structured FuturaFS
skeleton derives capability rights directly from the inode policy recorded in
its log; userland receives transient handles (read/write/admin) that mirror
those policies.

Rights summary:

- `FUT_RIGHT_READ/WRITE/ADMIN` – generic kernel objects.
- `FUT_BLK_READ/WRITE/ADMIN` – block handles and FuturaFS inode capabilities.
- `FUTFS_RIGHT_*` – userland-side mapping exposed by the log-structured FS.

Handles are copied explicitly across FIPC messages, providing uniform security
semantics for kernel subsystems, device drivers, and user services.

## IPC Flow

FIPC (Futura Inter-Process Communication) is the substrate tying the system
together. Syscalls are marshalled into FIPC messages, composers use the same
fabric for surface updates, and remote transports reuse the framing for
host-side loopback tests. Highlights:

- Kernel exports `fipc_send/recv` plus credit-based back-pressure.
- Userland services link against `libfipc_host` for deterministic tests.
- Registry (`svc_registryd`) authenticates channel registrations with HMAC.
- Async block completions fan out via wait queues instead of busy polling.

## Storage Stack

1. **Block Core (`kernel/blk/blkcore.c`)** – queues BIOs, drives worker
   threads, tracks debug counters, and enforces handle rights.
2. **Drivers** – Virtio-blk and AHCI (new) discover PCI devices, negotiate
   features, and bridge into the block core.
3. **FuturaFS Log Skeleton (`subsystems/futura_fs/`)** – a minimal
   log-structured design featuring superblock + segment headers + inode
   records + append-only extents. Crash safety relies on ordered `pwrite`
   + `fsync` and a monotonically advancing log tail in the superblock.
4. **mkfutfs (`tools/mkfutfs`)** – formats an image, seeds the root inode, and
   validates block size/segment alignment.
5. **Kernel VFS** – still exposes the legacy bitmap-based FuturaFS for now; a
   follow-up service will migrate fsd to the log skeleton via capability
   handles.

## Scheduler & Concurrency

The kernel remains cooperative: threads yield on blocking syscalls, timer
sleepers park in wait queues (`fut_waitq`), and the scheduler runs the highest
priority READY thread. Blocking I/O (blkcore, wait queues) reuses the same
mechanism, ensuring services such as fsd can multiplex work without busy loops.

## Userland Services & Libraries

- **libfutura** – crt0, syscall veneers, heap allocator, printf, string utils.
- **fsd** – current filesystem daemon; will adopt the log-structured backend
  through capability handles.
- **posixd** – POSIX compatibility over FIPC.
- **futurawayd** – compositor + demo tests.
- **Host tooling** – registry/netd utilities, mkfutfs, and the
  `tests/futfs_log_basic` regression harness.

## Security & Performance Objectives

Security OKRs:

1. 100% of new drivers and subsystems land in memory-safe languages (Rust) or
   carry a documented performance exception; track the percentage of
   memory-safe LOC in CI.
2. Dev builds run with KASAN/UBSan (or equivalent) and nightly fuzzers hammer
   IPC, the FuturaFS log parser, and the ELF loader.
3. Releases are reproducible, cosign-signed, and published with TUF metadata.

Performance OKRs:

1. Track IPC round-trip, context switch, and block I/O microbenchmarks on every
   PR; fail the gate on regressions above 5%.
2.“Fast path first”: keep async block completions in the low hundreds of
   microseconds on QEMU baseline hardware, mirroring the seL4 ethos.

These objectives complement the roadmap milestones (Phase 2–4). See
`docs/STATUS.md` for live milestone tracking and doc-drift safeguards.
