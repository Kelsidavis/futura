# Distributed FIPC Design
**Project:** Futura OS — Phase 4  
**Author:** Codex Agent  
**Date:** April 2025  
**Status:** Draft Implementation (netd prototype live, registry caching active)  
**License:** MPL 2.0

---

## 1. Goals
- Extend FIPC beyond a single node without changing the on-wire `fipc_msg_t`.
- Provide a minimal UDP transport (IPv4) that honours channel capabilities and CRC integrity.
- Keep userland daemons in charge of routing and discovery (`netd`, `svc_registryd`).
- Support loopback/self-test flows so the transport can be validated in CI today.

---

## 2. Transport Pipeline
1. **Channel Binding** — Kernel marks a channel as `REMOTE` via `fipc_register_remote()` with the peer metadata (test harness uses `node_id` as UDP port).
2. **Send Path** — `fipc_send()` packages the message and calls the registered transport ops; CRC is computed in the UDP backend.
3. **Network Bridge (netd)**
   - Maintains a UDP socket (one per node).
   - Encapsulates frames in the `fipc_net_hdr` and transmits to the peer address.
   - Polls the socket, validates CRC, and injects payloads directly into the destination channel.
4. **Receive Path** — Invalid CRC, truncated payloads, or unknown channels are discarded before they touch the queue.
5. **Channel Injection** — Valid frames reuse the ring-buffer enqueue logic (`fipc_channel_inject`), waking any waiters as if the message originated locally.

---

## 3. Service Discovery & Registry
- `svc_registryd` accepts CLI flags (`--service`, `--remote`) to publish name → channel bindings and optional remote endpoints.
- `libfutura` caches registry entries with `fipc_register_remote_service()` so clients can resolve handles without synchronous IPC.
- Future work: expose an FIPC control channel so registry updates propagate dynamically instead of via command-line bootstrap.

---

## 4. Security & Capability Ledger
- Capability tokens remain the primary guard. A remote message is accepted only when the destination channel has an identical capability bound.
- CRC32 ensures accidental corruption is detected; intentional tampering requires cryptographic transport (WireGuard planned for Phase 5).
- `netd` never mutates channel metadata—only the kernel may transition a channel between local/remote/system types.

---

## 5. NAT & Topology Considerations
- Current prototype assumes direct IPv4 reachability. Flags carry a UDP port; NAT traversal is deferred to Phase 5 when WireGuard tunnels arrive.
- Discovery is static (command-line). Dynamic discovery will require either multicast beacons or a rendezvous service once the security model is upgraded.

---

## 6. Testing Strategy
- `make tests/fipc_remote_loopback` + `./build/tests/fipc_remote_loopback --net=127.0.0.1:49500` validates the end-to-end path (CRC + latency < 1 ms expectation).
- CI should launch two instances with different UDP ports to exercise asymmetric latency and capability mismatches (TODO).
- Host fuzzers can target the UDP frame parser inside netd to ensure malformed packets are ignored deterministically.

---

## 7. Next Steps
1. Add WireGuard-backed transport module so netd can multiplex secure tunnels alongside raw UDP.
2. Promote registry cache into an FIPC service (registry channel) instead of CLI flags.
3. Teach netd to manage multiple sockets (multi-homing) and maintain per-peer statistics for observability.
4. Integrate remote transport into initd boot sequencing (spawn netd + svc_registryd automatically when remote services enabled).

---

## 8. UDP Frame Format & Host Loopback Harness
- Datagram layout: `fut_fipc_net_hdr { channel_id, payload_len, crc32 }` immediately followed by the serialized `fut_fipc_msg` header and payload bytes. CRC32 covers only the serialized message so transport metadata can change without recomputing hashes higher in the stack.
- Loopback convention: the host harness maps `remote.node_id` to a UDP port on `127.0.0.1`, keeping distributed FIPC tests hermetic while mirroring on-wire framing.
- Error handling: UDP send backpressure maps to `FIPC_EAGAIN`, hard transport failures escalate as `FIPC_EIO`, and missing transport ops surface as `FIPC_ENOTSUP` from the kernel send path.
- Capability guard: once the destination channel binds a non-zero capability, netd drops remote frames whose `msg.capability` differs, keeping enforcement at the network boundary without altering queue semantics.

---

## 9. Registry-Based Discovery (Test Harness)
- The registry daemon binds to `127.0.0.1:<port>` and speaks a tiny UDP protocol (`SRG_MAGIC` / `SRG_REG`, `SRG_LOOKUP`, `SRG_LOOKUP_RESP`, `SRG_ERROR`).
- `svc_registryd` keeps a fixed table (64 entries) of service name → channel_id mappings; registration overwrites existing entries and acknowledges with `SRG_LOOKUP_RESP`.
- Tests drive discovery by registering the service channel first, then issuing a lookup to learn the remote channel_id before re-registering the FIPC endpoint.
- The discovery test runs netd and the registry in-process: a polling thread services registry datagrams while the main thread performs lookups and exercises remote messaging.

## 10. Lazy Auto-Discovery on First Send
- `netd_bind_service()` associates a local channel with a registry name and host/port. When a remote endpoint has `channel_id == 0`, the first send triggers a registry lookup. The resolved channel id is cached and pushed back into the kernel via `fut_fipc_register_remote()`, so subsequent sends bypass the registry.
- If the lookup fails (service not registered yet), `udp_send_cb()` returns `FIPC_EAGAIN`, allowing callers to retry once the service appears.

## 11. Observability (Host netd)
- `netd` maintains counters for registry lookups: `lookup_attempts`, `lookup_hits`, `lookup_miss`, and `send_eagain`.
- `netd_metrics_snapshot()` copies these counters into a caller-provided struct; `netd_metrics_publish()` emits a one-line text record (key=value pairs) through a supplied FIPC channel for easy test/assertion.
