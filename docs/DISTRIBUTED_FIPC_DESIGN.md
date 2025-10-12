# Distributed FIPC Design
**Project:** Futura OS — Phase 4  
**Author:** Codex Agent  
**Date:** April 2025  
**Status:** Authenticated Prototype (netd, registry signing, control-channel auth live)  
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

## 3. Service Discovery & Registry (Signed)
- `svc_registryd` still consumes CLI bootstrap arguments but now requires every datagram to carry an HMAC-SHA256 signature over the service name, timestamp, and nonce. Requests without a valid signature return `SRG_ERR_AUTH`.
- The daemon tracks current and previous keys. During a rotation the previous key remains valid until the configured grace window expires, allowing staggered clients to reconnect without interruption.
- A nonce cache (64 entries) prevents replay within the timestamp tolerance window; timestamps outside ±5 minutes are rejected.
- `libfutura` and the test harness use `registry_client_set_keys()` to supply the active/previous secrets. Lookups and registrations are signed automatically and retried with the previous key when necessary.
- Future work: expose an FIPC registry control channel so initd can distribute and rotate secrets dynamically instead of relying on CLI bootstrap.

---

## 4. Security & Capability Ledger
- Capability tokens remain the primary guard. Remote messages are accepted only when the destination channel has an identical capability bound, and the binding itself is now authorised via the admin control channel using a shared token plus HMAC over the lease parameters.
- CRC32 ensures accidental corruption is detected; intentional tampering still motivates a future encrypted transport, but both the control plane and the registry are already authenticated via shared secrets.
- `netd` never mutates channel metadata—only the kernel may transition a channel between local/remote/system types. Admin operations (`cap_bind`, `cap_revoke`, `set_rate`) are signed and verified in `fut_fipc_admin_handle()` before the ledger is updated.

---

## 5. NAT & Topology Considerations
- Current prototype assumes direct IPv4 reachability. Flags carry a UDP port; NAT traversal is deferred to Phase 5 when WireGuard tunnels arrive.
- Discovery is static (command-line). Dynamic discovery will require either multicast beacons or a rendezvous service once the security model is upgraded.

---

## 6. Testing Strategy
- `make tests/fipc_remote_loopback` + `./build/tests/fipc_remote_loopback --net=127.0.0.1:49500` validates the end-to-end path (CRC + latency < 1 ms expectation).
- `./build/tests/fipc_admin_ops` exercises the control-channel token + HMAC bindings: missing token, wrong token, and incorrect HMAC must all fail before a signed bind succeeds.
- `./build/tests/registry_auth` spins up `svc_registryd`, proves that unsigned lookups are rejected, rotates keys, and confirms the grace window behaviour for the previous key.
- CI should launch two instances with different UDP ports to exercise asymmetric latency and capability mismatches (TODO).
- Host fuzzers can target the UDP frame parser inside netd to ensure malformed packets are ignored deterministically.

---

## 7. Next Steps
1. Add WireGuard-backed transport module so netd can multiplex secure tunnels alongside the current HMAC-protected UDP path.
2. Promote registry caching into an FIPC service managed by initd so secrets can rotate without CLI orchestration.
3. Teach netd to manage multiple sockets (multi-homing) and maintain per-peer statistics for observability.
4. Integrate remote transport into initd boot sequencing (spawn netd + svc_registryd automatically and provision secrets via the control channel).

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

## 12. Transport Header v1
- The UDP framing now includes `magic`, `version`, `flags`, `seq`, `credits`, `channel_id`, `payload_len`, and `crc`. Version defaults to 1, preserving compatibility with earlier payload parsing (receivers can ignore fields they do not recognise).
- `seq` increments with each transmitted frame per bound service, while `credits` remains advisory (current builds leave it at 0). Flow-control and acknowledgement flags are reserved for future implementations.

## 13. Kernel Capability Ledger & Quotas (Phase K1)
- Channels now carry a kernel-managed capability record: rights bits (`SEND`, `RECV`, `SYS`, `ADMIN`), message/byte quotas, and optional expiry tick.
- `fut_fipc_cap_bind()` installs or refreshes the ledger (counters reset); `fut_fipc_cap_unbind()` clears restrictions, restoring legacy behaviour.
- Enforcement occurs in both `fut_fipc_send()` and `fut_fipc_channel_inject()`. Rights violations return `FIPC_EPERM`; quota exhaustion maps to `FIPC_ENOSPC`.
- Counters accumulate per-channel usage (messages/bytes sent/injected) and feed the kernel system metrics publisher so observability reflects real traffic.
- Kernel metrics now originate from the core IPC code: the system stream reports live PMM totals and channel counts without relying on host shims.

## 14. Timers, Deadlines, and Reply-Chain PI (Phase K3)
- Host/kernel timers now expose `fut_timer_start()` / `fut_timer_cancel()` so subsystems can register millisecond callbacks without polling.
- Threads carry an absolute `deadline_tick`; sends past the deadline return `FIPC_EAGAIN` and contribute to the `FIPC_SYS_K_DROPS_DEADLINE` metric.
- Reply-chain priority inheritance boosts the server thread registered as the channel owner when a higher-priority client issues a request; priorities are restored on reply and surfaced via `FIPC_SYS_K_PI_APPLIED` / `FIPC_SYS_K_PI_RESTORED` counters.

## 15. Capability Revocation & Rate Limiting (Phase K4)
- Capability bindings gain `lease_id` generations and explicit revoke flags; `fut_fipc_cap_revoke()` strips send/recv rights immediately while metrics continue to accrue.
- `fut_fipc_set_rate()` enables per-channel token-bucket rate limiting. Rejections surface as `FIPC_EAGAIN` and roll into `FIPC_SYS_K_DROPS_RL`; aggregate token levels are reported via `FIPC_SYS_K_RL_TOKENS`.
