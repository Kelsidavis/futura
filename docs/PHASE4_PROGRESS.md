# Phase 4 Progress — Distributed FIPC

## Kernel & Core Transport
- Implemented CRC32-backed remote send path in `fipc_send()` with capability validation and MTU enforcement, delegating framing to registered transport ops.
- Added transport registration hooks so userland daemons (netd) can supply the physical send routine without touching kernel internals.
- Remote channel bookkeeping now records endpoint metadata (IPv4, port, MTU) and enforces capability equality on inbound frames.
- Control channel operations are now authenticated (shared admin token + HMAC-SHA256 over the capability lease) so unsigned requests never reach kernel state.

## Networking & Service Layer
- Introduced `netd` UDP bridge daemon (host build) with selectable listen endpoint, CRC checks, and loopback-friendly operation.
- Delivered `svc_registryd` bootstrap utility plus `libfutura` registry cache (`fipc_register_remote_service`, `fipc_lookup_service_id`).
- Registry protocol now signs every registration/lookup (HMAC-SHA256 with nonce + timestamp) and supports key rotation with a configurable grace window.
- Host-side `libfipc_host` shim reuses kernel IPC logic for tooling/tests.

## Testing & Tooling
- Added host test harness `tests/fipc_remote_loopback` which exercises the full send→UDP→recv pipeline and enforces <1 ms latency.
- Strengthened coverage with `tests/fipc_admin_ops` (control-channel auth failure modes) and `tests/registry_auth` (registry signing + key rotation).
- Updated build system with dedicated targets (`make tests/fipc_remote_loopback`, `make tests/fipc_admin_ops`, `make tests/registry_auth`) for CI-friendly invocation.

## Documentation
- Extended `docs/FIPC_SPEC.md` with remote transport, control-channel auth, and registry signing details.
- Updated `docs/DISTRIBUTED_FIPC_DESIGN.md` to document HMAC-protected discovery, nonce caching, and future secure transport goals.

## Next Steps
1. Layer WireGuard or DTLS over the UDP skeleton for encrypted transport.
2. Give `svc_registryd` a persistent FIPC control channel instead of CLI-driven setup, enabling runtime secret distribution.
3. Capture telemetry (latency histogram, auth failures, drop counters) in netd for observability.
4. Integrate netd + registry startup into initd bootstrap sequencing with automated key rollout.
