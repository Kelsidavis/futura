# Phase 4 Progress — Distributed FIPC

## Kernel & Core Transport
- Implemented CRC32-backed remote send path in `fipc_send()` with capability validation and MTU enforcement, delegating framing to registered transport ops.
- Added transport registration hooks so userland daemons (netd) can supply the physical send routine without touching kernel internals.
- Remote channel bookkeeping now records endpoint metadata (IPv4, port, MTU) and enforces capability equality on inbound frames.

## Networking & Service Layer
- Introduced `netd` UDP bridge daemon (host build) with selectable listen endpoint, CRC checks, and loopback-friendly operation.
- Delivered `svc_registryd` bootstrap utility plus `libfutura` registry cache (`fipc_register_remote_service`, `fipc_lookup_service_id`).
- Host-side `libfipc_host` shim reuses kernel IPC logic for tooling/tests.

## Testing & Tooling
- Added host test harness `tests/fipc_remote_loopback` which exercises the full send→UDP→recv pipeline and enforces <1 ms latency.
- Updated build system with `make tests/fipc_remote_loopback` target and CI-friendly commands.

## Documentation
- Extended `docs/FIPC_SPEC.md` with remote transport details and new testing workflow.
- Authored `docs/DISTRIBUTED_FIPC_DESIGN.md` covering architecture, registry flow, security, and next steps.

## Next Steps
1. Layer WireGuard or DTLS over the UDP skeleton for authenticated transport.
2. Give `svc_registryd` a persistent FIPC control channel instead of CLI-driven setup.
3. Capture telemetry (latency histogram, drop counters) in netd for observability.
4. Integrate netd + registry startup into initd bootstrap sequencing.
