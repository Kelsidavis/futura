# Security

## Reporting

Report security issues to the maintainer directly. Do not open public issues for vulnerabilities.

## Threat Model

Futura OS is a research operating system. It is not designed for production use and should not be exposed to untrusted networks or users without additional hardening.

## Memory Safety

- Kernel code uses Rust's ownership model to prevent use-after-free and buffer overflows
- Unsafe blocks are minimized and documented
- All syscall inputs are validated at the kernel boundary

## Capability-Based Security

Futura uses a capability-based security model for process isolation and resource access control. See `CAPABILITY_IO_TRANSITION.md` and `FSD_CAPABILITY_AUDIT.md` for details.
