# Phase 3 Progress — April 2025

## Kernel Base
- Expanded x86_64 heap/PMM bring-up to skip the legacy VGA/BIOS hole, so higher-half allocations start at 1 MiB and no longer collide with unmapped low memory.
- Added `fut_map_range` backing (via `fut_paging_init`) to prepare for dynamic mappings in upcoming userland daemons.

## Storage & Filesystems
- Introduced byte-sized ramdisk creation helpers and cleaned up the ramdisk allocator; this unblocks FuturaFS formatting on sub-megabyte test devices.
- FuturaFS formatter now emits detailed instrumentation so byte-level I/O paths and bitmap initialization can be validated on boot.
- Implemented `lookup`, `create`, and `mkdir` in the FuturaFS vnode layer, including on-disk directory entry management and bitmap syncing.
- Boot-time self-test: format, mount, and stat of `/mnt` all succeed under GRUB/QEMU, confirming the filesystem pipeline.

## Next Up
1. Finish the remaining directory CRUD work in FuturaFS (`readdir`, `unlink`, `rmdir`).
2. Restore userland builds (`initd`, `posixd`, `fsd`) and wire their FIPC protocols to the kernel bridges.
3. Capture allocator metrics and trim debug logging before merging into release branches.

Serial logs for the latest GRUB run are archived at `/tmp/futura-serial.log` for reference.
