# Phase 3 Progress — October 2025

## Kernel Base
- Expanded x86_64 heap/PMM bring-up to skip the legacy VGA/BIOS hole, so higher-half allocations start at 1 MiB and no longer collide with unmapped low memory.
- Added `fut_map_range` backing (via `fut_paging_init`) to prepare for dynamic mappings in upcoming userland daemons.

## Storage & Filesystems
- Introduced byte-sized ramdisk creation helpers and cleaned up the ramdisk allocator; this unblocks FuturaFS formatting on sub-megabyte test devices.
- FuturaFS formatter now emits detailed instrumentation so byte-level I/O paths and bitmap initialization can be validated on boot.
- Implemented `lookup`, `create`, and `mkdir` in the FuturaFS vnode layer, including on-disk directory entry management and bitmap syncing.
- Rounded out directory CRUD in FuturaFS: `readdir` now walks directory blocks deterministically, `unlink` reclaims inode data, and `rmdir` enforces emptiness while freeing blocks back to the allocator.
- VFS exposes directory CRUD helpers (`fut_vfs_readdir/unlink/rmdir/mkdir`) and the boot self-test now exercises listing, unlinking, and ENOTEMPTY paths to guard regressions.
- Userland scaffolding: `fsd` tracks directory handles/cookies and `posixd` mirrors the kernel helpers so libfutura can issue `opendir`/`readdir`/`mkdir`/`unlink` via FIPC once channel routing lands.
- Boot-time self-test: format, mount, and stat of `/mnt` all succeed under GRUB/QEMU, confirming the filesystem pipeline.

## Next Up
1. Extend coverage with focused stress tests (duplicate names, ENOSPC, vnode failure rollbacks) and pipe directory CRUD through `fsd` / `posixd` FIPC flows.
2. Restore userland builds (`initd`, `posixd`, `fsd`) and wire their FIPC protocols to the kernel bridges, fixing outstanding Werror breakages.
3. Capture allocator metrics and trim debug logging before merging into release branches.

Serial logs for the latest GRUB run are archived at `/tmp/futura-serial.log` for reference.
