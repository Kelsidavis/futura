#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
KERNEL=${KERNEL:-"$ROOT/build/bin/futura_kernel.elf"}
MKFUTFS=${MKFUTFS:-"$ROOT/build/tools/mkfutfs"}
FSCK=${FSCK:-"$ROOT/build/tools/fsck.futfs"}
QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}
IMAGE=${IMAGE:-"$ROOT/build/futfs_crash.img"}
MEMORY=${MEMORY:-512}
TIMEOUT_SECS=${TIMEOUT_SECS:-10}

QEMU_FLAGS=(
  -serial stdio
  -display none
  -m "$MEMORY"
  -device isa-debug-exit,iobase=0xf4,iosize=0x4
  -no-reboot
  -no-shutdown
  -netdev user,id=net0
  -device virtio-net,netdev=net0
)

if [[ ! -f "$KERNEL" ]]; then
  echo "futfs_crash_gc: kernel not found at $KERNEL" >&2
  exit 2
fi
if [[ ! -x "$MKFUTFS" ]]; then
  echo "futfs_crash_gc: mkfutfs not found at $MKFUTFS" >&2
  exit 2
fi
if [[ ! -x "$FSCK" ]]; then
  echo "futfs_crash_gc: fsck.futfs not found at $FSCK" >&2
  exit 2
fi

rm -f "$IMAGE"
"$MKFUTFS" "$IMAGE" --segments 32 --segment-sectors 16 --block-size 512 --label "CrashGC"

set +e
timeout "$TIMEOUT_SECS" "$QEMU_BIN" "${QEMU_FLAGS[@]}" \
  -drive if=virtio,file="$IMAGE",format=raw \
  -kernel "$KERNEL" \
  -append "futurafs.test_crash_compact=1" >/dev/null 2>&1
CRASH_RC=$?
set -e
if [[ $CRASH_RC -ne 124 ]]; then
  echo "futfs_crash_gc: expected crash run to timeout (rc=124), got $CRASH_RC" >&2
  exit 1
fi

set +e
"$QEMU_BIN" "${QEMU_FLAGS[@]}" \
  -drive if=virtio,file="$IMAGE",format=raw \
  -kernel "$KERNEL" >/dev/null 2>&1
BOOT_RC=$?
set -e
if [[ $BOOT_RC -ne 1 ]]; then
  echo "futfs_crash_gc: second boot failed (rc=$BOOT_RC)" >&2
  exit 1
fi

"$FSCK" --device "$IMAGE" --dry-run >/dev/null
"$FSCK" --device "$IMAGE" --repair --gc >/dev/null

echo "futfs_crash_gc: PASS"
