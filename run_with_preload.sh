#!/bin/bash
# Wrapper script to run commands with LD_PRELOAD for open syscall interception
# This bypasses QEMU's SYSCALL instruction limitation by forcing int 0x80

export LD_PRELOAD=/home/k/futura/build/lib/libopen_wrapper.so
exec "$@"
