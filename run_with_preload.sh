#!/bin/bash
# Wrapper script to run commands with LD_PRELOAD for open syscall interception
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# This bypasses QEMU's SYSCALL instruction limitation by forcing int 0x80.

export LD_PRELOAD=/home/k/futura/build/lib/libopen_wrapper.so
exec "$@"
