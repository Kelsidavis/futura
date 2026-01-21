#!/usr/bin/env python3
"""
Generate a C header that exposes the current boot command line requested by the build.

Copyright (c) 2025 Kelsi Davis
Licensed under the MPL v2.0 — see LICENSE for details.

The Makefile passes $(KAPPEND) so the kernel can fall back to that string when the
bootloader omits a CMDLINE tag.
"""

import json
import os
import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: gen_boot_cmdline.py <cmdline> <out-header>", file=sys.stderr)
        sys.exit(1)

    cmdline = sys.argv[1] or ""
    out_path = sys.argv[2]

    # Normalize whitespace: trim leading/trailing spaces but keep internal spacing.
    cmdline = cmdline.strip()

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as header:
        header.write("/* Auto-generated file: boot command line fallback */\n")
        header.write("#pragma once\n\n")
        header.write("static const char FUT_BUILD_BOOT_CMDLINE[] = ")
        header.write(json.dumps(cmdline))
        header.write(";\n")


if __name__ == "__main__":
    main()
