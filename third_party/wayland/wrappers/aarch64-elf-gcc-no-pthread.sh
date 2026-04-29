#!/bin/sh
# Wrapper around aarch64-elf-gcc that strips '-pthread' from argv.
#
# meson auto-adds -pthread when it detects dependency('threads'), but
# the bare-metal aarch64-elf-gcc rejects it (no native pthread; Futura
# provides its own threading via libfutura). The flag is only needed
# at link time on Linux to pull in libpthread, which isn't relevant
# here. Strip it and forward everything else verbatim.

REAL_CC=/opt/homebrew/bin/aarch64-elf-gcc
args=
for a in "$@"; do
    case "$a" in
        -pthread) ;;     # drop
        *) args="$args $a" ;;
    esac
done
exec "$REAL_CC" $args
