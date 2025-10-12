// SPDX-License-Identifier: MPL-2.0
/*
 * devfs.h - Minimal device filesystem registry
 */

#pragma once

#include <stddef.h>

int devfs_create_chr(const char *path, unsigned major, unsigned minor);
int devfs_lookup_chr(const char *path, unsigned *major, unsigned *minor);
