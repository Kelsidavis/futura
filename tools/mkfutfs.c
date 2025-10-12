// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../subsystems/futura_fs/logfs.h"

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <image-path> [--size-bytes N] [--block-size N]\n", argv0);
}

int main(int argc, char **argv) {
    const char *path = NULL;
    size_t size_bytes = 1u << 20; /* 1 MiB default */
    uint32_t block_size = 4096;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--size-bytes") == 0 && i + 1 < argc) {
            size_bytes = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--block-size") == 0 && i + 1 < argc) {
            block_size = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!path) {
            path = argv[i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!path) {
        usage(argv[0]);
        return 1;
    }

    int rc = futfs_format_path(path, size_bytes, block_size);
    if (rc != 0) {
        fprintf(stderr, "mkfutfs: format failed (%d)\n", rc);
        return 1;
    }
    return 0;
}
