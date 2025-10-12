/* fw_demo_main.c - CLI entry for Futuraway demo client
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#define _POSIX_C_SOURCE 200809L

#include "fw_demo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kernel/fut_fipc.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--w=<width>] [--h=<height>] [--surface=<id>]\n"
            "          [--service=<name>] [--registry=<port>]\n",
            prog);
}

int main(int argc, char **argv) {
    fut_fipc_init();

    struct fw_demo_config cfg = {
        .width = 800,
        .height = 600,
        .service_name = NULL,
        .registry_host = NULL,
        .registry_port = 0,
        .surface_id = 1,
    };

    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--w=", 4) == 0) {
            cfg.width = (uint32_t)strtoul(argv[i] + 4, NULL, 10);
        } else if (strncmp(argv[i], "--h=", 4) == 0) {
            cfg.height = (uint32_t)strtoul(argv[i] + 4, NULL, 10);
        } else if (strncmp(argv[i], "--surface=", 10) == 0) {
            cfg.surface_id = strtoull(argv[i] + 10, NULL, 10);
        } else if (strncmp(argv[i], "--service=", 10) == 0) {
            cfg.service_name = argv[i] + 10;
        } else if (strncmp(argv[i], "--registry=", 11) == 0) {
            cfg.registry_port = (uint16_t)strtoul(argv[i] + 11, NULL, 10);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    int rc = fw_demo_run(&cfg);
    if (rc != 0) {
        fprintf(stderr, "[fw_demo] exit code %d\n", rc);
    }
    return (rc == 0) ? 0 : 1;
}
