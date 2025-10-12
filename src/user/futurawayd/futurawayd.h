/* futurawayd.h - FuturaWay compositor (M1) host interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

struct futurawayd_config {
    uint32_t width;
    uint32_t height;
    const char *dump_path;     /* Optional PPM output path */
    const char *service_name;  /* Registry service name */
    const char *registry_host; /* Defaults to 127.0.0.1 when NULL */
    uint16_t registry_port;    /* 0 to skip registry registration */
    uint32_t frame_limit;      /* Stop after N commits (0 = run forever) */
};

int futurawayd_run(const struct futurawayd_config *config);
