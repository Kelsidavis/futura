/* fw_demo.h - Futuraway demo client helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

struct fw_demo_config {
    uint32_t width;
    uint32_t height;
    const char *service_name;
    const char *registry_host;
    uint16_t registry_port;
    uint64_t surface_id;
};

int fw_demo_run(const struct fw_demo_config *config);
