/* fipc_sys.h - System metrics publish/subscribe helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct netd;
struct netd_metrics;

bool fipc_sys_publish_metrics(struct netd *nd);
bool fipc_sys_decode_metrics(const uint8_t *buffer, size_t length, struct netd_metrics *out);
bool fipc_sys_publish_kernel_metrics(void);
