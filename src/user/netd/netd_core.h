/* netd_core.h - Host UDP transport for FIPC
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

struct netd;

struct netd *netd_bootstrap(const char *bind_ip, uint16_t port);
bool netd_is_running(const struct netd *nd);
bool netd_poll_once(struct netd *nd, uint32_t timeout_ms);
void netd_shutdown(struct netd *nd);
