/* netd_core.h - Host UDP transport for FIPC
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <kernel/fut_fipc.h>

struct netd;

struct netd *netd_bootstrap(const char *bind_ip, uint16_t port);
bool netd_is_running(const struct netd *nd);
bool netd_poll_once(struct netd *nd, uint32_t timeout_ms);
void netd_shutdown(struct netd *nd);

bool netd_bind_service(struct netd *nd,
                       uint64_t local_channel_id,
                       const char *service_name,
                       const char *registry_host,
                       uint16_t registry_port);

struct netd_metrics {
    uint64_t lookup_attempts;
    uint64_t lookup_hits;
    uint64_t lookup_miss;
    uint64_t send_eagain;
    uint64_t reserved0;
};

bool netd_metrics_snapshot(struct netd *nd, struct netd_metrics *out);
bool netd_metrics_publish(struct netd *nd, struct fut_fipc_channel *sink);
