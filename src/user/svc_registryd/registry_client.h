// SPDX-License-Identifier: MPL-2.0
// registry_client.h - helpers for UDP registry client calls

#ifndef FUTA_REGISTRY_CLIENT_H
#define FUTA_REGISTRY_CLIENT_H

#include <stdint.h>

int registry_client_register(const char *host,
                             uint16_t port,
                             const char *name,
                             uint64_t channel_id);

int registry_client_lookup(const char *host,
                           uint16_t port,
                           const char *name,
                           uint64_t *out_channel_id);

#endif /* FUTA_REGISTRY_CLIENT_H */
