// SPDX-License-Identifier: MPL-2.0
// registry_client.h - helpers for UDP registry client calls

#ifndef FUTA_REGISTRY_CLIENT_H
#define FUTA_REGISTRY_CLIENT_H

#include <stdint.h>
#include "registry_common.h"

void registry_client_set_keys(const uint8_t current[SRG_KEY_LEN],
                              const uint8_t previous[SRG_KEY_LEN],
                              uint64_t grace_ms);

int registry_client_register(const char *host,
                             uint16_t port,
                             const char *name,
                             uint64_t channel_id);

int registry_client_register_with_key(const char *host,
                                      uint16_t port,
                                      const char *name,
                                      uint64_t channel_id,
                                      const uint8_t key[SRG_KEY_LEN]);

int registry_client_lookup(const char *host,
                           uint16_t port,
                           const char *name,
                           uint64_t *out_channel_id);

int registry_client_lookup_with_key(const char *host,
                                    uint16_t port,
                                    const char *name,
                                    uint64_t *out_channel_id,
                                    const uint8_t key[SRG_KEY_LEN]);

#endif /* FUTA_REGISTRY_CLIENT_H */
