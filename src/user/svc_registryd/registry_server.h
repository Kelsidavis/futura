// SPDX-License-Identifier: MPL-2.0
// registry_server.h - test-facing registry server helpers

#ifndef FUTA_REGISTRY_SERVER_H
#define FUTA_REGISTRY_SERVER_H

#include <stdbool.h>
#include <stdint.h>

struct registryd;

struct registryd *registryd_start(uint16_t port);
bool registryd_poll_once(struct registryd *rd, uint32_t timeout_ms);
void registryd_stop(struct registryd *rd);

#endif /* FUTA_REGISTRY_SERVER_H */
