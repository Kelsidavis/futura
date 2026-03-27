/* include/kernel/userns.h - User namespace ID mapping helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

struct user_namespace;

#define USERNS_OVERFLOW_ID 65534U

struct user_namespace *userns_get_init(void);
struct user_namespace *userns_create(struct user_namespace *parent);
void userns_ref(struct user_namespace *ns);
void userns_unref(struct user_namespace *ns);

int userns_set_uid_map(struct user_namespace *ns, uint32_t ns_first,
                       uint32_t host_first, uint32_t count);
int userns_set_gid_map(struct user_namespace *ns, uint32_t ns_first,
                       uint32_t host_first, uint32_t count);

uint32_t userns_ns_to_host_uid(struct user_namespace *ns, uint32_t ns_uid);
uint32_t userns_ns_to_host_gid(struct user_namespace *ns, uint32_t ns_gid);
uint32_t userns_host_to_ns_uid(struct user_namespace *ns, uint32_t host_uid);
uint32_t userns_host_to_ns_gid(struct user_namespace *ns, uint32_t host_gid);
