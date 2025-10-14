// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "comp.h"

int shm_backend_init(struct compositor_state *comp);
void shm_backend_finish(struct compositor_state *comp);

int shm_buffer_import(struct wl_resource *buffer_resource,
                      struct comp_buffer *out);
void shm_buffer_release(struct comp_buffer *buffer);
