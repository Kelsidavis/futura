// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "comp.h"

int compositor_global_init(struct compositor_state *comp);
int xdg_shell_global_init(struct compositor_state *comp);
void xdg_shell_toplevel_send_close(struct comp_surface *surface);
void xdg_shell_surface_send_configure(struct comp_surface *surface,
                                      int32_t width,
                                      int32_t height,
                                      uint32_t state_flags);
