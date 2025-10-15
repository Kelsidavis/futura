// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "comp.h"

void shadow_draw(struct backbuffer *dst,
                 const struct comp_surface *surface,
                 const fut_rect_t *clip);
