// SPDX-License-Identifier: MPL-2.0
/*
 * fb_hw.h - Futuraway hardware framebuffer backend
 */

#pragma once

#include "fb_host.h"

int fb_hw_open(struct fw_framebuffer *fb);
void fb_hw_close(struct fw_framebuffer *fb);
