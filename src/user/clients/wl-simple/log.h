// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/stdio.h>

#ifdef DEBUG_WAYLAND
#define WLOG(...) printf(__VA_ARGS__)
#else
#define WLOG(...) do { } while (0)
#endif
