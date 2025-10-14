// SPDX-License-Identifier: MPL-2.0
//
// win_log.h - Conditional logging helpers for winsrv

#pragma once

#ifdef DEBUG_WINSRV
#include <user/stdio.h>
#define WLOG(fmt, ...) \
    printf("[WINSRV] " fmt, ##__VA_ARGS__)
#else
#define WLOG(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

#define WLOG_READY(w, h, bpp) \
    do { \
        /* avoid double evaluation */ \
        unsigned _w = (unsigned)(w); \
        unsigned _h = (unsigned)(h); \
        unsigned _bpp = (unsigned)(bpp); \
        WLOG("ready %ux%u bpp=%u\n", _w, _h, _bpp); \
        (void)_w; \
        (void)_h; \
        (void)_bpp; \
    } while (0)

#define WLOG_CREATE(w, h, id) \
    do { \
        unsigned _w = (unsigned)(w); \
        unsigned _h = (unsigned)(h); \
        unsigned _id = (unsigned)(id); \
        WLOG("create %ux%u -> id=%u\n", _w, _h, _id); \
        (void)_w; \
        (void)_h; \
        (void)_id; \
    } while (0)

#define WLOG_DAMAGE(id, x, y, w, h) \
    do { \
        unsigned _id = (unsigned)(id); \
        unsigned _x = (unsigned)(x); \
        unsigned _y = (unsigned)(y); \
        unsigned _w = (unsigned)(w); \
        unsigned _h = (unsigned)(h); \
        WLOG("damage id=%u rect x=%u y=%u w=%u h=%u\n", _id, _x, _y, _w, _h); \
        (void)_id; \
        (void)_x; \
        (void)_y; \
        (void)_w; \
        (void)_h; \
    } while (0)
