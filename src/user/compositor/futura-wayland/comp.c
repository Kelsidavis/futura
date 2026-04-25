#include "comp.h"
#include "cursor.h"
#include "log.h"
#include "seat.h"
#include "shadow.h"
#include "shm_backend.h"
#include "ui_text.h"
#include "xdg_shell.h"

#include <sys/timerfd.h>

#include <errno.h>
#include <stddef.h>
#include <fcntl.h>

#include <wayland-server-protocol.h>
#include <wayland-util.h>

#include <user/sys.h>
#include <user/libfutura.h>

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *dest, int c, size_t n);

/* Safe memcpy: skip copy when destination is obviously invalid
 * (NULL or near-NULL pointer from corrupted struct fields).
 * This prevents the compositor from crashing on heap corruption. */
static inline void *safe_memcpy(void *dest, const void *src, size_t n) {
    if ((uintptr_t)dest < 0x10000u || (uintptr_t)src < 0x10000u) {
        return dest;
    }
    return memcpy(dest, src, n);
}
#define memcpy safe_memcpy

#define NS_PER_MS 1000000ULL

/* Use system fcntl.h definitions when available */
#ifndef O_RDWR
#define O_RDWR      0x0002
#endif
#ifndef PROT_READ
#define PROT_READ   0x0001
#endif
#ifndef PROT_WRITE
#define PROT_WRITE  0x0002
#endif
#ifndef MAP_SHARED
#define MAP_SHARED  0x0001
#endif

/* Colors in ARGB format (0xAARRGGBB) - works with BGRA framebuffers on little-endian */
/* Futura desktop color palette — modern, clean aesthetic */
#define COLOR_CLEAR          0xFF1E1E2Eu  /* Dark purple-gray desktop */
#define COLOR_BAR_FOCUSED    0xFFE8E8E8u  /* Light gray title bar (focused) */
#define COLOR_BAR_UNFOCUSED  0xFFF6F6F6u  /* Very light gray (unfocused) */
#define COLOR_BTN_BASE       0xFFDDDDDDu  /* Button base */

/* Traffic-light window control buttons */
#define COLOR_BTN_CLOSE      0xFFFF5F57u  /* Red close */
#define COLOR_BTN_MINIMIZE   0xFFFEBB2Cu  /* Yellow minimize */
#define COLOR_BTN_MAXIMIZE   0xFF28C840u  /* Green maximize */
#define COLOR_BTN_INACTIVE   0xFFCCCCCCu  /* Gray when unfocused */
#define COLOR_BTN_HOVER      0xFFBBBBBBu  /* Light hover */
#define COLOR_BTN_PRESSED    0xFF999999u  /* Pressed */
#define COLOR_BTN_CROSS      0xFF4D4D4Du  /* Dark glyph on light button */
#define COLOR_TEXT_FOCUSED   0xFF333333u  /* Dark text on light title bar */
#define COLOR_TEXT_UNFOCUSED 0xFF999999u  /* Muted text for unfocused */
#define RESIZE_MARGIN        6
#define MENUBAR_HEIGHT       24

static inline uint32_t clamp_u32(uint32_t value, uint32_t max) {
    return value > max ? max : value;
}

static inline int32_t clamp_i32(int32_t value, int32_t min, int32_t max) {
    if (value < min) {
        return min;
    }
    if (value > max) {
        return max;
    }
    return value;
}

static fut_rect_t rect_clip_to_fb(const struct fut_fb_info *info, fut_rect_t rect, bool *out_valid) {
    fut_rect_t clipped = rect;
    if (clipped.w <= 0 || clipped.h <= 0) {
        if (out_valid) {
            *out_valid = false;
        }
        return clipped;
    }

    int32_t fb_w = (int32_t)info->width;
    int32_t fb_h = (int32_t)info->height;

    if (clipped.x < 0) {
        clipped.w += clipped.x;
        clipped.x = 0;
    }
    if (clipped.y < 0) {
        clipped.h += clipped.y;
        clipped.y = 0;
    }

    if (clipped.x + clipped.w > fb_w) {
        clipped.w = fb_w - clipped.x;
    }
    if (clipped.y + clipped.h > fb_h) {
        clipped.h = fb_h - clipped.y;
    }

    if (clipped.w <= 0 || clipped.h <= 0) {
        if (out_valid) {
            *out_valid = false;
        }
        return clipped;
    }

    if (out_valid) {
        *out_valid = true;
    }
    return clipped;
}

static fut_rect_t rect_union(fut_rect_t a, fut_rect_t b) {
    int32_t ax2 = a.x + a.w;
    int32_t ay2 = a.y + a.h;
    int32_t bx2 = b.x + b.w;
    int32_t by2 = b.y + b.h;

    fut_rect_t out;
    out.x = a.x < b.x ? a.x : b.x;
    out.y = a.y < b.y ? a.y : b.y;
    out.w = (ax2 > bx2 ? ax2 : bx2) - out.x;
    out.h = (ay2 > by2 ? ay2 : by2) - out.y;
    return out;
}

static bool rect_intersection(fut_rect_t a, fut_rect_t b, fut_rect_t *out) {
    int32_t ax2 = a.x + a.w;
    int32_t ay2 = a.y + a.h;
    int32_t bx2 = b.x + b.w;
    int32_t by2 = b.y + b.h;

    int32_t rx1 = a.x > b.x ? a.x : b.x;
    int32_t ry1 = a.y > b.y ? a.y : b.y;
    int32_t rx2 = ax2 < bx2 ? ax2 : bx2;
    int32_t ry2 = ay2 < by2 ? ay2 : by2;

    if (rx2 <= rx1 || ry2 <= ry1) {
        return false;
    }
    if (out) {
        out->x = rx1;
        out->y = ry1;
        out->w = rx2 - rx1;
        out->h = ry2 - ry1;
    }
    return true;
}

static bool rects_overlap_or_touch(fut_rect_t a, fut_rect_t b) {
    int32_t ax2 = a.x + a.w;
    int32_t ay2 = a.y + a.h;
    int32_t bx2 = b.x + b.w;
    int32_t by2 = b.y + b.h;

    return (a.x <= bx2 + 1 && bx2 >= a.x - 1 &&
            b.x <= ax2 + 1 && ax2 >= b.x - 1 &&
            a.y <= by2 + 1 && by2 >= a.y - 1 &&
            b.y <= ay2 + 1 && ay2 >= b.y - 1);
}

/* Optimized damage region coalescing using single-pass greedy merging.
 * Instead of repeatedly searching for overlaps (O(n²) with multiple passes),
 * use a greedy approach that merges the closest regions first.
 * This is much faster and prevents excessive region fragmentation.
 */
static void damage_coalesce(struct damage_accum *dmg) {
    if (!dmg || dmg->count <= 1) {
        return;
    }

    /* Greedy single-pass merging with region limit.
     * If we have many small regions, merge them rather than accumulating.
     */
    int max_iterations = dmg->count; /* Prevent infinite loops */
    int iteration = 0;

    while (iteration < max_iterations && dmg->count > 1) {
        iteration++;
        bool merged = false;

        /* Find the pair with best merge opportunity (most overlap/proximity) */
        int best_i = -1, best_j = -1;
        int32_t best_union_area = 0x7FFFFFFF; /* INT32_MAX equivalent */

        for (int i = 0; i < dmg->count && !merged; ++i) {
            for (int j = i + 1; j < dmg->count; ++j) {
                if (rects_overlap_or_touch(dmg->rects[i], dmg->rects[j])) {
                    fut_rect_t u = rect_union(dmg->rects[i], dmg->rects[j]);
                    int32_t area = u.w * u.h;

                    /* Pick the merge that creates smallest union (least waste) */
                    if (area < best_union_area) {
                        best_union_area = area;
                        best_i = i;
                        best_j = j;
                        merged = true; /* Stop after finding first overlap */
                        break;
                    }
                }
            }
        }

        /* Execute best merge if found */
        if (merged && best_i >= 0 && best_j >= 0) {
            dmg->rects[best_i] = rect_union(dmg->rects[best_i], dmg->rects[best_j]);
            for (int k = best_j; k < dmg->count - 1; ++k) {
                dmg->rects[k] = dmg->rects[k + 1];
            }
            --dmg->count;
        } else {
            break; /* No more merges possible */
        }

        /* Stop if we've reduced to reasonable number of regions */
        if (dmg->count <= 4) {
            break;
        }
    }
}

static void apply_constraints(struct comp_surface *surface,
                              int32_t *width,
                              int32_t *content_height) {
    if (!surface || !width || !content_height) {
        return;
    }
    if (*width < 1) {
        *width = 1;
    }
    if (*content_height < 0) {
        *content_height = 0;
    }
    if (surface->min_w > 0 && *width < surface->min_w) {
        *width = surface->min_w;
    }
    if (surface->min_h > 0 && *content_height < surface->min_h) {
        *content_height = surface->min_h;
    }
    if (surface->max_w > 0 && *width > surface->max_w) {
        *width = surface->max_w;
    }
    if (surface->max_h > 0 && *content_height > surface->max_h) {
        *content_height = surface->max_h;
    }
}

static void comp_apply_committed_size(struct compositor_state *comp,
                                      struct comp_surface *surface,
                                      int32_t new_width,
                                      int32_t new_content_height,
                                      bool was_backed) {
    if (!comp || !surface) {
        return;
    }

    fut_rect_t old_frame = was_backed ? comp_frame_rect(surface)
                                      : (fut_rect_t){0, 0, 0, 0};

    if (surface->have_pending_pos) {
        surface->x = surface->pend_x;
        surface->y = surface->pend_y;
        surface->have_pending_pos = false;
    }

    int32_t width = new_width;
    int32_t content_h = new_content_height;
    apply_constraints(surface, &width, &content_h);

    surface->width = width;
    surface->content_height = content_h;
    comp_surface_update_decorations(surface);
    surface->height = surface->content_height + surface->bar_height;

    int32_t max_x = (int32_t)comp->fb_info.width - surface->width;
    int32_t max_y = (int32_t)comp->fb_info.height - surface->height;
    if (max_x < 0) {
        max_x = 0;
    }
    if (max_y < 0) {
        max_y = 0;
    }

    surface->x = clamp_i32(surface->x, 0, max_x);
    surface->y = clamp_i32(surface->y, 0, max_y);

    fut_rect_t new_frame = comp_frame_rect(surface);
    if (was_backed && old_frame.w > 0 && old_frame.h > 0) {
        comp_damage_add_rect(comp, old_frame);
    }
    comp_damage_add_rect(comp, new_frame);
    comp_surface_mark_damage(surface);

    if (!surface->maximized) {
        surface->saved_x = surface->x;
        surface->saved_y = surface->y;
        surface->saved_w = surface->width;
        surface->saved_h = surface->content_height;
        surface->have_saved_geom = true;
    }
}

static int bb_create(struct backbuffer *bb, int width, int height, int pitch) {
    if (!bb || width <= 0 || height <= 0 || pitch <= 0) {
        printf("[BB-CREATE] Invalid params: bb=%p w=%d h=%d p=%d\n", (void*)bb, width, height, pitch);
        return -1;
    }
    size_t size = (size_t)pitch * (size_t)height;
    printf("[BB-CREATE] Allocating backbuffer: %d x %d, pitch=%d, size=%lu\n", width, height, pitch, (unsigned long)size);
    uint32_t *mem = malloc(size);
    printf("[BB-CREATE] malloc(%lu) returned %p\n", (unsigned long)size, (void*)mem);
    if (!mem) {
        printf("[BB-CREATE] malloc failed!\n");
        return -1;
    }
    bb->px = mem;
    bb->width = width;
    bb->height = height;
    bb->pitch = pitch;
    bb->owns = true;
    /* Initialize to opaque black (0xFF000000) instead of transparent (0x00000000) */
    size_t pixel_count = size / 4;
    for (size_t i = 0; i < pixel_count; i++) {
        mem[i] = 0xFF000000;
    }
    return 0;
}

static void bb_destroy(struct backbuffer *bb) {
    if (!bb) {
        return;
    }
    if (bb->owns && bb->px) {
        free(bb->px);
    }
    bb->px = NULL;
    bb->width = 0;
    bb->height = 0;
    bb->pitch = 0;
    bb->owns = false;
}

void comp_surface_update_decorations(struct comp_surface *surface) {
    if (!surface) {
        return;
    }

    struct compositor_state *comp = surface->comp;
    bool deco_enabled = comp && comp->deco_enabled;
    surface->shadow_px = (comp && comp->shadow_enabled) ? comp->shadow_radius : 0;

    if (!deco_enabled) {
        surface->bar_height = 0;
        surface->min_btn_w = surface->min_btn_h = 0;
        surface->min_btn_x = surface->min_btn_y = 0;
        surface->min_btn_hover = false;
        surface->min_btn_pressed = false;
        surface->btn_w = surface->btn_h = 0;
        surface->btn_x = surface->btn_y = 0;
        surface->btn_hover = false;
        surface->btn_pressed = false;
        surface->height = surface->content_height;
        return;
    }

    surface->bar_height = WINDOW_BAR_HEIGHT;
    surface->min_btn_w = WINDOW_BTN_WIDTH;
    surface->min_btn_h = WINDOW_BTN_HEIGHT;
    surface->btn_w = WINDOW_BTN_WIDTH;
    surface->btn_h = WINDOW_BTN_HEIGHT;
    /* Traffic-light buttons: left side — close (red), minimize (yellow), maximize (green) */
    int btn_y_center = surface->y + (surface->bar_height - WINDOW_BTN_HEIGHT) / 2;
    /* Close button: leftmost */
    surface->btn_x = surface->x + WINDOW_BTN_PADDING;
    surface->btn_y = btn_y_center;
    /* Minimize button: middle */
    surface->min_btn_x = surface->btn_x + WINDOW_BTN_WIDTH + WINDOW_BTN_PADDING;
    surface->min_btn_y = btn_y_center;
    /* Maximize button: rightmost of the three */
    surface->max_btn_x = surface->min_btn_x + WINDOW_BTN_WIDTH + WINDOW_BTN_PADDING;
    surface->max_btn_y = btn_y_center;
    surface->max_btn_w = WINDOW_BTN_WIDTH;
    surface->max_btn_h = WINDOW_BTN_HEIGHT;

    if (surface->btn_x < surface->x + WINDOW_BTN_PADDING) {
        surface->btn_x = surface->x + WINDOW_BTN_PADDING;
    }
    if (surface->btn_y < surface->y + 2) {
        surface->btn_y = surface->y + 2;
    }
    if (surface->min_btn_x < surface->x + WINDOW_BTN_PADDING) {
        surface->min_btn_x = surface->x + WINDOW_BTN_PADDING;
    }
    if (surface->min_btn_y < surface->y + 2) {
        surface->min_btn_y = surface->y + 2;
    }
    surface->height = surface->content_height + surface->bar_height;
}

void comp_show_toast(struct compositor_state *comp, const char *text) {
    if (!comp || !text) return;
    int i = 0;
    while (text[i] && i < 127) { comp->toast_text[i] = text[i]; i++; }
    comp->toast_text[i] = '\0';
    /* Get current time and set expiry 3 seconds from now */
    struct { long tv_sec; long tv_nsec; } ts = {0, 0};
    extern long sys_call2(long nr, long a, long b);
    sys_call2(98, 0, (long)&ts);
    comp->toast_expire_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                            (uint64_t)ts.tv_nsec + 5000000000ULL;  /* 5 seconds */
    comp->toast_active = true;
    comp_damage_add_full(comp);
    comp->needs_repaint = true;
}

/* Optimized bulk fill using 64-bit writes (2 pixels at a time).
 * This is significantly faster than pixel-by-pixel writes for large fills.
 * Further optimization could use SIMD (NEON/SSE) for 128-bit or wider writes.
 */
static void bb_fill_rect(struct backbuffer *bb, fut_rect_t rect, uint32_t argb) {
    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!bb || (uintptr_t)bb < 0x10000) {
        return;
    }
    if (!bb->px || (uintptr_t)bb->px < 0x10000 || rect.w <= 0 || rect.h <= 0) {
        return;
    }

    /* Bounds check: clip rect to backbuffer dimensions */
    if (rect.x < 0) {
        rect.w += rect.x;
        rect.x = 0;
    }
    if (rect.y < 0) {
        rect.h += rect.y;
        rect.y = 0;
    }
    if (rect.x + rect.w > bb->width) {
        rect.w = bb->width - rect.x;
    }
    if (rect.y + rect.h > bb->height) {
        rect.h = bb->height - rect.y;
    }
    if (rect.w <= 0 || rect.h <= 0) {
        return;
    }

    /* Use char* for byte-level row arithmetic (char* may alias any type per C standard).
     * Then cast to uint32_t* at row boundary for pixel access. */
    char *base = (char *)bb->px;

    for (int32_t y = 0; y < rect.h; ++y) {
        /* Compute row start using char* arithmetic, then cast to uint32_t* */
        uint32_t *row = (uint32_t *)(base + (size_t)(rect.y + y) * bb->pitch);
        uint32_t *dst = row + rect.x;

        for (int32_t x = 0; x < rect.w; ++x) {
            dst[x] = argb;
        }
    }
}

/* Pixel blit using memcpy for each row.
 * Modern compilers optimize memcpy very well, often using SIMD instructions.
 * Using char* for byte-level pointer arithmetic (allowed to alias per C standard).
 */
static void blit_argb(const char *src_base,
                      int src_pitch,
                      char *dst_base,
                      int dst_pitch,
                      int width,
                      int height) {
    if (!src_base || !dst_base || width <= 0 || height <= 0) {
        return;
    }
    if ((uintptr_t)dst_base < 0x10000 || (uintptr_t)src_base < 0x10000) {
        return;
    }
    size_t row_bytes = (size_t)width * 4u;
    const char *src = src_base;
    char *dst = dst_base;

    for (int y = 0; y < height; ++y) {
        memcpy(dst, src, row_bytes);
        src += src_pitch;
        dst += dst_pitch;
    }
}

static void draw_bar_segment(struct backbuffer *dst, fut_rect_t rect,
                             int32_t bar_top, int32_t bar_h, bool focused) {
    /* Refined title bar gradient with rounded top corners + focused accent */
    #define BAR_CORNER_R 6  /* Radius for rounded top corners */
    uint32_t top_col = focused ? 0xFFECECF6u : 0xFFF8F8FAu;
    uint32_t bot_col = focused ? 0xFFD4D4E2u : 0xFFEAEAEEu;
    char *base = (char *)dst->px;
    for (int32_t y = 0; y < rect.h; ++y) {
        int32_t gy = rect.y + y;
        int32_t bar_y = gy - bar_top;  /* row within full bar (0..bar_h-1) */
        uint32_t color;
        if (focused && bar_y >= 0 && bar_y < 2) {
            /* 2px accent line at actual top of focused window */
            color = (bar_y == 0) ? 0xFF5577CCu : 0xFF6688DDu;
        } else if (bar_y == 0) {
            color = focused ? 0xFFFCFCFEu : 0xFFFEFEFEu;
        } else if (bar_y == bar_h - 1) {
            color = focused ? 0xFFB8B8BEu : 0xFFD0D0D4u;
        } else {
            int t = (bar_h > 2) ? (bar_y * 255 / (bar_h - 2)) : 0;
            uint8_t r_c = (uint8_t)(((top_col >> 16) & 0xFF) + ((int)((bot_col >> 16) & 0xFF) - (int)((top_col >> 16) & 0xFF)) * t / 255);
            uint8_t g_c = (uint8_t)(((top_col >> 8) & 0xFF) + ((int)((bot_col >> 8) & 0xFF) - (int)((top_col >> 8) & 0xFF)) * t / 255);
            uint8_t b_c = (uint8_t)((top_col & 0xFF) + ((int)(bot_col & 0xFF) - (int)(top_col & 0xFF)) * t / 255);
            color = 0xFF000000u | ((uint32_t)r_c << 16) | ((uint32_t)g_c << 8) | b_c;
        }
        uint32_t *row = (uint32_t *)(base + (size_t)gy * dst->pitch);
        for (int32_t x = 0; x < rect.w; ++x) {
            /* Round top-left and top-right corners */
            if (y < BAR_CORNER_R) {
                int32_t dx_left = x;
                int32_t dx_right = rect.w - 1 - x;
                int32_t dy = BAR_CORNER_R - y;
                bool in_left = (dx_left < BAR_CORNER_R);
                bool in_right = (dx_right < BAR_CORNER_R);
                if (in_left) {
                    int32_t cx_d = BAR_CORNER_R - dx_left;
                    int32_t dist_sq = cx_d * cx_d + dy * dy;
                    int32_t r_sq = BAR_CORNER_R * BAR_CORNER_R;
                    if (dist_sq > r_sq) continue;  /* Outside rounded corner */
                }
                if (in_right) {
                    int32_t cx_d = BAR_CORNER_R - dx_right;
                    int32_t dist_sq = cx_d * cx_d + dy * dy;
                    int32_t r_sq = BAR_CORNER_R * BAR_CORNER_R;
                    if (dist_sq > r_sq) continue;
                }
            }
            /* Subtle noise dither for frosted-glass texture */
            uint32_t nh = (uint32_t)((rect.x + x) * 2971 + gy * 6337);
            nh ^= nh >> 13; nh *= 0x45d9f3bu; nh ^= nh >> 16;
            int noise = (int)(nh & 0x3) - 1;  /* -1..2 */
            int nr = (int)((color >> 16) & 0xFF) + noise;
            int ng = (int)((color >> 8) & 0xFF) + noise;
            int nb = (int)(color & 0xFF) + noise;
            if (nr < 0) nr = 0;
            if (nr > 255) nr = 255;
            if (ng < 0) ng = 0;
            if (ng > 255) ng = 255;
            if (nb < 0) nb = 0;
            if (nb > 255) nb = 255;
            row[rect.x + x] = 0xFF000000u | ((uint32_t)nr << 16) | ((uint32_t)ng << 8) | (uint32_t)nb;
        }
    }
    #undef BAR_CORNER_R
}

static void draw_minimize_button(struct backbuffer *dst,
                                 const struct comp_surface *surface,
                                 fut_rect_t clip) {
    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!dst || (uintptr_t)dst < 0x10000) {
        return;
    }
    if (!dst->px || (uintptr_t)dst->px < 0x10000 || clip.w <= 0 || clip.h <= 0) {
        return;
    }

    fut_rect_t btn = comp_min_btn_rect(surface);
    if (btn.w <= 0 || btn.h <= 0) {
        return;
    }

    /* Traffic-light style: yellow circle for minimize */
    bool focused = (surface->comp && surface == surface->comp->focused_surface);
    uint32_t btn_color = focused ? COLOR_BTN_MINIMIZE : COLOR_BTN_INACTIVE;
    if (surface->min_btn_pressed) btn_color = 0xFFE09B13u;
    else if (surface->min_btn_hover) btn_color = 0xFFFDD44Bu;

    int32_t cx = btn.x + btn.w / 2;
    int32_t cy = btn.y + btn.h / 2;
    int32_t r = (btn.w < btn.h ? btn.w : btn.h) / 2 - 1;

    char *base_ptr = (char *)dst->px;
    for (int32_t y = 0; y < clip.h; ++y) {
        int32_t gy = clip.y + y;
        uint32_t *row = (uint32_t *)(base_ptr + (size_t)gy * dst->pitch);
        uint32_t *px = row + clip.x;
        for (int32_t x = 0; x < clip.w; ++x) {
            int32_t gx = clip.x + x;
            int32_t dx = gx - cx, dy = gy - cy;
            if (dx * dx + dy * dy <= r * r) {
                /* Draw horizontal line glyph on hover */
                if (surface->min_btn_hover &&
                    dy == 0 && dx >= -3 && dx <= 3) {
                    px[x] = 0xFF8B6914u;  /* Dark amber line */
                } else {
                    px[x] = btn_color;
                }
            }
        }
    }
}

static void draw_maximize_button(struct backbuffer *dst,
                                 const struct comp_surface *surface,
                                 fut_rect_t clip) {
    if (!dst || (uintptr_t)dst < 0x10000) return;
    if (!dst->px || (uintptr_t)dst->px < 0x10000 || clip.w <= 0 || clip.h <= 0) return;

    fut_rect_t btn = comp_max_btn_rect(surface);
    if (btn.w <= 0 || btn.h <= 0) return;

    bool focused = (surface->comp && surface == surface->comp->focused_surface);
    uint32_t btn_color = focused ? COLOR_BTN_MAXIMIZE : COLOR_BTN_INACTIVE;
    if (surface->max_btn_pressed) btn_color = 0xFF1E9E30u;
    else if (surface->max_btn_hover) btn_color = 0xFF3BD555u;

    int32_t cx = btn.x + btn.w / 2;
    int32_t cy = btn.y + btn.h / 2;
    int32_t r = (btn.w < btn.h ? btn.w : btn.h) / 2 - 1;

    char *base_ptr = (char *)dst->px;
    for (int32_t y = 0; y < clip.h; ++y) {
        int32_t gy = clip.y + y;
        uint32_t *row = (uint32_t *)(base_ptr + (size_t)gy * dst->pitch);
        uint32_t *px = row + clip.x;
        for (int32_t x = 0; x < clip.w; ++x) {
            int32_t gx = clip.x + x;
            int32_t dx = gx - cx, dy = gy - cy;
            if (dx * dx + dy * dy <= r * r) {
                /* Draw small square glyph on hover */
                if (surface->max_btn_hover &&
                    dx >= -3 && dx <= 3 && dy >= -3 && dy <= 3 &&
                    (dx == -3 || dx == 3 || dy == -3 || dy == 3)) {
                    px[x] = 0xFF0F6B1Du;  /* Dark green outline */
                } else {
                    px[x] = btn_color;
                }
            }
        }
    }
}

static void draw_close_button(struct backbuffer *dst,
                              const struct comp_surface *surface,
                              fut_rect_t clip) {
    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!dst || (uintptr_t)dst < 0x10000) {
        return;
    }
    if (!dst->px || (uintptr_t)dst->px < 0x10000 || clip.w <= 0 || clip.h <= 0) {
        return;
    }

    fut_rect_t btn = comp_btn_rect(surface);
    if (btn.w <= 0 || btn.h <= 0) {
        return;
    }

    /* Traffic-light style: red circle for close */
    bool focused = (surface->comp && surface == surface->comp->focused_surface);
    uint32_t btn_color = focused ? COLOR_BTN_CLOSE : COLOR_BTN_INACTIVE;
    if (surface->btn_pressed) btn_color = 0xFFBF2519u;
    else if (surface->btn_hover) btn_color = 0xFFFF6961u;

    int32_t cx = btn.x + btn.w / 2;
    int32_t cy = btn.y + btn.h / 2;
    int32_t r = (btn.w < btn.h ? btn.w : btn.h) / 2 - 1;

    char *base_ptr = (char *)dst->px;
    for (int32_t y = 0; y < clip.h; ++y) {
        int32_t gy = clip.y + y;
        uint32_t *row = (uint32_t *)(base_ptr + (size_t)gy * dst->pitch);
        uint32_t *px = row + clip.x;
        for (int32_t x = 0; x < clip.w; ++x) {
            int32_t gx = clip.x + x;
            int32_t dx = gx - cx, dy = gy - cy;
            if (dx * dx + dy * dy <= r * r) {
                /* Draw X glyph on hover */
                int32_t lx = gx - btn.x, ly = gy - btn.y;
                if (surface->btn_hover && (lx == ly || lx == (btn.w - 1 - ly)) &&
                    lx >= 3 && lx < btn.w - 3) {
                    px[x] = 0xFF4D0000u;  /* Dark red X */
                } else {
                    px[x] = btn_color;
                }
            }
        }
    }
}

static void draw_title_text(struct backbuffer *dst,
                            struct comp_surface *surface,
                            const fut_rect_t *damage_clip) {
    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!dst || (uintptr_t)dst < 0x10000) {
        return;
    }
    if (!dst->px || (uintptr_t)dst->px < 0x10000 || !surface || !damage_clip) {
        return;
    }
    if (!surface->comp || !surface->comp->deco_enabled || surface->bar_height <= 0) {
        surface->title_dirty = false;
        return;
    }

    fut_rect_t bar_rect = comp_bar_rect(surface);
    if (bar_rect.h <= 0) {
        surface->title_dirty = false;
        return;
    }

    fut_rect_t clip;
    if (!rect_intersection(*damage_clip, bar_rect, &clip)) {
        return;
    }

    int available_px = surface->width - (8 + WINDOW_BTN_WIDTH + WINDOW_BTN_PADDING + 8);
    if (available_px <= 0) {
        surface->title_dirty = false;
        return;
    }

    int max_chars = available_px / UI_FONT_WIDTH;
    if (max_chars <= 0) {
        surface->title_dirty = false;
        return;
    }

    const char *title = surface->title;
    if (!title || title[0] == '\0') {
        surface->title_dirty = false;
        return;
    }

    char draw_buf[WINDOW_TITLE_MAX];
    int length = 0;
    while (length < (WINDOW_TITLE_MAX - 1) && title[length] != '\0') {
        draw_buf[length] = title[length];
        ++length;
    }
    draw_buf[length] = '\0';

    int draw_len = length;
    if (draw_len > max_chars) {
        if (max_chars >= 3) {
            int copy_len = max_chars - 3;
            if (copy_len < 0) {
                copy_len = 0;
            }
            if (copy_len > length) {
                copy_len = length;
            }
            for (int i = 0; i < copy_len; ++i) {
                draw_buf[i] = title[i];
            }
            draw_buf[copy_len] = '.';
            draw_buf[copy_len + 1] = '.';
            draw_buf[copy_len + 2] = '.';
            draw_buf[copy_len + 3] = '\0';
            draw_len = copy_len + 3;
        } else {
            if (max_chars > length) {
                max_chars = length;
            }
            for (int i = 0; i < max_chars; ++i) {
                draw_buf[i] = title[i];
            }
            draw_buf[max_chars] = '\0';
            draw_len = max_chars;
        }
    }

    if (draw_len <= 0) {
        surface->title_dirty = false;
        return;
    }

    /* Center title text in the title bar (between buttons on left and right edge) */
    int btn_area = 3 * (WINDOW_BTN_WIDTH + WINDOW_BTN_PADDING) + 8;
    int title_pixel_width = draw_len * UI_FONT_WIDTH;
    int text_x = surface->x + (surface->width - title_pixel_width) / 2;
    /* Clamp: don't overlap with traffic-light buttons */
    if (text_x < surface->x + btn_area) text_x = surface->x + btn_area;
    int text_y = surface->y + (surface->bar_height - UI_FONT_HEIGHT) / 2;
    if (text_y < surface->y) {
        text_y = surface->y;
    }

    fut_rect_t text_rect = {
        .x = text_x,
        .y = text_y,
        .w = draw_len * UI_FONT_WIDTH,
        .h = UI_FONT_HEIGHT,
    };

    fut_rect_t text_clip;
    if (!rect_intersection(*damage_clip, text_rect, &text_clip)) {
        surface->title_dirty = false;
        return;
    }

    uint32_t color = (surface->comp->focused_surface == surface)
                         ? COLOR_TEXT_FOCUSED
                         : COLOR_TEXT_UNFOCUSED;

    ui_draw_text(dst->px,
                 dst->pitch,
                 text_x,
                 text_y,
                 color,
                 draw_buf,
                 text_clip.x,
                 text_clip.y,
                 text_clip.w,
                 text_clip.h);

    surface->title_dirty = false;
}

static int comp_configure_backbuffers(struct compositor_state *comp);
static uint64_t comp_now_ns(void);

static void comp_surface_link_tail(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || !surface || surface->in_zlist) {
        return;
    }
    wl_list_insert(comp->surfaces.prev, &surface->link);
    surface->in_zlist = true;
}

static void comp_surface_unlink(struct comp_surface *surface) {
    if (!surface || !surface->in_zlist) {
        return;
    }
    wl_list_remove(&surface->link);
    surface->in_zlist = false;
}

void comp_surface_mark_damage(struct comp_surface *surface) {
    if (!surface) {
        return;
    }
    surface->damage_since_present = true;
}

void comp_damage_add_rect(struct compositor_state *comp, fut_rect_t rect) {
    if (!comp) {
        return;
    }

    bool valid = false;
    fut_rect_t clipped = rect_clip_to_fb(&comp->fb_info, rect, &valid);
    if (!valid) {
        return;
    }

    struct damage_accum *dmg = &comp->frame_damage;
    if (dmg->count >= MAX_DAMAGE) {
        comp_damage_add_full(comp);
        return;
    }

    dmg->rects[dmg->count++] = clipped;
    damage_coalesce(dmg);
    comp->needs_repaint = true;
}

void comp_damage_add_full(struct compositor_state *comp) {
    if (!comp) {
        return;
    }
    struct damage_accum *dmg = &comp->frame_damage;
    dmg->count = 1;
    dmg->rects[0].x = 0;
    dmg->rects[0].y = 0;
    dmg->rects[0].w = (int32_t)comp->fb_info.width;
    dmg->rects[0].h = (int32_t)comp->fb_info.height;
    comp->needs_repaint = true;
}

int comp_set_backbuffer_enabled(struct compositor_state *comp, bool enabled) {
    if (!comp) {
        return -1;
    }
    comp->backbuffer_enabled = enabled;
    return comp_configure_backbuffers(comp);
}

const struct fut_fb_info *comp_get_fb_info(const struct compositor_state *comp) {
    return comp ? &comp->fb_info : NULL;
}

int comp_state_init(struct compositor_state *comp) {
    if (!comp) {
        return -1;
    }

    bool deco_flag = comp->deco_enabled;
    bool backbuffer_flag = comp->backbuffer_enabled;
    bool shadow_flag = comp->shadow_enabled;
    bool resize_flag = comp->resize_enabled;
    bool throttle_flag = comp->throttle_enabled;
    int32_t shadow_radius = comp->shadow_radius;

    memset(comp, 0, sizeof(*comp));
    comp->multi_enabled = (WAYLAND_MULTI_BUILD != 0);
    comp->deco_enabled = (WAYLAND_DECO_BUILD != 0) ? deco_flag : false;
    comp->backbuffer_enabled = (WAYLAND_BACKBUFFER_BUILD != 0) ? backbuffer_flag : false;
    comp->shadow_enabled = (WAYLAND_SHADOW_BUILD != 0) ? shadow_flag : false;
    comp->shadow_radius = comp->shadow_enabled
                              ? (shadow_radius > 0 ? shadow_radius : WINDOW_SHADOW_DEFAULT)
                              : 0;
    comp->resize_enabled = (WAYLAND_RESIZE_BUILD != 0) ? resize_flag : true;
    comp->throttle_enabled = throttle_flag;
    comp->resize_surface = NULL;
    wl_list_init(&comp->surfaces);
    comp->fb_fd = -1;
    comp->timerfd = -1;
    comp->timer_source = NULL;
    comp->next_tick_ms = 0;
    comp->target_ms = 16u;
    comp->last_timer_tick_ms = 0;
    comp->vsync_hint_ms = comp->target_ms;
    comp->last_clock_min = -1;
    comp->dock_hover_index = -1;
    comp->alt_tab_active = false;
    comp->alt_tab_index = 0;
    comp->alt_tab_count = 0;
    comp->dock_tooltip_index = -1;
    comp->futura_menu_active = false;
    comp->futura_menu_hover = -1;
    comp->shortcut_overlay_active = false;
    comp->toast_active = false;
    comp->toast_text[0] = '\0';
    comp->toast_expire_ns = 0;

    /* Try to open /dev/fb0, but fall back to virtual framebuffer if not available */
    int fd = (int)sys_open("/dev/fb0", O_RDWR, 0);
    struct fut_fb_info info = {0};
    void *map = NULL;

    if (fd < 0) {
        /* Framebuffer device not available - create a virtual framebuffer */
        info.width = 1024;
        info.height = 768;
        info.pitch = 1024 * 4;
        info.bpp = 32;

        size_t map_size = (size_t)info.pitch * info.height;
        map = (void *)malloc(map_size);
        if (!map) {
            printf("[WAYLAND] failed to allocate virtual framebuffer\n");
            return -1;
        }

        memset(map, 0, map_size);
        comp->fb_fd = -1;
        comp->fb_map = (uint8_t *)map;
        comp->fb_map_size = map_size;
        comp->fb_info = info;
    } else {
        /* Got real framebuffer device */
        if (sys_ioctl(fd, FBIOGET_INFO, (long)&info) < 0) {
            printf("[WAYLAND] FBIOGET_INFO failed\n");
            sys_close(fd);
            return -1;
        }

        if (info.bpp != 32) {
            printf("[WAYLAND] unsupported bpp=%u\n", info.bpp);
            sys_close(fd);
            return -1;
        }

        size_t map_size = (size_t)info.pitch * info.height;
        map = (void *)sys_mmap(NULL, (long)map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if ((long)map < 0) {
            printf("[WAYLAND] mmap failed\n");
            sys_close(fd);
            return -1;
        }

        comp->fb_fd = fd;
        comp->fb_map = (uint8_t *)map;
        comp->fb_map_size = map_size;
        comp->fb_info = info;

        /* Clear framebuffer to opaque black on startup */
        uint32_t *fb32 = (uint32_t *)map;
        size_t pixel_count = map_size / 4;
        for (size_t i = 0; i < pixel_count; i++) {
            fb32[i] = 0xFF000000;
        }
        printf("[WAYLAND] Cleared framebuffer to black (%zu pixels)\n", pixel_count);

        /* Flush to ensure clear is visible */
        sys_ioctl(fd, FBIOFLUSH, 0);
    }

    comp->running = true;
    comp->last_present_ns = 0;
    comp->frame_damage.count = 0;
    comp->bb_index = 0;
    comp->pointer_x = (int32_t)info.width / 2;
    comp->pointer_y = (int32_t)info.height / 2;

    comp->cursor = cursor_create();
    if (!comp->cursor) {
        printf("[WAYLAND] cursor create failed\n");
        comp_state_finish(comp);
        return -1;
    }
    cursor_set_position(comp->cursor, comp->pointer_x, comp->pointer_y);

    if (comp_configure_backbuffers(comp) != 0) {
        printf("[WAYLAND] backbuffer failed\n");
        comp_state_finish(comp);
        return -1;
    }

    uint32_t hint = comp->vsync_hint_ms;
    (void)sys_ioctl(comp->fb_fd, FBIOSET_VSYNC_MS, (long)&hint);
    comp->vsync_hint_ms = hint;
    comp->last_present_ns = comp_now_ns() - (uint64_t)comp->target_ms * 1000000ULL;
    return 0;
}

void comp_state_finish(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    comp->running = false;
    comp_scheduler_stop(comp);

    for (int i = 0; i < 2; ++i) {
        bb_destroy(&comp->bb[i]);
    }

    if (comp->cursor) {
        cursor_destroy(comp->cursor);
        comp->cursor = NULL;
    }

    if (comp->fb_map && comp->fb_map_size) {
        if (comp->fb_fd >= 0) {
            /* Real framebuffer - unmap from kernel */
            sys_munmap_call(comp->fb_map, (long)comp->fb_map_size);
        } else {
            /* Virtual framebuffer - free allocated memory */
            free(comp->fb_map);
        }
        comp->fb_map = NULL;
        comp->fb_map_size = 0;
    }
    if (comp->fb_fd >= 0) {
        sys_close(comp->fb_fd);
        comp->fb_fd = -1;
    }
}

static int comp_configure_backbuffers(struct compositor_state *comp) {
    if (!comp) {
        return -1;
    }

    for (int i = 0; i < 2; ++i) {
        bb_destroy(&comp->bb[i]);
    }
    comp->bb_index = 0;

    if (!comp->backbuffer_enabled) {
        comp->bb[0].px = (uint32_t *)comp->fb_map;
        comp->bb[0].width = (int)comp->fb_info.width;
        comp->bb[0].height = (int)comp->fb_info.height;
        comp->bb[0].pitch = (int)comp->fb_info.pitch;
        comp->bb[0].owns = false;
        comp->bb[1].px = NULL;
        comp->bb[1].width = 0;
        comp->bb[1].height = 0;
        comp->bb[1].pitch = 0;
        comp->bb[1].owns = false;
        return 0;
    }

    int width = (int)comp->fb_info.width;
    int height = (int)comp->fb_info.height;
    int pitch = (int)comp->fb_info.pitch;

    if (bb_create(&comp->bb[0], width, height, pitch) != 0 ||
        bb_create(&comp->bb[1], width, height, pitch) != 0) {
        bb_destroy(&comp->bb[0]);
        bb_destroy(&comp->bb[1]);
        printf("[WAYLAND] backbuffer allocation failed, falling back to single buffer\n");
        comp->backbuffer_enabled = false;
        comp->bb[0].px = (uint32_t *)comp->fb_map;
        comp->bb[0].width = (int)comp->fb_info.width;
        comp->bb[0].height = (int)comp->fb_info.height;
        comp->bb[0].pitch = (int)comp->fb_info.pitch;
        comp->bb[0].owns = false;
        comp->bb[1].px = NULL;
        comp->bb[1].width = 0;
        comp->bb[1].height = 0;
        comp->bb[1].pitch = 0;
        comp->bb[1].owns = false;
        return 0;
    }
    return 0;
}

struct comp_surface *comp_surface_create(struct compositor_state *comp,
                                         struct wl_resource *surface_resource) {
    struct comp_surface *surface = malloc(sizeof(*surface));
    if (!surface) {
        return NULL;
    }
    memset(surface, 0, sizeof(*surface));
    surface->comp = comp;
    surface->x = 0;
    surface->y = 0;
    surface->pos_initialised = false;
    surface->in_zlist = false;
    surface->surface_resource = surface_resource;
    wl_list_init(&surface->frame_callbacks);
    surface->has_pending_damage = false;
    surface->has_pending_buffer = false;
    surface->had_new_buffer = false;
    surface->composed_this_tick = false;
    surface->damage_since_present = false;
    surface->surface_id = ++comp->next_surface_id;
    surface->cfg_serial_last = 0;
    surface->cfg_serial_pending = 0;
    surface->pend_w = 0;
    surface->pend_h = 0;
    surface->have_pending_size = false;
    surface->pend_x = 0;
    surface->pend_y = 0;
    surface->have_pending_pos = false;
    surface->min_w = 0;
    surface->min_h = 0;
    surface->max_w = 0;
    surface->max_h = 0;
    surface->maximized = false;
    surface->resizing = RSZ_NONE;
    surface->resize_dx = 0;
    surface->resize_dy = 0;
    surface->base_x = 0;
    surface->base_y = 0;
    surface->base_w = 0;
    surface->base_h = 0;
    surface->base_total_h = 0;
    surface->saved_x = 0;
    surface->saved_y = 0;
    surface->saved_w = 0;
    surface->saved_h = 0;
    surface->have_saved_geom = false;
    surface->bar_height = comp && comp->deco_enabled ? WINDOW_BAR_HEIGHT : 0;
    comp_surface_update_decorations(surface);
    comp_surface_link_tail(comp, surface);
    if (!comp->active_surface) {
        comp->active_surface = surface;
        /* Auto-focus the first surface so keyboard input works immediately */
        if (comp->seat) {
            seat_focus_surface(comp->seat, surface);
        }
    }
    return surface;
}

void comp_surface_destroy(struct comp_surface *surface) {
    /* Defensive check: reject NULL and corrupted pointers (addresses < 0x10000) */
    if (!surface || (uintptr_t)surface < 0x10000) {
        return;
    }

    /* If a commit is in progress, defer destruction until commit finishes.
     * This prevents use-after-free when event re-entrancy (e.g. buffer
     * release triggering client disconnect) destroys the surface mid-commit. */
    if (surface->in_commit) {
        surface->destroy_deferred = true;
        return;
    }

    /* Clear the resource's back-pointer so no stale reference survives. */
    if (surface->surface_resource) {
        wl_resource_set_user_data(surface->surface_resource, NULL);
    }

    struct comp_frame_callback *cb, *tmp;
    wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
        wl_resource_destroy(cb->resource);
    }

    if (surface->backing) {
        free(surface->backing);
        surface->backing = NULL;
        surface->backing_size = 0;
    }

    struct compositor_state *comp = surface->comp;
    if (comp) {
        comp_surface_unlink(surface);
        if (surface->has_backing) {
            comp_damage_add_rect(comp, comp_frame_rect(surface));
            comp_surface_mark_damage(surface);
        }
        if (comp->active_surface == surface) {
            if (!wl_list_empty(&comp->surfaces)) {
                struct wl_list *tail_link = comp->surfaces.prev;
                comp->active_surface = wl_container_of(tail_link, surface, link);
            } else {
                comp->active_surface = NULL;
            }
        }
        if (comp->focused_surface == surface) {
            comp->focused_surface = NULL;
            /* Focus the next visible window */
            if (!wl_list_empty(&comp->surfaces)) {
                struct comp_surface *other;
                wl_list_for_each_reverse(other, &comp->surfaces, link) {
                    if (other != surface && !other->minimized) {
                        comp->focused_surface = other;
                        break;
                    }
                }
            }
        }
        if (comp->drag_surface == surface) {
            comp->drag_surface = NULL;
            comp->dragging = false;
        }
        if (comp->resize_surface == surface) {
            comp->resize_surface = NULL;
        }
        if (comp->seat) {
            seat_surface_destroyed(comp->seat, surface);
        }
    }

    free(surface);
}

void comp_surface_attach(struct comp_surface *surface,
                         struct wl_resource *buffer_resource) {
    if (!surface) {
        return;
    }
    surface->pending_buffer_resource = buffer_resource;
    surface->has_pending_buffer = (buffer_resource != NULL);
    surface->had_new_buffer = (buffer_resource != NULL);
}

void comp_surface_damage(struct comp_surface *surface,
                         int32_t x, int32_t y,
                         int32_t width, int32_t height) {
    if (!surface) {
        return;
    }

    surface->pending_damage.x = x;
    surface->pending_damage.y = y;
    surface->pending_damage.w = width;
    surface->pending_damage.h = height;
    surface->has_pending_damage = true;
}

static uint64_t comp_now_msec(void) {
    /* sys_time_millis_call() returns the kernel tick counter, not
     * milliseconds.  The LAPIC timer runs at 100 Hz (10 ms/tick),
     * so multiply by 10 to get real milliseconds.  Must return
     * uint64_t to match timerfd's now_ms() — a uint32_t would
     * diverge from the timerfd clock after ~49 days and stall the
     * timer permanently. */
    return (uint64_t)sys_time_millis_call() * 10;
}

static void frame_callback_resource_destroy(struct wl_resource *resource) {
    struct comp_frame_callback *cb = wl_resource_get_user_data(resource);
    if (!cb) {
        return;
    }
    wl_list_remove(&cb->link);
    free(cb);
}

void comp_surface_commit(struct comp_surface *surface) {
    if (!surface) {
        return;
    }

    surface->in_commit = true;

    struct compositor_state *comp = surface->comp;
    bool throttle = comp && comp->throttle_enabled;
    bool has_buffer = surface->has_pending_buffer && surface->pending_buffer_resource;
    bool has_damage = surface->has_pending_damage;

    if (throttle && !has_buffer && !has_damage) {
#ifdef DEBUG_WAYLAND
        WLOG("[WAYLAND] throttle skip win=%p\n", (void *)surface);
#endif
        goto commit_done;
    }

    if (has_buffer) {
        struct comp_buffer buffer = {0};
        if (shm_buffer_import(surface->pending_buffer_resource, &buffer) == 0) {
            /* buffer imported successfully */
            /* Defense in depth: validate buffer before use */
            if (!buffer.data || buffer.width <= 0 || buffer.height <= 0 || buffer.stride <= 0
                || buffer.stride < buffer.width * 4) {
                shm_buffer_release(&buffer);
                wl_buffer_send_release(surface->pending_buffer_resource);
                surface->pending_buffer_resource = NULL;
                surface->has_pending_buffer = false;
                goto commit_done;
            }

            size_t required = (size_t)buffer.stride * (size_t)buffer.height;
            if (required == 0) {
                required = (size_t)buffer.width * 4u;
            }
            if (surface->backing_size < required) {
                uint8_t *new_mem = realloc(surface->backing, required);
                if (!new_mem) {
                    shm_buffer_release(&buffer);
                    surface->pending_buffer_resource = NULL;
                    surface->has_pending_buffer = false;
                    goto commit_done;
                }
                surface->backing = new_mem;
                surface->backing_size = required;
            }
            bool had_backing = surface->has_backing;
            if (!surface->backing || (uintptr_t)surface->backing < 0x10000) {
                shm_buffer_release(&buffer);
                wl_buffer_send_release(surface->pending_buffer_resource);
                surface->pending_buffer_resource = NULL;
                surface->has_pending_buffer = false;
                goto commit_done;
            }
            /* Cache backing pointer locally so the compiler doesn't
             * reload it from the struct each iteration (memcpy is an
             * opaque call that could alias surface->backing). */
            uint8_t *commit_dst = surface->backing;
            for (int32_t row = 0; row < buffer.height; ++row) {
                const uint8_t *src_row = (const uint8_t *)buffer.data + (size_t)row * buffer.stride;
                uint8_t *dst_row = commit_dst + (size_t)row * buffer.stride;
                memcpy(dst_row, src_row, (size_t)buffer.width * 4u);
            }

            surface->stride = buffer.stride;
            surface->has_backing = true;
            surface->had_new_buffer = true;
            comp_surface_mark_damage(surface);

            if (!surface->pos_initialised) {
                int32_t total_h = buffer.height + surface->bar_height;
                int32_t fb_w = (int32_t)surface->comp->fb_info.width;
                int32_t fb_h = (int32_t)surface->comp->fb_info.height;
                int32_t cx = (fb_w - buffer.width) / 2;
                int32_t cy = (fb_h - total_h) / 2;
                /* Cascade: offset each new window by 30px so they don't overlap */
                int32_t offset = (int32_t)(surface->comp->cascade_counter % 8u) * 30;
                surface->comp->cascade_counter++;
                cx += offset;
                cy += offset;
                /* Clamp so the window stays on screen */
                if (cx + buffer.width > fb_w)
                    cx = fb_w - buffer.width;
                if (cy + total_h > fb_h - 42) /* 42 = dock area */
                    cy = fb_h - 42 - total_h;
                if (cx < 0) cx = 0;
                if (cy < MENUBAR_HEIGHT) cy = MENUBAR_HEIGHT;
                surface->x = cx;
                surface->y = cy;
                surface->pos_initialised = true;
            }

            comp_surface_raise(surface->comp, surface);

            comp_apply_committed_size(surface->comp,
                                      surface,
                                      buffer.width,
                                      buffer.height,
                                      had_backing);
            if (surface->have_pending_size &&
                surface->pend_w == buffer.width &&
                surface->pend_h == buffer.height) {
                surface->have_pending_size = false;
            }

            shm_buffer_release(&buffer);
            if (!had_backing) {
                WLOG("[WAYLAND] window create win=%p size=%dx%d z=top\n",
                     (void *)surface,
                     surface->width,
                     surface->height);
            }
        } else {
            wl_buffer_send_release(surface->pending_buffer_resource);
            surface->had_new_buffer = false;
        }
        surface->pending_buffer_resource = NULL;
        surface->has_pending_buffer = false;
    }

    if (surface->has_pending_damage && surface->has_backing) {
        fut_rect_t local = surface->pending_damage;
        if (local.w > 0 && local.h > 0) {
            if (local.x < 0) {
                local.w += local.x;
                local.x = 0;
            }
            if (local.y < 0) {
                local.h += local.y;
                local.y = 0;
            }
            if (local.x + local.w > surface->width) {
                local.w = surface->width - local.x;
            }
            if (local.y + local.h > surface->content_height) {
                local.h = surface->content_height - local.y;
            }
            if (local.w > 0 && local.h > 0) {
                fut_rect_t global = {
                    .x = surface->x + local.x,
                    .y = surface->y + surface->bar_height + local.y,
                    .w = local.w,
                    .h = local.h,
                };
                comp_damage_add_rect(surface->comp, global);
                comp_surface_mark_damage(surface);
            }
        }
        surface->has_pending_damage = false;
    }

commit_done:
    surface->in_commit = false;
    if (surface->destroy_deferred) {
        comp_surface_destroy(surface);
    }
}

void comp_surface_frame(struct comp_surface *surface,
                        struct wl_resource *callback_resource) {
    if (!surface || !callback_resource) {
        return;
    }

    struct comp_frame_callback *cb = malloc(sizeof(*cb));
    if (!cb) {
        wl_resource_destroy(callback_resource);
        return;
    }
    cb->resource = callback_resource;
    wl_list_insert(surface->frame_callbacks.prev, &cb->link);
    wl_resource_set_user_data(callback_resource, cb);
    wl_resource_set_destructor(callback_resource, frame_callback_resource_destroy);
#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] frame request win=%p\n", (void *)surface);
#endif
}

static uint64_t comp_now_ns(void) {
    /* sys_time_millis_call() returns ticks (100 Hz = 10 ms/tick).
     * Each tick = 10,000,000 ns. */
    return (uint64_t)sys_time_millis_call() * 10000000ULL;
}

static void present_damage(struct compositor_state *comp, const struct damage_accum *damage) {
    if (!comp || !damage || !comp->fb_map) {
        return;
    }

    const struct backbuffer *src = &comp->bb[comp->bb_index];
    if (!src->px) {
        return;
    }

    int32_t fb_w = (int32_t)comp->fb_info.width;
    int32_t fb_h = (int32_t)comp->fb_info.height;

    for (int i = 0; i < damage->count; ++i) {
        fut_rect_t rect = damage->rects[i];

        /* Bounds check to prevent buffer overflow */
        if (rect.x < 0 || rect.y < 0 || rect.w <= 0 || rect.h <= 0) {
            continue;
        }
        /* Clamp rect to framebuffer bounds */
        if (rect.x + rect.w > fb_w) {
            rect.w = fb_w - rect.x;
        }
        if (rect.y + rect.h > fb_h) {
            rect.h = fb_h - rect.y;
        }
        if (rect.w <= 0 || rect.h <= 0) {
            continue;
        }

        const char *src_base = (const char *)src->px + (size_t)rect.y * src->pitch + (size_t)rect.x * 4u;
        char *dst_base = (char *)comp->fb_map + (size_t)rect.y * comp->fb_info.pitch + (size_t)rect.x * 4u;
        blit_argb(src_base, src->pitch, dst_base, comp->fb_info.pitch, rect.w, rect.h);
    }
}

static int comp_flush_frame_callbacks(struct compositor_state *comp, uint64_t now_msec) {
    if (!comp) {
        return 0;
    }

    int callbacks = 0;
    struct comp_surface *surface;
    wl_list_for_each(surface, &comp->surfaces, link) {
        if (surface->composed_this_tick && surface->has_backing) {
            struct comp_frame_callback *cb, *tmp;
            wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
                wl_callback_send_done(cb->resource, now_msec);
                wl_resource_destroy(cb->resource);
                ++callbacks;
            }
            surface->had_new_buffer = false;
            surface->damage_since_present = false;
        }
        surface->composed_this_tick = false;
    }
    return callbacks;
}

void comp_render_frame(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    struct damage_accum *damage = &comp->frame_damage;
    if (damage->count == 0) {
        comp->needs_repaint = false;
        return;
    }

    damage_coalesce(damage);
#ifdef DEBUG_WAYLAND
    int region_count = damage->count;
#endif

    int render_index = comp->backbuffer_enabled ? (comp->bb_index ^ 1) : 0;
    struct backbuffer *dst = &comp->bb[render_index];
    if (!dst->px) {
        comp_damage_add_full(comp);
        damage = &comp->frame_damage;
        damage_coalesce(damage);
#ifdef DEBUG_WAYLAND
        region_count = damage->count;
#endif
        dst = &comp->bb[render_index];
        if (!dst->px) {
            comp->needs_repaint = false;
            damage->count = 0;
            return;
        }
    }

    struct comp_surface *surface;
    wl_list_for_each(surface, &comp->surfaces, link) {
        if (surface->has_backing) {
            comp_surface_update_decorations(surface);
            surface->height = surface->content_height + surface->bar_height;
        }
        surface->composed_this_tick = false;
    }

    /* Get time for animated wallpaper elements */
    struct { long tv_sec; long tv_nsec; } wp_ts = {0, 0};
    {
        extern long sys_call2(long nr, long a, long b);
        sys_call2(98, 1, (long)&wp_ts);  /* CLOCK_MONOTONIC */
    }
    int wp_sec = (int)(wp_ts.tv_sec & 0x7FFFFFFF);

    /* Build occlusion list: opaque window rects that fully cover wallpaper pixels.
     * Damage rects fully inside a window don't need wallpaper rendering because
     * the window blit will overwrite every pixel. This prevents single-buffer
     * flashing where wallpaper is briefly visible behind windows. */
    #define MAX_OCCLUDERS 8
    fut_rect_t occluders[MAX_OCCLUDERS];
    int n_occluders = 0;
    {
        struct comp_surface *os;
        wl_list_for_each(os, &comp->surfaces, link) {
            if (!os->has_backing || os->minimized) continue;
            if (n_occluders >= MAX_OCCLUDERS) break;
            occluders[n_occluders++] = comp_window_rect(os);
        }
    }

    /* Desktop background: gradient + radial glows + aurora bands + stars */
    for (int i = 0; i < damage->count; ++i) {
        fut_rect_t r = damage->rects[i];
        if (r.w <= 0 || r.h <= 0) continue;

        /* Skip wallpaper for damage rects fully inside an opaque window */
        bool fully_occluded = false;
        for (int oi = 0; oi < n_occluders; oi++) {
            fut_rect_t w = occluders[oi];
            if (r.x >= w.x && r.y >= w.y &&
                r.x + r.w <= w.x + w.w && r.y + r.h <= w.y + w.h) {
                fully_occluded = true;
                break;
            }
        }
        if (fully_occluded) continue;
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        int32_t cx = fb_w / 2;
        int32_t cy = fb_h * 2 / 5;
        int32_t max_r = (fb_w > fb_h ? fb_w : fb_h) * 3 / 5;
        int64_t max_r_sq = (int64_t)max_r * max_r;
        int32_t cx2 = fb_w * 3 / 4;
        int32_t cy2 = fb_h * 3 / 4;
        int32_t max_r2 = (fb_w > fb_h ? fb_w : fb_h) * 2 / 5;
        int64_t max_r2_sq = (int64_t)max_r2 * max_r2;
        /* Aurora band parameters */
        int32_t aurora_y_center = fb_h * 3 / 10;  /* band at 30% from top */
        int32_t aurora_half_h = fb_h / 8;          /* band spread */
        char *base = (char *)dst->px;
        for (int32_t y = 0; y < r.h; ++y) {
            int32_t gy = r.y + y;
            /* Per-scanline occlusion: skip rows fully behind a window.
             * This prevents single-buffer flash when damage rects only
             * PARTIALLY overlap a window (the full-rect check above
             * only catches rects entirely inside a window). */
            bool row_occluded = false;
            for (int oi = 0; oi < n_occluders; oi++) {
                fut_rect_t w = occluders[oi];
                if (gy >= w.y && gy < w.y + w.h &&
                    r.x >= w.x && r.x + r.w <= w.x + w.w) {
                    row_occluded = true;
                    break;
                }
            }
            if (row_occluded) continue;
            int t = (fb_h > 0) ? (gy * 255 / fb_h) : 0;
            int base_r = 0x08 + (0x1A - 0x08) * t / 255;
            int base_g = 0x08 + (0x18 - 0x08) * t / 255;
            int base_b = 0x16 + (0x34 - 0x16) * t / 255;
            int32_t dy = gy - cy;
            int32_t dy2 = gy - cy2;
            /* Aurora Y falloff: Gaussian-ish bell curve */
            int32_t aurora_dy = gy - aurora_y_center;
            int aurora_env = 0;
            if (aurora_dy > -aurora_half_h && aurora_dy < aurora_half_h) {
                int32_t ad = aurora_dy < 0 ? -aurora_dy : aurora_dy;
                aurora_env = (aurora_half_h - ad) * 255 / aurora_half_h;
                aurora_env = aurora_env * aurora_env / 255;  /* quadratic falloff */
            }
            uint32_t *row = (uint32_t *)(base + (size_t)gy * dst->pitch);
            /* Per-scanline occlusion: skip x-ranges covered by opaque windows.
             * Build a skip list of up to MAX_OCCLUDERS x-intervals for this row. */
            int32_t skip_x0[MAX_OCCLUDERS], skip_x1[MAX_OCCLUDERS];
            int n_skips = 0;
            for (int oi = 0; oi < n_occluders; oi++) {
                fut_rect_t w = occluders[oi];
                if (gy >= w.y && gy < w.y + w.h) {
                    int32_t sx0 = w.x > r.x ? w.x : r.x;
                    int32_t sx1 = (w.x + w.w) < (r.x + r.w) ? (w.x + w.w) : (r.x + r.w);
                    if (sx0 < sx1) {
                        skip_x0[n_skips] = sx0;
                        skip_x1[n_skips] = sx1;
                        n_skips++;
                    }
                }
            }
            for (int32_t x = 0; x < r.w; ++x) {
                int32_t gx = r.x + x;
                /* Skip pixel if inside any opaque window */
                bool skip = false;
                for (int si = 0; si < n_skips; si++) {
                    if (gx >= skip_x0[si] && gx < skip_x1[si]) {
                        /* Jump x to end of this skip range */
                        x = skip_x1[si] - r.x - 1;
                        skip = true;
                        break;
                    }
                }
                if (skip) continue;
                int32_t dx = gx - cx;
                int64_t dist_sq = (int64_t)dx * dx + (int64_t)dy * dy;
                int glow = 0;
                if (dist_sq < max_r_sq) {
                    glow = (int)((max_r_sq - dist_sq) * 22 / max_r_sq);
                }
                int32_t dx2 = gx - cx2;
                int64_t dist2_sq = (int64_t)dx2 * dx2 + (int64_t)dy2 * dy2;
                int glow2 = 0;
                if (dist2_sq < max_r2_sq) {
                    glow2 = (int)((max_r2_sq - dist2_sq) * 12 / max_r2_sq);
                }

                /* Aurora band: smooth horizontal waves with gentle undulation */
                int aurora_r = 0, aurora_g = 0, aurora_b = 0;
                if (aurora_env > 0) {
                    /* Slow horizontal wave — period ~200px, with y-wobble */
                    int32_t wave_phase = ((gx * 327 / 100) + (gy * 41 / 100)) & 0xFF;
                    int wave_val;
                    if (wave_phase < 128) {
                        int32_t p = wave_phase - 64;
                        wave_val = 64 - (p * p * 64 / (64 * 64));
                    } else {
                        int32_t p = wave_phase - 192;
                        wave_val = -64 + (p * p * 64 / (64 * 64));
                    }
                    /* Second wave at different frequency for organic layering */
                    int32_t wave2_phase = ((gx * 173 / 100) + (gy * 67 / 100) + 137) & 0xFF;
                    int wave2_val;
                    if (wave2_phase < 128) {
                        int32_t p = wave2_phase - 64;
                        wave2_val = 64 - (p * p * 64 / (64 * 64));
                    } else {
                        int32_t p = wave2_phase - 192;
                        wave2_val = -64 + (p * p * 64 / (64 * 64));
                    }
                    /* Gentle hash turbulence at large scale */
                    uint32_t ah = (uint32_t)((gx / 4) * 2971 + (gy / 3) * 6337);
                    ah ^= ah >> 13; ah *= 0x45d9f3bu; ah ^= ah >> 16;
                    int turb = (int)(ah & 0xF) - 8;  /* -8..7 */
                    int combined = (wave_val + wave2_val / 2 + turb);
                    int intensity = aurora_env * (80 + combined) / (80 * 4);
                    if (intensity < 0) intensity = 0;
                    if (intensity > 18) intensity = 18;
                    /* Color: smoothly shift from teal to purple across screen */
                    int x_frac = fb_w > 0 ? gx * 255 / fb_w : 0;
                    int cr = intensity * x_frac / (255 * 4);           /* warm up on right */
                    int cg = intensity * (255 - x_frac / 2) / 255;     /* green stronger on left */
                    int cb = intensity * (128 + x_frac / 2) / 255;     /* blue everywhere */
                    aurora_r = cr;
                    aurora_g = cg;
                    aurora_b = cb;
                }

                /* Nebula wisps: deterministic noise patches for cosmic depth */
                int nebula_r = 0, nebula_g = 0, nebula_b = 0;
                {
                    /* Large-scale noise at two octaves for organic shapes */
                    uint32_t nh1 = (uint32_t)((gx / 6) * 48271 + (gy / 6) * 8171);
                    nh1 ^= nh1 >> 13; nh1 *= 0x45d9f3bu; nh1 ^= nh1 >> 16;
                    uint32_t nh2 = (uint32_t)((gx / 12) * 16381 + (gy / 12) * 32749);
                    nh2 ^= nh2 >> 13; nh2 *= 0x45d9f3bu; nh2 ^= nh2 >> 16;
                    int n1 = (int)(nh1 & 0xFF) - 128;  /* -128..127 */
                    int n2 = (int)(nh2 & 0xFF) - 128;
                    int nebula_val = (n1 + n2 / 2) / 3;
                    if (nebula_val > 0) {
                        /* Purple-blue nebula in upper-right quadrant */
                        int nx_frac = fb_w > 0 ? gx * 255 / fb_w : 0;
                        int ny_frac = fb_h > 0 ? gy * 255 / fb_h : 0;
                        int region1 = nx_frac * (255 - ny_frac) / 255;  /* upper-right */
                        int region2 = (255 - nx_frac) * ny_frac / 255;  /* lower-left */
                        int i1 = nebula_val * region1 / (255 * 3);
                        int i2 = nebula_val * region2 / (255 * 4);
                        /* Region 1: purple-magenta tint */
                        nebula_r = i1 * 2 / 3;
                        nebula_g = i1 / 5;
                        nebula_b = i1;
                        /* Region 2: teal tint */
                        nebula_g += i2 * 2 / 3;
                        nebula_b += i2 / 2;
                    }
                }

                int pr = base_r + glow / 3 + glow2 * 2 / 3 + aurora_r + nebula_r;
                int pg = base_g + glow / 4 + glow2 / 5 + aurora_g + nebula_g;
                int pb = base_b + glow + glow2 / 2 + aurora_b + nebula_b;
                if (pr > 255) pr = 255;
                if (pg > 255) pg = 255;
                if (pb > 255) pb = 255;

                /* Deterministic star field with colored stars + twinkling */
                uint32_t hash = (uint32_t)(gx * 7919 + gy * 104729);
                hash ^= hash >> 13;
                hash *= 0x5bd1e995u;
                hash ^= hash >> 15;
                if ((hash & 0x3FF) < 3) {
                    /* Bright star — with subtle color tint */
                    int brightness = 100 + (int)(hash >> 10 & 0x7F);
                    /* Twinkling: modulate brightness with per-star phase */
                    int twinkle_phase = (wp_sec + (int)(hash >> 20)) & 0x7;
                    /* 8-step triangle wave: 0,1,2,3,4,3,2,1 → scale 60..100% */
                    int wave = twinkle_phase < 4 ? twinkle_phase : (7 - twinkle_phase);
                    brightness = brightness * (60 + wave * 10) / 100;
                    int star_type = (hash >> 17) & 0x7;
                    if (star_type == 0) {
                        /* Blue-white star */
                        pr += brightness * 3 / 4;
                        pg += brightness * 7 / 8;
                        pb += brightness;
                    } else if (star_type == 1) {
                        /* Warm orange star */
                        pr += brightness;
                        pg += brightness * 3 / 4;
                        pb += brightness / 2;
                    } else {
                        /* White star */
                        pr += brightness; pg += brightness; pb += brightness;
                    }
                    if (pr > 255) pr = 255;
                    if (pg > 255) pg = 255;
                    if (pb > 255) pb = 255;
                } else if ((hash & 0x7FF) < 5) {
                    int brightness = 40 + (int)(hash >> 11 & 0x3F);
                    /* Dim stars twinkle too */
                    int twinkle2 = (wp_sec + (int)(hash >> 14)) & 0x3;
                    brightness = brightness * (70 + twinkle2 * 10) / 100;
                    pr += brightness; pg += brightness; pb += brightness + 8;
                    if (pr > 255) pr = 255;
                    if (pg > 255) pg = 255;
                    if (pb > 255) pb = 255;
                }

                /* Shooting stars — 1 meteor every 3 seconds */
                if ((wp_sec % 3) == 0) {
                    uint32_t seed = (uint32_t)(wp_sec / 3) * 2654435761u;
                    /* Only show on ~1/3 of cycles for rarity */
                    if ((seed & 0x3) < 3) {
                        int sx = (int)((seed >> 4) % (uint32_t)(fb_w * 2 / 3)) + fb_w / 6;
                        int sy = (int)((seed >> 14) % (uint32_t)(fb_h / 4)) + 30;
                        int trail_len = 35 + (int)((seed >> 22) & 0x1F);
                        /* Trail endpoint: going down-right */
                        int ex_t = sx + trail_len;
                        int ey_t = sy + trail_len * 2 / 3;
                        /* Check if pixel is near the trail line (sx,sy)->(ex_t,ey_t) */
                        int tx = gx - sx, ty = gy - sy;
                        int lx = ex_t - sx, ly = ey_t - sy;
                        int len2 = lx * lx + ly * ly;
                        if (len2 > 0) {
                            int dot = tx * lx + ty * ly;
                            if (dot >= 0 && dot <= len2) {
                                /* Perpendicular distance squared */
                                int cross = tx * ly - ty * lx;
                                int perp2 = cross * cross / len2;
                                if (perp2 <= 2) {
                                    int t_frac = dot * 255 / len2;
                                    /* Brighter at head (high t), fading toward tail */
                                    int bright = t_frac * 180 / 255;
                                    if (perp2 > 0) bright = bright * 2 / 3;
                                    pr += bright; pg += bright; pb += bright * 3 / 4;
                                    if (pr > 255) pr = 255;
                                    if (pg > 255) pg = 255;
                                    if (pb > 255) pb = 255;
                                }
                            }
                        }
                    }
                }

                /* Crescent moon in upper-right quadrant */
                {
                    int moon_cx = fb_w * 4 / 5;
                    int moon_cy = fb_h / 6;
                    int moon_r = fb_h / 14;
                    int dx_m = gx - moon_cx;
                    int dy_m = gy - moon_cy;
                    int d2_m = dx_m * dx_m + dy_m * dy_m;
                    if (d2_m <= moon_r * moon_r) {
                        /* Outer circle hit — check inner (shadow) circle offset */
                        int inner_cx = moon_cx + moon_r / 3;
                        int inner_cy = moon_cy - moon_r / 5;
                        int inner_r = moon_r * 4 / 5;
                        int dx_i = gx - inner_cx;
                        int dy_i = gy - inner_cy;
                        int d2_i = dx_i * dx_i + dy_i * dy_i;
                        if (d2_i > inner_r * inner_r) {
                            /* In crescent — bright moon surface with craters */
                            int dist = d2_m * 255 / (moon_r * moon_r);
                            int edge_fade = dist > 220 ? (255 - dist) * 7 : 255;
                            if (edge_fade < 0) edge_fade = 0;
                            /* Crater texture: hash noise darkens some spots */
                            uint32_t ch = (uint32_t)(gx * 1373 + gy * 7393);
                            ch ^= ch >> 13; ch *= 0x5bd1e995u; ch ^= ch >> 15;
                            int crater = (int)(ch & 0xF);  /* 0-15 */
                            int mr = (0xD0 - (crater > 10 ? 20 : 0)) * edge_fade / 255;
                            int mg = (0xCC - (crater > 10 ? 18 : 0)) * edge_fade / 255;
                            int mb = (0xB8 - (crater > 10 ? 15 : 0)) * edge_fade / 255;
                            pr = pr + (mr - pr) * edge_fade / 255;
                            pg = pg + (mg - pg) * edge_fade / 255;
                            pb = pb + (mb - pb) * edge_fade / 255;
                        }
                    }
                    /* Moon glow halo */
                    else if (d2_m <= (moon_r + 20) * (moon_r + 20)) {
                        int dist = d2_m - moon_r * moon_r;
                        int halo_area = (moon_r + 20) * (moon_r + 20) - moon_r * moon_r;
                        int glow_i = 12 * (halo_area - dist) / halo_area;
                        if (glow_i > 0) {
                            pr += glow_i; pg += glow_i; pb += glow_i / 2;
                            if (pr > 255) pr = 255;
                            if (pg > 255) pg = 255;
                            if (pb > 255) pb = 255;
                        }
                    }
                }

                /* Horizon glow: warm ambient light at the bottom edge */
                {
                    int horizon_zone = fb_h / 4;  /* bottom 25% */
                    int hy = gy - (fb_h - horizon_zone);
                    if (hy > 0) {
                        int intensity = hy * 18 / horizon_zone;
                        /* Warm purple-orange tint */
                        int hx_frac = fb_w > 0 ? gx * 255 / fb_w : 0;
                        int hr = intensity * (180 + hx_frac / 5) / 255;
                        int hg = intensity * (80 + hx_frac / 8) / 255;
                        int hb = intensity * (140 + (255 - hx_frac) / 4) / 255;
                        pr += hr; pg += hg; pb += hb;
                        if (pr > 255) pr = 255;
                        if (pg > 255) pg = 255;
                        if (pb > 255) pb = 255;
                    }
                }

                /* Edge vignette: darken corners/edges for depth */
                {
                    int ex = gx < cx ? gx : (fb_w - 1 - gx);
                    int ey = gy < cy ? gy : (fb_h - 1 - gy);
                    int edge = ex < ey ? ex : ey;
                    int vignette_r = fb_w < fb_h ? fb_w / 3 : fb_h / 3;
                    if (edge < vignette_r) {
                        int darken = 30 * (vignette_r - edge) / vignette_r;
                        pr = pr * (255 - darken) / 255;
                        pg = pg * (255 - darken) / 255;
                        pb = pb * (255 - darken) / 255;
                    }
                }

                row[gx] = 0xFF000000u | ((uint32_t)pr << 16)
                         | ((uint32_t)pg << 8) | (uint32_t)pb;
            }
        }
    }

    /* ── Desktop clock widget (centered, large) ── */
    {
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;

        /* Get current time */
        struct { long tv_sec; long tv_nsec; } wc_ts = {0, 0};
        extern long sys_call2(long nr, long a, long b);
        sys_call2(98, 0, (long)&wc_ts);
        long wc_secs = wc_ts.tv_sec;
        long wc_daytime = wc_secs % 86400;
        int wc_hr = (int)(wc_daytime / 3600);
        int wc_min = (int)((wc_daytime % 3600) / 60);
        int wc_sec = (int)(wc_daytime % 60);

        /* Format: "HH:MM" — solid colon (clock updates per-minute) */
        char wc_time[8];
        wc_time[0] = '0' + (char)(wc_hr / 10);
        wc_time[1] = '0' + (char)(wc_hr % 10);
        wc_time[2] = ':';
        wc_time[3] = '0' + (char)(wc_min / 10);
        wc_time[4] = '0' + (char)(wc_min % 10);
        wc_time[5] = '\0';

        /* Date line: "Wednesday, April 15" */
        long wc_days = wc_secs / 86400;
        int wc_dow = (int)((wc_days + 4) % 7);
        const char *wc_dow_full[] = {"Sunday","Monday","Tuesday","Wednesday",
                                     "Thursday","Friday","Saturday"};
        int wc_year = 1970;
        long wc_rem = wc_days;
        for (;;) {
            int diy = 365;
            if ((wc_year % 4 == 0 && wc_year % 100 != 0) || wc_year % 400 == 0) diy = 366;
            if (wc_rem < diy) break;
            wc_rem -= diy;
            wc_year++;
        }
        bool wc_leap = (wc_year % 4 == 0 && wc_year % 100 != 0) || wc_year % 400 == 0;
        int wc_md[] = {31, wc_leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        int wc_mon = 0;
        while (wc_mon < 11 && wc_rem >= wc_md[wc_mon]) { wc_rem -= wc_md[wc_mon]; wc_mon++; }
        int wc_day = (int)wc_rem + 1;
        const char *wc_mon_full[] = {"January","February","March","April","May","June",
                                     "July","August","September","October","November","December"};

        /* Build: "Wednesday, April 15" */
        char wc_date[48];
        int di = 0;
        const char *dn = wc_dow_full[wc_dow];
        while (*dn && di < 40) wc_date[di++] = *dn++;
        wc_date[di++] = ','; wc_date[di++] = ' ';
        const char *mn = wc_mon_full[wc_mon];
        while (*mn && di < 44) wc_date[di++] = *mn++;
        wc_date[di++] = ' ';
        if (wc_day >= 10) wc_date[di++] = '0' + (char)(wc_day / 10);
        wc_date[di++] = '0' + (char)(wc_day % 10);
        wc_date[di] = '\0';
        int wc_date_len = di;

        /* Large clock: scale=4, centered at 30% from top */
        int clock_scale = 4;
        int clock_char_w = UI_FONT_WIDTH * clock_scale;
        int clock_char_h = UI_FONT_HEIGHT * clock_scale;
        int clock_text_w = 5 * clock_char_w;  /* "HH:MM" */
        int clock_x = (fb_w - clock_text_w) / 2;
        int clock_y = fb_h * 28 / 100;

        /* Date line below clock at 1x scale */
        int date_w = wc_date_len * UI_FONT_WIDTH;
        int date_x = (fb_w - date_w) / 2;
        int date_y = clock_y + clock_char_h + 12;

        /* Seconds line: ":SS" below date, scale=2 */
        char wc_secs_str[4];
        wc_secs_str[0] = ':';
        wc_secs_str[1] = '0' + (char)(wc_sec / 10);
        wc_secs_str[2] = '0' + (char)(wc_sec % 10);
        wc_secs_str[3] = '\0';
        int sec_scale = 2;
        int sec_char_w = UI_FONT_WIDTH * sec_scale;
        int sec_text_w = 3 * sec_char_w;
        int sec_x = (fb_w - sec_text_w) / 2;
        int sec_y = date_y + UI_FONT_HEIGHT + 6;

        /* Time-of-day greeting below seconds */
        const char *greeting;
        if (wc_hr >= 5 && wc_hr < 12)       greeting = "Good Morning";
        else if (wc_hr >= 12 && wc_hr < 17) greeting = "Good Afternoon";
        else if (wc_hr >= 17 && wc_hr < 21) greeting = "Good Evening";
        else                                 greeting = "Good Night";
        int greet_len = 0;
        while (greeting[greet_len]) greet_len++;
        int greet_x = (fb_w - greet_len * UI_FONT_WIDTH) / 2;
        int greet_y = sec_y + UI_FONT_HEIGHT * sec_scale + 16;

        /* Render clock with subtle drop shadow for readability */
        fut_rect_t clock_rect = { clock_x - 6, clock_y - 6,
                                  clock_text_w + 12, greet_y + UI_FONT_HEIGHT + 8 - (clock_y - 6) };
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t cc;
            if (!rect_intersection(damage->rects[i], clock_rect, &cc)) continue;
            /* Skip if clipped area is fully behind an opaque window —
             * prevents single-buffer flash where clock renders briefly
             * before the window blit overwrites it. */
            bool clk_occluded = false;
            for (int oi = 0; oi < n_occluders; oi++) {
                fut_rect_t w = occluders[oi];
                if (cc.x >= w.x && cc.y >= w.y &&
                    cc.x + cc.w <= w.x + w.w && cc.y + cc.h <= w.y + w.h) {
                    clk_occluded = true;
                    break;
                }
            }
            if (clk_occluded) continue;
            /* Soft radial glow backdrop for readability */
            {
                int glow_cx = clock_x + clock_text_w / 2;
                int glow_cy = clock_y + clock_char_h / 2 + 16;
                int glow_rx = clock_text_w / 2 + 40;
                int glow_ry = clock_char_h + 32;
                int gx0 = glow_cx - glow_rx, gx1 = glow_cx + glow_rx;
                int gy0 = glow_cy - glow_ry, gy1 = glow_cy + glow_ry;
                if (gx0 < cc.x) gx0 = cc.x;
                if (gy0 < cc.y) gy0 = cc.y;
                if (gx1 > cc.x + cc.w) gx1 = cc.x + cc.w;
                if (gy1 > cc.y + cc.h) gy1 = cc.y + cc.h;
                char *gbase = (char *)dst->px;
                for (int gy = gy0; gy < gy1; gy++) {
                    uint32_t *grow = (uint32_t *)(gbase + (size_t)gy * dst->pitch);
                    int dy = gy - glow_cy;
                    int dy2 = dy * dy * glow_rx * glow_rx;
                    for (int gx = gx0; gx < gx1; gx++) {
                        int ddx = gx - glow_cx;
                        /* Elliptical distance: (dx/rx)^2 + (dy/ry)^2 */
                        int d2 = ddx * ddx * glow_ry * glow_ry + dy2;
                        int r2 = glow_rx * glow_rx * glow_ry * glow_ry;
                        if (d2 >= r2) continue;
                        /* Smooth falloff: alpha peaks at center */
                        int alpha = 28 * (r2 - d2) / r2;
                        if (alpha < 1) continue;
                        /* Inline alpha blend */
                        uint32_t _s = ((uint32_t)alpha << 24) | 0x00080810u;
                        uint32_t _d = grow[gx];
                        uint32_t _sa = _s >> 24;
                        uint32_t _sr = (_s >> 16) & 0xFF, _sg = (_s >> 8) & 0xFF, _sb = _s & 0xFF;
                        uint32_t _dr = (_d >> 16) & 0xFF, _dg = (_d >> 8) & 0xFF, _db = _d & 0xFF;
                        uint32_t _ia = 255 - _sa;
                        grow[gx] = 0xFF000000u
                            | (((_sr * _sa + _dr * _ia) / 255) << 16)
                            | (((_sg * _sa + _dg * _ia) / 255) << 8)
                            | ((_sb * _sa + _db * _ia) / 255);
                    }
                }
            }
            /* Shadow layer (offset +2,+2, dark) */
            ui_draw_text_scaled(dst->px, dst->pitch,
                                clock_x + 2, clock_y + 2,
                                0x40000000u, wc_time, clock_scale,
                                cc.x, cc.y, cc.w, cc.h);
            /* Main clock text */
            ui_draw_text_scaled(dst->px, dst->pitch,
                                clock_x, clock_y,
                                0xC0FFFFFFu, wc_time, clock_scale,
                                cc.x, cc.y, cc.w, cc.h);
            /* Date shadow */
            ui_draw_text(dst->px, dst->pitch,
                         date_x + 1, date_y + 1,
                         0x30000000u, wc_date,
                         cc.x, cc.y, cc.w, cc.h);
            /* Date text */
            ui_draw_text(dst->px, dst->pitch,
                         date_x, date_y,
                         0x90D8D8F0u, wc_date,
                         cc.x, cc.y, cc.w, cc.h);
            /* Seconds display (smaller, dimmer) */
            ui_draw_text_scaled(dst->px, dst->pitch,
                                sec_x + 1, sec_y + 1,
                                0x20000000u, wc_secs_str, sec_scale,
                                cc.x, cc.y, cc.w, cc.h);
            ui_draw_text_scaled(dst->px, dst->pitch,
                                sec_x, sec_y,
                                0x60C0C0E0u, wc_secs_str, sec_scale,
                                cc.x, cc.y, cc.w, cc.h);
            /* Time-of-day greeting */
            ui_draw_text(dst->px, dst->pitch,
                         greet_x + 1, greet_y + 1,
                         0x20000000u, greeting,
                         cc.x, cc.y, cc.w, cc.h);
            ui_draw_text(dst->px, dst->pitch,
                         greet_x, greet_y,
                         0x70A0B0D0u, greeting,
                         cc.x, cc.y, cc.w, cc.h);
        }
    }

    /* ── Desktop watermark (bottom-right, elegant 2x scale) ── */
    {
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        const char *watermark = "Futura OS";
        int wm_len = 0;
        while (watermark[wm_len]) wm_len++;
        int wm_scale = 2;
        int wm_char_w = UI_FONT_WIDTH * wm_scale;
        int wm_char_h = UI_FONT_HEIGHT * wm_scale;
        int wm_x = fb_w - wm_len * wm_char_w - 18;
        int wm_y = fb_h - wm_char_h - 68;  /* above dock area + shadow */
        int wm_w = wm_len * wm_char_w + 8;
        int wm_h = wm_char_h + 8;
        fut_rect_t wm_rect = { wm_x - 4, wm_y - 4, wm_w + 4, wm_h + 4 };
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t wm_clip;
            if (!rect_intersection(damage->rects[i], wm_rect, &wm_clip))
                continue;
            /* Skip if fully behind a window */
            bool wm_occluded = false;
            for (int oi = 0; oi < n_occluders; oi++) {
                fut_rect_t w = occluders[oi];
                if (wm_clip.x >= w.x && wm_clip.y >= w.y &&
                    wm_clip.x + wm_clip.w <= w.x + w.w &&
                    wm_clip.y + wm_clip.h <= w.y + w.h) {
                    wm_occluded = true;
                    break;
                }
            }
            if (wm_occluded) continue;
            /* Shadow offset (+2,+2) for depth at 2x */
            ui_draw_text_scaled(dst->px, dst->pitch, wm_x + 2, wm_y + 2,
                         0x18000000u, watermark, wm_scale,
                         wm_clip.x, wm_clip.y, wm_clip.w, wm_clip.h);
            /* Main text: semi-transparent light */
            ui_draw_text_scaled(dst->px, dst->pitch, wm_x, wm_y,
                         0x30C0C8E0u, watermark, wm_scale,
                         wm_clip.x, wm_clip.y, wm_clip.w, wm_clip.h);
        }
        /* Version number below, at 1x scale, slightly dimmer */
        {
            const char *ver = "v0.9.0";
            int ver_len = 0;
            while (ver[ver_len]) ver_len++;
            int ver_x = fb_w - ver_len * UI_FONT_WIDTH - 18;
            int ver_y = wm_y + wm_char_h + 4;
            fut_rect_t ver_rect = { ver_x - 2, ver_y - 2,
                                    ver_len * UI_FONT_WIDTH + 4, UI_FONT_HEIGHT + 4 };
            for (int i = 0; i < damage->count; ++i) {
                fut_rect_t ver_clip;
                if (!rect_intersection(damage->rects[i], ver_rect, &ver_clip))
                    continue;
                /* Skip if fully behind a window */
                bool ver_occluded = false;
                for (int oi = 0; oi < n_occluders; oi++) {
                    fut_rect_t w = occluders[oi];
                    if (ver_clip.x >= w.x && ver_clip.y >= w.y &&
                        ver_clip.x + ver_clip.w <= w.x + w.w &&
                        ver_clip.y + ver_clip.h <= w.y + w.h) {
                        ver_occluded = true;
                        break;
                    }
                }
                if (ver_occluded) continue;
                ui_draw_text_scaled(dst->px, dst->pitch, ver_x + 1, ver_y + 1,
                             0x10000000u, ver, 1,
                             ver_clip.x, ver_clip.y, ver_clip.w, ver_clip.h);
                ui_draw_text_scaled(dst->px, dst->pitch, ver_x, ver_y,
                             0x20A0A8B8u, ver, 1,
                             ver_clip.x, ver_clip.y, ver_clip.w, ver_clip.h);
            }
        }
    }

    /* Alpha-blend helper: blend src (with alpha) over dst pixel */
    #define ABLEND(src_argb, dst_px) do { \
        uint32_t _sa = ((src_argb) >> 24) & 0xFF; \
        if (_sa == 0xFF) { (dst_px) = (src_argb); } \
        else if (_sa > 0) { \
            uint32_t _da = 255u - _sa; \
            uint32_t _sr = ((src_argb) >> 16) & 0xFF; \
            uint32_t _sg = ((src_argb) >>  8) & 0xFF; \
            uint32_t _sb = ((src_argb)      ) & 0xFF; \
            uint32_t _dr = ((dst_px) >> 16) & 0xFF; \
            uint32_t _dg = ((dst_px) >>  8) & 0xFF; \
            uint32_t _db = ((dst_px)      ) & 0xFF; \
            uint32_t _or = (_sr * _sa + _dr * _da) / 255u; \
            uint32_t _og = (_sg * _sa + _dg * _da) / 255u; \
            uint32_t _ob = (_sb * _sa + _db * _da) / 255u; \
            (dst_px) = 0xFF000000u | (_or << 16) | (_og << 8) | _ob; \
        } } while (0)

    /* ── Top menu bar ── */
    {
        #define MENUBAR_COLOR   0xE0181828u  /* Dark frosted panel */

        int32_t fb_w = (int32_t)comp->fb_info.width;
        fut_rect_t mbar_rect = { 0, 0, fb_w, MENUBAR_HEIGHT };

        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t mbar_clip;
            if (!rect_intersection(damage->rects[i], mbar_rect, &mbar_clip))
                continue;

            char *base = (char *)dst->px;
            /* Draw background with subtle vertical gradient */
            for (int32_t py = mbar_clip.y; py < mbar_clip.y + mbar_clip.h; py++) {
                uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                /* Gradient: slightly lighter at top */
                int vg = py < 4 ? (4 - py) * 3 : 0;
                uint32_t bg_r = 0x18 + vg;
                uint32_t bg_g = 0x18 + vg;
                uint32_t bg_b = 0x28 + vg;
                uint32_t bg = 0xE0000000u | (bg_r << 16) | (bg_g << 8) | bg_b;
                for (int32_t px = mbar_clip.x; px < mbar_clip.x + mbar_clip.w; px++) {
                    /* Alpha blend over background */
                    uint32_t sa = (bg >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t sr = (bg >> 16) & 0xFF, sg = (bg >> 8) & 0xFF, sb = bg & 0xFF;
                    uint32_t dr = (row[px] >> 16) & 0xFF, dg = (row[px] >> 8) & 0xFF, db = row[px] & 0xFF;
                    uint32_t or_ = (sr * sa + dr * da) / 255u;
                    uint32_t og = (sg * sa + dg * da) / 255u;
                    uint32_t ob = (sb * sa + db * da) / 255u;
                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* 1px top highlight for glass edge */
            if (0 >= mbar_clip.y && 0 < mbar_clip.y + mbar_clip.h) {
                uint32_t *top_row = (uint32_t *)(base + 0);
                for (int32_t px = mbar_clip.x; px < mbar_clip.x + mbar_clip.w; px++) {
                    ABLEND(0x18FFFFFFu, top_row[px]);
                }
            }

            /* 1px bottom accent + separator for depth */
            if (MENUBAR_HEIGHT - 2 >= mbar_clip.y &&
                MENUBAR_HEIGHT - 2 < mbar_clip.y + mbar_clip.h) {
                /* Subtle blue accent line (1px) */
                uint32_t *acc_row = (uint32_t *)(base + (size_t)(MENUBAR_HEIGHT - 2) * dst->pitch);
                for (int32_t px = mbar_clip.x; px < mbar_clip.x + mbar_clip.w; px++) {
                    ABLEND(0x183060A0u, acc_row[px]);
                }
            }
            if (MENUBAR_HEIGHT - 1 >= mbar_clip.y &&
                MENUBAR_HEIGHT - 1 < mbar_clip.y + mbar_clip.h) {
                /* Dark separator below accent */
                uint32_t *sep_row = (uint32_t *)(base + (size_t)(MENUBAR_HEIGHT - 1) * dst->pitch);
                for (int32_t px = mbar_clip.x; px < mbar_clip.x + mbar_clip.w; px++) {
                    uint32_t old = sep_row[px];
                    uint32_t or_ = ((old >> 16) & 0xFF) * 140 / 255;
                    uint32_t og = ((old >> 8) & 0xFF) * 140 / 255;
                    uint32_t ob = (old & 0xFF) * 150 / 255;
                    sep_row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* "Futura" branding (left) — diamond logo + text with active highlight */
            {
                int brand_w = 10 + 6 * UI_FONT_WIDTH + 10;
                /* Active/hover highlight background */
                bool brand_hover = (!comp->futura_menu_active &&
                                    comp->pointer_y < MENUBAR_HEIGHT &&
                                    comp->pointer_x >= 4 &&
                                    comp->pointer_x < 4 + brand_w);
                if (comp->futura_menu_active || brand_hover) {
                    uint32_t hl_col = comp->futura_menu_active
                        ? 0x28446688u : 0x18446688u;
                    fut_rect_t brand_rect = { 4, 2, brand_w, MENUBAR_HEIGHT - 4 };
                    fut_rect_t brand_clip;
                    if (rect_intersection(mbar_clip, brand_rect, &brand_clip)) {
                        char *bbase = (char *)dst->px;
                        for (int32_t by = brand_clip.y; by < brand_clip.y + brand_clip.h; by++) {
                            uint32_t *brow = (uint32_t *)(bbase + (size_t)by * dst->pitch);
                            for (int32_t bx = brand_clip.x; bx < brand_clip.x + brand_clip.w; bx++)
                                ABLEND(hl_col, brow[bx]);
                        }
                    }
                }

                /* Tiny 8x8 diamond logo */
                {
                    int lx = 6, ly = 8;
                    char *lbase = (char *)dst->px;
                    for (int iy = 0; iy < 8; iy++) {
                        int gy = ly + iy;
                        if (gy < mbar_clip.y || gy >= mbar_clip.y + mbar_clip.h) continue;
                        uint32_t *lrow = (uint32_t *)(lbase + (size_t)gy * dst->pitch);
                        for (int ix = 0; ix < 8; ix++) {
                            int gx = lx + ix;
                            if (gx < mbar_clip.x || gx >= mbar_clip.x + mbar_clip.w) continue;
                            /* Diamond shape: manhattan distance from center <= 3 */
                            int dx = ix - 3, dy = iy - 3;
                            if (dx < 0) dx = -dx;
                            if (dy < 0) dy = -dy;
                            if (dx + dy > 3) continue;
                            /* Gradient: bright center to blue edge */
                            int dist = dx + dy;
                            uint32_t r, g, b;
                            if (dist <= 1) { r = 0xBB; g = 0xCC; b = 0xFF; }
                            else if (dist == 2) { r = 0x77; g = 0x99; b = 0xDD; }
                            else { r = 0x55; g = 0x77; b = 0xBB; }
                            uint32_t col = 0xFF000000u | (r << 16) | (g << 8) | b;
                            lrow[gx] = col;
                        }
                    }
                }

                /* Text shadow + text */
                ui_draw_text(dst->px, dst->pitch, 17, 5,
                             0x40000000u, "Futura",
                             mbar_clip.x, mbar_clip.y, mbar_clip.w, mbar_clip.h);
                ui_draw_text(dst->px, dst->pitch, 16, 4,
                             0xFF7799DDu, "Futura",
                             mbar_clip.x, mbar_clip.y, mbar_clip.w, mbar_clip.h);
            }

            /* Show focused window title in menu bar (after branding) */
            if (comp->focused_surface) {
                const char *win_title = comp->focused_surface->title[0]
                    ? comp->focused_surface->title
                    : (comp->focused_surface->app_id[0]
                       ? comp->focused_surface->app_id : NULL);
                if (win_title) {
                    int sep_x = 16 + 6 * UI_FONT_WIDTH + 6;
                    /* Thin separator between branding and title */
                    fut_rect_t sep = { sep_x, 5, 1, MENUBAR_HEIGHT - 10 };
                    fut_rect_t sep_c;
                    if (rect_intersection(mbar_clip, sep, &sep_c)) {
                        for (int32_t sy = sep_c.y; sy < sep_c.y + sep_c.h; sy++) {
                            uint32_t *srow = (uint32_t *)(base + (size_t)sy * dst->pitch);
                            for (int32_t sx = sep_c.x; sx < sep_c.x + sep_c.w; sx++) {
                                uint32_t old = srow[sx];
                                uint32_t or_ = ((old >> 16) & 0xFF) * 180 / 255;
                                uint32_t og = ((old >> 8) & 0xFF) * 180 / 255;
                                uint32_t ob = (old & 0xFF) * 180 / 255;
                                srow[sx] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                            }
                        }
                    }
                    /* Truncate to max 30 chars */
                    char mbar_title[32];
                    int mti = 0;
                    while (win_title[mti] && mti < 30) {
                        mbar_title[mti] = win_title[mti];
                        mti++;
                    }
                    mbar_title[mti] = '\0';
                    int title_x = sep_x + 7;
                    ui_draw_text(dst->px, dst->pitch, title_x, 4,
                                 0xFFB0B0C0u, mbar_title,
                                 mbar_clip.x, mbar_clip.y, mbar_clip.w, mbar_clip.h);
                }
            }

            /* Get current time for menubar clock */
            struct { long tv_sec; long tv_nsec; } mb_ts = {0, 0};
            extern long sys_call2(long nr, long a, long b);
            sys_call2(98, 0, (long)&mb_ts);
            long mb_secs = mb_ts.tv_sec;
            long mb_daytime = mb_secs % 86400;
            int mb_hr = (int)(mb_daytime / 3600);
            int mb_min = (int)((mb_daytime % 3600) / 60);
            int mb_sec = (int)(mb_daytime % 60);

            /* Day of week from epoch (Jan 1 1970 was Thursday) */
            int mb_dow = (int)((mb_secs / 86400 + 4) % 7);
            const char *dow_names[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};

            /* Build "Tue  20:43:05" */
            char mb_time[20];
            const char *dn = dow_names[mb_dow];
            int ci = 0;
            mb_time[ci++] = dn[0]; mb_time[ci++] = dn[1]; mb_time[ci++] = dn[2];
            mb_time[ci++] = ' '; mb_time[ci++] = ' ';
            mb_time[ci++] = '0' + (char)(mb_hr / 10);
            mb_time[ci++] = '0' + (char)(mb_hr % 10);
            mb_time[ci++] = ':';
            mb_time[ci++] = '0' + (char)(mb_min / 10);
            mb_time[ci++] = '0' + (char)(mb_min % 10);
            mb_time[ci++] = ':';
            mb_time[ci++] = '0' + (char)(mb_sec / 10);
            mb_time[ci++] = '0' + (char)(mb_sec % 10);
            mb_time[ci] = '\0';

            /* System tray indicators (right side, before clock) */
            /* Render: [net] [vol] [DOW  HH:MM] */
            int tray_right = fb_w - 10;

            /* Clock (rightmost) */
            int clock_tx = tray_right - ci * UI_FONT_WIDTH;
            ui_draw_text(dst->px, dst->pitch, clock_tx, 4,
                         0xFFE0E0E8u, mb_time,
                         mbar_clip.x, mbar_clip.y, mbar_clip.w, mbar_clip.h);

            /* Separator before clock */
            {
                int sep_x2 = clock_tx - 8;
                fut_rect_t sep2 = { sep_x2, 5, 1, MENUBAR_HEIGHT - 10 };
                fut_rect_t sep2_c;
                if (rect_intersection(mbar_clip, sep2, &sep2_c)) {
                    for (int32_t sy = sep2_c.y; sy < sep2_c.y + sep2_c.h; sy++) {
                        uint32_t *srow = (uint32_t *)((char *)dst->px + (size_t)sy * dst->pitch);
                        for (int32_t sx = sep2_c.x; sx < sep2_c.x + sep2_c.w; sx++) {
                            uint32_t old = srow[sx];
                            uint32_t or_ = ((old >> 16) & 0xFF) * 160 / 255;
                            uint32_t og = ((old >> 8) & 0xFF) * 160 / 255;
                            uint32_t ob = (old & 0xFF) * 160 / 255;
                            srow[sx] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                        }
                    }
                }

                /* Volume icon: speaker + sound waves (14x12 px) */
                {
                    /* Bitmap rows for speaker shape (14 columns, 12 rows)
                     * Bit layout per row: columns 0..13, MSB=col0
                     * Speaker body + cone, then two arc waves */
                    static const uint16_t vol_bits[12] = {
                        0x0000, /*               */
                        0x0000, /*               */
                        0x0800, /*     #         */
                        0x1900, /*    ## #       */
                        0xFA20, /*  ##### #   #  */
                        0xFA20, /*  ##### #   #  */
                        0xFA20, /*  ##### #   #  */
                        0xFA20, /*  ##### #   #  */
                        0x1900, /*    ## #       */
                        0x0800, /*     #         */
                        0x0000, /*               */
                        0x0000, /*               */
                    };
                    int vix = sep_x2 - 18;
                    int viy = 6;
                    char *vbase = (char *)dst->px;
                    for (int vy = 0; vy < 12; vy++) {
                        int gy = viy + vy;
                        if (gy < mbar_clip.y || gy >= mbar_clip.y + mbar_clip.h) continue;
                        uint32_t *vrow = (uint32_t *)(vbase + (size_t)gy * dst->pitch);
                        uint16_t bits = vol_bits[vy];
                        if (!bits) continue;
                        for (int vx = 0; vx < 14; vx++) {
                            if (!(bits & (uint16_t)(0x8000u >> vx))) continue;
                            int gx = vix + vx;
                            if (gx < mbar_clip.x || gx >= mbar_clip.x + mbar_clip.w) continue;
                            ABLEND(0xD090A0B8u, vrow[gx]);
                        }
                    }
                }

                /* Network/WiFi icon: concentric arcs with dot */
                {
                    int nix = sep_x2 - 40;
                    int niy = 4;
                    char *nbase = (char *)dst->px;
                    int ncx = nix + 6;  /* center x */
                    int ncy = niy + 12; /* center y (bottom) */
                    for (int ny = 0; ny < 14; ny++) {
                        int gy = niy + ny;
                        if (gy < mbar_clip.y || gy >= mbar_clip.y + mbar_clip.h) continue;
                        uint32_t *nrow = (uint32_t *)(nbase + (size_t)gy * dst->pitch);
                        for (int nx = 0; nx < 14; nx++) {
                            int gx = nix + nx;
                            if (gx < mbar_clip.x || gx >= mbar_clip.x + mbar_clip.w) continue;
                            int dx = gx - ncx;
                            int dy = gy - ncy;
                            int dist_sq = dx * dx + dy * dy;
                            bool pixel = false;
                            /* Center dot: radius 1 */
                            if (dist_sq <= 2 && dy <= 0) pixel = true;
                            /* Arc 1: radius 4-5 */
                            if (dist_sq >= 14 && dist_sq <= 27 && dy <= -2 && dx >= -4 && dx <= 4) pixel = true;
                            /* Arc 2: radius 7-8 */
                            if (dist_sq >= 42 && dist_sq <= 68 && dy <= -4 && dx >= -7 && dx <= 7) pixel = true;
                            /* Arc 3: radius 10-11 */
                            if (dist_sq >= 90 && dist_sq <= 125 && dy <= -6 && dx >= -10 && dx <= 10) pixel = true;
                            if (pixel) {
                                ABLEND(0xD070C890u, nrow[gx]);
                            }
                        }
                    }
                }

                /* Battery icon: rounded rectangle with charge level (16x10 px) */
                {
                    int bix = sep_x2 - 60;
                    int biy = 7;
                    /* Battery body: 13x10 rounded rect, +2px tip on right */
                    char *bbase = (char *)dst->px;
                    uint32_t bat_col = 0xD090B890u;  /* Green tint */
                    for (int by = 0; by < 10; by++) {
                        int gy = biy + by;
                        if (gy < mbar_clip.y || gy >= mbar_clip.y + mbar_clip.h) continue;
                        uint32_t *brow = (uint32_t *)(bbase + (size_t)gy * dst->pitch);
                        for (int bx = 0; bx < 16; bx++) {
                            int gx = bix + bx;
                            if (gx < mbar_clip.x || gx >= mbar_clip.x + mbar_clip.w) continue;
                            bool pixel = false;
                            /* Battery tip (right nub): cols 13-14, rows 3-6 */
                            if (bx >= 13 && bx <= 14 && by >= 3 && by <= 6) {
                                pixel = true;
                            }
                            /* Body outline (0-12 x 0-9) with rounded corners */
                            else if (bx <= 12) {
                                bool is_edge = (by == 0 || by == 9 || bx == 0 || bx == 12);
                                /* Round corners: skip 1px at each corner */
                                if (bx == 0 && (by == 0 || by == 9)) is_edge = false;
                                if (bx == 12 && (by == 0 || by == 9)) is_edge = false;
                                if (is_edge) pixel = true;
                                /* Fill interior: charge level (80% = 8 of 10 cols) */
                                if (bx >= 2 && bx <= 10 && by >= 2 && by <= 7) {
                                    if (bx <= 9) pixel = true;  /* ~80% charge */
                                }
                            }
                            if (pixel) {
                                ABLEND(bat_col, brow[gx]);
                            }
                        }
                    }
                }
            }
        }
    }

    /* ── Bottom dock panel ── */
    {
        #define DOCK_HEIGHT 38
        #define DOCK_COLOR      0xC8181828u  /* Frosted dark panel */
        #define DOCK_ITEM_W     148
        #define DOCK_ITEM_H     28
        #define DOCK_ITEM_PAD   4            /* gap between items */
        #define DOCK_FOCUSED    0xD0506080u  /* Focused: blue-tinted highlight */
        #define DOCK_HOVER      0xC03A3A55u  /* Hover highlight */
        #define DOCK_SEP_COLOR  0x40667788u  /* Subtle separator */
        #define DOCK_TEXT       0xFFD8D8E0u  /* Light text on dark dock */
        #define DOCK_TEXT_DIM   0xFFA0A0B0u  /* Dimmer text for unfocused */
        #define DOCK_CORNER_R   10           /* Larger corner radius */
        #define DOCK_DSKBTN_W   28           /* Desktop-show button width */
        #define DOCK_HIGHLIGHT  0x30FFFFFFu  /* Frosted glass top highlight */

        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;

        /* Count windows for dock sizing */
        int n_windows = 0;
        struct comp_surface *ds;
        wl_list_for_each(ds, &comp->surfaces, link) {
            if (ds->has_backing) n_windows++;
        }

        /* Get current time and date for clock display */
        struct { long tv_sec; long tv_nsec; } clock_ts = {0, 0};
        extern long sys_call2(long nr, long a, long b);
        sys_call2(98, 0, (long)&clock_ts);  /* SYS_clock_gettime(CLOCK_REALTIME, &ts) */
        long total_secs = clock_ts.tv_sec;
        long daytime = total_secs % 86400;
        int clock_hr = (int)(daytime / 3600);
        int clock_min = (int)((daytime % 3600) / 60);
        int clock_sec = (int)(daytime % 60);

        /* Compute month, day, and day-of-week from epoch seconds */
        long days_since_epoch = total_secs / 86400;
        int dock_dow = (int)((days_since_epoch + 4) % 7); /* Jan 1 1970 = Thursday */
        const char *dock_dow_names[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
        /* Approximate year from days (good enough for date display) */
        int year = 1970;
        long remaining_days = days_since_epoch;
        for (;;) {
            int days_in_year = 365;
            if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)
                days_in_year = 366;
            if (remaining_days < days_in_year) break;
            remaining_days -= days_in_year;
            year++;
        }
        bool is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        int month_days[] = {31, is_leap ? 29 : 28, 31, 30, 31, 30,
                            31, 31, 30, 31, 30, 31};
        int month = 0;
        while (month < 11 && remaining_days >= month_days[month]) {
            remaining_days -= month_days[month];
            month++;
        }
        int day = (int)remaining_days + 1;
        const char *month_names[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                     "Jul","Aug","Sep","Oct","Nov","Dec"};

        /* Format: "Thu, Apr 16  13:34" — clean date+time for dock */
        char clock_str[28];
        const char *ddn = dock_dow_names[dock_dow];
        const char *mn = month_names[month];
        int ci = 0;
        clock_str[ci++] = ddn[0]; clock_str[ci++] = ddn[1]; clock_str[ci++] = ddn[2];
        clock_str[ci++] = ','; clock_str[ci++] = ' ';
        clock_str[ci++] = mn[0]; clock_str[ci++] = mn[1]; clock_str[ci++] = mn[2];
        clock_str[ci++] = ' ';
        if (day >= 10) clock_str[ci++] = '0' + (char)(day / 10);
        clock_str[ci++] = '0' + (char)(day % 10);
        clock_str[ci++] = ' '; clock_str[ci++] = ' ';
        clock_str[ci++] = '0' + (char)(clock_hr / 10);
        clock_str[ci++] = '0' + (char)(clock_hr % 10);
        clock_str[ci++] = ':';
        clock_str[ci++] = '0' + (char)(clock_min / 10);
        clock_str[ci++] = '0' + (char)(clock_min % 10);
        clock_str[ci++] = ':';
        clock_str[ci++] = '0' + (char)(clock_sec / 10);
        clock_str[ci++] = '0' + (char)(clock_sec % 10);
        clock_str[ci] = '\0';
        int clock_text_len = ci;

        #define CLOCK_WIDTH_NEW (22 * UI_FONT_WIDTH + 16)  /* "Thu, Apr 16  HH:MM:SS" + padding */

        /* Dock geometry: items + separators + clock + desktop button */
        int items_w = n_windows > 0
            ? n_windows * DOCK_ITEM_W + (n_windows - 1) * DOCK_ITEM_PAD
            : 0;
        int dock_content_w = 8 + items_w + 8 + CLOCK_WIDTH_NEW + 4 + DOCK_DSKBTN_W + 4;
        if (dock_content_w < 240) dock_content_w = 240;
        int dock_w = dock_content_w;
        int dock_x = (fb_w - dock_w) / 2;
        int dock_y = fb_h - DOCK_HEIGHT - 6;

        fut_rect_t dock_rect = { dock_x, dock_y, dock_w, DOCK_HEIGHT };

        /* Inline pixel darkening for dock shadow */
        #define shadow_darken_pixel_inline(px_ptr, a) do { \
            uint32_t _sd = *(px_ptr); \
            uint32_t _sf = 255u - (a); \
            uint32_t _sdr = ((_sd >> 16) & 0xFF) * _sf / 255u; \
            uint32_t _sdg = ((_sd >>  8) & 0xFF) * _sf / 255u; \
            uint32_t _sdb = ((_sd      ) & 0xFF) * _sf / 255u; \
            *(px_ptr) = 0xFF000000u | (_sdr << 16) | (_sdg << 8) | _sdb; \
        } while (0)

        /* Draw soft shadow above dock for depth */
        {
            #define DOCK_SHADOW_H 12  /* shadow height above dock */
            fut_rect_t shadow_rect = { dock_x - 4, dock_y - DOCK_SHADOW_H,
                                       dock_w + 8, DOCK_SHADOW_H };
            for (int i = 0; i < damage->count; ++i) {
                fut_rect_t sc;
                if (!rect_intersection(damage->rects[i], shadow_rect, &sc))
                    continue;
                char *base = (char *)dst->px;
                for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                    uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                    /* t: 0 at top of shadow → 1 at dock edge */
                    int sy = py - (dock_y - DOCK_SHADOW_H);
                    int alpha = sy * sy * 40 / (DOCK_SHADOW_H * DOCK_SHADOW_H);
                    if (alpha <= 0) continue;
                    if (alpha > 40) alpha = 40;
                    for (int32_t px = sc.x; px < sc.x + sc.w; px++) {
                        /* Fade at horizontal edges */
                        int edge_fade = 255;
                        int dx = px - dock_x;
                        int dx2 = (dock_x + dock_w) - px;
                        if (dx < 8) edge_fade = dx * 255 / 8;
                        else if (dx2 < 8) edge_fade = dx2 * 255 / 8;
                        int a = alpha * edge_fade / 255;
                        if (a > 0)
                            shadow_darken_pixel_inline(&row[px], (uint8_t)a);
                    }
                }
            }
        }

        /* Check if dock overlaps any damage region */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t dock_clip;
            if (!rect_intersection(damage->rects[i], dock_rect, &dock_clip))
                continue;

            /* Draw dock background with rounded corners, frosted glass effect */
            {
                char *base = (char *)dst->px;
                for (int32_t py = dock_clip.y; py < dock_clip.y + dock_clip.h; py++) {
                    uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                    int32_t ry = py - dock_y;                    /* row within dock */
                    int32_t dy = ry < DOCK_HEIGHT / 2 ? ry : (DOCK_HEIGHT - 1 - ry);
                    for (int32_t px = dock_clip.x; px < dock_clip.x + dock_clip.w; px++) {
                        int32_t rx = px - dock_x;               /* col within dock */
                        int32_t dx = rx < dock_w / 2 ? rx : (dock_w - 1 - rx);

                        /* Compute corner alpha fade with smooth anti-aliasing */
                        uint32_t alpha = 0xC8;
                        if (dx < DOCK_CORNER_R && dy < DOCK_CORNER_R) {
                            int32_t cx_d = DOCK_CORNER_R - dx;
                            int32_t cy_d = DOCK_CORNER_R - dy;
                            int32_t dist_sq = cx_d * cx_d + cy_d * cy_d;
                            int32_t r_sq = DOCK_CORNER_R * DOCK_CORNER_R;
                            int32_t inner_r = DOCK_CORNER_R - 2;
                            int32_t inner_sq = inner_r * inner_r;
                            if (dist_sq > r_sq) {
                                alpha = 0;   /* outside the rounded corner */
                            } else if (dist_sq > inner_sq) {
                                /* Smooth falloff in the 2px edge band */
                                alpha = (uint32_t)(0xC8 * (r_sq - dist_sq) / (r_sq - inner_sq));
                            }
                        }

                        if (alpha > 0) {
                            /* Subtle vertical gradient: lighter at top for glass feel */
                            int vgrad = ry < 6 ? (6 - ry) * 4 : 0;
                            uint32_t bg_r = 0x18 + vgrad;
                            uint32_t bg_g = 0x18 + vgrad;
                            uint32_t bg_b = 0x28 + vgrad;
                            if (bg_r > 0xFF) bg_r = 0xFF;
                            if (bg_g > 0xFF) bg_g = 0xFF;
                            if (bg_b > 0xFF) bg_b = 0xFF;
                            /* Subtle noise dither for premium feel */
                            uint32_t dither = (uint32_t)(px * 2971 + py * 6337);
                            dither ^= dither >> 13; dither *= 0x45d9f3bu; dither ^= dither >> 16;
                            int noise = (int)(dither & 0x7) - 3;  /* -3..4 */
                            bg_r = (uint32_t)((int)bg_r + noise < 0 ? 0 : (int)bg_r + noise);
                            bg_g = (uint32_t)((int)bg_g + noise < 0 ? 0 : (int)bg_g + noise);
                            bg_b = (uint32_t)((int)bg_b + noise < 0 ? 0 : (int)bg_b + noise);
                            if (bg_r > 0xFF) bg_r = 0xFF;
                            if (bg_g > 0xFF) bg_g = 0xFF;
                            if (bg_b > 0xFF) bg_b = 0xFF;
                            uint32_t col = (alpha << 24) | (bg_r << 16) | (bg_g << 8) | bg_b;
                            ABLEND(col, row[px]);

                            /* 2px frosted glass highlight at top edge */
                            if (ry <= 1 && alpha > 0x20) {
                                uint32_t hi_alpha = alpha * (ry == 0 ? 0x40u : 0x18u) / 0xC8;
                                uint32_t hi = (hi_alpha << 24) | 0x00FFFFFFu;
                                ABLEND(hi, row[px]);
                            }
                        }
                    }
                }
            }

            /* Draw window items in the dock */
            int item_x = dock_x + 8;
            int item_y = dock_y + (DOCK_HEIGHT - DOCK_ITEM_H) / 2;
            int win_idx = 0;
            struct comp_surface *ws;
            wl_list_for_each(ws, &comp->surfaces, link) {
                if (!ws->has_backing) continue;

                fut_rect_t item_rect = { item_x, item_y, DOCK_ITEM_W, DOCK_ITEM_H };
                fut_rect_t item_clip;
                if (rect_intersection(dock_clip, item_rect, &item_clip)) {
                    /* Determine item background: focused > hovered > default */
                    bool is_focused = (ws == comp->focused_surface);
                    bool is_hovered = (win_idx == comp->dock_hover_index);
                    bool is_minimized = ws->minimized;
                    uint32_t item_bg;
                    if (is_focused)
                        item_bg = DOCK_FOCUSED;
                    else if (is_hovered)
                        item_bg = DOCK_HOVER;
                    else
                        item_bg = 0x00000000u;  /* transparent — dock bg shows through */

                    if (item_bg & 0xFF000000u) {
                        /* Alpha blend the item highlight with rounded corners */
                        #define DOCK_ITEM_R 6
                        char *base = (char *)dst->px;
                        for (int32_t py = item_clip.y; py < item_clip.y + item_clip.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            int32_t iry = py - item_y;
                            int32_t idy = iry < DOCK_ITEM_H / 2 ? iry : (DOCK_ITEM_H - 1 - iry);
                            for (int32_t px = item_clip.x; px < item_clip.x + item_clip.w; px++) {
                                int32_t irx = px - item_x;
                                int32_t idx = irx < DOCK_ITEM_W / 2 ? irx : (DOCK_ITEM_W - 1 - irx);
                                /* Round corners */
                                if (idx < DOCK_ITEM_R && idy < DOCK_ITEM_R) {
                                    int32_t cxd = DOCK_ITEM_R - idx;
                                    int32_t cyd = DOCK_ITEM_R - idy;
                                    if (cxd * cxd + cyd * cyd > DOCK_ITEM_R * DOCK_ITEM_R)
                                        continue;
                                }
                                ABLEND(item_bg, row[px]);
                            }
                        }
                        #undef DOCK_ITEM_R
                    }

                    /* Focused indicator: small pill-shaped dot below the title */
                    if (is_focused) {
                        /* Glowing dot indicator — small bright pill, 8x3px */
                        int dot_w = 8, dot_h = 3;
                        int dot_x = item_x + (DOCK_ITEM_W - dot_w) / 2;
                        int dot_y = item_y + DOCK_ITEM_H - dot_h - 1;
                        fut_rect_t dot_rect = { dot_x, dot_y, dot_w, dot_h };
                        fut_rect_t dot_clip;
                        if (rect_intersection(dock_clip, dot_rect, &dot_clip)) {
                            char *gbase = (char *)dst->px;
                            for (int32_t gy = dot_clip.y; gy < dot_clip.y + dot_clip.h; gy++) {
                                uint32_t *grow = (uint32_t *)(gbase + (size_t)gy * dst->pitch);
                                for (int32_t gx = dot_clip.x; gx < dot_clip.x + dot_clip.w; gx++) {
                                    /* Rounded pill shape with soft edges */
                                    int lx = gx - dot_x, ly = gy - dot_y;
                                    int half_h = dot_h / 2;
                                    int fade_x = (lx < 2) ? lx : ((dot_w - 1 - lx < 2) ? (dot_w - 1 - lx) : 2);
                                    int fade_y = (ly <= half_h) ? ly : (dot_h - 1 - ly);
                                    int alpha = 200 * fade_x / 2;
                                    if (fade_y == 0) alpha = alpha * 2 / 3;
                                    if (alpha > 255) alpha = 255;
                                    uint32_t gc = ((uint32_t)alpha << 24) | 0x007799DDu;
                                    ABLEND(gc, grow[gx]);
                                }
                            }
                        }
                        /* Subtle glow halo around the dot */
                        fut_rect_t halo = { dot_x - 3, dot_y - 2, dot_w + 6, dot_h + 4 };
                        fut_rect_t halo_clip;
                        if (rect_intersection(dock_clip, halo, &halo_clip)) {
                            char *hbase = (char *)dst->px;
                            for (int32_t hy = halo_clip.y; hy < halo_clip.y + halo_clip.h; hy++) {
                                uint32_t *hrow = (uint32_t *)(hbase + (size_t)hy * dst->pitch);
                                for (int32_t hx = halo_clip.x; hx < halo_clip.x + halo_clip.w; hx++) {
                                    /* Skip the dot area itself */
                                    if (hx >= dot_x && hx < dot_x + dot_w &&
                                        hy >= dot_y && hy < dot_y + dot_h) continue;
                                    int dx = hx < dot_x ? dot_x - hx : (hx >= dot_x + dot_w ? hx - (dot_x + dot_w - 1) : 0);
                                    int dy = hy < dot_y ? dot_y - hy : (hy >= dot_y + dot_h ? hy - (dot_y + dot_h - 1) : 0);
                                    int dist = dx * dx + dy * dy;
                                    if (dist < 12) {
                                        int ha = 20 - dist * 2;
                                        if (ha > 0) {
                                            uint32_t hc = ((uint32_t)ha << 24) | 0x007799DDu;
                                            ABLEND(hc, hrow[hx]);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    /* Non-focused running indicator: small dim dot */
                    if (!is_focused && !is_minimized) {
                        int rdot_w = 4, rdot_h = 2;
                        int rdot_x = item_x + (DOCK_ITEM_W - rdot_w) / 2;
                        int rdot_y = item_y + DOCK_ITEM_H - rdot_h - 1;
                        fut_rect_t rdot_rect = { rdot_x, rdot_y, rdot_w, rdot_h };
                        fut_rect_t rdot_clip;
                        if (rect_intersection(dock_clip, rdot_rect, &rdot_clip)) {
                            char *rbase = (char *)dst->px;
                            for (int32_t ry = rdot_clip.y; ry < rdot_clip.y + rdot_clip.h; ry++) {
                                uint32_t *rrow = (uint32_t *)(rbase + (size_t)ry * dst->pitch);
                                for (int32_t rx = rdot_clip.x; rx < rdot_clip.x + rdot_clip.w; rx++) {
                                    int lx = rx - rdot_x;
                                    int fade = (lx == 0 || lx == rdot_w - 1) ? 40 : 80;
                                    uint32_t rc = ((uint32_t)fade << 24) | 0x009090A0u;
                                    ABLEND(rc, rrow[rx]);
                                }
                            }
                        }
                    }

                    /* Draw window title text with small app color dot */
                    {
                        const char *src_title = ws->title[0]
                            ? ws->title
                            : (ws->app_id[0] ? ws->app_id : "Window");
                        uint32_t text_color;
                        if (is_minimized)
                            text_color = 0xFF707088u;  /* Dimmer for minimized */
                        else if (is_focused)
                            text_color = 0xFFFFFFFFu;
                        else
                            text_color = ws->title[0] ? DOCK_TEXT : DOCK_TEXT_DIM;

                        /* Small colored circle icon (6x6) derived from title */
                        {
                            uint32_t th = 5381;
                            for (int ci = 0; src_title[ci]; ci++)
                                th = th * 33 + (uint8_t)src_title[ci];
                            /* Pastel color from hash */
                            uint32_t cr = 100 + (th & 0x7F);
                            uint32_t cg = 100 + ((th >> 7) & 0x7F);
                            uint32_t cb = 120 + ((th >> 14) & 0x7F);
                            uint32_t dot_col = 0xFF000000u | (cr << 16) | (cg << 8) | cb;
                            if (is_minimized) dot_col = 0xFF505060u;
                            int dcx = item_x + 6;
                            int dcy = item_y + DOCK_ITEM_H / 2;
                            int dr = 3;
                            fut_rect_t dot_r = { dcx - dr, dcy - dr, dr * 2, dr * 2 };
                            fut_rect_t dot_c;
                            if (rect_intersection(dock_clip, dot_r, &dot_c)) {
                                char *dbase = (char *)dst->px;
                                for (int32_t dy = dot_c.y; dy < dot_c.y + dot_c.h; dy++) {
                                    uint32_t *drow = (uint32_t *)(dbase + (size_t)dy * dst->pitch);
                                    for (int32_t ddx = dot_c.x; ddx < dot_c.x + dot_c.w; ddx++) {
                                        int rx = ddx - dcx, ry = dy - dcy;
                                        if (rx * rx + ry * ry <= dr * dr)
                                            drow[ddx] = dot_col;
                                    }
                                }
                            }
                        }

                        int max_chars = (DOCK_ITEM_W - 20) / UI_FONT_WIDTH;
                        if (max_chars > 16) max_chars = 16;
                        if (max_chars > 0) {
                            int src_len = 0;
                            while (src_title[src_len]) src_len++;
                            bool needs_ellipsis = src_len > max_chars && max_chars >= 3;
                            char dock_title[16];
                            int ti = 0;
                            int copy_len = needs_ellipsis ? max_chars - 2 : max_chars;
                            while (ti < copy_len && src_title[ti]) {
                                dock_title[ti] = src_title[ti];
                                ti++;
                            }
                            if (needs_ellipsis) {
                                dock_title[ti++] = '.';
                                dock_title[ti++] = '.';
                            }
                            dock_title[ti] = '\0';

                            int text_w = ti * UI_FONT_WIDTH;
                            int tx = item_x + 14 + (DOCK_ITEM_W - 14 - text_w) / 2;
                            int ty = item_y + (DOCK_ITEM_H - UI_FONT_HEIGHT) / 2;
                            ui_draw_text(dst->px, dst->pitch, tx, ty,
                                         text_color, dock_title,
                                         item_clip.x, item_clip.y,
                                         item_clip.w, item_clip.h);
                        }
                    }
                }

                /* Thin 1px separator with vertical fade */
                {
                    int sep_x = item_x + DOCK_ITEM_W;
                    int sep_top = dock_y + 6;
                    int sep_h = DOCK_HEIGHT - 12;
                    fut_rect_t sep_rect = { sep_x, sep_top, 1, sep_h };
                    fut_rect_t sep_clip;
                    if (rect_intersection(dock_clip, sep_rect, &sep_clip)) {
                        char *base = (char *)dst->px;
                        for (int32_t py = sep_clip.y; py < sep_clip.y + sep_clip.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            /* Fade alpha at top and bottom of separator */
                            int sy = py - sep_top;
                            int edge = sy < sep_h / 2 ? sy : (sep_h - 1 - sy);
                            int fade = edge < 4 ? (edge + 1) * 255 / 5 : 255;
                            uint32_t sep_a = ((DOCK_SEP_COLOR >> 24) & 0xFF) * (uint32_t)fade / 255;
                            uint32_t sep_c = (sep_a << 24) | (DOCK_SEP_COLOR & 0x00FFFFFFu);
                            for (int32_t px = sep_clip.x; px < sep_clip.x + sep_clip.w; px++)
                                ABLEND(sep_c, row[px]);
                        }
                    }
                }

                item_x += DOCK_ITEM_W + DOCK_ITEM_PAD;
                win_idx++;
            }

            /* Draw date + clock at the right side of dock (before desktop button) */
            {
                int cw = clock_text_len * UI_FONT_WIDTH + 12;
                int clock_x = dock_x + dock_w - DOCK_DSKBTN_W - 4 - cw;
                int clock_y_pos = dock_y + (DOCK_HEIGHT - UI_FONT_HEIGHT) / 2;
                fut_rect_t crect = { clock_x, clock_y_pos, cw, UI_FONT_HEIGHT };
                fut_rect_t cclip;
                if (rect_intersection(dock_clip, crect, &cclip)) {
                    int tx = clock_x + 6;
                    ui_draw_text(dst->px, dst->pitch, tx, clock_y_pos,
                                 0xFFFFFFFFu, clock_str,
                                 cclip.x, cclip.y, cclip.w, cclip.h);
                }

                /* Thin separator before clock with vertical fade */
                {
                    int cs_top = dock_y + 6;
                    int cs_h = DOCK_HEIGHT - 12;
                    fut_rect_t sep = { clock_x - 4, cs_top, 1, cs_h };
                    fut_rect_t sc;
                    if (rect_intersection(dock_clip, sep, &sc)) {
                        char *base = (char *)dst->px;
                        for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            int sy = py - cs_top;
                            int edge = sy < cs_h / 2 ? sy : (cs_h - 1 - sy);
                            int fade = edge < 4 ? (edge + 1) * 255 / 5 : 255;
                            uint32_t sep_a = ((DOCK_SEP_COLOR >> 24) & 0xFF) * (uint32_t)fade / 255;
                            uint32_t sep_c = (sep_a << 24) | (DOCK_SEP_COLOR & 0x00FFFFFFu);
                            for (int32_t px = sc.x; px < sc.x + sc.w; px++)
                                ABLEND(sep_c, row[px]);
                        }
                    }
                }
            }

            /* Desktop-show button at far right: small icon (stacked rectangles) */
            {
                int btn_x = dock_x + dock_w - DOCK_DSKBTN_W - 2;
                int btn_y_pos = dock_y + (DOCK_HEIGHT - DOCK_ITEM_H) / 2;
                fut_rect_t btn_rect = { btn_x, btn_y_pos, DOCK_DSKBTN_W, DOCK_ITEM_H };
                fut_rect_t btn_clip;
                if (rect_intersection(dock_clip, btn_rect, &btn_clip)) {
                    /* Hover highlight for desktop button */
                    if (comp->dock_hover_index == -2) {
                        char *base = (char *)dst->px;
                        for (int32_t py = btn_clip.y; py < btn_clip.y + btn_clip.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            for (int32_t px = btn_clip.x; px < btn_clip.x + btn_clip.w; px++)
                                ABLEND(DOCK_HOVER, row[px]);
                        }
                    }
                    /* Separator before desktop button with vertical fade */
                    {
                        int ds_top = dock_y + 6;
                        int ds_h = DOCK_HEIGHT - 12;
                        fut_rect_t sep = { btn_x - 3, ds_top, 1, ds_h };
                        fut_rect_t sc;
                        if (rect_intersection(dock_clip, sep, &sc)) {
                            char *base = (char *)dst->px;
                            for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                                uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                                int sy = py - ds_top;
                                int edge = sy < ds_h / 2 ? sy : (ds_h - 1 - sy);
                                int fade = edge < 4 ? (edge + 1) * 255 / 5 : 255;
                                uint32_t sep_a = ((DOCK_SEP_COLOR >> 24) & 0xFF) * (uint32_t)fade / 255;
                                uint32_t sep_c = (sep_a << 24) | (DOCK_SEP_COLOR & 0x00FFFFFFu);
                                for (int32_t px = sc.x; px < sc.x + sc.w; px++)
                                    ABLEND(sep_c, row[px]);
                            }
                        }
                    }
                    /* Draw a small "stacked windows" icon: two offset rectangles */
                    int ix = btn_x + (DOCK_DSKBTN_W - 14) / 2;
                    int iy = btn_y_pos + (DOCK_ITEM_H - 12) / 2;
                    uint32_t icon_col = comp->dock_hover_index == -2 ? 0xFFFFFFFFu : DOCK_TEXT;
                    /* Back rect (offset +3,+3) */
                    fut_rect_t br = { ix + 3, iy, 10, 8 };
                    fut_rect_t bc;
                    if (rect_intersection(btn_clip, br, &bc))
                        bb_fill_rect(dst, bc, icon_col);
                    /* Front rect (offset 0,+3) */
                    fut_rect_t fr = { ix, iy + 3, 10, 8 };
                    fut_rect_t fc;
                    if (rect_intersection(btn_clip, fr, &fc))
                        bb_fill_rect(dst, fc, icon_col);
                    /* Dark interior on front rect for depth */
                    fut_rect_t fi = { ix + 1, iy + 4, 8, 6 };
                    fut_rect_t fic;
                    if (rect_intersection(btn_clip, fi, &fic))
                        bb_fill_rect(dst, fic, 0xFF222233u);
                }
            }
        }

        /* Dock tooltip: floating label above hovered dock item */
        if (comp->dock_tooltip_index >= 0) {
            /* Find the window for this dock index */
            int tip_idx = 0;
            struct comp_surface *tip_surf = NULL;
            struct comp_surface *tds;
            wl_list_for_each(tds, &comp->surfaces, link) {
                if (!tds->has_backing) continue;
                if (tip_idx == comp->dock_tooltip_index) { tip_surf = tds; break; }
                tip_idx++;
            }
            if (tip_surf) {
                const char *tip_text = tip_surf->title[0]
                    ? tip_surf->title
                    : (tip_surf->app_id[0] ? tip_surf->app_id : "Window");
                int tip_len = 0;
                while (tip_text[tip_len] && tip_len < 30) tip_len++;
                int text_w = tip_len * UI_FONT_WIDTH + 12;

                /* Compute thumbnail dimensions if window has content */
                #define TIP_THUMB_W 160
                #define TIP_THUMB_H 100
                #define TIP_THUMB_PAD 6
                bool has_thumb = (tip_surf->backing && tip_surf->content_height > 0 && tip_surf->width > 0);
                int tip_w = text_w;
                if (has_thumb && tip_w < TIP_THUMB_W + TIP_THUMB_PAD * 2)
                    tip_w = TIP_THUMB_W + TIP_THUMB_PAD * 2;
                int tip_h = UI_FONT_HEIGHT + 8;
                if (has_thumb) tip_h += TIP_THUMB_H + TIP_THUMB_PAD;

                int tip_x = comp->dock_tooltip_x - tip_w / 2;
                int tip_y = comp->dock_tooltip_y - tip_h - 6;
                /* Clamp to screen */
                if (tip_x < 2) tip_x = 2;
                if (tip_x + tip_w > fb_w - 2) tip_x = fb_w - 2 - tip_w;
                if (tip_y < 2) tip_y = 2;

                fut_rect_t tip_rect = { tip_x, tip_y, tip_w, tip_h };
                for (int i = 0; i < damage->count; ++i) {
                    fut_rect_t tip_clip;
                    if (!rect_intersection(damage->rects[i], tip_rect, &tip_clip))
                        continue;
                    /* Tooltip background with rounded corners */
                    char *tbase = (char *)dst->px;
                    #define TIP_CORNER 6
                    for (int32_t py = tip_clip.y; py < tip_clip.y + tip_clip.h; py++) {
                        uint32_t *row = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                        int32_t ry = py - tip_y;
                        int32_t dy2 = ry < tip_h / 2 ? ry : (tip_h - 1 - ry);
                        for (int32_t px = tip_clip.x; px < tip_clip.x + tip_clip.w; px++) {
                            int32_t rx = px - tip_x;
                            int32_t dx2 = rx < tip_w / 2 ? rx : (tip_w - 1 - rx);
                            if (dx2 < TIP_CORNER && dy2 < TIP_CORNER) {
                                int32_t ccx = TIP_CORNER - dx2, ccy = TIP_CORNER - dy2;
                                if (ccx * ccx + ccy * ccy > TIP_CORNER * TIP_CORNER) continue;
                            }
                            ABLEND(0xE8202030u, row[px]);
                        }
                    }
                    #undef TIP_CORNER

                    /* Window preview thumbnail */
                    if (has_thumb) {
                        int src_w = tip_surf->width;
                        int src_h = tip_surf->content_height;
                        int scale_w = TIP_THUMB_W - 4;
                        int scale_h = src_h * scale_w / src_w;
                        if (scale_h > TIP_THUMB_H - 4) {
                            scale_h = TIP_THUMB_H - 4;
                            scale_w = src_w * scale_h / src_h;
                        }
                        int tx = tip_x + (tip_w - scale_w) / 2;
                        int ty2 = tip_y + TIP_THUMB_PAD;
                        /* Dark preview background */
                        fut_rect_t pb = { tip_x + TIP_THUMB_PAD, tip_y + TIP_THUMB_PAD,
                                          tip_w - TIP_THUMB_PAD * 2, TIP_THUMB_H };
                        fut_rect_t pbc;
                        if (rect_intersection(tip_clip, pb, &pbc)) {
                            for (int32_t py = pbc.y; py < pbc.y + pbc.h; py++) {
                                uint32_t *pr = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                                for (int32_t px = pbc.x; px < pbc.x + pbc.w; px++)
                                    pr[px] = 0xFF0A0A18u;
                            }
                        }
                        /* Scale content into preview */
                        fut_rect_t prev = { tx, ty2, scale_w, scale_h };
                        fut_rect_t pc;
                        if (rect_intersection(tip_clip, prev, &pc)) {
                            for (int32_t py = pc.y; py < pc.y + pc.h; py++) {
                                uint32_t *pr = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                                int sy = (py - ty2) * src_h / scale_h;
                                if (sy < 0 || sy >= src_h) continue;
                                const uint32_t *sr = (const uint32_t *)
                                    ((const char *)tip_surf->backing + (size_t)sy * tip_surf->stride);
                                for (int32_t px = pc.x; px < pc.x + pc.w; px++) {
                                    int sx = (px - tx) * src_w / scale_w;
                                    if (sx >= 0 && sx < src_w) pr[px] = sr[sx];
                                }
                            }
                        }
                    }

                    /* Tooltip text */
                    char tip_buf[32];
                    int ti = 0;
                    while (ti < tip_len) { tip_buf[ti] = tip_text[ti]; ti++; }
                    tip_buf[ti] = '\0';
                    int text_y = has_thumb ? (tip_y + TIP_THUMB_PAD + TIP_THUMB_H + 4)
                                           : (tip_y + 4);
                    int text_x = tip_x + (tip_w - tip_len * UI_FONT_WIDTH) / 2;
                    ui_draw_text(dst->px, dst->pitch,
                                 text_x, text_y,
                                 0xFFE0E0E8u, tip_buf,
                                 tip_clip.x, tip_clip.y, tip_clip.w, tip_clip.h);
                }
                #undef TIP_THUMB_W
                #undef TIP_THUMB_H
                #undef TIP_THUMB_PAD
            }
        }

    }

    int surface_count = 0;
    wl_list_for_each(surface, &comp->surfaces, link) {
        surface_count++;
        if (!surface->has_backing || surface->minimized) {
            continue;
        }
        fut_rect_t frame_rect = comp_frame_rect(surface);
        fut_rect_t window_rect = comp_window_rect(surface);
        bool touched = false;

        for (int i = 0; i < damage->count; ++i) {
            if (surface->shadow_px > 0) {
                fut_rect_t shadow_clip;
                if (rect_intersection(damage->rects[i], frame_rect, &shadow_clip)) {
                    shadow_draw(dst, surface, &shadow_clip);
                    touched = true;
                }
            }

            /* Focused window: blue glow border */
            if (surface == comp->focused_surface && surface->shadow_px > 0) {
                #define FOCUS_GLOW 6
                fut_rect_t glow_outer = {
                    window_rect.x - FOCUS_GLOW,
                    window_rect.y - FOCUS_GLOW,
                    window_rect.w + FOCUS_GLOW * 2,
                    window_rect.h + FOCUS_GLOW * 2
                };
                fut_rect_t glow_clip;
                if (rect_intersection(damage->rects[i], glow_outer, &glow_clip)) {
                    char *gbase = (char *)dst->px;
                    for (int32_t gy = glow_clip.y; gy < glow_clip.y + glow_clip.h; gy++) {
                        uint32_t *grow = (uint32_t *)(gbase + (size_t)gy * dst->pitch);
                        /* Distance to nearest window edge */
                        int dy_in = 0;
                        if (gy < window_rect.y) dy_in = window_rect.y - gy;
                        else if (gy >= window_rect.y + window_rect.h)
                            dy_in = gy - (window_rect.y + window_rect.h) + 1;
                        for (int32_t gx = glow_clip.x; gx < glow_clip.x + glow_clip.w; gx++) {
                            /* Skip pixels inside the window */
                            if (gx >= window_rect.x && gx < window_rect.x + window_rect.w &&
                                gy >= window_rect.y && gy < window_rect.y + window_rect.h)
                                continue;
                            int dx_in = 0;
                            if (gx < window_rect.x) dx_in = window_rect.x - gx;
                            else if (gx >= window_rect.x + window_rect.w)
                                dx_in = gx - (window_rect.x + window_rect.w) + 1;
                            int dist = dx_in > dy_in ? dx_in : dy_in;
                            if (dist > 0 && dist <= FOCUS_GLOW) {
                                int alpha = 55 * (FOCUS_GLOW + 1 - dist) / (FOCUS_GLOW + 1);
                                uint32_t gc = ((uint32_t)alpha << 24) | 0x005577CCu;
                                ABLEND(gc, grow[gx]);
                            }
                        }
                    }
                    touched = true;
                }
                #undef FOCUS_GLOW
            }

            fut_rect_t clip;
            if (!rect_intersection(damage->rects[i], window_rect, &clip)) {
                continue;
            }

            if (comp->deco_enabled && surface->bar_height > 0) {
                fut_rect_t bar_rect = comp_bar_rect(surface);
                fut_rect_t bar_clip;
                if (rect_intersection(damage->rects[i], bar_rect, &bar_clip)) {
                    draw_bar_segment(dst, bar_clip, bar_rect.y, bar_rect.h,
                                     surface == comp->focused_surface);
                    draw_title_text(dst, surface, &bar_clip);
                    touched = true;
                }

                /* 2px shadow at bottom of title bar for depth */
                {
                    int32_t sy = bar_rect.y + bar_rect.h;
                    fut_rect_t shadow = { bar_rect.x, sy, bar_rect.w, 2 };
                    fut_rect_t sc;
                    if (rect_intersection(damage->rects[i], shadow, &sc)) {
                        char *sbase = (char *)dst->px;
                        for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                            uint32_t *srow = (uint32_t *)(sbase + (size_t)py * dst->pitch);
                            int dark = (py == sy) ? 30 : 15;
                            for (int32_t px = sc.x; px < sc.x + sc.w; px++) {
                                uint32_t d = srow[px];
                                uint32_t dr = ((d >> 16) & 0xFF) * (255 - dark) / 255;
                                uint32_t dg = ((d >> 8) & 0xFF) * (255 - dark) / 255;
                                uint32_t db = (d & 0xFF) * (255 - dark) / 255;
                                srow[px] = 0xFF000000u | (dr << 16) | (dg << 8) | db;
                            }
                        }
                    }
                }

                fut_rect_t min_btn_rect = comp_min_btn_rect(surface);
                fut_rect_t min_btn_clip;
                if (min_btn_rect.w > 0 && min_btn_rect.h > 0 &&
                    rect_intersection(damage->rects[i], min_btn_rect, &min_btn_clip)) {
                    draw_minimize_button(dst, surface, min_btn_clip);
                    touched = true;
                }

                fut_rect_t max_btn_rect = comp_max_btn_rect(surface);
                fut_rect_t max_btn_clip;
                if (max_btn_rect.w > 0 && max_btn_rect.h > 0 &&
                    rect_intersection(damage->rects[i], max_btn_rect, &max_btn_clip)) {
                    draw_maximize_button(dst, surface, max_btn_clip);
                    touched = true;
                }

                fut_rect_t btn_rect = comp_btn_rect(surface);
                fut_rect_t btn_clip;
                if (btn_rect.w > 0 && btn_rect.h > 0 &&
                    rect_intersection(damage->rects[i], btn_rect, &btn_clip)) {
                    draw_close_button(dst, surface, btn_clip);
                    touched = true;
                }
            }

            fut_rect_t content_rect = comp_content_rect(surface);
            if (content_rect.h <= 0) {
                printf("[WAYLAND] Skipping content: h=%d\n", content_rect.h);
                continue;
            }
            fut_rect_t content_clip;
            if (!rect_intersection(damage->rects[i], content_rect, &content_clip)) {
                continue;
            }
            if (!surface->backing || surface->stride <= 0) {
                printf("[WAYLAND] No backing buffer: backing=%p stride=%d\n",
                       surface->backing, surface->stride);
                continue;
            }
            /* Bounds-check the backing buffer read */
            int32_t src_y = content_clip.y - content_rect.y;
            int32_t src_x = content_clip.x - content_rect.x;
            if (src_y < 0 || src_x < 0) {
                continue;
            }
            size_t src_end = (size_t)(src_y + content_clip.h - 1) * surface->stride +
                             (size_t)(src_x + content_clip.w) * 4u;
            if (src_end > surface->backing_size) {
                continue;
            }
            const char *src_ptr = (const char *)surface->backing +
                (size_t)src_y * surface->stride +
                (size_t)src_x * 4u;
            char *dst_ptr = (char *)dst->px +
                (size_t)content_clip.y * dst->pitch +
                (size_t)content_clip.x * 4u;
            /* Blit content with rounded bottom corners (radius 6) */
            {
                #define CONTENT_CORNER_R 6
                int32_t bot_y = content_rect.y + content_rect.h;
                const char *s = src_ptr;
                char *d = dst_ptr;
                for (int32_t row = 0; row < content_clip.h; row++) {
                    int32_t abs_y = content_clip.y + row;
                    int32_t dy_bot = bot_y - 1 - abs_y;  /* rows from bottom */
                    if (dy_bot < CONTENT_CORNER_R) {
                        /* In the bottom corner zone — per-pixel check */
                        const uint32_t *sp = (const uint32_t *)s;
                        uint32_t *dp = (uint32_t *)d;
                        for (int32_t col = 0; col < content_clip.w; col++) {
                            int32_t abs_x = content_clip.x + col;
                            int32_t dx_left = abs_x - content_rect.x;
                            int32_t dx_right = (content_rect.x + content_rect.w - 1) - abs_x;
                            int32_t dx = dx_left < dx_right ? dx_left : dx_right;
                            bool skip = false;
                            if (dx < CONTENT_CORNER_R) {
                                int32_t cxd = CONTENT_CORNER_R - dx;
                                int32_t cyd = CONTENT_CORNER_R - dy_bot;
                                if (cxd * cxd + cyd * cyd > CONTENT_CORNER_R * CONTENT_CORNER_R)
                                    skip = true;
                            }
                            if (!skip) dp[col] = sp[col];
                        }
                    } else {
                        memcpy(d, s, (size_t)content_clip.w * 4u);
                    }
                    s += surface->stride;
                    d += dst->pitch;
                }
                #undef CONTENT_CORNER_R
            }

            /* Subtle inset shadow at top of content for recessed depth */
            {
                #define INSET_H 3
                fut_rect_t inset_rect = { content_rect.x, content_rect.y,
                                          content_rect.w, INSET_H };
                fut_rect_t inset_clip;
                if (rect_intersection(damage->rects[i], inset_rect, &inset_clip)) {
                    char *ibase = (char *)dst->px;
                    for (int32_t py = inset_clip.y; py < inset_clip.y + inset_clip.h; py++) {
                        uint32_t *irow = (uint32_t *)(ibase + (size_t)py * dst->pitch);
                        int row_in = py - content_rect.y;
                        int darken = (INSET_H - row_in) * 18 / INSET_H;
                        for (int32_t px = inset_clip.x; px < inset_clip.x + inset_clip.w; px++) {
                            uint32_t d = irow[px];
                            uint32_t dr = ((d >> 16) & 0xFF) * (255 - darken) / 255;
                            uint32_t dg = ((d >> 8) & 0xFF) * (255 - darken) / 255;
                            uint32_t db = (d & 0xFF) * (255 - darken) / 255;
                            irow[px] = 0xFF000000u | (dr << 16) | (dg << 8) | db;
                        }
                    }
                }
                #undef INSET_H
            }

            /* Thin 1px border outline on focused windows for crisp edge */
            if (comp->deco_enabled && surface == comp->focused_surface) {
                uint32_t border_col = 0x30445588u;
                /* Left edge */
                fut_rect_t bl = { content_rect.x, content_rect.y, 1, content_rect.h };
                fut_rect_t blc;
                if (rect_intersection(damage->rects[i], bl, &blc)) {
                    char *bbase = (char *)dst->px;
                    for (int32_t py = blc.y; py < blc.y + blc.h; py++) {
                        uint32_t *brow = (uint32_t *)(bbase + (size_t)py * dst->pitch);
                        for (int32_t px = blc.x; px < blc.x + blc.w; px++)
                            ABLEND(border_col, brow[px]);
                    }
                }
                /* Right edge */
                fut_rect_t br = { content_rect.x + content_rect.w - 1, content_rect.y,
                                  1, content_rect.h };
                fut_rect_t brc;
                if (rect_intersection(damage->rects[i], br, &brc)) {
                    char *bbase = (char *)dst->px;
                    for (int32_t py = brc.y; py < brc.y + brc.h; py++) {
                        uint32_t *brow = (uint32_t *)(bbase + (size_t)py * dst->pitch);
                        for (int32_t px = brc.x; px < brc.x + brc.w; px++)
                            ABLEND(border_col, brow[px]);
                    }
                }
                /* Bottom edge */
                fut_rect_t bb = { content_rect.x, content_rect.y + content_rect.h - 1,
                                  content_rect.w, 1 };
                fut_rect_t bbc;
                if (rect_intersection(damage->rects[i], bb, &bbc)) {
                    char *bbase = (char *)dst->px;
                    for (int32_t py = bbc.y; py < bbc.y + bbc.h; py++) {
                        uint32_t *brow = (uint32_t *)(bbase + (size_t)py * dst->pitch);
                        for (int32_t px = bbc.x; px < bbc.x + bbc.w; px++)
                            ABLEND(border_col, brow[px]);
                    }
                }
            }

            /* Resize grip: 3 diagonal lines at bottom-right corner */
            if (comp->deco_enabled && !surface->maximized) {
                #define GRIP_SIZE 12
                int32_t gr_x0 = content_rect.x + content_rect.w - GRIP_SIZE;
                int32_t gr_y0 = content_rect.y + content_rect.h - GRIP_SIZE;
                fut_rect_t grip_rect = { gr_x0, gr_y0, GRIP_SIZE, GRIP_SIZE };
                fut_rect_t grip_clip;
                if (rect_intersection(damage->rects[i], grip_rect, &grip_clip)) {
                    char *grbase = (char *)dst->px;
                    for (int32_t gy = grip_clip.y; gy < grip_clip.y + grip_clip.h; gy++) {
                        uint32_t *grow = (uint32_t *)(grbase + (size_t)gy * dst->pitch);
                        for (int32_t gx = grip_clip.x; gx < grip_clip.x + grip_clip.w; gx++) {
                            int lx = gx - gr_x0;
                            int ly = gy - gr_y0;
                            /* Diagonal lines: lx + ly == GRIP_SIZE-2, -5, -8 */
                            int sum = lx + ly;
                            if (sum == GRIP_SIZE - 3 || sum == GRIP_SIZE - 6 ||
                                sum == GRIP_SIZE - 9) {
                                ABLEND(0x30FFFFFFu, grow[gx]);
                            } else if (sum == GRIP_SIZE - 2 || sum == GRIP_SIZE - 5 ||
                                       sum == GRIP_SIZE - 8) {
                                ABLEND(0x20000000u, grow[gx]);
                            }
                        }
                    }
                }
                #undef GRIP_SIZE
            }

            /* 1px side and bottom borders for framed window look */
            if (comp->deco_enabled && surface->bar_height > 0) {
                uint32_t border_col = (surface == comp->focused_surface)
                    ? 0xFFB0B0B8u : 0xFFCCCCD0u;
                char *bbase = (char *)dst->px;
                /* Left border */
                if (content_rect.x > 0) {
                    int32_t bx = content_rect.x - 1;
                    fut_rect_t lb = { bx, content_rect.y, 1, content_rect.h };
                    fut_rect_t lbc;
                    if (rect_intersection(damage->rects[i], lb, &lbc)) {
                        for (int32_t by = lbc.y; by < lbc.y + lbc.h; by++) {
                            uint32_t *brow = (uint32_t *)(bbase + (size_t)by * dst->pitch);
                            brow[bx] = border_col;
                        }
                    }
                }
                /* Right border */
                {
                    int32_t bx = content_rect.x + content_rect.w;
                    fut_rect_t rb = { bx, content_rect.y, 1, content_rect.h };
                    fut_rect_t rbc;
                    if (rect_intersection(damage->rects[i], rb, &rbc)) {
                        for (int32_t by = rbc.y; by < rbc.y + rbc.h; by++) {
                            uint32_t *brow = (uint32_t *)(bbase + (size_t)by * dst->pitch);
                            brow[bx] = border_col;
                        }
                    }
                }
                /* Bottom border */
                {
                    int32_t by = content_rect.y + content_rect.h;
                    fut_rect_t bb = { content_rect.x - 1, by,
                                      content_rect.w + 2, 1 };
                    fut_rect_t bbc;
                    if (rect_intersection(damage->rects[i], bb, &bbc)) {
                        uint32_t *brow = (uint32_t *)(bbase + (size_t)by * dst->pitch);
                        for (int32_t bx = bbc.x; bx < bbc.x + bbc.w; bx++)
                            brow[bx] = border_col;
                    }
                }
            }

            touched = true;
        }

        /* Draw window border: focused gets a subtle blue glow, unfocused gets thin dark line */
        if (touched && comp->deco_enabled) {
            bool is_focused = (surface == comp->focused_surface);
            fut_rect_t wr = comp_window_rect(surface);
            char *bbase = (char *)dst->px;

            if (is_focused) {
                /* Focused: 2px outer glow with blue tint + 1px inner border */
                for (int glow_i = 0; glow_i < 3; glow_i++) {
                    /* glow_i: 0 = outermost (2px out), 1 = 1px out, 2 = border itself */
                    int offset = 2 - glow_i;
                    uint32_t glow_color;
                    if (glow_i == 0) glow_color = 0x28506090u;  /* Faint outer */
                    else if (glow_i == 1) glow_color = 0x486688AAu;  /* Mid glow */
                    else glow_color = 0x68445578u;  /* Inner border */
                    fut_rect_t gr = { wr.x - offset, wr.y - offset,
                                      wr.w + offset * 2, wr.h + offset * 2 };
                    int32_t gedges[4][4] = {
                        { gr.x, gr.y, gr.w, 1 },
                        { gr.x, gr.y + gr.h - 1, gr.w, 1 },
                        { gr.x, gr.y, 1, gr.h },
                        { gr.x + gr.w - 1, gr.y, 1, gr.h },
                    };
                    for (int e = 0; e < 4; e++) {
                        fut_rect_t edge = { gedges[e][0], gedges[e][1], gedges[e][2], gedges[e][3] };
                        for (int di = 0; di < damage->count; ++di) {
                            fut_rect_t ec;
                            if (!rect_intersection(damage->rects[di], edge, &ec)) continue;
                            uint32_t sa = (glow_color >> 24) & 0xFF;
                            uint32_t da_ = 255u - sa;
                            uint32_t sr = (glow_color >> 16) & 0xFF;
                            uint32_t sg = (glow_color >> 8) & 0xFF;
                            uint32_t sb = glow_color & 0xFF;
                            for (int32_t py = ec.y; py < ec.y + ec.h; py++) {
                                uint32_t *row = (uint32_t *)(bbase + (size_t)py * dst->pitch);
                                for (int32_t px = ec.x; px < ec.x + ec.w; px++) {
                                    uint32_t d = row[px];
                                    uint32_t or_ = (sr * sa + ((d >> 16) & 0xFF) * da_) / 255u;
                                    uint32_t og = (sg * sa + ((d >> 8) & 0xFF) * da_) / 255u;
                                    uint32_t ob = (sb * sa + (d & 0xFF) * da_) / 255u;
                                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                                }
                            }
                        }
                    }
                }
            } else {
                /* Unfocused: simple 1px dark border */
                uint32_t border_color = 0x30000000u;
                int32_t edges[4][4] = {
                    { wr.x, wr.y, wr.w, 1 },
                    { wr.x, wr.y + wr.h - 1, wr.w, 1 },
                    { wr.x, wr.y, 1, wr.h },
                    { wr.x + wr.w - 1, wr.y, 1, wr.h },
                };
                for (int e = 0; e < 4; e++) {
                    fut_rect_t edge = { edges[e][0], edges[e][1], edges[e][2], edges[e][3] };
                    for (int di = 0; di < damage->count; ++di) {
                        fut_rect_t ec;
                        if (!rect_intersection(damage->rects[di], edge, &ec)) continue;
                        uint32_t sa = (border_color >> 24) & 0xFF;
                        uint32_t da_ = 255u - sa;
                        for (int32_t py = ec.y; py < ec.y + ec.h; py++) {
                            uint32_t *row = (uint32_t *)(bbase + (size_t)py * dst->pitch);
                            for (int32_t px = ec.x; px < ec.x + ec.w; px++) {
                                uint32_t d = row[px];
                                uint32_t or_ = ((d >> 16) & 0xFF) * da_ / 255u;
                                uint32_t og = ((d >> 8) & 0xFF) * da_ / 255u;
                                uint32_t ob = (d & 0xFF) * da_ / 255u;
                                row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                            }
                        }
                    }
                }
            }
        }

        if (touched) {
            surface->composed_this_tick = true;
        }
    }

    /* Draw snap preview overlay (translucent blue rectangle with rounded corners) */
    if (comp->snap_preview_active) {
        fut_rect_t sp = comp->snap_preview_rect;
        #define SNAP_PREVIEW_COLOR  0x38446699u  /* Semi-transparent blue */
        #define SNAP_BORDER_COLOR   0x807799DDu  /* Brighter blue border */
        #define SP_CORNER_R 8
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t sc;
            if (!rect_intersection(damage->rects[i], sp, &sc)) continue;
            char *spbase = (char *)dst->px;
            for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                uint32_t *row = (uint32_t *)(spbase + (size_t)py * dst->pitch);
                int32_t ry = py - sp.y;
                int32_t dy_edge = ry < sp.h / 2 ? ry : (sp.h - 1 - ry);
                for (int32_t px = sc.x; px < sc.x + sc.w; px++) {
                    int32_t rx = px - sp.x;
                    int32_t dx_edge = rx < sp.w / 2 ? rx : (sp.w - 1 - rx);
                    /* Rounded corner check */
                    if (dx_edge < SP_CORNER_R && dy_edge < SP_CORNER_R) {
                        int32_t cx_d = SP_CORNER_R - dx_edge;
                        int32_t cy_d = SP_CORNER_R - dy_edge;
                        if (cx_d * cx_d + cy_d * cy_d > SP_CORNER_R * SP_CORNER_R)
                            continue;
                    }
                    /* Determine if border (2px) or fill */
                    bool is_border = (rx < 2 || rx >= sp.w - 2 ||
                                      ry < 2 || ry >= sp.h - 2);
                    uint32_t color = is_border ? SNAP_BORDER_COLOR : SNAP_PREVIEW_COLOR;
                    uint32_t sa = (color >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t sr = (color >> 16) & 0xFF;
                    uint32_t sg = (color >> 8) & 0xFF;
                    uint32_t sb = color & 0xFF;
                    uint32_t d = row[px];
                    uint32_t or_ = (sr * sa + ((d >> 16) & 0xFF) * da) / 255u;
                    uint32_t og = (sg * sa + ((d >> 8) & 0xFF) * da) / 255u;
                    uint32_t ob = (sb * sa + (d & 0xFF) * da) / 255u;
                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }
        }
        #undef SNAP_PREVIEW_COLOR
        #undef SNAP_BORDER_COLOR
        #undef SP_CORNER_R
    }

    /* Draw desktop right-click context menu */
    if (comp->ctx_menu_active) {
        #define CTX_W     240
        #define CTX_ITEM_H 28
        #define CTX_ITEMS  6
        #define CTX_SEP_AFTER_1 1   /* separator after item index 1 */
        #define CTX_SEP_AFTER_2 3   /* separator after item index 3 */
        #define CTX_NUM_SEPS 2
        #define CTX_SEP_H  9       /* separator row height */
        #define CTX_PAD    4
        #define CTX_CORNER 6
        #define CTX_BG     0xE8202030u
        #define CTX_HOVER  0xFF334466u
        #define CTX_TEXT   0xFFE0E0E8u
        #define CTX_HINT   0xFF808098u  /* Dimmer shortcut hint */
        #define CTX_SEP    0x40667788u

        /* Menu height: items + separator rows + padding */
        int32_t menu_h = CTX_PAD + CTX_ITEMS * CTX_ITEM_H + CTX_NUM_SEPS * CTX_SEP_H + CTX_PAD;
        int32_t menu_x = comp->ctx_menu_x;
        int32_t menu_y = comp->ctx_menu_y;
        /* Clamp to screen */
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        if (menu_x + CTX_W > fb_w) menu_x = fb_w - CTX_W;
        if (menu_y + menu_h > fb_h) menu_y = fb_h - menu_h;
        fut_rect_t menu_rect = { menu_x, menu_y, CTX_W, menu_h };

        const char *ctx_labels[] = { "New Terminal", "Show Desktop",
                                      "Tile Left", "Tile Right",
                                      "Fullscreen", "About Futura" };
        const char *ctx_hints[] = { "Ctrl+Alt+T", "Super+D",
                                     "Super+Left", "Super+Right",
                                     "F11", NULL };

        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t mc;
            if (!rect_intersection(damage->rects[i], menu_rect, &mc)) continue;
            char *mbase = (char *)dst->px;

            /* Draw menu background with rounded corners */
            for (int32_t py = mc.y; py < mc.y + mc.h; py++) {
                uint32_t *row = (uint32_t *)(mbase + (size_t)py * dst->pitch);
                int32_t ry = py - menu_y;
                int32_t dy_edge = ry < menu_h / 2 ? ry : (menu_h - 1 - ry);
                for (int32_t px = mc.x; px < mc.x + mc.w; px++) {
                    int32_t rx = px - menu_x;
                    int32_t dx_edge = rx < CTX_W / 2 ? rx : (CTX_W - 1 - rx);

                    /* Rounded corner check */
                    if (dx_edge < CTX_CORNER && dy_edge < CTX_CORNER) {
                        int32_t cx_d = CTX_CORNER - dx_edge;
                        int32_t cy_d = CTX_CORNER - dy_edge;
                        if (cx_d * cx_d + cy_d * cy_d > CTX_CORNER * CTX_CORNER)
                            continue;
                    }

                    /* Check if this pixel is in a hovered item
                     * Layout: PAD | item0 | item1 | SEP | item2..3 | SEP | item4..5 | PAD */
                    int item_idx = -1;
                    int32_t local_ry = ry - CTX_PAD;
                    if (local_ry >= 0) {
                        /* Group 1: items 0..CTX_SEP_AFTER_1 */
                        int g1_h = (CTX_SEP_AFTER_1 + 1) * CTX_ITEM_H;
                        /* Group 2: items (CTX_SEP_AFTER_1+1)..CTX_SEP_AFTER_2 */
                        int g2_start = g1_h + CTX_SEP_H;
                        int g2_count = CTX_SEP_AFTER_2 - CTX_SEP_AFTER_1;
                        int g2_h = g2_count * CTX_ITEM_H;
                        /* Group 3: items (CTX_SEP_AFTER_2+1)..end */
                        int g3_start = g2_start + g2_h + CTX_SEP_H;
                        int g3_count = CTX_ITEMS - CTX_SEP_AFTER_2 - 1;
                        int g3_h = g3_count * CTX_ITEM_H;
                        if (local_ry < g1_h) {
                            item_idx = local_ry / CTX_ITEM_H;
                        } else if (local_ry >= g2_start && local_ry < g2_start + g2_h) {
                            item_idx = CTX_SEP_AFTER_1 + 1 +
                                       (local_ry - g2_start) / CTX_ITEM_H;
                        } else if (local_ry >= g3_start && local_ry < g3_start + g3_h) {
                            item_idx = CTX_SEP_AFTER_2 + 1 +
                                       (local_ry - g3_start) / CTX_ITEM_H;
                        }
                        (void)g3_h;
                    }

                    uint32_t bg = CTX_BG;
                    if (item_idx >= 0 && item_idx == comp->ctx_menu_hover) {
                        bg = CTX_HOVER;
                    }

                    /* Alpha blend */
                    uint32_t sa = (bg >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t sr = (bg >> 16) & 0xFF;
                    uint32_t sg = (bg >> 8) & 0xFF;
                    uint32_t sb = bg & 0xFF;
                    uint32_t d = row[px];
                    uint32_t or_ = (sr * sa + ((d >> 16) & 0xFF) * da) / 255u;
                    uint32_t og = (sg * sa + ((d >> 8) & 0xFF) * da) / 255u;
                    uint32_t ob = (sb * sa + (d & 0xFF) * da) / 255u;
                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* Draw 1px border */
            uint32_t border = 0x50667799u;
            int32_t bedges[4][4] = {
                { menu_x, menu_y, CTX_W, 1 },
                { menu_x, menu_y + menu_h - 1, CTX_W, 1 },
                { menu_x, menu_y, 1, menu_h },
                { menu_x + CTX_W - 1, menu_y, 1, menu_h },
            };
            for (int e = 0; e < 4; e++) {
                fut_rect_t edge = { bedges[e][0], bedges[e][1], bedges[e][2], bedges[e][3] };
                fut_rect_t ec;
                if (!rect_intersection(mc, edge, &ec)) continue;
                uint32_t bsa = (border >> 24) & 0xFF;
                uint32_t bda = 255u - bsa;
                uint32_t bsr = (border >> 16) & 0xFF;
                uint32_t bsg = (border >> 8) & 0xFF;
                uint32_t bsb = border & 0xFF;
                for (int32_t py = ec.y; py < ec.y + ec.h; py++) {
                    uint32_t *row = (uint32_t *)(mbase + (size_t)py * dst->pitch);
                    for (int32_t px = ec.x; px < ec.x + ec.w; px++) {
                        uint32_t d = row[px];
                        uint32_t or_ = (bsr * bsa + ((d >> 16) & 0xFF) * bda) / 255u;
                        uint32_t og = (bsg * bsa + ((d >> 8) & 0xFF) * bda) / 255u;
                        uint32_t ob = (bsb * bsa + (d & 0xFF) * bda) / 255u;
                        row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                    }
                }
            }

            /* Draw separator lines between groups */
            {
                int sep_positions[2] = { CTX_SEP_AFTER_1, CTX_SEP_AFTER_2 };
                for (int si = 0; si < CTX_NUM_SEPS; si++) {
                    /* Y position: items before this sep + previous seps */
                    int items_above = sep_positions[si] + 1;
                    int seps_above = si;
                    int sep_top = items_above * CTX_ITEM_H + seps_above * CTX_SEP_H + CTX_PAD;
                    int32_t sy = menu_y + sep_top + CTX_SEP_H / 2;
                    fut_rect_t sep_line = { menu_x + 8, sy, CTX_W - 16, 1 };
                    fut_rect_t slc;
                    if (rect_intersection(mc, sep_line, &slc)) {
                        char *slbase = (char *)dst->px;
                        for (int32_t spy = slc.y; spy < slc.y + slc.h; spy++) {
                            uint32_t *srow = (uint32_t *)(slbase + (size_t)spy * dst->pitch);
                            for (int32_t spx = slc.x; spx < slc.x + slc.w; spx++)
                                ABLEND(CTX_SEP, srow[spx]);
                        }
                    }
                }
            }

            /* Draw menu item icons + labels + shortcut hints */
            /* 8x8 pixel-art icons for each context menu item */
            static const uint8_t ctx_icons[CTX_ITEMS][8] = {
                /* Terminal: >_ prompt */
                { 0x00, 0x20, 0x30, 0x18, 0x30, 0x20, 0x0E, 0x00 },
                /* Desktop: monitor outline */
                { 0x7E, 0x42, 0x42, 0x42, 0x7E, 0x18, 0x3C, 0x00 },
                /* Tile left: filled left half */
                { 0xFF, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xFF, 0x00 },
                /* Tile right: filled right half */
                { 0xFF, 0x8F, 0x8F, 0x8F, 0x8F, 0x8F, 0xFF, 0x00 },
                /* Fullscreen: expand arrows */
                { 0xE1, 0x61, 0x30, 0x18, 0x0C, 0x86, 0x87, 0x00 },
                /* About: circled 'i' */
                { 0x3C, 0x42, 0x5A, 0x42, 0x5A, 0x5A, 0x42, 0x3C },
            };
            for (int item = 0; item < CTX_ITEMS; item++) {
                /* Y offset: items after each separator get shifted */
                int y_offset = 0;
                if (item > CTX_SEP_AFTER_1) y_offset += CTX_SEP_H;
                if (item > CTX_SEP_AFTER_2) y_offset += CTX_SEP_H;
                int text_y = menu_y + CTX_PAD + item * CTX_ITEM_H + y_offset +
                             (CTX_ITEM_H - UI_FONT_HEIGHT) / 2;
                /* Draw 8x8 icon */
                {
                    int icon_x = menu_x + 10;
                    int icon_y = text_y + (UI_FONT_HEIGHT - 8) / 2;
                    char *ibase = (char *)dst->px;
                    uint32_t icon_col = (item == comp->ctx_menu_hover)
                        ? 0xFFBBCCEEu : 0xB0A0A8C0u;
                    for (int iy = 0; iy < 8; iy++) {
                        int gy = icon_y + iy;
                        if (gy < mc.y || gy >= mc.y + mc.h) continue;
                        uint32_t *irow = (uint32_t *)(ibase + (size_t)gy * dst->pitch);
                        uint8_t bits = ctx_icons[item][iy];
                        for (int ix = 0; ix < 8; ix++) {
                            if (!(bits & (uint8_t)(0x80u >> ix))) continue;
                            int gx = icon_x + ix;
                            if (gx < mc.x || gx >= mc.x + mc.w) continue;
                            ABLEND(icon_col, irow[gx]);
                        }
                    }
                }
                int text_x = menu_x + 24;
                ui_draw_text(dst->px, dst->pitch, text_x, text_y,
                             CTX_TEXT, ctx_labels[item],
                             mc.x, mc.y, mc.w, mc.h);
                /* Draw right-aligned shortcut hint */
                if (ctx_hints[item]) {
                    int hlen = 0;
                    while (ctx_hints[item][hlen]) hlen++;
                    int hint_x = menu_x + CTX_W - 12 - hlen * UI_FONT_WIDTH;
                    ui_draw_text(dst->px, dst->pitch, hint_x, text_y,
                                 CTX_HINT, ctx_hints[item],
                                 mc.x, mc.y, mc.w, mc.h);
                }
            }
        }

        /* Draw shadow under menu */
        {
            #define CTX_SHADOW_SIZE 6
            fut_rect_t shadow_r = { menu_x + 3, menu_y + menu_h,
                                    CTX_W - 3, CTX_SHADOW_SIZE };
            fut_rect_t shadow_b = { menu_x + CTX_W, menu_y + 3,
                                    CTX_SHADOW_SIZE, menu_h - 3 };
            for (int si = 0; si < 2; si++) {
                fut_rect_t sr = si == 0 ? shadow_r : shadow_b;
                for (int di = 0; di < damage->count; ++di) {
                    fut_rect_t sc;
                    if (!rect_intersection(damage->rects[di], sr, &sc)) continue;
                    char *sbase = (char *)dst->px;
                    for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                        uint32_t *row = (uint32_t *)(sbase + (size_t)py * dst->pitch);
                        for (int32_t px = sc.x; px < sc.x + sc.w; px++) {
                            int32_t dx = si == 1 ? (px - menu_x - CTX_W) : 0;
                            int32_t dy = si == 0 ? (py - menu_y - menu_h) : (py - menu_y - 3);
                            int d2 = (si == 0 ? dy : dx);
                            if (d2 < 0) d2 = 0;
                            int alpha = 30 - d2 * 5;
                            if (alpha <= 0) continue;
                            uint32_t old = row[px];
                            uint32_t f = (uint32_t)(255 - alpha);
                            uint32_t or_ = ((old >> 16) & 0xFF) * f / 255u;
                            uint32_t og = ((old >> 8) & 0xFF) * f / 255u;
                            uint32_t ob = (old & 0xFF) * f / 255u;
                            row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                        }
                    }
                }
            }
            #undef CTX_SHADOW_SIZE
        }

        #undef CTX_W
        #undef CTX_ITEM_H
        #undef CTX_ITEMS
        #undef CTX_SEP_AFTER_1
        #undef CTX_SEP_AFTER_2
        #undef CTX_NUM_SEPS
        #undef CTX_SEP_H
        #undef CTX_PAD
        #undef CTX_CORNER
        #undef CTX_BG
        #undef CTX_HOVER
        #undef CTX_TEXT
        #undef CTX_HINT
        #undef CTX_SEP
    }

    /* Futura menu dropdown (top-left, below "Futura" branding) */
    if (comp->futura_menu_active) {
        #define FM_W       220
        #define FM_ITEM_H  26
        #define FM_ITEMS   8
        #define FM_SEP_AFTER 2   /* separator after Task Manager (apps group) */
        #define FM_SEP_H   7
        #define FM_PAD     4
        #define FM_CORNER  6
        #define FM_BG      0xE8202030u
        #define FM_HOVER   0xFF334466u
        #define FM_TEXT    0xFFE0E0E8u
        #define FM_HINT    0xFF808098u
        #define FM_SEP     0x40667788u

        int32_t fm_h = FM_PAD + FM_ITEMS * FM_ITEM_H + FM_SEP_H + FM_PAD;
        int32_t fm_x = 4;
        int32_t fm_y = MENUBAR_HEIGHT;
        fut_rect_t fm_rect = { fm_x, fm_y, FM_W, fm_h };

        const char *fm_labels[] = { "New Terminal", "Text Editor",
                                     "Task Manager", "About Futura",
                                     "Shortcuts", "System Info",
                                     "Show Desktop", "Quit" };
        const char *fm_hints[] = { "Ctrl+Alt+T", NULL,
                                    NULL, NULL,
                                    "Super+/", "Super+I",
                                    "Super+D", "Ctrl+Alt+Del" };

        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t fc;
            if (!rect_intersection(damage->rects[i], fm_rect, &fc)) continue;
            char *fbase = (char *)dst->px;

            /* Background with rounded corners */
            for (int32_t py = fc.y; py < fc.y + fc.h; py++) {
                uint32_t *row = (uint32_t *)(fbase + (size_t)py * dst->pitch);
                int32_t ry = py - fm_y;
                int32_t dy_e = ry < fm_h / 2 ? ry : (fm_h - 1 - ry);
                for (int32_t px = fc.x; px < fc.x + fc.w; px++) {
                    int32_t rx = px - fm_x;
                    int32_t dx_e = rx < FM_W / 2 ? rx : (FM_W - 1 - rx);
                    if (dx_e < FM_CORNER && dy_e < FM_CORNER) {
                        int32_t cxd = FM_CORNER - dx_e, cyd = FM_CORNER - dy_e;
                        if (cxd * cxd + cyd * cyd > FM_CORNER * FM_CORNER) continue;
                    }
                    /* Determine item index */
                    int fmi = -1;
                    int32_t lry = ry - FM_PAD;
                    if (lry >= 0) {
                        int before_sep = (FM_SEP_AFTER + 1) * FM_ITEM_H;
                        if (lry < before_sep) {
                            fmi = lry / FM_ITEM_H;
                        } else if (lry >= before_sep + FM_SEP_H) {
                            fmi = FM_SEP_AFTER + 1 + (lry - before_sep - FM_SEP_H) / FM_ITEM_H;
                        }
                        if (fmi >= FM_ITEMS) fmi = -1;
                    }
                    uint32_t bg = FM_BG;
                    if (fmi >= 0 && fmi == comp->futura_menu_hover) bg = FM_HOVER;
                    uint32_t sa = (bg >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t d = row[px];
                    uint32_t or_ = (((bg >> 16) & 0xFF) * sa + ((d >> 16) & 0xFF) * da) / 255u;
                    uint32_t og = (((bg >> 8) & 0xFF) * sa + ((d >> 8) & 0xFF) * da) / 255u;
                    uint32_t ob = ((bg & 0xFF) * sa + (d & 0xFF) * da) / 255u;
                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* Border */
            uint32_t fb_color = 0x50667799u;
            int32_t fb_edges[4][4] = {
                { fm_x, fm_y, FM_W, 1 },
                { fm_x, fm_y + fm_h - 1, FM_W, 1 },
                { fm_x, fm_y, 1, fm_h },
                { fm_x + FM_W - 1, fm_y, 1, fm_h },
            };
            for (int e = 0; e < 4; e++) {
                fut_rect_t edge = { fb_edges[e][0], fb_edges[e][1], fb_edges[e][2], fb_edges[e][3] };
                fut_rect_t ec;
                if (!rect_intersection(fc, edge, &ec)) continue;
                for (int32_t py = ec.y; py < ec.y + ec.h; py++) {
                    uint32_t *row = (uint32_t *)(fbase + (size_t)py * dst->pitch);
                    for (int32_t px = ec.x; px < ec.x + ec.w; px++) {
                        uint32_t sa = (fb_color >> 24) & 0xFF;
                        uint32_t da = 255u - sa;
                        uint32_t d = row[px];
                        row[px] = 0xFF000000u |
                            ((((fb_color>>16)&0xFF)*sa+((d>>16)&0xFF)*da)/255u << 16) |
                            ((((fb_color>>8)&0xFF)*sa+((d>>8)&0xFF)*da)/255u << 8) |
                            (((fb_color&0xFF)*sa+(d&0xFF)*da)/255u);
                    }
                }
            }

            /* Separator line */
            {
                int sep_top = (FM_SEP_AFTER + 1) * FM_ITEM_H + FM_PAD;
                int32_t sy = fm_y + sep_top + FM_SEP_H / 2;
                fut_rect_t sep_line = { fm_x + 8, sy, FM_W - 16, 1 };
                fut_rect_t sc;
                if (rect_intersection(fc, sep_line, &sc)) {
                    for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                        uint32_t *srow = (uint32_t *)(fbase + (size_t)py * dst->pitch);
                        for (int32_t px = sc.x; px < sc.x + sc.w; px++)
                            srow[px] = 0xFF333344u;
                    }
                }
            }

            /* Item icons + labels + hints */
            /* 8x8 pixel-art icons for Futura menu */
            static const uint8_t fm_icons[FM_ITEMS][8] = {
                /* Terminal: >_ prompt */
                { 0x00, 0x20, 0x30, 0x18, 0x30, 0x20, 0x0E, 0x00 },
                /* Text Editor: document with lines */
                { 0x7E, 0x42, 0x7E, 0x42, 0x7E, 0x42, 0x7E, 0x00 },
                /* Task Manager: bar chart */
                { 0x00, 0x02, 0x0A, 0x2A, 0xAA, 0xAA, 0xAA, 0xFF },
                /* About: circled 'i' */
                { 0x3C, 0x42, 0x5A, 0x42, 0x5A, 0x5A, 0x42, 0x3C },
                /* Shortcuts: keyboard outline */
                { 0x00, 0xFF, 0x81, 0xAD, 0x81, 0xBD, 0xFF, 0x00 },
                /* System info: gear/cog */
                { 0x18, 0x5A, 0xFF, 0xDB, 0xDB, 0xFF, 0x5A, 0x18 },
                /* Desktop: monitor */
                { 0x7E, 0x42, 0x42, 0x42, 0x7E, 0x18, 0x3C, 0x00 },
                /* Quit: power icon */
                { 0x18, 0x18, 0x7E, 0xC3, 0xC3, 0xC3, 0x7E, 0x3C },
            };
            for (int item = 0; item < FM_ITEMS; item++) {
                int y_off = (item > FM_SEP_AFTER) ? FM_SEP_H : 0;
                int ty = fm_y + FM_PAD + item * FM_ITEM_H + y_off +
                         (FM_ITEM_H - UI_FONT_HEIGHT) / 2;
                /* Draw 8x8 icon */
                {
                    int icon_x = fm_x + 10;
                    int icon_y = ty + (UI_FONT_HEIGHT - 8) / 2;
                    char *ibase = (char *)dst->px;
                    uint32_t icon_col = (item == comp->futura_menu_hover)
                        ? 0xFFBBCCEEu : 0xB0A0A8C0u;
                    /* "Quit" item gets red tint */
                    if (item == FM_ITEMS - 1)
                        icon_col = (item == comp->futura_menu_hover)
                            ? 0xFFFF8888u : 0xB0CC6060u;
                    for (int iy = 0; iy < 8; iy++) {
                        int gy = icon_y + iy;
                        if (gy < fc.y || gy >= fc.y + fc.h) continue;
                        uint32_t *irow = (uint32_t *)(ibase + (size_t)gy * dst->pitch);
                        uint8_t bits = fm_icons[item][iy];
                        for (int ix = 0; ix < 8; ix++) {
                            if (!(bits & (uint8_t)(0x80u >> ix))) continue;
                            int gx = icon_x + ix;
                            if (gx < fc.x || gx >= fc.x + fc.w) continue;
                            ABLEND(icon_col, irow[gx]);
                        }
                    }
                }
                ui_draw_text(dst->px, dst->pitch, fm_x + 24, ty,
                             FM_TEXT, fm_labels[item],
                             fc.x, fc.y, fc.w, fc.h);
                if (fm_hints[item]) {
                    int hl = 0;
                    while (fm_hints[item][hl]) hl++;
                    ui_draw_text(dst->px, dst->pitch,
                                 fm_x + FM_W - 12 - hl * UI_FONT_WIDTH, ty,
                                 FM_HINT, fm_hints[item],
                                 fc.x, fc.y, fc.w, fc.h);
                }
            }
        }
        #undef FM_W
        #undef FM_ITEM_H
        #undef FM_ITEMS
        #undef FM_SEP_AFTER
        #undef FM_SEP_H
        #undef FM_PAD
        #undef FM_CORNER
        #undef FM_BG
        #undef FM_HOVER
        #undef FM_TEXT
        #undef FM_HINT
        #undef FM_SEP
    }

    /* Keyboard shortcut overlay */
    if (comp->shortcut_overlay_active) {
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        #define SO_W 340
        #define SO_H 338
        #define SO_R 10
        #define SO_BG 0xF0181828u
        int32_t sox = (fb_w - SO_W) / 2;
        int32_t soy = (fb_h - SO_H) / 2;
        fut_rect_t so_rect = { sox, soy, SO_W, SO_H };

        /* Dim background */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t frc;
            fut_rect_t full = { 0, 0, fb_w, fb_h };
            if (!rect_intersection(damage->rects[i], full, &frc)) continue;
            char *dbase = (char *)dst->px;
            for (int32_t py = frc.y; py < frc.y + frc.h; py++) {
                uint32_t *row = (uint32_t *)(dbase + (size_t)py * dst->pitch);
                for (int32_t px = frc.x; px < frc.x + frc.w; px++) {
                    uint32_t d = row[px];
                    row[px] = 0xFF000000u |
                        ((((d>>16)&0xFF)*160/255)<<16) |
                        ((((d>>8)&0xFF)*160/255)<<8) |
                        (((d&0xFF)*160/255));
                }
            }
        }

        /* Draw overlay box */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t sc;
            if (!rect_intersection(damage->rects[i], so_rect, &sc)) continue;
            char *sbase = (char *)dst->px;
            /* Background with rounded corners */
            for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                uint32_t *row = (uint32_t *)(sbase + (size_t)py * dst->pitch);
                int32_t ry = py - soy;
                int32_t dy_e = ry < SO_H / 2 ? ry : (SO_H - 1 - ry);
                for (int32_t px = sc.x; px < sc.x + sc.w; px++) {
                    int32_t rx = px - sox;
                    int32_t dx_e = rx < SO_W / 2 ? rx : (SO_W - 1 - rx);
                    if (dx_e < SO_R && dy_e < SO_R) {
                        int32_t cxd = SO_R - dx_e, cyd = SO_R - dy_e;
                        if (cxd * cxd + cyd * cyd > SO_R * SO_R) continue;
                    }
                    uint32_t sa = (SO_BG >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t d = row[px];
                    uint32_t or_ = (((SO_BG>>16)&0xFF)*sa+((d>>16)&0xFF)*da)/255u;
                    uint32_t og = (((SO_BG>>8)&0xFF)*sa+((d>>8)&0xFF)*da)/255u;
                    uint32_t ob = ((SO_BG&0xFF)*sa+(d&0xFF)*da)/255u;
                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* Title */
            ui_draw_text(dst->px, dst->pitch,
                         sox + SO_W / 2 - 9 * UI_FONT_WIDTH / 2, soy + 16,
                         0xFF7799DDu, "Shortcuts",
                         sc.x, sc.y, sc.w, sc.h);

            /* Separator */
            {
                fut_rect_t sep = { sox + 16, soy + 38, SO_W - 32, 1 };
                fut_rect_t sepc;
                if (rect_intersection(sc, sep, &sepc)) {
                    for (int32_t py = sepc.y; py < sepc.y + sepc.h; py++) {
                        uint32_t *row = (uint32_t *)(sbase + (size_t)py * dst->pitch);
                        for (int32_t px = sepc.x; px < sepc.x + sepc.w; px++)
                            row[px] = 0xFF333344u;
                    }
                }
            }

            /* Shortcut entries */
            const char *so_keys[] = {
                "Ctrl+Alt+T", "Super+Enter",
                "Alt+Tab", "Alt+F4",
                "Super+Q", "Super+D",
                "Super+M", "Super+F",
                "Super+Left", "Super+Right",
                "Super+Up", "Super+Down",
                "F11", "Super+I",
                "Super+/",
            };
            const char *so_desc[] = {
                "New terminal", "New terminal",
                "Switch windows", "Close window",
                "Close window", "Show desktop",
                "Minimize", "Fullscreen",
                "Tile left", "Tile right",
                "Maximize", "Restore",
                "Fullscreen", "System info",
                "This overlay",
            };
            int so_n = 15;
            for (int si = 0; si < so_n; si++) {
                int ty = soy + 50 + si * 18;
                ui_draw_text(dst->px, dst->pitch, sox + 20, ty,
                             0xFFB0B0C0u, so_keys[si],
                             sc.x, sc.y, sc.w, sc.h);
                ui_draw_text(dst->px, dst->pitch, sox + 160, ty,
                             0xFF808098u, so_desc[si],
                             sc.x, sc.y, sc.w, sc.h);
            }

            /* Dismiss hint */
            ui_draw_text(dst->px, dst->pitch,
                         sox + SO_W / 2 - 11 * UI_FONT_WIDTH, soy + SO_H - 22,
                         0xFF606078u, "Press any key to close",
                         sc.x, sc.y, sc.w, sc.h);
        }
        #undef SO_W
        #undef SO_H
        #undef SO_R
        #undef SO_BG
    }

    /* Alt+Tab window switcher overlay */
    if (comp->alt_tab_active) {
        #define TAB_ITEM_W    140
        #define TAB_ITEM_H    100
        #define TAB_ITEM_PAD  10
        #define TAB_PAD       16
        #define TAB_TITLE_H   22
        #define TAB_BG        0xE0181828u
        #define TAB_SEL       0xFF3A5588u
        #define TAB_BORDER    0x60667799u
        #define TAB_CORNER    10
        #define TAB_THUMB_BG  0xFF0A0A18u

        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;

        /* Count switchable windows */
        int n_tab = 0;
        struct comp_surface *ts;
        wl_list_for_each(ts, &comp->surfaces, link) {
            if (ts->has_backing && !ts->minimized) n_tab++;
        }
        if (n_tab > 8) n_tab = 8;  /* limit to 8 visible items */

        int total_w = TAB_PAD * 2 + n_tab * TAB_ITEM_W + (n_tab > 1 ? (n_tab - 1) * TAB_ITEM_PAD : 0);
        int total_h = TAB_PAD * 2 + TAB_ITEM_H + TAB_TITLE_H;
        int tab_x = (fb_w - total_w) / 2;
        int tab_y = (fb_h - total_h) / 2;
        fut_rect_t tab_rect = { tab_x, tab_y, total_w, total_h };

        /* Dim background */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t fc;
            fut_rect_t full = { 0, 0, fb_w, fb_h };
            if (!rect_intersection(damage->rects[i], full, &fc)) continue;
            char *dbase = (char *)dst->px;
            for (int32_t py = fc.y; py < fc.y + fc.h; py++) {
                uint32_t *row = (uint32_t *)(dbase + (size_t)py * dst->pitch);
                for (int32_t px = fc.x; px < fc.x + fc.w; px++) {
                    uint32_t d = row[px];
                    uint32_t r = ((d >> 16) & 0xFF) * 140 / 255;
                    uint32_t g = ((d >> 8) & 0xFF) * 140 / 255;
                    uint32_t b = (d & 0xFF) * 140 / 255;
                    row[px] = 0xFF000000u | (r << 16) | (g << 8) | b;
                }
            }
        }

        /* Draw switcher panel background with rounded corners */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t tc;
            if (!rect_intersection(damage->rects[i], tab_rect, &tc)) continue;
            char *tbase = (char *)dst->px;
            for (int32_t py = tc.y; py < tc.y + tc.h; py++) {
                uint32_t *row = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                int32_t ry = py - tab_y;
                int32_t dy = ry < total_h / 2 ? ry : (total_h - 1 - ry);
                for (int32_t px = tc.x; px < tc.x + tc.w; px++) {
                    int32_t rx = px - tab_x;
                    int32_t dx = rx < total_w / 2 ? rx : (total_w - 1 - rx);
                    /* Round corners */
                    if (dx < TAB_CORNER && dy < TAB_CORNER) {
                        int32_t cx = TAB_CORNER - dx;
                        int32_t cy = TAB_CORNER - dy;
                        if (cx * cx + cy * cy > TAB_CORNER * TAB_CORNER) continue;
                    }
                    uint32_t sa = (TAB_BG >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t sr = (TAB_BG >> 16) & 0xFF;
                    uint32_t sg = (TAB_BG >> 8) & 0xFF;
                    uint32_t sb = TAB_BG & 0xFF;
                    uint32_t d = row[px];
                    uint32_t or_ = (sr * sa + ((d >> 16) & 0xFF) * da) / 255u;
                    uint32_t og = (sg * sa + ((d >> 8) & 0xFF) * da) / 255u;
                    uint32_t ob = (sb * sa + (d & 0xFF) * da) / 255u;
                    row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* 1px panel border */
            {
                int32_t bedges[4][4] = {
                    { tab_x, tab_y, total_w, 1 },
                    { tab_x, tab_y + total_h - 1, total_w, 1 },
                    { tab_x, tab_y, 1, total_h },
                    { tab_x + total_w - 1, tab_y, 1, total_h },
                };
                for (int e = 0; e < 4; e++) {
                    fut_rect_t edge = { bedges[e][0], bedges[e][1], bedges[e][2], bedges[e][3] };
                    fut_rect_t ec;
                    if (!rect_intersection(tc, edge, &ec)) continue;
                    for (int32_t py2 = ec.y; py2 < ec.y + ec.h; py2++) {
                        uint32_t *brow = (uint32_t *)((char *)dst->px + (size_t)py2 * dst->pitch);
                        for (int32_t px2 = ec.x; px2 < ec.x + ec.w; px2++) {
                            uint32_t d = brow[px2];
                            uint32_t bsa = (TAB_BORDER >> 24) & 0xFF;
                            uint32_t bda = 255u - bsa;
                            uint32_t or_ = (((TAB_BORDER >> 16) & 0xFF) * bsa + ((d >> 16) & 0xFF) * bda) / 255u;
                            uint32_t og = (((TAB_BORDER >> 8) & 0xFF) * bsa + ((d >> 8) & 0xFF) * bda) / 255u;
                            uint32_t ob = ((TAB_BORDER & 0xFF) * bsa + (d & 0xFF) * bda) / 255u;
                            brow[px2] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                        }
                    }
                }
            }

            /* Draw each window item */
            int item_idx = 0;
            struct comp_surface *ws2;
            wl_list_for_each(ws2, &comp->surfaces, link) {
                if (!ws2->has_backing || ws2->minimized) continue;
                if (item_idx >= 8) break;

                int ix = tab_x + TAB_PAD + item_idx * (TAB_ITEM_W + TAB_ITEM_PAD);
                int iy = tab_y + TAB_PAD;
                bool selected = (item_idx == comp->alt_tab_index);

                /* Selection highlight */
                if (selected) {
                    fut_rect_t sel_rect = { ix - 3, iy - 3, TAB_ITEM_W + 6, TAB_ITEM_H + TAB_TITLE_H + 6 };
                    fut_rect_t sel_clip;
                    if (rect_intersection(tc, sel_rect, &sel_clip)) {
                        for (int32_t sy = sel_clip.y; sy < sel_clip.y + sel_clip.h; sy++) {
                            uint32_t *srow = (uint32_t *)(tbase + (size_t)sy * dst->pitch);
                            int32_t sry = sy - sel_rect.y;
                            int32_t sdy = sry < sel_rect.h / 2 ? sry : (sel_rect.h - 1 - sry);
                            for (int32_t sx = sel_clip.x; sx < sel_clip.x + sel_clip.w; sx++) {
                                int32_t srx = sx - sel_rect.x;
                                int32_t sdx = srx < sel_rect.w / 2 ? srx : (sel_rect.w - 1 - srx);
                                if (sdx < 6 && sdy < 6) {
                                    int32_t ccx = 6 - sdx, ccy = 6 - sdy;
                                    if (ccx * ccx + ccy * ccy > 36) continue;
                                }
                                uint32_t ssa = (TAB_SEL >> 24) & 0xFF;
                                uint32_t sda = 255u - ssa;
                                uint32_t d = srow[sx];
                                uint32_t or_ = (((TAB_SEL >> 16) & 0xFF) * ssa + ((d >> 16) & 0xFF) * sda) / 255u;
                                uint32_t og = (((TAB_SEL >> 8) & 0xFF) * ssa + ((d >> 8) & 0xFF) * sda) / 255u;
                                uint32_t ob = ((TAB_SEL & 0xFF) * ssa + (d & 0xFF) * sda) / 255u;
                                srow[sx] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                            }
                        }
                    }
                }

                /* Window thumbnail area: draw scaled-down preview of window content */
                fut_rect_t thumb_rect = { ix, iy, TAB_ITEM_W, TAB_ITEM_H };
                fut_rect_t thumb_clip;
                if (rect_intersection(tc, thumb_rect, &thumb_clip)) {
                    /* Dark background for thumbnail */
                    for (int32_t ty = thumb_clip.y; ty < thumb_clip.y + thumb_clip.h; ty++) {
                        uint32_t *trow = (uint32_t *)(tbase + (size_t)ty * dst->pitch);
                        for (int32_t tx = thumb_clip.x; tx < thumb_clip.x + thumb_clip.w; tx++)
                            trow[tx] = TAB_THUMB_BG;
                    }

                    /* Scale window content into thumbnail */
                    if (ws2->backing && ws2->content_height > 0 && ws2->width > 0) {
                        int src_w = ws2->width;
                        int src_h = ws2->content_height;
                        /* Fit within thumbnail while preserving aspect ratio */
                        int thumb_inner_w = TAB_ITEM_W - 4;
                        int thumb_inner_h = TAB_ITEM_H - 4;
                        int scale_w = thumb_inner_w;
                        int scale_h = src_h * thumb_inner_w / src_w;
                        if (scale_h > thumb_inner_h) {
                            scale_h = thumb_inner_h;
                            scale_w = src_w * thumb_inner_h / src_h;
                        }
                        int ox = ix + (TAB_ITEM_W - scale_w) / 2;
                        int oy = iy + (TAB_ITEM_H - scale_h) / 2;
                        fut_rect_t prev_rect = { ox, oy, scale_w, scale_h };
                        fut_rect_t prev_clip;
                        if (rect_intersection(thumb_clip, prev_rect, &prev_clip)) {
                            for (int32_t py = prev_clip.y; py < prev_clip.y + prev_clip.h; py++) {
                                uint32_t *prow = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                                int sy = (py - oy) * src_h / scale_h;
                                if (sy < 0 || sy >= src_h) continue;
                                const uint32_t *src_row = (const uint32_t *)((const char *)ws2->backing + (size_t)sy * ws2->stride);
                                for (int32_t ppx = prev_clip.x; ppx < prev_clip.x + prev_clip.w; ppx++) {
                                    int sx = (ppx - ox) * src_w / scale_w;
                                    if (sx < 0 || sx >= src_w) continue;
                                    prow[ppx] = src_row[sx] | 0xFF000000u;
                                }
                            }
                        }
                    }
                }

                /* Window title below thumbnail */
                {
                    const char *ttl = ws2->title[0] ? ws2->title
                                    : (ws2->app_id[0] ? ws2->app_id : "Window");
                    int max_c = (TAB_ITEM_W - 4) / UI_FONT_WIDTH;
                    if (max_c > 18) max_c = 18;
                    char tbuf[20];
                    int ti = 0;
                    int slen = 0;
                    while (ttl[slen]) slen++;
                    bool ellip = slen > max_c && max_c >= 3;
                    int clen = ellip ? max_c - 2 : (slen < max_c ? slen : max_c);
                    while (ti < clen) { tbuf[ti] = ttl[ti]; ti++; }
                    if (ellip) { tbuf[ti++] = '.'; tbuf[ti++] = '.'; }
                    tbuf[ti] = '\0';
                    int tw = ti * UI_FONT_WIDTH;
                    int ttx = ix + (TAB_ITEM_W - tw) / 2;
                    int tty = iy + TAB_ITEM_H + 4;
                    uint32_t tcol = selected ? 0xFFFFFFFFu : 0xFFA0A0B0u;
                    ui_draw_text(dst->px, dst->pitch, ttx, tty, tcol, tbuf,
                                 tc.x, tc.y, tc.w, tc.h);
                }

                item_idx++;
            }
        }

        #undef TAB_ITEM_W
        #undef TAB_ITEM_H
        #undef TAB_ITEM_PAD
        #undef TAB_PAD
        #undef TAB_TITLE_H
        #undef TAB_BG
        #undef TAB_SEL
        #undef TAB_BORDER
        #undef TAB_CORNER
        #undef TAB_THUMB_BG
    }

    /* About Futura dialog overlay */
    if (comp->about_active) {
        #define ABOUT_W    320
        #define ABOUT_H    330
        #define ABOUT_R    12
        #define ABOUT_BG   0xF0181828u
        #define ABOUT_BORDER 0x70667799u
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        int32_t ax = (fb_w - ABOUT_W) / 2;
        int32_t ay = (fb_h - ABOUT_H) / 2;
        fut_rect_t about_rect = { ax, ay, ABOUT_W, ABOUT_H };

        /* Dim the background */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t fc;
            fut_rect_t full = { 0, 0, fb_w, fb_h };
            if (!rect_intersection(damage->rects[i], full, &fc)) continue;
            char *dbase = (char *)dst->px;
            for (int32_t py = fc.y; py < fc.y + fc.h; py++) {
                uint32_t *row = (uint32_t *)(dbase + (size_t)py * dst->pitch);
                for (int32_t px = fc.x; px < fc.x + fc.w; px++) {
                    uint32_t d = row[px];
                    uint32_t r = ((d >> 16) & 0xFF) * 160 / 255;
                    uint32_t g = ((d >> 8) & 0xFF) * 160 / 255;
                    uint32_t b = (d & 0xFF) * 160 / 255;
                    row[px] = 0xFF000000u | (r << 16) | (g << 8) | b;
                }
            }
        }

        /* Draw dialog box */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t ac;
            if (!rect_intersection(damage->rects[i], about_rect, &ac)) continue;
            char *abase = (char *)dst->px;
            for (int32_t py = ac.y; py < ac.y + ac.h; py++) {
                uint32_t *arow = (uint32_t *)(abase + (size_t)py * dst->pitch);
                int32_t ry = py - ay;
                int32_t dy = ry < ABOUT_H / 2 ? ry : (ABOUT_H - 1 - ry);
                for (int32_t px = ac.x; px < ac.x + ac.w; px++) {
                    int32_t rx = px - ax;
                    int32_t dx = rx < ABOUT_W / 2 ? rx : (ABOUT_W - 1 - rx);
                    if (dx < ABOUT_R && dy < ABOUT_R) {
                        int32_t cx = ABOUT_R - dx;
                        int32_t cy = ABOUT_R - dy;
                        if (cx * cx + cy * cy > ABOUT_R * ABOUT_R) continue;
                    }
                    uint32_t sa = (ABOUT_BG >> 24) & 0xFF;
                    uint32_t da = 255u - sa;
                    uint32_t sr = (ABOUT_BG >> 16) & 0xFF;
                    uint32_t sg = (ABOUT_BG >> 8) & 0xFF;
                    uint32_t sb = ABOUT_BG & 0xFF;
                    uint32_t d = arow[px];
                    uint32_t or_ = (sr * sa + ((d >> 16) & 0xFF) * da) / 255u;
                    uint32_t og = (sg * sa + ((d >> 8) & 0xFF) * da) / 255u;
                    uint32_t ob = (sb * sa + (d & 0xFF) * da) / 255u;
                    arow[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }

            /* Border */
            int32_t bedges[4][4] = {
                { ax, ay, ABOUT_W, 1 },
                { ax, ay + ABOUT_H - 1, ABOUT_W, 1 },
                { ax, ay, 1, ABOUT_H },
                { ax + ABOUT_W - 1, ay, 1, ABOUT_H },
            };
            for (int e = 0; e < 4; e++) {
                fut_rect_t edge = { bedges[e][0], bedges[e][1], bedges[e][2], bedges[e][3] };
                fut_rect_t ec;
                if (!rect_intersection(ac, edge, &ec)) continue;
                uint32_t bsa = (ABOUT_BORDER >> 24) & 0xFF;
                uint32_t bda = 255u - bsa;
                for (int32_t py2 = ec.y; py2 < ec.y + ec.h; py2++) {
                    uint32_t *brow = (uint32_t *)(abase + (size_t)py2 * dst->pitch);
                    for (int32_t px2 = ec.x; px2 < ec.x + ec.w; px2++) {
                        uint32_t d = brow[px2];
                        uint32_t or_ = ((ABOUT_BORDER >> 16) & 0xFF) * bsa / 255u +
                                        ((d >> 16) & 0xFF) * bda / 255u;
                        uint32_t og = ((ABOUT_BORDER >> 8) & 0xFF) * bsa / 255u +
                                       ((d >> 8) & 0xFF) * bda / 255u;
                        uint32_t ob = (ABOUT_BORDER & 0xFF) * bsa / 255u +
                                       (d & 0xFF) * bda / 255u;
                        brow[px2] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                    }
                }
            }

            /* Futura logo: geometric diamond/star shape (24x24 px) */
            {
                int logo_cx = ax + ABOUT_W / 2;
                int logo_cy = ay + 28;
                int logo_r = 12;
                char *lbase = (char *)dst->px;
                for (int ly = -logo_r; ly <= logo_r; ly++) {
                    int gy = logo_cy + ly;
                    if (gy < ac.y || gy >= ac.y + ac.h) continue;
                    uint32_t *lrow = (uint32_t *)(lbase + (size_t)gy * dst->pitch);
                    int aly = ly < 0 ? -ly : ly;
                    for (int lx = -logo_r; lx <= logo_r; lx++) {
                        int gx = logo_cx + lx;
                        if (gx < ac.x || gx >= ac.x + ac.w) continue;
                        int alx = lx < 0 ? -lx : lx;
                        /* Diamond shape: |x| + |y| <= r */
                        int manhattan = alx + aly;
                        if (manhattan > logo_r) continue;
                        /* Gradient from bright center to blue edge */
                        int frac = manhattan * 255 / logo_r;
                        uint32_t lr = 0x99 + (0x44 - 0x99) * frac / 255;
                        if (lr > 255) lr = 0;
                        uint32_t lg = 0xBB + (0x66 - 0xBB) * frac / 255;
                        if (lg > 255) lg = 0;
                        uint32_t lb = 0xFF + (0xBB - 0xFF) * frac / 255;
                        if (lb > 255) lb = 0xFF;
                        /* Anti-aliased edge: soften outermost 2px */
                        uint32_t la = 0xFF;
                        if (manhattan >= logo_r - 1) {
                            la = (uint32_t)((logo_r - manhattan + 1) * 200);
                            if (la > 0xFF) la = 0xFF;
                        }
                        uint32_t lc = (la << 24) | (lr << 16) | (lg << 8) | lb;
                        ABLEND(lc, lrow[gx]);
                    }
                }
                /* Inner "F" letter cutout (dark) — 6x10 centered */
                /* F shape: top bar, middle bar, left stem */
                static const uint8_t f_bits[10] = {
                    0x7C, /* .#####. */
                    0x7C, /* .#####. */
                    0x60, /* .##.... */
                    0x60, /* .##.... */
                    0x78, /* .####.. */
                    0x78, /* .####.. */
                    0x60, /* .##.... */
                    0x60, /* .##.... */
                    0x60, /* .##.... */
                    0x60, /* .##.... */
                };
                int fx0 = logo_cx - 3;
                int fy0 = logo_cy - 5;
                for (int fy = 0; fy < 10; fy++) {
                    int gy = fy0 + fy;
                    if (gy < ac.y || gy >= ac.y + ac.h) continue;
                    uint32_t *frow = (uint32_t *)(lbase + (size_t)gy * dst->pitch);
                    uint8_t bits = f_bits[fy];
                    for (int fx = 0; fx < 7; fx++) {
                        if (!(bits & (0x80u >> fx))) continue;
                        int gx = fx0 + fx;
                        if (gx < ac.x || gx >= ac.x + ac.w) continue;
                        ABLEND(0xC0101020u, frow[gx]);
                    }
                }
            }

            /* Title — centered large text below logo */
            ui_draw_text_scaled(dst->px, dst->pitch,
                         ax + (ABOUT_W - 9 * UI_FONT_WIDTH * 2) / 2, ay + 46,
                         0xFF7799DDu, "Futura OS", 2,
                         ac.x, ac.y, ac.w, ac.h);

            /* Tagline */
            {
                const char *tag = "The Future of Computing";
                int tag_len = 23;
                int tag_x = ax + (ABOUT_W - tag_len * UI_FONT_WIDTH) / 2;
                ui_draw_text(dst->px, dst->pitch, tag_x, ay + 82,
                             0xFF8090A8u, tag,
                             ac.x, ac.y, ac.w, ac.h);
            }

            /* Separator */
            {
                fut_rect_t sep = { ax + 20, ay + 100, ABOUT_W - 40, 1 };
                fut_rect_t sc;
                if (rect_intersection(ac, sep, &sc)) {
                    for (int32_t spy = sc.y; spy < sc.y + sc.h; spy++) {
                        uint32_t *srow = (uint32_t *)(abase + (size_t)spy * dst->pitch);
                        for (int32_t spx = sc.x; spx < sc.x + sc.w; spx++)
                            srow[spx] = 0xFF333344u;
                    }
                }
            }

            /* Info lines */
            ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 114,
                         0xFFA0A0B0u, "Version       0.9.0",
                         ac.x, ac.y, ac.w, ac.h);
            ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 134,
                         0xFFA0A0B0u, "Desktop       Horizon",
                         ac.x, ac.y, ac.w, ac.h);
            ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 154,
                         0xFFA0A0B0u, "Display       Wayland",
                         ac.x, ac.y, ac.w, ac.h);
            ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 174,
                         0xFFA0A0B0u, "Kernel        Futura",
                         ac.x, ac.y, ac.w, ac.h);
            ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 194,
                         0xFFA0A0B0u, "Architecture  x86_64",
                         ac.x, ac.y, ac.w, ac.h);

            /* Resolution line — dynamic */
            {
                char res_buf[40];
                int ri = 0;
                /* "Resolution    WxH" */
                const char *prefix = "Resolution    ";
                while (*prefix) res_buf[ri++] = *prefix++;
                int fw = (int)comp->fb_info.width;
                int fh = (int)comp->fb_info.height;
                /* width digits */
                if (fw >= 1000) res_buf[ri++] = '0' + (char)(fw / 1000 % 10);
                if (fw >= 100) res_buf[ri++] = '0' + (char)(fw / 100 % 10);
                if (fw >= 10) res_buf[ri++] = '0' + (char)(fw / 10 % 10);
                res_buf[ri++] = '0' + (char)(fw % 10);
                res_buf[ri++] = 'x';
                if (fh >= 1000) res_buf[ri++] = '0' + (char)(fh / 1000 % 10);
                if (fh >= 100) res_buf[ri++] = '0' + (char)(fh / 100 % 10);
                if (fh >= 10) res_buf[ri++] = '0' + (char)(fh / 10 % 10);
                res_buf[ri++] = '0' + (char)(fh % 10);
                res_buf[ri] = '\0';
                ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 214,
                             0xFFA0A0B0u, res_buf,
                             ac.x, ac.y, ac.w, ac.h);
            }

            /* Uptime line — dynamic */
            {
                struct { long tv_sec; long tv_nsec; } up_ts = {0, 0};
                extern long sys_call2(long nr, long a, long b);
                sys_call2(98, 1, (long)&up_ts);  /* CLOCK_MONOTONIC */
                long up_secs = up_ts.tv_sec;
                int up_h = (int)(up_secs / 3600);
                int up_m = (int)((up_secs % 3600) / 60);
                int up_s = (int)(up_secs % 60);
                char up_buf[40];
                int ui = 0;
                const char *up_pfx = "Uptime        ";
                while (*up_pfx) up_buf[ui++] = *up_pfx++;
                if (up_h > 0) {
                    if (up_h >= 10) up_buf[ui++] = '0' + (char)(up_h / 10);
                    up_buf[ui++] = '0' + (char)(up_h % 10);
                    up_buf[ui++] = 'h'; up_buf[ui++] = ' ';
                }
                if (up_m >= 10) up_buf[ui++] = '0' + (char)(up_m / 10);
                else up_buf[ui++] = '0';
                up_buf[ui++] = '0' + (char)(up_m % 10);
                up_buf[ui++] = 'm'; up_buf[ui++] = ' ';
                if (up_s >= 10) up_buf[ui++] = '0' + (char)(up_s / 10);
                else up_buf[ui++] = '0';
                up_buf[ui++] = '0' + (char)(up_s % 10);
                up_buf[ui++] = 's';
                up_buf[ui] = '\0';
                ui_draw_text(dst->px, dst->pitch, ax + 24, ay + 234,
                             0xFFA0A0B0u, up_buf,
                             ac.x, ac.y, ac.w, ac.h);
            }

            /* Second separator */
            {
                fut_rect_t sep2 = { ax + 20, ay + 258, ABOUT_W - 40, 1 };
                fut_rect_t sc2;
                if (rect_intersection(ac, sep2, &sc2)) {
                    for (int32_t spy = sc2.y; spy < sc2.y + sc2.h; spy++) {
                        uint32_t *srow = (uint32_t *)(abase + (size_t)spy * dst->pitch);
                        for (int32_t spx = sc2.x; spx < sc2.x + sc2.w; spx++)
                            srow[spx] = 0xFF333344u;
                    }
                }
            }

            /* Copyright */
            {
                const char *cr = "Copyright 2025-2026";
                int cr_len = 19;
                int cr_x = ax + (ABOUT_W - cr_len * UI_FONT_WIDTH) / 2;
                ui_draw_text(dst->px, dst->pitch, cr_x, ay + 270,
                             0xFF707088u, cr,
                             ac.x, ac.y, ac.w, ac.h);
            }

            /* Dismiss hint */
            {
                const char *hint = "Click anywhere to close";
                int hint_len = 23;
                int hint_x = ax + (ABOUT_W - hint_len * UI_FONT_WIDTH) / 2;
                ui_draw_text(dst->px, dst->pitch, hint_x, ay + ABOUT_H - 24,
                             0xFF505068u, hint,
                             ac.x, ac.y, ac.w, ac.h);
            }
        }
        #undef ABOUT_W
        #undef ABOUT_H
        #undef ABOUT_R
        #undef ABOUT_BG
        #undef ABOUT_BORDER
    }

    /* Toast notification (top-right, auto-dismiss) */
    if (comp->toast_active) {
        /* Check expiry */
        struct { long tv_sec; long tv_nsec; } toast_ts = {0, 0};
        extern long sys_call2(long nr, long a, long b);
        sys_call2(98, 0, (long)&toast_ts);
        uint64_t now_ns = (uint64_t)toast_ts.tv_sec * 1000000000ULL +
                          (uint64_t)toast_ts.tv_nsec;
        if (now_ns >= comp->toast_expire_ns) {
            comp->toast_active = false;
            comp_damage_add_full(comp);
            comp->needs_repaint = true;
        } else {
            int32_t fb_w = (int32_t)comp->fb_info.width;
            int tl = 0;
            while (comp->toast_text[tl] && tl < 127) tl++;
            int tw = tl * UI_FONT_WIDTH + 24;
            int th = UI_FONT_HEIGHT + 16;
            int tx = fb_w - tw - 12;
            int ty = 24 + 8;  /* below menubar */
            #define TOAST_R 6
            #define TOAST_BG 0xE0202030u
            fut_rect_t toast_rect = { tx, ty, tw, th };
            for (int i = 0; i < damage->count; ++i) {
                fut_rect_t tc;
                if (!rect_intersection(damage->rects[i], toast_rect, &tc)) continue;
                char *tbase = (char *)dst->px;
                for (int32_t py = tc.y; py < tc.y + tc.h; py++) {
                    uint32_t *row = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                    int32_t ry = py - ty;
                    int32_t dy_e = ry < th / 2 ? ry : (th - 1 - ry);
                    for (int32_t px = tc.x; px < tc.x + tc.w; px++) {
                        int32_t rx = px - tx;
                        int32_t dx_e = rx < tw / 2 ? rx : (tw - 1 - rx);
                        if (dx_e < TOAST_R && dy_e < TOAST_R) {
                            int32_t cxd = TOAST_R - dx_e, cyd = TOAST_R - dy_e;
                            if (cxd * cxd + cyd * cyd > TOAST_R * TOAST_R) continue;
                        }
                        uint32_t sa = (TOAST_BG >> 24) & 0xFF;
                        uint32_t da = 255u - sa;
                        uint32_t d = row[px];
                        uint32_t or_ = (((TOAST_BG>>16)&0xFF)*sa+((d>>16)&0xFF)*da)/255u;
                        uint32_t og = (((TOAST_BG>>8)&0xFF)*sa+((d>>8)&0xFF)*da)/255u;
                        uint32_t ob = ((TOAST_BG&0xFF)*sa+(d&0xFF)*da)/255u;
                        row[px] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                    }
                }
                /* Border */
                uint32_t bc = 0x50667799u;
                int32_t be[4][4] = {
                    { tx, ty, tw, 1 }, { tx, ty+th-1, tw, 1 },
                    { tx, ty, 1, th }, { tx+tw-1, ty, 1, th },
                };
                for (int e = 0; e < 4; e++) {
                    fut_rect_t er = { be[e][0], be[e][1], be[e][2], be[e][3] };
                    fut_rect_t ec;
                    if (!rect_intersection(tc, er, &ec)) continue;
                    for (int32_t py = ec.y; py < ec.y+ec.h; py++) {
                        uint32_t *row = (uint32_t *)(tbase + (size_t)py * dst->pitch);
                        for (int32_t px = ec.x; px < ec.x+ec.w; px++) {
                            uint32_t sa = (bc >> 24) & 0xFF;
                            uint32_t da = 255u - sa;
                            uint32_t d = row[px];
                            row[px] = 0xFF000000u |
                                ((((bc>>16)&0xFF)*sa+((d>>16)&0xFF)*da)/255u << 16) |
                                ((((bc>>8)&0xFF)*sa+((d>>8)&0xFF)*da)/255u << 8) |
                                (((bc&0xFF)*sa+(d&0xFF)*da)/255u);
                        }
                    }
                }
                /* Toast text */
                ui_draw_text(dst->px, dst->pitch, tx + 12, ty + 8,
                             0xFFE0E0E8u, comp->toast_text,
                             tc.x, tc.y, tc.w, tc.h);
            }
            #undef TOAST_R
            #undef TOAST_BG
        }
    }

    /* Subtle cursor spotlight glow (reduced radius for performance) */
    {
        int32_t mx = comp->pointer_x;
        int32_t my = comp->pointer_y;
        int glow_r = 12;
        int32_t gx0 = mx - glow_r, gy0 = my - glow_r;
        int32_t gx1 = mx + glow_r, gy1 = my + glow_r;
        int32_t fw = (int32_t)comp->fb_info.width;
        int32_t fh = (int32_t)comp->fb_info.height;
        if (gx0 < 0) gx0 = 0;
        if (gy0 < 0) gy0 = 0;
        if (gx1 > fw) gx1 = fw;
        if (gy1 > fh) gy1 = fh;
        char *gbase = (char *)dst->px;
        for (int32_t gy = gy0; gy < gy1; gy++) {
            uint32_t *grow = (uint32_t *)(gbase + (size_t)gy * dst->pitch);
            int dy = gy - my;
            for (int32_t gx = gx0; gx < gx1; gx++) {
                int dx = gx - mx;
                int d2 = dx * dx + dy * dy;
                int r2 = glow_r * glow_r;
                if (d2 >= r2) continue;
                int a = 14 * (r2 - d2) / r2;
                if (a < 1) continue;
                uint32_t overlay = ((uint32_t)a << 24) | 0x00C0D0FFu;
                ABLEND(overlay, grow[gx]);
            }
        }
    }

    if (comp->cursor) {
        struct fut_fb_info info = comp->fb_info;
        info.pitch = (uint32_t)dst->pitch;
        cursor_draw(comp->cursor, (uint8_t *)dst->px, &info);
    }

    if (comp->backbuffer_enabled) {
        comp->bb_index = render_index;
    }

    /* Always present rendered content to framebuffer, whether backbuffer is enabled or not */
    present_damage(comp, damage);

    /* Flush framebuffer to display (required for virtio-GPU) */
    if (comp->fb_fd >= 0) {
        sys_ioctl(comp->fb_fd, FBIOFLUSH, 0);
    }

    int frame_cb_count = comp_flush_frame_callbacks(comp, comp_now_msec());

#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] present bb=%d regions=%d frame_cbs=%d\n",
         comp->bb_index, region_count, frame_cb_count);
#else
    (void)frame_cb_count;
#endif

    #undef ABLEND

    comp->frame_damage.count = 0;
    comp->needs_repaint = false;
    comp->last_present_ns = comp_now_ns();
}

/* Demo rendering: shows a test pattern when socket creation fails */
void comp_render_demo_frame(struct compositor_state *comp) {
    if (!comp || !comp->fb_map) {
        printf("[DEMO] fb_map is NULL, skipping demo render\n");
        return;
    }

    int w = comp->fb_info.width;
    int h = comp->fb_info.height;

    printf("[DEMO] Rendering demo frame: %dx%d pitch=%u\n", w, h, comp->fb_info.pitch);
    printf("[DEMO] Framebuffer: %p (bpp=%u)\n", (void*)comp->fb_map, comp->fb_info.bpp);

    if (w <= 0 || h <= 0) {
        printf("[DEMO] ERROR: Invalid framebuffer dimensions: %dx%d\n", w, h);
        return;
    }

    /* Always render directly to framebuffer for demo mode (simpler, more reliable) */
    uint8_t *fb = comp->fb_map;
    uint32_t pitch = comp->fb_info.pitch;

    if (pitch == 0) {
        printf("[DEMO] ERROR: Invalid pitch: %u\n", pitch);
        return;
    }

    /* First, render a simple horizontal stripe pattern to verify rendering works */
    printf("[DEMO] Rendering horizontal stripe test pattern (alternating red/blue every 50 pixels)\n");
    for (int y = 0; y < h; ++y) {
        uint32_t *row = (uint32_t *)(fb + y * pitch);
        uint32_t color = (y / 50) % 2 ? 0xFFFF0000 : 0xFF0000FF;  /* Alternate red/blue */
        for (int x = 0; x < w; ++x) {
            row[x] = color;
        }
    }

    /* Sample a few pixels to verify they were written */
    printf("[DEMO] Stripe pattern pixel verification:\n");
    uint32_t *p0 = (uint32_t *)(fb + 25 * pitch + 0);
    uint32_t *p50 = (uint32_t *)(fb + 75 * pitch + 0);
    uint32_t *p100 = (uint32_t *)(fb + 125 * pitch + 0);
    printf("[DEMO] Pixel at y=25: %08x (expect FF0000 red)\n", *p0);
    printf("[DEMO] Pixel at y=75: %08x (expect 0000FF blue)\n", *p50);
    printf("[DEMO] Pixel at y=125: %08x (expect FF0000 red)\n", *p100);

    /* Test pattern: vertical stripes (alternating every 100 pixels wide) */
    printf("[DEMO] Rendering vertical stripe test pattern (alternating red/green every 100 pixels)\n");
    for (int y = 0; y < h; ++y) {
        uint32_t *row = (uint32_t *)(fb + y * pitch);
        for (int x = 0; x < w; ++x) {
            uint32_t color = (x / 100) % 2 ? 0xFFFF0000 : 0xFF00FF00;  /* Alternate red/green */
            row[x] = color;
        }
    }

    /* Sample vertical stripe pixels */
    printf("[DEMO] Vertical stripe pattern pixel verification:\n");
    uint32_t *pv_left = (uint32_t *)(fb + 0 * pitch + 50 * 4);
    uint32_t *pv_mid = (uint32_t *)(fb + 0 * pitch + 150 * 4);
    uint32_t *pv_right = (uint32_t *)(fb + 0 * pitch + 250 * 4);
    printf("[DEMO] Pixel at x=50: %08x (expect 00FF00 green)\n", *pv_left);
    printf("[DEMO] Pixel at x=150: %08x (expect FF0000 red)\n", *pv_mid);
    printf("[DEMO] Pixel at x=250: %08x (expect 00FF00 green)\n", *pv_right);

    /* Test pattern: 4 quadrants with different colors */
    printf("[DEMO] Drawing 4-quadrant test pattern\n");

    int qw = w / 2;
    int qh = h / 2;

    printf("[DEMO] Quadrant dimensions: qw=%d, qh=%d\n", qw, qh);

    /* Top-left: Red */
    printf("[DEMO] Top-left quadrant: Red (0xFFFF0000)\n");
    uint32_t red_samples = 0;
    for (int y = 0; y < qh; ++y) {
        uint32_t *row = (uint32_t *)(fb + y * pitch);
        for (int x = 0; x < qw; ++x) {
            row[x] = 0xFFFF0000;  /* Red */
            if ((y == qh/4 && x == qw/4) || (y == 0 && x == 0)) {
                red_samples++;
                printf("[DEMO] RED pixel at (%d,%d) = 0x%08x (addr=%p)\n", x, y, row[x], (void*)&row[x]);
            }
        }
    }

    /* Top-right: Green */
    printf("[DEMO] Top-right quadrant: Green (0xFF00FF00)\n");
    uint32_t green_samples = 0;
    for (int y = 0; y < qh; ++y) {
        uint32_t *row = (uint32_t *)(fb + y * pitch);
        for (int x = qw; x < w; ++x) {
            row[x] = 0xFF00FF00;  /* Green */
            if ((y == qh/4 && x == qw + qw/4) || (y == 0 && x == qw)) {
                green_samples++;
                printf("[DEMO] GREEN pixel at (%d,%d) = 0x%08x (addr=%p)\n", x, y, row[x], (void*)&row[x]);
            }
        }
    }

    /* Bottom-left: Blue */
    printf("[DEMO] Bottom-left quadrant: Blue (0xFF0000FF)\n");
    uint32_t blue_samples = 0;
    for (int y = qh; y < h; ++y) {
        uint32_t *row = (uint32_t *)(fb + y * pitch);
        for (int x = 0; x < qw; ++x) {
            row[x] = 0xFF0000FF;  /* Blue */
            if ((y == qh + qh/4 && x == qw/4) || (y == qh && x == 0)) {
                blue_samples++;
                printf("[DEMO] BLUE pixel at (%d,%d) = 0x%08x (addr=%p)\n", x, y, row[x], (void*)&row[x]);
            }
        }
    }

    /* Bottom-right: Yellow */
    printf("[DEMO] Bottom-right quadrant: Yellow (0xFFFFFF00)\n");
    uint32_t yellow_samples = 0;
    for (int y = qh; y < h; ++y) {
        uint32_t *row = (uint32_t *)(fb + y * pitch);
        for (int x = qw; x < w; ++x) {
            row[x] = 0xFFFFFF00;  /* Yellow (Red + Green) */
            if ((y == qh + qh/4 && x == qw + qw/4) || (y == qh && x == qw)) {
                yellow_samples++;
                printf("[DEMO] YELLOW pixel at (%d,%d) = 0x%08x (addr=%p)\n", x, y, row[x], (void*)&row[x]);
            }
        }
    }

    printf("[DEMO] Test pattern rendering complete\n");
    printf("[DEMO] Samples: RED=%u GREEN=%u BLUE=%u YELLOW=%u\n", red_samples, green_samples, blue_samples, yellow_samples);

    /* Read back and verify a few pixels from each quadrant */
    printf("[DEMO] Readback verification:\n");
    uint32_t *p_red = (uint32_t *)(fb + 10 * pitch + 10 * 4);
    uint32_t *p_green = (uint32_t *)(fb + 10 * pitch + (qw + 10) * 4);
    uint32_t *p_blue = (uint32_t *)(fb + (qh + 10) * pitch + 10 * 4);
    uint32_t *p_yellow = (uint32_t *)(fb + (qh + 10) * pitch + (qw + 10) * 4);
    printf("[DEMO] Readback RED: %08x (expect FF0000)\n", *p_red);
    printf("[DEMO] Readback GREEN: %08x (expect 00FF00)\n", *p_green);
    printf("[DEMO] Readback BLUE: %08x (expect 0000FF)\n", *p_blue);
    printf("[DEMO] Readback YELLOW: %08x (expect FFFF00)\n", *p_yellow);

    /* Flush framebuffer to display (required for virtio-GPU) */
    if (comp->fb_fd >= 0) {
        sys_ioctl(comp->fb_fd, FBIOFLUSH, 0);
        printf("[DEMO] FBIOFLUSH called\n");
    }
}

static void ms_to_timespec(uint64_t ms, struct timespec *ts) {
    if (!ts) {
        return;
    }
    ts->tv_sec = (time_t)(ms / 1000ULL);
    ts->tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);
}

static int comp_timer_arm(struct compositor_state *comp) {
    if (!comp || comp->timerfd < 0) {
        return -1;
    }
    if (comp->next_tick_ms == 0) {
        comp->next_tick_ms = (uint64_t)comp_now_msec() + comp->target_ms;
    }
    struct itimerspec its = {0};
    ms_to_timespec(comp->next_tick_ms, &its.it_value);
    return timerfd_settime(comp->timerfd, TFD_TIMER_ABSTIME, &its, NULL);
}

static void comp_handle_timer_tick(struct compositor_state *comp, uint64_t expirations) {
    if (!comp) {
        return;
    }
    if (expirations == 0) {
        expirations = 1;
    }

    uint64_t now_ms = comp_now_msec();
    comp->last_timer_tick_ms = now_ms;

    if (comp->next_tick_ms == 0) {
        comp->next_tick_ms = now_ms + comp->target_ms;
    } else {
        uint64_t advance = (uint64_t)comp->target_ms * expirations;
        comp->next_tick_ms += advance;
        if (comp->next_tick_ms <= now_ms) {
            comp->next_tick_ms = now_ms + comp->target_ms;
        }
    }

    if (comp_timer_arm(comp) < 0) {
        /* Timer arm failed — reset next_tick so we recalculate next time */
        comp->next_tick_ms = 0;
    }

    /* Auto-damage the dock area when the clock minute changes so the
     * displayed time stays current even when nothing else triggers a
     * repaint (e.g. the user is idle). */
    {
        struct { long tv_sec; long tv_nsec; } cts = {0, 0};
        extern long sys_call2(long nr, long a, long b);
        sys_call2(98, 0, (long)&cts);  /* SYS_clock_gettime(CLOCK_REALTIME) */
        int cur_sec = (int)(cts.tv_sec % 60);
        int cur_min = (int)((cts.tv_sec % 3600) / 60);
        /* Per-second: damage ONLY menubar and dock clock text areas.
         * The desktop clock (center of screen) is NOT damaged per-second
         * because it overlaps windows and causes visible flashing
         * (wallpaper re-rendered before window re-blit on single-buffer FB). */
        if (cur_sec != (comp->last_clock_min >> 8)) {
            comp->last_clock_min = (comp->last_clock_min & 0xFF) | (cur_sec << 8);
            int32_t fb_h = (int32_t)comp->fb_info.height;
            int32_t fb_w = (int32_t)comp->fb_info.width;

            /* Menubar clock — only the rightmost clock text area */
            int mbar_clock_w = 14 * UI_FONT_WIDTH + 16;
            fut_rect_t mbar_damage = { fb_w - mbar_clock_w - 4, 0,
                                       mbar_clock_w + 4, MENUBAR_HEIGHT };
            comp_damage_add_rect(comp, mbar_damage);

            /* Dock — damage a generous center strip covering the dock.
             * The dock is centered and typically ≤500px wide, but we use
             * a wider band to account for all dock sizes. */
            int dock_dmg_w = fb_w / 2 + 80;  /* generous half-width */
            int dock_dmg_x = (fb_w - dock_dmg_w) / 2;
            fut_rect_t dock_damage = { dock_dmg_x, fb_h - 48, dock_dmg_w, 48 };
            comp_damage_add_rect(comp, dock_damage);
        }
        /* Per-minute: damage desktop clock + shooting star areas,
         * but ONLY if no window covers them. On a single-buffer FB,
         * re-compositing the wallpaper briefly shows through windows
         * (visible flash). Skip damage when a window occludes the area. */
        if (cur_min != (comp->last_clock_min & 0xFF)) {
            comp->last_clock_min = (cur_sec << 8) | cur_min;
            int32_t fb_h = (int32_t)comp->fb_info.height;
            int32_t fb_w = (int32_t)comp->fb_info.width;

            /* Desktop clock widget — only updates per minute now */
            int32_t clock_cy = fb_h * 28 / 100;
            fut_rect_t clock_dmg = { fb_w / 2 - 100, clock_cy - 4, 200, 90 };

            /* Check if any window overlaps the desktop clock area */
            bool clock_occluded = false;
            struct comp_surface *cs;
            wl_list_for_each(cs, &comp->surfaces, link) {
                if (!cs->has_backing || cs->minimized) continue;
                fut_rect_t wr = comp_frame_rect(cs);
                /* Simple overlap test */
                if (wr.x < clock_dmg.x + clock_dmg.w &&
                    wr.x + wr.w > clock_dmg.x &&
                    wr.y < clock_dmg.y + clock_dmg.h &&
                    wr.y + wr.h > clock_dmg.y) {
                    clock_occluded = true;
                    break;
                }
            }
            if (!clock_occluded) {
                comp_damage_add_rect(comp, clock_dmg);
            }

            /* Shooting stars — only if no window covers the top area */
            fut_rect_t meteor_dmg = { 0, 0, fb_w, fb_h / 4 };
            bool meteor_occluded = false;
            wl_list_for_each(cs, &comp->surfaces, link) {
                if (!cs->has_backing || cs->minimized) continue;
                fut_rect_t wr = comp_frame_rect(cs);
                /* If any window covers more than half the meteor strip width,
                 * skip the damage to avoid flashing */
                if (wr.y < fb_h / 4 &&
                    wr.x < fb_w * 3 / 4 &&
                    wr.x + wr.w > fb_w / 4) {
                    meteor_occluded = true;
                    break;
                }
            }
            if (!meteor_occluded) {
                comp_damage_add_rect(comp, meteor_dmg);
            }
        }
    }

    /* Auto-damage the toast area while it's active so the expiry check fires */
    if (comp->toast_active) {
        int32_t fb_w = (int32_t)comp->fb_info.width;
        fut_rect_t toast_d = { fb_w - 300, MENUBAR_HEIGHT, 300, 40 };
        comp_damage_add_rect(comp, toast_d);
    }

    /* Auto-damage the About dialog for live uptime counter */
    if (comp->about_active) {
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        fut_rect_t about_d = { (fb_w - 320) / 2 + 20, (fb_h - 330) / 2 + 230,
                                280, 20 };
        comp_damage_add_rect(comp, about_d);
    }

    if (comp->frame_damage.count > 0) {
        comp_render_frame(comp);
    }
}

static int comp_timerfd_cb(int fd, uint32_t mask, void *data) {
    struct compositor_state *comp = data;
    if (!comp) {
        return 0;
    }

    if (!(mask & WL_EVENT_READABLE)) {
        return 0;
    }

    uint64_t expirations = 0;
    ssize_t rc = read(fd, &expirations, sizeof(expirations));
    if (rc <= 0) {
        return 0;
    }
    comp_handle_timer_tick(comp, expirations);
    return 0;
}

int comp_run(struct compositor_state *comp) {
    if (!comp || !comp->display || !comp->loop) {
        return -1;
    }

    int dispatch_errors = 0;

    /* Welcome toast — delayed until first frame with a surface */
    bool welcome_shown = false;

    while (comp->running) {
        if (!welcome_shown && !wl_list_empty(&comp->surfaces)) {
            comp_show_toast(comp, "Welcome to Horizon Desktop");
            welcome_shown = true;
        }
        /* Poll input FIRST — never let epoll_wait starvation delay mouse/kbd.
         * On a single-CPU kernel, epoll_wait can sometimes overshoot its
         * timeout, freezing the cursor.  Polling before and after epoll
         * ensures responsive input regardless of timer accuracy. */
        if (comp->seat) {
            seat_poll_input(comp->seat);
        }

        wl_display_flush_clients(comp->display);

        /* Dispatch Wayland events with short timeout.  Use 1ms instead of
         * 16ms to keep input responsive — if the kernel's epoll timeout
         * overshoots, we still recover quickly.  The 1ms nanosleep below
         * provides additional pacing to avoid busy-spinning. */
        int rc = wl_event_loop_dispatch(comp->loop, 1);
        if (rc < 0 && errno != EINTR) {
            dispatch_errors++;
            if (dispatch_errors > 1000) {
                printf("[WAYLAND] event loop failed %d times, exiting\n",
                       dispatch_errors);
                break;
            }
        } else {
            dispatch_errors = 0;
        }

        /* Poll input again after epoll dispatch — catch any events that
         * arrived while we were processing Wayland protocol messages. */
        if (comp->seat) {
            seat_poll_input(comp->seat);
        }

        /* Manually handle timer events.
         * The user-space timerfd is not a real kernel fd, so even when
         * wl_event_loop_add_fd succeeds (due to bypassed epoll_ctl),
         * the event loop won't deliver timer events. Always poll manually. */
        bool rendered_this_iter = false;
        if (comp->timerfd >= 0) {
            uint64_t expirations = 0;
            ssize_t read_rc = read(comp->timerfd, &expirations, sizeof(expirations));
            if (read_rc > 0 && expirations > 0) {
                /* Cap to avoid processing hundreds of ticks after a stall */
                if (expirations > 4) {
                    expirations = 4;
                }
                comp_handle_timer_tick(comp, expirations);
                rendered_this_iter = true;
            }
        }

        /* Timer watchdog: if the timerfd hasn't fired in >200ms, the
         * timer is stuck.  Force re-arm and add clock damage so the
         * desktop doesn't freeze.  This catches races where the one-shot
         * timerfd disarms itself but comp_timer_arm fails to re-arm. */
        if (!rendered_this_iter && comp->timerfd >= 0) {
            uint64_t now_check = comp_now_msec();
            uint64_t since_tick = now_check - comp->last_timer_tick_ms;
            if (comp->last_timer_tick_ms > 0 && since_tick > 200) {
                comp->next_tick_ms = 0;
                comp_timer_arm(comp);
                /* Force per-second clock damage so clocks keep ticking */
                int32_t fb_w = (int32_t)comp->fb_info.width;
                int32_t fb_h = (int32_t)comp->fb_info.height;
                fut_rect_t menubar_clock = { fb_w - 160, 0, 160, MENUBAR_HEIGHT };
                comp_damage_add_rect(comp, menubar_clock);
                fut_rect_t dock_clock = { 0, fb_h - 48, fb_w, 48 };
                comp_damage_add_rect(comp, dock_clock);
                comp->last_timer_tick_ms = now_check;
            }
        }

        /* Fallback: if the timer didn't fire but we have pending damage,
         * render anyway to prevent desktop freezes.  Re-arm the timer
         * so it doesn't stay stuck. */
        if (!rendered_this_iter && comp->frame_damage.count > 0) {
            comp_render_frame(comp);
            if (comp->timerfd >= 0) {
                comp->next_tick_ms = 0; /* recalculate from now */
                comp_timer_arm(comp);
            }
        }

        /* Reap zombie child processes (launched terminals) */
        while (sys_wait4_call(-1, NULL, 1 /* WNOHANG */, NULL) > 0) {
            /* reaped one */
        }

        /* Flush events generated by input polling to clients.
         * The top-of-loop flush handles most cases, but this ensures
         * keyboard/mouse events reach clients before the next sleep. */
        wl_display_flush_clients(comp->display);

        /* Yield to client processes.  On a single-CPU system, the
         * compositor can starve clients if epoll_wait returns immediately
         * (e.g. when timer or client events are always pending).  An
         * explicit yield gives wl-term and other clients CPU time to
         * process the events we just flushed.  Follow with a brief sleep
         * to guarantee we actually block and let the scheduler run other
         * tasks; sched_yield alone may return immediately if we are the
         * highest-priority runnable thread. */
        sys_sched_yield();
        {
            struct timespec ys = { .tv_sec = 0, .tv_nsec = 1000000 }; /* 1ms */
            nanosleep(&ys, NULL);
        }
    }

    printf("[WAYLAND] event loop exited (running=%d errors=%d)\n",
           comp->running, dispatch_errors);
    return 0;
}

int comp_scheduler_start(struct compositor_state *comp) {
    if (!comp || !comp->loop) {
        return -1;
    }
    if (comp->timerfd >= 0) {
        return 0;
    }

    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[SCHEDULER-DEBUG] timerfd_create succeeded: fd=%d (nonblocking)\n", fd);
#endif

    comp->timerfd = fd;
    comp->next_tick_ms = (uint64_t)comp_now_msec() + comp->target_ms;
    if (comp_timer_arm(comp) < 0) {
#ifdef DEBUG_WAYLAND
        printf("[SCHEDULER-DEBUG] comp_timer_arm failed\n");
#endif
        struct itimerspec disarm = {0};
        timerfd_settime(fd, 0, &disarm, NULL);
        close(fd);
        comp->timerfd = -1;
        comp->next_tick_ms = 0;
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[SCHEDULER-DEBUG] comp_timer_arm succeeded\n");
#endif

#ifdef DEBUG_WAYLAND
    printf("[SCHEDULER-DEBUG] About to call wl_event_loop_add_fd\n");
#endif
    comp->timer_source = wl_event_loop_add_fd(comp->loop,
                                              comp->timerfd,
                                              WL_EVENT_READABLE,
                                              comp_timerfd_cb,
                                              comp);
#ifdef DEBUG_WAYLAND
    printf("[SCHEDULER-DEBUG] wl_event_loop_add_fd returned: %p (errno=%d)\n", (void *)comp->timer_source, errno);
#endif
    if (!comp->timer_source) {
#ifdef DEBUG_WAYLAND
        printf("[SCHEDULER-DEBUG] Event loop add_fd returned NULL (errno=%d), bypassing event loop\n", errno);
#endif
        /* Similar to input devices: timerfd doesn't support epoll in this environment.
         * Mark as not registered but timer is still valid.
         * We'll handle timer events manually in comp_run().
         */
        comp->timer_source_registered = false;
#ifdef DEBUG_WAYLAND
        printf("[SCHEDULER-DEBUG] Marked timer_source as not registered with event loop\n");
#endif
    } else {
        comp->timer_source_registered = true;
    }
#ifdef DEBUG_WAYLAND
    printf("[SCHEDULER-DEBUG] Scheduler started successfully\n");
#endif
    return 0;
}

void comp_scheduler_stop(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    if (comp->timer_source_registered && comp->timer_source) {
        /* Only call wl_event_source_remove if registered with event loop */
        wl_event_source_remove(comp->timer_source);
        comp->timer_source = NULL;
        comp->timer_source_registered = false;
    }

    if (comp->timerfd >= 0) {
        struct itimerspec disarm = {0};
        timerfd_settime(comp->timerfd, 0, &disarm, NULL);
        close(comp->timerfd);
        comp->timerfd = -1;
    }
    comp->next_tick_ms = 0;
}

bool comp_pointer_inside_surface(const struct compositor_state *comp,
                                 const struct comp_surface *surface,
                                 int32_t px,
                                 int32_t py,
                                 int32_t *out_sx,
                                 int32_t *out_sy) {
    if (!comp || !surface || !surface->has_backing) {
        return false;
    }

    int32_t sx = px - surface->x;
    int32_t sy = py - surface->y - surface->bar_height;
    if (surface->bar_height > 0) {
        if (sy < 0) {
            return false;
        }
    } else {
        sy = py - surface->y;
    }
    if (sx < 0 || sy < 0 ||
        sx >= surface->width || sy >= surface->content_height) {
        return false;
    }
    if (out_sx) {
        *out_sx = sx;
    }
    if (out_sy) {
        *out_sy = sy;
    }
    return true;
}

struct comp_surface *comp_surface_at(struct compositor_state *comp,
                                     int32_t px,
                                     int32_t py,
                                     int32_t *out_sx,
                                     int32_t *out_sy) {
    if (!comp) {
        return NULL;
    }
    struct comp_surface *surface;
    wl_list_for_each_reverse(surface, &comp->surfaces, link) {
        if (!surface->has_backing || surface->minimized) {
            continue;
        }
        int32_t sx = px - surface->x;
        int32_t sy = py - surface->y;
        if (sx < 0 || sy < 0 ||
            sx >= surface->width || sy >= surface->height) {
            continue;
        }
        if (out_sx) {
            *out_sx = sx;
        }
        if (out_sy) {
            *out_sy = sy;
        }
        return surface;
    }
    return NULL;
}

void comp_surface_raise(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || !surface) {
        return;
    }

    if (!surface->in_zlist) {
        comp_surface_link_tail(comp, surface);
    } else if (comp->multi_enabled) {
        wl_list_remove(&surface->link);
        wl_list_insert(comp->surfaces.prev, &surface->link);
    }
    surface->in_zlist = true;
    comp->active_surface = surface;
    comp_surface_update_decorations(surface);
    if (surface->has_backing) {
        fut_rect_t rect = {
            .x = surface->x,
            .y = surface->y,
            .w = surface->width,
            .h = surface->height,
        };
        comp_damage_add_rect(comp, rect);
        comp_surface_mark_damage(surface);
    }
}

static void comp_cursor_damage(struct compositor_state *comp,
                               int32_t x,
                               int32_t y,
                               int32_t w,
                                int32_t h) {
    fut_rect_t rect = {
        .x = x,
        .y = y,
        .w = w,
        .h = h,
    };
    comp_damage_add_rect(comp, rect);
}

void comp_pointer_motion(struct compositor_state *comp, int32_t new_x, int32_t new_y) {
    if (!comp || !comp->cursor) {
        return;
    }

    int32_t cursor_w = cursor_get_width(comp->cursor);
    int32_t cursor_h = cursor_get_height(comp->cursor);
    /* Clamp the pointer hot-spot to the framebuffer's last pixel, not to
     * (fb - cursor_size). cursor_draw already clips per-pixel, so letting
     * the cursor visually overhang the right/bottom edge is fine — and the
     * tighter clamp made it impossible to reach the snap-right zone, the
     * close button on maximized windows, or anything pinned to the right
     * or bottom edge of the screen. */
    int32_t max_x = (int32_t)comp->fb_info.width - 1;
    int32_t max_y = (int32_t)comp->fb_info.height - 1;
    if (max_x < 0) {
        max_x = 0;
    }
    if (max_y < 0) {
        max_y = 0;
    }

    int32_t clamped_x = clamp_i32(new_x, 0, max_x);
    int32_t clamped_y = clamp_i32(new_y, 0, max_y);

    if (clamped_x == comp->pointer_x && clamped_y == comp->pointer_y) {
        if (comp->dragging) {
            comp_update_drag(comp);
        }
        if (comp->resize_surface) {
            comp_update_resize(comp);
        }
        return;
    }

    /* Damage old cursor position + glow radius */
    comp_cursor_damage(comp, comp->pointer_x - 12, comp->pointer_y - 12,
                       cursor_w + 24, cursor_h + 24);

    comp->pointer_x = clamped_x;
    comp->pointer_y = clamped_y;
    cursor_set_position(comp->cursor, comp->pointer_x, comp->pointer_y);

    /* Damage new cursor position + glow radius */
    comp_cursor_damage(comp, comp->pointer_x - 12, comp->pointer_y - 12,
                       cursor_w + 24, cursor_h + 24);
    comp->needs_repaint = true;

    /* Update dock hover state */
    {
        /* Constants must match the dock renderer. They were copies of the
         * old (pre-widening) values, so dock hover/tooltip targeted the
         * wrong items in the same way the click handler did before. */
        #define HOV_DOCK_HEIGHT  38
        #define HOV_DOCK_ITEM_W  148
        #define HOV_DOCK_PAD     4
        #define HOV_DOCK_DSKBTN  28
        #define HOV_CLOCK_W      (22 * 8 + 16)
        int32_t fb_h = (int32_t)comp->fb_info.height;
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t dock_y = fb_h - HOV_DOCK_HEIGHT - 6;
        int old_hover = comp->dock_hover_index;
        int new_hover = -1;
        int tooltip_cx = 0;  /* center x for tooltip */

        if (comp->pointer_y >= dock_y && comp->pointer_y < fb_h) {
            int n_win = 0;
            struct comp_surface *ds;
            wl_list_for_each(ds, &comp->surfaces, link)
                if (ds->has_backing) n_win++;

            int items_w = n_win > 0
                ? n_win * HOV_DOCK_ITEM_W + (n_win - 1) * HOV_DOCK_PAD
                : 0;
            int dock_content_w = 8 + items_w + 8 + HOV_CLOCK_W + 4 + HOV_DOCK_DSKBTN + 4;
            if (dock_content_w < 240) dock_content_w = 240;
            int dock_x = (fb_w - dock_content_w) / 2;

            /* Check desktop button at far right */
            int dskbtn_x = dock_x + dock_content_w - HOV_DOCK_DSKBTN - 2;
            if (comp->pointer_x >= dskbtn_x &&
                comp->pointer_x < dskbtn_x + HOV_DOCK_DSKBTN) {
                new_hover = -2;
            } else {
                /* Check window items */
                int item_x = dock_x + 8;
                int idx = 0;
                wl_list_for_each(ds, &comp->surfaces, link) {
                    if (!ds->has_backing) continue;
                    if (comp->pointer_x >= item_x &&
                        comp->pointer_x < item_x + HOV_DOCK_ITEM_W) {
                        new_hover = idx;
                        tooltip_cx = item_x + HOV_DOCK_ITEM_W / 2;
                        break;
                    }
                    item_x += HOV_DOCK_ITEM_W + HOV_DOCK_PAD;
                    idx++;
                }
            }
        }
        #undef HOV_DOCK_HEIGHT
        #undef HOV_DOCK_ITEM_W
        #undef HOV_DOCK_PAD
        #undef HOV_DOCK_DSKBTN
        #undef HOV_CLOCK_W

        if (new_hover != old_hover) {
            comp->dock_hover_index = new_hover;
            /* Damage dock area for hover highlight update */
            /* Damage includes tooltip preview area above dock */
            int tip_damage_h = 140;  /* tooltip with thumbnail */
            fut_rect_t dock_damage = { 0, dock_y - tip_damage_h, fb_w, fb_h - dock_y + tip_damage_h };
            comp_damage_add_rect(comp, dock_damage);

            /* Update tooltip state */
            if (new_hover >= 0) {
                comp->dock_tooltip_index = new_hover;
                comp->dock_tooltip_x = tooltip_cx;
                comp->dock_tooltip_y = dock_y;
            } else {
                comp->dock_tooltip_index = -1;
            }
        }
    }

    /* Update context menu hover state */
    if (comp->ctx_menu_active) {
        #define CTX_MENU_W       240
        #define CTX_MENU_ITEM_H  28
        #define CTX_MENU_ITEMS   6
        #define CTX_MENU_PAD     4
        #define CTX_MENU_SEP1    1   /* separator after item 1 */
        #define CTX_MENU_SEP2    3   /* separator after item 3 */
        #define CTX_MENU_SEP_H   9
        int32_t menu_h = CTX_MENU_PAD + CTX_MENU_ITEMS * CTX_MENU_ITEM_H +
                          2 * CTX_MENU_SEP_H + CTX_MENU_PAD;
        int32_t mx = comp->pointer_x - comp->ctx_menu_x;
        int32_t my = comp->pointer_y - comp->ctx_menu_y;
        int old_hover = comp->ctx_menu_hover;
        int new_hover = -1;
        if (mx >= 0 && mx < CTX_MENU_W && my >= CTX_MENU_PAD) {
            int ly = my - CTX_MENU_PAD;
            /* Group 1: items 0..1 */
            int g1_h = (CTX_MENU_SEP1 + 1) * CTX_MENU_ITEM_H;
            int g2_start = g1_h + CTX_MENU_SEP_H;
            int g2_count = CTX_MENU_SEP2 - CTX_MENU_SEP1;
            int g2_h = g2_count * CTX_MENU_ITEM_H;
            int g3_start = g2_start + g2_h + CTX_MENU_SEP_H;
            int g3_count = CTX_MENU_ITEMS - CTX_MENU_SEP2 - 1;
            int g3_h = g3_count * CTX_MENU_ITEM_H;
            if (ly < g1_h) {
                new_hover = ly / CTX_MENU_ITEM_H;
            } else if (ly >= g2_start && ly < g2_start + g2_h) {
                new_hover = CTX_MENU_SEP1 + 1 + (ly - g2_start) / CTX_MENU_ITEM_H;
            } else if (ly >= g3_start && ly < g3_start + g3_h) {
                new_hover = CTX_MENU_SEP2 + 1 + (ly - g3_start) / CTX_MENU_ITEM_H;
            }
            (void)g3_h;
            if (new_hover >= CTX_MENU_ITEMS) new_hover = -1;
        }
        if (new_hover != old_hover) {
            comp->ctx_menu_hover = new_hover;
            fut_rect_t md = { comp->ctx_menu_x, comp->ctx_menu_y,
                              CTX_MENU_W, menu_h };
            comp_damage_add_rect(comp, md);
        }
        #undef CTX_MENU_W
        #undef CTX_MENU_ITEM_H
        #undef CTX_MENU_ITEMS
        #undef CTX_MENU_PAD
        #undef CTX_MENU_SEP1
        #undef CTX_MENU_SEP2
        #undef CTX_MENU_SEP_H
    }

    /* Update Futura menu hover state */
    if (comp->futura_menu_active) {
        #define FM_MENU_W       220
        #define FM_MENU_ITEM_H  26
        #define FM_MENU_ITEMS   8
        #define FM_MENU_PAD     4
        #define FM_MENU_SEP_AFTER 2
        #define FM_MENU_SEP_H   7
        int32_t fm_h = FM_MENU_PAD + FM_MENU_ITEMS * FM_MENU_ITEM_H +
                        FM_MENU_SEP_H + FM_MENU_PAD;
        int32_t mx = comp->pointer_x - 4;
        int32_t my = comp->pointer_y - MENUBAR_HEIGHT;
        int old_h = comp->futura_menu_hover;
        int new_h = -1;
        if (mx >= 0 && mx < FM_MENU_W && my >= FM_MENU_PAD && my < fm_h) {
            int ly = my - FM_MENU_PAD;
            int before = (FM_MENU_SEP_AFTER + 1) * FM_MENU_ITEM_H;
            if (ly < before) {
                new_h = ly / FM_MENU_ITEM_H;
            } else if (ly >= before + FM_MENU_SEP_H) {
                new_h = FM_MENU_SEP_AFTER + 1 + (ly - before - FM_MENU_SEP_H) / FM_MENU_ITEM_H;
            }
            if (new_h >= FM_MENU_ITEMS) new_h = -1;
        }
        if (new_h != old_h) {
            comp->futura_menu_hover = new_h;
            fut_rect_t fd = { 4, MENUBAR_HEIGHT, FM_MENU_W, fm_h };
            comp_damage_add_rect(comp, fd);
        }
        #undef FM_MENU_W
        #undef FM_MENU_ITEM_H
        #undef FM_MENU_ITEMS
        #undef FM_MENU_PAD
        #undef FM_MENU_SEP_AFTER
        #undef FM_MENU_SEP_H
    }

    comp_update_drag(comp);
    comp_update_resize(comp);
}

void comp_start_drag(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || comp->dragging || !surface || !surface->has_backing) {
        return;
    }
    if (surface->maximized || surface->resizing != RSZ_NONE) {
        return;
    }
    if (comp->resize_surface) {
        return;
    }
    comp->dragging = true;
    comp->drag_surface = surface;
    comp->drag_offset_x = comp->pointer_x - surface->x;
    comp->drag_offset_y = comp->pointer_y - surface->y;
}

void comp_end_drag(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    /* Edge-snap: snap window to half-screen when dragged to left/right edge,
     * or maximize when dragged to top edge */
    struct comp_surface *surface = comp->drag_surface;
    if (surface && surface->has_backing && !surface->maximized) {
        int32_t fb_w = (int32_t)comp->fb_info.width;
        int32_t fb_h = (int32_t)comp->fb_info.height;
        int32_t px = comp->pointer_x;
        int32_t py = comp->pointer_y;
        /* Must match SNAP_PREVIEW_THRESHOLD in comp_drag_motion. Otherwise
         * the tile preview appears in the 5-8px band but releasing there
         * doesn't actually snap, which feels broken. */
        #define SNAP_THRESHOLD 8  /* pixels from edge to trigger snap */

        if (px <= SNAP_THRESHOLD || px >= fb_w - SNAP_THRESHOLD - 1) {
            /* Save geometry for restore */
            if (!surface->have_saved_geom) {
                surface->saved_x = surface->x;
                surface->saved_y = surface->y;
                surface->saved_w = surface->width;
                surface->saved_h = surface->content_height;
                surface->have_saved_geom = true;
            }
            int32_t snap_w = fb_w / 2;
            int32_t snap_content_h = fb_h - MENUBAR_HEIGHT - 48 - surface->bar_height;
            if (snap_content_h < 100) snap_content_h = 100;
            int32_t snap_x = (px <= SNAP_THRESHOLD) ? 0 : (fb_w - snap_w);

            surface->pend_x = snap_x;
            surface->pend_y = MENUBAR_HEIGHT;
            surface->have_pending_pos = true;

            uint32_t flags = comp_surface_state_flags(surface);
            xdg_shell_surface_send_configure(surface, snap_w, snap_content_h, flags);
            comp_update_surface_position(comp, surface, snap_x, MENUBAR_HEIGHT);
        } else if (py <= SNAP_THRESHOLD + (int32_t)MENUBAR_HEIGHT) {
            /* Snap to top = maximize */
            comp_surface_set_maximized(surface, true);
        }
        #undef SNAP_THRESHOLD
    }

    /* Clear snap preview */
    if (comp->snap_preview_active) {
        comp_damage_add_rect(comp, comp->snap_preview_rect);
        comp->snap_preview_active = false;
    }

    comp->dragging = false;
    comp->drag_surface = NULL;
}

void comp_update_surface_position(struct compositor_state *comp,
                                  struct comp_surface *surface,
                                  int32_t new_x,
                                  int32_t new_y) {
    if (!comp || !surface || !surface->has_backing) {
        return;
    }

    fut_rect_t old_frame = comp_frame_rect(surface);

    int32_t width = surface->width;
    int32_t height = surface->height;
    int32_t max_x = (int32_t)comp->fb_info.width - width;
    int32_t max_y = (int32_t)comp->fb_info.height - height;
    if (max_x < 0) {
        max_x = 0;
    }
    if (max_y < 0) {
        max_y = 0;
    }

    int32_t clamped_x = clamp_i32(new_x, 0, max_x);
    int32_t clamped_y = clamp_i32(new_y, 0, max_y);
    if (clamped_x != new_x || clamped_y != new_y) {
#ifdef DEBUG_WAYLAND
        WLOG("[WAYLAND] clamp win=%p -> x=%d y=%d\n",
             (void *)surface, clamped_x, clamped_y);
#endif
    }
    if (clamped_x == surface->x && clamped_y == surface->y) {
        return;
    }

    surface->x = clamped_x;
   surface->y = clamped_y;
   comp_surface_update_decorations(surface);
   fut_rect_t new_frame = comp_frame_rect(surface);
   comp_damage_add_rect(comp, old_frame);
   comp_damage_add_rect(comp, new_frame);
    comp_surface_mark_damage(surface);
   comp->needs_repaint = true;
   if (surface == comp->active_surface) {
       WLOG("[WAYLAND] move win=%p -> x=%d y=%d\n",
            (void *)surface,
            clamped_x,
             clamped_y);
    }
}

void comp_start_resize(struct compositor_state *comp,
                       struct comp_surface *surface,
                       resize_edge_t edge) {
    if (!comp || !surface || edge == RSZ_NONE) {
        return;
    }
    if (!comp->resize_enabled || surface->maximized || !surface->has_backing) {
        return;
    }
    if (comp->resize_surface && comp->resize_surface != surface) {
        comp_end_resize(comp, comp->resize_surface);
    }
    comp_end_drag(comp);
    comp->resize_surface = surface;
    surface->resizing = edge;
    surface->base_x = surface->x;
    surface->base_y = surface->y;
    surface->base_w = surface->width;
    surface->base_h = surface->content_height;
    surface->base_total_h = surface->height;
}

void comp_update_resize(struct compositor_state *comp) {
    if (!comp || !comp->resize_surface) {
        return;
    }
    struct comp_surface *surface = comp->resize_surface;
    if (surface->resizing == RSZ_NONE) {
        comp->resize_surface = NULL;
        return;
    }

    int mx = comp->pointer_x;
    int my = comp->pointer_y;

    int32_t new_x = surface->base_x;
    int32_t new_y = surface->base_y;
    int32_t new_w = surface->base_w;
    int32_t new_total = surface->base_total_h;

    if (surface->resizing & RSZ_LEFT) {
        int32_t delta = mx - surface->base_x;
        new_w = surface->base_w - delta;
        new_x = surface->base_x + delta;
    }
    if (surface->resizing & RSZ_RIGHT) {
        int32_t delta = mx - (surface->base_x + surface->base_w);
        new_w = surface->base_w + delta;
    }
    if (surface->resizing & RSZ_TOP) {
        int32_t delta = my - surface->base_y;
        new_total = surface->base_total_h - delta;
        new_y = surface->base_y + delta;
    }
    if (surface->resizing & RSZ_BOTTOM) {
        int32_t delta = my - (surface->base_y + surface->base_total_h);
        new_total = surface->base_total_h + delta;
    }

    int32_t new_content_h = new_total - surface->bar_height;
    apply_constraints(surface, &new_w, &new_content_h);
    if (surface->resizing & RSZ_LEFT) {
        new_x = surface->base_x + (surface->base_w - new_w);
    }
    if (surface->resizing & RSZ_TOP) {
        int32_t total_after = new_content_h + surface->bar_height;
        new_y = surface->base_y + (surface->base_total_h - total_after);
        new_total = total_after;
    } else {
        new_total = new_content_h + surface->bar_height;
    }

    if (new_w < 1) {
        new_w = 1;
    }
    if (new_content_h < 0) {
        new_content_h = 0;
        new_total = surface->bar_height;
    }

    int32_t fb_w = (int32_t)comp->fb_info.width;
    int32_t fb_h = (int32_t)comp->fb_info.height;

    if (new_x < 0) {
        if (surface->resizing & RSZ_LEFT) {
            new_w += new_x;
            if (new_w < 1) {
                new_w = 1;
            }
        }
        new_x = 0;
    }
    if (new_y < 0) {
        if (surface->resizing & RSZ_TOP) {
            int32_t adjust = -new_y;
            new_total += adjust;
            new_content_h = new_total - surface->bar_height;
        }
        new_y = 0;
    }
    if (new_x + new_w > fb_w) {
        if (surface->resizing & RSZ_RIGHT) {
            new_w = fb_w - new_x;
            if (new_w < 1) {
                new_w = 1;
            }
        } else {
            new_x = fb_w - new_w;
            if (new_x < 0) {
                new_x = 0;
            }
        }
    }
    if (new_y + new_total > fb_h) {
        if (surface->resizing & RSZ_BOTTOM) {
            new_total = fb_h - new_y;
            if (new_total < surface->bar_height) {
                new_total = surface->bar_height;
            }
            new_content_h = new_total - surface->bar_height;
        } else {
            new_y = fb_h - new_total;
            if (new_y < 0) {
                new_y = 0;
            }
        }
    }

    if (new_w < 1) {
        new_w = 1;
    }
    if (new_content_h < 0) {
        new_content_h = 0;
    }

    if (surface->pend_w == new_w &&
        surface->pend_h == new_content_h &&
        surface->have_pending_pos &&
        surface->pend_x == new_x &&
        surface->pend_y == new_y) {
        return;
    }

    surface->pend_x = new_x;
    surface->pend_y = new_y;
    surface->have_pending_pos = true;

    uint32_t flags = comp_surface_state_flags(surface) | XDG_CFG_STATE_RESIZING;
    xdg_shell_surface_send_configure(surface, new_w, new_content_h, flags);

#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] resize drag win=%p -> %dx%d\n",
         (void *)surface,
         new_w,
         new_content_h + surface->bar_height);
#endif
}

void comp_end_resize(struct compositor_state *comp, struct comp_surface *surface) {
    if (!comp || !surface) {
        return;
    }
    if (surface->resizing != RSZ_NONE) {
        surface->resizing = RSZ_NONE;
    }
    if (comp->resize_surface == surface) {
        comp->resize_surface = NULL;
    }
}

void comp_surface_set_maximized(struct comp_surface *surface, bool maximized) {
    if (!surface || !surface->comp || surface->maximized == maximized) {
        return;
    }

    struct compositor_state *comp = surface->comp;

    if (maximized) {
        if (!surface->have_saved_geom) {
            surface->saved_x = surface->x;
            surface->saved_y = surface->y;
            surface->saved_w = surface->width;
            surface->saved_h = surface->content_height;
            surface->have_saved_geom = true;
        }
        surface->maximized = true;
        surface->resizing = RSZ_NONE;
        if (comp->resize_surface == surface) {
            comp->resize_surface = NULL;
        }
        comp_end_drag(comp);

        int32_t target_w = (int32_t)comp->fb_info.width;
        int32_t target_h = (int32_t)comp->fb_info.height - surface->bar_height;
        if (target_h < 0) {
            target_h = 0;
        }

        surface->pend_x = 0;
        surface->pend_y = 0;
        surface->have_pending_pos = true;

        uint32_t flags = comp_surface_state_flags(surface) | XDG_CFG_STATE_MAXIMIZED;
        xdg_shell_surface_send_configure(surface, target_w, target_h, flags);
        comp_update_surface_position(comp, surface, 0, 0);
    } else {
        surface->maximized = false;
        int32_t target_w = surface->have_saved_geom ? surface->saved_w : surface->width;
        int32_t target_h = surface->have_saved_geom ? surface->saved_h : surface->content_height;
        int32_t target_x = surface->have_saved_geom ? surface->saved_x : surface->x;
        int32_t target_y = surface->have_saved_geom ? surface->saved_y : surface->y;

        surface->pend_x = target_x;
        surface->pend_y = target_y;
        surface->have_pending_pos = true;
        /* Clear the saved-geom latch so a subsequent maximize captures the
         * user's *current* geometry (post-move/resize). Otherwise a sequence
         * of max → unmax → move → max → unmax would restore the original
         * pre-max geometry instead of the moved position. */
        surface->have_saved_geom = false;

        uint32_t flags = comp_surface_state_flags(surface);
        xdg_shell_surface_send_configure(surface, target_w, target_h, flags);
    }
}

void comp_surface_toggle_maximize(struct comp_surface *surface) {
    if (!surface) {
        return;
    }
    comp_surface_set_maximized(surface, !surface->maximized);
}

void comp_surface_set_fullscreen(struct comp_surface *surface, bool fullscreen) {
    if (!surface || !surface->comp || surface->fullscreen == fullscreen) {
        return;
    }

    struct compositor_state *comp = surface->comp;

    if (fullscreen) {
        /* Save current geometry for restore */
        surface->pre_fs_x = surface->x;
        surface->pre_fs_y = surface->y;
        surface->pre_fs_w = surface->width;
        surface->pre_fs_h = surface->content_height;
        surface->fullscreen = true;
        surface->bar_height = 0;
        surface->shadow_px = 0;

        int32_t fs_w = (int32_t)comp->fb_info.width;
        int32_t fs_h = (int32_t)comp->fb_info.height;

        surface->pend_x = 0;
        surface->pend_y = 0;
        surface->have_pending_pos = true;

        uint32_t flags = comp_surface_state_flags(surface);
        xdg_shell_surface_send_configure(surface, fs_w, fs_h, flags);
        comp_update_surface_position(comp, surface, 0, 0);
    } else {
        surface->fullscreen = false;
        if (comp->deco_enabled) {
            surface->bar_height = WINDOW_BAR_HEIGHT;
        }
        if (comp->shadow_enabled) {
            surface->shadow_px = comp->shadow_radius;
        }

        surface->pend_x = surface->pre_fs_x;
        surface->pend_y = surface->pre_fs_y;
        surface->have_pending_pos = true;

        uint32_t flags = comp_surface_state_flags(surface);
        xdg_shell_surface_send_configure(surface, surface->pre_fs_w,
                                         surface->pre_fs_h, flags);
    }
}

void comp_surface_toggle_fullscreen(struct comp_surface *surface) {
    if (!surface) {
        return;
    }
    comp_surface_set_fullscreen(surface, !surface->fullscreen);
}

void comp_surface_set_minimized(struct comp_surface *surface, bool minimized) {
    if (!surface || !surface->comp) {
        return;
    }

    if (surface->minimized == minimized) {
        return;
    }

    struct compositor_state *comp = surface->comp;

    if (minimized) {
        surface->minimized = true;
        /* Mark for damage so it disappears from screen */
        if (surface->has_backing) {
            comp_damage_add_rect(comp, comp_frame_rect(surface));
            comp_surface_mark_damage(surface);
        }
        /* Transfer focus to next visible window */
        if (comp->focused_surface == surface) {
            comp->focused_surface = NULL;
            struct comp_surface *other;
            wl_list_for_each_reverse(other, &comp->surfaces, link) {
                if (other != surface && !other->minimized) {
                    comp->focused_surface = other;
                    break;
                }
            }
        }
        if (comp->active_surface == surface) {
            comp->active_surface = comp->focused_surface;
        }
    } else {
        surface->minimized = false;
        /* Mark for damage so it reappears on screen */
        if (surface->has_backing) {
            comp_damage_add_rect(comp, comp_frame_rect(surface));
            comp_surface_mark_damage(surface);
        }
        /* Bring to front and focus */
        comp_surface_raise(comp, surface);
        comp->focused_surface = surface;
    }
}

void comp_surface_toggle_minimize(struct comp_surface *surface) {
    if (!surface) {
        return;
    }
    comp_surface_set_minimized(surface, !surface->minimized);
}

void comp_update_drag(struct compositor_state *comp) {
    if (!comp || !comp->dragging || !comp->drag_surface) {
        return;
    }
    struct comp_surface *surface = comp->drag_surface;
    int32_t new_x = comp->pointer_x - comp->drag_offset_x;
    int32_t new_y = comp->pointer_y - comp->drag_offset_y;
    comp_update_surface_position(comp, surface, new_x, new_y);

    /* Update snap preview: show translucent rectangle at target snap zone */
    int32_t fb_w = (int32_t)comp->fb_info.width;
    int32_t fb_h = (int32_t)comp->fb_info.height;
    int32_t px = comp->pointer_x;
    int32_t py = comp->pointer_y;
    bool old_active = comp->snap_preview_active;
    fut_rect_t old_rect = comp->snap_preview_rect;
    #define SNAP_PREVIEW_THRESHOLD 8
    int32_t snap_h = fb_h - MENUBAR_HEIGHT - 48;

    if (px <= SNAP_PREVIEW_THRESHOLD && !surface->maximized) {
        comp->snap_preview_active = true;
        comp->snap_preview_rect = (fut_rect_t){ 2, MENUBAR_HEIGHT + 2,
                                                 fb_w / 2 - 4, snap_h - 4 };
    } else if (px >= fb_w - SNAP_PREVIEW_THRESHOLD - 1 && !surface->maximized) {
        comp->snap_preview_active = true;
        comp->snap_preview_rect = (fut_rect_t){ fb_w / 2 + 2, MENUBAR_HEIGHT + 2,
                                                 fb_w / 2 - 4, snap_h - 4 };
    } else if (py <= SNAP_PREVIEW_THRESHOLD + (int32_t)MENUBAR_HEIGHT && !surface->maximized) {
        comp->snap_preview_active = true;
        comp->snap_preview_rect = (fut_rect_t){ 2, 2, fb_w - 4, fb_h - 4 };
    } else {
        comp->snap_preview_active = false;
    }
    #undef SNAP_PREVIEW_THRESHOLD

    /* Damage old and new preview areas */
    if (old_active) {
        fut_rect_t expanded = { old_rect.x - 2, old_rect.y - 2,
                                old_rect.w + 4, old_rect.h + 4 };
        comp_damage_add_rect(comp, expanded);
    }
    if (comp->snap_preview_active) {
        fut_rect_t expanded = { comp->snap_preview_rect.x - 2,
                                comp->snap_preview_rect.y - 2,
                                comp->snap_preview_rect.w + 4,
                                comp->snap_preview_rect.h + 4 };
        comp_damage_add_rect(comp, expanded);
    }
}

hit_role_t comp_hit_test(struct compositor_state *comp,
                         int32_t px,
                         int32_t py,
                         struct comp_surface **out_surface,
                         resize_edge_t *out_edge) {
    if (out_edge) {
        *out_edge = RSZ_NONE;
    }
    struct comp_surface *surface = comp_surface_at(comp, px, py, NULL, NULL);
    if (out_surface) {
        *out_surface = surface;
    }
    if (!surface) {
        return HIT_NONE;
    }

    comp_surface_update_decorations(surface);

    if (comp->deco_enabled && surface->bar_height > 0) {
        /* Check minimize button */
        fut_rect_t min_btn = comp_min_btn_rect(surface);
        if (min_btn.w > 0 && min_btn.h > 0 && rect_contains(&min_btn, px, py)) {
            return HIT_MINIMIZE;
        }

        /* Check maximize button */
        fut_rect_t max_btn = comp_max_btn_rect(surface);
        if (max_btn.w > 0 && max_btn.h > 0 && rect_contains(&max_btn, px, py)) {
            return HIT_MAXIMIZE;
        }

        /* Check close button */
        fut_rect_t btn = comp_btn_rect(surface);
        if (btn.w > 0 && btn.h > 0 && rect_contains(&btn, px, py)) {
            return HIT_CLOSE;
        }

        /* Check title bar */
        fut_rect_t bar = comp_bar_rect(surface);
        if (bar.h > 0 && rect_contains(&bar, px, py)) {
            return HIT_BAR;
        }
    }

    if (comp->resize_enabled && !surface->maximized) {
        fut_rect_t window_rect = comp_window_rect(surface);
        if (window_rect.w > 0 && window_rect.h > 0 &&
            rect_contains(&window_rect, px, py)) {
            int32_t local_x = px - window_rect.x;
            int32_t local_y = py - window_rect.y;
            resize_edge_t edge = RSZ_NONE;

            bool near_left = (local_x >= 0 && local_x < RESIZE_MARGIN);
            bool near_right = (local_x >= window_rect.w - RESIZE_MARGIN && local_x < window_rect.w);
            if (near_left && (!near_right || local_x <= window_rect.w - local_x)) {
                edge |= RSZ_LEFT;
            } else if (near_right) {
                edge |= RSZ_RIGHT;
            }

            bool near_bottom = (local_y >= window_rect.h - RESIZE_MARGIN && local_y < window_rect.h);
            bool near_top = false;
            int32_t top_limit = surface->bar_height;
            if (surface->bar_height > 0) {
                near_top = (local_y >= top_limit && local_y < top_limit + RESIZE_MARGIN);
            } else {
                near_top = (local_y >= 0 && local_y < RESIZE_MARGIN);
            }

            if (near_top && (!near_bottom || local_y <= window_rect.h - local_y)) {
                edge |= RSZ_TOP;
            } else if (near_bottom) {
                edge |= RSZ_BOTTOM;
            }

            if (edge != RSZ_NONE) {
                if (out_edge) {
                    *out_edge = edge;
                }
                return HIT_RESIZE;
            }
        }
    }

    fut_rect_t content = comp_content_rect(surface);
    if (content.h > 0 && rect_contains(&content, px, py)) {
        return HIT_CONTENT;
    }

    return HIT_NONE;
}

void comp_surface_request_close(struct comp_surface *surface) {
    if (!surface || !surface->xdg_toplevel) {
        return;
    }
    xdg_shell_toplevel_send_close(surface);
}
