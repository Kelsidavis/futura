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
    size_t row_bytes = (size_t)width * 4u;
    const char *src = src_base;
    char *dst = dst_base;

    for (int y = 0; y < height; ++y) {
        memcpy(dst, src, row_bytes);
        src += src_pitch;
        dst += dst_pitch;
    }
}

static void draw_bar_segment(struct backbuffer *dst, fut_rect_t rect, bool focused) {
    uint32_t color = focused ? COLOR_BAR_FOCUSED : COLOR_BAR_UNFOCUSED;
    bb_fill_rect(dst, rect, color);
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
                px[x] = btn_color;
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
                px[x] = btn_color;
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
    comp->vsync_hint_ms = comp->target_ms;

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

    struct comp_frame_callback *cb, *tmp;
    wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
        wl_resource_destroy(cb->resource);
    }

    if (surface->backing) {
        free(surface->backing);
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

static uint32_t comp_now_msec(void) {
    return (uint32_t)sys_time_millis_call();
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

    struct compositor_state *comp = surface->comp;
    bool throttle = comp && comp->throttle_enabled;
    bool has_buffer = surface->has_pending_buffer && surface->pending_buffer_resource;
    bool has_damage = surface->has_pending_damage;

    if (throttle && !has_buffer && !has_damage) {
#ifdef DEBUG_WAYLAND
        WLOG("[WAYLAND] throttle skip win=%p\n", (void *)surface);
#endif
        return;
    }

    if (has_buffer) {
        struct comp_buffer buffer = {0};
        if (shm_buffer_import(surface->pending_buffer_resource, &buffer) == 0) {
            printf("[DEBUG] Buffer import OK: %dx%d stride=%d data=%p\n",
                   buffer.width, buffer.height, buffer.stride, buffer.data);
            /* Defense in depth: validate buffer before use */
            if (!buffer.data || buffer.width <= 0 || buffer.height <= 0 || buffer.stride <= 0) {
                shm_buffer_release(&buffer);
                wl_buffer_send_release(surface->pending_buffer_resource);
                surface->pending_buffer_resource = NULL;
                surface->has_pending_buffer = false;
                return;
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
                    return;
                }
                surface->backing = new_mem;
                surface->backing_size = required;
            }
            bool had_backing = surface->has_backing;
            for (int32_t row = 0; row < buffer.height; ++row) {
                const uint8_t *src_row = (const uint8_t *)buffer.data + (size_t)row * buffer.stride;
                uint8_t *dst_row = surface->backing + (size_t)row * buffer.stride;
                memcpy(dst_row, src_row, (size_t)buffer.width * 4u);
            }

            surface->stride = buffer.stride;
            surface->has_backing = true;
            surface->had_new_buffer = true;
            comp_surface_mark_damage(surface);

            if (!surface->pos_initialised) {
                int32_t total_h = buffer.height + surface->bar_height;
                int32_t cx = ((int32_t)surface->comp->fb_info.width - buffer.width) / 2;
                int32_t cy = ((int32_t)surface->comp->fb_info.height - total_h) / 2;
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
    return (uint64_t)sys_time_millis_call() * 1000000ULL;
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

static int comp_flush_frame_callbacks(struct compositor_state *comp, uint32_t now_msec) {
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

    /* Desktop background: vertical gradient from dark top to slightly lighter bottom */
    for (int i = 0; i < damage->count; ++i) {
        fut_rect_t r = damage->rects[i];
        if (r.w <= 0 || r.h <= 0) continue;
        int32_t fb_height = (int32_t)comp->fb_info.height;
        char *base = (char *)dst->px;
        for (int32_t y = 0; y < r.h; ++y) {
            int32_t gy = r.y + y;
            /* Interpolate: top=#1A1A2E, bottom=#2D2D44 */
            int t = (fb_height > 0) ? (gy * 255 / fb_height) : 0;
            uint8_t rb = (uint8_t)(0x1A + (0x2D - 0x1A) * t / 255);
            uint8_t gb = (uint8_t)(0x1A + (0x2D - 0x1A) * t / 255);
            uint8_t bb_c = (uint8_t)(0x2E + (0x44 - 0x2E) * t / 255);
            uint32_t color = 0xFF000000u | ((uint32_t)rb << 16) | ((uint32_t)gb << 8) | bb_c;
            uint32_t *row = (uint32_t *)(base + (size_t)gy * dst->pitch);
            for (int32_t x = 0; x < r.w; ++x) {
                row[r.x + x] = color;
            }
        }
    }

    /* ── Bottom dock panel ── */
    {
        #define DOCK_HEIGHT 36
        #define DOCK_COLOR      0xD0222233u  /* Semi-transparent dark panel */
        #define DOCK_ITEM_W     120
        #define DOCK_ITEM_H     26
        #define DOCK_ITEM_PAD   2            /* thin gap between items */
        #define DOCK_FOCUSED    0xD0505070u  /* Focused window highlight */
        #define DOCK_HOVER      0xD03A3A50u  /* Hover highlight */
        #define DOCK_SEP_COLOR  0x60888899u  /* Thin separator */
        #define DOCK_TEXT       0xFFD0D0D8u  /* Light text on dark dock */
        #define DOCK_TEXT_DIM   0xFF909098u  /* Dimmer text for unfocused */
        #define DOCK_CORNER_R   8            /* Corner radius for rounded look */
        #define DOCK_DSKBTN_W   28           /* Desktop-show button width */

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
        sys_call2(228, 0, (long)&clock_ts);
        long total_secs = clock_ts.tv_sec;
        long daytime = total_secs % 86400;
        int clock_hr = (int)(daytime / 3600);
        int clock_min = (int)((daytime % 3600) / 60);

        /* Compute month and day from epoch seconds */
        long days_since_epoch = total_secs / 86400;
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

        /* Format: "Mar 28  14:05" */
        char clock_str[16];
        const char *mn = month_names[month];
        int ci = 0;
        clock_str[ci++] = mn[0];
        clock_str[ci++] = mn[1];
        clock_str[ci++] = mn[2];
        clock_str[ci++] = ' ';
        if (day >= 10) clock_str[ci++] = '0' + (char)(day / 10);
        clock_str[ci++] = '0' + (char)(day % 10);
        clock_str[ci++] = ' ';
        clock_str[ci++] = ' ';
        clock_str[ci++] = '0' + (char)(clock_hr / 10);
        clock_str[ci++] = '0' + (char)(clock_hr % 10);
        clock_str[ci++] = ':';
        clock_str[ci++] = '0' + (char)(clock_min / 10);
        clock_str[ci++] = '0' + (char)(clock_min % 10);
        clock_str[ci] = '\0';
        int clock_text_len = ci;

        #define CLOCK_WIDTH_NEW (13 * UI_FONT_WIDTH + 16)  /* "Mar 28  HH:MM" + padding */

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

        /* Check if dock overlaps any damage region */
        for (int i = 0; i < damage->count; ++i) {
            fut_rect_t dock_clip;
            if (!rect_intersection(damage->rects[i], dock_rect, &dock_clip))
                continue;

            /* Draw dock background with rounded corners via alpha blending */
            {
                char *base = (char *)dst->px;
                for (int32_t py = dock_clip.y; py < dock_clip.y + dock_clip.h; py++) {
                    uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                    int32_t ry = py - dock_y;                    /* row within dock */
                    int32_t dy = ry < DOCK_HEIGHT / 2 ? ry : (DOCK_HEIGHT - 1 - ry);
                    for (int32_t px = dock_clip.x; px < dock_clip.x + dock_clip.w; px++) {
                        int32_t rx = px - dock_x;               /* col within dock */
                        int32_t dx = rx < dock_w / 2 ? rx : (dock_w - 1 - rx);

                        /* Compute corner alpha fade for rounded appearance */
                        uint32_t alpha = 0xD0;
                        if (dx < DOCK_CORNER_R && dy < DOCK_CORNER_R) {
                            int32_t cx = DOCK_CORNER_R - dx;
                            int32_t cy = DOCK_CORNER_R - dy;
                            int32_t dist_sq = cx * cx + cy * cy;
                            int32_t r_sq = DOCK_CORNER_R * DOCK_CORNER_R;
                            if (dist_sq > r_sq) {
                                alpha = 0;   /* outside the rounded corner */
                            } else if (dist_sq > (DOCK_CORNER_R - 2) * (DOCK_CORNER_R - 2)) {
                                alpha = 0x60; /* anti-alias edge band */
                            }
                        }

                        if (alpha > 0) {
                            uint32_t col = (alpha << 24) | 0x00222233u;
                            ABLEND(col, row[px]);
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
                    uint32_t item_bg;
                    if (is_focused)
                        item_bg = DOCK_FOCUSED;
                    else if (is_hovered)
                        item_bg = DOCK_HOVER;
                    else
                        item_bg = 0x00000000u;  /* transparent — dock bg shows through */

                    if (item_bg & 0xFF000000u) {
                        /* Alpha blend the item highlight over existing dock bg */
                        char *base = (char *)dst->px;
                        for (int32_t py = item_clip.y; py < item_clip.y + item_clip.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            for (int32_t px = item_clip.x; px < item_clip.x + item_clip.w; px++) {
                                ABLEND(item_bg, row[px]);
                            }
                        }
                    }

                    /* Focused indicator: a 2px accent bar at the bottom of the item */
                    if (is_focused) {
                        fut_rect_t accent = { item_x + 8, item_y + DOCK_ITEM_H - 2,
                                              DOCK_ITEM_W - 16, 2 };
                        fut_rect_t accent_clip;
                        if (rect_intersection(dock_clip, accent, &accent_clip))
                            bb_fill_rect(dst, accent_clip, 0xFF6688CCu);
                    }

                    /* Draw window title text, centered in the item */
                    if (ws->title[0]) {
                        int max_chars = (DOCK_ITEM_W - 12) / UI_FONT_WIDTH;
                        if (max_chars > 15) max_chars = 15;
                        if (max_chars > 0) {
                            char dock_title[16];
                            int ti = 0;
                            while (ti < max_chars && ws->title[ti]) {
                                dock_title[ti] = ws->title[ti];
                                ti++;
                            }
                            dock_title[ti] = '\0';

                            /* Center text horizontally within item */
                            int text_w = ti * UI_FONT_WIDTH;
                            int tx = item_x + (DOCK_ITEM_W - text_w) / 2;
                            int ty = item_y + (DOCK_ITEM_H - UI_FONT_HEIGHT) / 2;
                            uint32_t text_color = is_focused ? 0xFFFFFFFFu : DOCK_TEXT;
                            ui_draw_text(dst->px, dst->pitch, tx, ty,
                                         text_color, dock_title,
                                         item_clip.x, item_clip.y,
                                         item_clip.w, item_clip.h);
                        }
                    } else {
                        /* No title: show app_id or fallback "Window" */
                        const char *label = ws->app_id[0] ? ws->app_id : "Window";
                        int max_chars = (DOCK_ITEM_W - 12) / UI_FONT_WIDTH;
                        if (max_chars > 15) max_chars = 15;
                        if (max_chars > 0) {
                            char dock_title[16];
                            int ti = 0;
                            while (ti < max_chars && label[ti]) {
                                dock_title[ti] = label[ti];
                                ti++;
                            }
                            dock_title[ti] = '\0';
                            int text_w = ti * UI_FONT_WIDTH;
                            int tx = item_x + (DOCK_ITEM_W - text_w) / 2;
                            int ty = item_y + (DOCK_ITEM_H - UI_FONT_HEIGHT) / 2;
                            uint32_t text_color = is_focused ? 0xFFFFFFFFu : DOCK_TEXT_DIM;
                            ui_draw_text(dst->px, dst->pitch, tx, ty,
                                         text_color, dock_title,
                                         item_clip.x, item_clip.y,
                                         item_clip.w, item_clip.h);
                        }
                    }
                }

                /* Thin 1px separator after this item (except the last) */
                {
                    int sep_x = item_x + DOCK_ITEM_W;
                    fut_rect_t sep_rect = { sep_x, dock_y + 6, 1, DOCK_HEIGHT - 12 };
                    fut_rect_t sep_clip;
                    if (rect_intersection(dock_clip, sep_rect, &sep_clip)) {
                        char *base = (char *)dst->px;
                        for (int32_t py = sep_clip.y; py < sep_clip.y + sep_clip.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            for (int32_t px = sep_clip.x; px < sep_clip.x + sep_clip.w; px++)
                                ABLEND(DOCK_SEP_COLOR, row[px]);
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

                /* Thin separator before clock */
                {
                    fut_rect_t sep = { clock_x - 4, dock_y + 6, 1, DOCK_HEIGHT - 12 };
                    fut_rect_t sc;
                    if (rect_intersection(dock_clip, sep, &sc)) {
                        char *base = (char *)dst->px;
                        for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                            uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                            for (int32_t px = sc.x; px < sc.x + sc.w; px++)
                                ABLEND(DOCK_SEP_COLOR, row[px]);
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
                    /* Separator before desktop button */
                    {
                        fut_rect_t sep = { btn_x - 3, dock_y + 6, 1, DOCK_HEIGHT - 12 };
                        fut_rect_t sc;
                        if (rect_intersection(dock_clip, sep, &sc)) {
                            char *base = (char *)dst->px;
                            for (int32_t py = sc.y; py < sc.y + sc.h; py++) {
                                uint32_t *row = (uint32_t *)(base + (size_t)py * dst->pitch);
                                for (int32_t px = sc.x; px < sc.x + sc.w; px++)
                                    ABLEND(DOCK_SEP_COLOR, row[px]);
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

        #undef ABLEND
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

            fut_rect_t clip;
            if (!rect_intersection(damage->rects[i], window_rect, &clip)) {
                continue;
            }

            if (comp->deco_enabled && surface->bar_height > 0) {
                fut_rect_t bar_rect = comp_bar_rect(surface);
                fut_rect_t bar_clip;
                if (rect_intersection(damage->rects[i], bar_rect, &bar_clip)) {
                    draw_bar_segment(dst, bar_clip, surface == comp->focused_surface);
                    draw_title_text(dst, surface, &bar_clip);
                    touched = true;
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
            const char *src_ptr = (const char *)surface->backing +
                (size_t)(content_clip.y - content_rect.y) * surface->stride +
                (size_t)(content_clip.x - content_rect.x) * 4u;
            char *dst_ptr = (char *)dst->px +
                (size_t)content_clip.y * dst->pitch +
                (size_t)content_clip.x * 4u;
            blit_argb(src_ptr, surface->stride, dst_ptr, dst->pitch,
                      content_clip.w, content_clip.h);
            touched = true;
        }

        if (touched) {
            surface->composed_this_tick = true;
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

    uint64_t now_ms = (uint64_t)comp_now_msec();
    if (comp->next_tick_ms == 0) {
        comp->next_tick_ms = now_ms + comp->target_ms;
    } else {
        uint64_t advance = (uint64_t)comp->target_ms * expirations;
        comp->next_tick_ms += advance;
        if (comp->next_tick_ms <= now_ms) {
            comp->next_tick_ms = now_ms + comp->target_ms;
        }
    }

    (void)comp_timer_arm(comp);

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

    while (comp->running) {
        wl_display_flush_clients(comp->display);

        /* Dispatch Wayland events with 16ms timeout (~60Hz frame rate).
         * This blocks in epoll_wait until events arrive or timeout expires. */
        int rc = wl_event_loop_dispatch(comp->loop, 16);
        if (rc < 0 && errno != EINTR) {
            break;
        }

        /* Manually handle timer events.
         * The user-space timerfd is not a real kernel fd, so even when
         * wl_event_loop_add_fd succeeds (due to bypassed epoll_ctl),
         * the event loop won't deliver timer events. Always poll manually. */
        if (comp->timerfd >= 0) {
            uint64_t expirations = 0;
            ssize_t read_rc = read(comp->timerfd, &expirations, sizeof(expirations));
            if (read_rc > 0 && expirations > 0) {
                comp_handle_timer_tick(comp, expirations);
            }
        }

        /* Poll input devices for keyboard/mouse events */
        if (comp->seat) {
            seat_poll_input(comp->seat);
        }

        /* Flush events generated by input polling to clients.
         * The top-of-loop flush handles most cases, but this ensures
         * keyboard/mouse events reach clients before the next sleep. */
        wl_display_flush_clients(comp->display);
    }

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
        if (!surface->has_backing) {
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
    int32_t max_x = (int32_t)comp->fb_info.width - cursor_w;
    int32_t max_y = (int32_t)comp->fb_info.height - cursor_h;
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

    comp_cursor_damage(comp, comp->pointer_x, comp->pointer_y, cursor_w, cursor_h);

    comp->pointer_x = clamped_x;
    comp->pointer_y = clamped_y;
    cursor_set_position(comp->cursor, comp->pointer_x, comp->pointer_y);

    comp_cursor_damage(comp, comp->pointer_x, comp->pointer_y, cursor_w, cursor_h);
    comp->needs_repaint = true;

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
        /* Clear focus if this window had it */
        if (comp->focused_surface == surface) {
            comp->focused_surface = NULL;
        }
        if (comp->active_surface == surface) {
            /* Switch to another window */
            if (!wl_list_empty(&comp->surfaces)) {
                struct comp_surface *other;
                wl_list_for_each_reverse(other, &comp->surfaces, link) {
                    if (other != surface && !other->minimized) {
                        comp->active_surface = other;
                        break;
                    }
                }
            }
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
