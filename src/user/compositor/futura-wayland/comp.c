#include "comp.h"
#include "log.h"
#include "shm_backend.h"

#include <errno.h>
#include <string.h>

#include <user/libfutura.h>
#include <user/stdio.h>
#include <user/sys.h>

#define O_RDWR      0x0002
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

static inline uint32_t clamp_u32(uint32_t value, uint32_t max) {
    return value > max ? max : value;
}

const struct fut_fb_info *comp_get_fb_info(const struct compositor_state *comp) {
    return comp ? &comp->fb_info : NULL;
}

int comp_state_init(struct compositor_state *comp) {
    if (!comp) {
        return -1;
    }

    memset(comp, 0, sizeof(*comp));

    int fd = (int)sys_open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        printf("[WAYLAND] failed to open /dev/fb0 (err=%d)\n", fd);
        return -1;
    }

    struct fut_fb_info info = {0};
    if (sys_ioctl(fd, FBIOGET_INFO, (long)&info) < 0) {
        printf("[WAYLAND] FBIOGET_INFO failed\n");
        sys_close(fd);
        return -1;
    }

    if (info.bpp != 32) {
        printf("[WAYLAND] unsupported framebuffer format (bpp=%u)\n", info.bpp);
        sys_close(fd);
        return -1;
    }

    size_t map_size = (size_t)info.pitch * info.height;
    void *map = (void *)sys_mmap(NULL,
                                 (long)map_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED,
                                 fd,
                                 0);
    if ((long)map < 0) {
        printf("[WAYLAND] mmap framebuffer failed\n");
        sys_close(fd);
        return -1;
    }

    comp->fb_fd = fd;
    comp->fb_map = (uint8_t *)map;
    comp->fb_map_size = map_size;
    comp->fb_info = info;
    comp->running = true;
    comp->frame_delay_ms = 16u;
    return 0;
}

void comp_state_finish(struct compositor_state *comp) {
    if (!comp) {
        return;
    }

    comp->running = false;

    if (comp->fb_map && comp->fb_map_size) {
        sys_munmap_call(comp->fb_map, (long)comp->fb_map_size);
        comp->fb_map = NULL;
        comp->fb_map_size = 0;
    }
    if (comp->fb_fd >= 0) {
        sys_close(comp->fb_fd);
        comp->fb_fd = -1;
    }
}

void comp_present_buffer(struct compositor_state *comp,
                         struct comp_buffer *buffer,
                         const struct comp_damage *damage) {
    if (!comp || !buffer || !buffer->data || !comp->fb_map) {
        return;
    }

    int32_t src_width = buffer->width;
    int32_t src_height = buffer->height;
    int32_t src_stride = buffer->stride;
    if (src_width <= 0 || src_height <= 0 || src_stride <= 0) {
        return;
    }

    int32_t copy_x = 0;
    int32_t copy_y = 0;
    int32_t copy_w = src_width;
    int32_t copy_h = src_height;

    if (damage && damage->valid) {
        copy_x = damage->x;
        copy_y = damage->y;
        copy_w = damage->width;
        copy_h = damage->height;
    }

    if (copy_x < 0) {
        copy_w += copy_x;
        copy_x = 0;
    }
    if (copy_y < 0) {
        copy_h += copy_y;
        copy_y = 0;
    }

    if (copy_w <= 0 || copy_h <= 0) {
        return;
    }

    uint32_t dst_w = comp->fb_info.width;
    uint32_t dst_h = comp->fb_info.height;

    if (copy_x >= src_width || copy_y >= src_height) {
        return;
    }
    if ((uint32_t)copy_x >= dst_w || (uint32_t)copy_y >= dst_h) {
        return;
    }

    int32_t max_w_src = src_width - copy_x;
    int32_t max_h_src = src_height - copy_y;
    if (copy_w > max_w_src) {
        copy_w = max_w_src;
    }
    if (copy_h > max_h_src) {
        copy_h = max_h_src;
    }

    copy_w = (int32_t)clamp_u32((uint32_t)copy_w, dst_w);
    copy_h = (int32_t)clamp_u32((uint32_t)copy_h, dst_h);

    uint8_t *dst = comp->fb_map + (size_t)(copy_y * comp->fb_info.pitch) + (size_t)(copy_x * 4);
    const uint8_t *src = (const uint8_t *)buffer->data + (size_t)(copy_y * src_stride) + (size_t)(copy_x * 4);
    uint32_t row_bytes = (uint32_t)copy_w * 4u;

    for (int32_t y = 0; y < copy_h; ++y) {
        memcpy(dst + (size_t)y * comp->fb_info.pitch,
               src + (size_t)y * src_stride,
               row_bytes);
    }
}

struct comp_surface *comp_surface_create(struct compositor_state *comp,
                                         struct wl_resource *surface_resource) {
    struct comp_surface *surface = malloc(sizeof(*surface));
    if (!surface) {
        return NULL;
    }
    memset(surface, 0, sizeof(*surface));
    surface->comp = comp;
    surface->surface_resource = surface_resource;
    wl_list_init(&surface->frame_callbacks);
    surface->pending_damage.valid = false;
    surface->has_pending_buffer = false;
    return surface;
}

void comp_surface_destroy(struct comp_surface *surface) {
    if (!surface) {
        return;
    }

    struct comp_frame_callback *cb, *tmp;
    wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
        wl_resource_destroy(cb->resource);
        free(cb);
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
}

void comp_surface_damage(struct comp_surface *surface,
                         int32_t x, int32_t y,
                         int32_t width, int32_t height) {
    if (!surface) {
        return;
    }

    surface->pending_damage.x = x;
    surface->pending_damage.y = y;
    surface->pending_damage.width = width;
    surface->pending_damage.height = height;
    surface->pending_damage.valid = true;
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

    if (surface->has_pending_buffer && surface->pending_buffer_resource) {
        struct comp_buffer buffer = {0};
        if (shm_buffer_import(surface->pending_buffer_resource, &buffer) == 0) {
            comp_present_buffer(surface->comp, &buffer,
                                surface->pending_damage.valid ? &surface->pending_damage : NULL);
            shm_buffer_release(&buffer);
        } else {
            wl_buffer_send_release(surface->pending_buffer_resource);
        }
        surface->pending_buffer_resource = NULL;
        surface->has_pending_buffer = false;
        surface->pending_damage.valid = false;
    }

    uint32_t now = comp_now_msec();
    struct comp_frame_callback *cb, *tmp;
    wl_list_for_each_safe(cb, tmp, &surface->frame_callbacks, link) {
        wl_callback_send_done(cb->resource, now);
        wl_resource_destroy(cb->resource);
        wl_list_remove(&cb->link);
        free(cb);
    }
}

int comp_run(struct compositor_state *comp) {
    if (!comp || !comp->display || !comp->loop) {
        return -1;
    }

    while (comp->running) {
        wl_display_dispatch_pending(comp->display);
        wl_display_flush_clients(comp->display);

        int rc = wl_event_loop_dispatch(comp->loop, (int)comp->frame_delay_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }

    return 0;
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
}
