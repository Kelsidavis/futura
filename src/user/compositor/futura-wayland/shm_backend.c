#include "shm_backend.h"
#include "log.h"

#include <wayland-server-protocol.h>

int shm_backend_init(struct compositor_state *comp) {
    (void)comp;
    return 0; /* wl_display_init_shm is handled internally by libwayland */
}

void shm_backend_finish(struct compositor_state *comp) {
    (void)comp;
}

int shm_buffer_import(struct wl_resource *buffer_resource,
                      struct comp_buffer *out) {
    if (!buffer_resource || !out) {
        return -1;
    }

    struct wl_shm_buffer *shm = wl_shm_buffer_get(buffer_resource);
    if (!shm) {
        return -1;
    }

    uint32_t format = wl_shm_buffer_get_format(shm);
    if (format != WL_SHM_FORMAT_ARGB8888 && format != WL_SHM_FORMAT_XRGB8888) {
        WLOG("[WAYLAND] unsupported shm format %u\n", format);
        return -1;
    }

    wl_shm_buffer_begin_access(shm);

    out->resource = buffer_resource;
    out->shm = shm;
    out->data = wl_shm_buffer_get_data(shm);
    out->width = wl_shm_buffer_get_width(shm);
    out->height = wl_shm_buffer_get_height(shm);
    out->stride = wl_shm_buffer_get_stride(shm);
    out->format = format;

    /* Critical: check for NULL data pointer (buffer mapping failure) */
    if (!out->data) {
        WLOG("[WAYLAND] failed to get buffer data (mapping failed)\n");
        wl_shm_buffer_end_access(shm);
        out->shm = NULL;
        out->resource = NULL;
        return -1;
    }

    /* Validate buffer dimensions */
    if (out->width <= 0 || out->height <= 0 || out->stride <= 0) {
        WLOG("[WAYLAND] invalid buffer dimensions: %dx%d stride=%d\n",
             out->width, out->height, out->stride);
        wl_shm_buffer_end_access(shm);
        out->shm = NULL;
        out->resource = NULL;
        out->data = NULL;
        return -1;
    }

    return 0;
}

void shm_buffer_release(struct comp_buffer *buffer) {
    if (!buffer || !buffer->shm) {
        return;
    }

    /* Save pointers before clearing - prevents use-after-free race */
    struct wl_shm_buffer *shm = buffer->shm;
    struct wl_resource *resource = buffer->resource;

    /* Clear buffer pointers BEFORE releasing to prevent race conditions */
    buffer->data = NULL;
    buffer->shm = NULL;
    buffer->resource = NULL;

    /* Now safely end access and notify client */
    wl_shm_buffer_end_access(shm);
    if (resource) {
        wl_buffer_send_release(resource);
    }
}
