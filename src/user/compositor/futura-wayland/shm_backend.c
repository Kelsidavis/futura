#include "shm_backend.h"
#include "log.h"

#include <stdio.h>

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
    return 0;
}

void shm_buffer_release(struct comp_buffer *buffer) {
    if (!buffer || !buffer->shm) {
        return;
    }

    wl_shm_buffer_end_access(buffer->shm);
    wl_buffer_send_release(buffer->resource);
    buffer->shm = NULL;
    buffer->resource = NULL;
    buffer->data = NULL;
}
