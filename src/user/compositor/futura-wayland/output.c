#include "comp.h"
#include "output.h"

#include <wayland-server-protocol.h>

static const struct wl_output_interface output_impl = {
    .release = NULL,
};

static void output_bind(struct wl_client *client,
                        void *data,
                        uint32_t version,
                        uint32_t id) {
    struct compositor_state *comp = data;
    if (!comp) {
        return;
    }

    uint32_t ver = version > 3 ? 3 : version;
    struct wl_resource *resource =
        wl_resource_create(client, &wl_output_interface, ver, id);
    if (!resource) {
        wl_client_post_no_memory(client);
        return;
    }

    wl_resource_set_implementation(resource, &output_impl, comp, NULL);

    const struct fut_fb_info *info = &comp->fb_info;
    wl_output_send_geometry(resource,
                            0,
                            0,
                            0,
                            0,
                            WL_OUTPUT_SUBPIXEL_UNKNOWN,
                            "Futura",
                            "Framebuffer",
                            WL_OUTPUT_TRANSFORM_NORMAL);
    wl_output_send_mode(resource,
                        WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED,
                        info->width,
                        info->height,
                        60000);
    if (ver >= 2) {
        wl_output_send_done(resource);
    }
}

int output_global_init(struct compositor_state *comp) {
    if (!comp || !comp->display) {
        return -1;
    }

    if (!wl_global_create(comp->display,
                          &wl_output_interface,
                          3,
                          comp,
                          output_bind)) {
        return -1;
    }
    return 0;
}
