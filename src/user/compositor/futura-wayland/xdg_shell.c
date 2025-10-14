#include "comp.h"
#include "log.h"
#include "xdg_shell.h"
#include "shm_backend.h"

#include <stdlib.h>

#include "xdg-shell-server-protocol.h"

static const struct wl_compositor_interface compositor_impl;
static const struct wl_surface_interface surface_impl;
static const struct xdg_wm_base_interface xdg_wm_base_impl;
static const struct xdg_surface_interface xdg_surface_impl;
static const struct xdg_toplevel_interface xdg_toplevel_impl;

static void compositor_bind(struct wl_client *client,
                            void *data,
                            uint32_t version,
                            uint32_t id) {
    struct compositor_state *comp = data;
    if (!comp) {
        return;
    }

    uint32_t ver = version > 4 ? 4 : version;
    struct wl_resource *resource =
        wl_resource_create(client, &wl_compositor_interface, ver, id);
    if (!resource) {
        wl_client_post_no_memory(client);
        return;
    }

    wl_resource_set_implementation(resource, &compositor_impl, comp, NULL);
}

int compositor_global_init(struct compositor_state *comp) {
    if (!comp || !comp->display) {
        return -1;
    }
    if (!wl_global_create(comp->display,
                          &wl_compositor_interface,
                          4,
                          comp,
                          compositor_bind)) {
        return -1;
    }
    return 0;
}

static struct comp_surface *surface_from_resource(struct wl_resource *resource) {
    if (!resource) {
        return NULL;
    }
    return wl_resource_get_user_data(resource);
}

static void surface_resource_destroy(struct wl_resource *resource) {
    struct comp_surface *surface = surface_from_resource(resource);
    comp_surface_destroy(surface);
}

static void surface_destroy(struct wl_client *client,
                            struct wl_resource *resource) {
    (void)client;
    struct comp_surface *surface = surface_from_resource(resource);
    comp_surface_destroy(surface);
    wl_resource_destroy(resource);
}

static void surface_attach(struct wl_client *client,
                           struct wl_resource *resource,
                           struct wl_resource *buffer,
                           int32_t dx,
                           int32_t dy) {
    (void)client;
    (void)dx;
    (void)dy;
    comp_surface_attach(surface_from_resource(resource), buffer);
}

static void surface_damage(struct wl_client *client,
                           struct wl_resource *resource,
                           int32_t x,
                           int32_t y,
                           int32_t width,
                           int32_t height) {
    (void)client;
    comp_surface_damage(surface_from_resource(resource), x, y, width, height);
}

static void surface_frame_req(struct wl_client *client,
                              struct wl_resource *resource,
                              uint32_t callback_id) {
    (void)client;
    struct comp_surface *surface = surface_from_resource(resource);
    struct wl_resource *callback =
        wl_resource_create(client, &wl_callback_interface,
                           wl_resource_get_version(resource), callback_id);
    if (!callback) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(callback, NULL, NULL, NULL);
    comp_surface_frame(surface, callback);
}

static void surface_commit(struct wl_client *client,
                           struct wl_resource *resource) {
    (void)client;
    comp_surface_commit(surface_from_resource(resource));
}

static void surface_damage_buffer(struct wl_client *client,
                                  struct wl_resource *resource,
                                  int32_t x,
                                  int32_t y,
                                  int32_t width,
                                  int32_t height) {
    (void)client;
    comp_surface_damage(surface_from_resource(resource), x, y, width, height);
}

static void surface_set_opaque_region(struct wl_client *client,
                                      struct wl_resource *resource,
                                      struct wl_resource *region) {
    (void)client;
    (void)resource;
    (void)region;
}

static void surface_set_input_region(struct wl_client *client,
                                     struct wl_resource *resource,
                                     struct wl_resource *region) {
    (void)client;
    (void)resource;
    (void)region;
}

static void surface_set_buffer_transform(struct wl_client *client,
                                         struct wl_resource *resource,
                                         int32_t transform) {
    (void)client;
    (void)resource;
    (void)transform;
}

static void surface_set_buffer_scale(struct wl_client *client,
                                     struct wl_resource *resource,
                                     int32_t scale) {
    (void)client;
    (void)resource;
    (void)scale;
}

static void surface_offset(struct wl_client *client,
                           struct wl_resource *resource,
                           int32_t x,
                           int32_t y) {
    (void)client;
    (void)resource;
    (void)x;
    (void)y;
}

static const struct wl_surface_interface surface_impl = {
    .destroy = surface_destroy,
    .attach = surface_attach,
    .damage = surface_damage,
    .frame = surface_frame_req,
    .set_opaque_region = surface_set_opaque_region,
    .set_input_region = surface_set_input_region,
    .commit = surface_commit,
    .damage_buffer = surface_damage_buffer,
    .set_buffer_transform = surface_set_buffer_transform,
    .set_buffer_scale = surface_set_buffer_scale,
    .offset = surface_offset,
};

static void compositor_create_surface(struct wl_client *client,
                                      struct wl_resource *resource,
                                      uint32_t id) {
    struct compositor_state *comp = wl_resource_get_user_data(resource);
    struct wl_resource *surface_res =
        wl_resource_create(client, &wl_surface_interface,
                           wl_resource_get_version(resource), id);
    if (!surface_res) {
        wl_client_post_no_memory(client);
        return;
    }

    struct comp_surface *surface = comp_surface_create(comp, surface_res);
    if (!surface) {
        wl_resource_destroy(surface_res);
        wl_client_post_no_memory(client);
        return;
    }

    wl_resource_set_implementation(surface_res, &surface_impl, surface, NULL);
    wl_resource_set_destructor(surface_res, surface_resource_destroy);
}

static void region_destroy(struct wl_client *client,
                           struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct wl_region_interface region_impl = {
    .destroy = region_destroy,
    .add = NULL,
    .subtract = NULL,
};

static void compositor_create_region(struct wl_client *client,
                                     struct wl_resource *resource,
                                     uint32_t id) {
    struct wl_resource *region_res =
        wl_resource_create(client, &wl_region_interface,
                           wl_resource_get_version(resource), id);
    if (!region_res) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(region_res, &region_impl, NULL, NULL);
}

static const struct wl_compositor_interface compositor_impl = {
    .create_surface = compositor_create_surface,
    .create_region = compositor_create_region,
};

struct xdg_surface_state {
    struct cuboid {
        int32_t width;
        int32_t height;
    } size;
    uint32_t configure_serial;
    struct comp_surface *surface;
    struct compositor_state *comp;
    struct wl_resource *xdg_surface_res;
    struct wl_resource *xdg_toplevel_res;
};

static void xdg_surface_destroy(struct wl_client *client,
                                struct wl_resource *resource) {
    (void)client;
    struct xdg_surface_state *state = wl_resource_get_user_data(resource);
    free(state);
    wl_resource_destroy(resource);
}

static void xdg_surface_get_toplevel(struct wl_client *client,
                                     struct wl_resource *resource,
                                     uint32_t id) {
    struct xdg_surface_state *state = wl_resource_get_user_data(resource);
    if (!state) {
        wl_client_post_no_memory(client);
        return;
    }

    struct wl_resource *toplevel =
        wl_resource_create(client, &xdg_toplevel_interface,
                           wl_resource_get_version(resource), id);
    if (!toplevel) {
        wl_client_post_no_memory(client);
        return;
    }

    wl_resource_set_implementation(toplevel, &xdg_toplevel_impl, state, NULL);
    state->xdg_toplevel_res = toplevel;

    uint32_t serial = wl_display_next_serial(state->comp->display);
    xdg_surface_send_configure(state->xdg_surface_res, serial);
    xdg_toplevel_send_configure(toplevel, state->size.width, state->size.height, NULL);
    state->configure_serial = serial;
}

static void xdg_surface_get_popup(struct wl_client *client,
                                  struct wl_resource *resource,
                                  uint32_t id,
                                  struct wl_resource *parent,
                                  struct wl_resource *positioner) {
    (void)client;
    (void)resource;
    (void)id;
    (void)parent;
    (void)positioner;
}

static void xdg_surface_set_window_geometry(struct wl_client *client,
                                            struct wl_resource *resource,
                                            int32_t x,
                                            int32_t y,
                                            int32_t width,
                                            int32_t height) {
    (void)client;
    (void)resource;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
}

static void xdg_surface_ack_configure(struct wl_client *client,
                                      struct wl_resource *resource,
                                      uint32_t serial) {
    (void)client;
    struct xdg_surface_state *state = wl_resource_get_user_data(resource);
    if (state && state->configure_serial == serial) {
        state->configure_serial = 0;
    }
}

static const struct xdg_surface_interface xdg_surface_impl = {
    .destroy = xdg_surface_destroy,
    .get_toplevel = xdg_surface_get_toplevel,
    .get_popup = xdg_surface_get_popup,
    .set_window_geometry = xdg_surface_set_window_geometry,
    .ack_configure = xdg_surface_ack_configure,
};

static void xdg_toplevel_destroy(struct wl_client *client,
                                 struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct xdg_toplevel_interface xdg_toplevel_impl = {
    .destroy = xdg_toplevel_destroy,
    .set_parent = NULL,
    .set_title = NULL,
    .set_app_id = NULL,
    .show_window_menu = NULL,
    .move = NULL,
    .resize = NULL,
    .set_max_size = NULL,
    .set_min_size = NULL,
    .set_maximized = NULL,
    .unset_maximized = NULL,
    .set_fullscreen = NULL,
    .unset_fullscreen = NULL,
    .set_minimized = NULL,
};

static void xdg_wm_base_destroy(struct wl_client *client,
                                struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void xdg_wm_base_create_positioner(struct wl_client *client,
                                          struct wl_resource *resource,
                                          uint32_t id) {
    (void)resource;
    struct wl_resource *positioner =
        wl_resource_create(client, &xdg_positioner_interface,
                           wl_resource_get_version(resource), id);
    if (!positioner) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(positioner, NULL, NULL, NULL);
}

static void xdg_wm_base_get_xdg_surface(struct wl_client *client,
                                        struct wl_resource *resource,
                                        uint32_t id,
                                        struct wl_resource *surface_resource) {
    struct compositor_state *comp = wl_resource_get_user_data(resource);
    struct comp_surface *surface = wl_resource_get_user_data(surface_resource);
    if (!comp || !surface) {
        wl_client_post_no_memory(client);
        return;
    }

    struct wl_resource *xdg_surface_res =
        wl_resource_create(client, &xdg_surface_interface,
                           wl_resource_get_version(resource), id);
    if (!xdg_surface_res) {
        wl_client_post_no_memory(client);
        return;
    }

    struct xdg_surface_state *state = calloc(1, sizeof(*state));
    if (!state) {
        wl_resource_destroy(xdg_surface_res);
        wl_client_post_no_memory(client);
        return;
    }

    state->surface = surface;
    state->comp = comp;
    state->xdg_surface_res = xdg_surface_res;
    state->size.width = comp->fb_info.width;
    state->size.height = comp->fb_info.height;

    wl_resource_set_implementation(xdg_surface_res, &xdg_surface_impl, state,
                                   (wl_resource_destroy_func_t)free);
}

static void xdg_wm_base_pong(struct wl_client *client,
                             struct wl_resource *resource,
                             uint32_t serial) {
    (void)client;
    (void)resource;
    (void)serial;
}

static const struct xdg_wm_base_interface xdg_wm_base_impl = {
    .destroy = xdg_wm_base_destroy,
    .create_positioner = xdg_wm_base_create_positioner,
    .get_xdg_surface = xdg_wm_base_get_xdg_surface,
    .pong = xdg_wm_base_pong,
};

static void xdg_wm_base_bind(struct wl_client *client,
                             void *data,
                             uint32_t version,
                             uint32_t id) {
    struct compositor_state *comp = data;
    uint32_t ver = version > 4 ? 4 : version;
    struct wl_resource *resource =
        wl_resource_create(client, &xdg_wm_base_interface, ver, id);
    if (!resource) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(resource, &xdg_wm_base_impl, comp, NULL);
}

int xdg_shell_global_init(struct compositor_state *comp) {
    if (!comp || !comp->display) {
        return -1;
    }
    if (!wl_global_create(comp->display,
                          &xdg_wm_base_interface,
                          4,
                          comp,
                          xdg_wm_base_bind)) {
        return -1;
    }
    return 0;
}
