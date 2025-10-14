#include "seat.h"

#include "comp.h"
#include "log.h"

#include <stdlib.h>

#include <futura/input_event.h>
#include <user/sys.h>

#include <wayland-server-core.h>
#include <wayland-server-protocol.h>

#define O_RDONLY 0x0000

struct seat_client {
    struct seat_state *seat;
    struct wl_resource *seat_resource;
    struct wl_resource *pointer_resource;
    struct wl_resource *keyboard_resource;
    bool pointer_entered;
    bool keyboard_entered;
    struct wl_list link;
};

struct seat_state {
    struct compositor_state *comp;
    struct wl_global *global;
    struct wl_event_source *kbd_source;
    struct wl_event_source *mouse_source;
    int kbd_fd;
    int mouse_fd;
    struct wl_list clients;
    struct comp_surface *pointer_focus;
    struct comp_surface *keyboard_focus;
    int32_t pointer_sx;
    int32_t pointer_sy;
    bool left_button_down;
};

static void seat_update_pointer_focus(struct seat_state *seat, uint32_t time_msec);
static void seat_focus_surface(struct seat_state *seat, struct comp_surface *surface);

static struct seat_client *seat_client_from_resource(struct wl_resource *resource) {
    return resource ? wl_resource_get_user_data(resource) : NULL;
}

static void pointer_resource_destroy(struct wl_resource *resource) {
    struct seat_client *client = wl_resource_get_user_data(resource);
    if (!client) {
        return;
    }
    if (client->pointer_resource == resource) {
        client->pointer_resource = NULL;
    }
    client->pointer_entered = false;
}

static void keyboard_resource_destroy(struct wl_resource *resource) {
    struct seat_client *client = wl_resource_get_user_data(resource);
    if (!client) {
        return;
    }
    if (client->keyboard_resource == resource) {
        client->keyboard_resource = NULL;
    }
    client->keyboard_entered = false;
}

static void seat_client_destroy(struct seat_client *client) {
    if (!client) {
        return;
    }
    if (client->pointer_resource) {
        struct wl_resource *res = client->pointer_resource;
        client->pointer_resource = NULL;
        wl_resource_destroy(res);
    }
    if (client->keyboard_resource) {
        struct wl_resource *res = client->keyboard_resource;
        client->keyboard_resource = NULL;
        wl_resource_destroy(res);
    }
    wl_list_remove(&client->link);
    free(client);
}

static void seat_pointer_leave(struct seat_state *seat) {
    if (!seat || !seat->pointer_focus) {
        return;
    }

    struct comp_surface *surface = seat->pointer_focus;
    struct wl_client *target = wl_resource_get_client(surface->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->pointer_resource) {
            continue;
        }
        if (wl_resource_get_client(client->pointer_resource) != target) {
            continue;
        }
        wl_pointer_send_leave(client->pointer_resource, serial, surface->surface_resource);
        wl_pointer_send_frame(client->pointer_resource);
        client->pointer_entered = false;
    }

    seat->pointer_focus = NULL;
}

static void seat_pointer_enter(struct seat_state *seat,
                               struct comp_surface *surface,
                               wl_fixed_t sx,
                               wl_fixed_t sy,
                               uint32_t time_msec) {
    if (!seat || !surface) {
        return;
    }
    struct wl_client *target = wl_resource_get_client(surface->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);

    struct seat_client *client;
    bool sent = false;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->pointer_resource) {
            continue;
        }
        if (wl_resource_get_client(client->pointer_resource) != target) {
            continue;
        }
        wl_pointer_send_enter(client->pointer_resource, serial, surface->surface_resource, sx, sy);
        wl_pointer_send_motion(client->pointer_resource, time_msec, sx, sy);
        wl_pointer_send_frame(client->pointer_resource);
        client->pointer_entered = true;
        sent = true;
    }

    if (sent) {
        seat->pointer_focus = surface;
        seat->pointer_sx = wl_fixed_to_int(sx);
        seat->pointer_sy = wl_fixed_to_int(sy);
    }
}

static void seat_pointer_motion(struct seat_state *seat,
                                wl_fixed_t sx,
                                wl_fixed_t sy,
                                uint32_t time_msec) {
    if (!seat || !seat->pointer_focus) {
        return;
    }

    struct wl_client *target = wl_resource_get_client(seat->pointer_focus->surface_resource);
    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->pointer_resource || !client->pointer_entered) {
            continue;
        }
        if (wl_resource_get_client(client->pointer_resource) != target) {
            continue;
        }
        wl_pointer_send_motion(client->pointer_resource, time_msec, sx, sy);
        wl_pointer_send_frame(client->pointer_resource);
    }
    WLOG("[WAYLAND] seat: pointer x=%d y=%d\n",
         wl_fixed_to_int(sx),
         wl_fixed_to_int(sy));
    seat->pointer_sx = wl_fixed_to_int(sx);
    seat->pointer_sy = wl_fixed_to_int(sy);
}

static void seat_pointer_button(struct seat_state *seat,
                                uint32_t button,
                                bool pressed,
                                uint32_t time_msec) {
    if (!seat || !seat->pointer_focus) {
        return;
    }

    struct wl_client *target = wl_resource_get_client(seat->pointer_focus->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);
    enum wl_pointer_button_state state = pressed
        ? WL_POINTER_BUTTON_STATE_PRESSED
        : WL_POINTER_BUTTON_STATE_RELEASED;

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->pointer_resource || !client->pointer_entered) {
            continue;
        }
        if (wl_resource_get_client(client->pointer_resource) != target) {
            continue;
        }
        wl_pointer_send_button(client->pointer_resource, serial, time_msec, button, state);
        wl_pointer_send_frame(client->pointer_resource);
    }
    const char *label = "M";
    if (button == FUT_BTN_LEFT) {
        label = "L";
    } else if (button == FUT_BTN_RIGHT) {
        label = "R";
    }
    WLOG("[WAYLAND] seat: pointer btn=%s down=%u\n", label, pressed ? 1u : 0u);
}

static void seat_keyboard_leave(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat || !surface) {
        return;
    }

    struct wl_client *target = wl_resource_get_client(surface->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->keyboard_resource || !client->keyboard_entered) {
            continue;
        }
        if (wl_resource_get_client(client->keyboard_resource) != target) {
            continue;
        }
        wl_keyboard_send_leave(client->keyboard_resource, serial, surface->surface_resource);
        client->keyboard_entered = false;
    }
}

static void seat_keyboard_enter(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat || !surface) {
        return;
    }

    struct wl_client *target = wl_resource_get_client(surface->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->keyboard_resource) {
            continue;
        }
        if (wl_resource_get_client(client->keyboard_resource) != target) {
            continue;
        }
        struct wl_array empty;
        wl_array_init(&empty);
        wl_keyboard_send_enter(client->keyboard_resource, serial, surface->surface_resource, &empty);
        wl_array_release(&empty);
        wl_keyboard_send_modifiers(client->keyboard_resource, serial, 0, 0, 0, 0);
        client->keyboard_entered = true;
    }
}

static void seat_send_key(struct seat_state *seat,
                          uint32_t keycode,
                          bool pressed,
                          uint32_t time_msec) {
    if (!seat || !seat->keyboard_focus) {
        return;
    }

    struct wl_client *target = wl_resource_get_client(seat->keyboard_focus->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);
    enum wl_keyboard_key_state state = pressed
        ? WL_KEYBOARD_KEY_STATE_PRESSED
        : WL_KEYBOARD_KEY_STATE_RELEASED;

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->keyboard_resource || !client->keyboard_entered) {
            continue;
        }
        if (wl_resource_get_client(client->keyboard_resource) != target) {
            continue;
        }
        wl_keyboard_send_key(client->keyboard_resource, serial, time_msec, keycode, state);
    }
    WLOG("[WAYLAND] seat: key code=%u down=%u\n", keycode, pressed ? 1u : 0u);
}

static void seat_focus_surface(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat) {
        return;
    }

    if (seat->keyboard_focus == surface) {
        return;
    }

    struct comp_surface *previous = seat->keyboard_focus;
    if (previous) {
        seat_keyboard_leave(seat, previous);
    }

    seat->keyboard_focus = surface;
    seat->comp->focused_surface = surface;

    if (surface) {
        seat_keyboard_enter(seat, surface);
        WLOG("[WAYLAND] raise+focus id=%u\n", surface->surface_id);
    }
}

static void seat_update_pointer_focus(struct seat_state *seat, uint32_t time_msec) {
    if (!seat) {
        return;
    }

    struct comp_surface *surface = seat->comp->active_surface;
    int32_t sx = 0;
    int32_t sy = 0;
    bool inside = comp_pointer_inside_surface(seat->comp,
                                              surface,
                                              seat->comp->pointer_x,
                                              seat->comp->pointer_y,
                                              &sx,
                                              &sy);

    if (inside) {
        wl_fixed_t fx = wl_fixed_from_int(sx);
        wl_fixed_t fy = wl_fixed_from_int(sy);
        if (seat->pointer_focus != surface) {
            seat_pointer_enter(seat, surface, fx, fy, time_msec);
        } else {
            seat_pointer_motion(seat, fx, fy, time_msec);
        }
        return;
    }

    if (seat->comp->dragging && seat->pointer_focus) {
        int32_t drag_sx = seat->comp->pointer_x - seat->comp->window_x;
        int32_t drag_sy = seat->comp->pointer_y - seat->comp->window_y;
        wl_fixed_t fx = wl_fixed_from_int(drag_sx);
        wl_fixed_t fy = wl_fixed_from_int(drag_sy);
        seat_pointer_motion(seat, fx, fy, time_msec);
        return;
    }

    seat_pointer_leave(seat);
}

static void seat_handle_button(struct seat_state *seat,
                               uint16_t code,
                               bool pressed,
                               uint32_t time_msec) {
    if (!seat) {
        return;
    }

    seat_update_pointer_focus(seat, time_msec);

    if (code == FUT_BTN_LEFT) {
        if (pressed) {
            seat->left_button_down = true;
            if (seat->pointer_focus && seat->comp->active_surface) {
                seat_focus_surface(seat, seat->comp->active_surface);
                comp_start_drag(seat->comp);
            }
        } else {
            seat->left_button_down = false;
            comp_end_drag(seat->comp);
            seat_update_pointer_focus(seat, time_msec);
        }
    }

    seat_pointer_button(seat, code, pressed, time_msec);
}

static void seat_handle_mouse_event(struct seat_state *seat,
                                    const struct fut_input_event *ev) {
    if (!seat || !ev) {
        return;
    }

    uint32_t time_msec = (uint32_t)(ev->ts_ns / 1000000ULL);
    int32_t target_x = seat->comp->pointer_x;
    int32_t target_y = seat->comp->pointer_y;
    bool moved = false;

    switch (ev->type) {
    case FUT_EV_MOUSE_MOVE:
        if (ev->code == FUT_REL_X) {
            target_x += ev->value;
            moved = true;
        } else if (ev->code == FUT_REL_Y) {
            target_y += ev->value;
            moved = true;
        }
        break;
    case FUT_EV_MOUSE_BTN:
        seat_handle_button(seat, (uint16_t)ev->code, ev->value != 0, time_msec);
        break;
    default:
        break;
    }

    if (moved) {
        comp_pointer_motion(seat->comp, target_x, target_y);
        seat_update_pointer_focus(seat, time_msec);
    }
}

static void seat_handle_key_event(struct seat_state *seat,
                                  const struct fut_input_event *ev) {
    if (!seat || !ev) {
        return;
    }

    if (ev->type != FUT_EV_KEY) {
        return;
    }

    uint32_t time_msec = (uint32_t)(ev->ts_ns / 1000000ULL);
    uint32_t keycode = (uint32_t)ev->code;
    bool pressed = (ev->value != 0);
    seat_send_key(seat, keycode, pressed, time_msec);
}

static int seat_keyboard_cb(int fd, uint32_t mask, void *data) {
    (void)fd;
    if (!(mask & WL_EVENT_READABLE)) {
        return 0;
    }

    struct seat_state *seat = data;
    struct fut_input_event events[8];

    long rc = sys_read(seat->kbd_fd, events, (long)sizeof(events));
    if (rc <= 0) {
        return 0;
    }

    size_t count = (size_t)rc / sizeof(struct fut_input_event);
    for (size_t i = 0; i < count; ++i) {
        seat_handle_key_event(seat, &events[i]);
    }
    return 0;
}

static int seat_mouse_cb(int fd, uint32_t mask, void *data) {
    (void)fd;
    if (!(mask & WL_EVENT_READABLE)) {
        return 0;
    }

    struct seat_state *seat = data;
    struct fut_input_event events[16];

    long rc = sys_read(seat->mouse_fd, events, (long)sizeof(events));
    if (rc <= 0) {
        return 0;
    }

    size_t count = (size_t)rc / sizeof(struct fut_input_event);
    for (size_t i = 0; i < count; ++i) {
        seat_handle_mouse_event(seat, &events[i]);
    }
    return 0;
}

static void seat_pointer_release(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct wl_pointer_interface pointer_impl = {
    .set_cursor = NULL,
    .release = seat_pointer_release,
};

static void seat_keyboard_release(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct wl_keyboard_interface keyboard_impl = {
    .release = seat_keyboard_release,
};

static void seat_get_pointer(struct wl_client *client,
                             struct wl_resource *resource,
                             uint32_t id) {
    struct seat_client *seat_client = seat_client_from_resource(resource);
    if (!seat_client) {
        wl_client_post_no_memory(client);
        return;
    }

    uint32_t version = wl_resource_get_version(resource);
    struct wl_resource *pointer =
        wl_resource_create(client, &wl_pointer_interface, version, id);
    if (!pointer) {
        wl_client_post_no_memory(client);
        return;
    }

    wl_resource_set_implementation(pointer, &pointer_impl, seat_client, pointer_resource_destroy);
    seat_client->pointer_resource = pointer;
}

static void seat_get_keyboard(struct wl_client *client,
                              struct wl_resource *resource,
                              uint32_t id) {
    struct seat_client *seat_client = seat_client_from_resource(resource);
    if (!seat_client) {
        wl_client_post_no_memory(client);
        return;
    }

    uint32_t version = wl_resource_get_version(resource);
    struct wl_resource *keyboard =
        wl_resource_create(client, &wl_keyboard_interface, version, id);
    if (!keyboard) {
        wl_client_post_no_memory(client);
        return;
    }

    wl_resource_set_implementation(keyboard, &keyboard_impl, seat_client, keyboard_resource_destroy);
    seat_client->keyboard_resource = keyboard;
    wl_keyboard_send_keymap(keyboard,
                            WL_KEYBOARD_KEYMAP_FORMAT_NO_KEYMAP,
                            -1,
                            0);
}

static void seat_release(struct wl_client *client, struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void seat_resource_destroy(struct wl_resource *resource) {
    struct seat_client *client = seat_client_from_resource(resource);
    if (!client) {
        return;
    }

    if (client->seat->pointer_focus && wl_resource_get_client(client->seat->pointer_focus->surface_resource) ==
            wl_resource_get_client(resource)) {
        seat_pointer_leave(client->seat);
    }

    if (client->seat->keyboard_focus && wl_resource_get_client(client->seat->keyboard_focus->surface_resource) ==
            wl_resource_get_client(resource)) {
        seat_keyboard_leave(client->seat, client->seat->keyboard_focus);
        client->seat->keyboard_focus = NULL;
        client->seat->comp->focused_surface = NULL;
    }

    seat_client_destroy(client);
}

static const struct wl_seat_interface seat_impl = {
    .get_pointer = seat_get_pointer,
    .get_keyboard = seat_get_keyboard,
    .get_touch = NULL,
    .release = seat_release,
};

static void seat_bind(struct wl_client *client,
                      void *data,
                      uint32_t version,
                      uint32_t id) {
    struct seat_state *seat = data;
    uint32_t max_version = version > 7 ? 7 : version;
    struct wl_resource *resource =
        wl_resource_create(client, &wl_seat_interface, max_version, id);
    if (!resource) {
        wl_client_post_no_memory(client);
        return;
    }

    struct seat_client *seat_client = calloc(1, sizeof(*seat_client));
    if (!seat_client) {
        wl_resource_destroy(resource);
        wl_client_post_no_memory(client);
        return;
    }

    seat_client->seat = seat;
    seat_client->seat_resource = resource;
    wl_list_insert(&seat->clients, &seat_client->link);

    wl_resource_set_implementation(resource, &seat_impl, seat_client, seat_resource_destroy);

    uint32_t caps = WL_SEAT_CAPABILITY_POINTER | WL_SEAT_CAPABILITY_KEYBOARD;
    wl_seat_send_capabilities(resource, caps);
    if (max_version >= 2) {
        wl_seat_send_name(resource, "futura-seat");
    }
}

struct seat_state *seat_init(struct compositor_state *comp) {
    if (!comp || !comp->display || !comp->loop) {
        return NULL;
    }

    struct seat_state *seat = calloc(1, sizeof(*seat));
    if (!seat) {
        return NULL;
    }

    seat->comp = comp;
    wl_list_init(&seat->clients);

    seat->kbd_fd = (int)sys_open("/dev/input/kbd0", O_RDONLY, 0);
    seat->mouse_fd = (int)sys_open("/dev/input/mouse0", O_RDONLY, 0);

    if (seat->kbd_fd < 0 || seat->mouse_fd < 0) {
        if (seat->kbd_fd >= 0) {
            sys_close(seat->kbd_fd);
        }
        if (seat->mouse_fd >= 0) {
            sys_close(seat->mouse_fd);
        }
        free(seat);
        return NULL;
    }

    seat->kbd_source = wl_event_loop_add_fd(comp->loop,
                                            seat->kbd_fd,
                                            WL_EVENT_READABLE,
                                            seat_keyboard_cb,
                                            seat);
    seat->mouse_source = wl_event_loop_add_fd(comp->loop,
                                              seat->mouse_fd,
                                              WL_EVENT_READABLE,
                                              seat_mouse_cb,
                                              seat);
    if (!seat->kbd_source || !seat->mouse_source) {
        seat_finish(seat);
        return NULL;
    }

    seat->global = wl_global_create(comp->display,
                                    &wl_seat_interface,
                                    7,
                                    seat,
                                    seat_bind);
    if (!seat->global) {
        seat_finish(seat);
        return NULL;
    }

    comp->seat = seat;
    return seat;
}

void seat_finish(struct seat_state *seat) {
    if (!seat) {
        return;
    }

    if (seat->kbd_source) {
        wl_event_source_remove(seat->kbd_source);
        seat->kbd_source = NULL;
    }
    if (seat->mouse_source) {
        wl_event_source_remove(seat->mouse_source);
        seat->mouse_source = NULL;
    }

    if (seat->kbd_fd >= 0) {
        sys_close(seat->kbd_fd);
        seat->kbd_fd = -1;
    }
    if (seat->mouse_fd >= 0) {
        sys_close(seat->mouse_fd);
        seat->mouse_fd = -1;
    }

    if (seat->global) {
        wl_global_destroy(seat->global);
        seat->global = NULL;
    }

    struct seat_client *client, *tmp;
    wl_list_for_each_safe(client, tmp, &seat->clients, link) {
        seat_client_destroy(client);
    }

    if (seat->comp && seat->comp->seat == seat) {
        seat->comp->seat = NULL;
    }

    free(seat);
}

void seat_surface_destroyed(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat || !surface) {
        return;
    }

    if (seat->pointer_focus == surface) {
        seat_pointer_leave(seat);
    }

    if (seat->keyboard_focus == surface) {
        seat_keyboard_leave(seat, surface);
        seat->keyboard_focus = NULL;
        seat->comp->focused_surface = NULL;
    }
}
