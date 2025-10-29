#include "seat.h"

#include "comp.h"
#include "log.h"
#include "xdg_shell.h"
#include "data_device.h"

#include <stdlib.h>

#include <futura/input_event.h>
#include <user/sys.h>

#include <wayland-server-core.h>
#include <wayland-server-protocol.h>

#define O_RDONLY 0x0000
#define O_NONBLOCK 0x0800
#define DOUBLE_CLICK_MS 300

static void seat_clear_button_hover(struct seat_state *seat) {
    if (!seat || !seat->hover_btn_surface) {
        return;
    }
    struct comp_surface *surface = seat->hover_btn_surface;
   if (surface->btn_hover) {
       surface->btn_hover = false;
       comp_damage_add_rect(seat->comp, comp_btn_rect(surface));
        comp_surface_mark_damage(surface);
   }
   seat->hover_btn_surface = NULL;
}

static void seat_set_button_hover(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat) {
        return;
    }
    if (seat->hover_btn_surface == surface) {
        return;
    }
    seat_clear_button_hover(seat);
    if (!surface) {
        return;
    }
    surface->btn_hover = true;
    comp_damage_add_rect(seat->comp, comp_btn_rect(surface));
    comp_surface_mark_damage(surface);
    seat->hover_btn_surface = surface;
}

static void seat_clear_min_button_hover(struct seat_state *seat) {
    if (!seat || !seat->hover_min_btn_surface) {
        return;
    }
    struct comp_surface *surface = seat->hover_min_btn_surface;
    if (surface->min_btn_hover) {
        surface->min_btn_hover = false;
        comp_damage_add_rect(seat->comp, comp_min_btn_rect(surface));
        comp_surface_mark_damage(surface);
    }
    seat->hover_min_btn_surface = NULL;
}

static void seat_set_min_button_hover(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat) {
        return;
    }
    if (seat->hover_min_btn_surface == surface) {
        return;
    }
    seat_clear_min_button_hover(seat);
    if (!surface) {
        return;
    }
    surface->min_btn_hover = true;
    comp_damage_add_rect(seat->comp, comp_min_btn_rect(surface));
    comp_surface_mark_damage(surface);
    seat->hover_min_btn_surface = surface;
}

static void seat_update_hover(struct seat_state *seat) {
    if (!seat) {
        return;
    }
    if (!seat->comp->deco_enabled) {
        seat_clear_button_hover(seat);
        seat_clear_min_button_hover(seat);
        return;
    }

    struct comp_surface *surface = NULL;
    resize_edge_t edge = RSZ_NONE;
    hit_role_t role = comp_hit_test(seat->comp,
                                    seat->comp->pointer_x,
                                    seat->comp->pointer_y,
                                    &surface,
                                    &edge);
    if (role == HIT_MINIMIZE && surface) {
        seat_set_min_button_hover(seat, surface);
        seat_clear_button_hover(seat);
    } else if (role == HIT_CLOSE && surface) {
        seat_set_button_hover(seat, surface);
        seat_clear_min_button_hover(seat);
    } else {
        seat_clear_button_hover(seat);
        seat_clear_min_button_hover(seat);
    }
}

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
    data_device_client_cleanup(client);
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
    if (!seat) {
        return;
    }

    seat_clear_button_hover(seat);

    if (!seat->pointer_focus) {
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
#ifdef DEBUG_WAYLAND
    const char *label = "M";
    if (button == FUT_BTN_LEFT) {
        label = "L";
    } else if (button == FUT_BTN_RIGHT) {
        label = "R";
    }
    WLOG("[WAYLAND] seat: pointer btn=%s down=%u\n", label, pressed ? 1u : 0u);
#endif
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
        comp_surface_update_decorations(previous);
        if (previous->bar_height > 0) {
            comp_damage_add_rect(seat->comp, comp_bar_rect(previous));
            comp_surface_mark_damage(previous);
        }
        seat_keyboard_leave(seat, previous);
    }

    seat->keyboard_focus = surface;
    seat->comp->focused_surface = surface;
    seat->comp->active_surface = surface;

    if (surface) {
        seat_keyboard_enter(seat, surface);
        comp_surface_update_decorations(surface);
        if (surface->bar_height > 0) {
            comp_damage_add_rect(seat->comp, comp_bar_rect(surface));
            comp_surface_mark_damage(surface);
        }
#ifdef DEBUG_WAYLAND
        WLOG("[WAYLAND] deco: focus win=%p\n", (void *)surface);
#endif
    }
}

static void seat_update_pointer_focus(struct seat_state *seat, uint32_t time_msec) {
    if (!seat) {
        return;
    }

    int32_t sx = 0;
    int32_t sy = 0;
    struct comp_surface *surface = NULL;

    struct comp_surface *iter;
    wl_list_for_each_reverse(iter, &seat->comp->surfaces, link) {
        if (!iter->has_backing) {
            continue;
        }
        if (comp_pointer_inside_surface(seat->comp, iter,
                                        seat->comp->pointer_x,
                                        seat->comp->pointer_y,
                                        &sx,
                                        &sy)) {
            surface = iter;
            break;
        }
    }

    if (surface) {
        wl_fixed_t fx = wl_fixed_from_int(sx);
        wl_fixed_t fy = wl_fixed_from_int(sy);
        if (seat->pointer_focus != surface) {
            seat_pointer_leave(seat);
            seat_pointer_enter(seat, surface, fx, fy, time_msec);
        } else {
            seat_pointer_motion(seat, fx, fy, time_msec);
        }
    } else {
        seat_pointer_leave(seat);
    }

    seat_update_hover(seat);
}

static void seat_handle_button(struct seat_state *seat,
                               uint16_t code,
                               bool pressed,
                               uint32_t time_msec) {
    if (!seat) {
        return;
    }

    seat_update_pointer_focus(seat, time_msec);
    seat_update_hover(seat);

    if (code == FUT_BTN_LEFT) {
        struct comp_surface *hit_surface = NULL;
        resize_edge_t edge = RSZ_NONE;
        hit_role_t role = comp_hit_test(seat->comp,
                                        seat->comp->pointer_x,
                                        seat->comp->pointer_y,
                                        &hit_surface,
                                        &edge);

        if (pressed) {
            seat->left_button_down = true;
            seat->pressed_surface = hit_surface;
            seat->pressed_role = role;
            seat->pressed_edge = edge;

            if (hit_surface) {
                if (seat->comp->active_surface != hit_surface) {
                    comp_surface_raise(seat->comp, hit_surface);
                }
                seat_focus_surface(seat, hit_surface);
            }

            if (role == HIT_BAR && hit_surface && !hit_surface->maximized) {
                comp_start_drag(seat->comp, hit_surface);
            } else if (role == HIT_CLOSE && hit_surface && seat->comp->deco_enabled) {
                hit_surface->btn_pressed = true;
                comp_damage_add_rect(seat->comp, comp_btn_rect(hit_surface));
                comp_surface_mark_damage(hit_surface);
#ifdef DEBUG_WAYLAND
                WLOG("[WAYLAND] deco: press close win=%p\n", (void *)hit_surface);
#endif
            } else if (role == HIT_RESIZE && hit_surface && edge != RSZ_NONE) {
                comp_start_resize(seat->comp, hit_surface, edge);
            }
        } else {
            seat->left_button_down = false;
            comp_end_drag(seat->comp);
            if (seat->pressed_surface) {
                comp_end_resize(seat->comp, seat->pressed_surface);
            }

            struct comp_surface *pressed_surface = seat->pressed_surface;
            hit_role_t pressed_role = seat->pressed_role;
            resize_edge_t pressed_edge = seat->pressed_edge;
            seat->pressed_surface = NULL;
            seat->pressed_role = HIT_NONE;
            seat->pressed_edge = RSZ_NONE;

            if (pressed_surface && pressed_role == HIT_CLOSE && seat->comp->deco_enabled) {
                if (pressed_surface->btn_pressed) {
                    pressed_surface->btn_pressed = false;
                    comp_damage_add_rect(seat->comp, comp_btn_rect(pressed_surface));
                    comp_surface_mark_damage(pressed_surface);
                }
                if (pressed_surface == hit_surface && role == HIT_CLOSE) {
#ifdef DEBUG_WAYLAND
                    WLOG("[WAYLAND] deco: send close win=%p\n", (void *)pressed_surface);
#endif
                    comp_surface_request_close(pressed_surface);
                }
            }

            if (pressed_surface && pressed_role == HIT_BAR &&
                pressed_surface == hit_surface && role == HIT_BAR &&
                !seat->comp->dragging && pressed_edge == RSZ_NONE) {
                uint32_t delta = 0;
                bool double_click = false;
                if (seat->last_click_surface == pressed_surface) {
                    delta = time_msec - seat->last_click_time;
                    if (delta <= DOUBLE_CLICK_MS) {
                        double_click = true;
                    }
                }
                seat->last_click_surface = pressed_surface;
                seat->last_click_time = time_msec;
                if (double_click) {
                    comp_surface_toggle_maximize(pressed_surface);
                    seat->last_click_surface = NULL;
                    seat->last_click_time = 0;
                }
            } else if (pressed_role == HIT_RESIZE && pressed_surface) {
                seat->last_click_surface = NULL;
                seat->last_click_time = 0;
            } else {
                seat->last_click_surface = NULL;
                seat->last_click_time = 0;
            }
        }
    }

    seat_update_hover(seat);
    seat_pointer_button(seat, code, pressed, time_msec);
}

static void __attribute__((unused)) seat_handle_mouse_event(struct seat_state *seat,
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

static void __attribute__((unused)) seat_handle_key_event(struct seat_state *seat,
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

static int __attribute__((unused)) seat_keyboard_cb(int fd, uint32_t mask, void *data) {
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

static int __attribute__((unused)) seat_mouse_cb(int fd, uint32_t mask, void *data) {
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
    data_device_client_init(seat_client);
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
    data_device_seat_init(seat);

    seat->kbd_fd = (int)sys_open("/dev/input/kbd0", O_RDONLY | O_NONBLOCK, 0);
    seat->mouse_fd = (int)sys_open("/dev/input/mouse0", O_RDONLY | O_NONBLOCK, 0);

    printf("[SEAT-DEBUG] kbd_fd=%d, mouse_fd=%d\n", seat->kbd_fd, seat->mouse_fd);

    if (seat->kbd_fd < 0 || seat->mouse_fd < 0) {
        printf("[SEAT-DEBUG] Device open failed: kbd_fd=%d, mouse_fd=%d\n",
               seat->kbd_fd, seat->mouse_fd);
        if (seat->kbd_fd >= 0) {
            sys_close(seat->kbd_fd);
        }
        if (seat->mouse_fd >= 0) {
            sys_close(seat->mouse_fd);
        }
        free(seat);
        return NULL;
    }

    /* Note: Input device files (/dev/input/kbd0, /dev/input/mouse0) are character
       devices that don't support epoll/poll. They cannot be added to the Wayland event
       loop. For now, we mark this as unsupported and continue without input handling.
       A proper implementation would use libinput or a separate input thread. */

    printf("[SEAT-DEBUG] Skipping event loop registration - input devices don't support epoll\n");

    /* Mark that we have input devices available, even though they're not in the event loop */
    seat->kbd_source = (void *)1;   /* Mark as non-NULL to indicate success */
    seat->mouse_source = (void *)1;  /* Mark as non-NULL to indicate success */

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

    data_device_seat_finish(seat);

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

    if (seat->hover_btn_surface == surface) {
        seat_clear_button_hover(seat);
    }
    if (seat->pressed_surface == surface) {
        seat->pressed_surface = NULL;
        seat->pressed_role = HIT_NONE;
        seat->pressed_edge = RSZ_NONE;
    }
    if (seat->last_click_surface == surface) {
        seat->last_click_surface = NULL;
        seat->last_click_time = 0;
    }
}

struct seat_client *seat_client_lookup(struct seat_state *seat, struct wl_client *client) {
    if (!seat || !client) {
        return NULL;
    }
    struct seat_client *cursor;
    wl_list_for_each(cursor, &seat->clients, link) {
        if (cursor->seat_resource &&
            wl_resource_get_client(cursor->seat_resource) == client) {
            return cursor;
        }
    }
    return NULL;
}
