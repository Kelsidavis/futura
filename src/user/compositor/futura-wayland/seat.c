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
#define O_RDWR   0x0002
#define O_CREAT  0x0040
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
/* seat_focus_surface declared in seat.h */

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
    if (!seat) {
        printf("[KEY] seat=NULL\n");
        return;
    }
    if (!seat->keyboard_focus) {
        printf("[KEY] code=%u focus=NULL\n", keycode);
        return;
    }

    struct wl_client *target = wl_resource_get_client(seat->keyboard_focus->surface_resource);

    /* Ensure at least one client has keyboard_entered for the focused surface.
     * Due to Wayland protocol ordering, the keyboard enter event may not have
     * been sent yet (e.g. get_keyboard processed before create_surface). */
    bool any_entered = false;
    int n_clients = 0;
    int n_kbd = 0;
    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        n_clients++;
        if (client->keyboard_resource) {
            n_kbd++;
            if (client->keyboard_entered &&
                wl_resource_get_client(client->keyboard_resource) == target) {
                any_entered = true;
            }
        }
    }
    if (!any_entered) {
        printf("[KEY] force-enter: clients=%d kbd=%d\n", n_clients, n_kbd);
        seat_keyboard_enter(seat, seat->keyboard_focus);
    }

    uint32_t serial = wl_display_next_serial(seat->comp->display);
    enum wl_keyboard_key_state state = pressed
        ? WL_KEYBOARD_KEY_STATE_PRESSED
        : WL_KEYBOARD_KEY_STATE_RELEASED;

    int sent = 0;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->keyboard_resource || !client->keyboard_entered) {
            continue;
        }
        if (wl_resource_get_client(client->keyboard_resource) != target) {
            continue;
        }
        wl_keyboard_send_key(client->keyboard_resource, serial, time_msec, keycode, state);
        sent++;
    }
    printf("[KEY] code=%u down=%u sent=%d\n", keycode, pressed ? 1u : 0u, sent);
}

void seat_focus_surface(struct seat_state *seat, struct comp_surface *surface) {
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

            /* Dock click: if click is in the dock area, find which window and focus it */
            if (!hit_surface && seat->comp) {
                int32_t mx = seat->comp->pointer_x;
                int32_t my = seat->comp->pointer_y;
                int32_t fb_h = (int32_t)seat->comp->fb_info.height;
                int32_t fb_w = (int32_t)seat->comp->fb_info.width;
                int32_t dock_y = fb_h - 32 - 8;  /* DOCK_HEIGHT=32, 8px margin */

                if (my >= dock_y && my < fb_h) {
                    /* Count windows to compute dock geometry */
                    int n_win = 0;
                    struct comp_surface *ds;
                    wl_list_for_each(ds, &seat->comp->surfaces, link)
                        if (ds->has_backing) n_win++;

                    int dock_w = n_win * 104 + 8;  /* DOCK_ITEM_W(100)+PAD(4) per item + padding */
                    if (dock_w < 208) dock_w = 208;
                    int dock_x = (fb_w - dock_w) / 2;

                    if (mx >= dock_x && mx < dock_x + dock_w) {
                        int item_x = dock_x + 4;
                        wl_list_for_each(ds, &seat->comp->surfaces, link) {
                            if (!ds->has_backing) continue;
                            if (mx >= item_x && mx < item_x + 100) {
                                /* Click on this window's dock entry — focus and raise */
                                if (ds->minimized) ds->minimized = false;
                                comp_surface_raise(seat->comp, ds);
                                seat_focus_surface(seat, ds);
                                comp_damage_add_full(seat->comp);
                                seat->comp->needs_repaint = true;
                                break;
                            }
                            item_x += 104;
                        }
                    }
                }
            }

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
            } else if (role == HIT_MINIMIZE && hit_surface && seat->comp->deco_enabled) {
                hit_surface->min_btn_pressed = true;
                comp_damage_add_rect(seat->comp, comp_min_btn_rect(hit_surface));
                comp_surface_mark_damage(hit_surface);
#ifdef DEBUG_WAYLAND
                WLOG("[WAYLAND] deco: press minimize win=%p\n", (void *)hit_surface);
#endif
            } else if (role == HIT_MAXIMIZE && hit_surface && seat->comp->deco_enabled) {
                hit_surface->max_btn_pressed = true;
                comp_damage_add_rect(seat->comp, comp_max_btn_rect(hit_surface));
                comp_surface_mark_damage(hit_surface);
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

            if (pressed_surface && pressed_role == HIT_MINIMIZE && seat->comp->deco_enabled) {
                if (pressed_surface->min_btn_pressed) {
                    pressed_surface->min_btn_pressed = false;
                    comp_damage_add_rect(seat->comp, comp_min_btn_rect(pressed_surface));
                    comp_surface_mark_damage(pressed_surface);
                }
                if (pressed_surface == hit_surface && role == HIT_MINIMIZE) {
#ifdef DEBUG_WAYLAND
                    WLOG("[WAYLAND] deco: toggle minimize win=%p\n", (void *)pressed_surface);
#endif
                    comp_surface_toggle_minimize(pressed_surface);
                }
            }

            if (pressed_surface && pressed_role == HIT_MAXIMIZE && seat->comp->deco_enabled) {
                if (pressed_surface->max_btn_pressed) {
                    pressed_surface->max_btn_pressed = false;
                    comp_damage_add_rect(seat->comp, comp_max_btn_rect(pressed_surface));
                    comp_surface_mark_damage(pressed_surface);
                }
                if (pressed_surface == hit_surface && role == HIT_MAXIMIZE) {
                    comp_surface_toggle_maximize(pressed_surface);
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
    case FUT_EV_MOUSE_MOVE: {
        /* Apply simple mouse acceleration: small movements get 2x,
         * larger movements get 3x to make the cursor feel responsive */
        int32_t delta = ev->value;
        int32_t abs_delta = delta < 0 ? -delta : delta;
        int32_t factor = abs_delta > 5 ? 3 : 2;
        delta *= factor;
        if (ev->code == FUT_REL_X) {
            target_x += delta;
            moved = true;
        } else if (ev->code == FUT_REL_Y) {
            target_y += delta;
            moved = true;
        }
        break;
    }
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

/* Track modifier state for compositor keybindings */
static uint32_t compositor_mods = 0;
#define COMP_MOD_CTRL  (1u << 0)
#define COMP_MOD_ALT   (1u << 1)
#define COMP_MOD_SUPER (1u << 2)

/* Launch a new terminal instance */
static void compositor_launch_terminal(void) {
    extern long sys_fork_call(void);
    extern void sys_execve_call(const char *, char *const[], char *const[]);
    extern void sys_exit(int);
    long pid = sys_fork_call();
    if (pid == 0) {
        /* Child: exec wl-term */
        char *argv[] = { "/bin/wl-term", (void*)0 };
        char *envp[] = { "WAYLAND_DISPLAY=wayland-0", "XDG_RUNTIME_DIR=/tmp",
                         "TERM=xterm-256color", (void*)0 };
        sys_execve_call("/bin/wl-term", argv, envp);
        sys_exit(127);
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

    uint32_t keycode = (uint32_t)ev->code;
    bool pressed = (ev->value != 0);

    /* Track modifier keys */
    if (keycode == 29 || keycode == 97) {  /* Left/Right Ctrl */
        if (pressed) compositor_mods |= COMP_MOD_CTRL;
        else compositor_mods &= ~COMP_MOD_CTRL;
    }
    if (keycode == 56 || keycode == 100) {  /* Left/Right Alt */
        if (pressed) compositor_mods |= COMP_MOD_ALT;
        else compositor_mods &= ~COMP_MOD_ALT;
    }
    if (keycode == 125 || keycode == 126) {  /* Super/Meta */
        if (pressed) compositor_mods |= COMP_MOD_SUPER;
        else compositor_mods &= ~COMP_MOD_SUPER;
    }

    /* Compositor keybindings (consumed, not forwarded to clients) */
    if (pressed) {
        /* Ctrl+Alt+T or Super+Enter: launch new terminal */
        if ((compositor_mods == (COMP_MOD_CTRL | COMP_MOD_ALT) && keycode == 20 /* T */) ||
            (compositor_mods == COMP_MOD_SUPER && keycode == 28 /* Enter */)) {
            compositor_launch_terminal();
            return;
        }

        /* Alt+Tab: cycle focus to next window */
        if ((compositor_mods & COMP_MOD_ALT) && keycode == 15 /* Tab */) {
            if (seat->comp) {
                struct comp_surface *current = seat->comp->focused_surface;
                struct comp_surface *next = NULL;

                if (current) {
                    /* Find next surface after current in the list */
                    struct comp_surface *s;
                    bool found_current = false;
                    wl_list_for_each(s, &seat->comp->surfaces, link) {
                        if (!s->has_backing || s->minimized) continue;
                        if (found_current) { next = s; break; }
                        if (s == current) found_current = true;
                    }
                    /* Wrap around to first */
                    if (!next) {
                        wl_list_for_each(s, &seat->comp->surfaces, link) {
                            if (s->has_backing && !s->minimized) { next = s; break; }
                        }
                    }
                } else {
                    /* No focused window — focus first */
                    struct comp_surface *s;
                    wl_list_for_each(s, &seat->comp->surfaces, link) {
                        if (s->has_backing && !s->minimized) { next = s; break; }
                    }
                }

                if (next && next != current) {
                    comp_surface_raise(seat->comp, next);
                    seat_focus_surface(seat, next);
                    comp_damage_add_full(seat->comp);
                    seat->comp->needs_repaint = true;
                }
            }
            return;
        }

        /* Alt+F4: close focused window */
        if ((compositor_mods & COMP_MOD_ALT) && keycode == 62 /* F4 */) {
            if (seat->comp && seat->comp->focused_surface) {
                struct comp_surface *s = seat->comp->focused_surface;
                if (s->xdg_toplevel_resource) {
                    extern void xdg_toplevel_send_close(struct wl_resource *);
                    xdg_toplevel_send_close(s->xdg_toplevel_resource);
                }
            }
            return;
        }
    }

    uint32_t time_msec = (uint32_t)(ev->ts_ns / 1000000ULL);
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

    /* libwayland requires a valid fd for keymap even with NO_KEYMAP format.
     * Create a minimal dummy file that can be dup'd successfully. */
    int keymap_fd = (int)sys_open("/tmp/.keymap_dummy", O_RDWR | O_CREAT, 0600);
    if (keymap_fd < 0) {
        /* Fallback: try /dev/null */
        keymap_fd = (int)sys_open("/dev/null", O_RDONLY, 0);
    }

    wl_keyboard_send_keymap(keyboard,
                            WL_KEYBOARD_KEYMAP_FORMAT_NO_KEYMAP,
                            keymap_fd >= 0 ? keymap_fd : 0,
                            0);

    if (keymap_fd >= 0) {
        sys_close(keymap_fd);
    }

    /* If a surface is already focused and belongs to this client,
     * send keyboard enter immediately so keys are delivered */
    struct seat_state *seat = seat_client->seat;
    if (seat && seat->keyboard_focus) {
        struct wl_client *focus_client =
            wl_resource_get_client(seat->keyboard_focus->surface_resource);
        if (focus_client == client) {
            uint32_t serial = wl_display_next_serial(seat->comp->display);
            struct wl_array empty;
            wl_array_init(&empty);
            wl_keyboard_send_enter(keyboard, serial,
                                   seat->keyboard_focus->surface_resource, &empty);
            wl_array_release(&empty);
            wl_keyboard_send_modifiers(keyboard, serial, 0, 0, 0, 0);
            seat_client->keyboard_entered = true;
        }
    }
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
    printf("[SEAT] kbd_fd=%d mouse_fd=%d\n", seat->kbd_fd, seat->mouse_fd);

    /* Input devices are polled manually in seat_poll_input() since they
       don't support epoll. The compositor main loop calls seat_poll_input()
       each iteration to check for keyboard/mouse events. */

    /* Mark that we have input devices available, even though they're not in the event loop */
    seat->kbd_source_registered = false;   /* Not registered with event loop */
    seat->mouse_source_registered = false;  /* Not registered with event loop */

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

void seat_poll_input(struct seat_state *seat) {
    if (!seat) {
        return;
    }

    /* Poll keyboard for events (non-blocking) */
    if (seat->kbd_fd >= 0) {
        struct fut_input_event events[8];
        long rc = sys_read(seat->kbd_fd, events, (long)sizeof(events));
        if (rc > 0) {
            size_t count = (size_t)rc / sizeof(struct fut_input_event);
            for (size_t i = 0; i < count; ++i) {
                seat_handle_key_event(seat, &events[i]);
            }
        }
    }

    /* Poll mouse for events (non-blocking) */
    if (seat->mouse_fd >= 0) {
        struct fut_input_event events[16];
        long rc = sys_read(seat->mouse_fd, events, (long)sizeof(events));
        if (rc > 0) {
            size_t count = (size_t)rc / sizeof(struct fut_input_event);
            for (size_t i = 0; i < count; ++i) {
                seat_handle_mouse_event(seat, &events[i]);
            }
        }
    }
}

void seat_finish(struct seat_state *seat) {
    if (!seat) {
        return;
    }

    if (seat->kbd_source_registered && seat->kbd_source) {
        wl_event_source_remove(seat->kbd_source);
        seat->kbd_source = NULL;
        seat->kbd_source_registered = false;
    }
    if (seat->mouse_source_registered && seat->mouse_source) {
        wl_event_source_remove(seat->mouse_source);
        seat->mouse_source = NULL;
        seat->mouse_source_registered = false;
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
    if (seat->hover_min_btn_surface == surface) {
        seat_clear_min_button_hover(seat);
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
