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

static void seat_clear_max_button_hover(struct seat_state *seat) {
    if (!seat || !seat->hover_max_btn_surface) {
        return;
    }
    struct comp_surface *surface = seat->hover_max_btn_surface;
    if (surface->max_btn_hover) {
        surface->max_btn_hover = false;
        comp_damage_add_rect(seat->comp, comp_max_btn_rect(surface));
        comp_surface_mark_damage(surface);
    }
    seat->hover_max_btn_surface = NULL;
}

static void seat_set_max_button_hover(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat) {
        return;
    }
    if (seat->hover_max_btn_surface == surface) {
        return;
    }
    seat_clear_max_button_hover(seat);
    if (!surface) {
        return;
    }
    surface->max_btn_hover = true;
    comp_damage_add_rect(seat->comp, comp_max_btn_rect(surface));
    comp_surface_mark_damage(surface);
    seat->hover_max_btn_surface = surface;
}

static void seat_update_hover(struct seat_state *seat) {
    if (!seat) {
        return;
    }
    if (!seat->comp->deco_enabled) {
        seat_clear_button_hover(seat);
        seat_clear_min_button_hover(seat);
        seat_clear_max_button_hover(seat);
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
        seat_clear_max_button_hover(seat);
    } else if (role == HIT_MAXIMIZE && surface) {
        seat_set_max_button_hover(seat, surface);
        seat_clear_button_hover(seat);
        seat_clear_min_button_hover(seat);
    } else if (role == HIT_CLOSE && surface) {
        seat_set_button_hover(seat, surface);
        seat_clear_min_button_hover(seat);
        seat_clear_max_button_hover(seat);
    } else {
        seat_clear_button_hover(seat);
        seat_clear_min_button_hover(seat);
        seat_clear_max_button_hover(seat);
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

    if (!seat->pointer_focus || !seat->pointer_focus->surface_resource) {
        seat->pointer_focus = NULL;
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
    if (!seat || !surface || !surface->surface_resource) {
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
    if (!seat || !seat->pointer_focus || !seat->pointer_focus->surface_resource) {
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
    if (!seat || !seat->pointer_focus || !seat->pointer_focus->surface_resource) {
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
    if (!seat || !surface || !surface->surface_resource) {
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

/* Forward declaration: defined further below alongside the rest of the
 * compositor-side modifier tracking. seat_keyboard_enter needs the
 * current XKB-format mod mask to send a real value (rather than zeros)
 * when a client first acquires keyboard focus. */
static uint32_t compositor_mods_to_xkb(void);

static void seat_keyboard_enter(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat || !surface || !surface->surface_resource) {
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
        wl_keyboard_send_modifiers(client->keyboard_resource, serial,
                                   compositor_mods_to_xkb(), 0, 0, 0);
        client->keyboard_entered = true;
    }
}

static void seat_send_key(struct seat_state *seat,
                          uint32_t keycode,
                          bool pressed,
                          uint32_t time_msec) {
    if (!seat || !seat->keyboard_focus || !seat->keyboard_focus->surface_resource) {
        return;
    }

    struct wl_client *target = wl_resource_get_client(seat->keyboard_focus->surface_resource);

    /* Ensure at least one client has keyboard_entered for the focused surface.
     * Due to Wayland protocol ordering, the keyboard enter event may not have
     * been sent yet (e.g. get_keyboard processed before create_surface). */
    bool any_entered = false;
    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (client->keyboard_resource && client->keyboard_entered &&
            wl_resource_get_client(client->keyboard_resource) == target) {
            any_entered = true;
            break;
        }
    }
    if (!any_entered) {
        seat_keyboard_enter(seat, seat->keyboard_focus);
    }

    uint32_t serial = wl_display_next_serial(seat->comp->display);
    enum wl_keyboard_key_state state = pressed
        ? WL_KEYBOARD_KEY_STATE_PRESSED
        : WL_KEYBOARD_KEY_STATE_RELEASED;

    wl_list_for_each(client, &seat->clients, link) {
        if (!client->keyboard_resource || !client->keyboard_entered) {
            continue;
        }
        if (wl_resource_get_client(client->keyboard_resource) != target) {
            continue;
        }
        wl_keyboard_send_key(client->keyboard_resource, serial, time_msec, keycode, state);
    }
}

void seat_focus_surface(struct seat_state *seat, struct comp_surface *surface) {
    if (!seat) {
        return;
    }

    if (seat->keyboard_focus == surface) {
        return;
    }

    /* Damage the focused-window halo (FOCUS_GLOW=6 in comp.c) plus a few
     * extra pixels for the shadow region. Both the OLD and NEW focused
     * window need this — without it the previously-focused window keeps
     * its blue glow ring after focus moved on. */
    #define FOCUS_HALO_PAD 12
    struct comp_surface *previous = seat->keyboard_focus;
    if (previous) {
        comp_surface_update_decorations(previous);
        if (previous->bar_height > 0) {
            comp_damage_add_rect(seat->comp, comp_bar_rect(previous));
        }
        if (previous->has_backing) {
            fut_rect_t halo = {
                previous->x - FOCUS_HALO_PAD,
                previous->y - FOCUS_HALO_PAD,
                previous->width + 2 * FOCUS_HALO_PAD,
                previous->height + 2 * FOCUS_HALO_PAD,
            };
            comp_damage_add_rect(seat->comp, halo);
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
        }
        if (surface->has_backing) {
            fut_rect_t halo = {
                surface->x - FOCUS_HALO_PAD,
                surface->y - FOCUS_HALO_PAD,
                surface->width + 2 * FOCUS_HALO_PAD,
                surface->height + 2 * FOCUS_HALO_PAD,
            };
            comp_damage_add_rect(seat->comp, halo);
            comp_surface_mark_damage(surface);
        }
#ifdef DEBUG_WAYLAND
        WLOG("[WAYLAND] deco: focus win=%p\n", (void *)surface);
#endif
    }

    /* Re-issue configure on both the old and new focused surfaces so the
     * ACTIVATED toplevel state actually reaches clients. The size doesn't
     * change — comp_surface_state_flags() already reflects max/fs/resize,
     * and xdg_surface_issue_configure() injects ACTIVATED based on the
     * current focused_surface (now updated above). */
    if (previous && previous->xdg_toplevel) {
        xdg_shell_surface_send_configure(previous,
                                         previous->width,
                                         previous->content_height,
                                         comp_surface_state_flags(previous));
    }
    if (surface && surface->xdg_toplevel) {
        xdg_shell_surface_send_configure(surface,
                                         surface->width,
                                         surface->content_height,
                                         comp_surface_state_flags(surface));
    }
    #undef FOCUS_HALO_PAD
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
        if (!iter->has_backing || iter->minimized) {
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

static void compositor_launch_terminal(void);
static void compositor_launch_edit(void);
static void compositor_launch_sysmon(void);
static void compositor_launch_files(void);

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

            /* Dock click: if click is in the dock area, find which window and focus it.
             * Geometry MUST match the dock renderer in comp.c exactly. The
             * renderer was updated (commit e3d74639 widened items, prior
             * commits added the date+seconds clock) without updating these
             * numbers, so dock clicks were landing on the wrong items. */
            if (!hit_surface && seat->comp) {
                int32_t mx = seat->comp->pointer_x;
                int32_t my = seat->comp->pointer_y;
                int32_t fb_h = (int32_t)seat->comp->fb_info.height;
                int32_t fb_w = (int32_t)seat->comp->fb_info.width;
                #define SEAT_DOCK_HEIGHT   38                  /* DOCK_HEIGHT */
                #define SEAT_DOCK_ITEM_W   148                 /* DOCK_ITEM_W */
                #define SEAT_DOCK_ITEM_PAD 4                   /* DOCK_ITEM_PAD */
                #define SEAT_DOCK_DSKBTN_W 28                  /* DOCK_DSKBTN_W */
                #define SEAT_CLOCK_W       (22 * 8 + 16)       /* CLOCK_WIDTH_NEW: "Day, Mon DD  HH:MM:SS" */
                int32_t dock_y = fb_h - SEAT_DOCK_HEIGHT - 6;

                if (my >= dock_y && my < fb_h) {
                    /* Count windows to compute dock geometry */
                    int n_win = 0;
                    struct comp_surface *ds;
                    wl_list_for_each(ds, &seat->comp->surfaces, link)
                        if (ds->has_backing) n_win++;

                    int items_w = n_win > 0
                        ? n_win * SEAT_DOCK_ITEM_W + (n_win - 1) * SEAT_DOCK_ITEM_PAD
                        : 0;
                    int dock_content_w = 8 + items_w + 8 + SEAT_CLOCK_W + 4 + SEAT_DOCK_DSKBTN_W + 4;
                    if (dock_content_w < 240) dock_content_w = 240;
                    /* Mirror the renderer's fb_w - 16 cap so the
                     * hit-test geometry matches what's actually drawn
                     * when many windows force the dock to clip. */
                    int dock_w_max = fb_w - 16;
                    if (dock_w_max < 240) dock_w_max = 240;
                    int dock_w = dock_content_w > dock_w_max ? dock_w_max : dock_content_w;
                    int dock_x = (fb_w - dock_w) / 2;

                    if (mx >= dock_x && mx < dock_x + dock_w) {
                        /* Check desktop-show button at far right */
                        int dskbtn_x = dock_x + dock_w - SEAT_DOCK_DSKBTN_W - 2;
                        if (mx >= dskbtn_x && mx < dskbtn_x + SEAT_DOCK_DSKBTN_W) {
                            /* Toggle show-desktop: minimize all or restore all */
                            bool any_visible = false;
                            wl_list_for_each(ds, &seat->comp->surfaces, link) {
                                if (ds->has_backing && !ds->minimized)
                                    any_visible = true;
                            }
                            wl_list_for_each(ds, &seat->comp->surfaces, link) {
                                if (ds->has_backing)
                                    comp_surface_set_minimized(ds, any_visible);
                            }
                            seat->comp->dock_all_minimized = any_visible;
                            comp_damage_add_full(seat->comp);
                            seat->comp->needs_repaint = true;
                        } else {
                            /* Check window items */
                            int item_x = dock_x + 8;
                            wl_list_for_each(ds, &seat->comp->surfaces, link) {
                                if (!ds->has_backing) continue;
                                if (mx >= item_x && mx < item_x + SEAT_DOCK_ITEM_W) {
                                    /* Click on this window's dock entry — toggle minimize or focus.
                                     * Go through comp_surface_set_minimized so the focus/active-
                                     * surface bookkeeping happens; setting ds->minimized = true
                                     * directly leaves keyboard_focus pointing at the now-hidden
                                     * surface, dropping subsequent keys into the void. */
                                    if (ds == seat->comp->focused_surface && !ds->minimized) {
                                        comp_surface_set_minimized(ds, true);
                                    } else {
                                        comp_surface_set_minimized(ds, false);
                                        comp_surface_raise(seat->comp, ds);
                                        seat_focus_surface(seat, ds);
                                    }
                                    comp_damage_add_full(seat->comp);
                                    seat->comp->needs_repaint = true;
                                    break;
                                }
                                item_x += SEAT_DOCK_ITEM_W + SEAT_DOCK_ITEM_PAD;
                            }
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

    /* Middle-click on title bar: minimize window */
    if (code == FUT_BTN_MIDDLE && pressed) {
        struct comp_surface *hit_surface = NULL;
        resize_edge_t edge = RSZ_NONE;
        hit_role_t role = comp_hit_test(seat->comp,
                                        seat->comp->pointer_x,
                                        seat->comp->pointer_y,
                                        &hit_surface, &edge);
        if (role == HIT_BAR && hit_surface && seat->comp->deco_enabled) {
            comp_surface_set_minimized(hit_surface, true);
            comp_damage_add_full(seat->comp);
            seat->comp->needs_repaint = true;
        }
    }

    /* Right-click on desktop background: show context menu */
    if (code == FUT_BTN_RIGHT && pressed) {
        struct comp_surface *hit_surface = NULL;
        resize_edge_t edge = RSZ_NONE;
        hit_role_t role = comp_hit_test(seat->comp,
                                        seat->comp->pointer_x,
                                        seat->comp->pointer_y,
                                        &hit_surface,
                                        &edge);
        (void)role; (void)edge;
        /* Dismiss Futura menu first — without this, opening the desktop
         * context menu via right-click while the Futura menu was open
         * left both menus rendered at once (Futura on the left, ctx on
         * the right). The dismiss handlers below only run for left
         * clicks or about/shortcut-overlay state, so the Futura menu
         * would silently survive. */
        if (seat->comp && seat->comp->futura_menu_active) {
            seat->comp->futura_menu_active = false;
            seat->comp->futura_menu_hover = -1;
            comp_damage_add_full(seat->comp);
            seat->comp->needs_repaint = true;
        }
        if (!hit_surface && seat->comp) {
            /* Clamp the menu origin to the screen so the renderer's
             * on-screen clamp and the hover detector's offset math agree.
             * Without this, right-clicking near the right/bottom edge drew
             * the menu in a clamped spot but computed hover/click offsets
             * against the original pointer, so highlights never lit. */
            #define SEAT_CTX_MENU_W   240
            #define SEAT_CTX_MENU_H   (4 + 6 * 28 + 2 * 9 + 4)
            int32_t fb_w = (int32_t)seat->comp->fb_info.width;
            int32_t fb_h = (int32_t)seat->comp->fb_info.height;
            int32_t mx = seat->comp->pointer_x;
            int32_t my = seat->comp->pointer_y;
            if (mx + SEAT_CTX_MENU_W > fb_w) mx = fb_w - SEAT_CTX_MENU_W;
            if (my + SEAT_CTX_MENU_H > fb_h) my = fb_h - SEAT_CTX_MENU_H;
            if (mx < 0) mx = 0;
            /* Don't let the menu overlap the top menubar — same reservation
             * the window y-clamp uses. The hover detector subtracts
             * ctx_menu_y from pointer_y, so as long as both renderer and
             * hit-test see the same clamped origin, hovering still works. */
            if (my < (int32_t)24 /* MENUBAR_HEIGHT */) my = 24;
            #undef SEAT_CTX_MENU_W
            #undef SEAT_CTX_MENU_H
            seat->comp->ctx_menu_active = true;
            seat->comp->ctx_menu_x = mx;
            seat->comp->ctx_menu_y = my;
            seat->comp->ctx_menu_hover = -1;
            comp_damage_add_full(seat->comp);
            seat->comp->needs_repaint = true;
        }
    }

    /* Click anywhere dismisses shortcut overlay */
    if (pressed && seat->comp && seat->comp->shortcut_overlay_active) {
        seat->comp->shortcut_overlay_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    /* Click anywhere dismisses about dialog */
    if (pressed && seat->comp && seat->comp->about_active) {
        seat->comp->about_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    /* Left-click on Futura menu: select item or dismiss */
    if (code == FUT_BTN_LEFT && pressed && seat->comp && seat->comp->futura_menu_active) {
        int sel = seat->comp->futura_menu_hover;
        seat->comp->futura_menu_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        if (sel == 0) compositor_launch_terminal();
        if (sel == 1) compositor_launch_edit();
        if (sel == 2) compositor_launch_sysmon();
        if (sel == 3) compositor_launch_files();
        if (sel == 4) { seat->comp->about_active = true; }
        if (sel == 5) { seat->comp->shortcut_overlay_active = true; }
        if (sel == 6) {
            /* System Info — show toast */
            int32_t w = (int32_t)seat->comp->fb_info.width;
            int32_t h = (int32_t)seat->comp->fb_info.height;
            int n_win = 0;
            struct comp_surface *ws;
            wl_list_for_each(ws, &seat->comp->surfaces, link) {
                if (ws->has_backing) n_win++;
            }
            char info[128];
            int ci = 0;
            const char *prefix = "Horizon | ";
            while (*prefix) info[ci++] = *prefix++;
            if (w >= 1000) info[ci++] = '0' + (char)(w / 1000);
            if (w >= 100)  info[ci++] = '0' + (char)((w / 100) % 10);
            info[ci++] = '0' + (char)((w / 10) % 10);
            info[ci++] = '0' + (char)(w % 10);
            info[ci++] = 'x';
            if (h >= 1000) info[ci++] = '0' + (char)(h / 1000);
            if (h >= 100)  info[ci++] = '0' + (char)((h / 100) % 10);
            info[ci++] = '0' + (char)((h / 10) % 10);
            info[ci++] = '0' + (char)(h % 10);
            const char *mid = " | Windows: ";
            while (*mid) info[ci++] = *mid++;
            if (n_win >= 10) info[ci++] = '0' + (char)(n_win / 10);
            info[ci++] = '0' + (char)(n_win % 10);
            info[ci] = '\0';
            comp_show_toast(seat->comp, info);
        }
        if (sel == 7) {
            /* Show Desktop */
            bool any_vis = false;
            struct comp_surface *s;
            wl_list_for_each(s, &seat->comp->surfaces, link) {
                if (s->has_backing && !s->minimized) any_vis = true;
            }
            wl_list_for_each(s, &seat->comp->surfaces, link) {
                if (s->has_backing) comp_surface_set_minimized(s, any_vis);
            }
            seat->comp->dock_all_minimized = any_vis;
        }
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    /* Left-click dismisses context menu, or selects an item */
    if (code == FUT_BTN_LEFT && pressed && seat->comp && seat->comp->ctx_menu_active) {
        int sel = seat->comp->ctx_menu_hover;
        seat->comp->ctx_menu_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        if (sel == 0) {
            /* "New Terminal" */
            compositor_launch_terminal();
        }
        /* sel == 1: "Show Desktop" handled below */
        if (sel == 1) {
            /* Toggle show desktop */
            bool any_visible = false;
            struct comp_surface *s;
            wl_list_for_each(s, &seat->comp->surfaces, link) {
                if (s->has_backing && !s->minimized)
                    any_visible = true;
            }
            wl_list_for_each(s, &seat->comp->surfaces, link) {
                if (s->has_backing)
                    comp_surface_set_minimized(s, any_visible);
            }
            seat->comp->dock_all_minimized = any_visible;
            comp_damage_add_full(seat->comp);
            seat->comp->needs_repaint = true;
        }
        if (sel == 2 || sel == 3) {
            /* "Tile Left" / "Tile Right" */
            struct comp_surface *sf = seat->comp->focused_surface;
            if (sf) {
                int32_t fw = (int32_t)seat->comp->fb_info.width;
                int32_t fh = (int32_t)seat->comp->fb_info.height;
                if (sf->maximized) comp_surface_set_maximized(sf, false);
                if (sf->fullscreen) comp_surface_set_fullscreen(sf, false);
                /* Same shape as the Super+Left/Right fix: only capture the
                 * pre-tile geometry once, so tile-left → tile-right doesn't
                 * overwrite the original rect with a tiled one. */
                if (!sf->have_saved_geom) {
                    sf->saved_x = sf->x; sf->saved_y = sf->y;
                    sf->saved_w = sf->width;
                    /* saved_h is the *content* height across the codebase
                     * (matches comp_surface_set_maximized + drag-snap), so
                     * the unified restore in Super+Down doesn't need any
                     * bar_height arithmetic. */
                    sf->saved_h = sf->content_height;
                    sf->have_saved_geom = true;
                }
                int32_t tile_y = 24 /* MENUBAR_HEIGHT */;
                int32_t tile_h = fh - 24 - 48;
                int32_t tile_w = fw / 2;
                int32_t tile_x = (sel == 2) ? 0 : (fw - tile_w);
                comp_update_surface_position(seat->comp, sf, tile_x, tile_y);
                int32_t content_h = tile_h - sf->bar_height;
                if (content_h < 1) content_h = 1;
                xdg_shell_surface_send_configure(sf, tile_w, content_h,
                    comp_surface_state_flags(sf));
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
        }
        if (sel == 4) {
            /* Toggle fullscreen on focused window */
            if (seat->comp->focused_surface) {
                comp_surface_toggle_fullscreen(seat->comp->focused_surface);
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
        }
        if (sel == 5) {
            /* "About Futura" — show about dialog overlay */
            seat->comp->about_active = true;
            comp_damage_add_full(seat->comp);
            seat->comp->needs_repaint = true;
        }
        /* Don't process this click further if menu was open */
        return;
    }

    /* Left-click on "Futura" branding → toggle Futura menu.
     * Hit-zone must match the renderer in comp.c:
     *   brand_w = 10 (diamond) + 6 * UI_FONT_WIDTH + 10 = 68
     *   brand_rect = { x=4, y=2, w=68, h=MENUBAR_HEIGHT-4 }
     * The click condition was hard-coded to pointer_x < 60, so the right
     * 12px of the visible "Futura" label silently did nothing.
     * Lower bound was missing too, so a click at x=0..3 (left of the
     * visible label) toggled the menu. Match the renderer's hover
     * region exactly. */
    if (code == FUT_BTN_LEFT && pressed && seat->comp &&
        seat->comp->pointer_y < 24 /* MENUBAR_HEIGHT */ &&
        seat->comp->pointer_x >= 4 &&
        seat->comp->pointer_x < 4 + (10 + 6 * 8 + 10)) {
        seat->comp->futura_menu_active = !seat->comp->futura_menu_active;
        seat->comp->futura_menu_hover = -1;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    seat_update_hover(seat);
    /* Don't forward decoration clicks (title bar, traffic-light buttons,
     * resize edges) to the client — those zones are owned by the
     * compositor's server-side decorations, not the client surface, and
     * forwarding caused clients to receive spurious button events on
     * pixels they don't render. Only forward content-area clicks. */
    {
        struct comp_surface *hit = NULL;
        resize_edge_t edge = RSZ_NONE;
        hit_role_t role = comp_hit_test(seat->comp,
                                        seat->comp->pointer_x,
                                        seat->comp->pointer_y,
                                        &hit, &edge);
        (void)edge; (void)hit;
        if (role == HIT_BAR || role == HIT_CLOSE ||
            role == HIT_MINIMIZE || role == HIT_MAXIMIZE ||
            role == HIT_RESIZE) {
            return;
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
#define COMP_MOD_SHIFT (1u << 3)

/* Translate compositor_mods bits into the XKB layout that
 * wl_keyboard.modifiers expects:
 *   bit 0 = Shift, bit 2 = Ctrl, bit 3 = Mod1 (Alt), bit 6 = Mod4 (Super).
 * Without this, clients see all-zero mods and Ctrl/Alt/Shift detection
 * (Ctrl+S in wl-edit, Ctrl+C in wl-term, etc.) silently fails. */
static uint32_t compositor_mods_to_xkb(void) {
    uint32_t m = 0;
    if (compositor_mods & COMP_MOD_SHIFT) m |= (1u << 0);
    if (compositor_mods & COMP_MOD_CTRL)  m |= (1u << 2);
    if (compositor_mods & COMP_MOD_ALT)   m |= (1u << 3);
    if (compositor_mods & COMP_MOD_SUPER) m |= (1u << 6);
    return m;
}

/* Send the current modifier state to all clients with keyboard focus on
 * the focused surface. Called whenever a modifier key transition happens. */
static void seat_send_current_modifiers(struct seat_state *seat) {
    if (!seat || !seat->keyboard_focus || !seat->keyboard_focus->surface_resource)
        return;
    struct wl_client *target = wl_resource_get_client(seat->keyboard_focus->surface_resource);
    uint32_t serial = wl_display_next_serial(seat->comp->display);
    uint32_t xkb = compositor_mods_to_xkb();
    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->keyboard_resource || !client->keyboard_entered) continue;
        if (wl_resource_get_client(client->keyboard_resource) != target) continue;
        wl_keyboard_send_modifiers(client->keyboard_resource, serial, xkb, 0, 0, 0);
    }
}

/* Launch a new terminal instance */
static void compositor_launch_terminal(void) {
    long pid = sys_fork_call();
    if (pid == 0) {
        /* Child: exec wl-term */
        char *argv[] = { "/bin/wl-term", (void*)0 };
        /* XDG_RUNTIME_DIR must match the dir the compositor actually
         * bound the wayland-0 socket in (set by platform_init: /run).
         * Hardcoding /tmp here meant children opened /tmp/wayland-0
         * and got ENOENT instead of connecting. */
        char *envp[] = { "WAYLAND_DISPLAY=wayland-0", "XDG_RUNTIME_DIR=/run",
                         "TERM=xterm-256color", "PATH=/bin:/sbin",
                         "TZ_OFFSET_SEC=-25200", (void*)0 };
        sys_execve_call("/bin/wl-term", argv, envp);
        sys_exit(127);
    }
}

/* Launch the text editor */
static void compositor_launch_edit(void) {
    long pid = sys_fork_call();
    if (pid == 0) {
        char *argv[] = { "/bin/wl-edit", (void*)0 };
        char *envp[] = { "WAYLAND_DISPLAY=wayland-0", "XDG_RUNTIME_DIR=/run",
                         "PATH=/bin:/sbin", "TZ_OFFSET_SEC=-25200", (void*)0 };
        sys_execve_call("/bin/wl-edit", argv, envp);
        sys_exit(127);
    }
}

/* Launch the task manager */
static void compositor_launch_sysmon(void) {
    long pid = sys_fork_call();
    if (pid == 0) {
        char *argv[] = { "/bin/wl-sysmon", (void*)0 };
        char *envp[] = { "WAYLAND_DISPLAY=wayland-0", "XDG_RUNTIME_DIR=/run",
                         "PATH=/bin:/sbin", "TZ_OFFSET_SEC=-25200", (void*)0 };
        sys_execve_call("/bin/wl-sysmon", argv, envp);
        sys_exit(127);
    }
}

/* Launch the file manager */
static void compositor_launch_files(void) {
    long pid = sys_fork_call();
    if (pid == 0) {
        char *argv[] = { "/bin/wl-files", (void*)0 };
        char *envp[] = { "WAYLAND_DISPLAY=wayland-0", "XDG_RUNTIME_DIR=/run",
                         "PATH=/bin:/sbin", "HOME=/", "TZ_OFFSET_SEC=-25200", (void*)0 };
        sys_execve_call("/bin/wl-files", argv, envp);
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

    /* Any key dismisses shortcut overlay */
    if (pressed && seat->comp && seat->comp->shortcut_overlay_active) {
        seat->comp->shortcut_overlay_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    /* Escape dismisses Futura menu */
    if (pressed && keycode == 1 && seat->comp && seat->comp->futura_menu_active) {
        seat->comp->futura_menu_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    /* Escape cancels an in-flight Alt+Tab without committing focus to the
     * highlighted window. The Alt-release path commits otherwise. */
    if (pressed && keycode == 1 && seat->comp && seat->comp->alt_tab_active) {
        seat->comp->alt_tab_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        return;
    }

    /* Escape or any key dismisses about dialog */
    if (pressed && seat->comp && seat->comp->about_active) {
        seat->comp->about_active = false;
        comp_damage_add_full(seat->comp);
        seat->comp->needs_repaint = true;
        if (keycode == 1) return;  /* Escape: consume the key */
    }

    /* Track modifier keys */
    bool mods_changed = false;
    if (keycode == 29 || keycode == 97) {  /* Left/Right Ctrl */
        if (pressed) compositor_mods |= COMP_MOD_CTRL;
        else compositor_mods &= ~COMP_MOD_CTRL;
        mods_changed = true;
    }
    if (keycode == 56 || keycode == 100) {  /* Left/Right Alt */
        if (pressed) {
            compositor_mods |= COMP_MOD_ALT;
            mods_changed = true;
        } else {
            compositor_mods &= ~COMP_MOD_ALT;
            mods_changed = true;
            /* Alt released: commit alt-tab selection */
            if (seat->comp && seat->comp->alt_tab_active) {
                seat->comp->alt_tab_active = false;
                /* Focus the selected window */
                int idx = 0;
                struct comp_surface *target = NULL;
                struct comp_surface *s;
                wl_list_for_each(s, &seat->comp->surfaces, link) {
                    if (!s->has_backing || s->minimized) continue;
                    if (idx == seat->comp->alt_tab_index) { target = s; break; }
                    idx++;
                }
                if (target) {
                    comp_surface_raise(seat->comp, target);
                    seat_focus_surface(seat, target);
                }
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
        }
    }
    if (keycode == 125 || keycode == 126) {  /* Super/Meta */
        if (pressed) compositor_mods |= COMP_MOD_SUPER;
        else compositor_mods &= ~COMP_MOD_SUPER;
        mods_changed = true;
    }
    if (keycode == 42 || keycode == 54) {  /* Left/Right Shift */
        if (pressed) compositor_mods |= COMP_MOD_SHIFT;
        else compositor_mods &= ~COMP_MOD_SHIFT;
        mods_changed = true;
    }
    if (mods_changed) {
        seat_send_current_modifiers(seat);
    }

    /* Compositor keybindings (consumed, not forwarded to clients).
     * For shortcut equality checks, mask out Shift so accidental Shift
     * combinations (e.g. Super+Shift+D) still trigger. The Alt+Tab path
     * below explicitly inspects Shift for reverse cycling. */
    uint32_t mods_no_shift = compositor_mods & ~COMP_MOD_SHIFT;
    if (pressed) {
        /* Ctrl+Alt+T or Super+Enter: launch new terminal */
        if ((mods_no_shift == (COMP_MOD_CTRL | COMP_MOD_ALT) && keycode == 20 /* T */) ||
            (mods_no_shift == COMP_MOD_SUPER && keycode == 28 /* Enter */)) {
            compositor_launch_terminal();
            return;
        }

        /* Alt+Tab: show window switcher overlay and cycle */
        if ((compositor_mods & COMP_MOD_ALT) && keycode == 15 /* Tab */) {
            if (seat->comp) {
                /* Count switchable windows */
                int count = 0;
                struct comp_surface *s;
                wl_list_for_each(s, &seat->comp->surfaces, link) {
                    if (s->has_backing && !s->minimized) count++;
                }
                /* Cap to the renderer's visible cap so the highlight ring
                 * stays in sync with what's actually drawn. Cycling past the
                 * last visible item otherwise advanced an (invisible)
                 * selection past the overlay; on Alt release the focus
                 * jumped to a window the user couldn't see was selected.
                 * The renderer further trims if 8 items don't fit on the
                 * current display (e.g. 1024-wide); match that here. */
                if (count > ALT_TAB_MAX_VISIBLE) count = ALT_TAB_MAX_VISIBLE;
                {
                    /* Mirror the comp.c renderer: 16px breathing room each
                     * side, TAB_PAD=16, TAB_ITEM_W=140, TAB_ITEM_PAD=10. */
                    int32_t fb_w = (int32_t)seat->comp->fb_info.width;
                    int max_fit = (fb_w - 32 - 32 + 10) / (140 + 10);
                    if (max_fit < 1) max_fit = 1;
                    if (count > max_fit) count = max_fit;
                }
                if (count > 0) {
                    bool reverse = (compositor_mods & COMP_MOD_SHIFT) != 0;
                    if (!seat->comp->alt_tab_active) {
                        /* First press: activate switcher. Dismiss any
                         * other modal UI (Futura menu, desktop ctx menu,
                         * shortcut overlay, about dialog) so only the
                         * Alt+Tab overlay is visible. */
                        seat->comp->futura_menu_active = false;
                        seat->comp->ctx_menu_active = false;
                        seat->comp->shortcut_overlay_active = false;
                        seat->comp->about_active = false;
                        /* Forward: start at index 1 (next window).
                         * Reverse (shift+alt+tab): start at last index. */
                        seat->comp->alt_tab_active = true;
                        seat->comp->alt_tab_count = count;
                        if (count > 1) {
                            seat->comp->alt_tab_index = reverse ? (count - 1) : 1;
                        } else {
                            seat->comp->alt_tab_index = 0;
                        }
                    } else {
                        /* Subsequent Tab press: advance/retreat index */
                        if (reverse) {
                            seat->comp->alt_tab_index =
                                (seat->comp->alt_tab_index + count - 1) % count;
                        } else {
                            seat->comp->alt_tab_index = (seat->comp->alt_tab_index + 1) % count;
                        }
                    }
                    comp_damage_add_full(seat->comp);
                    seat->comp->needs_repaint = true;
                }
            }
            return;
        }

        /* Super+D: toggle show-desktop (minimize/restore all windows) */
        if (mods_no_shift == COMP_MOD_SUPER && keycode == 32 /* D */) {
            if (seat->comp) {
                bool any_visible = false;
                struct comp_surface *s;
                wl_list_for_each(s, &seat->comp->surfaces, link) {
                    if (s->has_backing && !s->minimized)
                        any_visible = true;
                }
                wl_list_for_each(s, &seat->comp->surfaces, link) {
                    if (s->has_backing)
                        comp_surface_set_minimized(s, any_visible);
                }
                seat->comp->dock_all_minimized = any_visible;
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
            return;
        }

        /* Super+Arrow: window tiling / snap */
        if (mods_no_shift == COMP_MOD_SUPER && seat->comp && seat->comp->focused_surface) {
            struct comp_surface *sf = seat->comp->focused_surface;
            int32_t fw = (int32_t)seat->comp->fb_info.width;
            int32_t fh = (int32_t)seat->comp->fb_info.height;

            if (keycode == 75 /* Left arrow */) {
                /* Tile to left half */
                if (sf->maximized) comp_surface_set_maximized(sf, false);
                if (sf->fullscreen) comp_surface_set_fullscreen(sf, false);
                /* Only capture pre-tile geometry if we're not already in a
                 * tiled/saved state — otherwise tile-left → tile-right
                 * overwrites the original rect, leaving Super+Down with no
                 * way to restore the user's actual window position. */
                if (!sf->have_saved_geom) {
                    sf->saved_x = sf->x; sf->saved_y = sf->y;
                    sf->saved_w = sf->width;
                    /* saved_h is the *content* height across the codebase
                     * (matches comp_surface_set_maximized + drag-snap), so
                     * the unified restore in Super+Down doesn't need any
                     * bar_height arithmetic. */
                    sf->saved_h = sf->content_height;
                    sf->have_saved_geom = true;
                }
                int32_t tile_y = 24 /* MENUBAR_HEIGHT */;
                int32_t tile_h = fh - 24 /* MENUBAR_HEIGHT */ - 48;
                int32_t tile_w = fw / 2;
                comp_update_surface_position(seat->comp, sf, 0, tile_y);
                int32_t content_h = tile_h - sf->bar_height;
                if (content_h < 1) content_h = 1;
                xdg_shell_surface_send_configure(sf, tile_w, content_h,
                    comp_surface_state_flags(sf));
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
                return;
            }
            if (keycode == 77 /* Right arrow */) {
                /* Tile to right half */
                if (sf->maximized) comp_surface_set_maximized(sf, false);
                if (sf->fullscreen) comp_surface_set_fullscreen(sf, false);
                if (!sf->have_saved_geom) {
                    sf->saved_x = sf->x; sf->saved_y = sf->y;
                    sf->saved_w = sf->width;
                    /* saved_h is the *content* height across the codebase
                     * (matches comp_surface_set_maximized + drag-snap), so
                     * the unified restore in Super+Down doesn't need any
                     * bar_height arithmetic. */
                    sf->saved_h = sf->content_height;
                    sf->have_saved_geom = true;
                }
                int32_t tile_y = 24 /* MENUBAR_HEIGHT */;
                int32_t tile_h = fh - 24 /* MENUBAR_HEIGHT */ - 48;
                int32_t tile_w = fw / 2;
                comp_update_surface_position(seat->comp, sf, fw - tile_w, tile_y);
                int32_t content_h = tile_h - sf->bar_height;
                if (content_h < 1) content_h = 1;
                xdg_shell_surface_send_configure(sf, tile_w, content_h,
                    comp_surface_state_flags(sf));
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
                return;
            }
            if (keycode == 72 /* Up arrow */) {
                /* Maximize */
                if (!sf->maximized) {
                    comp_surface_set_maximized(sf, true);
                    comp_damage_add_full(seat->comp);
                    seat->comp->needs_repaint = true;
                }
                return;
            }
            if (keycode == 80 /* Down arrow */) {
                /* Restore from maximized/tiled */
                if (sf->maximized) {
                    comp_surface_set_maximized(sf, false);
                } else if (sf->have_saved_geom) {
                    comp_update_surface_position(seat->comp, sf, sf->saved_x, sf->saved_y);
                    /* saved_h is content height (see set_maximized/drag-snap);
                     * pass it straight through to configure. */
                    int32_t content_h = sf->saved_h;
                    if (content_h < 1) content_h = 1;
                    xdg_shell_surface_send_configure(sf, sf->saved_w, content_h,
                        comp_surface_state_flags(sf));
                    sf->have_saved_geom = false;
                }
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
                return;
            }
        }

        /* Super+/: toggle shortcut overlay */
        if (mods_no_shift == COMP_MOD_SUPER && keycode == 53 /* / */) {
            if (seat->comp) {
                bool now_on = !seat->comp->shortcut_overlay_active;
                seat->comp->shortcut_overlay_active = now_on;
                /* On activation, dismiss other modal UIs so only the
                 * overlay is visible. */
                if (now_on) {
                    seat->comp->futura_menu_active = false;
                    seat->comp->ctx_menu_active = false;
                    seat->comp->about_active = false;
                    seat->comp->alt_tab_active = false;
                }
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
            return;
        }

        /* F11: toggle fullscreen on focused window */
        if (keycode == 87 /* F11 */) {
            if (seat->comp && seat->comp->focused_surface) {
                comp_surface_toggle_fullscreen(seat->comp->focused_surface);
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
            return;
        }

        /* Super+M: minimize focused window */
        if (mods_no_shift == COMP_MOD_SUPER && keycode == 50 /* M */) {
            if (seat->comp && seat->comp->focused_surface) {
                comp_surface_set_minimized(seat->comp->focused_surface, true);
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
            return;
        }

        /* Super+Q: close focused window */
        if (mods_no_shift == COMP_MOD_SUPER && keycode == 16 /* Q */) {
            if (seat->comp && seat->comp->focused_surface) {
                struct comp_surface *s = seat->comp->focused_surface;
                if (s->xdg_toplevel) {
                    xdg_shell_toplevel_send_close(s);
                }
            }
            return;
        }

        /* Super+F: toggle fullscreen for focused window */
        if (mods_no_shift == COMP_MOD_SUPER && keycode == 33 /* F */) {
            if (seat->comp && seat->comp->focused_surface) {
                comp_surface_toggle_fullscreen(seat->comp->focused_surface);
                comp_damage_add_full(seat->comp);
                seat->comp->needs_repaint = true;
            }
            return;
        }

        /* Super+I: show system info toast */
        if (mods_no_shift == COMP_MOD_SUPER && keycode == 23 /* I */) {
            if (seat->comp) {
                int32_t w = (int32_t)seat->comp->fb_info.width;
                int32_t h = (int32_t)seat->comp->fb_info.height;
                int n_win = 0;
                struct comp_surface *ws;
                wl_list_for_each(ws, &seat->comp->surfaces, link) {
                    if (ws->has_backing) n_win++;
                }
                char info[128];
                int ci = 0;
                const char *prefix = "Horizon | ";
                while (*prefix) info[ci++] = *prefix++;
                /* Resolution: WxH */
                if (w >= 1000) info[ci++] = '0' + (char)(w / 1000);
                if (w >= 100)  info[ci++] = '0' + (char)((w / 100) % 10);
                info[ci++] = '0' + (char)((w / 10) % 10);
                info[ci++] = '0' + (char)(w % 10);
                info[ci++] = 'x';
                if (h >= 1000) info[ci++] = '0' + (char)(h / 1000);
                if (h >= 100)  info[ci++] = '0' + (char)((h / 100) % 10);
                info[ci++] = '0' + (char)((h / 10) % 10);
                info[ci++] = '0' + (char)(h % 10);
                const char *mid = " | Windows: ";
                while (*mid) info[ci++] = *mid++;
                if (n_win >= 10) info[ci++] = '0' + (char)(n_win / 10);
                info[ci++] = '0' + (char)(n_win % 10);
                info[ci] = '\0';
                comp_show_toast(seat->comp, info);
            }
            return;
        }

        /* Alt+F4: close focused window */
        if ((compositor_mods & COMP_MOD_ALT) && keycode == 62 /* F4 */) {
            if (seat->comp && seat->comp->focused_surface) {
                struct comp_surface *s = seat->comp->focused_surface;
                if (s->xdg_toplevel) {
                    xdg_shell_toplevel_send_close(s);
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

/* wl_pointer.set_cursor is a v1 request that GTK/Qt and most toolkits
 * call on pointer enter to swap the cursor surface. We don't render
 * client-supplied cursors yet, but the handler must be non-NULL so
 * libwayland-server doesn't dispatch through a NULL pointer and crash
 * the compositor. */
static void seat_pointer_set_cursor(struct wl_client *client,
                                    struct wl_resource *resource,
                                    uint32_t serial,
                                    struct wl_resource *surface,
                                    int32_t hotspot_x,
                                    int32_t hotspot_y) {
    (void)client; (void)resource; (void)serial;
    (void)surface; (void)hotspot_x; (void)hotspot_y;
}

static const struct wl_pointer_interface pointer_impl = {
    .set_cursor = seat_pointer_set_cursor,
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
    if (seat && seat->keyboard_focus && seat->keyboard_focus->surface_resource) {
        struct wl_client *focus_client =
            wl_resource_get_client(seat->keyboard_focus->surface_resource);
        if (focus_client == client) {
            uint32_t serial = wl_display_next_serial(seat->comp->display);
            struct wl_array empty;
            wl_array_init(&empty);
            wl_keyboard_send_enter(keyboard, serial,
                                   seat->keyboard_focus->surface_resource, &empty);
            wl_array_release(&empty);
            wl_keyboard_send_modifiers(keyboard, serial,
                                       compositor_mods_to_xkb(), 0, 0, 0);
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

    if (client->seat->pointer_focus &&
        client->seat->pointer_focus->surface_resource &&
        wl_resource_get_client(client->seat->pointer_focus->surface_resource) ==
            wl_resource_get_client(resource)) {
        seat_pointer_leave(client->seat);
    }

    if (client->seat->keyboard_focus &&
        client->seat->keyboard_focus->surface_resource &&
        wl_resource_get_client(client->seat->keyboard_focus->surface_resource) ==
            wl_resource_get_client(resource)) {
        struct comp_surface *leaving = client->seat->keyboard_focus;
        seat_keyboard_leave(client->seat, leaving);
        client->seat->keyboard_focus = NULL;
        client->seat->comp->focused_surface = NULL;
        /* Hand focus to the next visible window. Without this, if
         * libwayland tears down the seat resource before the per-
         * surface destroy listeners run, focus stays NULL and the
         * desktop ends up with no keyboard target even though other
         * windows are still visible. seat_surface_destroyed has the
         * same fallback for the symmetric case where surfaces are
         * destroyed first. */
        if (!wl_list_empty(&client->seat->comp->surfaces)) {
            struct comp_surface *other;
            wl_list_for_each_reverse(other, &client->seat->comp->surfaces, link) {
                if (other != leaving && other->has_backing && !other->minimized) {
                    seat_focus_surface(client->seat, other);
                    break;
                }
            }
        }
    }

    seat_client_destroy(client);
}

/* wl_seat.get_touch: we have no touch input, but a client calling
 * get_touch must not dispatch through a NULL function pointer. Create
 * a wl_touch resource with a release-only implementation so the
 * client can still bind/destroy it; we just never send events on it. */
static void seat_touch_release(struct wl_client *client,
                               struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct wl_touch_interface touch_impl = {
    .release = seat_touch_release,
};

static void seat_get_touch(struct wl_client *client,
                           struct wl_resource *resource,
                           uint32_t id) {
    uint32_t version = wl_resource_get_version(resource);
    struct wl_resource *touch =
        wl_resource_create(client, &wl_touch_interface, version, id);
    if (!touch) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(touch, &touch_impl, NULL, NULL);
}

static const struct wl_seat_interface seat_impl = {
    .get_pointer = seat_get_pointer,
    .get_keyboard = seat_get_keyboard,
    .get_touch = seat_get_touch,
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
        /* Focus next visible window. Must check has_backing too — a
         * surface that hasn't committed a buffer yet has nothing to
         * focus on visually, and every other "find next focus target"
         * path in this file already gates on both flags. */
        if (!wl_list_empty(&seat->comp->surfaces)) {
            struct comp_surface *other;
            wl_list_for_each_reverse(other, &seat->comp->surfaces, link) {
                if (other != surface && other->has_backing && !other->minimized) {
                    seat_focus_surface(seat, other);
                    break;
                }
            }
        }
    }

    if (seat->hover_btn_surface == surface) {
        seat_clear_button_hover(seat);
    }
    if (seat->hover_min_btn_surface == surface) {
        seat_clear_min_button_hover(seat);
    }
    if (seat->hover_max_btn_surface == surface) {
        seat_clear_max_button_hover(seat);
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
