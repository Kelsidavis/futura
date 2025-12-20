#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <wayland-server-core.h>
#include <wayland-util.h>

#include "comp.h"

struct comp_surface;
struct seat_state;

struct seat_client {
    struct seat_state *seat;
    struct wl_resource *seat_resource;
    struct wl_resource *pointer_resource;
    struct wl_resource *keyboard_resource;
    struct wl_resource *data_device_resource;
    struct wl_resource *current_offer;
    bool pointer_entered;
    bool keyboard_entered;
    bool offer_has_mime;
    char offer_mime[64];
    struct wl_list link;
};

struct seat_state {
    struct compositor_state *comp;
    struct wl_global *global;
    struct wl_event_source *kbd_source;
    bool kbd_source_registered;  /* Track if kbd_source is registered with event loop */
    struct wl_event_source *mouse_source;
    bool mouse_source_registered;  /* Track if mouse_source is registered with event loop */
    int kbd_fd;
    int mouse_fd;
    struct wl_list clients;
    struct comp_surface *pointer_focus;
    struct comp_surface *keyboard_focus;
    int32_t pointer_sx;
    int32_t pointer_sy;
    bool left_button_down;
    bool middle_button_down;
    bool right_button_down;
    struct comp_surface *hover_btn_surface;
    struct comp_surface *hover_min_btn_surface;
    struct comp_surface *pressed_surface;
    hit_role_t pressed_role;
    resize_edge_t pressed_edge;
    uint32_t last_click_time;
    struct comp_surface *last_click_surface;
    comp_selection_t selection;
    struct wl_listener selection_destroy_listener;
};

struct seat_state *seat_init(struct compositor_state *comp);
void seat_finish(struct seat_state *seat);
void seat_poll_input(struct seat_state *seat);
void seat_surface_destroyed(struct seat_state *seat, struct comp_surface *surface);
struct seat_client *seat_client_lookup(struct seat_state *seat, struct wl_client *client);
