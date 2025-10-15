#pragma once

#include <stdbool.h>
#include <stdint.h>

struct compositor_state;
struct seat_state;
struct seat_client;
struct wl_resource;

#define WAYLAND_CLIPBOARD_MIME "text/plain;charset=utf-8"

int data_device_manager_init(struct compositor_state *comp);
void data_device_manager_finish(struct compositor_state *comp);

void data_device_seat_init(struct seat_state *seat);
void data_device_seat_finish(struct seat_state *seat);

void data_device_client_init(struct seat_client *client);
void data_device_client_cleanup(struct seat_client *client);

void data_device_selection_source_destroyed(struct seat_state *seat,
                                            struct wl_resource *source);
