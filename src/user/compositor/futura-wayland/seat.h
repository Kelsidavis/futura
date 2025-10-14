#pragma once

#include <stdbool.h>
#include <stdint.h>

struct compositor_state;
struct comp_surface;
struct seat_state;

struct seat_state *seat_init(struct compositor_state *comp);
void seat_finish(struct seat_state *seat);
void seat_surface_destroyed(struct seat_state *seat, struct comp_surface *surface);
