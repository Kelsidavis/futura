#include "data_device.h"

#include "comp.h"
#include "log.h"
#include "seat.h"

#include <stdlib.h>
#include <user/libfutura.h>

#include <wayland-server.h>

#include <user/sys.h>

struct data_source {
    struct seat_state *seat;
    struct wl_resource *resource;
    bool has_mime;
    char mime[64];
};

struct data_offer {
    struct seat_state *seat;
    struct seat_client *client;
    struct wl_resource *resource;
};

static struct wl_global *g_data_device_global;

static bool mime_supported(const char *mime) {
    if (!mime) {
        return false;
    }
    return strcmp(mime, WAYLAND_CLIPBOARD_MIME) == 0;
}

static void data_offer_resource_destroy(struct wl_resource *resource);
static void data_offer_destroy_request(struct wl_client *client,
                                       struct wl_resource *resource);

static void clear_client_offer(struct seat_client *client) {
    if (!client) {
        return;
    }
    if (!client->current_offer) {
        client->offer_has_mime = false;
        client->offer_mime[0] = '\0';
        return;
    }
    struct wl_resource *offer = client->current_offer;
    client->current_offer = NULL;
    client->offer_has_mime = false;
    client->offer_mime[0] = '\0';
    wl_resource_set_user_data(offer, NULL);
    wl_resource_destroy(offer);
}

static void selection_broadcast_clear(struct seat_state *seat) {
    if (!seat) {
        return;
    }

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (client->data_device_resource) {
            wl_data_device_send_selection(client->data_device_resource, NULL);
        }
        clear_client_offer(client);
    }
}

static void selection_clear(struct seat_state *seat) {
    if (!seat || !seat->selection.source) {
        return;
    }

    if (seat->selection_destroy_listener.link.prev) {
        wl_list_remove(&seat->selection_destroy_listener.link);
        seat->selection_destroy_listener.link.prev = NULL;
        seat->selection_destroy_listener.link.next = NULL;
    }

    seat->selection.source = NULL;
    seat->selection.mime[0] = '\0';
    seat->selection.serial = 0;

    selection_broadcast_clear(seat);
}

static void selection_destroy_notify(struct wl_listener *listener, void *data) {
    (void)data;
    struct seat_state *seat = wl_container_of(listener, seat, selection_destroy_listener);
    selection_clear(seat);
}

static void selection_send_to_fd(struct seat_state *seat, int fd) {
    if (!seat || fd < 0) {
        if (fd >= 0) {
            sys_close(fd);
        }
        return;
    }

    if (!seat->selection.source || seat->selection.mime[0] == '\0') {
        sys_close(fd);
        return;
    }

    wl_data_source_send_send(seat->selection.source, seat->selection.mime, fd);

#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] send selection to fd=%d mime=%s\n", fd, seat->selection.mime);
#endif

    sys_close(fd);
}

static void offer_handle_receive(struct wl_client *client,
                                 struct wl_resource *resource,
                                 const char *mime,
                                 int32_t fd);

static void data_offer_accept(struct wl_client *client,
                              struct wl_resource *resource,
                              uint32_t serial,
                              const char *mime_type) {
    (void)client;
    (void)resource;
    (void)serial;
    (void)mime_type;
}

static const struct wl_data_offer_interface data_offer_impl = {
    .accept = data_offer_accept,
    .receive = offer_handle_receive,
    .destroy = data_offer_destroy_request,
};

static void create_data_offer_for(struct seat_state *seat,
                                  struct seat_client *client,
                                  struct data_source *source) {
    if (!seat || !client || !client->data_device_resource || !source) {
        return;
    }

    clear_client_offer(client);

    struct wl_client *target = wl_resource_get_client(client->data_device_resource);
    uint32_t version = (uint32_t)wl_resource_get_version(client->data_device_resource);
    uint32_t offer_id = wl_display_next_serial(seat->comp->display);

    struct wl_resource *offer_res = wl_resource_create(target,
                                                       &wl_data_offer_interface,
                                                       (int)version,
                                                       offer_id);
    if (!offer_res) {
        wl_client_post_no_memory(target);
        return;
    }

    struct data_offer *offer = calloc(1, sizeof(*offer));
    if (!offer) {
        wl_client_post_no_memory(target);
        wl_resource_destroy(offer_res);
        return;
    }

    offer->seat = seat;
    offer->client = client;
    offer->resource = offer_res;

    wl_resource_set_implementation(offer_res, &data_offer_impl, offer, data_offer_resource_destroy);

    wl_data_device_send_data_offer(client->data_device_resource, offer_res);
    wl_data_offer_send_offer(offer_res, source->mime);
    wl_data_device_send_selection(client->data_device_resource, offer_res);

    client->current_offer = offer_res;
    client->offer_has_mime = true;
    strncpy(client->offer_mime, source->mime, sizeof(client->offer_mime) - 1);
    client->offer_mime[sizeof(client->offer_mime) - 1] = '\0';

#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] offer -> client=%p mime=%s\n", (void *)target, source->mime);
#endif
}

static void selection_broadcast(struct seat_state *seat,
                                struct data_source *source) {
    if (!seat || !source) {
        return;
    }

    struct wl_client *owner = wl_resource_get_client(source->resource);

    struct seat_client *client;
    wl_list_for_each(client, &seat->clients, link) {
        if (!client->data_device_resource) {
            continue;
        }
        if (wl_resource_get_client(client->data_device_resource) == owner) {
            continue;
        }
        create_data_offer_for(seat, client, source);
    }
}

static void selection_set(struct seat_state *seat,
                          struct data_source *source,
                          uint32_t serial) {
    if (!seat) {
        return;
    }

    if (!source || !source->has_mime) {
        selection_clear(seat);
        return;
    }

    if (seat->selection_destroy_listener.link.prev) {
        wl_list_remove(&seat->selection_destroy_listener.link);
        seat->selection_destroy_listener.link.prev = NULL;
        seat->selection_destroy_listener.link.next = NULL;
    }

    seat->selection.source = source->resource;
    strncpy(seat->selection.mime, source->mime, sizeof(seat->selection.mime) - 1);
    seat->selection.mime[sizeof(seat->selection.mime) - 1] = '\0';
    seat->selection.serial = serial;

    source->seat = seat;
    seat->selection_destroy_listener.notify = selection_destroy_notify;
    wl_resource_add_destroy_listener(source->resource, &seat->selection_destroy_listener);

    selection_broadcast_clear(seat);
    selection_broadcast(seat, source);

#ifdef DEBUG_WAYLAND
    WLOG("[WAYLAND] selection set owner=%p serial=%u\n",
         (void *)wl_resource_get_client(source->resource), serial);
#endif
}

static void offer_handle_receive(struct wl_client *client,
                                 struct wl_resource *resource,
                                 const char *mime,
                                 int32_t fd) {
    (void)client;
    struct data_offer *offer = wl_resource_get_user_data(resource);
    if (!offer || !offer->seat) {
        if (fd >= 0) {
            sys_close(fd);
        }
        return;
    }

    if (!mime_supported(mime)) {
        sys_close(fd);
        return;
    }

    selection_send_to_fd(offer->seat, fd);
}

static void data_offer_resource_destroy(struct wl_resource *resource) {
    struct data_offer *offer = wl_resource_get_user_data(resource);
    if (!offer) {
        return;
    }

    if (offer->client && offer->client->current_offer == resource) {
        offer->client->current_offer = NULL;
        offer->client->offer_has_mime = false;
        offer->client->offer_mime[0] = '\0';
    }

    free(offer);
}

static void data_offer_destroy_request(struct wl_client *client,
                                       struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void data_source_offer(struct wl_client *client,
                              struct wl_resource *resource,
                              const char *mime_type) {
    (void)client;
    struct data_source *source = wl_resource_get_user_data(resource);
    if (!source) {
        return;
    }

    if (!mime_supported(mime_type)) {
        return;
    }

    strncpy(source->mime, mime_type, sizeof(source->mime) - 1);
    source->mime[sizeof(source->mime) - 1] = '\0';
    source->has_mime = true;
}

static void data_source_destroy_request(struct wl_client *client,
                                        struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static void data_source_resource_destroy(struct wl_resource *resource) {
    struct data_source *source = wl_resource_get_user_data(resource);
    if (source && source->seat && source->seat->selection.source == resource) {
        selection_clear(source->seat);
    }
    free(source);
}

static const struct wl_data_source_interface data_source_impl = {
    .offer = data_source_offer,
    .destroy = data_source_destroy_request,
};

static void data_device_start_drag(struct wl_client *client,
                                   struct wl_resource *resource,
                                   struct wl_resource *src,
                                   struct wl_resource *origin,
                                   struct wl_resource *icon,
                                   uint32_t serial) {
    (void)client;
    (void)resource;
    (void)src;
    (void)origin;
    (void)icon;
    (void)serial;
}

static void data_device_set_selection(struct wl_client *client,
                                      struct wl_resource *resource,
                                      struct wl_resource *source_res,
                                      uint32_t serial) {
    (void)client;
    struct seat_client *seat_client = wl_resource_get_user_data(resource);
    if (!seat_client) {
        return;
    }
    struct seat_state *seat = seat_client->seat;

    if (!source_res) {
        selection_clear(seat);
        return;
    }

    struct data_source *source = wl_resource_get_user_data(source_res);
    if (!source || !source->has_mime) {
        return;
    }

    selection_set(seat, source, serial);
}

static void data_device_release(struct wl_client *client,
                                struct wl_resource *resource) {
    (void)client;
    wl_resource_destroy(resource);
}

static const struct wl_data_device_interface data_device_impl = {
    .start_drag = data_device_start_drag,
    .set_selection = data_device_set_selection,
    .release = data_device_release,
};

static void data_device_resource_destroy(struct wl_resource *resource) {
    struct seat_client *client = wl_resource_get_user_data(resource);
    if (!client) {
        return;
    }
    if (client->current_offer) {
        struct wl_resource *offer = client->current_offer;
        client->current_offer = NULL;
        client->offer_has_mime = false;
        client->offer_mime[0] = '\0';
        wl_resource_destroy(offer);
    }
    client->data_device_resource = NULL;
}

static void manager_create_data_source(struct wl_client *client,
                                       struct wl_resource *resource,
                                       uint32_t id) {
    int version = wl_resource_get_version(resource);
    struct wl_resource *res = wl_resource_create(client,
                                                 &wl_data_source_interface,
                                                 version,
                                                 id);
    if (!res) {
        wl_client_post_no_memory(client);
        return;
    }

    struct data_source *source = calloc(1, sizeof(*source));
    if (!source) {
        wl_client_post_no_memory(client);
        wl_resource_destroy(res);
        return;
    }

    source->resource = res;
    wl_resource_set_implementation(res, &data_source_impl, source, data_source_resource_destroy);
}

static void manager_get_data_device(struct wl_client *client,
                                    struct wl_resource *resource,
                                    uint32_t id,
                                    struct wl_resource *seat_resource) {
    (void)resource;
    if (!seat_resource) {
        wl_client_post_no_memory(client);
        return;
    }

    struct seat_state *seat = wl_resource_get_user_data(seat_resource);
    if (!seat) {
        wl_client_post_no_memory(client);
        return;
    }

    struct seat_client *seat_client = seat_client_lookup(seat, client);
    if (!seat_client) {
        wl_client_post_no_memory(client);
        return;
    }

    int version = wl_resource_get_version(resource);
    struct wl_resource *dev = wl_resource_create(client,
                                                 &wl_data_device_interface,
                                                 version,
                                                 id);
    if (!dev) {
        wl_client_post_no_memory(client);
        return;
    }

    seat_client->data_device_resource = dev;
    wl_resource_set_implementation(dev, &data_device_impl, seat_client, data_device_resource_destroy);

    if (seat->selection.source && seat->selection.mime[0] != '\0') {
        struct data_source *source = wl_resource_get_user_data(seat->selection.source);
        if (source) {
            create_data_offer_for(seat, seat_client, source);
        }
    }
}

static const struct wl_data_device_manager_interface manager_impl = {
    .create_data_source = manager_create_data_source,
    .get_data_device = manager_get_data_device,
};

static void data_device_manager_bind(struct wl_client *client,
                                     void *data,
                                     uint32_t version,
                                     uint32_t id) {
    (void)data;
    uint32_t ver = version > 1 ? 1 : version;
    struct wl_resource *res = wl_resource_create(client,
                                                 &wl_data_device_manager_interface,
                                                 (int)ver,
                                                 id);
    if (!res) {
        wl_client_post_no_memory(client);
        return;
    }
    wl_resource_set_implementation(res, &manager_impl, NULL, NULL);
}

int data_device_manager_init(struct compositor_state *comp) {
    if (!comp || !comp->display) {
        return -1;
    }
    g_data_device_global = wl_global_create(comp->display,
                                            &wl_data_device_manager_interface,
                                            1,
                                            NULL,
                                            data_device_manager_bind);
    return g_data_device_global ? 0 : -1;
}

void data_device_manager_finish(struct compositor_state *comp) {
    (void)comp;
    if (g_data_device_global) {
        wl_global_destroy(g_data_device_global);
        g_data_device_global = NULL;
    }
}

void data_device_seat_init(struct seat_state *seat) {
    if (!seat) {
        return;
    }
    seat->selection.source = NULL;
    seat->selection.mime[0] = '\0';
    seat->selection.serial = 0;
    seat->selection_destroy_listener.link.prev = NULL;
    seat->selection_destroy_listener.link.next = NULL;
    seat->selection_destroy_listener.notify = selection_destroy_notify;
}

void data_device_seat_finish(struct seat_state *seat) {
    if (!seat) {
        return;
    }
    selection_clear(seat);
}

void data_device_client_init(struct seat_client *client) {
    if (!client) {
        return;
    }
    client->data_device_resource = NULL;
    client->current_offer = NULL;
    client->offer_has_mime = false;
    client->offer_mime[0] = '\0';
}

void data_device_client_cleanup(struct seat_client *client) {
    if (!client) {
        return;
    }
    clear_client_offer(client);
    if (client->data_device_resource) {
        struct wl_resource *res = client->data_device_resource;
        client->data_device_resource = NULL;
        wl_resource_set_user_data(res, NULL);
        wl_resource_destroy(res);
    }
}

void data_device_selection_source_destroyed(struct seat_state *seat,
                                            struct wl_resource *source) {
    if (!seat || seat->selection.source != source) {
        return;
    }
    selection_clear(seat);
}
