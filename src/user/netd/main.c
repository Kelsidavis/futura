/* main.c - netd entry point
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include "netd_core.h"

#include <kernel/fut_fipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void netd_usage(const char *prog) {
    fprintf(stderr, "Usage: %s --listen <addr:port>\n", prog);
}

static int parse_endpoint(const char *value, char *host_out, size_t host_len, uint16_t *port_out) {
    const char *colon = strchr(value, ':');
    if (!colon) {
        return -1;
    }

    size_t host_size = (size_t)(colon - value);
    if (host_size == 0 || host_size >= host_len) {
        return -1;
    }

    memcpy(host_out, value, host_size);
    host_out[host_size] = '\0';

    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) {
        return -1;
    }

    *port_out = (uint16_t)port;
    return 0;
}

int main(int argc, char **argv) {
    const char *listen_arg = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && (i + 1) < argc) {
            listen_arg = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            netd_usage(argv[0]);
            return 0;
        }
    }

    if (!listen_arg) {
        netd_usage(argv[0]);
        return 1;
    }

    char host[64];
    uint16_t port = 0;

    if (parse_endpoint(listen_arg, host, sizeof(host), &port) != 0) {
        fprintf(stderr, "[netd] invalid listen endpoint: %s\n", listen_arg);
        return 1;
    }

    fut_fipc_init();

    struct netd *nd = netd_bootstrap(host, port);
    if (!nd) {
        fprintf(stderr, "[netd] bootstrap failed\n");
        return 1;
    }

    while (netd_is_running(nd)) {
        if (!netd_poll_once(nd, 1000)) {
            break;
        }
    }

    netd_shutdown(nd);
    return 0;
}
