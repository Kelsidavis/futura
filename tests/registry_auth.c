// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/user/svc_registryd/registry_server.h"
#include "../src/user/svc_registryd/registry_client.h"

struct poller_ctx {
    struct registryd *rd;
    bool running;
};

static void *registry_poller(void *arg) {
    struct poller_ctx *ctx = (struct poller_ctx *)arg;
    while (ctx->running) {
        (void)registryd_poll_once(ctx->rd, 10);
    }
    return NULL;
}

int main(void) {
    const char *host = "127.0.0.1";
    uint16_t port = 29001;

    struct registryd *rd = registryd_start(port);
    if (!rd) {
        fprintf(stderr, "[REG-AUTH] registryd_start failed\n");
        return 1;
    }

    struct poller_ctx ctx = {
        .rd = rd,
        .running = true,
    };
    pthread_t th;
    if (pthread_create(&th, NULL, registry_poller, &ctx) != 0) {
        fprintf(stderr, "[REG-AUTH] failed to spawn poller\n");
        registryd_stop(rd);
        return 1;
    }

    uint64_t channel = 0;
    if (registry_client_lookup_with_key(host, port, "svc.none", &channel, NULL) == 0) {
        fprintf(stderr, "[REG-AUTH] unauthenticated lookup unexpectedly succeeded\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }

    if (registry_client_register(host, port, "svc.demo", 0xABCDEFULL) != 0) {
        fprintf(stderr, "[REG-AUTH] authenticated register failed\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }

    if (registry_client_lookup(host, port, "svc.demo", &channel) != 0 || channel != 0xABCDEFULL) {
        fprintf(stderr, "[REG-AUTH] authenticated lookup failed\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }

    uint8_t new_key[SRG_KEY_LEN];
    uint8_t old_key[SRG_KEY_LEN];
    memcpy(old_key, (uint8_t[])SRG_KEY_DEFAULT_CURRENT_INIT, SRG_KEY_LEN);
    for (size_t i = 0; i < SRG_KEY_LEN; ++i) {
        new_key[i] = (uint8_t)(old_key[i] ^ 0x5Au);
    }

    if (registryd_set_keys(rd, new_key, old_key, 100) != 0) {
        fprintf(stderr, "[REG-AUTH] registryd_set_keys failed\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }
    registry_client_set_keys(new_key, old_key, 100);

    if (registry_client_lookup_with_key(host, port, "svc.demo", &channel, old_key) != 0) {
        fprintf(stderr, "[REG-AUTH] old key not accepted within grace window\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }

    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 200000000L,
    };
    nanosleep(&ts, NULL);

    if (registry_client_lookup_with_key(host, port, "svc.demo", &channel, old_key) == 0) {
        fprintf(stderr, "[REG-AUTH] old key accepted after grace window\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }

    if (registry_client_lookup(host, port, "svc.demo", &channel) != 0 || channel != 0xABCDEFULL) {
        fprintf(stderr, "[REG-AUTH] new key lookup failed\n");
        ctx.running = false;
        pthread_join(th, NULL);
        registryd_stop(rd);
        return 1;
    }

    ctx.running = false;
    pthread_join(th, NULL);
    registryd_stop(rd);

    printf("[REG-AUTH] registry auth + key rotation — PASS\n");
    return 0;
}
