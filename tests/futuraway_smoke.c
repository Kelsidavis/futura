// SPDX-License-Identifier: MPL-2.0
// futuraway_smoke.c - Validate Futuraway M1 compositor rendering

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>
#include <kernel/fut_hmac.h>

#include "../src/user/futurawayd/futurawayd.h"
#include "../src/user/futurawayd/fw_demo.h"
#include "../src/user/svc_registryd/registry_client.h"
#include "../src/user/svc_registryd/registry_server.h"
#include "../src/user/sys/fipc_idlv0_codegen.h"
#include "../src/user/sys/fipc_sys.h"

#define FWAY_SMOKE_SERVICE "futurawayd"
#define FWAY_SMOKE_REG_PORT 27991
#define FWAY_DUMP_PATH "build/artifacts/futuraway_fb_000.ppm"

struct registry_ctx {
    struct registryd *daemon;
    bool running;
};

static void *registry_thread(void *arg) {
    struct registry_ctx *ctx = (struct registry_ctx *)arg;
    while (ctx->running) {
        (void)registryd_poll_once(ctx->daemon, 10);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static struct fut_fipc_channel *ensure_system_channel(void) {
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (channel) {
        return channel;
    }
    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_NONBLOCKING,
                                &channel) != 0 || !channel) {
        return NULL;
    }
    channel->id = FIPC_SYS_CHANNEL_ID;
    channel->type = FIPC_CHANNEL_SYSTEM;
    return channel;
}

static int sha256_file(const char *path, uint8_t digest[FUT_SHA256_DIGEST_LEN]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return -errno;
    }
    fut_sha256_ctx ctx;
    fut_sha256_init(&ctx);

    uint8_t buffer[4096];
    size_t read_bytes = 0;
    while ((read_bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        fut_sha256_update(&ctx, buffer, read_bytes);
    }
    if (ferror(file)) {
        int err = errno;
        fclose(file);
        return -err;
    }
    fut_sha256_final(&ctx, digest);
    fclose(file);
    return 0;
}

#define FIPC_FWAY_TABLE(M)            \
    M(FIPC_FWAY_EVT, evt)             \
    M(FIPC_FWAY_SURF_ID, surface_id)  \
    M(FIPC_FWAY_CLIENT_PID, client)   \
    M(FIPC_FWAY_T_START, t_start)     \
    M(FIPC_FWAY_T_END, t_end)         \
    M(FIPC_FWAY_DUR_MS, duration)

FIPC_IDL_DEF_STRUCT(fway_view, FIPC_FWAY_TABLE)
FIPC_IDL_DEF_DECODE_BOUNDED(fway_view,
                            FIPC_FWAY_TABLE,
                            FIPC_FWAY_BEGIN,
                            FIPC_FWAY_END)

static int wait_for_commit(struct fut_fipc_channel *sys_channel,
                           uint64_t expected_surface) {
    uint8_t buffer[512];
    const struct timespec delay = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000 };

    for (int i = 0; i < 400; ++i) {
        ssize_t rc = fut_fipc_recv(sys_channel, buffer, sizeof(buffer));
        if (rc > 0) {
            struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
            if (msg->type != FIPC_SYS_MSG_FWAY_METRICS) {
                continue;
            }
            fway_view view;
            if (fway_view_decode(msg->payload, msg->length, &view) != 0) {
                continue;
            }
            if (view.evt == FIPC_FWAY_SURFACE_COMMIT &&
                view.surface_id == expected_surface) {
                return 0;
            }
        } else if (rc != FIPC_EAGAIN) {
            break;
        }
        nanosleep(&delay, NULL);
    }
    return -1;
}

struct compositor_thread_args {
    struct futurawayd_config cfg;
    int rc;
};

static void *compositor_entry(void *arg) {
    struct compositor_thread_args *args = (struct compositor_thread_args *)arg;
    args->rc = futurawayd_run(&args->cfg);
    return NULL;
}

int main(void) {
    fut_fipc_init();

    struct registryd *reg = registryd_start(FWAY_SMOKE_REG_PORT);
    if (!reg) {
        fprintf(stderr, "[FWAY-SMOKE] registry start failed\n");
        return 1;
    }

    struct registry_ctx reg_ctx = { .daemon = reg, .running = true };
    pthread_t reg_thread;
    if (pthread_create(&reg_thread, NULL, registry_thread, &reg_ctx) != 0) {
        fprintf(stderr, "[FWAY-SMOKE] registry thread launch failed\n");
        registryd_stop(reg);
        return 1;
    }

    struct compositor_thread_args comp_args = {
        .cfg = {
            .width = 800,
            .height = 600,
            .dump_path = FWAY_DUMP_PATH,
            .service_name = FWAY_SMOKE_SERVICE,
            .registry_host = "127.0.0.1",
            .registry_port = FWAY_SMOKE_REG_PORT,
            .frame_limit = 1,
        },
        .rc = -1,
    };

    pthread_t comp_thread;
    if (pthread_create(&comp_thread, NULL, compositor_entry, &comp_args) != 0) {
        fprintf(stderr, "[FWAY-SMOKE] compositor thread launch failed\n");
        reg_ctx.running = false;
        pthread_join(reg_thread, NULL);
        registryd_stop(reg);
        return 1;
    }

    struct fw_demo_config demo_cfg = {
        .width = 800,
        .height = 600,
        .service_name = FWAY_SMOKE_SERVICE,
        .registry_host = "127.0.0.1",
        .registry_port = FWAY_SMOKE_REG_PORT,
        .surface_id = 1,
    };

    if (fw_demo_run(&demo_cfg) != 0) {
        fprintf(stderr, "[FWAY-SMOKE] demo execution failed\n");
        reg_ctx.running = false;
        pthread_join(comp_thread, NULL);
        pthread_join(reg_thread, NULL);
        registryd_stop(reg);
        return 1;
    }

    pthread_join(comp_thread, NULL);
    reg_ctx.running = false;
    pthread_join(reg_thread, NULL);
    registryd_stop(reg);

    if (comp_args.rc != 0) {
        fprintf(stderr, "[FWAY-SMOKE] compositor returned %d\n", comp_args.rc);
        return 1;
    }

    uint8_t digest[FUT_SHA256_DIGEST_LEN];
    if (sha256_file(FWAY_DUMP_PATH, digest) != 0) {
        fprintf(stderr, "[FWAY-SMOKE] unable to hash framebuffer dump\n");
        return 1;
    }

    static const uint8_t expected[FUT_SHA256_DIGEST_LEN] = {
        0x83, 0xFC, 0x74, 0x73, 0xA5, 0xDA, 0xB7, 0x38,
        0x88, 0x10, 0x47, 0x06, 0xFA, 0x73, 0x9F, 0x8B,
        0x12, 0xA1, 0xB7, 0x78, 0x5D, 0x2D, 0xCF, 0x24,
        0x29, 0xEB, 0x9A, 0xA7, 0xA5, 0x35, 0x09, 0xED
    };

    if (memcmp(digest, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "[FWAY-SMOKE] framebuffer hash mismatch\n");
        return 1;
    }

    struct fut_fipc_channel *sys_channel = ensure_system_channel();
    if (!sys_channel) {
        fprintf(stderr, "[FWAY-SMOKE] missing system channel\n");
        return 1;
    }

    if (wait_for_commit(sys_channel, demo_cfg.surface_id) != 0) {
        fprintf(stderr, "[FWAY-SMOKE] missing FWAY commit metric\n");
        return 1;
    }

    printf("[FWAY-SMOKE] framebuffer hash + metrics — PASS\n");
    return 0;
}
