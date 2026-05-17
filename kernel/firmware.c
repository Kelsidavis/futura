/* firmware.c - Kernel firmware blob loader
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implementation of include/kernel/firmware.h.  Two layers:
 *
 *   1. A fixed-size provider table (FUT_FIRMWARE_PROVIDER_MAX
 *      entries).  Each provider is a probe function; fut_firmware_load
 *      walks them in registration order.
 *
 *   2. A built-in "embedded" provider, auto-registered on first call.
 *      Drivers (or build-time tooling) push (name, data, size) into
 *      a small static table via fut_firmware_embed().  Useful for the
 *      handful of small blobs that ship inside the kernel image —
 *      typically per-machine NVRAM/calibration data, not the multi-
 *      hundred-KB firmware payloads themselves.
 *
 * The FS-backed provider (which reads /lib/firmware/<name> off the
 * root filesystem) is intentionally absent.  It will be wired in once
 * Apple Silicon boots far enough to have a filesystem mounted at
 * platform init time.  Until then, drivers that need large blobs will
 * see -ENOENT and should log clearly that firmware loading is the
 * blocker — never silently bring the device up with stale state.
 */

#include <kernel/firmware.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <string.h>

#define FUT_FIRMWARE_PROVIDER_MAX  4

static fut_firmware_probe_fn g_providers[FUT_FIRMWARE_PROVIDER_MAX];
static unsigned int          g_num_providers;

/* Embedded provider state. */
struct embedded_entry {
    char        name[FUT_FIRMWARE_NAME_MAX];
    const void *data;
    size_t      size;
};
static struct embedded_entry g_embedded[FUT_FIRMWARE_EMBEDDED_MAX];
static unsigned int          g_num_embedded;
static int                   g_embedded_registered;  /* 0/1 */

static int embedded_probe(const char *name,
                          const void **out_data,
                          size_t *out_size)
{
    for (unsigned int i = 0; i < g_num_embedded; i++) {
        if (strncmp(g_embedded[i].name, name, FUT_FIRMWARE_NAME_MAX) == 0) {
            *out_data = g_embedded[i].data;
            *out_size = g_embedded[i].size;
            return 0;
        }
    }
    return -ENOENT;
}

static void ensure_embedded_registered(void)
{
    if (g_embedded_registered) return;
    g_embedded_registered = 1;
    /* Use the public registration path so the embedded provider sits
     * in the same table as any future provider. */
    fut_firmware_register_provider(embedded_probe);
}

int fut_firmware_register_provider(fut_firmware_probe_fn probe)
{
    if (!probe) return -EINVAL;

    /* Idempotent — same callback twice is a no-op. */
    for (unsigned int i = 0; i < g_num_providers; i++) {
        if (g_providers[i] == probe) return 0;
    }

    if (g_num_providers >= FUT_FIRMWARE_PROVIDER_MAX) return -ENOMEM;
    g_providers[g_num_providers++] = probe;
    return 0;
}

int fut_firmware_load(const char *name,
                      const void **out_data,
                      size_t *out_size)
{
    if (!name || !out_data || !out_size) return -EINVAL;

    ensure_embedded_registered();

    *out_data = NULL;
    *out_size = 0;

    int last_err = -ENOENT;
    for (unsigned int i = 0; i < g_num_providers; i++) {
        int rc = g_providers[i](name, out_data, out_size);
        if (rc == 0) return 0;
        if (rc != -ENOENT) {
            /* Hard failure — surface it but keep trying other
             * providers in case one of them has it.  Remember the
             * first hard error to return if nobody else has it. */
            if (last_err == -ENOENT) last_err = rc;
        }
    }
    return last_err;
}

void fut_firmware_reset_providers(void)
{
    g_num_providers = 0;
    g_embedded_registered = 0;
    g_num_embedded = 0;
}

int fut_firmware_embed(const char *name, const void *data, size_t size)
{
    if (!name || !data || size == 0) return -EINVAL;
    if (g_num_embedded >= FUT_FIRMWARE_EMBEDDED_MAX) return -ENOMEM;

    /* Reject duplicates — if a driver re-embeds the same name, it
     * almost certainly means a build-time wiring mistake. */
    for (unsigned int i = 0; i < g_num_embedded; i++) {
        if (strncmp(g_embedded[i].name, name, FUT_FIRMWARE_NAME_MAX) == 0) {
            return -EEXIST;
        }
    }

    size_t name_len = 0;
    while (name[name_len] != '\0' && name_len < FUT_FIRMWARE_NAME_MAX - 1) {
        name_len++;
    }
    memcpy(g_embedded[g_num_embedded].name, name, name_len);
    g_embedded[g_num_embedded].name[name_len] = '\0';
    g_embedded[g_num_embedded].data = data;
    g_embedded[g_num_embedded].size = size;
    g_num_embedded++;

    ensure_embedded_registered();
    return 0;
}

int fut_firmware_embed_binary(const char *name,
                              const void *blob_start,
                              const void *blob_end)
{
    if (!blob_start || !blob_end) return -EINVAL;
    if (blob_end < blob_start) return -EINVAL;
    size_t size = (size_t)((const char *)blob_end - (const char *)blob_start);
    if (size == 0) return -EINVAL;
    return fut_firmware_embed(name, blob_start, size);
}

unsigned int fut_firmware_provider_count(void) { return g_num_providers; }
unsigned int fut_firmware_embed_count(void)    { return g_num_embedded; }
