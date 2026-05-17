/* firmware.h - Kernel firmware blob loader
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Minimal request-firmware API for drivers that need to load
 * proprietary blobs (Broadcom WiFi, Apple AGX, etc.).  Providers
 * register a probe callback; fut_firmware_load walks them in
 * registration order until one returns success.
 *
 * Today there is a single embedded provider that serves blobs linked
 * into the kernel image at build time (via the FIRMWARE_BLOB macro
 * in a .c source file).  An FS-backed provider will appear once
 * Apple Silicon boots far enough to mount a filesystem with a
 * /lib/firmware directory.
 */

#ifndef __FUTURA_FIRMWARE_H__
#define __FUTURA_FIRMWARE_H__

#include <stddef.h>
#include <stdint.h>

#define FUT_FIRMWARE_NAME_MAX  64

/* Probe callback — given a NUL-terminated firmware name, populate
 * `*out_data` and `*out_size` with a read-only pointer to the blob
 * if the provider has it, then return 0.  Return -ENOENT if the
 * provider doesn't have this name (caller will try the next one).
 * Any other negative errno is a hard failure.
 *
 * The returned pointer must remain valid for the lifetime of the
 * kernel — i.e. providers either serve from .rodata or from a
 * permanent kernel allocation.  Drivers do NOT free the buffer. */
typedef int (*fut_firmware_probe_fn)(const char *name,
                                     const void **out_data,
                                     size_t *out_size);

/* Register a firmware provider.  Returns 0 on success or -ENOMEM if
 * the provider table is full.  Idempotent — registering the same
 * callback twice is a no-op (returns 0). */
int fut_firmware_register_provider(fut_firmware_probe_fn probe);

/* Look up a firmware blob by name.  Walks providers in registration
 * order; first one to return success wins.  Sets *out_data and
 * *out_size on success and returns 0.  Returns -ENOENT if no provider
 * has it, or the first hard failure a provider reported.
 *
 * `name` is a short identifier without path prefix or extension
 * (the provider decides how to map it to actual storage). */
int fut_firmware_load(const char *name,
                      const void **out_data,
                      size_t *out_size);

/* For tests / shutdown — wipe the provider table. */
void fut_firmware_reset_providers(void);

/* Helper used by the embedded provider's call sites.  Registers a
 * (name, data, size) triplet that fut_firmware_load can return.  Up
 * to FUT_FIRMWARE_EMBEDDED_MAX entries; returns -ENOMEM past that. */
#define FUT_FIRMWARE_EMBEDDED_MAX  16
int fut_firmware_embed(const char *name, const void *data, size_t size);

/* Convenience wrapper for blobs linked into the kernel image via
 * objcopy (-I binary -B …).  objcopy emits two symbols per input
 * file: `_binary_<sanitised_path>_start` and `_..._end`; pass both
 * to this helper and it computes size and forwards to
 * fut_firmware_embed.  Returns the same codes.  Useful for tiny
 * per-machine NVRAM tables that fit in the kernel image; large
 * firmware blobs should come from an FS provider instead. */
int fut_firmware_embed_binary(const char *name,
                              const void *blob_start,
                              const void *blob_end);

#endif /* __FUTURA_FIRMWARE_H__ */
