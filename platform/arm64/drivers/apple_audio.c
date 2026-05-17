/* apple_audio.c - Apple Silicon Audio Subsystem — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Audio playback via Apple MCA (Multi-Channel Audio) I2S controller
 * with an I2C-connected speaker-amplifier codec.  All MCA register
 * work — clock master programming, SERDES/FSYNC setup, TX FIFO push,
 * DMA-completion bookkeeping — lives in the Rust apple_mca crate
 * under drivers/rust/apple_mca.  This file is a thin glue layer that:
 *
 *   1. Owns the AppleMca handle (one cluster wired to the internal
 *      speakers on M1/M2 MacBooks) and the I2C handle to the codec.
 *   2. Maps the public format/channel/rate API onto rust_mca_setup_*.
 *   3. Walks a ring buffer of PCM samples into rust_mca_tx_write()
 *      in polled mode.
 *   4. Keeps the codec init / volume writes in C — they are pure
 *      I2C register pokes already going through rust_i2c.
 *
 * Compat note: apple_audio_platform_init() guards on
 * info->type == PLATFORM_APPLE_M[1-4] so RPi and QEMU virt boots
 * never reach the Rust MCA driver.
 */

#include <platform/arm64/apple_audio.h>
#include <platform/arm64/apple_i2c.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* Codec I2C address (typical speaker amplifier on Apple Silicon) */
#define CODEC_I2C_ADDR       0x38

/* Audio ring buffer size */
#define AUDIO_BUF_SIZE       (16 * 1024)  /* 16KB ring buffer */

/* MCA programming constants.  Cluster 0 is wired to the internal
 * speakers on M1/M2 MacBooks.  MCLK source 0 is the SoC's audio PLL
 * fed at ~24 MHz on shipping silicon — matches the previous C code's
 * 24 MHz reference clock. */
#define MCA_SPEAKER_CLUSTER  0u
#define MCA_MCLK_SEL         0u
#define MCA_MCLK_HZ          24000000u

/* Static state */
static struct {
    AppleMca *mca;
    AppleI2c *codec_i2c;

    apple_audio_state_t state;
    apple_audio_buffer_t play_buf;

    bool initialized;
    uint8_t volume;        /* 0-100 */
    uint32_t cluster;      /* MCA cluster index (0 for speakers) */
} g_audio;

/* ============================================================
 *   Codec (Speaker Amplifier) Configuration
 * ============================================================ */

static int codec_write_reg(uint8_t reg, uint8_t val) {
    if (!g_audio.codec_i2c) return -1;
    uint8_t buf[2] = { reg, val };
    return rust_i2c_write(g_audio.codec_i2c, CODEC_I2C_ADDR, buf, 2);
}

static int codec_init(void) {
    if (!g_audio.codec_i2c) return -1;

    /* Reset codec */
    codec_write_reg(0x00, 0x01);  /* Software reset */

    /* Wait for reset */
    for (volatile int i = 0; i < 10000; i++);

    /* Configure for I2S input, speaker output */
    codec_write_reg(0x01, 0x00);  /* Power up */
    codec_write_reg(0x02, 0x0A);  /* I2S mode, 16-bit */
    codec_write_reg(0x03, 0x00);  /* Sample rate auto-detect */
    codec_write_reg(0x04, 0xCF);  /* Volume: default to ~80% */

    fut_printf("[AUDIO] Codec initialized at I2C addr 0x%02x\n", CODEC_I2C_ADDR);
    return 0;
}

/* ============================================================
 *   Public API
 * ============================================================ */

int apple_audio_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    memset(&g_audio, 0, sizeof(g_audio));
    g_audio.volume = 80;
    g_audio.cluster = MCA_SPEAKER_CLUSTER;

    /* MCA base would come from the DTB (/arm-io/mca on Apple Silicon).
     * The platform_info struct does not surface it yet; until DTB
     * parsing wires that up, the driver stays in "probed but not
     * active" mode — no Rust MCA handle, write() returns success but
     * silently drops audio. */
    g_audio.mca = NULL;

    /* Initialize I2C for codec */
    if (info->i2c0_base != 0) {
        g_audio.codec_i2c = rust_i2c_init(info->i2c0_base);
    }

    /* Allocate playback buffer */
    g_audio.play_buf.data = fut_malloc_pages(AUDIO_BUF_SIZE / 4096);
    if (!g_audio.play_buf.data) {
        fut_printf("[AUDIO] Failed to allocate playback buffer\n");
        return -1;
    }
    g_audio.play_buf.size = AUDIO_BUF_SIZE;
    memset(g_audio.play_buf.data, 0, AUDIO_BUF_SIZE);

    /* Set defaults */
    g_audio.state.sample_rate = 48000;
    g_audio.state.channels = 2;
    g_audio.state.format = AUDIO_FMT_S16LE;

    g_audio.initialized = true;
    fut_printf("[AUDIO] Apple audio subsystem initialized (Rust MCA)\n");

    /* Initialize codec if I2C is available */
    if (g_audio.codec_i2c) {
        codec_init();
    }

    return 0;
}

int apple_audio_configure(uint32_t sample_rate, uint8_t channels, uint8_t format) {
    if (!g_audio.initialized) return -1;
    if (g_audio.state.playing) return -16;  /* EBUSY */

    g_audio.state.sample_rate = sample_rate;
    g_audio.state.channels = channels;
    g_audio.state.format = format;

    /* Re-program MCA for the new sample rate, only if a handle exists.
     * The Rust crate handles MCLK divider computation, SERDES/FSYNC
     * programming, and clock enable internally. */
    if (g_audio.mca) {
        int rc = rust_mca_setup_playback(g_audio.mca, g_audio.cluster,
                                         MCA_MCLK_SEL, MCA_MCLK_HZ,
                                         sample_rate);
        if (rc != 0) {
            fut_printf("[AUDIO] rust_mca_setup_playback failed: %d\n", rc);
            return rc;
        }
    }

    fut_printf("[AUDIO] Configured: %uHz, %uch, fmt=%u\n",
               sample_rate, channels, format);
    return 0;
}

int apple_audio_play_start(void) {
    if (!g_audio.initialized) return -1;
    if (g_audio.state.playing) return 0;

    /* If we hold an MCA handle but configure() was never called,
     * push a default setup so the cluster is ready to accept data. */
    if (g_audio.mca) {
        int rc = rust_mca_setup_playback(g_audio.mca, g_audio.cluster,
                                         MCA_MCLK_SEL, MCA_MCLK_HZ,
                                         g_audio.state.sample_rate);
        if (rc != 0) {
            fut_printf("[AUDIO] rust_mca_setup_playback (start) failed: %d\n", rc);
            return rc;
        }
    }

    g_audio.state.playing = true;
    g_audio.play_buf.read_pos = 0;
    g_audio.play_buf.write_pos = 0;

    return 0;
}

int apple_audio_play_stop(void) {
    if (!g_audio.initialized) return -1;
    if (!g_audio.state.playing) return 0;

    if (g_audio.mca) {
        rust_mca_stop(g_audio.mca, g_audio.cluster);
    }

    g_audio.state.playing = false;
    return 0;
}

int apple_audio_write(const void *data, uint32_t len) {
    if (!g_audio.initialized || !data || len == 0) return -1;

    uint8_t *buf = (uint8_t *)g_audio.play_buf.data;
    uint32_t size = g_audio.play_buf.size;
    uint32_t written = 0;

    while (written < len) {
        uint32_t space = (g_audio.play_buf.read_pos - g_audio.play_buf.write_pos - 1 + size) % size;
        if (space == 0) break;

        uint32_t chunk = len - written;
        if (chunk > space) chunk = space;

        /* Write to ring buffer */
        uint32_t to_end = size - g_audio.play_buf.write_pos;
        if (chunk <= to_end) {
            memcpy(buf + g_audio.play_buf.write_pos, (const uint8_t *)data + written, chunk);
        } else {
            memcpy(buf + g_audio.play_buf.write_pos, (const uint8_t *)data + written, to_end);
            memcpy(buf, (const uint8_t *)data + written + to_end, chunk - to_end);
        }

        g_audio.play_buf.write_pos = (g_audio.play_buf.write_pos + chunk) % size;
        written += chunk;
    }

    /* Push samples to MCA TX FIFO if playing.  Polled-mode: hand a
     * contiguous u32 slice to the Rust crate each pass and let it
     * gate on its own FIFO-level check. */
    if (g_audio.state.playing && g_audio.mca) {
        while (g_audio.play_buf.read_pos != g_audio.play_buf.write_pos) {
            /* Find the largest contiguous run of u32 samples that
             * doesn't wrap the ring buffer. */
            uint32_t run_bytes;
            if (g_audio.play_buf.write_pos > g_audio.play_buf.read_pos) {
                run_bytes = g_audio.play_buf.write_pos - g_audio.play_buf.read_pos;
            } else {
                run_bytes = size - g_audio.play_buf.read_pos;
            }
            uint32_t run_samples = run_bytes / 4;
            if (run_samples == 0) break;

            const uint32_t *src = (const uint32_t *)(buf + g_audio.play_buf.read_pos);
            int32_t pushed = rust_mca_tx_write(g_audio.mca, g_audio.cluster,
                                               src, (uint64_t)run_samples);
            if (pushed <= 0) break;  /* FIFO full or error — try next poll */

            g_audio.play_buf.read_pos = (g_audio.play_buf.read_pos + ((uint32_t)pushed * 4)) % size;
        }
    }

    return (int)written;
}

int apple_audio_get_state(apple_audio_state_t *state) {
    if (!g_audio.initialized || !state) return -1;
    *state = g_audio.state;
    return 0;
}

int apple_audio_set_volume(uint8_t volume) {
    if (!g_audio.initialized) return -1;
    if (volume > 100) volume = 100;
    g_audio.volume = volume;

    /* Map 0-100 to codec volume register range */
    if (g_audio.codec_i2c) {
        uint8_t codec_vol = (uint8_t)((volume * 255) / 100);
        codec_write_reg(0x04, codec_vol);
    }

    return 0;
}

int apple_audio_platform_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }

    return apple_audio_init(info);
}
