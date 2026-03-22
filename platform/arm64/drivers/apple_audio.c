/* apple_audio.c - Apple Silicon Audio Subsystem Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Audio playback via Apple MCA (Multi-Channel Audio) I2S controller
 * with I2C-connected speaker amplifier codec.
 *
 * MCA register layout (per cluster, offset = cluster * 0x200):
 *   0x000  MCLK_CONF   — MCLK divider configuration
 *   0x004  SW_RESET     — Software reset
 *   0x008  CLK_CONF     — Clock enable and source
 *   0x020  SERDES_CONF  — Serializer/deserializer format
 *   0x024  SERDES_WS    — Frame sync (FSYNC) period
 *   0x040  TX_CONF      — TX DMA configuration
 *   0x044  TX_WATERMARK — TX FIFO watermark
 *   0x048  TX_FIFO_LVL  — TX FIFO level
 *   0x080  TX_DATA      — TX FIFO data port
 *   0x0C0  RX_CONF      — RX DMA configuration
 *   0x100  RX_DATA      — RX FIFO data port
 *   0x200  STATUS       — Interrupt status
 *   0x204  IRQ_MASK     — Interrupt mask
 */

#include <platform/arm64/apple_audio.h>
#include <platform/arm64/apple_i2c.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* MCA register offsets (per cluster) */
#define MCA_CLUSTER_STRIDE  0x200
#define MCA_MCLK_CONF       0x000
#define MCA_SW_RESET         0x004
#define MCA_CLK_CONF         0x008
#define MCA_SERDES_CONF      0x020
#define MCA_SERDES_WS        0x024
#define MCA_TX_CONF          0x040
#define MCA_TX_WATERMARK     0x044
#define MCA_TX_FIFO_LVL      0x048
#define MCA_TX_DATA          0x080
#define MCA_STATUS           0x200
#define MCA_IRQ_MASK         0x204

/* MCA_CLK_CONF bits */
#define CLK_CONF_ENABLE       (1 << 0)
#define CLK_CONF_MCLK_EN      (1 << 1)

/* MCA_TX_CONF bits */
#define TX_CONF_ENABLE        (1 << 0)
#define TX_CONF_FIFO_RESET    (1 << 1)

/* MCA_SERDES_CONF: I2S format */
#define SERDES_I2S_16BIT     0x00000010
#define SERDES_I2S_24BIT     0x00000018
#define SERDES_I2S_32BIT     0x00000020

/* MCA_SW_RESET */
#define SW_RESET_ASSERT      (1 << 0)

/* Codec I2C address (typical speaker amplifier) */
#define CODEC_I2C_ADDR       0x38

/* Audio ring buffer size */
#define AUDIO_BUF_SIZE       (16 * 1024)  /* 16KB ring buffer */

/* Static state */
static struct {
    volatile uint8_t *mca_base;
    uint64_t mca_phys;
    AppleI2c *codec_i2c;

    apple_audio_state_t state;
    apple_audio_buffer_t play_buf;

    bool initialized;
    uint8_t volume;        /* 0-100 */
    uint32_t cluster;      /* MCA cluster index (0 for speakers) */
} g_audio;

/* ============================================================
 *   MCA Register Access
 * ============================================================ */

static inline uint32_t mca_read(uint32_t off) {
    return *((volatile uint32_t *)(g_audio.mca_base + g_audio.cluster * MCA_CLUSTER_STRIDE + off));
}

static inline void mca_write(uint32_t off, uint32_t val) {
    *((volatile uint32_t *)(g_audio.mca_base + g_audio.cluster * MCA_CLUSTER_STRIDE + off)) = val;
}

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

    /* MCA base would be parsed from DTB — use a sensible default.
     * On M1/M2 the MCA block is at different addresses per SoC.
     * For now we accept a zero base (driver probed but not active). */
    /* TODO: Parse /arm-io/mca from DTB when MCA is present */

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
    fut_printf("[AUDIO] Apple audio subsystem initialized\n");

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

    /* Configure MCA if base is available */
    if (g_audio.mca_base) {
        /* Reset MCA cluster */
        mca_write(MCA_SW_RESET, SW_RESET_ASSERT);
        for (volatile int i = 0; i < 1000; i++);
        mca_write(MCA_SW_RESET, 0);

        /* Set serializer format */
        uint32_t serdes;
        switch (format) {
            case AUDIO_FMT_S24LE: serdes = SERDES_I2S_24BIT; break;
            case AUDIO_FMT_S32LE: serdes = SERDES_I2S_32BIT; break;
            default:              serdes = SERDES_I2S_16BIT;  break;
        }
        mca_write(MCA_SERDES_CONF, serdes);

        /* Configure FSYNC period (samples per frame) */
        uint32_t ws_period = (channels == 1) ? 32 : 64;
        mca_write(MCA_SERDES_WS, ws_period - 1);

        /* Configure MCLK divider for target sample rate */
        /* MCLK = 24MHz / divider; BCLK = MCLK / (ws_period) */
        uint32_t mclk_div = 24000000 / (sample_rate * ws_period);
        if (mclk_div < 1) mclk_div = 1;
        mca_write(MCA_MCLK_CONF, mclk_div - 1);

        /* Enable clocks */
        mca_write(MCA_CLK_CONF, CLK_CONF_ENABLE | CLK_CONF_MCLK_EN);
    }

    fut_printf("[AUDIO] Configured: %uHz, %uch, fmt=%u\n",
               sample_rate, channels, format);
    return 0;
}

int apple_audio_play_start(void) {
    if (!g_audio.initialized) return -1;
    if (g_audio.state.playing) return 0;

    if (g_audio.mca_base) {
        /* Flush TX FIFO */
        mca_write(MCA_TX_CONF, TX_CONF_FIFO_RESET);
        mca_write(MCA_TX_CONF, 0);

        /* Set watermark (interrupt when FIFO is half empty) */
        mca_write(MCA_TX_WATERMARK, 8);

        /* Enable TX */
        mca_write(MCA_TX_CONF, TX_CONF_ENABLE);
    }

    g_audio.state.playing = true;
    g_audio.play_buf.read_pos = 0;
    g_audio.play_buf.write_pos = 0;

    return 0;
}

int apple_audio_play_stop(void) {
    if (!g_audio.initialized) return -1;
    if (!g_audio.state.playing) return 0;

    if (g_audio.mca_base) {
        mca_write(MCA_TX_CONF, 0);
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

    /* Push samples to MCA TX FIFO if playing */
    if (g_audio.state.playing && g_audio.mca_base) {
        while (g_audio.play_buf.read_pos != g_audio.play_buf.write_pos) {
            uint32_t fifo_lvl = mca_read(MCA_TX_FIFO_LVL) & 0x1F;
            if (fifo_lvl >= 16) break;  /* FIFO full */

            uint32_t sample;
            memcpy(&sample, buf + g_audio.play_buf.read_pos, 4);
            mca_write(MCA_TX_DATA, sample);
            g_audio.play_buf.read_pos = (g_audio.play_buf.read_pos + 4) % size;
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
