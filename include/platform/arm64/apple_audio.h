/* apple_audio.h - Apple Silicon Audio Subsystem Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Audio playback/capture via Apple MCA (Multi-Channel Audio) controller.
 * Uses I2C for codec (speaker amplifier) configuration.
 */

#ifndef __FUTURA_APPLE_AUDIO_H__
#define __FUTURA_APPLE_AUDIO_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* Audio sample formats */
#define AUDIO_FMT_S16LE   0  /* 16-bit signed, little-endian */
#define AUDIO_FMT_S24LE   1  /* 24-bit signed, little-endian */
#define AUDIO_FMT_S32LE   2  /* 32-bit signed, little-endian */

/* Audio stream state */
typedef struct {
    uint32_t sample_rate;    /* Sample rate in Hz */
    uint8_t  channels;       /* Number of channels (1=mono, 2=stereo) */
    uint8_t  format;         /* Sample format (AUDIO_FMT_*) */
    bool     playing;        /* Playback active */
    bool     capturing;      /* Capture active */
} apple_audio_state_t;

/* PCM buffer descriptor */
typedef struct {
    void     *data;          /* Buffer pointer (page-aligned) */
    uint32_t  size;          /* Buffer size in bytes */
    uint32_t  write_pos;     /* Current write position */
    uint32_t  read_pos;      /* Current read position (DMA) */
} apple_audio_buffer_t;

/**
 * Initialize the Apple audio subsystem.
 * @param info: Platform information
 * @return: 0 on success, negative on failure
 */
int apple_audio_init(const fut_platform_info_t *info);

/**
 * Configure audio stream parameters.
 * @param sample_rate: Sample rate (44100, 48000, 96000)
 * @param channels: Number of channels (1 or 2)
 * @param format: Sample format (AUDIO_FMT_*)
 * @return: 0 on success
 */
int apple_audio_configure(uint32_t sample_rate, uint8_t channels, uint8_t format);

/**
 * Start audio playback.
 * @return: 0 on success
 */
int apple_audio_play_start(void);

/**
 * Stop audio playback.
 * @return: 0 on success
 */
int apple_audio_play_stop(void);

/**
 * Write PCM samples to the playback buffer.
 * @param data: Sample data
 * @param len: Data length in bytes
 * @return: Bytes written
 */
int apple_audio_write(const void *data, uint32_t len);

/**
 * Get current audio state.
 */
int apple_audio_get_state(apple_audio_state_t *state);

/**
 * Set output volume (0-100).
 */
int apple_audio_set_volume(uint8_t volume);

/**
 * Platform integration entry point.
 */
int apple_audio_platform_init(const fut_platform_info_t *info);

#endif /* __FUTURA_APPLE_AUDIO_H__ */
