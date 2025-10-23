/*
 * VideoCore IV GPU Driver for Raspberry Pi
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This header defines the GPU driver interface for VideoCore IV (VC4)
 * used in Raspberry Pi 3, and similar cores in RPi 4/5 (VC6).
 *
 * This is a port of the Linux vc4 DRM driver adapted for Futura OS.
 *
 * References:
 * - https://github.com/torvalds/linux/tree/master/drivers/gpu/drm/vc4
 * - https://github.com/raspberrypi/linux/tree/rpi-5.15.y/drivers/gpu/drm/vc4
 */

#ifndef __FUTURA_DRIVERS_GPU_VC4_H__
#define __FUTURA_DRIVERS_GPU_VC4_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================
 *   GPU Memory Address Mapping
 * ============================================================
 *
 * The VideoCore GPU has its own address space and memory organization.
 * Arm memory is mapped to VC address space via the mailbox interface.
 */

/* GPU memory allocation flags (from Linux vc4 driver) */
#define GPU_MEM_FLAG_DISCARDABLE    (1 << 0)  /* Can be discarded by GPU */
#define GPU_MEM_FLAG_NORMAL         (1 << 1)  /* Normal cached memory */
#define GPU_MEM_FLAG_DIRECT         (1 << 2)  /* Direct access from GPU */
#define GPU_MEM_FLAG_COHERENT       (1 << 3)  /* Cache coherent */
#define GPU_MEM_FLAG_L1_NONALLOC    (1 << 5)  /* L1 non-allocating */
#define GPU_MEM_FLAG_ZERO           (1 << 4)  /* Pre-zero memory */

/* ============================================================
 *   Display Modes and Resolution
 * ============================================================ */

/* Common display resolutions */
#define GPU_MODE_640x480            0
#define GPU_MODE_800x600            1
#define GPU_MODE_1024x768           2
#define GPU_MODE_1280x1024          3
#define GPU_MODE_1920x1080          4
#define GPU_MODE_1920x1200          5
#define GPU_MODE_2560x1440          6

/* Display mode information structure */
typedef struct {
    uint32_t width;         /* Horizontal resolution in pixels */
    uint32_t height;        /* Vertical resolution in pixels */
    uint32_t refresh_rate;  /* Refresh rate in Hz */
} gpu_display_mode_t;

/* ============================================================
 *   Framebuffer Configuration
 * ============================================================ */

/* Framebuffer pixel formats */
typedef enum {
    GPU_PIXEL_FORMAT_RGB565,    /* 16-bit RGB */
    GPU_PIXEL_FORMAT_RGB888,    /* 24-bit RGB */
    GPU_PIXEL_FORMAT_RGBA8888,  /* 32-bit RGBA */
    GPU_PIXEL_FORMAT_RGBX8888,  /* 32-bit RGB with padding */
} gpu_pixel_format_t;

/* Framebuffer rotation */
typedef enum {
    GPU_ROTATE_0,      /* No rotation */
    GPU_ROTATE_90,     /* 90 degrees clockwise */
    GPU_ROTATE_180,    /* 180 degrees */
    GPU_ROTATE_270,    /* 270 degrees clockwise */
} gpu_rotation_t;

/* Framebuffer configuration structure */
typedef struct {
    uint32_t width;             /* Framebuffer width in pixels */
    uint32_t height;            /* Framebuffer height in pixels */
    uint32_t virtual_width;     /* Virtual framebuffer width (for panning) */
    uint32_t virtual_height;    /* Virtual framebuffer height */
    uint32_t x_offset;          /* X offset for panning */
    uint32_t y_offset;          /* Y offset for panning */
    gpu_pixel_format_t format;  /* Pixel format */
    uint32_t depth;             /* Bits per pixel (16, 24, 32) */
    uint32_t pitch;             /* Bytes per scanline */
    uint32_t bus_address;       /* GPU bus address of framebuffer */
    uint32_t size;              /* Total size in bytes */
} gpu_framebuffer_t;

/* ============================================================
 *   V3D GPU Support (RPi4/5)
 * ============================================================
 *
 * The V3D core is the 3D graphics engine in RPi4/5.
 * This is a simplified interface for basic 3D support.
 */

/* V3D feature levels */
typedef enum {
    V3D_VERSION_33,  /* RPi4 (V3D 4.1) */
    V3D_VERSION_41,
    V3D_VERSION_42,  /* RPi5 (V3D 7.1) */
    V3D_VERSION_71,
} v3d_version_t;

/* V3D device information */
typedef struct {
    v3d_version_t version;
    uint32_t cache_line_size;
    uint32_t max_texture_size;
    uint32_t max_shader_size;
    uint32_t max_vertex_attributes;
} v3d_device_info_t;

/* ============================================================
 *   HDMI Output Support
 * ============================================================ */

/* HDMI modes */
typedef enum {
    HDMI_MODE_DVI,              /* DVI (digital only) */
    HDMI_MODE_HDMI,             /* HDMI (with audio) */
} hdmi_mode_t;

/* HDMI colorspace */
typedef enum {
    HDMI_COLORSPACE_RGB,        /* RGB colorspace */
    HDMI_COLORSPACE_YCBCR444,   /* YCbCr 4:4:4 */
    HDMI_COLORSPACE_YCBCR422,   /* YCbCr 4:2:2 */
} hdmi_colorspace_t;

/* EDID-based resolution structure */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_rate;
    bool interlaced;
} hdmi_resolution_t;

/* ============================================================
 *   HVS (Hardware Video Scaler) Configuration
 * ============================================================
 *
 * The HVS handles video scaling, compositing, and output formatting.
 */

/* Display channel configuration */
typedef struct {
    uint32_t channel;           /* Display channel (0, 1, or 2) */
    gpu_pixel_format_t format;  /* Output format */
    uint32_t width;
    uint32_t height;
    uint32_t x_offset;
    uint32_t y_offset;
} hvs_channel_config_t;

/* ============================================================
 *   GPU Driver State and Operations
 * ============================================================ */

/* GPU driver state */
typedef struct {
    /* Memory management */
    uint32_t gpu_memory_base;   /* GPU memory physical base */
    uint32_t gpu_memory_size;   /* GPU memory size */
    uint32_t arm_memory_base;   /* ARM memory physical base */
    uint32_t arm_memory_size;   /* ARM memory size */

    /* Display information */
    gpu_framebuffer_t framebuffer;
    uint32_t display_width;
    uint32_t display_height;
    uint32_t display_depth;

    /* V3D GPU support (RPi4/5) */
    bool v3d_available;
    v3d_device_info_t v3d_info;

    /* HDMI output */
    bool hdmi_connected;
    hdmi_resolution_t *edid_modes;
    uint32_t num_edid_modes;

    /* Status */
    bool initialized;
    uint32_t temperature;       /* Last read temperature (millidegrees C) */
} gpu_device_t;

/* ============================================================
 *   GPU Driver API
 * ============================================================ */

/* Initialize GPU driver */
int gpu_init(void);

/* Get GPU device state */
gpu_device_t *gpu_get_device(void);

/* Allocate DMA memory from GPU memory pool */
uint32_t gpu_mem_alloc(uint32_t size, uint32_t flags, uint32_t *vc_address);

/* Free previously allocated GPU memory */
void gpu_mem_free(uint32_t handle);

/* Lock GPU memory (prevent it from being moved/discarded) */
uint32_t gpu_mem_lock(uint32_t handle);

/* Unlock GPU memory */
void gpu_mem_unlock(uint32_t handle);

/* ============================================================
 *   Framebuffer Operations
 * ============================================================ */

/* Allocate and initialize framebuffer */
int gpu_framebuffer_allocate(uint32_t width, uint32_t height,
                              gpu_pixel_format_t format);

/* Release framebuffer */
void gpu_framebuffer_release(void);

/* Get framebuffer information */
const gpu_framebuffer_t *gpu_framebuffer_get(void);

/* Flush framebuffer cache for display */
void gpu_framebuffer_flush(uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height);

/* ============================================================
 *   Display Configuration
 * ============================================================ */

/* Enable display output */
int gpu_display_enable(uint32_t width, uint32_t height,
                       gpu_pixel_format_t format);

/* Disable display output */
void gpu_display_disable(void);

/* Get display resolution */
void gpu_display_get_resolution(uint32_t *width, uint32_t *height);

/* Set display palette (for indexed color modes) */
int gpu_display_set_palette(uint32_t *colors, uint32_t count);

/* ============================================================
 *   HDMI Support
 * ============================================================ */

/* Detect HDMI connection */
bool gpu_hdmi_detect(void);

/* Get HDMI EDID information */
int gpu_hdmi_get_edid(uint8_t *buffer, uint32_t size);

/* Get supported HDMI resolutions */
const hdmi_resolution_t *gpu_hdmi_get_modes(uint32_t *count);

/* Set HDMI output mode */
int gpu_hdmi_set_mode(uint32_t width, uint32_t height, uint32_t refresh);

/* ============================================================
 *   V3D Graphics (RPi4/5)
 * ============================================================ */

/* Check if V3D GPU is available */
bool gpu_v3d_available(void);

/* Get V3D device information */
const v3d_device_info_t *gpu_v3d_get_info(void);

/* Enable V3D GPU clock */
int gpu_v3d_clock_enable(uint32_t rate);

/* Disable V3D GPU clock */
void gpu_v3d_clock_disable(void);

/* Submit command buffer to V3D */
int gpu_v3d_execute(uint32_t job_list_address, uint32_t job_list_size);

/* ============================================================
 *   Temperature and Monitoring
 * ============================================================ */

/* Get GPU temperature in millidegrees Celsius */
uint32_t gpu_get_temperature(void);

/* Get GPU core clock rate in Hz */
uint32_t gpu_get_clock_rate(void);

/* Set GPU core clock rate in Hz */
int gpu_set_clock_rate(uint32_t rate);

#endif /* __FUTURA_DRIVERS_GPU_VC4_H__ */
