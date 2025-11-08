// SPDX-License-Identifier: MPL-2.0

#include <stdint.h>
#include <stddef.h>
#include <futura/fb_ioctl.h>
#include <shared/fut_timespec.h>
#include <user/stdio.h>
#include <user/sys.h>

void *malloc(size_t size);
void free(void *ptr);
void *memcpy(void *dest, const void *src, size_t n);

#define O_RDWR      0x0002
#define PROT_WRITE  0x2
#define MAP_SHARED  0x1

int main(void) {
    int fd = (int)sys_open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        sys_exit(-1);
    }

    struct fut_fb_info info;
    if (sys_ioctl(fd, FBIOGET_INFO, (long)&info) < 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    size_t fb_size = (size_t)info.pitch * info.height;
    uint32_t *fb = (uint32_t *)sys_mmap(NULL, (long)fb_size, PROT_WRITE, MAP_SHARED, fd, 0);
    if ((long)fb < 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    uint32_t stride = info.pitch / 4u;
    uint32_t width = info.width;
    uint32_t height = info.height;

    if (stride == 0 || width == 0 || height == 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    uint32_t *line = malloc(width * sizeof(uint32_t));
    if (!line) {
        sys_close(fd);
        sys_exit(-1);
    }

    fut_timespec_t sleep_ts = { .tv_sec = 0, .tv_nsec = 16 * 1000 * 1000 };

    const uint32_t frames = 120;
    uint64_t start_ms = (uint64_t)sys_time_millis_call();

    for (uint32_t frame = 0; frame < frames; ++frame) {
        for (uint32_t y = 0; y < height; ++y) {
            for (uint32_t x = 0; x < width; ++x) {
                uint32_t r = (x + frame) & 0xFFu;
                uint32_t g = (y + frame) & 0xFFu;
                uint32_t b = 0x40u;
                line[x] = (r << 16) | (g << 8) | b;
            }
            memcpy(&fb[y * stride], line, width * sizeof(uint32_t));
        }

        sys_nanosleep_call(&sleep_ts, NULL);
    }

    uint64_t end_ms = (uint64_t)sys_time_millis_call();
    uint64_t elapsed_ms = (end_ms > start_ms) ? (end_ms - start_ms) : 1u;
    uint32_t fps_times100 = (uint32_t)((frames * 100000ULL) / elapsed_ms);

    printf("fbtest fps x100: %u\n", fps_times100);

    free(line);
    sys_close(fd);
    sys_exit(0);
    return 0;
}
