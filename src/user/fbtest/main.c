// SPDX-License-Identifier: MPL-2.0

#include <stdint.h>
#include <stddef.h>
#include <kernel/fb_ioctl.h>
#include <user/sys.h>

#define O_RDWR      0x0002
#define PROT_WRITE  0x2
#define MAP_SHARED  0x1

static void write_str(const char *s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    sys_write(1, s, (long)len);
}

static void write_u64(uint64_t value) {
    char digits[32];
    int pos = 0;
    if (value == 0) {
        digits[pos++] = '0';
    } else {
        char tmp[32];
        int tpos = 0;
        while (value > 0 && tpos < (int)sizeof(tmp)) {
            tmp[tpos++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
        while (tpos > 0) {
            digits[pos++] = tmp[--tpos];
        }
    }
    digits[pos++] = '\n';
    sys_write(1, digits, pos);
}

int main(void) {
    char input[] = "AbCd";
    char output[sizeof(input)] = {0};
    (void)sys_echo_call(input, output, (long)sizeof(input));

    int fd = (int)sys_open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        sys_exit(-1);
    }

    struct fb_fix_screeninfo fix;
    if (sys_ioctl(fd, FBIOGET_FSCREENINFO, (long)&fix) < 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    struct fb_var_screeninfo var;
    if (sys_ioctl(fd, FBIOGET_VSCREENINFO, (long)&var) < 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    size_t fb_size = fix.smem_len;
    uint32_t *fb = (uint32_t *)sys_mmap(NULL, (long)fb_size, PROT_WRITE, MAP_SHARED, fd, 0);
    if ((long)fb < 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    uint32_t stride = fix.line_length ? (fix.line_length / 4u) : var.xres;
    uint32_t width = var.xres;
    uint32_t height = var.yres;

    if (stride == 0 || width == 0 || height == 0) {
        sys_close(fd);
        sys_exit(-1);
    }

    const uint32_t frames = 120;
    uint64_t start_ms = (uint64_t)sys_time_millis_call();

    for (uint32_t frame = 0; frame < frames; ++frame) {
        for (uint32_t y = 0; y < height; ++y) {
            for (uint32_t x = 0; x < width; ++x) {
                uint32_t r = (x + frame) & 0xFFu;
                uint32_t g = (y + frame) & 0xFFu;
                uint32_t b = 0x40u;
                fb[y * stride + x] = (r << 16) | (g << 8) | b;
            }
        }
    }

    uint64_t end_ms = (uint64_t)sys_time_millis_call();
    uint64_t elapsed_ms = (end_ms > start_ms) ? (end_ms - start_ms) : 1u;
    uint64_t fps_times100 = (frames * 100000ULL) / elapsed_ms; /* FPS scaled by 100 */

    write_str("fbtest fps x100:\n");
    write_u64(fps_times100);

    sys_close(fd);
    sys_exit(0);
    return 0;
}
