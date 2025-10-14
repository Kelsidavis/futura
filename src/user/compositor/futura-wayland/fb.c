#include "fb.h"

#include <stdint.h>

#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <futura/fb_ioctl.h>
#include <user/sys.h>

#define FB_DEVICE "/dev/fb0"

int fb_open(struct fb_info *info) {
    if (!info) {
        return -1;
    }

    int fd = (int)sys_open(FB_DEVICE, 0 /* O_RDONLY */, 0);
    if (fd < 0) {
        return -1;
    }

    struct fut_fb_info fb;
    long ret = sys_ioctl(fd, FBIOGET_INFO, (long)&fb);
    if (ret < 0) {
        sys_close(fd);
        return -1;
    }

    info->width = fb.width;
    info->height = fb.height;
    info->pitch = fb.pitch;
    info->bpp = fb.bpp;

    sys_close(fd);
    return 0;
}
