#include <futura/compat/posix_shm.h>

#include <user/sys.h>
#include "fd.h"

#define O_CREAT  0x0040
#define O_RDWR   0x0002
#define O_TRUNC  0x0200

#define FUT_SHM_PREFIX "/tmp/fut-shm-"
#define FUT_SHM_SUFFIX ".bin"

static int fut_build_shm_path(const char *name, char *out, size_t out_len) {
    if (!name || !out || out_len == 0) {
        return -1;
    }

    const char *base = name;
    if (*base == '/') {
        base++;
    }
    if (*base == '\0') {
        return -1;
    }

    /* Only allow simple POSIX shm names: alnum, '-', '_' */
    size_t base_len = 0;
    for (const char *p = base; *p; ++p) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '_')) {
            return -1;
        }
        base_len++;
    }

    const size_t prefix_len = sizeof(FUT_SHM_PREFIX) - 1;
    const size_t suffix_len = sizeof(FUT_SHM_SUFFIX) - 1;
    const size_t total_len = prefix_len + base_len + suffix_len;

    if (total_len + 1 > out_len) {
        return -1;
    }

    size_t idx = 0;
    for (size_t i = 0; i < prefix_len; ++i) {
        out[idx++] = FUT_SHM_PREFIX[i];
    }
    for (const char *p = base; *p; ++p) {
        out[idx++] = *p;
    }
    for (size_t i = 0; i < suffix_len; ++i) {
        out[idx++] = FUT_SHM_SUFFIX[i];
    }
    out[idx] = '\0';
    return 0;
}

__attribute__((unused))
static int fut_write_zeros(int fd, size_t size) {
    static char zeros[4096];
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = (remaining > sizeof(zeros)) ? sizeof(zeros) : remaining;
        long wr = sys_write(fd, zeros, (long)chunk);
        if (wr < 0 || (size_t)wr != chunk) {
            return -1;
        }
        remaining -= chunk;
    }
    return 0;
}

int fut_shm_open(const char *name, int oflag, int mode) {
    (void)mode;
    char path[128];
    if (fut_build_shm_path(name, path, sizeof(path)) != 0) {
        return -1;
    }
    int fd = (int)sys_open(path, oflag, 0);
    if (fd >= 0) {
        fut_fd_path_register(fd, path);
    }
    return fd;
}

int fut_shm_create(const char *name, size_t size, int oflag, int mode) {
    char path[128];
    if (fut_build_shm_path(name, path, sizeof(path)) != 0) {
        return -1;
    }

    int fd = (int)sys_open(path, oflag | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        return fd;
    }
    fut_fd_path_register(fd, path);

    /* Use ftruncate for efficient allocation instead of write-zeros loop */
    long ret = sys_ftruncate(fd, (long)size);
    if (ret < 0) {
        sys_close(fd);
        fut_fd_path_forget(fd);
        return (int)ret;
    }
    return fd;
}

int fut_shm_unlink(const char *name) {
    char path[128];
    if (fut_build_shm_path(name, path, sizeof(path)) != 0) {
        return -1;
    }
    long ret = sys_unlink(path);
    if (ret < 0) {
        return (int)ret;
    }
    return 0;
}

int fut_shm_resize(int fd, size_t size) {
    /* Use ftruncate syscall for efficient allocation */
    long ret = sys_ftruncate(fd, (long)size);
    if (ret < 0) {
        return (int)ret;
    }
    return 0;
}

int msync(void *addr, size_t length, int flags) {
    (void)addr;
    (void)length;
    (void)flags;
    return 0;
}
