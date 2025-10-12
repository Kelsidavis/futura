// SPDX-License-Identifier: MPL-2.0
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../subsystems/futura_fs/logfs.h"

static void write_temp_fs(const char *path) {
    int rc = futfs_format_path(path, 1 << 20, 4096);
    assert(rc == 0);
}

int main(void) {
    char tmpl[] = "/tmp/futfsXXXXXX";
    int fd = mkstemp(tmpl);
    assert(fd >= 0);
    close(fd);

    write_temp_fs(tmpl);

    futfs_t *fs = NULL;
    assert(futfs_mount_path(tmpl, &fs) == 0);

    futfs_handle_t *file = NULL;
    assert(futfs_create(fs,
                        futfs_root_ino(fs),
                        "logfile",
                        FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN,
                        FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN,
                        &file) == 0);

    const char payload[] = "hello logfs";
    assert(futfs_write(file, payload, sizeof(payload) - 1) == 0);

    uint8_t *data = NULL;
    size_t len = 0;
    assert(futfs_read_all(file, &data, &len) == 0);
    assert(len == sizeof(payload) - 1);
    assert(memcmp(data, payload, len) == 0);
    free(data);

    assert(futfs_rename(file, futfs_root_ino(fs), "renamed") == 0);

    futfs_handle_close(file);
    futfs_unmount(fs);
    unlink(tmpl);
    return 0;
}
