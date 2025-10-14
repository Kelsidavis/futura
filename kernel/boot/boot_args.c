// SPDX-License-Identifier: MPL-2.0
#include <kernel/boot_args.h>

#include <stddef.h>
#include <string.h>

#define BOOT_CMDSZ 512

static char s_cmdline[BOOT_CMDSZ];
static int s_initialized = 0;

static size_t boot_strnlen(const char *s, size_t max_len) {
    size_t len = 0;
    while (len < max_len && s[len] != '\0') {
        ++len;
    }
    return len;
}

static size_t boot_strlen(const char *s) {
    size_t len = 0;
    while (s[len] != '\0') {
        ++len;
    }
    return len;
}

static int boot_strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb || ca == '\0' || cb == '\0') {
            return (int)ca - (int)cb;
        }
    }
    return 0;
}

static const char *boot_strchr(const char *s, char ch) {
    while (*s) {
        if (*s == ch) {
            return s;
        }
        ++s;
    }
    return NULL;
}

static int boot_strcmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

void fut_boot_args_init(const char *cmdline) {
    if (!cmdline) {
        s_cmdline[0] = '\0';
        s_initialized = 1;
        return;
    }
    size_t len = boot_strnlen(cmdline, BOOT_CMDSZ - 1);
    memcpy(s_cmdline, cmdline, len);
    s_cmdline[len] = '\0';
    s_initialized = 1;
}

static const char *find_key(const char *key) {
    if (!s_initialized) {
        return NULL;
    }
    size_t key_len = boot_strlen(key);
    const char *cursor = s_cmdline;
    while (*cursor) {
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        const char *start = cursor;
        while (*cursor && *cursor != ' ') {
            cursor++;
        }
        size_t token_len = (size_t)(cursor - start);
        if (token_len >= key_len && boot_strncmp(start, key, key_len) == 0) {
            if (token_len == key_len || start[key_len] == '=') {
                return start;
            }
        }
    }
    return NULL;
}

const char *fut_boot_arg_value(const char *key) {
    const char *token = find_key(key);
    if (!token) {
        return NULL;
    }
    const char *equals = boot_strchr(token, '=');
    if (!equals) {
        return "";
    }
    return equals + 1;
}

bool fut_boot_arg_flag(const char *key) {
    const char *token = find_key(key);
    if (!token) {
        return false;
    }
    const char *value = boot_strchr(token, '=');
    if (!value) {
        return true;
    }
    value++; /* skip '=' */
    if (*value == '\0') {
        return true;
    }
    if (boot_strcmp(value, "1") == 0 ||
        boot_strcmp(value, "true") == 0 ||
        boot_strcmp(value, "on") == 0) {
        return true;
    }
    return false;
}
