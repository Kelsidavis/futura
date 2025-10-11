/* config.c - Init System Configuration Parser
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Parses /etc/futura/init.conf and builds service definitions.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <user/futura_init.h>

/* Maximum configuration file size */
#define MAX_CONFIG_SIZE (64 * 1024)
#define MAX_LINE_LENGTH 1024

/* Global configuration */
static struct {
    char hostname[256];
    int respawn_limit;
    int shutdown_timeout;
} global_config = {
    .hostname = "futura-os",
    .respawn_limit = 5,
    .shutdown_timeout = 30000,
};

/**
 * Simple string comparison (no libc).
 */
static bool str_equals(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/**
 * Simple string copy (no libc).
 */
static void str_copy(char *dest, const char *src, size_t max) {
    size_t i = 0;
    while (src[i] && i < max - 1) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

/**
 * Parse a key=value line.
 */
__attribute__((unused))
static int parse_key_value(const char *line, char *key, char *value, size_t max_len) {
    const char *p = line;
    size_t key_len = 0;
    size_t val_len = 0;

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Skip comments and empty lines */
    if (*p == '#' || *p == '\n' || *p == '\0') {
        return -1;
    }

    /* Read key */
    while (*p && *p != '=' && key_len < max_len - 1) {
        key[key_len++] = *p++;
    }
    key[key_len] = '\0';

    if (*p != '=') {
        return -1;  /* No '=' found */
    }
    p++;  /* Skip '=' */

    /* Read value */
    while (*p && *p != '\n' && val_len < max_len - 1) {
        value[val_len++] = *p++;
    }
    value[val_len] = '\0';

    return 0;
}

/**
 * Parse global configuration section.
 */
__attribute__((unused))
static void parse_global_section(const char *key, const char *value) {
    if (str_equals(key, "hostname")) {
        str_copy(global_config.hostname, value, sizeof(global_config.hostname));
    } else if (str_equals(key, "respawn_limit")) {
        /* Phase 3: Parse integer */
        global_config.respawn_limit = 5;
    } else if (str_equals(key, "shutdown_timeout")) {
        /* Phase 3: Parse integer */
        global_config.shutdown_timeout = 30000;
    }
}

/**
 * Parse service definition section.
 */
__attribute__((unused))
static int parse_service_section(const char *name, const char **lines, int num_lines) {
    (void)name;
    (void)lines;
    (void)num_lines;

    /* Phase 3: Would create struct fui_service and populate:
     * - name, exec_path, args, env, priority
     * - depends array
     * - respawn flag
     * Then register service with service manager
     */

    return 0;
}

/**
 * Parse configuration file.
 */
int init_config_parse(const char *path) {
    (void)path;

    /* Phase 3: Full implementation would:
     * 1. Open configuration file via VFS/posixd
     * 2. Read entire file into buffer
     * 3. Parse line by line:
     *    - Detect [global] section
     *    - Detect [service:name] sections
     *    - Parse key=value pairs
     * 4. Build service structures
     * 5. Validate dependencies
     */

    /* For now, hard-code basic services matching init.conf */

    /* Service: fsd (priority 1) */
    struct fui_service fsd = {
        .name = "fsd",
        .exec_path = "/sbin/fsd",
        .args = NULL,
        .pid = 0,
        .priority = 1,
        .respawn = true,
        .depends = NULL,
        .state = SERVICE_STOPPED,
        .channel = NULL,
    };
    (void)fsd;  /* Suppress warning - would be registered */

    /* Service: posixd (priority 2, depends on fsd) */
    struct fui_service posixd = {
        .name = "posixd",
        .exec_path = "/sbin/posixd",
        .args = NULL,
        .pid = 0,
        .priority = 2,
        .respawn = true,
        .depends = NULL,  /* Would be ["fsd"] */
        .state = SERVICE_STOPPED,
        .channel = NULL,
    };
    (void)posixd;

    /* Service: futurawayd (priority 3, depends on fsd) */
    struct fui_service futurawayd = {
        .name = "futurawayd",
        .exec_path = "/sbin/futurawayd",
        .args = NULL,  /* Would be ["--display=:0", "--software-render"] */
        .pid = 0,
        .priority = 3,
        .respawn = true,
        .depends = NULL,  /* Would be ["fsd"] */
        .state = SERVICE_STOPPED,
        .channel = NULL,
    };
    (void)futurawayd;

    return 0;
}

/**
 * Get global configuration values.
 */
const char *init_config_get_hostname(void) {
    return global_config.hostname;
}

int init_config_get_respawn_limit(void) {
    return global_config.respawn_limit;
}

int init_config_get_shutdown_timeout(void) {
    return global_config.shutdown_timeout;
}
