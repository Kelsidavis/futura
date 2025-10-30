/* env.c - Minimal process environment for Futura OS userland
 *
 * Provides getenv/setenv/putenv helpers and maintains a simple environment
 * table backed by our heap allocator. The implementation favours simplicity
 * over absolute POSIX fidelity but covers the subset required by Wayland.
 */

#include <errno.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/stdlib.h>

static volatile int g_env_lock;
static char **g_environ = NULL;
static size_t g_env_count;
static size_t g_env_capacity;

char **environ = NULL;

/**
 * Initialize environ from the envp passed to the program during execve.
 * This should be called once during program startup (from crt0).
 * Called with the envp array from the user stack.
 */
void __libc_init_environ(char **envp) {
    if (!envp || envp[0] == NULL) {
        /* No environment passed, or empty environment */
        g_environ = NULL;
        environ = NULL;
        g_env_count = 0;
        g_env_capacity = 0;
        return;
    }

    /* Count environment variables */
    size_t count = 0;
    while (envp[count] != NULL) {
        count++;
    }

    /* Allocate environment array (+1 for NULL terminator) */
    g_environ = (char **)malloc((count + 1) * sizeof(char *));
    if (!g_environ) {
        environ = NULL;
        g_env_count = 0;
        g_env_capacity = 0;
        return;
    }

    /* Copy environment variable strings */
    for (size_t i = 0; i < count; i++) {
        size_t len = strlen(envp[i]) + 1;
        char *copy = (char *)malloc(len);
        if (copy) {
            memcpy(copy, envp[i], len);
            g_environ[i] = copy;
        } else {
            g_environ[i] = NULL;
        }
    }
    g_environ[count] = NULL;

    environ = g_environ;
    g_env_count = count;
    g_env_capacity = count + 1;
}

static void env_lock(void) {
    while (__atomic_test_and_set(&g_env_lock, __ATOMIC_ACQUIRE)) {
        /* spin */
    }
}

static void env_unlock(void) {
    __atomic_clear(&g_env_lock, __ATOMIC_RELEASE);
}

static bool key_equals(const char *entry, const char *name) {
    if (!entry || !name) {
        return false;
    }
    while (*entry && *name) {
        if (*entry != *name) {
            return false;
        }
        entry++;
        name++;
    }
    return (*name == '\0' && *entry == '=');
}

static int find_index(const char *name) {
    for (size_t i = 0; i < g_env_count; ++i) {
        if (key_equals(g_environ[i], name)) {
            return (int)i;
        }
    }
    return -1;
}

static int ensure_capacity(size_t required) {
    if (g_env_capacity >= required && g_environ != NULL) {
        return 0;
    }

    size_t new_cap = g_env_capacity ? g_env_capacity : 8;
    while (new_cap < required) {
        new_cap *= 2;
    }

    char **new_env = (char **)malloc(new_cap * sizeof(char *));
    if (!new_env) {
        return -1;
    }

    for (size_t i = 0; i < g_env_count; ++i) {
        new_env[i] = g_environ ? g_environ[i] : NULL;
    }
    new_env[g_env_count] = NULL;
    for (size_t i = g_env_count + 1; i < new_cap; ++i) {
        new_env[i] = NULL;
    }

    free(g_environ);
    g_environ = new_env;
    environ = g_environ;
    g_env_capacity = new_cap;
    return 0;
}

static int set_pair(const char *name, const char *value, int overwrite, char *owned) {
    if (!name || name[0] == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    const char *val_ptr = value ? value : "";
    size_t name_len = strlen(name);
    size_t value_len = strlen(val_ptr);

    char *kv = owned;
    if (!kv) {
        kv = (char *)malloc(name_len + 1 + value_len + 1);
        if (!kv) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(kv, name, name_len);
        kv[name_len] = '=';
        memcpy(kv + name_len + 1, val_ptr, value_len);
        kv[name_len + 1 + value_len] = '\0';
    }

    env_lock();
    int idx = find_index(name);
    if (idx >= 0 && !overwrite) {
        env_unlock();
        if (!owned) {
            free(kv);
        }
        return 0;
    }

    if (idx >= 0) {
        if (g_environ[idx] != kv) {
            free(g_environ[idx]);
        }
        g_environ[idx] = kv;
    } else {
        if (ensure_capacity(g_env_count + 2) != 0) {
            env_unlock();
            if (!owned) {
                free(kv);
            }
            errno = ENOMEM;
            return -1;
        }
        g_environ[g_env_count++] = kv;
        g_environ[g_env_count] = NULL;
    }
    env_unlock();
    return 0;
}

char *getenv(const char *name) {
    if (!name) {
        return NULL;
    }

    env_lock();
    int idx = find_index(name);
    char *result = NULL;
    if (idx >= 0 && g_environ[idx]) {
        char *eq = strchr(g_environ[idx], '=');
        if (eq) {
            result = eq + 1;
        }
    }
    env_unlock();
    return result;
}

char *secure_getenv(const char *name) {
    return getenv(name);
}

char *__secure_getenv(const char *name) {
    return secure_getenv(name);
}

int setenv(const char *name, const char *value, int overwrite) {
    return set_pair(name, value, overwrite ? 1 : 0, NULL);
}

int putenv(char *string) {
    if (!string) {
        errno = EINVAL;
        return -1;
    }
    char *eq = strchr(string, '=');
    if (!eq || eq == string) {
        errno = EINVAL;
        return -1;
    }
    char saved = *eq;
    *eq = '\0';
    const char *value = eq + 1;
    int rc = set_pair(string, value, 1, string);
    *eq = saved;
    return rc;
}

int unsetenv(const char *name) {
    if (!name || name[0] == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    env_lock();
    int idx = find_index(name);
    if (idx >= 0) {
        free(g_environ[idx]);
        for (size_t i = (size_t)idx + 1; i < g_env_count; ++i) {
            g_environ[i - 1] = g_environ[i];
        }
        g_env_count--;
        if (g_environ) {
            g_environ[g_env_count] = NULL;
        }
    }
    env_unlock();
    return 0;
}

int clearenv(void) {
    env_lock();
    for (size_t i = 0; i < g_env_count; ++i) {
        free(g_environ[i]);
    }
    free(g_environ);
    g_environ = NULL;
    environ = NULL;
    g_env_count = 0;
    g_env_capacity = 0;
    env_unlock();
    return 0;
}
