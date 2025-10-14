// SPDX-License-Identifier: MPL-2.0

#include <stdbool.h>
#include <stddef.h>

#include <pthread.h>

#define MAX_PTHREAD_KEYS 32

struct pthread_key_slot {
    bool in_use;
    void *value;
    void (*destructor)(void *);
};

static struct pthread_key_slot key_table[MAX_PTHREAD_KEYS];

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    if (*once_control != PTHREAD_ONCE_INIT_COMPLETED) {
        *once_control = PTHREAD_ONCE_INIT_COMPLETED;
        init_routine();
    }
    return 0;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
    for (pthread_key_t i = 0; i < MAX_PTHREAD_KEYS; ++i) {
        if (!key_table[i].in_use) {
            key_table[i].in_use = true;
            key_table[i].value = NULL;
            key_table[i].destructor = destructor;
            *key = i + 1;
            return 0;
        }
    }
    return -1;
}

int pthread_key_delete(pthread_key_t key) {
    if (key == 0 || key > MAX_PTHREAD_KEYS) {
        return -1;
    }
    struct pthread_key_slot *slot = &key_table[key - 1];
    slot->in_use = false;
    slot->value = NULL;
    slot->destructor = NULL;
    return 0;
}

int pthread_setspecific(pthread_key_t key, const void *value) {
    if (key == 0 || key > MAX_PTHREAD_KEYS) {
        return -1;
    }
    struct pthread_key_slot *slot = &key_table[key - 1];
    if (!slot->in_use) {
        return -1;
    }
    slot->value = (void *)value;
    return 0;
}

void *pthread_getspecific(pthread_key_t key) {
    if (key == 0 || key > MAX_PTHREAD_KEYS) {
        return NULL;
    }
    struct pthread_key_slot *slot = &key_table[key - 1];
    if (!slot->in_use) {
        return NULL;
    }
    return slot->value;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    (void)mutex;
    (void)attr;
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    (void)cond;
    (void)attr;
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    (void)cond;
    (void)mutex;
    return 0;
}

int pthread_cond_signal(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}
