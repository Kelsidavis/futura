// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

#ifdef __has_include
#if __has_include(<pthread.h>)
#ifdef __GNUC__
#include_next <pthread.h>
#define FUTURA_HAVE_NATIVE_PTHREAD 1
#endif
#endif
#endif

#ifndef FUTURA_HAVE_NATIVE_PTHREAD
typedef unsigned long pthread_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;

#define PTHREAD_ONCE_INIT 0
#define PTHREAD_ONCE_INIT_COMPLETED 1

typedef struct {
    int unused;
} pthread_mutex_t;

typedef struct {
    int unused;
} pthread_cond_t;

typedef struct {
    int unused;
} pthread_mutexattr_t;

typedef struct {
    int unused;
} pthread_condattr_t;

#else
#ifndef PTHREAD_ONCE_INIT_COMPLETED
#define PTHREAD_ONCE_INIT_COMPLETED 1
#endif
#endif

#ifndef FUTURA_HAVE_NATIVE_PTHREAD
int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
void *pthread_getspecific(pthread_key_t key);
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
#endif
