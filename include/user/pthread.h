// SPDX-License-Identifier: MPL-2.0
//
// Minimal pthread.h surface — libwayland uses pthread_mutex_*,
// pthread_cond_*, pthread_create. Backed by libfutura's thread shim.

#pragma once

#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { void *__opaque[8]; } pthread_mutex_t;
typedef struct { void *__opaque[2]; } pthread_mutexattr_t;
typedef struct { void *__opaque[8]; } pthread_cond_t;
typedef struct { void *__opaque[2]; } pthread_condattr_t;
typedef struct { void *__opaque[8]; } pthread_rwlock_t;
typedef struct { void *__opaque[2]; } pthread_rwlockattr_t;
typedef struct { void *__opaque[8]; } pthread_attr_t;

#define PTHREAD_MUTEX_INITIALIZER     { { 0 } }
#define PTHREAD_COND_INITIALIZER      { { 0 } }
#define PTHREAD_RWLOCK_INITIALIZER    { { 0 } }
#define PTHREAD_ONCE_INIT             0

#define PTHREAD_MUTEX_NORMAL     0
#define PTHREAD_MUTEX_RECURSIVE  1
#define PTHREAD_MUTEX_ERRORCHECK 2

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *m);
int pthread_mutex_lock(pthread_mutex_t *m);
int pthread_mutex_trylock(pthread_mutex_t *m);
int pthread_mutex_unlock(pthread_mutex_t *m);
int pthread_mutexattr_init(pthread_mutexattr_t *a);
int pthread_mutexattr_destroy(pthread_mutexattr_t *a);
int pthread_mutexattr_settype(pthread_mutexattr_t *a, int type);

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *c);
int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m);
int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, const struct timespec *abstime);
int pthread_cond_signal(pthread_cond_t *c);
int pthread_cond_broadcast(pthread_cond_t *c);

int pthread_rwlock_init(pthread_rwlock_t *l, const pthread_rwlockattr_t *attr);
int pthread_rwlock_destroy(pthread_rwlock_t *l);
int pthread_rwlock_rdlock(pthread_rwlock_t *l);
int pthread_rwlock_wrlock(pthread_rwlock_t *l);
int pthread_rwlock_unlock(pthread_rwlock_t *l);

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg);
int pthread_join(pthread_t thread, void **retval);
int pthread_detach(pthread_t thread);
pthread_t pthread_self(void);
int pthread_equal(pthread_t a, pthread_t b);

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);

int pthread_attr_init(pthread_attr_t *a);
int pthread_attr_destroy(pthread_attr_t *a);
int pthread_attr_setdetachstate(pthread_attr_t *a, int detachstate);
int pthread_attr_setstacksize(pthread_attr_t *a, size_t stacksize);

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

#ifdef __cplusplus
}
#endif
