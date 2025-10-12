// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t head;
    size_t tail;
} ring_model_t;

static inline void rm_init(ring_model_t *m, uint8_t *storage, size_t capacity) {
    m->buf = storage;
    m->cap = capacity;
    m->head = 0;
    m->tail = 0;
}

static inline size_t rm_used(const ring_model_t *m) {
    return (m->head + m->cap - m->tail) % m->cap;
}

static inline size_t rm_free(const ring_model_t *m) {
    return m->cap - 1 - rm_used(m);
}

static inline int rm_push(ring_model_t *m, const uint8_t *src, size_t len) {
    if (rm_free(m) < len) {
        return -1;
    }
    size_t first = len;
    size_t wrap = 0;
    if (m->head + len > m->cap) {
        first = m->cap - m->head;
        wrap = len - first;
    }
    if (first) {
        memcpy(m->buf + m->head, src, first);
    }
    if (wrap) {
        memcpy(m->buf, src + first, wrap);
    }
    m->head = (m->head + len) % m->cap;
    return 0;
}

static inline int rm_pop(ring_model_t *m, uint8_t *dst, size_t len) {
    if (rm_used(m) < len) {
        return -1;
    }
    size_t first = len;
    size_t wrap = 0;
    if (m->tail + len > m->cap) {
        first = m->cap - m->tail;
        wrap = len - first;
    }
    if (first) {
        memcpy(dst, m->buf + m->tail, first);
    }
    if (wrap) {
        memcpy(dst + first, m->buf, wrap);
    }
    m->tail = (m->tail + len) % m->cap;
    return 0;
}
