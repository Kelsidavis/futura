/* fipc_idlv0_codegen.h - Micro helpers for IDL-v0 decoding
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * Provides macros that generate simple structs and decode routines based on
 * a tag table. Intended for tests and tooling; not a full schema compiler.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define FIPC_IDL_FIELD_DECL(tag, field) uint64_t field;
#define FIPC_IDL_FIELD_INIT(tag, field) (s->field = 0);
#define FIPC_IDL_FIELD_CASE(tag, field) case tag: out->field = value; break;

static inline const uint8_t *fipc_idlv0_read_u64(const uint8_t *cursor,
                                                 const uint8_t *end,
                                                 uint64_t *out_value) {
    uint64_t value = 0;
    uint32_t shift = 0;
    while (cursor && cursor < end) {
        uint8_t byte = *cursor++;
        value |= (uint64_t)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            if (out_value) {
                *out_value = value;
            }
            return cursor;
        }
        shift += 7;
        if (shift >= 64) {
            break;
        }
    }
    return NULL;
}

#define FIPC_IDL_DEF_STRUCT(name, TABLE_MACRO)                              \
    typedef struct name {                                                   \
        TABLE_MACRO(FIPC_IDL_FIELD_DECL)                                    \
    } name;                                                                 \
    static inline void name##_init(name *s) {                               \
        if (!s) {                                                           \
            return;                                                         \
        }                                                                   \
        TABLE_MACRO(FIPC_IDL_FIELD_INIT)                                    \
    }

#define FIPC_IDL_DEF_DECODE_BOUNDED(name, TABLE_MACRO, BEGIN_TAG, END_TAG)  \
    static inline int name##_decode(const uint8_t *buffer,                  \
                                    size_t length,                          \
                                    name *out) {                            \
        if (!buffer || !out) {                                              \
            return -1;                                                      \
        }                                                                   \
        const uint8_t *cursor = buffer;                                     \
        const uint8_t *const end = buffer + length;                         \
        name##_init(out);                                                   \
        while (cursor < end) {                                              \
            uint8_t tag = *cursor++;                                        \
            if ((BEGIN_TAG) >= 0 && tag == (uint8_t)(BEGIN_TAG)) {          \
                continue;                                                   \
            }                                                               \
            if ((END_TAG) >= 0 && tag == (uint8_t)(END_TAG)) {              \
                break;                                                      \
            }                                                               \
            uint64_t value = 0;                                             \
            cursor = fipc_idlv0_read_u64(cursor, end, &value);              \
            if (!cursor) {                                                  \
                return -1;                                                  \
            }                                                               \
            switch (tag) {                                                  \
                TABLE_MACRO(FIPC_IDL_FIELD_CASE)                            \
                default:                                                    \
                    break;                                                  \
            }                                                               \
        }                                                                   \
        return 0;                                                           \
    }

#define FIPC_IDL_DEF_DECODE(name, TABLE_MACRO)                              \
    FIPC_IDL_DEF_DECODE_BOUNDED(name, TABLE_MACRO, -1, -1)
