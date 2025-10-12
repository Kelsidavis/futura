
// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>
#include <kernel/fut_hmac.h>

#define ADM_FIELD_MAX 11u

static uint8_t *adm_write(uint8_t *cursor, uint8_t tag, uint64_t value) {
    *cursor++ = tag;
    return fipc_sys_varint_u64(cursor, value);
}

static bool adm_emit(uint8_t **cursor, uint8_t *end, uint8_t tag, uint64_t value) {
    if (!cursor || !*cursor) {
        return false;
    }
    if ((size_t)(end - *cursor) < ADM_FIELD_MAX) {
        return false;
    }
    *cursor = adm_write(*cursor, tag, value);
    return *cursor <= end;
}

static bool adm_emit_bytes(uint8_t **cursor, uint8_t *end, uint8_t tag, const uint8_t *data, size_t len) {
    if (!cursor || !*cursor) {
        return false;
    }
    if ((size_t)(end - *cursor) < 1 + 2 + len) {
        return false;
    }
    *(*cursor)++ = tag;
    *cursor = fipc_sys_varint_u64(*cursor, (uint64_t)len);
    if ((size_t)(end - *cursor) < len) {
        return false;
    }
    if (len > 0 && data) {
        memcpy(*cursor, data, len);
    }
    *cursor += len;
    return *cursor <= end;
}

static const uint8_t *adm_read(const uint8_t *cursor, const uint8_t *end, uint64_t *out) {
    uint64_t value = 0;
    uint32_t shift = 0;
    while (cursor < end) {
        uint8_t byte = *cursor++;
        value |= (uint64_t)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            if (out) {
                *out = value;
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

static const uint8_t admin_token_default[FIPC_ADMIN_TOKEN_LEN] = FIPC_ADMIN_TOKEN_DEFAULT_INIT;
static const uint8_t admin_hmac_key[FIPC_ADMIN_HMAC_KEY_LEN] = FIPC_ADMIN_HMAC_KEY_DEFAULT_INIT;

static void write_le64(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)((value >> (i * 8)) & 0xFFu);
    }
}

static int send_admin(enum fipc_admin_op op,
                      uint64_t target,
                      uint32_t rights,
                      uint64_t max_msgs,
                      uint64_t max_bytes,
                      uint64_t expiry,
                      uint32_t revoke,
                      uint32_t rate,
                      uint32_t burst,
                      uint64_t lease_id,
                      const uint8_t *token,
                      size_t token_len,
                      const uint8_t *override_hmac) {
    struct fut_fipc_channel *ctl = fut_fipc_channel_lookup(FIPC_CTL_CHANNEL_ID);
    if (!ctl) {
        return -1;
    }

    uint8_t payload[256];
    uint8_t *w = payload;
    uint8_t *const end = payload + sizeof(payload);
    *w++ = FIPC_ADM_BEGIN;
    if (!adm_emit(&w, end, FIPC_ADM_OP, (uint64_t)op) ||
        !adm_emit(&w, end, FIPC_ADM_TARGET, target)) {
        return -1;
    }
    if (op == FIPC_ADM_CAP_BIND) {
        if (!adm_emit(&w, end, FIPC_ADM_RIGHTS, rights)) {
            return -1;
        }
        if (max_msgs && !adm_emit(&w, end, FIPC_ADM_MAX_MSGS, max_msgs)) {
            return -1;
        }
        if (max_bytes && !adm_emit(&w, end, FIPC_ADM_MAX_BYTES, max_bytes)) {
            return -1;
        }
        if (expiry && !adm_emit(&w, end, FIPC_ADM_EXP_TICK, expiry)) {
            return -1;
        }
        if (!adm_emit(&w, end, FIPC_ADM_LEASE, lease_id)) {
            return -1;
        }
        uint8_t material[40];
        uint8_t *mat = material;
        write_le64(mat, lease_id);
        mat += 8;
        write_le64(mat, rights);
        mat += 8;
        write_le64(mat, max_msgs);
        mat += 8;
        write_le64(mat, max_bytes);
        mat += 8;
        write_le64(mat, expiry);
        uint8_t hmac[FUT_SHA256_DIGEST_LEN];
        fut_hmac_sha256(admin_hmac_key, sizeof(admin_hmac_key), material, sizeof(material), hmac);
        const uint8_t *hmac_ptr = override_hmac ? override_hmac : hmac;
        if (!adm_emit_bytes(&w, end, FIPC_ADM_HMAC, hmac_ptr, FUT_SHA256_DIGEST_LEN)) {
            return -1;
        }
    } else if (op == FIPC_ADM_CAP_REVOKE) {
        if (!adm_emit(&w, end, FIPC_ADM_REVOKE, revoke)) {
            return -1;
        }
    } else if (op == FIPC_ADM_RATE_SET) {
        if (!adm_emit(&w, end, FIPC_ADM_RATE, rate) ||
            !adm_emit(&w, end, FIPC_ADM_BURST, burst)) {
            return -1;
        }
    }
    if (token && token_len > 0) {
        if (!adm_emit_bytes(&w, end, FIPC_ADM_TOKEN, token, token_len)) {
            return -1;
        }
    }
    if (w >= end) {
        return -1;
    }
    *w++ = FIPC_ADM_END;

    int send_rc = fut_fipc_send(ctl, FIPC_SYS_MSG_ADMIN_OP, payload, (size_t)(w - payload));
    if (send_rc != 0 && send_rc != FIPC_EPERM && send_rc != FIPC_EINVAL) {
        fprintf(stderr, "[ADM] send_rc=%d\n", send_rc);
        return -1;
    }

    uint8_t buf[256];
    ssize_t r = fut_fipc_recv(ctl, buf, sizeof(buf));
    if (r <= 0) {
        return -1;
    }
    struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buf;
    if (msg->type != FIPC_SYS_MSG_ADMIN_RP) {
        return -1;
    }
    const uint8_t *cursor = msg->payload;
    const uint8_t *iend = cursor + msg->length;
    if (cursor >= iend || *cursor++ != FIPC_ADM_RP_BEGIN) {
        return -1;
    }
    uint64_t code = 1;
    while (cursor < iend) {
        uint8_t tag = *cursor++;
        if (tag == FIPC_ADM_RP_END) {
            break;
        }
        if (tag == FIPC_ADM_RP_CODE) {
            const uint8_t *next = adm_read(cursor, iend, &code);
            if (!next) {
                return -1;
            }
            cursor = next;
        } else {
            const uint8_t *next = adm_read(cursor, iend, NULL);
            if (!next) {
                return -1;
            }
            cursor = next;
        }
    }
    return (int)code;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 1024, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[ADM] channel create failed\n");
        return 1;
    }
    uint64_t target_id = ch->id;

    uint8_t invalid_token[FIPC_ADMIN_TOKEN_LEN];
    memcpy(invalid_token, admin_token_default, sizeof(invalid_token));
    invalid_token[0] ^= 0xFF;

    const uint64_t lease_id = 0x1122334455667788ULL;

    if (send_admin(FIPC_ADM_CAP_BIND, target_id,
                   FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
                   100, 0, 0, 0, 0, 0,
                   lease_id,
                   NULL, 0,
                   NULL) != -FIPC_EPERM) {
        fprintf(stderr, "[ADM] missing token did not fail as expected\n");
        return 1;
    }

    if (send_admin(FIPC_ADM_CAP_BIND, target_id,
                   FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
                   100, 0, 0, 0, 0, 0,
                   lease_id,
                   invalid_token, sizeof(invalid_token),
                   NULL) != -FIPC_EPERM) {
        fprintf(stderr, "[ADM] invalid token accepted\n");
        return 1;
    }

    uint8_t invalid_hmac[FUT_SHA256_DIGEST_LEN] = {0};
    if (send_admin(FIPC_ADM_CAP_BIND, target_id,
                   FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
                   100, 0, 0, 0, 0, 0,
                   lease_id,
                   admin_token_default, sizeof(admin_token_default),
                   invalid_hmac) != -FIPC_EPERM) {
        fprintf(stderr, "[ADM] invalid HMAC accepted\n");
        return 1;
    }

    if (send_admin(FIPC_ADM_CAP_BIND, target_id,
                   FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
                   100, 0, 0, 0, 0, 0,
                   lease_id,
                   admin_token_default, sizeof(admin_token_default),
                   NULL) != 0) {
        fprintf(stderr, "[ADM] cap-bind failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xEE00u, "A", 1) != 0) {
        fprintf(stderr, "[ADM] send after bind failed\n");
        return 1;
    }

    if (send_admin(FIPC_ADM_CAP_REVOKE, target_id, 0, 0, 0, 0,
                   FIPC_CAP_REVOKE_SEND, 0, 0,
                   0,
                   admin_token_default, sizeof(admin_token_default),
                   NULL) != 0) {
        fprintf(stderr, "[ADM] revoke send failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xEE01u, "B", 1) != FIPC_EPERM) {
        fprintf(stderr, "[ADM] send not revoked\n");
        return 1;
    }

    if (send_admin(FIPC_ADM_CAP_UNBIND, target_id, 0, 0, 0, 0, 0, 0, 0,
                   0,
                   admin_token_default, sizeof(admin_token_default),
                   NULL) != 0) {
        fprintf(stderr, "[ADM] unbind failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xEE02u, "C", 1) != 0) {
        fprintf(stderr, "[ADM] send after unbind failed\n");
        return 1;
    }

    if (send_admin(FIPC_ADM_RATE_SET, target_id, 0, 0, 0, 0, 0, 1, 2,
                   0,
                   admin_token_default, sizeof(admin_token_default),
                   NULL) != 0) {
        fprintf(stderr, "[ADM] rate-set failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xEE10u, "D", 1) != 0) {
        fprintf(stderr, "[ADM] rate send 1 failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xEE11u, "E", 1) != 0) {
        fprintf(stderr, "[ADM] rate send 2 failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xEE12u, "F", 1) != FIPC_EAGAIN) {
        fprintf(stderr, "[ADM] rate limit not enforced\n");
        return 1;
    }

    printf("[ADM] admin ops over control channel — PASS\n");
    return 0;
}
