
// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>
#include <kernel/fut_hmac.h>

#define ADM_FIELD_MAX 11u
static const uint8_t default_token[FIPC_ADMIN_TOKEN_LEN] = FIPC_ADMIN_TOKEN_DEFAULT_INIT;
static const uint8_t default_hmac_key[FIPC_ADMIN_HMAC_KEY_LEN] = FIPC_ADMIN_HMAC_KEY_DEFAULT_INIT;

static void write_le64(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)((value >> (i * 8)) & 0xFFu);
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <op> --chan <id> [options]\n"
            "  ops: cap-bind, cap-unbind, cap-revoke, rate-set\n"
            "  cap-bind options: --rights send,recv,admin [--max-msgs N --max-bytes N --expiry T]\n"
            "  cap-revoke options: --rights send,recv\n"
            "  rate-set options: --rate R --burst B\n"
            "  common options: --token <64-hex> [--lease value]\n",
            prog);
}

static uint32_t parse_rights(const char *arg) {
    uint32_t rights = 0;
    char *dup = strdup(arg);
    if (!dup) {
        return 0;
    }
    char *token = strtok(dup, ",");
    while (token) {
        if (strcmp(token, "send") == 0) {
            rights |= FIPC_CAP_R_SEND;
        } else if (strcmp(token, "recv") == 0) {
            rights |= FIPC_CAP_R_RECV;
        } else if (strcmp(token, "admin") == 0) {
            rights |= FIPC_CAP_R_ADMIN;
        }
        token = strtok(NULL, ",");
    }
    free(dup);
    return rights;
}

static uint8_t *adm_write_u64(uint8_t *cursor, uint8_t tag, uint64_t value) {
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
    *cursor = adm_write_u64(*cursor, tag, value);
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

static const uint8_t *adm_read_u64(const uint8_t *cursor,
                                   const uint8_t *end,
                                   uint64_t *out_value) {
    uint64_t value = 0;
    uint32_t shift = 0;
    while (cursor < end) {
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

static int parse_hex_token(const char *hex, uint8_t *out, size_t expected_len) {
    if (!hex || !out) {
        return -1;
    }
    size_t len = strlen(hex);
    if (len != expected_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < expected_len; ++i) {
        int hi = hex[i * 2];
        int lo = hex[i * 2 + 1];
        if (!isxdigit(hi) || !isxdigit(lo)) {
            return -1;
        }
        int value = (isdigit(hi) ? hi - '0' : 10 + (tolower(hi) - 'a')) << 4;
        value |= (isdigit(lo) ? lo - '0' : 10 + (tolower(lo) - 'a'));
        out[i] = (uint8_t)value;
    }
    return 0;
}

static int send_admin_message(const uint8_t *payload, size_t len) {
    struct fut_fipc_channel *ctl = fut_fipc_channel_lookup(FIPC_CTL_CHANNEL_ID);
    if (!ctl) {
        fprintf(stderr, "ctltool: control channel not available\n");
        return 1;
    }

    if (fut_fipc_send(ctl, FIPC_SYS_MSG_ADMIN_OP, payload, len) != 0) {
        fprintf(stderr, "ctltool: send failed\n");
        return 1;
    }

    uint8_t buf[256];
    ssize_t r = fut_fipc_recv(ctl, buf, sizeof(buf));
    if (r <= 0) {
        fprintf(stderr, "ctltool: no reply\n");
        return 1;
    }

    struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buf;
    if (msg->type != FIPC_SYS_MSG_ADMIN_RP) {
        fprintf(stderr, "ctltool: unexpected reply type\n");
        return 1;
    }

    const uint8_t *cursor = msg->payload;
    const uint8_t *end = cursor + msg->length;
    if (cursor >= end || *cursor++ != FIPC_ADM_RP_BEGIN) {
        fprintf(stderr, "ctltool: malformed reply\n");
        return 1;
    }
    uint64_t code = 1;
    while (cursor < end) {
        uint8_t tag = *cursor++;
        if (tag == FIPC_ADM_RP_END) {
            break;
        }
        if (tag == FIPC_ADM_RP_CODE) {
            const uint8_t *next = adm_read_u64(cursor, end, &code);
            if (!next) {
                fprintf(stderr, "ctltool: malformed varint\n");
                return 1;
            }
            cursor = next;
        } else {
            const uint8_t *next = adm_read_u64(cursor, end, NULL);
            if (!next) {
                fprintf(stderr, "ctltool: malformed reply\n");
                return 1;
            }
            cursor = next;
        }
    }

    if (code == 0) {
        printf("OK\n");
        return 0;
    }
    printf("ERR %llu\n", (unsigned long long)code);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    enum fipc_admin_op op = 0;
    uint64_t target = 0;
    uint32_t rights = 0;
    uint64_t max_msgs = 0;
    uint64_t max_bytes = 0;
    uint64_t expiry = 0;
    uint32_t revoke = 0;
    uint32_t rate = 0;
    uint32_t burst = 0;
    bool has_rights = false, has_max_msgs = false, has_max_bytes = false, has_expiry = false;
    bool has_rate = false, has_burst = false;
    uint8_t token[FIPC_ADMIN_TOKEN_LEN];
    memcpy(token, default_token, sizeof(token));
    size_t token_len = FIPC_ADMIN_TOKEN_LEN;
    uint64_t lease_id = 0;
    bool lease_custom = false;

    if (strcmp(argv[1], "cap-bind") == 0) {
        op = FIPC_ADM_CAP_BIND;
    } else if (strcmp(argv[1], "cap-unbind") == 0) {
        op = FIPC_ADM_CAP_UNBIND;
    } else if (strcmp(argv[1], "cap-revoke") == 0) {
        op = FIPC_ADM_CAP_REVOKE;
    } else if (strcmp(argv[1], "rate-set") == 0) {
        op = FIPC_ADM_RATE_SET;
    } else {
        usage(argv[0]);
        return 1;
    }

    for (int i = 2; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--chan") == 0 && i + 1 < argc) {
            target = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(arg, "--rights") == 0 && i + 1 < argc) {
            rights = parse_rights(argv[++i]);
            has_rights = true;
        } else if (strcmp(arg, "--max-msgs") == 0 && i + 1 < argc) {
            max_msgs = strtoull(argv[++i], NULL, 0);
            has_max_msgs = true;
        } else if (strcmp(arg, "--max-bytes") == 0 && i + 1 < argc) {
            max_bytes = strtoull(argv[++i], NULL, 0);
            has_max_bytes = true;
        } else if (strcmp(arg, "--expiry") == 0 && i + 1 < argc) {
            expiry = strtoull(argv[++i], NULL, 0);
            has_expiry = true;
        } else if (strcmp(arg, "--rate") == 0 && i + 1 < argc) {
            rate = (uint32_t)strtoul(argv[++i], NULL, 0);
            has_rate = true;
        } else if (strcmp(arg, "--burst") == 0 && i + 1 < argc) {
            burst = (uint32_t)strtoul(argv[++i], NULL, 0);
            has_burst = true;
        } else if (strcmp(arg, "--token") == 0 && i + 1 < argc) {
            if (parse_hex_token(argv[++i], token, FIPC_ADMIN_TOKEN_LEN) != 0) {
                fprintf(stderr, "ctltool: invalid token (need %u hex chars)\n", FIPC_ADMIN_TOKEN_LEN * 2);
                return 1;
            }
        } else if (strcmp(arg, "--lease") == 0 && i + 1 < argc) {
            lease_id = strtoull(argv[++i], NULL, 0);
            lease_custom = true;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (target == 0) {
        usage(argv[0]);
        return 1;
    }

    if (op == FIPC_ADM_CAP_BIND && !lease_custom) {
        lease_id = ((uint64_t)target << 32) ^ (uint64_t)rights ^ max_msgs ^ max_bytes ^ expiry;
    }

    fut_fipc_init();

    uint8_t payload[256];
    uint8_t *w = payload;
    uint8_t *const end = payload + sizeof(payload);

    if (w >= end) {
        fprintf(stderr, "ctltool: buffer too small\n");
        return 1;
    }
    *w++ = FIPC_ADM_BEGIN;
    if (!adm_emit(&w, end, FIPC_ADM_OP, (uint64_t)op) ||
        !adm_emit(&w, end, FIPC_ADM_TARGET, target)) {
        fprintf(stderr, "ctltool: message too large\n");
        return 1;
    }

    switch (op) {
        case FIPC_ADM_CAP_BIND:
            if (!has_rights) {
                fprintf(stderr, "ctltool: cap-bind requires --rights\n");
                return 1;
            }
            if (!adm_emit(&w, end, FIPC_ADM_RIGHTS, rights) ||
                (has_max_msgs && !adm_emit(&w, end, FIPC_ADM_MAX_MSGS, max_msgs)) ||
                (has_max_bytes && !adm_emit(&w, end, FIPC_ADM_MAX_BYTES, max_bytes)) ||
                (has_expiry && !adm_emit(&w, end, FIPC_ADM_EXP_TICK, expiry))) {
                fprintf(stderr, "ctltool: message too large\n");
                return 1;
            }
            if (!adm_emit(&w, end, FIPC_ADM_LEASE, lease_id)) {
                fprintf(stderr, "ctltool: failed to encode lease\n");
                return 1;
            }
            {
                uint64_t mm = has_max_msgs ? max_msgs : 0;
                uint64_t mb = has_max_bytes ? max_bytes : 0;
                uint64_t ex = has_expiry ? expiry : 0;
                uint8_t material[40];
                uint8_t *mat = material;
                write_le64(mat, lease_id); mat += 8;
                write_le64(mat, rights);   mat += 8;
                write_le64(mat, mm);       mat += 8;
                write_le64(mat, mb);       mat += 8;
                write_le64(mat, ex);
                uint8_t hmac[FUT_SHA256_DIGEST_LEN];
                fut_hmac_sha256(default_hmac_key, sizeof(default_hmac_key), material, sizeof(material), hmac);
                if (!adm_emit_bytes(&w, end, FIPC_ADM_HMAC, hmac, FUT_SHA256_DIGEST_LEN)) {
                    fprintf(stderr, "ctltool: failed to encode hmac\n");
                    return 1;
                }
            }
            break;
        case FIPC_ADM_CAP_REVOKE:
            if (!has_rights) {
                fprintf(stderr, "ctltool: cap-revoke requires --rights (send,recv)\n");
                return 1;
            }
            revoke = 0;
            if (rights & FIPC_CAP_R_SEND) revoke |= FIPC_CAP_REVOKE_SEND;
            if (rights & FIPC_CAP_R_RECV) revoke |= FIPC_CAP_REVOKE_RECV;
            if (!adm_emit(&w, end, FIPC_ADM_REVOKE, revoke)) {
                fprintf(stderr, "ctltool: message too large\n");
                return 1;
            }
            break;
        case FIPC_ADM_RATE_SET:
            if (!has_rate || !has_burst) {
                fprintf(stderr, "ctltool: rate-set requires --rate and --burst\n");
                return 1;
            }
            if (!adm_emit(&w, end, FIPC_ADM_RATE, rate) ||
                !adm_emit(&w, end, FIPC_ADM_BURST, burst)) {
                fprintf(stderr, "ctltool: message too large\n");
                return 1;
            }
            break;
        case FIPC_ADM_CAP_UNBIND:
        default:
            break;
    }

    if (!adm_emit_bytes(&w, end, FIPC_ADM_TOKEN, token, token_len)) {
        fprintf(stderr, "ctltool: message too large for token\n");
        return 1;
    }

    if (w >= end) {
        fprintf(stderr, "ctltool: message too large\n");
        return 1;
    }
    *w++ = FIPC_ADM_END;

    return send_admin_message(payload, (size_t)(w - payload));
}
