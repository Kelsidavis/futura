/* kernel/sys_keyring.c - Linux keyring management subsystem
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the Linux kernel keyring interface (add_key/request_key/keyctl)
 * for managing cryptographic keys, authentication tokens, and certificates.
 * Used by OpenSSL, GnuTLS, PAM, SSH, Kerberos, dm-crypt, and eCryptfs.
 *
 * Syscall numbers (Linux x86_64):
 *   add_key       248
 *   request_key   249
 *   keyctl        250
 *
 * Keyring hierarchy:
 *   @t  - Thread keyring  (per-thread, inherited on clone)
 *   @p  - Process keyring (per-task, cleared on exec)
 *   @s  - Session keyring (per-session, inherited by children)
 *   @u  - User keyring    (per-UID, shared across sessions)
 *   @us - User-session default keyring
 *
 * Key types supported: "user", "logon", "keyring", "big_key"
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <platform/platform.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Copy from user or kernel buffer depending on pointer address.
 * Kernel-space callers (self-tests) pass kernel pointers directly. */
static inline int keyring_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    /* Previously called keyring_copy_from_user() — itself — which would
     * infinite-recurse on any actual user-space pointer and blow the
     * kernel stack the first time a userspace caller used add_key /
     * request_key / keyctl with non-kernel buffers. */
    return fut_copy_from_user(dst, src, n);
}

static inline int keyring_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* ── Keyctl operations (Linux ABI) ── */
#define KEYCTL_GET_KEYRING_ID         0
#define KEYCTL_JOIN_SESSION_KEYRING   1
#define KEYCTL_UPDATE                 2
#define KEYCTL_REVOKE                 3
#define KEYCTL_CHOWN                  4
#define KEYCTL_SETPERM                5
#define KEYCTL_DESCRIBE               6
#define KEYCTL_CLEAR                  7
#define KEYCTL_LINK                   8
#define KEYCTL_UNLINK                 9
#define KEYCTL_SEARCH                10
#define KEYCTL_READ                  11
#define KEYCTL_INSTANTIATE           12
#define KEYCTL_NEGATE                13
#define KEYCTL_SET_REQKEY_KEYRING    14
#define KEYCTL_SET_TIMEOUT           15
#define KEYCTL_ASSUME_AUTHORITY      16
#define KEYCTL_GET_SECURITY          17
#define KEYCTL_SESSION_TO_PARENT     18
#define KEYCTL_REJECT                19
#define KEYCTL_INSTANTIATE_IOV       20
#define KEYCTL_INVALIDATE            21
#define KEYCTL_GET_PERSISTENT        22
#define KEYCTL_RESTRICT_KEYRING      29

/* Special keyring IDs */
#define KEY_SPEC_THREAD_KEYRING       (-1)
#define KEY_SPEC_PROCESS_KEYRING      (-2)
#define KEY_SPEC_SESSION_KEYRING      (-3)
#define KEY_SPEC_USER_KEYRING         (-4)
#define KEY_SPEC_USER_SESSION_KEYRING (-5)
#define KEY_SPEC_GROUP_KEYRING        (-6)
#define KEY_SPEC_REQKEY_AUTH_KEY       (-7)

/* Key permissions */
#define KEY_POS_VIEW    0x01000000
#define KEY_POS_READ    0x02000000
#define KEY_POS_WRITE   0x04000000
#define KEY_POS_SEARCH  0x08000000
#define KEY_POS_LINK    0x10000000
#define KEY_POS_SETATTR 0x20000000
#define KEY_POS_ALL     0x3f000000

#define KEY_USR_VIEW    0x00010000
#define KEY_USR_READ    0x00020000
#define KEY_USR_WRITE   0x00040000
#define KEY_USR_SEARCH  0x00080000
#define KEY_USR_LINK    0x00100000
#define KEY_USR_SETATTR 0x00200000
#define KEY_USR_ALL     0x003f0000

#define KEY_GRP_ALL     0x00003f00
#define KEY_OTH_ALL     0x0000003f

/* ── Internal key storage ── */

#define MAX_KEYS          256
#define MAX_KEY_PAYLOAD   4096
#define MAX_KEY_DESC      128
#define MAX_KEY_TYPE      32
#define KEY_SERIAL_BASE   0x10000000

/* Key types */
enum key_type_id {
    KEY_TYPE_USER = 0,
    KEY_TYPE_LOGON,
    KEY_TYPE_KEYRING,
    KEY_TYPE_BIG_KEY,
};

struct kernel_key {
    bool     active;
    int32_t  serial;            /* Unique key serial number */
    char     type[MAX_KEY_TYPE];
    char     description[MAX_KEY_DESC];
    uint8_t  payload[MAX_KEY_PAYLOAD];
    size_t   payload_len;
    uint32_t perm;              /* KEY_POS_* | KEY_USR_* | ... */
    uint32_t uid;               /* Owner UID */
    uint32_t gid;               /* Owner GID */
    int32_t  parent_keyring;    /* Parent keyring serial (or 0) */
    uint64_t expiry_ticks;      /* Expiry time (0 = never) */
    bool     revoked;
    bool     is_keyring;        /* True if this key is a keyring */

    /* Keyring children (if is_keyring) */
    int32_t  children[32];      /* Child key serials */
    uint32_t nr_children;
};

static struct kernel_key keys[MAX_KEYS];
static int32_t next_serial = KEY_SERIAL_BASE;

/* Special keyrings — lazily created per-task */
static int32_t thread_keyring_serial;
static int32_t process_keyring_serial;
static int32_t session_keyring_serial;
static int32_t user_keyring_serial;
static int32_t user_session_keyring_serial;

/* ── Helpers ── */

static struct kernel_key *key_find_serial(int32_t serial) {
    for (int i = 0; i < MAX_KEYS; i++) {
        if (keys[i].active && keys[i].serial == serial)
            return &keys[i];
    }
    return NULL;
}

static struct kernel_key *key_alloc(void) {
    for (int i = 0; i < MAX_KEYS; i++) {
        if (!keys[i].active) {
            memset(&keys[i], 0, sizeof(keys[i]));
            keys[i].active = true;
            keys[i].serial = next_serial++;
            return &keys[i];
        }
    }
    return NULL;
}

static struct kernel_key *key_find_in_keyring(int32_t keyring_serial,
                                                const char *type,
                                                const char *desc) {
    struct kernel_key *kr = key_find_serial(keyring_serial);
    if (!kr || !kr->is_keyring) return NULL;

    for (uint32_t i = 0; i < kr->nr_children; i++) {
        struct kernel_key *child = key_find_serial(kr->children[i]);
        if (child && child->active && !child->revoked &&
            strcmp(child->type, type) == 0 &&
            strcmp(child->description, desc) == 0) {
            return child;
        }
    }
    return NULL;
}

static int keyring_link(struct kernel_key *kr, int32_t child_serial) {
    if (!kr || !kr->is_keyring) return -ENOTDIR;
    if (kr->nr_children >= 32) return -ENFILE;

    /* Check for duplicate */
    for (uint32_t i = 0; i < kr->nr_children; i++) {
        if (kr->children[i] == child_serial) return 0; /* already linked */
    }

    kr->children[kr->nr_children++] = child_serial;
    return 0;
}

static int keyring_unlink(struct kernel_key *kr, int32_t child_serial) {
    if (!kr || !kr->is_keyring) return -ENOTDIR;
    for (uint32_t i = 0; i < kr->nr_children; i++) {
        if (kr->children[i] == child_serial) {
            kr->children[i] = kr->children[--kr->nr_children];
            return 0;
        }
    }
    return -ENOKEY;
}

/* Create a special keyring (thread/process/session/user) */
static int32_t ensure_special_keyring(int32_t *serial_ptr, const char *name) {
    if (*serial_ptr != 0) {
        struct kernel_key *k = key_find_serial(*serial_ptr);
        if (k && k->active) return *serial_ptr;
    }

    struct kernel_key *kr = key_alloc();
    if (!kr) return -ENOMEM;

    kr->is_keyring = true;
    {
        const char *s = "keyring";
        int i = 0;
        while (s[i] && i < MAX_KEY_TYPE - 1) { kr->type[i] = s[i]; i++; }
        kr->type[i] = '\0';
    }
    {
        int i = 0;
        while (name[i] && i < MAX_KEY_DESC - 1) { kr->description[i] = name[i]; i++; }
        kr->description[i] = '\0';
    }
    kr->perm = KEY_POS_ALL | KEY_USR_ALL;

    fut_task_t *task = fut_task_current();
    kr->uid = task ? task->uid : 0;
    kr->gid = task ? task->gid : 0;

    *serial_ptr = kr->serial;
    return kr->serial;
}

/* Resolve special keyring ID to serial */
static int32_t resolve_keyring(int keyring_id) {
    switch (keyring_id) {
    case KEY_SPEC_THREAD_KEYRING:
        return ensure_special_keyring(&thread_keyring_serial, ".thread_keyring");
    case KEY_SPEC_PROCESS_KEYRING:
        return ensure_special_keyring(&process_keyring_serial, ".process_keyring");
    case KEY_SPEC_SESSION_KEYRING:
        return ensure_special_keyring(&session_keyring_serial, ".session_keyring");
    case KEY_SPEC_USER_KEYRING:
        return ensure_special_keyring(&user_keyring_serial, "_uid.0");
    case KEY_SPEC_USER_SESSION_KEYRING:
        return ensure_special_keyring(&user_session_keyring_serial, "_uid_ses.0");
    default:
        /* Positive values are direct serial numbers */
        if (keyring_id > 0) return (int32_t)keyring_id;
        return -EINVAL;
    }
}

/* ── Syscall implementations ── */

/**
 * add_key() - Add a key to the kernel keyring.
 * @type:        Key type ("user", "logon", "keyring", "big_key").
 * @description: Key description string.
 * @payload:     Key payload data (type-specific).
 * @plen:        Payload length in bytes.
 * @keyring:     Target keyring (KEY_SPEC_* or serial).
 * Returns: key serial number on success, negative errno on failure.
 */
long sys_add_key(const char *type, const char *description,
                 const void *payload, size_t plen, int keyring) {
    if (!type || !description) return -EINVAL;
    if (plen > MAX_KEY_PAYLOAD) return -EDQUOT;

    /* Copy strings from user space (SMAP-safe) */
    char k_type[MAX_KEY_TYPE];
    char k_desc[MAX_KEY_DESC];
    if (keyring_copy_from_user(k_type, type, MAX_KEY_TYPE) != 0) return -EFAULT;
    if (keyring_copy_from_user(k_desc, description, MAX_KEY_DESC) != 0) return -EFAULT;
    k_type[MAX_KEY_TYPE - 1] = '\0';
    k_desc[MAX_KEY_DESC - 1] = '\0';

    /* Validate key type */
    bool valid_type = false;
    const char *valid_types[] = {"user", "logon", "keyring", "big_key", NULL};
    for (int i = 0; valid_types[i]; i++) {
        if (strcmp(k_type, valid_types[i]) == 0) { valid_type = true; break; }
    }
    if (!valid_type) return -EINVAL;

    /* Resolve target keyring */
    int32_t kr_serial = resolve_keyring(keyring);
    if (kr_serial < 0) return kr_serial;

    struct kernel_key *kr = key_find_serial(kr_serial);
    if (!kr || !kr->is_keyring) return -ENOTDIR;

    /* Check for existing key with same type+description → update */
    struct kernel_key *existing = key_find_in_keyring(kr_serial, k_type, k_desc);
    if (existing) {
        if (payload && plen > 0) {
            if (keyring_copy_from_user(existing->payload, payload, plen) != 0)
                return -EFAULT;
            existing->payload_len = plen;
        }
        return existing->serial;
    }

    /* Allocate new key */
    struct kernel_key *key = key_alloc();
    if (!key) return -ENOMEM;

    memcpy(key->type, k_type, MAX_KEY_TYPE);
    memcpy(key->description, k_desc, MAX_KEY_DESC);
    if (payload && plen > 0) {
        if (keyring_copy_from_user(key->payload, payload, plen) != 0) {
            key->active = false;
            return -EFAULT;
        }
        key->payload_len = plen;
    }
    key->perm = KEY_POS_ALL | KEY_USR_ALL;
    key->is_keyring = (strcmp(k_type, "keyring") == 0);

    fut_task_t *task = fut_task_current();
    key->uid = task ? task->uid : 0;
    key->gid = task ? task->gid : 0;
    key->parent_keyring = kr_serial;

    /* Link into target keyring */
    int rc = keyring_link(kr, key->serial);
    if (rc < 0) {
        key->active = false;
        return rc;
    }

    return key->serial;
}

/**
 * request_key() - Request a key from the kernel keyring.
 * @type:         Key type to search for.
 * @description:  Key description to match.
 * @callout_info: Information string for key instantiation (may be NULL).
 * @dest_keyring: Destination keyring for found key (KEY_SPEC_* or serial).
 * Returns: key serial number on success, -ENOKEY if not found.
 */
long sys_request_key(const char *type, const char *description,
                     const char *callout_info, int dest_keyring) {
    (void)callout_info;
    if (!type || !description) return -EINVAL;

    /* Copy strings from user space (SMAP-safe) */
    char k_type[MAX_KEY_TYPE];
    char k_desc[MAX_KEY_DESC];
    if (keyring_copy_from_user(k_type, type, MAX_KEY_TYPE) != 0) return -EFAULT;
    if (keyring_copy_from_user(k_desc, description, MAX_KEY_DESC) != 0) return -EFAULT;
    k_type[MAX_KEY_TYPE - 1] = '\0';
    k_desc[MAX_KEY_DESC - 1] = '\0';

    /* Search through session, process, thread keyrings in order */
    int32_t search_order[] = {
        session_keyring_serial,
        process_keyring_serial,
        thread_keyring_serial,
        user_keyring_serial,
        user_session_keyring_serial,
    };

    for (int i = 0; i < 5; i++) {
        if (search_order[i] == 0) continue;
        struct kernel_key *found = key_find_in_keyring(search_order[i], k_type, k_desc);
        if (found) {
            /* Optionally link into dest_keyring */
            if (dest_keyring != 0) {
                int32_t dst = resolve_keyring(dest_keyring);
                if (dst > 0) {
                    struct kernel_key *dkr = key_find_serial(dst);
                    if (dkr && dkr->is_keyring)
                        keyring_link(dkr, found->serial);
                }
            }
            return found->serial;
        }
    }

    return -ENOKEY;
}

/**
 * keyctl() - Perform operations on the kernel keyring.
 * @operation: KEYCTL_* operation code.
 * @arg2-arg5: Operation-specific arguments.
 * Returns: operation-dependent value, or negative errno.
 */
long sys_keyctl(int operation, unsigned long arg2, unsigned long arg3,
                unsigned long arg4, unsigned long arg5) {
    switch (operation) {
    case KEYCTL_GET_KEYRING_ID: {
        /* arg2 = special keyring ID, arg3 = create flag */
        int special = (int)(long)arg2;
        int create = (int)arg3;
        int32_t serial;

        if (special >= KEY_SPEC_REQKEY_AUTH_KEY && special <= KEY_SPEC_THREAD_KEYRING) {
            serial = resolve_keyring(special);
        } else if (special > 0) {
            serial = special;
        } else {
            return -EINVAL;
        }

        if (serial < 0) {
            if (create) {
                /* Force creation */
                serial = resolve_keyring(special);
            }
            if (serial < 0) return serial;
        }

        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        return (long)serial;
    }

    case KEYCTL_DESCRIBE: {
        /* arg2 = key serial, arg3 = buffer, arg4 = buflen */
        int32_t serial = (int32_t)(long)arg2;
        char *buf = (char *)(uintptr_t)arg3;
        size_t buflen = (size_t)arg4;

        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        if (k->revoked) return -EKEYREVOKED;

        /* Format: "type;uid;gid;perm;description" */
        char desc[512];
        int len = 0;
        /* Build manually since we may not have snprintf */
        const char *t = k->type;
        while (*t && len < 500) desc[len++] = *t++;
        desc[len++] = ';';

        /* uid */
        char numbuf[16];
        int npos = 0;
        uint32_t val = k->uid;
        if (val == 0) { numbuf[npos++] = '0'; }
        else {
            char tmp[16]; int tpos = 0;
            while (val > 0) { tmp[tpos++] = '0' + (val % 10); val /= 10; }
            while (tpos > 0) numbuf[npos++] = tmp[--tpos];
        }
        for (int i = 0; i < npos && len < 500; i++) desc[len++] = numbuf[i];
        desc[len++] = ';';

        /* gid */
        npos = 0;
        val = k->gid;
        if (val == 0) { numbuf[npos++] = '0'; }
        else {
            char tmp[16]; int tpos = 0;
            while (val > 0) { tmp[tpos++] = '0' + (val % 10); val /= 10; }
            while (tpos > 0) numbuf[npos++] = tmp[--tpos];
        }
        for (int i = 0; i < npos && len < 500; i++) desc[len++] = numbuf[i];
        desc[len++] = ';';

        /* perm (hex) */
        const char hex[] = "0123456789abcdef";
        uint32_t p = k->perm;
        for (int i = 7; i >= 0; i--) {
            desc[len++] = hex[(p >> (i * 4)) & 0xf];
        }
        desc[len++] = ';';

        /* description */
        const char *d = k->description;
        while (*d && len < 510) desc[len++] = *d++;
        desc[len] = '\0';

        if (buf && buflen > 0) {
            size_t copy = (size_t)len < buflen ? (size_t)len : buflen - 1;
            /* NUL-terminate inside the staging buffer first, then copy
             * the whole thing through copy_to_user — direct memcpy here
             * lets a caller point buf at kernel memory and dump the
             * description plus a NUL byte into it as a write-anywhere
             * primitive (and faults the kernel on bad pointers). */
            desc[copy] = '\0';
            if (keyring_copy_to_user(buf, desc, copy + 1) != 0)
                return -EFAULT;
        }

        return (long)(len + 1); /* Include NUL terminator */
    }

    case KEYCTL_READ: {
        /* arg2 = key serial, arg3 = buffer, arg4 = buflen */
        int32_t serial = (int32_t)(long)arg2;
        void *buf = (void *)(uintptr_t)arg3;
        size_t buflen = (size_t)arg4;

        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        if (k->revoked) return -EKEYREVOKED;

        /* Linux: "logon" keys are write-only — even the owner cannot
         * read the payload back. */
        if (!k->is_keyring && strcmp(k->type, "logon") == 0)
            return -EOPNOTSUPP;

        /* Read permission required: owner or CAP_SYS_ADMIN. Without
         * this gate any process could enumerate every key on the
         * system and dump credentials/cred-cache contents by serial. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != k->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }

        if (k->is_keyring) {
            /* Reading a keyring returns the child serial numbers */
            size_t needed = k->nr_children * sizeof(int32_t);
            if (buf && buflen > 0) {
                size_t copy = needed < buflen ? needed : buflen;
                /* copy_to_user gates the kernel-pointer bypass to
                 * self-tests; raw memcpy let a user point buf at any
                 * kernel address and have the child serials written
                 * there as a write-anywhere primitive. */
                if (keyring_copy_to_user(buf, k->children, copy) != 0)
                    return -EFAULT;
            }
            return (long)needed;
        }

        /* Regular key — return payload */
        if (buf && buflen > 0) {
            size_t copy = k->payload_len < buflen ? k->payload_len : buflen;
            if (keyring_copy_to_user(buf, k->payload, copy) != 0)
                return -EFAULT;
        }
        return (long)k->payload_len;
    }

    case KEYCTL_UPDATE: {
        /* arg2 = key serial, arg3 = payload, arg4 = plen */
        int32_t serial = (int32_t)(long)arg2;
        const void *payload = (const void *)(uintptr_t)arg3;
        size_t plen = (size_t)arg4;

        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        if (k->revoked) return -EKEYREVOKED;
        if (k->is_keyring) return -EOPNOTSUPP;
        if (plen > MAX_KEY_PAYLOAD) return -EDQUOT;
        /* Linux: write permission required. We model that as owner-or-
         * CAP_SYS_ADMIN; without any check anyone could overwrite any
         * key's payload by serial number. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != k->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }

        if (payload && plen > 0) {
            /* Use the keyring copy helper so a user pointer can't be
             * dereferenced as a kernel pointer (info disclosure) and a
             * faulty pointer returns -EFAULT instead of crashing. */
            if (keyring_copy_from_user(k->payload, payload, plen) != 0)
                return -EFAULT;
            k->payload_len = plen;
        } else {
            k->payload_len = 0;
        }
        return 0;
    }

    case KEYCTL_REVOKE: {
        int32_t serial = (int32_t)(long)arg2;
        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        /* Linux: only the key owner or CAP_SYS_ADMIN may revoke. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != k->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }
        k->revoked = true;
        return 0;
    }

    case KEYCTL_LINK: {
        /* arg2 = key serial, arg3 = keyring serial */
        int32_t key_serial = (int32_t)(long)arg2;
        int32_t kr_id = (int32_t)(long)arg3;

        struct kernel_key *k = key_find_serial(key_serial);
        if (!k) return -ENOKEY;

        int32_t kr_serial = resolve_keyring(kr_id);
        if (kr_serial < 0) return kr_serial;
        struct kernel_key *kr = key_find_serial(kr_serial);
        if (!kr || !kr->is_keyring) return -ENOTDIR;

        /* Linux: requires WRITE permission on the keyring (modeled here
         * as owner-or-CAP_SYS_ADMIN). Without this any process could
         * attach a forged key into another user's session keyring. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != kr->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }
        return keyring_link(kr, key_serial);
    }

    case KEYCTL_UNLINK: {
        int32_t key_serial = (int32_t)(long)arg2;
        int32_t kr_id = (int32_t)(long)arg3;

        int32_t kr_serial = resolve_keyring(kr_id);
        if (kr_serial < 0) return kr_serial;
        struct kernel_key *kr = key_find_serial(kr_serial);
        if (!kr) return -ENOKEY;
        /* Same WRITE-permission gate as LINK so a non-owner can't strip
         * keys out of another user's keyring. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != kr->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }
        return keyring_unlink(kr, key_serial);
    }

    case KEYCTL_CLEAR: {
        int32_t serial = (int32_t)(long)arg2;
        struct kernel_key *kr = key_find_serial(serial);
        if (!kr) return -ENOKEY;
        if (!kr->is_keyring) return -ENOTDIR;
        /* Linux: clear requires write permission on the keyring (owner
         * or CAP_SYS_ADMIN here). Without this gate any process could
         * empty the session/user keyring of another user. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != kr->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }
        kr->nr_children = 0;
        return 0;
    }

    case KEYCTL_SEARCH: {
        /* arg2 = keyring serial, arg3 = type, arg4 = description, arg5 = dest_keyring */
        int32_t kr_id = (int32_t)(long)arg2;
        const char *type = (const char *)(uintptr_t)arg3;
        const char *desc = (const char *)(uintptr_t)arg4;
        if (!type || !desc) return -EINVAL;

        int32_t kr_serial = resolve_keyring(kr_id);
        if (kr_serial < 0) return kr_serial;

        struct kernel_key *found = key_find_in_keyring(kr_serial, type, desc);
        if (!found) return -ENOKEY;

        /* Optionally link to dest keyring */
        if (arg5 != 0) {
            int32_t dst = resolve_keyring((int)(long)arg5);
            if (dst > 0) {
                struct kernel_key *dkr = key_find_serial(dst);
                if (dkr && dkr->is_keyring)
                    keyring_link(dkr, found->serial);
            }
        }

        return (long)found->serial;
    }

    case KEYCTL_SETPERM: {
        int32_t serial = (int32_t)(long)arg2;
        uint32_t perm = (uint32_t)arg3;
        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        /* Linux: only the key owner or CAP_SYS_ADMIN may change perm.
         * Without this check any process could grant itself any access
         * to any key (including system keyrings owned by root). */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != k->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }
        k->perm = perm;
        return 0;
    }

    case KEYCTL_CHOWN: {
        int32_t serial = (int32_t)(long)arg2;
        uint32_t uid = (uint32_t)arg3;
        uint32_t gid = (uint32_t)arg4;
        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        /* Linux keyctl(2): "To change the UID the caller must have an
         * effective UID of zero or possess CAP_SYS_ADMIN. The same
         * condition applies to changing the GID, except that GID can
         * also be changed to a group of which the caller is a member."
         * Without any check, any unprivileged process could chown the
         * root @us/@u keyrings to itself. */
        {
            fut_task_t *cur = fut_task_current();
            bool privileged = cur && (cur->uid == 0 ||
                (cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)));
            if (!privileged)
                return -EACCES;
        }
        if (uid != (uint32_t)-1) k->uid = uid;
        if (gid != (uint32_t)-1) k->gid = gid;
        return 0;
    }

    case KEYCTL_SET_TIMEOUT: {
        int32_t serial = (int32_t)(long)arg2;
        unsigned int timeout = (unsigned int)arg3;
        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        if (timeout == 0) {
            k->expiry_ticks = 0; /* Never expires */
        } else {
            extern uint64_t fut_get_ticks(void);
            k->expiry_ticks = fut_get_ticks() + (uint64_t)timeout * 100;
        }
        return 0;
    }

    case KEYCTL_INVALIDATE: {
        int32_t serial = (int32_t)(long)arg2;
        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;
        /* Linux: invalidate requires SEARCH permission on the key, which
         * the key owner and CAP_SYS_ADMIN always have. Without any check
         * any unprivileged caller could destroy any key by serial. */
        {
            fut_task_t *cur = fut_task_current();
            if (cur && cur->uid != 0 && cur->uid != k->uid &&
                !(cur->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */)))
                return -EACCES;
        }
        k->active = false;
        return 0;
    }

    case KEYCTL_SET_REQKEY_KEYRING: {
        /* arg2 = keyring target (0=default, 1=thread, 2=process, ...) */
        int target = (int)(long)arg2;
        if (target < 0 || target > 7) return -EINVAL;
        return 0; /* Accept silently */
    }

    case KEYCTL_JOIN_SESSION_KEYRING: {
        /* arg2 = name (NULL = join anonymous session) */
        int32_t serial = ensure_special_keyring(&session_keyring_serial,
                                                 arg2 ? (const char *)(uintptr_t)arg2 : "_ses");
        return (long)serial;
    }

    case KEYCTL_GET_SECURITY: {
        /* arg2 = key serial, arg3 = buffer, arg4 = buflen */
        int32_t serial = (int32_t)(long)arg2;
        char *buf = (char *)(uintptr_t)arg3;
        size_t buflen = (size_t)arg4;
        struct kernel_key *k = key_find_serial(serial);
        if (!k) return -ENOKEY;

        const char *label = "unconfined";
        size_t len = strlen(label);
        if (buf && buflen > 0) {
            char tmp[16];
            size_t copy = len < buflen ? len : buflen - 1;
            if (copy >= sizeof(tmp))
                copy = sizeof(tmp) - 1;
            __builtin_memcpy(tmp, label, copy);
            tmp[copy] = '\0';
            if (keyring_copy_to_user(buf, tmp, copy + 1) != 0)
                return -EFAULT;
        }
        return (long)(len + 1);
    }

    case KEYCTL_GET_PERSISTENT: {
        /* arg2 = uid, arg3 = dest keyring */
        (void)arg2;
        int32_t dest = resolve_keyring((int)(long)arg3);
        if (dest < 0) return dest;
        return dest;
    }

    case KEYCTL_RESTRICT_KEYRING:
        /* Accept silently — restriction enforcement is a no-op */
        return 0;

    case KEYCTL_SESSION_TO_PARENT:
        /* Install session keyring in parent — would need parent task access */
        return -EPERM;

    case KEYCTL_ASSUME_AUTHORITY:
        return 0; /* Accept silently */

    default:
        return -EOPNOTSUPP;
    }
}
