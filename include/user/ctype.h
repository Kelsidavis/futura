// SPDX-License-Identifier: MPL-2.0
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

static inline int isspace(int c) { return c == ' ' || (c >= 0x09 && c <= 0x0D); }
static inline int isdigit(int c) { return c >= '0' && c <= '9'; }
static inline int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static inline int isalpha(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static inline int isalnum(int c) { return isalpha(c) || isdigit(c); }
static inline int isupper(int c) { return c >= 'A' && c <= 'Z'; }
static inline int islower(int c) { return c >= 'a' && c <= 'z'; }
static inline int isprint(int c) { return c >= 0x20 && c < 0x7F; }
static inline int iscntrl(int c) { return (c >= 0 && c < 0x20) || c == 0x7F; }
static inline int isgraph(int c) { return c > 0x20 && c < 0x7F; }
static inline int ispunct(int c) {
    return isprint(c) && !isspace(c) && !isalnum(c);
}
static inline int tolower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}
static inline int toupper(int c) {
    return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
}

#ifdef __cplusplus
}
#endif
