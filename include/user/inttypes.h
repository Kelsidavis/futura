// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRId8     "d"
#define PRId16    "d"
#define PRId32    "d"
#define PRId64    "lld"
#define PRIi8     "i"
#define PRIi16    "i"
#define PRIi32    "i"
#define PRIi64    "lli"
#define PRIu8     "u"
#define PRIu16    "u"
#define PRIu32    "u"
#define PRIu64    "llu"
#define PRIx8     "x"
#define PRIx16    "x"
#define PRIx32    "x"
#define PRIx64    "llx"
#define PRIX8     "X"
#define PRIX16    "X"
#define PRIX32    "X"
#define PRIX64    "llX"
#define PRIo8     "o"
#define PRIo16    "o"
#define PRIo32    "o"
#define PRIo64    "llo"

#define PRIdMAX   "lld"
#define PRIuMAX   "llu"
#define PRIxMAX   "llx"

#define PRIdPTR   "ld"
#define PRIuPTR   "lu"
#define PRIxPTR   "lx"

#define SCNd8     "hhd"
#define SCNd16    "hd"
#define SCNd32    "d"
#define SCNd64    "lld"
#define SCNu64    "llu"
#define SCNx64    "llx"

typedef struct {
    intmax_t quot;
    intmax_t rem;
} imaxdiv_t;

intmax_t  imaxabs(intmax_t j);
imaxdiv_t imaxdiv(intmax_t numer, intmax_t denom);

#ifdef __cplusplus
}
#endif
