// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STRUCT_IOVEC_DEFINED
#define _STRUCT_IOVEC_DEFINED
struct iovec {
    void  *iov_base;
    size_t iov_len;
};
#endif

#define UIO_MAXIOV 1024

ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

#ifdef __cplusplus
}
#endif
