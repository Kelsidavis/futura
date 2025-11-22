#ifndef WAYLAND_NOFORTIFY_H
#define WAYLAND_NOFORTIFY_H

/* Ensure the vendored Wayland build never depends on glibc fortify hooks. */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#define _FORTIFY_SOURCE 0

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

#define __memcpy_chk(dst, src, len, bsz) memcpy((dst), (src), (len))
#define __memmove_chk(dst, src, len, bsz) memmove((dst), (src), (len))
#define __memset_chk(dst, c, len, bsz) memset((dst), (c), (len))
#define __snprintf_chk(buf, sz, fl, bsz, fmt, ...) snprintf((buf), (sz), (fmt), __VA_ARGS__)
#define __vsnprintf_chk(buf, sz, fl, bsz, fmt, ap) vsnprintf((buf), (sz), (fmt), (ap))
#define __vfprintf_chk(stream, fl, fmt, ap) vfprintf((stream), (fmt), (ap))
#define __fprintf_chk(stream, fl, fmt, ...) fprintf((stream), (fmt), __VA_ARGS__)
#define __fputs_chk(str, stream, bsz) fputs((str), (stream))
#define __fwrite_chk(ptr, sz, nmemb, stream, bsz) fwrite((ptr), (sz), (nmemb), (stream))

#define mmap64(addr, length, prot, flags, fd, offset) mmap((addr), (length), (prot), (flags), (fd), (offset))

#define __fstat64_time64(fd, st) fstat((fd), (st))
#define __fxstat64(ver, fd, st)  fstat((fd), (st))

#endif /* WAYLAND_NOFORTIFY_H */
