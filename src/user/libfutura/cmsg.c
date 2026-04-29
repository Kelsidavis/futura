// SPDX-License-Identifier: MPL-2.0
//
// Out-of-line implementation for the CMSG_NXTHDR() macro defined in
// <sys/socket.h>.  glibc compiles the iteration step into a small
// helper called __cmsg_nxthdr; libwayland (and any other code that
// uses CMSG_NXTHDR for SCM_RIGHTS fd-passing) generates calls to it.

#include <stddef.h>
#include <sys/socket.h>

struct cmsghdr *__cmsg_nxthdr(struct msghdr *mhdr, struct cmsghdr *cmsg) {
    if (!mhdr || !cmsg) return (struct cmsghdr *)0;

    size_t cmsg_len = (size_t)cmsg->cmsg_len;
    if (cmsg_len < sizeof(struct cmsghdr)) return (struct cmsghdr *)0;

    /* Step past this entry, padded to size_t alignment. */
    unsigned char *next = (unsigned char *)cmsg + CMSG_ALIGN(cmsg_len);
    unsigned char *ctl_start = (unsigned char *)mhdr->msg_control;
    unsigned char *ctl_end   = ctl_start + mhdr->msg_controllen;

    if (next + sizeof(struct cmsghdr) > ctl_end) {
        return (struct cmsghdr *)0;
    }
    return (struct cmsghdr *)next;
}
