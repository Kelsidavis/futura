/* Test program to verify int 0x80 socket syscalls work */

#include <user/stdio.h>
#include <user/stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

int main(void) {
    printf("[TEST_SOCKET] Testing int 0x80 socket syscalls\n");

    /* Test 1: Create a Unix domain socket */
    printf("[TEST_SOCKET] Test 1: Creating AF_UNIX SOCK_STREAM socket\n");
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[TEST_SOCKET] FAILED: socket() returned %d, errno=%d\n", sock, errno);
        return 1;
    }
    printf("[TEST_SOCKET] SUCCESS: socket fd=%d\n", sock);

    /* Test 2: Try to bind to a socket path */
    printf("[TEST_SOCKET] Test 2: Binding to socket path\n");
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/test-wayland-socket");

    int ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        printf("[TEST_SOCKET] FAILED: bind() returned %d, errno=%d\n", ret, errno);
        close(sock);
        return 1;
    }
    printf("[TEST_SOCKET] SUCCESS: bind() succeeded\n");

    /* Test 3: Try to listen */
    printf("[TEST_SOCKET] Test 3: Listening on socket\n");
    ret = listen(sock, 1);
    if (ret < 0) {
        printf("[TEST_SOCKET] FAILED: listen() returned %d, errno=%d\n", ret, errno);
        close(sock);
        return 1;
    }
    printf("[TEST_SOCKET] SUCCESS: listen() succeeded\n");

    /* Cleanup */
    close(sock);
    printf("[TEST_SOCKET] All tests passed!\n");
    return 0;
}
