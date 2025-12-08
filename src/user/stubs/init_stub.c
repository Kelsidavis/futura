// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>
#include <user/stdio.h>
#include <shared/fut_timespec.h>

int main(void) {
    // Init process - wait for compositor (launched by kernel) and start wl-term
    // NOTE: The kernel launches futura-wayland compositor when ENABLE_WAYLAND_DEMO=1
    // We just need to wait for the socket and launch wl-term

    // VERY FIRST message - before anything else
    sys_write(1, "[INIT-STUB] MAIN STARTED\n", 25);

    // First, set up our own file descriptors to /dev/console
    int test_fd = sys_open("/dev/console", 2, 0);  // O_RDWR = 2
    if (test_fd >= 0) {
        const char *test_msg = "[INIT-STUB] Opened /dev/console, fd=%d\n";
        char buf[100];
        int len = 0;
        const char *p = test_msg;
        while (*p && len < 90) {
            if (*p == '%' && *(p+1) == 'd') {
                buf[len++] = '0' + (test_fd / 10);
                buf[len++] = '0' + (test_fd % 10);
                p += 2;
            } else {
                buf[len++] = *p++;
            }
        }
        sys_write(test_fd, buf, len);
        sys_close(test_fd);
    }

    printf("[INIT-STUB] Started, waiting for compositor socket...\n");

    // Wait for compositor (launched by kernel) to create Wayland socket
    int socket_found = 0;

    // Initial delay to let compositor initialize
    for (volatile unsigned long i = 0; i < 500000000UL; i++) {
        // Empty loop - burn cycles to give compositor time to start
    }

    for (int attempt = 0; attempt < 1000; attempt++) {
        // Busy-wait between checks
        for (volatile unsigned long i = 0; i < 5000000UL; i++) {
            // Empty loop
        }

        // Try to open the socket file
        int fd = sys_open("/tmp/wayland-0", 0, 0);  // O_RDONLY
        if (fd >= 0) {
            sys_close(fd);
            printf("[INIT-STUB] Wayland socket found on attempt %d!\n", attempt + 1);
            socket_found = 1;

            // Extra wait for compositor to finish listening setup
            for (volatile unsigned long i = 0; i < 100000000UL; i++) {
                // Empty loop
            }
            break;
        }

        if (attempt % 200 == 199) {
            printf("[INIT-STUB] Still waiting for socket... (attempt %d)\n", attempt + 1);
        }
    }

    if (!socket_found) {
        printf("[INIT-STUB] WARNING: Wayland socket not found after 1000 attempts\n");
    }
    printf("[INIT-STUB] Done waiting, about to fork\n");

    // Fork and exec wl-term
    printf("[INIT-STUB] About to call sys_fork_call()...\n");
    long shell_pid = sys_fork_call();
    printf("[INIT-STUB] sys_fork_call() returned: %ld\n", shell_pid);

    if (shell_pid == 0) {
        // Child process - set up file descriptors and exec into wl-term
        // Use sys_write to /dev/console before closing FDs
        sys_write(1, "[INIT-CHILD] ENTERED CHILD PROCESS\n", 36);

        // Close any inherited file descriptors first
        sys_close(0);
        sys_close(1);
        sys_close(2);

        // Open /dev/console for stdin, stdout, stderr
        int fd0 = sys_open("/dev/console", 2, 0);  // O_RDWR = 2
        int fd1 = sys_open("/dev/console", 2, 0);
        int fd2 = sys_open("/dev/console", 2, 0);

        // Now we can print debug output since stdout is open
        printf("[INIT-CHILD] FDs: fd0=%d fd1=%d fd2=%d\n", fd0, fd1, fd2);

        if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
            // File descriptors aren't in expected order - this is a problem
            printf("[INIT-CHILD] WARNING: FDs not in expected order!\n");
        }

        printf("[INIT-CHILD] About to exec /bin/wl-term\n");
        const char *argv[] = { "/bin/wl-term", 0 };
        const char *envp[] = {
            "WAYLAND_DISPLAY=wayland-0",
            "XDG_RUNTIME_DIR=/tmp",
            0
        };
        sys_execve_call("/bin/wl-term", (char * const *)argv, (char * const *)envp);
        // If execve fails, print error and exit
        printf("[INIT-CHILD] Failed to exec /bin/wl-term\n");
        sys_exit(1);
    } else if (shell_pid > 0) {
        // Parent waits for wl-term to complete (when user exits)
        int wstatus = 0;
        sys_wait4_call(shell_pid, &wstatus, 0, 0);
        printf("wl-term exited. Restarting...\n");

        // Restart wl-term if it exits
        while (1) {
            shell_pid = sys_fork_call();
            if (shell_pid == 0) {
                // Set up file descriptors for restarted wl-term
                sys_close(0);
                sys_close(1);
                sys_close(2);
                sys_open("/dev/console", 2, 0);  // fd 0 (stdin)
                sys_open("/dev/console", 2, 0);  // fd 1 (stdout)
                sys_open("/dev/console", 2, 0);  // fd 2 (stderr)

                const char *argv[] = { "/bin/wl-term", 0 };
                const char *envp[] = {
                    "WAYLAND_DISPLAY=wayland-0",
                    "XDG_RUNTIME_DIR=/tmp",
                    0
                };
                sys_execve_call("/bin/wl-term", (char * const *)argv, (char * const *)envp);
                sys_exit(1);
            } else if (shell_pid > 0) {
                sys_wait4_call(shell_pid, &wstatus, 0, 0);
                printf("wl-term exited. Restarting...\n");
            } else {
                printf("Failed to fork for wl-term\n");
                break;
            }
        }
    } else {
        printf("Failed to fork for wl-term\n");
    }

    // Keep init running - sleep forever if wl-term fails
    fut_timespec_t forever = { .tv_sec = 3600, .tv_nsec = 0 };
    while (1) {
        sys_nanosleep_call(&forever, 0);
    }

    return 0;
}
