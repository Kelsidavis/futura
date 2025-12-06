// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>
#include <user/stdio.h>
#include <shared/fut_timespec.h>

int main(void) {
    // Init process - launch Wayland compositor and wl-term terminal

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

    // Create /tmp directory for Wayland socket
    sys_mkdir_call("/tmp", 0755);
    printf("[INIT-STUB] Created /tmp directory\n");

    // Fork and exec the Wayland compositor first
    printf("[INIT-STUB] Launching futura-wayland compositor...\n");
    long compositor_pid = sys_fork_call();

    if (compositor_pid == 0) {
        // Child process - exec into futura-wayland compositor
        sys_close(0);
        sys_close(1);
        sys_close(2);
        sys_open("/dev/console", 2, 0);  // fd 0 (stdin)
        sys_open("/dev/console", 2, 0);  // fd 1 (stdout)
        sys_open("/dev/console", 2, 0);  // fd 2 (stderr)

        const char *argv[] = { "/sbin/futura-wayland", 0 };
        const char *envp[] = {
            "XDG_RUNTIME_DIR=/tmp",
            0
        };
        sys_execve_call("/sbin/futura-wayland", (char * const *)argv, (char * const *)envp);
        // If execve fails, print error and exit
        printf("[INIT-STUB] FATAL: Failed to exec /sbin/futura-wayland\n");
        sys_exit(1);
    } else if (compositor_pid < 0) {
        printf("[INIT-STUB] FATAL: Failed to fork for compositor\n");
        // Fall through and try wl-term anyway
    } else {
        printf("[INIT-STUB] Compositor launched with PID %ld\n", compositor_pid);
    }

    // Give compositor time to initialize and create Wayland socket
    printf("[INIT-STUB] Waiting for compositor to start...\n");
    fut_timespec_t delay = { .tv_sec = 2, .tv_nsec = 0 };
    sys_nanosleep_call(&delay, 0);

    // Fork and exec wl-term
    printf("[INIT-STUB] Launching wl-term...\n");
    long shell_pid = sys_fork_call();

    if (shell_pid == 0) {
        // Child process - set up file descriptors and exec into wl-term
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
