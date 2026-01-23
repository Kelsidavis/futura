// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>
#include <user/stdio.h>
#include <shared/fut_timespec.h>
#include <shared/fut_stat.h>

int main(void) {
    // Init process - launch compositor, wait for socket, then start wl-term

    // VERY FIRST message - before anything else
    sys_write(1, "[INIT] MAIN STARTED\n", 20);

    // Ensure stdin/stdout/stderr are bound to /dev/console
    int console_fd = sys_open("/dev/console", 2, 0);  // O_RDWR = 2
    if (console_fd >= 0) {
        if (console_fd != 0) {
            sys_dup2_call(console_fd, 0);
        }
        if (console_fd != 1) {
            sys_dup2_call(console_fd, 1);
        }
        if (console_fd != 2) {
            sys_dup2_call(console_fd, 2);
        }
        if (console_fd > 2) {
            sys_close(console_fd);
        }
    }

    printf("[INIT] Started, launching compositor...\n");

    // Create /tmp directory for Wayland socket (should already exist but be safe)
    sys_mkdir_call("/tmp", 0755);

    // Fork and exec the Wayland compositor
    long compositor_pid = sys_fork_call();
    if (compositor_pid == 0) {
        // Child - exec compositor
        sys_write(1, "[INIT] Child: execing compositor\n", 38);

        // Set up stdio
        sys_close(0);
        sys_close(1);
        sys_close(2);
        sys_open("/dev/console", 2, 0);  // stdin
        sys_open("/dev/console", 2, 0);  // stdout
        sys_open("/dev/console", 2, 0);  // stderr

        const char *argv[] = { "/sbin/futura-wayland", 0 };
        const char *envp[] = {
            "XDG_RUNTIME_DIR=/tmp",
            "WAYLAND_DISPLAY=wayland-0",
            0
        };
        sys_execve_call("/sbin/futura-wayland", (char * const *)argv, (char * const *)envp);
        // If exec fails
        sys_write(1, "[INIT] Failed to exec compositor!\n", 39);
        sys_exit(1);
    } else if (compositor_pid < 0) {
        printf("[INIT] Failed to fork for compositor: %ld\n", compositor_pid);
    } else {
        printf("[INIT] Compositor forked, pid=%ld\n", compositor_pid);
    }

    // Wait for compositor to create Wayland socket or readiness marker
    int socket_found = 0;

    printf("[INIT] Waiting 200ms for compositor startup...\n");
    fflush(stdout);
    fut_timespec_t initial_delay = { .tv_sec = 0, .tv_nsec = 200000000 };
    sys_nanosleep_call(&initial_delay, 0);
    printf("[INIT] Initial delay done, looking for socket...\n");
    fflush(stdout);

    const char *ready_paths[] = {
        "/tmp/wayland-ready",
        "/tmp/wayland-0",
        0
    };

    printf("[INIT] About to enter stat loop...\n");
    fflush(stdout);
    for (int attempt = 0; attempt < 1000; attempt++) {
        if (attempt == 0) {
            printf("[INIT] First stat attempt starting...\n");
            fflush(stdout);
        }
        struct fut_stat st;
        for (int i = 0; ready_paths[i]; i++) {
            if (attempt == 0) {
                printf("[INIT] Calling stat(%s)...\n", ready_paths[i]);
                fflush(stdout);
            }
            long stat_rc = sys_stat_call(ready_paths[i], &st);
            if (attempt == 0) {
                printf("[INIT] stat(%s) returned %ld\n", ready_paths[i], stat_rc);
                fflush(stdout);
            }
            if (stat_rc == 0) {
                printf("[INIT] Wayland ready marker found at %s (attempt %d)\n",
                       ready_paths[i], attempt + 1);
                fflush(stdout);
                socket_found = 1;
                break;
            }
        }

        if (socket_found) {
            break;
        }

        if (attempt % 50 == 49) {
            printf("[INIT] Still waiting for socket... (attempt %d)\n", attempt + 1);
            fflush(stdout);
        }

        fut_timespec_t retry_delay = { .tv_sec = 0, .tv_nsec = 20000000 };
        sys_nanosleep_call(&retry_delay, 0);
    }

    if (!socket_found) {
        printf("[INIT] WARNING: Wayland socket not found after 1000 attempts\n");
    }
    printf("[INIT] Done waiting, about to fork wl-term\n");

    // Fork and exec wl-term
    printf("[INIT] About to call sys_fork_call()...\n");
    long shell_pid = sys_fork_call();
    printf("[INIT] sys_fork_call() returned: %ld\n", shell_pid);

    if (shell_pid == 0) {
        // Child process - set up file descriptors and exec into wl-term
        // Use sys_write to /dev/console before closing FDs
        sys_write(1, "[INIT] ENTERED CHILD PROCESS\n", 36);

        // Close any inherited file descriptors first
        sys_close(0);
        sys_close(1);
        sys_close(2);

        // Open /dev/console for stdin, stdout, stderr
        int fd0 = sys_open("/dev/console", 2, 0);  // O_RDWR = 2
        int fd1 = sys_open("/dev/console", 2, 0);
        int fd2 = sys_open("/dev/console", 2, 0);

        // Now we can print debug output since stdout is open
        printf("[INIT] FDs: fd0=%d fd1=%d fd2=%d\n", fd0, fd1, fd2);

        if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
            // File descriptors aren't in expected order - this is a problem
            printf("[INIT] WARNING: FDs not in expected order!\n");
        }

        printf("[INIT] About to exec /bin/wl-term\n");
        const char *argv[] = { "/bin/wl-term", 0 };
        const char *envp[] = {
            "WAYLAND_DISPLAY=wayland-0",
            "XDG_RUNTIME_DIR=/tmp",
            0
        };
        sys_execve_call("/bin/wl-term", (char * const *)argv, (char * const *)envp);
        // If execve fails, print error and exit
        printf("[INIT] Failed to exec /bin/wl-term\n");
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
