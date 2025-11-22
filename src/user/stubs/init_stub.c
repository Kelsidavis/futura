// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>
#include <user/stdio.h>
#include <shared/fut_timespec.h>

int main(void) {
    // Init process - launch shell on framebuffer console

    printf("Futura OS Init - Launching shell...\n");

    // Brief delay to let boot messages settle
    fut_timespec_t delay = { .tv_sec = 1, .tv_nsec = 0 };
    sys_nanosleep_call(&delay, 0);

    // Fork and exec shell
    long shell_pid = sys_fork_call();

    if (shell_pid == 0) {
        // Child process - exec into shell
        const char *argv[] = { "/bin/shell", 0 };
        const char *envp[] = { 0 };
        sys_execve_call("/bin/shell", (char * const *)argv, (char * const *)envp);
        // If execve fails, print error and exit
        printf("Failed to exec /bin/shell\n");
        sys_exit(1);
    } else if (shell_pid > 0) {
        // Parent waits for shell to complete (when user exits)
        int wstatus = 0;
        sys_wait4_call(shell_pid, &wstatus, 0, 0);
        printf("Shell exited. Restarting...\n");

        // Restart shell if it exits
        while (1) {
            shell_pid = sys_fork_call();
            if (shell_pid == 0) {
                const char *argv[] = { "/bin/shell", 0 };
                const char *envp[] = { 0 };
                sys_execve_call("/bin/shell", (char * const *)argv, (char * const *)envp);
                sys_exit(1);
            } else if (shell_pid > 0) {
                sys_wait4_call(shell_pid, &wstatus, 0, 0);
                printf("Shell exited. Restarting...\n");
            } else {
                printf("Failed to fork for shell\n");
                break;
            }
        }
    } else {
        printf("Failed to fork for shell\n");
    }

    // Keep init running - sleep forever if shell fails
    fut_timespec_t forever = { .tv_sec = 3600, .tv_nsec = 0 };
    while (1) {
        sys_nanosleep_call(&forever, 0);
    }

    return 0;
}
