// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>

int main(void) {
    // Init process - launch compositor and shell, then supervise them

    // Fork for the Wayland compositor
    long compositor_pid = sys_fork_call();

    if (compositor_pid == 0) {
        // Child process - exec into compositor
        const char *comp_argv[] = { "/sbin/futura-wayland", 0 };
        const char *comp_envp[] = { 0 };
        sys_execve_call("/sbin/futura-wayland", (char * const *)comp_argv, (char * const *)comp_envp);
        // If execve fails, exit child
        sys_exit(1);
    } else if (compositor_pid > 0) {
        // Parent continues to launch shell

        // Small delay to let compositor initialize (simple busy-wait)
        for (volatile int i = 0; i < 500000000; i++) {
            // Wait for compositor to start
        }

        // Fork for the shell
        long shell_pid = sys_fork_call();

        if (shell_pid == 0) {
            // Child process - exec into shell launcher
            const char *shell_argv[] = { "/sbin/launch-shell", 0 };
            const char *shell_envp[] = { 0 };
            sys_execve_call("/sbin/launch-shell", (char * const *)shell_argv, (char * const *)shell_envp);
            // If execve fails, exit child
            sys_exit(1);
        } else if (shell_pid > 0) {
            // Parent waits for children
            int wstatus = 0;
            while (1) {
                // Wait for any child process to exit
                long wait_result = sys_wait4_call(-1, &wstatus, 0, 0);
                if (wait_result > 0) {
                    // Child exited, restart it
                    // For now just loop
                }
            }
        }
    }

    // Should never reach here
    sys_exit(127);
    return 127;
}
