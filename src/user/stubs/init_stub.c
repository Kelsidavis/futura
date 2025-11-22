// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>
#include <user/stdio.h>
#include <shared/fut_timespec.h>

int main(void) {
    // Init process - show boot messages, then launch framebuffer demo

    printf("Futura OS Init - Launching framebuffer demo in 2 seconds...\n");

    // Wait 2 seconds to let user see boot messages
    fut_timespec_t delay = { .tv_sec = 2, .tv_nsec = 0 };
    sys_nanosleep_call(&delay, 0);

    // Fork and exec fbtest
    long fbtest_pid = sys_fork_call();

    if (fbtest_pid == 0) {
        // Child process - exec into fbtest
        const char *argv[] = { "/bin/fbtest", 0 };
        const char *envp[] = { 0 };
        sys_execve_call("/bin/fbtest", (char * const *)argv, (char * const *)envp);
        // If execve fails, print error and exit
        printf("Failed to exec /bin/fbtest\n");
        sys_exit(1);
    } else if (fbtest_pid > 0) {
        // Parent waits for fbtest to complete
        int wstatus = 0;
        sys_wait4_call(fbtest_pid, &wstatus, 0, 0);
        printf("Framebuffer demo complete!\n");
    } else {
        printf("Failed to fork for fbtest\n");
    }

    // Keep init running - sleep forever
    fut_timespec_t forever = { .tv_sec = 3600, .tv_nsec = 0 };
    while (1) {
        sys_nanosleep_call(&forever, 0);
    }

    return 0;
}
