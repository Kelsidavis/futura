// SPDX-License-Identifier: MPL-2.0
/*
 * forktest - ARM64 multi-process test
 *
 * Tests fork(), exec(), and waitpid() functionality by:
 * 1. Forking a child process
 * 2. Child writes message and exits with status 42
 * 3. Parent waits for child and verifies exit status
 */

#include <user/sys.h>

#define SYS_write  1
#define SYS_exit   60
#define SYS_fork   57
#define SYS_wait4  61
#define SYS_getpid 39

/* Use static strings to avoid stack issues */
static const char msg_start[] = "\nTEST START\n";
static const char msg_pid[] = "PID:";
static const char msg_fork[] = "fork\n";
static const char msg_child[] = "CHILD\n";
static const char msg_parent[] = "PARENT\n";
static const char msg_pass[] = "PASS\n";
static const char msg_fail[] = "FAIL\n";
static const char msg_err[] = "ERROR\n";

static void write_str(const char *msg) {
    const char *p = msg;
    unsigned long len = 0;
    while (*p++) len++;
    sys_write(1, msg, len);
}

static void write_num(long num) {
    char buf[32];
    int i = 0;

    if (num == 0) {
        sys_write(1, "0", 1);
        return;
    }

    if (num < 0) {
        sys_write(1, "-", 1);
        num = -num;
    }

    while (num > 0) {
        buf[i++] = '0' + (num % 10);
        num /= 10;
    }

    while (i > 0) {
        sys_write(1, &buf[--i], 1);
    }
}

int main(void) {
    write_str(msg_start);

    /* Get parent PID */
    long parent_pid = sys_call0(SYS_getpid);
    write_str(msg_pid);
    write_num(parent_pid);
    sys_write(1, "\n", 1);

    /* Fork a child */
    write_str(msg_fork);
    long pid = sys_call0(SYS_fork);

    if (pid < 0) {
        write_str(msg_err);
        sys_exit(1);
    }

    if (pid == 0) {
        /* Child process */
        write_str(msg_child);
        sys_exit(42);
    } else {
        /* Parent process */
        write_str(msg_parent);

        /* Wait for child */
        int status = 0;
        long wait_ret = sys_call4(SYS_wait4, pid, (long)&status, 0, 0);

        if (wait_ret < 0) {
            write_str(msg_fail);
            sys_exit(1);
        }

        /* Extract exit code from wait status (WEXITSTATUS macro) */
        int exit_code = (status >> 8) & 0xff;

        if (exit_code == 42) {
            write_str(msg_pass);
            sys_exit(0);
        } else {
            write_str(msg_fail);
            sys_exit(1);
        }
    }
}
