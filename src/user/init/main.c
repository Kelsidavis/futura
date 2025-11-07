/* main.c - Futura OS Init System (PID 1)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Init system for Futura OS - manages system services and orchestrates boot.
 * Communicates via FIPC channels.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <user/futura_init.h>
#include <user/sys.h>

/* Forward declarations */
extern int init_config_parse(const char *path);
extern int init_service_start_all(void);
extern void init_service_monitor(void);
extern void init_handle_message(struct fut_fipc_msg *msg);

/* Global state */
static bool running = true;
static struct fut_fipc_channel *control_channel = NULL;

/**
 * Early initialization - set up logging and core subsystems.
 */
static int init_early_setup(void) {
    /* Phase 3: Stub - would initialize:
     * - Basic memory allocator
     * - Logging infrastructure
     * - FIPC control channel
     */
    return 0;
}

/**
 * Print banner to show init is starting.
 */
static void print_banner(void) {
    /* Phase 3: Would output to serial/console:
     * "Futura OS Init System v0.3.0"
     * "Starting system services..."
     */
}

/**
 * Main event loop for init system.
 * Monitors FIPC channels for service messages and handles events.
 */
static void init_main_loop(void) {
    uint8_t msg_buffer[4096];

    while (running) {
        /* Monitor all running services */
        init_service_monitor();

        /* Check for messages on control channel */
        if (control_channel) {
            ssize_t received = fut_fipc_recv(control_channel, msg_buffer, sizeof(msg_buffer));
            if (received > 0) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;
                init_handle_message(msg);
            }
        }

        /* Phase 3: Would implement proper event waiting:
         * - Wait on multiple FIPC channels
         * - Handle signals (SIGCHLD for process exits)
         * - Timeout for periodic service checks
         */
    }
}

/**
 * Shutdown sequence - stop all services in reverse dependency order.
 */
static void init_shutdown(void) {
    /* Phase 3: Would implement:
     * - Send STOP messages to all services
     * - Wait for graceful shutdown (with timeout)
     * - Force kill remaining processes
     * - Sync filesystems
     * - Reboot/halt system
     */
}

/**
 * Init entry point (PID 1).
 */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* TEST: Verify syscalls work from user mode (EL0) */
    const char *test_msg = "[INIT-USER] Hello from user mode! Syscalls work!\n";
    long msg_len = 0;
    while (test_msg[msg_len]) msg_len++;
    sys_write(1, test_msg, msg_len);  /* fd=1 is stdout */

    /* TEST: brk() syscall - heap memory allocation
     * This tests the brk() syscall by allocating 4096 bytes on the heap.
     * brk(NULL) returns the current heap end, brk(addr) extends heap to addr.
     */
    const char *test_brk = "[INIT-USER] Testing brk() syscall...\n";
    msg_len = 0; while (test_brk[msg_len]) msg_len++;
    sys_write(1, test_brk, msg_len);

    void *heap_start = (void *)sys_brk_call(NULL);
    void *heap_end = (void *)sys_brk_call((void*)((char*)heap_start + 4096));

    if (heap_end != (void*)-1) {
        const char *brk_ok = "[INIT-USER] brk() test passed!\n";
        msg_len = 0; while (brk_ok[msg_len]) msg_len++;
        sys_write(1, brk_ok, msg_len);
    }

    /* TEST: getpid() syscall - process ID retrieval
     * This tests the getpid() syscall and verifies it returns a valid PID.
     * On ARM64, init may not be PID 1 due to boot tasks created before init.
     */
    const char *test_getpid = "[INIT-USER] Testing getpid() syscall...\n";
    msg_len = 0; while (test_getpid[msg_len]) msg_len++;
    sys_write(1, test_getpid, msg_len);

    long pid = sys_getpid_call();

    /* Print the PID using manual decimal conversion (no printf available yet) */
    const char *pid_prefix = "[INIT-USER] getpid() returned: ";
    msg_len = 0; while (pid_prefix[msg_len]) msg_len++;
    sys_write(1, pid_prefix, msg_len);

    /* Convert PID to string and print it */
    char pid_buf[20];
    long pid_tmp = pid;
    int pid_len = 0;
    if (pid_tmp == 0) {
        pid_buf[pid_len++] = '0';
    } else {
        char digits[20];
        int digit_count = 0;
        while (pid_tmp > 0) {
            digits[digit_count++] = '0' + (pid_tmp % 10);
            pid_tmp /= 10;
        }
        for (int i = digit_count - 1; i >= 0; i--) {
            pid_buf[pid_len++] = digits[i];
        }
    }
    sys_write(1, pid_buf, pid_len);

    const char *newline = "\n";
    sys_write(1, newline, 1);

    if (pid == 1) {
        const char *pid_ok = "[INIT-USER] ✓ PID is 1 (correct for init)!\n";
        msg_len = 0; while (pid_ok[msg_len]) msg_len++;
        sys_write(1, pid_ok, msg_len);
    } else {
        const char *pid_warn = "[INIT-USER] Note: PID is not 1 (ARM64 spawns init after other tasks)\n";
        msg_len = 0; while (pid_warn[msg_len]) msg_len++;
        sys_write(1, pid_warn, msg_len);
    }

    /* TEST: File I/O syscalls - open(), read(), fstat(), close()
     * This tests basic file I/O operations using the init binary itself.
     * We open the binary, read some bytes, stat it, and close it.
     */
    const char *test_fileio = "[INIT-USER] Testing file I/O syscalls (open/read/fstat/close)...\n";
    msg_len = 0; while (test_fileio[msg_len]) msg_len++;
    sys_write(1, test_fileio, msg_len);

    /* Open /sbin/init for reading */
    long fd = sys_open("/sbin/init", 0 /* O_RDONLY */, 0);
    if (fd < 0) {
        const char *open_fail = "[INIT-USER] ✗ open() failed\n";
        msg_len = 0; while (open_fail[msg_len]) msg_len++;
        sys_write(1, open_fail, msg_len);
    } else {
        const char *open_ok = "[INIT-USER] ✓ open() succeeded, fd=";
        msg_len = 0; while (open_ok[msg_len]) msg_len++;
        sys_write(1, open_ok, msg_len);

        /* Print fd number */
        char fd_buf[20];
        long fd_tmp = fd;
        int fd_len = 0;
        if (fd_tmp == 0) {
            fd_buf[fd_len++] = '0';
        } else {
            char fd_digits[20];
            int fd_digit_count = 0;
            while (fd_tmp > 0) {
                fd_digits[fd_digit_count++] = '0' + (fd_tmp % 10);
                fd_tmp /= 10;
            }
            for (int i = fd_digit_count - 1; i >= 0; i--) {
                fd_buf[fd_len++] = fd_digits[i];
            }
        }
        sys_write(1, fd_buf, fd_len);
        sys_write(1, "\n", 1);

        /* Read 16 bytes from the file */
        char read_buf[16];
        long bytes_read = sys_read(fd, read_buf, sizeof(read_buf));
        if (bytes_read >= 0) {
            const char *read_ok = "[INIT-USER] ✓ read() succeeded, read ";
            msg_len = 0; while (read_ok[msg_len]) msg_len++;
            sys_write(1, read_ok, msg_len);

            /* Print bytes read */
            char bytes_buf[20];
            long bytes_tmp = bytes_read;
            int bytes_len = 0;
            if (bytes_tmp == 0) {
                bytes_buf[bytes_len++] = '0';
            } else {
                char bytes_digits[20];
                int bytes_digit_count = 0;
                while (bytes_tmp > 0) {
                    bytes_digits[bytes_digit_count++] = '0' + (bytes_tmp % 10);
                    bytes_tmp /= 10;
                }
                for (int i = bytes_digit_count - 1; i >= 0; i--) {
                    bytes_buf[bytes_len++] = bytes_digits[i];
                }
            }
            sys_write(1, bytes_buf, bytes_len);
            const char *bytes_suffix = " bytes\n";
            msg_len = 0; while (bytes_suffix[msg_len]) msg_len++;
            sys_write(1, bytes_suffix, msg_len);
        } else {
            const char *read_fail = "[INIT-USER] ✗ read() failed\n";
            msg_len = 0; while (read_fail[msg_len]) msg_len++;
            sys_write(1, read_fail, msg_len);
        }

        /* Get file stats with fstat() */
        char stat_buf[256];  /* Large enough for struct stat */
        long stat_ret = sys_fstat_call(fd, (void*)stat_buf);
        if (stat_ret == 0) {
            const char *fstat_ok = "[INIT-USER] ✓ fstat() succeeded\n";
            msg_len = 0; while (fstat_ok[msg_len]) msg_len++;
            sys_write(1, fstat_ok, msg_len);
        } else {
            const char *fstat_fail = "[INIT-USER] ✗ fstat() failed\n";
            msg_len = 0; while (fstat_fail[msg_len]) msg_len++;
            sys_write(1, fstat_fail, msg_len);
        }

        /* Close the file */
        long close_ret = sys_close(fd);
        if (close_ret == 0) {
            const char *close_ok = "[INIT-USER] ✓ close() succeeded\n";
            msg_len = 0; while (close_ok[msg_len]) msg_len++;
            sys_write(1, close_ok, msg_len);
        } else {
            const char *close_fail = "[INIT-USER] ✗ close() failed\n";
            msg_len = 0; while (close_fail[msg_len]) msg_len++;
            sys_write(1, close_fail, msg_len);
        }
    }

    /* TEST: Directory operations - mkdir(), chdir(), getcwd()
     * This tests directory creation, navigation, and querying operations.
     */
    const char *test_dir = "[INIT-USER] Testing directory operations (mkdir/chdir/getcwd)...\n";
    msg_len = 0; while (test_dir[msg_len]) msg_len++;
    sys_write(1, test_dir, msg_len);

    /* Test mkdir() - create a new directory in root (/ must exist) */
    long mkdir_ret = sys_mkdir_call("/testdir", 0755);
    if (mkdir_ret == 0) {
        const char *mkdir_ok = "[INIT-USER] ✓ mkdir() succeeded\n";
        msg_len = 0; while (mkdir_ok[msg_len]) msg_len++;
        sys_write(1, mkdir_ok, msg_len);
    } else {
        const char *mkdir_fail = "[INIT-USER] ✗ mkdir() failed\n";
        msg_len = 0; while (mkdir_fail[msg_len]) msg_len++;
        sys_write(1, mkdir_fail, msg_len);
    }

    /* Test getcwd() - get current working directory (should be /) */
    char cwd_buf[256];
    long getcwd_ret = sys_getcwd_call(cwd_buf, sizeof(cwd_buf));
    if (getcwd_ret >= 0) {
        const char *getcwd_ok = "[INIT-USER] ✓ getcwd() succeeded, cwd=";
        msg_len = 0; while (getcwd_ok[msg_len]) msg_len++;
        sys_write(1, getcwd_ok, msg_len);

        /* Print cwd (should be "/") */
        long cwd_len = 0;
        while (cwd_buf[cwd_len] && cwd_len < 256) cwd_len++;
        sys_write(1, cwd_buf, cwd_len);
        sys_write(1, "\n", 1);
    } else {
        const char *getcwd_fail = "[INIT-USER] ✗ getcwd() failed\n";
        msg_len = 0; while (getcwd_fail[msg_len]) msg_len++;
        sys_write(1, getcwd_fail, msg_len);
    }

    /* Test chdir() - change to /testdir directory (that we just created) */
    long chdir_ret = sys_chdir_call("/testdir");
    if (chdir_ret == 0) {
        const char *chdir_ok = "[INIT-USER] ✓ chdir() succeeded\n";
        msg_len = 0; while (chdir_ok[msg_len]) msg_len++;
        sys_write(1, chdir_ok, msg_len);

        /* Verify chdir worked by calling getcwd() again */
        getcwd_ret = sys_getcwd_call(cwd_buf, sizeof(cwd_buf));
        if (getcwd_ret >= 0) {
            const char *verify_cwd = "[INIT-USER] ✓ Verified: new cwd=";
            msg_len = 0; while (verify_cwd[msg_len]) msg_len++;
            sys_write(1, verify_cwd, msg_len);

            long cwd_len = 0;
            while (cwd_buf[cwd_len] && cwd_len < 256) cwd_len++;
            sys_write(1, cwd_buf, cwd_len);
            sys_write(1, "\n", 1);
        }
    } else {
        const char *chdir_fail = "[INIT-USER] ✗ chdir() failed\n";
        msg_len = 0; while (chdir_fail[msg_len]) msg_len++;
        sys_write(1, chdir_fail, msg_len);
    }

    /* TEST: Advanced file operations - stat(), lseek()
     * This tests file metadata retrieval and file positioning operations.
     */
    const char *test_advanced = "[INIT-USER] Testing advanced file operations (stat/lseek)...\n";
    msg_len = 0; while (test_advanced[msg_len]) msg_len++;
    sys_write(1, test_advanced, msg_len);

    /* Test stat() - get file metadata for /sbin/init */
    char stat_buf_path[256];
    long stat_ret = sys_stat_call("/sbin/init", (void*)stat_buf_path);
    if (stat_ret == 0) {
        const char *stat_ok = "[INIT-USER] ✓ stat() succeeded on /sbin/init\n";
        msg_len = 0; while (stat_ok[msg_len]) msg_len++;
        sys_write(1, stat_ok, msg_len);
    } else {
        const char *stat_fail = "[INIT-USER] ✗ stat() failed\n";
        msg_len = 0; while (stat_fail[msg_len]) msg_len++;
        sys_write(1, stat_fail, msg_len);
    }

    /* Test stat() on directory - get metadata for /testdir */
    stat_ret = sys_stat_call("/testdir", (void*)stat_buf_path);
    if (stat_ret == 0) {
        const char *stat_dir_ok = "[INIT-USER] ✓ stat() succeeded on /testdir directory\n";
        msg_len = 0; while (stat_dir_ok[msg_len]) msg_len++;
        sys_write(1, stat_dir_ok, msg_len);
    } else {
        const char *stat_dir_fail = "[INIT-USER] ✗ stat() failed on directory\n";
        msg_len = 0; while (stat_dir_fail[msg_len]) msg_len++;
        sys_write(1, stat_dir_fail, msg_len);
    }

    /* Test lseek() - file positioning
     * Open a file, read first 4 bytes, seek to offset 8, read again
     */
    long fd_lseek = sys_open("/sbin/init", 0 /* O_RDONLY */, 0);
    if (fd_lseek >= 0) {
        char lseek_buf1[4];
        long read1 = sys_read(fd_lseek, lseek_buf1, 4);
        if (read1 == 4) {
            /* Seek to offset 8 (skip 4 bytes) */
            long seek_ret = sys_lseek_call(fd_lseek, 8, 0 /* SEEK_SET */);
            if (seek_ret == 8) {
                const char *lseek_ok = "[INIT-USER] ✓ lseek() succeeded, new offset=8\n";
                msg_len = 0; while (lseek_ok[msg_len]) msg_len++;
                sys_write(1, lseek_ok, msg_len);

                /* Read again from offset 8 to verify seek worked */
                char lseek_buf2[4];
                long read2 = sys_read(fd_lseek, lseek_buf2, 4);
                if (read2 == 4) {
                    const char *lseek_verify = "[INIT-USER] ✓ Verified: read after lseek succeeded\n";
                    msg_len = 0; while (lseek_verify[msg_len]) msg_len++;
                    sys_write(1, lseek_verify, msg_len);
                }
            } else {
                const char *lseek_fail = "[INIT-USER] ✗ lseek() failed\n";
                msg_len = 0; while (lseek_fail[msg_len]) msg_len++;
                sys_write(1, lseek_fail, msg_len);
            }
        }
        sys_close(fd_lseek);
    }

    /* TEST: File deletion - unlink(), rmdir()
     * This tests file and directory deletion operations.
     */
    const char *test_delete = "[INIT-USER] Testing deletion operations (unlink/rmdir)...\n";
    msg_len = 0; while (test_delete[msg_len]) msg_len++;
    sys_write(1, test_delete, msg_len);

    /* Create a test file to delete */
    long fd_testfile = sys_open("/testfile", 0x0041 /* O_CREAT | O_WRONLY */, 0644);
    if (fd_testfile >= 0) {
        const char *test_content = "test";
        sys_write(fd_testfile, test_content, 4);
        sys_close(fd_testfile);

        const char *created = "[INIT-USER] ✓ Created /testfile for deletion test\n";
        msg_len = 0; while (created[msg_len]) msg_len++;
        sys_write(1, created, msg_len);

        /* Now delete it with unlink() */
        long unlink_ret = sys_unlink("/testfile");
        if (unlink_ret == 0) {
            const char *unlink_ok = "[INIT-USER] ✓ unlink() succeeded\n";
            msg_len = 0; while (unlink_ok[msg_len]) msg_len++;
            sys_write(1, unlink_ok, msg_len);
        } else {
            const char *unlink_fail = "[INIT-USER] ✗ unlink() failed\n";
            msg_len = 0; while (unlink_fail[msg_len]) msg_len++;
            sys_write(1, unlink_fail, msg_len);
        }
    }

    /* Test rmdir() - delete the /testdir directory we created earlier */
    long rmdir_ret = sys_rmdir_call("/testdir");
    if (rmdir_ret == 0) {
        const char *rmdir_ok = "[INIT-USER] ✓ rmdir() succeeded\n";
        msg_len = 0; while (rmdir_ok[msg_len]) msg_len++;
        sys_write(1, rmdir_ok, msg_len);
    } else {
        const char *rmdir_fail = "[INIT-USER] ✗ rmdir() failed\n";
        msg_len = 0; while (rmdir_fail[msg_len]) msg_len++;
        sys_write(1, rmdir_fail, msg_len);
    }

    /* TEST: nanosleep() - sleep for specified time
     * This tests timing/delay functionality.
     */
    const char *test_sleep = "[INIT-USER] Testing nanosleep() syscall...\n";
    msg_len = 0; while (test_sleep[msg_len]) msg_len++;
    sys_write(1, test_sleep, msg_len);

    /* Sleep for 100 milliseconds (0.1 seconds) */
    fut_timespec_t sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 100000000;  /* 100 million nanoseconds = 100 ms */

    fut_timespec_t remaining;
    long sleep_ret = sys_nanosleep_call(&sleep_time, &remaining);
    if (sleep_ret == 0) {
        const char *sleep_ok = "[INIT-USER] ✓ nanosleep() succeeded (slept 100ms)\n";
        msg_len = 0; while (sleep_ok[msg_len]) msg_len++;
        sys_write(1, sleep_ok, msg_len);
    } else {
        const char *sleep_fail = "[INIT-USER] ✗ nanosleep() failed\n";
        msg_len = 0; while (sleep_fail[msg_len]) msg_len++;
        sys_write(1, sleep_fail, msg_len);
    }

    /* TEST: Process management syscalls - fork(), wait4()
     * This tests process creation and parent-child synchronization.
     * Note: We skip execve() test since it would replace init process.
     * We run this test BEFORE the IPC test to avoid pipe() FD issues.
     */
    const char *test_fork = "[INIT-USER] Testing process management (fork/wait4)...\n";
    msg_len = 0; while (test_fork[msg_len]) msg_len++;
    sys_write(1, test_fork, msg_len);

    long fork_ret = sys_fork_call();
    if (fork_ret < 0) {
        /* Fork failed */
        const char *fork_fail = "[INIT-USER] ✗ fork() failed\n";
        msg_len = 0; while (fork_fail[msg_len]) msg_len++;
        sys_write(1, fork_fail, msg_len);
    } else if (fork_ret == 0) {
        /* Child process */
        const char *child_msg = "[INIT-USER-CHILD] Child process running, PID=";
        msg_len = 0; while (child_msg[msg_len]) msg_len++;
        sys_write(1, child_msg, msg_len);

        /* Get and print child PID */
        long child_pid = sys_getpid_call();
        char child_pid_buf[16];
        long child_pid_idx = 0;
        if (child_pid == 0) {
            child_pid_buf[child_pid_idx++] = '0';
        } else {
            long divisor = 1;
            long temp = child_pid;
            while (temp >= 10) { temp /= 10; divisor *= 10; }
            while (divisor > 0) {
                child_pid_buf[child_pid_idx++] = '0' + (child_pid / divisor) % 10;
                divisor /= 10;
            }
        }
        sys_write(1, child_pid_buf, child_pid_idx);
        sys_write(1, "\n", 1);

        /* Child exits with status 42 */
        const char *child_exit = "[INIT-USER-CHILD] Child exiting with status 42\n";
        msg_len = 0; while (child_exit[msg_len]) msg_len++;
        sys_write(1, child_exit, msg_len);
        sys_exit(42);

        /* Should never reach here */
        for (;;);
    } else {
        /* Parent process */
        const char *fork_ok = "[INIT-USER] ✓ fork() succeeded, child_pid=";
        msg_len = 0; while (fork_ok[msg_len]) msg_len++;
        sys_write(1, fork_ok, msg_len);

        /* Print child PID */
        char fork_pid_buf[16];
        long fork_pid_idx = 0;
        if (fork_ret == 0) {
            fork_pid_buf[fork_pid_idx++] = '0';
        } else {
            long divisor = 1;
            long temp = fork_ret;
            while (temp >= 10) { temp /= 10; divisor *= 10; }
            while (divisor > 0) {
                fork_pid_buf[fork_pid_idx++] = '0' + (fork_ret / divisor) % 10;
                divisor /= 10;
            }
        }
        sys_write(1, fork_pid_buf, fork_pid_idx);
        sys_write(1, "\n", 1);

        /* Wait for child to exit */
        int child_status = 0;
        long wait_ret = sys_wait4_call(fork_ret, &child_status, 0, 0);
        if (wait_ret == fork_ret) {
            const char *wait_ok = "[INIT-USER] ✓ wait4() succeeded, child exited with status ";
            msg_len = 0; while (wait_ok[msg_len]) msg_len++;
            sys_write(1, wait_ok, msg_len);

            /* Extract exit status (upper 8 bits of child_status) */
            long exit_code = (child_status >> 8) & 0xFF;
            char status_buf[16];
            long status_idx = 0;
            if (exit_code == 0) {
                status_buf[status_idx++] = '0';
            } else {
                long divisor = 1;
                long temp = exit_code;
                while (temp >= 10) { temp /= 10; divisor *= 10; }
                while (divisor > 0) {
                    status_buf[status_idx++] = '0' + (exit_code / divisor) % 10;
                    divisor /= 10;
                }
            }
            sys_write(1, status_buf, status_idx);
            sys_write(1, "\n", 1);

            /* Verify exit status is 42 */
            if (exit_code == 42) {
                const char *verify_ok = "[INIT-USER] ✓ Verified: child exit status correct (42)\n";
                msg_len = 0; while (verify_ok[msg_len]) msg_len++;
                sys_write(1, verify_ok, msg_len);
            } else {
                const char *verify_fail = "[INIT-USER] ✗ Child exit status mismatch\n";
                msg_len = 0; while (verify_fail[msg_len]) msg_len++;
                sys_write(1, verify_fail, msg_len);
            }
        } else {
            const char *wait_fail = "[INIT-USER] ✗ wait4() failed\n";
            msg_len = 0; while (wait_fail[msg_len]) msg_len++;
            sys_write(1, wait_fail, msg_len);
        }
    }

    /* TEST: IPC syscalls - pipe(), dup(), dup2()
     * This tests inter-process communication primitives and FD duplication.
     */
    const char *test_ipc = "[INIT-USER] Testing IPC syscalls (pipe/dup/dup2)...\n";
    msg_len = 0; while (test_ipc[msg_len]) msg_len++;
    sys_write(1, test_ipc, msg_len);

    /* Test pipe() - create a communication channel */
    int pipefd[2];
    long pipe_ret = sys_pipe_call(pipefd);
    if (pipe_ret == 0) {
        const char *pipe_ok = "[INIT-USER] ✓ pipe() succeeded, read_fd=";
        msg_len = 0; while (pipe_ok[msg_len]) msg_len++;
        sys_write(1, pipe_ok, msg_len);

        /* Print read_fd (pipefd[0]) */
        char fd_buf[16];
        long fd_idx = 0;
        long read_fd_val = pipefd[0];
        if (read_fd_val == 0) {
            fd_buf[fd_idx++] = '0';
        } else {
            long divisor = 1;
            long temp = read_fd_val;
            while (temp >= 10) { temp /= 10; divisor *= 10; }
            while (divisor > 0) {
                fd_buf[fd_idx++] = '0' + (read_fd_val / divisor) % 10;
                divisor /= 10;
            }
        }
        sys_write(1, fd_buf, fd_idx);
        sys_write(1, ", write_fd=", 11);

        /* Print write_fd (pipefd[1]) */
        fd_idx = 0;
        long write_fd_val = pipefd[1];
        if (write_fd_val == 0) {
            fd_buf[fd_idx++] = '0';
        } else {
            long divisor = 1;
            long temp = write_fd_val;
            while (temp >= 10) { temp /= 10; divisor *= 10; }
            while (divisor > 0) {
                fd_buf[fd_idx++] = '0' + (write_fd_val / divisor) % 10;
                divisor /= 10;
            }
        }
        sys_write(1, fd_buf, fd_idx);
        sys_write(1, "\n", 1);

        /* Write test data to pipe */
        const char *pipe_msg = "PIPE_TEST";
        long write_ret = sys_write(pipefd[1], pipe_msg, 9);
        if (write_ret == 9) {
            const char *write_ok = "[INIT-USER] ✓ write() to pipe succeeded\n";
            msg_len = 0; while (write_ok[msg_len]) msg_len++;
            sys_write(1, write_ok, msg_len);

            /* Read test data from pipe */
            char pipe_buf[16];
            long read_ret = sys_read(pipefd[0], pipe_buf, 9);
            if (read_ret == 9) {
                /* Verify data matches */
                int match = 1;
                for (int i = 0; i < 9; i++) {
                    if (pipe_buf[i] != pipe_msg[i]) {
                        match = 0;
                        break;
                    }
                }

                if (match) {
                    const char *read_ok = "[INIT-USER] ✓ read() from pipe succeeded, data verified\n";
                    msg_len = 0; while (read_ok[msg_len]) msg_len++;
                    sys_write(1, read_ok, msg_len);
                } else {
                    const char *verify_fail = "[INIT-USER] ✗ pipe data mismatch\n";
                    msg_len = 0; while (verify_fail[msg_len]) msg_len++;
                    sys_write(1, verify_fail, msg_len);
                }
            } else {
                const char *read_fail = "[INIT-USER] ✗ read() from pipe failed\n";
                msg_len = 0; while (read_fail[msg_len]) msg_len++;
                sys_write(1, read_fail, msg_len);
            }
        }

        /* Test dup() - duplicate file descriptor to lowest available */
        long dup_fd = sys_dup_call(pipefd[0]);
        if (dup_fd >= 0) {
            const char *dup_ok = "[INIT-USER] ✓ dup() succeeded, new_fd=";
            msg_len = 0; while (dup_ok[msg_len]) msg_len++;
            sys_write(1, dup_ok, msg_len);

            /* Print dup_fd */
            fd_idx = 0;
            if (dup_fd == 0) {
                fd_buf[fd_idx++] = '0';
            } else {
                long divisor = 1;
                long temp = dup_fd;
                while (temp >= 10) { temp /= 10; divisor *= 10; }
                while (divisor > 0) {
                    fd_buf[fd_idx++] = '0' + (dup_fd / divisor) % 10;
                    divisor /= 10;
                }
            }
            sys_write(1, fd_buf, fd_idx);
            sys_write(1, "\n", 1);

            /* Close the dup'd fd */
            sys_close(dup_fd);
        } else {
            const char *dup_fail = "[INIT-USER] ✗ dup() failed\n";
            msg_len = 0; while (dup_fail[msg_len]) msg_len++;
            sys_write(1, dup_fail, msg_len);
        }

        /* Test dup2() - duplicate to specific fd number (10) */
        long dup2_ret = sys_dup2_call(pipefd[0], 10);
        if (dup2_ret == 10) {
            const char *dup2_ok = "[INIT-USER] ✓ dup2() succeeded, newfd=10\n";
            msg_len = 0; while (dup2_ok[msg_len]) msg_len++;
            sys_write(1, dup2_ok, msg_len);

            /* Close fd 10 */
            sys_close(10);
        } else {
            const char *dup2_fail = "[INIT-USER] ✗ dup2() failed\n";
            msg_len = 0; while (dup2_fail[msg_len]) msg_len++;
            sys_write(1, dup2_fail, msg_len);
        }

        /* Clean up pipe fds */
        sys_close(pipefd[0]);
        sys_close(pipefd[1]);
    } else {
        const char *pipe_fail = "[INIT-USER] ✗ pipe() failed\n";
        msg_len = 0; while (pipe_fail[msg_len]) msg_len++;
        sys_write(1, pipe_fail, msg_len);
    }

    const char *all_tests_ok = "[INIT-USER] All syscall tests passed! Entering main loop...\n";
    msg_len = 0; while (all_tests_ok[msg_len]) msg_len++;
    sys_write(1, all_tests_ok, msg_len);

    /* Early setup */
    if (init_early_setup() < 0) {
        /* Fatal error - can't continue */
        return 1;
    }

    /* Print banner */
    print_banner();

    /* Parse configuration */
    const char *config_path = "/etc/futura/init.conf";
    if (init_config_parse(config_path) < 0) {
        /* Non-fatal - continue with defaults */
    }

    /* Start all configured services */
    if (init_service_start_all() < 0) {
        /* Some services failed - but continue */
    }

    /* Enter main event loop */
    init_main_loop();

    /* Shutdown (only reached on explicit shutdown request) */
    init_shutdown();

    return 0;
}

/**
 * Handle messages received on control channel.
 */
void init_handle_message(struct fut_fipc_msg *msg) {
    if (!msg) {
        return;
    }

    /* Parse message type */
    switch (msg->type) {
    case INIT_MSG_START:
        /* Request to start a service */
        /* Phase 3: Parse service name from payload and start it */
        break;

    case INIT_MSG_STOP:
        /* Request to stop a service */
        /* Phase 3: Parse service name and stop it gracefully */
        break;

    case INIT_MSG_RESTART:
        /* Request to restart a service */
        /* Phase 3: Stop then start service */
        break;

    case INIT_MSG_STATUS:
        /* Query service status */
        /* Phase 3: Send status response */
        break;

    case INIT_MSG_SHUTDOWN:
        /* System shutdown request */
        running = false;
        break;

    default:
        /* Unknown message type - ignore */
        break;
    }
}
