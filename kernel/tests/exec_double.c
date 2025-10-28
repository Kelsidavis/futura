// SPDX-License-Identifier: MPL-2.0

#include <kernel/exec.h>
#include <kernel/fut_vfs.h>
#include <platform/platform.h>
#include <tests/test_api.h>

extern void fut_printf(const char *fmt, ...);

void fut_exec_double_smoke(void) {
    static int already_run = 0;
    if (already_run) {
        return;
    }
    already_run = 1;

    fut_vfs_check_root_canary("exec-double:start");

    int rc = fut_stage_init_stub_binary();
    if (rc != 0) {
        fut_printf("[EXEC-DOUBLE] staging init_stub failed: %d\n", rc);
        return;
    }

    rc = fut_stage_second_stub_binary();
    if (rc != 0) {
        fut_printf("[EXEC-DOUBLE] staging second_stub failed: %d\n", rc);
        return;
    }

    fut_vfs_check_root_canary("exec-double:post-stage");

    struct fut_vnode *root = fut_vfs_get_root();
    if (!root || root->type != VN_DIR) {
        fut_platform_panic("[EXEC-DOUBLE] invalid root vnode before exec");
    }

    char shell_name[] = "shell";
    char *shell_args[] = { shell_name, NULL };
    rc = fut_exec_elf("/bin/shell", shell_args, NULL);
    fut_printf("[EXEC-DOUBLE] exec shell rc=%d\n", rc);
    fut_vfs_check_root_canary("exec-double:after-first");

    root = fut_vfs_get_root();
    if (!root || root->type != VN_DIR) {
        fut_platform_panic("[EXEC-DOUBLE] root vnode corrupted after first exec");
    }

    char second_name[] = "second";
    char *second_args[] = { second_name, NULL };
    rc = fut_exec_elf("/sbin/second", second_args, NULL);
    fut_printf("[EXEC-DOUBLE] exec second_stub rc=%d\n", rc);
    fut_vfs_check_root_canary("exec-double:after-second");

    root = fut_vfs_get_root();
    if (!root || root->type != VN_DIR) {
        fut_platform_panic("[EXEC-DOUBLE] root vnode corrupted after second exec");
    }

    fut_test_pass();
}
