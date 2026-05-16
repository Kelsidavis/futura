/*
 * Futura OS - ARM64 Stub Implementations
 * Copyright (C) 2025 Futura OS Project
 *
 * This file provides stub implementations for ARM64 platform of functions
 * that are either x86-64 specific or require full implementation in later phases.
 */

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <generated/feature_flags.h>

/* ============================================================
 *   Test Framework — implemented in kernel/stubs_missing.c
 *
 * The real fut_test_plan / fut_test_pass / fut_test_fail /
 * fut_tests_completed are defined in kernel/stubs_missing.c and
 * call qemu_exit() through <platform/arm64/qemu_exit.h>.  The
 * varargs stubs that used to live here silently swallowed every
 * test_pass call, so `make test-arm64 async-tests=1` never reached
 * qemu_exit(0) and always timed out the harness at 600 s.
 * fut_perf_selftest_schedule is the only one that legitimately stays
 * stubbed on ARM64 (the perf suite depends on x86 qemu_exit and
 * cycle-counter plumbing that isn't wired here yet). */

/* Forward decl matches the real signature in kernel/tests/perf.c so
 * callers that pass a task pointer (e.g. selftest_sequential_runner)
 * link cleanly on ARM64 instead of relying on K&R-style any-args
 * tolerance.  Body is still a no-op until the ARM64 cycle-counter
 * plumbing for the perf harness lands. */
struct fut_task;
void fut_perf_selftest_schedule(struct fut_task *task) {
    (void)task;
    /* Performance self-test not implemented for ARM64 */
}

/* ============================================================
 *   Framebuffer - Now implemented via Rust virtio-gpu driver
 * ============================================================ */
/* Framebuffer functions (fb_boot_splash, fb_is_available, etc.)
 * are now provided by kernel/video/fb_mmio.c with ARM64 support */

/* ============================================================
 *   Networking Stubs (x86-64 specific)
 * ============================================================ */

/* virtio_net_init now implemented in Rust for ARM64 - see drivers/rust/virtio_net */

/* ============================================================
 *   Wayland staging — ARM64 implementations
 * ============================================================
 *
 * Same API as x86_64's fut_stage_*_binary() functions, just pulling
 * from the ARM64-built blobs that the kernel image embeds.  The
 * arm64_init_spawner_thread() in platform_init.c calls these to drop
 * the wayland desktop binaries into the staging filesystem at boot.
 * ============================================================ */

extern int fut_vfs_mkdir(const char *path, int mode);
extern int stage_arm64_blob(const unsigned char *start, const unsigned char *end, const char *path);

#define ARM64_BLOB_DECL(name)                                          \
    extern unsigned char _binary_build_bin_arm64_user_##name##_start[]; \
    extern unsigned char _binary_build_bin_arm64_user_##name##_end[]

#define ARM64_STAGE_FN(fn, name, dir, path)                              \
    ARM64_BLOB_DECL(name);                                                \
    int fn(void) {                                                        \
        (void)fut_vfs_mkdir(dir, 0755);                                   \
        return stage_arm64_blob(_binary_build_bin_arm64_user_##name##_start, \
                                _binary_build_bin_arm64_user_##name##_end,   \
                                path);                                    \
    }

#if defined(ENABLE_WAYLAND) && ENABLE_WAYLAND
ARM64_STAGE_FN(fut_stage_wayland_compositor_binary, futura_wayland, "/sbin", "/sbin/futura-wayland")
ARM64_STAGE_FN(fut_stage_futura_shell_binary,       futura_shell,   "/sbin", "/sbin/futura-shell")
ARM64_STAGE_FN(fut_stage_wl_term_binary,            wl_term,        "/bin",  "/bin/wl-term")
ARM64_STAGE_FN(fut_stage_wl_panel_binary,           wl_panel,       "/bin",  "/bin/wl-panel")
ARM64_STAGE_FN(fut_stage_wl_edit_binary,            wl_edit,        "/bin",  "/bin/wl-edit")
ARM64_STAGE_FN(fut_stage_wl_sysmon_binary,          wl_sysmon,      "/bin",  "/bin/wl-sysmon")
ARM64_STAGE_FN(fut_stage_wl_settings_binary,        wl_settings,    "/bin",  "/bin/wl-settings")
ARM64_STAGE_FN(fut_stage_wl_files_binary,           wl_files,       "/bin",  "/bin/wl-files")
ARM64_STAGE_FN(fut_stage_wl_wallpaper_binary,       wl_wallpaper,   "/bin",  "/bin/wl-wallpaper")
#else
int fut_stage_wayland_compositor_binary(void) { return -ENODEV; }
int fut_stage_futura_shell_binary(void)       { return -ENODEV; }
int fut_stage_wl_term_binary(void)            { return -ENODEV; }
int fut_stage_wl_panel_binary(void)           { return -ENODEV; }
int fut_stage_wl_edit_binary(void)            { return -ENODEV; }
int fut_stage_wl_sysmon_binary(void)          { return -ENODEV; }
int fut_stage_wl_settings_binary(void)        { return -ENODEV; }
int fut_stage_wl_files_binary(void)           { return -ENODEV; }
int fut_stage_wl_wallpaper_binary(void)       { return -ENODEV; }
#endif

#if defined(ENABLE_RUST_USERLAND) && ENABLE_RUST_USERLAND
ARM64_STAGE_FN(fut_stage_rust_hello_binary,         rust_hello,     "/bin",  "/bin/hello")
ARM64_STAGE_FN(fut_stage_rust_uname_binary,         rust_uname,     "/bin",  "/bin/uname")
ARM64_STAGE_FN(fut_stage_rust_pwd_binary,           rust_pwd,       "/bin",  "/bin/pwd")
ARM64_STAGE_FN(fut_stage_rust_ls_binary,            rust_ls,        "/bin",  "/bin/ls")
ARM64_STAGE_FN(fut_stage_rust_mkdir_binary,         rust_mkdir,     "/bin",  "/bin/mkdir")
ARM64_STAGE_FN(fut_stage_rust_touch_binary,         rust_touch,     "/bin",  "/bin/touch")
ARM64_STAGE_FN(fut_stage_rust_rm_binary,            rust_rm,        "/bin",  "/bin/rm")
ARM64_STAGE_FN(fut_stage_rust_cat_binary,           rust_cat,       "/bin",  "/bin/cat")
ARM64_STAGE_FN(fut_stage_rust_wc_binary,            rust_wc,        "/bin",  "/bin/wc")
ARM64_STAGE_FN(fut_stage_rust_true_binary,          rust_true,      "/bin",  "/bin/true")
ARM64_STAGE_FN(fut_stage_rust_false_binary,         rust_false,     "/bin",  "/bin/false")
ARM64_STAGE_FN(fut_stage_rust_env_binary,           rust_env,       "/bin",  "/bin/env")
ARM64_STAGE_FN(fut_stage_rust_head_binary,          rust_head,      "/bin",  "/bin/head")
ARM64_STAGE_FN(fut_stage_rust_tail_binary,          rust_tail,      "/bin",  "/bin/tail")
ARM64_STAGE_FN(fut_stage_rust_grep_binary,          rust_grep,      "/bin",  "/bin/grep")
ARM64_STAGE_FN(fut_stage_rust_sleep_binary,         rust_sleep,     "/bin",  "/bin/sleep")
ARM64_STAGE_FN(fut_stage_rust_date_binary,          rust_date,      "/bin",  "/bin/date")
ARM64_STAGE_FN(fut_stage_rust_settings_binary,      rust_settings,  "/bin",  "/bin/settings")
ARM64_STAGE_FN(fut_stage_rust_tree_binary,          rust_tree,      "/bin",  "/bin/tree")
ARM64_STAGE_FN(fut_stage_rust_wallpaper_binary,     rust_wallpaper, "/bin",  "/bin/wallpaper")
ARM64_STAGE_FN(fut_stage_rust_cp_binary,            rust_cp,        "/bin",  "/bin/cp")
ARM64_STAGE_FN(fut_stage_rust_mv_binary,            rust_mv,        "/bin",  "/bin/mv")
ARM64_STAGE_FN(fut_stage_rust_basename_binary,      rust_basename,  "/bin",  "/bin/basename")
ARM64_STAGE_FN(fut_stage_rust_dirname_binary,       rust_dirname,   "/bin",  "/bin/dirname")
ARM64_STAGE_FN(fut_stage_rust_clear_binary,         rust_clear,     "/bin",  "/bin/clear")
ARM64_STAGE_FN(fut_stage_rust_which_binary,         rust_which,     "/bin",  "/bin/which")
ARM64_STAGE_FN(fut_stage_rust_readlink_binary,      rust_readlink,  "/bin",  "/bin/readlink")
ARM64_STAGE_FN(fut_stage_rust_ln_binary,            rust_ln,        "/bin",  "/bin/ln")
ARM64_STAGE_FN(fut_stage_rust_tee_binary,           rust_tee,       "/bin",  "/bin/tee")
ARM64_STAGE_FN(fut_stage_rust_yes_binary,           rust_yes,       "/bin",  "/bin/yes")
ARM64_STAGE_FN(fut_stage_rust_uniq_binary,          rust_uniq,      "/bin",  "/bin/uniq")
ARM64_STAGE_FN(fut_stage_rust_realpath_binary,      rust_realpath,  "/bin",  "/bin/realpath")
ARM64_STAGE_FN(fut_stage_rust_cmp_binary,           rust_cmp,       "/bin",  "/bin/cmp")
ARM64_STAGE_FN(fut_stage_rust_nl_binary,            rust_nl,        "/bin",  "/bin/nl")
ARM64_STAGE_FN(fut_stage_rust_rev_binary,           rust_rev,       "/bin",  "/bin/rev")
ARM64_STAGE_FN(fut_stage_rust_od_binary,            rust_od,        "/bin",  "/bin/od")
ARM64_STAGE_FN(fut_stage_rust_printenv_binary,      rust_printenv,  "/bin",  "/bin/printenv")
ARM64_STAGE_FN(fut_stage_rust_whoami_binary,        rust_whoami,    "/bin",  "/bin/whoami")
ARM64_STAGE_FN(fut_stage_rust_id_binary,            rust_id,        "/bin",  "/bin/id")
ARM64_STAGE_FN(fut_stage_rust_chmod_binary,         rust_chmod,     "/bin",  "/bin/chmod")
ARM64_STAGE_FN(fut_stage_rust_hostname_binary,      rust_hostname,  "/bin",  "/bin/hostname")
ARM64_STAGE_FN(fut_stage_rust_arch_binary,          rust_arch,      "/bin",  "/bin/arch")
ARM64_STAGE_FN(fut_stage_rust_kill_binary,          rust_kill,      "/bin",  "/bin/kill")
ARM64_STAGE_FN(fut_stage_rust_rmdir_binary,         rust_rmdir,     "/bin",  "/bin/rmdir")
ARM64_STAGE_FN(fut_stage_rust_sync_binary,          rust_sync,      "/bin",  "/bin/sync")
ARM64_STAGE_FN(fut_stage_rust_fold_binary,          rust_fold,      "/bin",  "/bin/fold")
ARM64_STAGE_FN(fut_stage_rust_tac_binary,           rust_tac,       "/bin",  "/bin/tac")
ARM64_STAGE_FN(fut_stage_rust_strings_binary,       rust_strings,   "/bin",  "/bin/strings")
ARM64_STAGE_FN(fut_stage_rust_cut_binary,           rust_cut,       "/bin",  "/bin/cut")
ARM64_STAGE_FN(fut_stage_rust_seq_binary,           rust_seq,       "/bin",  "/bin/seq")
ARM64_STAGE_FN(fut_stage_rust_tr_binary,            rust_tr,        "/bin",  "/bin/tr")
ARM64_STAGE_FN(fut_stage_rust_base64_binary,        rust_base64,    "/bin",  "/bin/base64")
ARM64_STAGE_FN(fut_stage_rust_mktemp_binary,        rust_mktemp,    "/bin",  "/bin/mktemp")
ARM64_STAGE_FN(fut_stage_rust_uptime_binary,        rust_uptime,    "/bin",  "/bin/uptime")
ARM64_STAGE_FN(fut_stage_rust_truncate_binary,      rust_truncate,  "/bin",  "/bin/truncate")
ARM64_STAGE_FN(fut_stage_rust_stat_binary,          rust_stat,      "/bin",  "/bin/stat")
ARM64_STAGE_FN(fut_stage_rust_tty_binary,           rust_tty,       "/bin",  "/bin/tty")
#else
int fut_stage_rust_hello_binary(void)         { return -ENODEV; }
int fut_stage_rust_uname_binary(void)         { return -ENODEV; }
int fut_stage_rust_pwd_binary(void)           { return -ENODEV; }
int fut_stage_rust_ls_binary(void)            { return -ENODEV; }
int fut_stage_rust_mkdir_binary(void)         { return -ENODEV; }
int fut_stage_rust_touch_binary(void)         { return -ENODEV; }
int fut_stage_rust_rm_binary(void)            { return -ENODEV; }
int fut_stage_rust_cat_binary(void)           { return -ENODEV; }
int fut_stage_rust_wc_binary(void)            { return -ENODEV; }
int fut_stage_rust_true_binary(void)          { return -ENODEV; }
int fut_stage_rust_false_binary(void)         { return -ENODEV; }
int fut_stage_rust_env_binary(void)           { return -ENODEV; }
int fut_stage_rust_head_binary(void)          { return -ENODEV; }
int fut_stage_rust_tail_binary(void)          { return -ENODEV; }
int fut_stage_rust_grep_binary(void)          { return -ENODEV; }
int fut_stage_rust_sleep_binary(void)         { return -ENODEV; }
int fut_stage_rust_date_binary(void)          { return -ENODEV; }
int fut_stage_rust_settings_binary(void)      { return -ENODEV; }
int fut_stage_rust_tree_binary(void)          { return -ENODEV; }
int fut_stage_rust_wallpaper_binary(void)     { return -ENODEV; }
int fut_stage_rust_cp_binary(void)            { return -ENODEV; }
int fut_stage_rust_mv_binary(void)            { return -ENODEV; }
int fut_stage_rust_basename_binary(void)      { return -ENODEV; }
int fut_stage_rust_dirname_binary(void)       { return -ENODEV; }
int fut_stage_rust_clear_binary(void)         { return -ENODEV; }
int fut_stage_rust_which_binary(void)         { return -ENODEV; }
int fut_stage_rust_readlink_binary(void)      { return -ENODEV; }
int fut_stage_rust_ln_binary(void)            { return -ENODEV; }
int fut_stage_rust_tee_binary(void)           { return -ENODEV; }
int fut_stage_rust_yes_binary(void)           { return -ENODEV; }
int fut_stage_rust_uniq_binary(void)          { return -ENODEV; }
int fut_stage_rust_realpath_binary(void)      { return -ENODEV; }
int fut_stage_rust_cmp_binary(void)           { return -ENODEV; }
int fut_stage_rust_nl_binary(void)            { return -ENODEV; }
int fut_stage_rust_rev_binary(void)           { return -ENODEV; }
int fut_stage_rust_od_binary(void)            { return -ENODEV; }
int fut_stage_rust_printenv_binary(void)      { return -ENODEV; }
int fut_stage_rust_whoami_binary(void)        { return -ENODEV; }
int fut_stage_rust_id_binary(void)            { return -ENODEV; }
int fut_stage_rust_chmod_binary(void)         { return -ENODEV; }
int fut_stage_rust_hostname_binary(void)      { return -ENODEV; }
int fut_stage_rust_arch_binary(void)          { return -ENODEV; }
int fut_stage_rust_kill_binary(void)          { return -ENODEV; }
int fut_stage_rust_rmdir_binary(void)         { return -ENODEV; }
int fut_stage_rust_sync_binary(void)          { return -ENODEV; }
int fut_stage_rust_fold_binary(void)          { return -ENODEV; }
int fut_stage_rust_tac_binary(void)           { return -ENODEV; }
int fut_stage_rust_strings_binary(void)       { return -ENODEV; }
int fut_stage_rust_cut_binary(void)           { return -ENODEV; }
int fut_stage_rust_seq_binary(void)           { return -ENODEV; }
int fut_stage_rust_tr_binary(void)            { return -ENODEV; }
int fut_stage_rust_base64_binary(void)        { return -ENODEV; }
int fut_stage_rust_mktemp_binary(void)        { return -ENODEV; }
int fut_stage_rust_uptime_binary(void)        { return -ENODEV; }
int fut_stage_rust_truncate_binary(void)      { return -ENODEV; }
int fut_stage_rust_stat_binary(void)          { return -ENODEV; }
int fut_stage_rust_tty_binary(void)           { return -ENODEV; }
#endif
ARM64_STAGE_FN(fut_stage_init_binary,               init,           "/sbin", "/sbin/init")
ARM64_STAGE_FN(fut_stage_shell_binary,              shell,          "/bin",  "/bin/shell")

/* Optional / not-yet-staged on ARM64 */
int fut_stage_wayland_client_binary(void) {
    return -ENODEV;  /* wl-simple — diagnostics-only, not staged */
}

int fut_stage_wayland_color_client_binary(void) {
    return -ENODEV;  /* wl-colorwheel — diagnostics-only, not staged */
}

/* fbtest / second-stub aren't part of the ARM64 build set — the
 * kernel image only embeds the binaries listed above. */
int fut_stage_second_stub_binary(void)  { return -ENODEV; }
int fut_stage_fbtest_binary(void)       { return -ENODEV; }

/* fut_stage_startup_sound stub for ARM64 lives in kernel/exec/elf64.c
 * (the aarch64 #elif branch), alongside the other per-arch staging
 * helpers.  Don't duplicate it here. */

/* ============================================================
 *   Page Table Management
 * ============================================================
 * Implemented in platform/arm64/pmap.c
 * ============================================================ */

/* ============================================================
 *   Task State Segment Stubs (x86-64 specific)
 * ============================================================ */

void fut_tss_set_kernel_stack(uint32_t cpu_id, uint64_t stack_top) {
    (void)cpu_id;
    (void)stack_top;
    /* TSS not used on ARM64 */
}

/* ============================================================
 *   Context Switching (Architecture-dependent)
 * ============================================================ */

/* Context switch functions are now implemented in context_switch.S */
extern void fut_context_switch_asm(void);

/* ============================================================
 *   Hardware I/O Stubs (x86-64 specific)
 * ============================================================ */

void hal_outb(uint16_t port, uint8_t value) {
    (void)port;
    (void)value;
    /* x86-64 I/O port access not available on ARM64 */
}

/* ============================================================
 *   ARM64 Atomic Operation Symbols
 * ============================================================ */

/*
 * ARM64 atomic operations using inline assembly.
 * GCC generates calls to these libgcc helpers for C11 atomic operations.
 * We implement them using ARM64 atomic instructions (LDADD, STLR, etc.)
 */

#include <stdint.h>

/* Atomic store operations (used by atomic_store_explicit) */
void __atomic_store_8(volatile void *ptr, uint64_t val, int memorder) {
    (void)memorder;
    /* Use STLR (store-release) for atomic store */
    __asm__ volatile(
        "stlr %0, [%1]"
        :
        : "r"(val), "r"(ptr)
        : "memory"
    );
}

void __atomic_store_4(volatile void *ptr, uint32_t val, int memorder) {
    (void)memorder;
    __asm__ volatile(
        "stlr %w0, [%1]"
        :
        : "r"(val), "r"(ptr)
        : "memory"
    );
}

/* Atomic load operations (used by atomic_load_explicit) */
uint64_t __atomic_load_8(const volatile void *ptr, int memorder) {
    (void)memorder;
    uint64_t result;
    /* Use LDAR (load-acquire) for atomic load */
    __asm__ volatile(
        "ldar %0, [%1]"
        : "=r"(result)
        : "r"(ptr)
        : "memory"
    );
    return result;
}

uint32_t __atomic_load_4(const volatile void *ptr, int memorder) {
    (void)memorder;
    uint32_t result;
    __asm__ volatile(
        "ldar %w0, [%1]"
        : "=r"(result)
        : "r"(ptr)
        : "memory"
    );
    return result;
}

/* Atomic compare-and-exchange (used by atomic_compare_exchange_*) */
_Bool __atomic_compare_exchange_8(volatile void *ptr, void *expected, uint64_t desired,
                                   _Bool weak, int success_memorder, int failure_memorder) {
    (void)weak;
    (void)success_memorder;
    (void)failure_memorder;

    uint64_t *exp_ptr = (uint64_t *)expected;
    uint64_t old_val = *exp_ptr;
    uint64_t tmp;
    uint32_t store_result;
    _Bool success;

    __asm__ volatile(
        "1: ldaxr %0, [%3]\n"           // Load-exclusive with acquire
        "   cmp %0, %4\n"                // Compare with expected
        "   b.ne 2f\n"                   // Branch if not equal
        "   stlxr %w1, %5, [%3]\n"       // Store-exclusive with release
        "   cbnz %w1, 1b\n"              // Retry if store failed
        "   mov %w2, #1\n"               // Success
        "   b 3f\n"
        "2: clrex\n"                     // Clear exclusive monitor
        "   mov %w2, #0\n"               // Failure
        "3:"
        : "=&r"(tmp), "=&r"(store_result), "=&r"(success)
        : "r"(ptr), "r"(old_val), "r"(desired)
        : "cc", "memory"
    );

    if (!success) {
        *exp_ptr = tmp;
    }

    return success;
}

_Bool __atomic_compare_exchange_4(volatile void *ptr, void *expected, uint32_t desired,
                                   _Bool weak, int success_memorder, int failure_memorder) {
    (void)weak;
    (void)success_memorder;
    (void)failure_memorder;

    uint32_t *exp_ptr = (uint32_t *)expected;
    uint32_t old_val = *exp_ptr;
    uint32_t tmp;
    uint32_t store_result;
    _Bool success;

    __asm__ volatile(
        "1: ldaxr %w0, [%3]\n"
        "   cmp %w0, %w4\n"
        "   b.ne 2f\n"
        "   stlxr %w1, %w5, [%3]\n"
        "   cbnz %w1, 1b\n"
        "   mov %w2, #1\n"
        "   b 3f\n"
        "2: clrex\n"
        "   mov %w2, #0\n"
        "3:"
        : "=&r"(tmp), "=&r"(store_result), "=&r"(success)
        : "r"(ptr), "r"(old_val), "r"(desired)
        : "cc", "memory"
    );

    if (!success) {
        *exp_ptr = tmp;
    }

    return success;
}

/* ============================================================
 *   Interrupt Descriptor Table Stubs (x86-64 specific)
 * ============================================================ */

void fut_idt_set_entry(uint8_t vector, uint64_t handler, uint16_t selector, uint8_t type_attr, uint8_t ist) {
    (void)vector;
    (void)handler;
    (void)selector;
    (void)type_attr;
    (void)ist;
    /* IDT not used on ARM64 - interrupts handled via GIC */
}
