// SPDX-License-Identifier: MPL-2.0
//
// rust-env — twelfth user-space Rust program for Futura OS.
//
//   env                    dump every NAME=VALUE one per line
//   env <cmd> [args...]    execve <cmd> with the current envp; if
//                          <cmd> has no '/' separator, walk PATH to
//                          locate it. This is the path #!/usr/bin/env
//                          shebangs depend on — without the exec
//                          branch they would just dump env and exit.
//
// No allocator. argv is forwarded as the existing pointer array
// pointing at +1 inside argv[]; the kernel doesn't need it
// re-flattened.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const EXECVE: u64 = 221;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const EXECVE: u64 = 59;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall1(nr: u64, a: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") sysn::EXIT,
            in("x0") code,
            options(nostack, noreturn),
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall1(nr: u64, a: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") sysn::EXIT,
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

fn write_all(fd: i32, mut s: &[u8]) {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return;
        }
        s = &s[n as usize..];
    }
}

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(STDERR, b"[rust-env] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Look up PATH in envp and return the value pointer, if any.
fn env_path(envp: *const *const u8) -> Option<*const u8> {
    if envp.is_null() {
        return None;
    }
    let key = b"PATH";
    let mut i = 0usize;
    loop {
        let entry = unsafe { *envp.add(i) };
        if entry.is_null() {
            return None;
        }
        if (entry as usize) < 0x10000 {
            return None;
        }
        let mut ok = true;
        for j in 0..key.len() {
            if unsafe { *entry.add(j) } != key[j] {
                ok = false;
                break;
            }
        }
        if ok && unsafe { *entry.add(key.len()) } == b'=' {
            return Some(unsafe { entry.add(key.len() + 1) });
        }
        i += 1;
    }
}

// Build "<dir>/<name>\0" into buf and execve() it. If openat()
// confirms the file exists, fall through to execve. Returns true
// on a non-fatal miss (fall through to next PATH dir) or never
// returns on success.
fn try_exec_path(dir: &[u8], name: &[u8],
                 argv: *const *const u8, envp: *const *const u8,
                 buf: &mut [u8; 512]) -> bool {
    let dir_use: &[u8] = if dir.is_empty() { b"." } else { dir };
    if dir_use.len() + 1 + name.len() + 1 > buf.len() {
        return false;
    }
    let mut n = 0usize;
    for &b in dir_use {
        buf[n] = b; n += 1;
    }
    if n == 0 || buf[n - 1] != b'/' {
        buf[n] = b'/'; n += 1;
    }
    for &b in name {
        buf[n] = b; n += 1;
    }
    buf[n] = 0;

    // Probe for existence so a typo-d PATH dir can't print misleading
    // execve errors for every PATH entry.
    let fd = unsafe {
        syscall4(sysn::OPENAT, AT_FDCWD as u64, buf.as_ptr() as u64, O_RDONLY, 0) as i32
    };
    if fd < 0 {
        return false;
    }
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
    // Found — try to exec. If the binary isn't actually executable
    // execve will fail; bubble up so the caller can keep walking.
    let _ = unsafe {
        syscall3(sysn::EXECVE, buf.as_ptr() as u64, argv as u64, envp as u64)
    };
    // execve only returns on failure.
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    // --help intercept before the env-as-launcher branch — without
    // this, `env --help` would try to exec a binary literally named
    // "--help".
    if argc == 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let n = cstr_len(first);
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *first.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-env [-0] [COMMAND [ARG...]]
With no COMMAND, dump the environment one VAR=VALUE per line.
With COMMAND, execve it (PATH-walked if it has no slash) using the
current environment - the standard /usr/bin/env shebang shape.

  -0, --null    end each output line with NUL, not newline
                (only applies when dumping the environment)
      --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                              help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    // Parse leading flags before deciding dump-vs-exec. Currently:
    //   -0 / --null  use NUL line separator in dump mode (no effect on exec)
    let mut flag_idx: i32 = 1;
    let mut null_sep = false;
    while flag_idx < argc {
        let p = unsafe { *argv.add(flag_idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        // -0 / --null
        let n = cstr_len(p);
        let m0 = b"-0";
        let mn = b"--null";
        let is_zero = n == m0.len()
            && (0..m0.len()).all(|i| unsafe { *p.add(i) } == m0[i]);
        let is_null = n == mn.len()
            && (0..mn.len()).all(|i| unsafe { *p.add(i) } == mn[i]);
        if is_zero || is_null {
            null_sep = true;
            flag_idx += 1;
            continue;
        }
        break;
    }

    // env <cmd> [args...]: execve cmd with the current envp; PATH
    // walk if cmd has no slash. Without this branch, /usr/bin/env
    // shebangs would dump env and exit instead of running their
    // interpreter.
    if flag_idx < argc {
        let cmd_p = unsafe { *argv.add(flag_idx as usize) };
        if !cmd_p.is_null() && (cmd_p as usize) >= 0x10000 {
            // The argv pointer to forward starts at the cmd slot so the
            // child sees argv[0] = cmd, argv[1..] = its own args.
            let child_argv: *const *const u8 = unsafe { argv.add(flag_idx as usize) };

            // Slash → exec literal path.
            let mut has_slash = false;
            let cmd_n = cstr_len(cmd_p);
            for i in 0..cmd_n {
                if unsafe { *cmd_p.add(i) } == b'/' {
                    has_slash = true;
                    break;
                }
            }
            if has_slash {
                let _ = unsafe {
                    syscall3(sysn::EXECVE, cmd_p as u64, child_argv as u64, envp as u64)
                };
                write_all(STDERR, b"rust-env: exec failed\n");
                return 127;
            }

            // PATH walk (default to /bin:/sbin if PATH unset).
            let path_ptr = env_path(envp);
            let default_path: &[u8] = b"/bin:/sbin";
            let path_slice: &[u8] = match path_ptr {
                Some(p) => {
                    let n = cstr_len(p);
                    unsafe { core::slice::from_raw_parts(p, n) }
                }
                None => default_path,
            };
            let cmd_slice = unsafe { core::slice::from_raw_parts(cmd_p, cmd_n) };
            let mut buf = [0u8; 512];
            let mut start = 0usize;
            for i in 0..=path_slice.len() {
                let at_end = i == path_slice.len();
                if at_end || path_slice[i] == b':' {
                    let dir = &path_slice[start..i];
                    if try_exec_path(dir, cmd_slice, child_argv, envp, &mut buf) {
                        // unreachable on success — execve doesn't return.
                        return 0;
                    }
                    start = i + 1;
                }
            }
            write_all(STDERR, b"rust-env: command not found\n");
            return 127;
        }
    }

    // No command — dump env and exit.
    if envp.is_null() {
        return 0;
    }
    let mut i = 0usize;
    loop {
        let e = unsafe { *envp.add(i) };
        if e.is_null() {
            break;
        }
        // Defensive: a corrupt envp could hold a low-half non-pointer.
        // Refuse to dereference it before its first byte fault.
        if (e as usize) < 0x10000 {
            break;
        }
        let n = cstr_len(e);
        let bytes = unsafe { core::slice::from_raw_parts(e, n) };
        write_all(STDOUT, bytes);
        if null_sep {
            write_all(STDOUT, b"\0");
        } else {
            write_all(STDOUT, b"\n");
        }
        i += 1;
    }
    0
}
