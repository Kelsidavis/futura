// SPDX-License-Identifier: MPL-2.0
//
// rust-id — print effective user / group / supplementary group ids.
//
//   rust-id        ->  uid=0(root) gid=0(root) groups=0(root)
//
// Pulls uid/gid via the four no-arg syscalls (getuid, geteuid,
// getgid, getegid) and the user name from $USER. No supplementary
// groups query yet — Futura doesn't track them per-task; we just
// repeat the primary gid in the groups= field so the output shape
// matches GNU id.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const GETUID: u64 = 102;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
}

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall0(nr: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

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
unsafe fn syscall0(nr: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
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

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-id] panic\n");
    unsafe {
        sys_exit(1);
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

fn env_lookup(envp: *const *const u8, key: &[u8]) -> Option<*const u8> {
    if envp.is_null() {
        return None;
    }
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

fn write_dec(n: u64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    write_str(STDOUT, &buf[i..]);
}

fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[derive(Copy, Clone)]
enum Mode { Default, OnlyUid, OnlyGid }

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    // Flags: -u (uid only), -g (gid only), -n (print name not number),
    // -r (use real ids — same as effective on Futura). -n requires
    // either -u or -g, matching GNU id.
    let mut mode = Mode::Default;
    let mut name_only = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { idx += 1; continue; }
        if arg_eq(p, b"-u") { mode = Mode::OnlyUid; idx += 1; continue; }
        if arg_eq(p, b"-g") { mode = Mode::OnlyGid; idx += 1; continue; }
        if arg_eq(p, b"-n") { name_only = true; idx += 1; continue; }
        if arg_eq(p, b"-r") { idx += 1; continue; } // real == effective on Futura
        if arg_eq(p, b"--") { break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-id [OPTION]
Print user and group IDs.

  -u            print only the effective UID
  -g            print only the effective GID
  -n            print name instead of number (with -u or -g)
  -r            use real instead of effective IDs (same on Futura)
      --help        show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        write_str(STDERR, b"rust-id: unsupported option (use -u / -g / -n / -r)\n");
        return 1;
    }
    if name_only && matches!(mode, Mode::Default) {
        write_str(STDERR, b"rust-id: -n requires -u or -g\n");
        return 1;
    }

    let uid = unsafe { syscall0(sysn::GETUID) } as u64;
    let _euid = unsafe { syscall0(sysn::GETEUID) } as u64;
    let gid = unsafe { syscall0(sysn::GETGID) } as u64;
    let _egid = unsafe { syscall0(sysn::GETEGID) } as u64;

    // Pick a user / group name. Without a getpwuid wiring, derive
    // from $USER and $LOGNAME with a "root" fallback for uid 0.
    let user = env_lookup(envp, b"USER")
        .or_else(|| env_lookup(envp, b"LOGNAME"));
    let user_slice: &[u8] = match user {
        Some(p) => {
            let n = cstr_len(p);
            unsafe { core::slice::from_raw_parts(p, n) }
        }
        None => if uid == 0 { b"root" } else { b"" },
    };
    // Group name: same heuristic — root for gid 0, else fall back to
    // the user name (Futura uses primary-group-equals-user).
    let group_slice: &[u8] = if gid == 0 { b"root" } else { user_slice };

    match mode {
        Mode::OnlyUid => {
            if name_only {
                if user_slice.is_empty() {
                    write_dec(uid);
                } else {
                    write_str(STDOUT, user_slice);
                }
            } else {
                write_dec(uid);
            }
            write_str(STDOUT, b"\n");
            return 0;
        }
        Mode::OnlyGid => {
            if name_only {
                if group_slice.is_empty() {
                    write_dec(gid);
                } else {
                    write_str(STDOUT, group_slice);
                }
            } else {
                write_dec(gid);
            }
            write_str(STDOUT, b"\n");
            return 0;
        }
        Mode::Default => {}
    }

    write_str(STDOUT, b"uid=");
    write_dec(uid);
    if !user_slice.is_empty() {
        write_str(STDOUT, b"(");
        write_str(STDOUT, user_slice);
        write_str(STDOUT, b")");
    }
    write_str(STDOUT, b" gid=");
    write_dec(gid);
    if !group_slice.is_empty() {
        write_str(STDOUT, b"(");
        write_str(STDOUT, group_slice);
        write_str(STDOUT, b")");
    }
    write_str(STDOUT, b" groups=");
    write_dec(gid);
    if !group_slice.is_empty() {
        write_str(STDOUT, b"(");
        write_str(STDOUT, group_slice);
        write_str(STDOUT, b")");
    }
    write_str(STDOUT, b"\n");
    0
}
