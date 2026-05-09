// SPDX-License-Identifier: MPL-2.0
//
// rust-rmdir — remove an EMPTY directory (POSIX rmdir(1)).
//
//   rust-rmdir <dir> [<dir>...]      remove each leaf directory
//   rust-rmdir -p <dir> [<dir>...]   also remove empty parent dirs
//
// Per-arch syscall:
//   aarch64 -> unlinkat(AT_FDCWD, dir, AT_REMOVEDIR=0x200) (SYS=35)
//   x86_64  -> rmdir(dir)                                  (SYS=84)
//
// Same per-arch dispatch shape as rust-rm — x86_64's sysnums.h
// only exports the deprecated 1-arg rmdir, while aarch64's generic
// set drops both rmdir and unlink and routes through unlinkat with
// the AT_REMOVEDIR flag.
//
// Will not remove a non-empty directory; the kernel returns
// -ENOTEMPTY and we surface it as "rmdir failed".

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const UNLINKAT: u64 = 35;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const RMDIR: u64 = 84;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
#[cfg(target_arch = "aarch64")]
const AT_REMOVEDIR: u64 = 0x200;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

// aarch64 path uses syscall3 (unlinkat) only — no syscall1 wrapper needed.

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
    write_str(STDERR, b"[rust-rmdir] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Try to remove a single directory by NUL-terminated path. Returns
// the kernel's negative errno (or 0 on success).
fn try_rmdir(path: *const u8) -> i64 {
    #[cfg(target_arch = "aarch64")]
    unsafe { syscall3(sysn::UNLINKAT, AT_FDCWD as u64, path as u64, AT_REMOVEDIR) }
    #[cfg(target_arch = "x86_64")]
    unsafe { syscall1(sysn::RMDIR, path as u64) }
}

const PATH_MAX: usize = 1024;

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: i32 = 1;
    let mut parents = false;
    let mut verbose = false;
    let arg_eq = |p: *const u8, want: &[u8]| -> bool {
        for (i, &b) in want.iter().enumerate() {
            if unsafe { *p.add(i) } != b { return false; }
        }
        unsafe { *p.add(want.len()) == 0 }
    };
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_eq(p, b"-p") || arg_eq(p, b"--parents") {
            parents = true; idx += 1; continue;
        }
        if arg_eq(p, b"-v") || arg_eq(p, b"--verbose") {
            verbose = true; idx += 1; continue;
        }
        if arg_eq(p, b"-pv") || arg_eq(p, b"-vp") {
            parents = true; verbose = true; idx += 1; continue;
        }
        if arg_eq(p, b"--") { idx += 1; break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-rmdir [-pv] DIR [DIR...]
Remove each empty DIR.

  -p, --parents   also remove each empty ancestor directory
  -v, --verbose   emit a message per directory removed
      --help          show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }

    if idx >= argc {
        write_str(STDERR, b"usage: rust-rmdir [-p] <dir> [<dir>...]\n");
        return 1;
    }
    let mut had_error = false;
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        let r = try_rmdir(p);
        if r < 0 {
            write_str(STDERR, b"rust-rmdir: cannot remove '");
            let mut n = 0usize;
            unsafe { while *p.add(n) != 0 { n += 1; } }
            unsafe {
                let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
            }
            write_str(STDERR, b"'\n");
            had_error = true;
            continue;
        }
        if verbose {
            let mut n = 0usize;
            unsafe { while *p.add(n) != 0 { n += 1; } }
            write_str(STDOUT, b"rmdir: removing directory, '");
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64, p as u64, n as u64); }
            write_str(STDOUT, b"'\n");
        }
        // -p: also remove each parent component until something fails
        // (typically ENOTEMPTY when the parent has other entries) or
        // we reach the path's first component. Errors on parents are
        // not treated as user-visible failures since the leaf removal
        // already succeeded.
        if parents {
            let mut buf = [0u8; PATH_MAX];
            let mut len = 0usize;
            unsafe {
                while *p.add(len) != 0 && len < PATH_MAX - 1 {
                    buf[len] = *p.add(len);
                    len += 1;
                }
            }
            buf[len] = 0;
            // Strip any trailing slash (treat "a/b/" same as "a/b").
            while len > 1 && buf[len - 1] == b'/' { len -= 1; buf[len] = 0; }
            // Walk back, lopping off the last component each time.
            loop {
                let mut cut = len;
                while cut > 0 && buf[cut - 1] != b'/' { cut -= 1; }
                if cut == 0 { break; }      // no parent component left
                while cut > 1 && buf[cut - 1] == b'/' { cut -= 1; }
                if cut == 0 { break; }      // path was rooted at "/"
                // Truncate buf to `cut` bytes and try to rmdir it.
                buf[cut] = 0;
                len = cut;
                let pr = try_rmdir(buf.as_ptr());
                if pr < 0 { break; }
                if verbose {
                    write_str(STDOUT, b"rmdir: removing directory, '");
                    unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64, buf.as_ptr() as u64, len as u64); }
                    write_str(STDOUT, b"'\n");
                }
            }
        }
    }
    if had_error { 1 } else { 0 }
}
