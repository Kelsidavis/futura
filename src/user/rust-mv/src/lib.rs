// SPDX-License-Identifier: MPL-2.0
//
// rust-mv — single-file rename via renameat(2).
//
//   rust-mv <src> <dst>           rename src to dst (overwrites)
//   rust-mv -n <src> <dst>        no-clobber: refuse if dst exists
//
// One renameat call. Cross-filesystem moves are not handled (the
// kernel returns EXDEV and we surface it as an error). For same-FS
// moves on FuturaFS this is a metadata operation, not a copy + delete.
//
// On aarch64 -n uses renameat2 with RENAME_NOREPLACE so the check
// is atomic. On x86_64 we fall back to a stat-style probe + rename
// (small TOCTOU window — acceptable, since the alternative is just
// silently overwriting).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const RENAMEAT: u64 = 38;
    pub const RENAMEAT2: u64 = 276;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    // x86_64 sysnums.h only exports SYS_rename = 82 (the deprecated
    // 2-arg form). aarch64 uses renameat = 38. Pick at compile time.
    pub const RENAME: u64 = 82;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200_000;
#[cfg(target_arch = "aarch64")]
const RENAME_NOREPLACE: u64 = 1;
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
unsafe fn syscall5(nr: u64, a: u64, b: u64, c: u64, d: u64, e: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            in("x4") e,
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
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
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

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-mv] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut no_clobber = false;
    let mut idx: i32 = 1;
    if idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if !p.is_null() && (p as usize) >= 0x10000 && arg_eq(p, b"-n") {
            no_clobber = true;
            idx += 1;
        }
    }
    if argc - idx != 2 {
        write_str(STDERR, b"usage: rust-mv [-n] <src> <dst>\n");
        return 1;
    }
    let src = unsafe { *argv.add(idx as usize) };
    let dst_arg = unsafe { *argv.add((idx + 1) as usize) };
    if src.is_null() || (src as usize) < 0x10000 ||
       dst_arg.is_null() || (dst_arg as usize) < 0x10000 {
        write_str(STDERR, b"rust-mv: invalid arguments\n");
        return 1;
    }

    // If DST is an existing directory, the rename target is
    // "<dst>/<basename(src)>" (POSIX mv into a directory).
    let mut composed = [0u8; 1024];
    let dst: *const u8 = {
        let probe = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, dst_arg as u64,
                     O_RDONLY | O_DIRECTORY, 0)
        };
        if probe >= 0 {
            unsafe { let _ = syscall1(sysn::CLOSE, probe as u64); }
            let mut dlen = 0usize;
            unsafe { while *dst_arg.add(dlen) != 0 { dlen += 1; } }
            let mut slen = 0usize;
            unsafe { while *src.add(slen) != 0 { slen += 1; } }
            let mut bstart = slen;
            while bstart > 0 && unsafe { *src.add(bstart - 1) } != b'/' {
                bstart -= 1;
            }
            let basename_len = slen - bstart;
            let need_sep = dlen > 0 && unsafe { *dst_arg.add(dlen - 1) } != b'/';
            let total = dlen + (if need_sep { 1 } else { 0 }) + basename_len;
            if basename_len == 0 || total + 1 > composed.len() {
                write_str(STDERR, b"rust-mv: composed path too long or basename empty\n");
                return 1;
            }
            for i in 0..dlen { composed[i] = unsafe { *dst_arg.add(i) }; }
            let mut pos = dlen;
            if need_sep { composed[pos] = b'/'; pos += 1; }
            for i in 0..basename_len {
                composed[pos + i] = unsafe { *src.add(bstart + i) };
            }
            composed[pos + basename_len] = 0;
            composed.as_ptr()
        } else {
            dst_arg
        }
    };

    let r: i64;

    #[cfg(target_arch = "aarch64")]
    {
        if no_clobber {
            r = unsafe {
                syscall5(
                    sysn::RENAMEAT2,
                    AT_FDCWD as u64,
                    src as u64,
                    AT_FDCWD as u64,
                    dst as u64,
                    RENAME_NOREPLACE,
                )
            };
        } else {
            r = unsafe {
                syscall4(
                    sysn::RENAMEAT,
                    AT_FDCWD as u64,
                    src as u64,
                    AT_FDCWD as u64,
                    dst as u64,
                )
            };
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if no_clobber {
            // No renameat2 on x86_64 — fall back to a probe + rename.
            // Race window between the probe and the rename is small
            // enough to be acceptable for a `-n` advisory check.
            let probe = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, dst as u64, O_RDONLY, 0)
            };
            if probe >= 0 {
                unsafe { let _ = syscall1(sysn::CLOSE, probe as u64); }
                write_str(STDERR, b"rust-mv: destination exists (use without -n to overwrite)\n");
                return 1;
            }
        }
        r = unsafe { syscall2(sysn::RENAME, src as u64, dst as u64) };
    }

    if r < 0 {
        if no_clobber {
            write_str(STDERR, b"rust-mv: destination exists (use without -n to overwrite)\n");
        } else {
            write_str(STDERR, b"rust-mv: renameat failed\n");
        }
        return 1;
    }
    0
}
