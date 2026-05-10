// SPDX-License-Identifier: MPL-2.0
//
// rust-ln — create a hard or symbolic link.
//
//   rust-ln <target> <linkpath>      hard link (POSIX default)
//   rust-ln -s <target> <linkpath>   symbolic link
//
// Per-arch syscall:
//   aarch64 -> linkat (37, 5-arg) for hard, symlinkat (36, 3-arg) for soft
//   x86_64  -> link (86, 2-arg) for hard, symlink (88, 2-arg) for soft
//                 — sysnums.h on x86_64 doesn't export linkat/symlinkat,
//                 only the historical 2-arg forms.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const LINKAT: u64 = 37;
    pub const SYMLINKAT: u64 = 36;
    pub const UNLINKAT: u64 = 35;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const LINK: u64 = 86;
    pub const SYMLINK: u64 = 88;
    pub const UNLINK: u64 = 87;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
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
    write_str(STDERR, b"[rust-ln] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut symbolic = false;
    let mut force = false;
    let mut verbose = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if cstr_eq(p, b"-s") || cstr_eq(p, b"--symbolic") {
            symbolic = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-v") || cstr_eq(p, b"--verbose") {
            verbose = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-f") || cstr_eq(p, b"--force") {
            force = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-sv") || cstr_eq(p, b"-vs") {
            symbolic = true; verbose = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-sf") || cstr_eq(p, b"-fs") {
            symbolic = true; force = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-sfv") || cstr_eq(p, b"-svf")
            || cstr_eq(p, b"-fsv") || cstr_eq(p, b"-fvs")
            || cstr_eq(p, b"-vsf") || cstr_eq(p, b"-vfs") {
            symbolic = true; force = true; verbose = true; idx += 1; continue;
        }
        if cstr_eq(p, b"--") { idx += 1; break; }
        if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-ln [-sv] TARGET LINKPATH
Create a link from LINKPATH to TARGET.

  -s, --symbolic   make a symbolic link instead of a hard link
  -f, --force      remove the destination first if it exists
  -v, --verbose    emit \"'linkpath' -> 'target'\" on success
      --help           show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }
    if argc - idx != 2 {
        write_str(STDERR, b"usage: rust-ln [-sv] <target> <linkpath>\n");
        return 1;
    }
    let target = unsafe { *argv.add(idx as usize) };
    let linkpath = unsafe { *argv.add((idx + 1) as usize) };
    if target.is_null() || (target as usize) < 0x10000 ||
       linkpath.is_null() || (linkpath as usize) < 0x10000 {
        write_str(STDERR, b"rust-ln: invalid arguments\n");
        return 1;
    }

    // -f: remove the destination first if it exists. We ignore the
    // unlink return — ENOENT is the normal "nothing to remove" case.
    if force {
        #[cfg(target_arch = "aarch64")]
        unsafe { let _ = syscall3(sysn::UNLINKAT, AT_FDCWD as u64, linkpath as u64, 0); }
        #[cfg(target_arch = "x86_64")]
        unsafe { let _ = syscall1(sysn::UNLINK, linkpath as u64); }
    }

    let r: i64 = if symbolic {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            syscall3(sysn::SYMLINKAT, target as u64, AT_FDCWD as u64, linkpath as u64)
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { syscall2(sysn::SYMLINK, target as u64, linkpath as u64) }
    } else {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // linkat(olddirfd, oldpath, newdirfd, newpath, flags=0)
            syscall5(
                sysn::LINKAT,
                AT_FDCWD as u64,
                target as u64,
                AT_FDCWD as u64,
                linkpath as u64,
                0,
            )
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { syscall2(sysn::LINK, target as u64, linkpath as u64) }
    };

    if r < 0 {
        if symbolic {
            write_str(STDERR, b"rust-ln: symlink failed\n");
        } else {
            write_str(STDERR, b"rust-ln: hard link failed (target may not exist or fs may not support it)\n");
        }
        return 1;
    }
    if verbose {
        // GNU ln -v: "'<linkpath>' -> '<target>'\n".
        let mut tlen = 0usize;
        unsafe { while *target.add(tlen) != 0 { tlen += 1; } }
        let mut llen = 0usize;
        unsafe { while *linkpath.add(llen) != 0 { llen += 1; } }
        unsafe {
            let _ = syscall3(sysn::WRITE, 1, b"'".as_ptr() as u64, 1);
            let _ = syscall3(sysn::WRITE, 1, linkpath as u64, llen as u64);
            let _ = syscall3(sysn::WRITE, 1, b"' -> '".as_ptr() as u64, 6);
            let _ = syscall3(sysn::WRITE, 1, target as u64, tlen as u64);
            let _ = syscall3(sysn::WRITE, 1, b"'\n".as_ptr() as u64, 2);
        }
    }
    0
}
