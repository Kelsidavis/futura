// SPDX-License-Identifier: MPL-2.0
//
// rust-realpath — print a path with its terminal symlink resolved.
//
//   rust-realpath <path>     -> path with the final symlink chased
//                              through (up to MAX_HOPS), one round
//                              of readlink per hop.
//
// Limited to the FINAL component, not full canonicalization. That
// covers the common case (/bin/cat → /bin/rust-cat → ...) and matches
// what `readlink -f` does for the immediate target. Fully canonical
// path resolution would need per-component resolution, getcwd, and
// dot-component squashing — a future iteration if/when ENOSYS bites.
//
// If the path itself isn't a symlink, prints it back as-is.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const READLINKAT: u64 = 78;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const READLINK: u64 = 89;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;

const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const PATH_MAX: usize = 1024;
const MAX_HOPS: usize = 16;

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
    write_str(STDERR, b"[rust-realpath] panic\n");
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

// Try readlink on the NUL-terminated path in `cur` of length `cur_len`.
// On success, write the target into `out` and return Some(target_len).
// On failure (not a symlink, ENOENT, etc), return None.
fn try_readlink(cur: &[u8], out: &mut [u8]) -> Option<usize> {
    // cur must be NUL-terminated; we're handed the slice up to but
    // excluding NUL, plus the NUL byte sitting at cur.as_ptr().add(len).
    #[cfg(target_arch = "aarch64")]
    let n = unsafe {
        syscall4(
            sysn::READLINKAT,
            AT_FDCWD as u64,
            cur.as_ptr() as u64,
            out.as_mut_ptr() as u64,
            (out.len() - 1) as u64,
        )
    };
    #[cfg(target_arch = "x86_64")]
    let n = unsafe {
        syscall3(
            sysn::READLINK,
            cur.as_ptr() as u64,
            out.as_mut_ptr() as u64,
            (out.len() - 1) as u64,
        )
    };
    if n <= 0 {
        return None;
    }
    Some(n as usize)
}

// Resolve one path's terminal symlink, printing the (possibly chased)
// result. Returns false on hard failures (only "argument unusable" —
// non-symlink paths just echo back as-is, like `readlink -f` does).
fn resolve_one(p: *const u8) -> bool {
    // Working buffer: NUL-terminated path we feed to readlinkat each hop.
    let mut cur = [0u8; PATH_MAX];
    let n = cstr_len(p).min(PATH_MAX - 1);
    for i in 0..n { cur[i] = unsafe { *p.add(i) }; }
    let mut cur_len = n;
    cur[cur_len] = 0;

    let mut tmp = [0u8; PATH_MAX];

    for _hop in 0..MAX_HOPS {
        let target_len = match try_readlink(&cur[..cur_len + 1], &mut tmp) {
            Some(l) => l,
            None => break, // not a symlink (or can't read) — print what we have
        };
        let absolute = target_len > 0 && tmp[0] == b'/';
        if absolute {
            if target_len >= PATH_MAX - 1 { break; }
            cur[..target_len].copy_from_slice(&tmp[..target_len]);
            cur_len = target_len;
            cur[cur_len] = 0;
        } else {
            // Find last slash in cur[..cur_len] for dirname.
            let mut dir_end = 0usize;
            for i in (0..cur_len).rev() {
                if cur[i] == b'/' { dir_end = i + 1; break; }
            }
            if dir_end == 0 {
                if target_len >= PATH_MAX - 1 { break; }
                cur[..target_len].copy_from_slice(&tmp[..target_len]);
                cur_len = target_len;
            } else {
                let new_len = dir_end + target_len;
                if new_len >= PATH_MAX - 1 { break; }
                cur[dir_end..new_len].copy_from_slice(&tmp[..target_len]);
                cur_len = new_len;
            }
            cur[cur_len] = 0;
        }
    }

    write_str(STDOUT, &cur[..cur_len]);
    write_str(STDOUT, b"\n");
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        write_str(STDERR, b"usage: rust-realpath <path> [<path>...]\n");
        return 1;
    }
    let mut had_error = false;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            write_str(STDERR, b"rust-realpath: invalid argument\n");
            had_error = true;
            continue;
        }
        if !resolve_one(p) {
            had_error = true;
        }
    }
    if had_error { 1 } else { 0 }
}
