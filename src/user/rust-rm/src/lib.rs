// SPDX-License-Identifier: MPL-2.0
//
// rust-rm — remove files (and, with -r, whole directory trees).
//
//   rust-rm [-f] FILE [FILE...]            unlink each FILE
//   rust-rm -r [-f] PATH [PATH...]         depth-first remove a tree
//
// With -f, missing-file errors are silently swallowed and the exit
// code stays 0 unless a different error occurs. Without -r, refuses
// to act on a directory (kernel returns EISDIR/EPERM/etc which we
// surface). With -r, walks each directory via getdents64 and removes
// children before issuing rmdir, bounded to MAX_DEPTH so the
// recursion can't blow our fixed stack.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const UNLINKAT: u64 = 35;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const GETDENTS64: u64 = 61;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const UNLINK: u64 = 87;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const GETDENTS64: u64 = 217;
    pub const RMDIR: u64 = 84;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200_000;
const STDERR: i32 = 2;
const ENOENT: i64 = -2;
const EISDIR: i64 = -21;
// Per-arch mismatch in errno when unlinking a dir on x86_64 (-EPERM=-1):
const EPERM: i64 = -1;
#[cfg(target_arch = "aarch64")]
const AT_REMOVEDIR: u64 = 0x200;
const MAX_DEPTH: usize = 16;

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
unsafe fn sys_unlink(path: *const u8) -> i64 {
    unsafe { syscall3(sysn::UNLINKAT, AT_FDCWD as u64, path as u64, 0) }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn sys_rmdir(path: *const u8) -> i64 {
    unsafe { syscall3(sysn::UNLINKAT, AT_FDCWD as u64, path as u64, AT_REMOVEDIR) }
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
unsafe fn sys_unlink(path: *const u8) -> i64 {
    unsafe { syscall1(sysn::UNLINK, path as u64) }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn sys_rmdir(path: *const u8) -> i64 {
    unsafe { syscall1(sysn::RMDIR, path as u64) }
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

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

fn argv_get(argc: i32, argv: *const *const u8, idx: usize) -> Option<*const u8> {
    if (idx as i32) >= argc {
        return None;
    }
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() { None } else { Some(p) }
    }
}

fn arg_is(p: *const u8, want: &[u8]) -> bool {
    let n = cstr_len(p);
    if n != want.len() {
        return false;
    }
    for i in 0..n {
        if unsafe { *p.add(i) } != want[i] {
            return false;
        }
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-rm] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Open `path` as a directory; return fd or negative errno.
fn open_dir(path: *const u8) -> i64 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY | O_DIRECTORY, 0) }
}

fn close_fd(fd: i32) {
    unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
}

const PATH_BUF: usize = 1024;

fn report_removed(path_buf: &[u8], path_len: usize) {
    // GNU rm -v format: "removed '<path>'\n".
    write_str(1, b"removed '");
    write_str(1, &path_buf[..path_len]);
    write_str(1, b"'\n");
}

// Depth-first remove rooted at `path` (NUL-terminated). The caller's
// path buffer is reused for each child by appending "/<name>" and
// rewinding the length on return — this keeps memory bounded at one
// PATH_BUF for the whole tree.
fn rm_tree(path_buf: &mut [u8; PATH_BUF], path_len: usize, depth: usize, force: bool, verbose: bool) -> bool {
    // Try unlink first — covers the common case where the entry is a
    // regular file or symlink. ENOENT under -f is silent success;
    // EISDIR / EPERM (x86_64 returns EPERM here) means "it's a dir,
    // recurse".
    let r = unsafe { sys_unlink(path_buf.as_ptr()) };
    if r == 0 {
        if verbose { report_removed(path_buf, path_len); }
        return true;
    }
    if force && r == ENOENT { return true; }
    let is_dir_err = r == EISDIR || r == EPERM;
    if !is_dir_err {
        // Hard error other than "is a directory": surface it.
        write_str(STDERR, b"rust-rm: cannot remove '");
        write_str(STDERR, &path_buf[..path_len]);
        write_str(STDERR, b"'\n");
        return false;
    }
    if depth >= MAX_DEPTH {
        write_str(STDERR, b"rust-rm: tree too deep at '");
        write_str(STDERR, &path_buf[..path_len]);
        write_str(STDERR, b"'\n");
        return false;
    }

    let fd = open_dir(path_buf.as_ptr());
    if fd < 0 {
        if force && fd == ENOENT { return true; }
        write_str(STDERR, b"rust-rm: cannot open '");
        write_str(STDERR, &path_buf[..path_len]);
        write_str(STDERR, b"'\n");
        return false;
    }
    let dir_fd = fd as i32;

    let mut had_error = false;
    let mut buf = [0u8; 4096];
    'read: loop {
        let n = unsafe {
            syscall3(sysn::GETDENTS64, dir_fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let bytes = n as usize;
        let mut off = 0usize;
        while off < bytes {
            if off + 19 > bytes { break; }
            let lo = buf[off + 16] as usize;
            let hi = buf[off + 17] as usize;
            let reclen = lo | (hi << 8);
            if reclen < 19 || off + reclen > bytes { break; }
            let dtype = buf[off + 18];
            let name_start = off + 19;
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            let nlen = name.len();
            // Skip "." and "..".
            let is_dot = nlen == 1 && name[0] == b'.';
            let is_dotdot = nlen == 2 && name[0] == b'.' && name[1] == b'.';
            if !(is_dot || is_dotdot) {
                // Compose path_buf[..path_len] + "/" + name + NUL.
                let need_sep = path_len > 0 && path_buf[path_len - 1] != b'/';
                let total = path_len + (if need_sep { 1 } else { 0 }) + nlen;
                if total + 1 > path_buf.len() {
                    write_str(STDERR, b"rust-rm: composed path too long\n");
                    had_error = true;
                    break 'read;
                }
                let mut pos = path_len;
                if need_sep { path_buf[pos] = b'/'; pos += 1; }
                for i in 0..nlen { path_buf[pos + i] = name[i]; }
                path_buf[pos + nlen] = 0;
                let child_len = pos + nlen;
                let _ = dtype;  // hint only; rm_tree re-checks via sys_unlink return
                if !rm_tree(path_buf, child_len, depth + 1, force, verbose) {
                    had_error = true;
                }
                // Restore parent path (NUL-terminate at original len).
                path_buf[path_len] = 0;
            }
            off += reclen;
        }
    }
    close_fd(dir_fd);
    if had_error { return false; }
    // All children gone; remove the now-empty directory.
    let r2 = unsafe { sys_rmdir(path_buf.as_ptr()) };
    if r2 < 0 && !(force && r2 == ENOENT) {
        write_str(STDERR, b"rust-rm: cannot rmdir '");
        write_str(STDERR, &path_buf[..path_len]);
        write_str(STDERR, b"'\n");
        return false;
    }
    if verbose && r2 == 0 { report_removed(path_buf, path_len); }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut force = false;
    let mut recursive = false;
    let mut verbose = false;
    let mut dir_ok = false;

    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-f") {
            force = true;
            idx += 1;
        } else if arg_is(p, b"-r") || arg_is(p, b"-R")
            || arg_is(p, b"--recursive")
        {
            recursive = true;
            idx += 1;
        } else if arg_is(p, b"-v") || arg_is(p, b"--verbose") {
            verbose = true;
            idx += 1;
        } else if arg_is(p, b"-d") || arg_is(p, b"--dir") {
            dir_ok = true;
            idx += 1;
        } else if arg_is(p, b"-rf") || arg_is(p, b"-fr")
            || arg_is(p, b"-Rf") || arg_is(p, b"-fR")
        {
            recursive = true;
            force = true;
            idx += 1;
        } else if arg_is(p, b"-rv") || arg_is(p, b"-vr")
            || arg_is(p, b"-Rv") || arg_is(p, b"-vR")
        {
            recursive = true;
            verbose = true;
            idx += 1;
        } else if arg_is(p, b"-rfv") || arg_is(p, b"-rvf")
            || arg_is(p, b"-frv") || arg_is(p, b"-fvr")
            || arg_is(p, b"-vfr") || arg_is(p, b"-vrf")
        {
            recursive = true;
            force = true;
            verbose = true;
            idx += 1;
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-rm [OPTION]... FILE [FILE...]
Remove each FILE.

  -f                   ignore missing files; do not prompt
  -r, -R, --recursive  walk directories and remove their contents
  -d, --dir            remove empty directories too
  -v, --verbose        emit \"removed '<path>'\" for each removal
      --help           show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        } else {
            break;
        }
    }

    if (idx as i32) >= argc {
        write_str(STDERR, b"usage: rust-rm [-rf] FILE [FILE...]\n");
        return 1;
    }

    let mut had_error = false;
    let mut path_buf = [0u8; PATH_BUF];
    while let Some(p) = argv_get(argc, argv, idx) {
        let n = cstr_len(p);
        if n == 0 {
            if !force {
                write_str(STDERR, b"rust-rm: empty filename\n");
                had_error = true;
            }
            idx += 1;
            continue;
        }
        if recursive {
            if n + 1 > path_buf.len() {
                write_str(STDERR, b"rust-rm: path too long\n");
                had_error = true;
                idx += 1;
                continue;
            }
            for i in 0..n { path_buf[i] = unsafe { *p.add(i) }; }
            path_buf[n] = 0;
            if !rm_tree(&mut path_buf, n, 0, force, verbose) {
                had_error = true;
            }
        } else {
            let mut rc = unsafe { sys_unlink(p) };
            // -d: if unlink failed because path is a directory, try
            // rmdir. EISDIR or EPERM (BSD-style) both warrant a
            // fallback; rather than match exact errno values, just
            // attempt rmdir on any unlink failure when -d is on.
            if rc < 0 && dir_ok {
                let r2 = unsafe { sys_rmdir(p) };
                if r2 == 0 { rc = 0; }
            }
            if rc < 0 {
                if force && rc == ENOENT {
                    // Silent swallow.
                } else {
                    write_str(STDERR, b"rust-rm: cannot remove '");
                    unsafe {
                        let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                    }
                    write_str(STDERR, b"'\n");
                    had_error = true;
                }
            } else if verbose {
                write_str(1, b"removed '");
                unsafe { let _ = syscall3(sysn::WRITE, 1, p as u64, n as u64); }
                write_str(1, b"'\n");
            }
        }
        idx += 1;
    }

    if had_error { 1 } else { 0 }
}
