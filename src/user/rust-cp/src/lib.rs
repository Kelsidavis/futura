// SPDX-License-Identifier: MPL-2.0
//
// rust-cp — copy a single regular file.
//
//   rust-cp [-n] <src> <dst>
//   rust-cp [-n] <src> <dst-dir>/   (DST treated as directory →
//                                    copy goes to <dst-dir>/<basename>)
//
// Reads SRC and writes DST in 4 KiB chunks. Creates DST with mode
// 0644:
//   default: O_WRONLY|O_CREAT|O_TRUNC  (truncate existing content)
//   -n:      O_WRONLY|O_CREAT|O_EXCL   (no-clobber — refuse to
//                                       overwrite an existing DST)
//
// If DST is an existing directory, the copy lands at DST/<basename>
// (matches POSIX cp behavior). No recursive copy, no preserve flags.
// Errors are written to stderr with a short prefix and exit code 1.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const READ: u64 = 63;
    pub const GETDENTS64: u64 = 61;
    pub const MKDIRAT: u64 = 34;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const READ: u64 = 0;
    pub const GETDENTS64: u64 = 217;
    pub const MKDIR: u64 = 83;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
// Linux generic O_DIRECTORY value; matches the kernel's flag bit.
const O_DIRECTORY: u64 = 0o200_000;

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const BUF: usize = 4096;

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
    write_str(STDERR, b"[rust-cp] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn open_read(path: *const u8) -> i32 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY, 0) as i32 }
}

fn sys_mkdir(path: *const u8, mode: u32) -> i64 {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { syscall3(sysn::MKDIRAT, AT_FDCWD as u64, path as u64, mode as u64) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SYS_mkdir takes 2 args (path, mode). Pass 0 for the unused
        // third register — syscall3 sets rdx but the kernel ignores
        // it for SYS_mkdir.
        unsafe { syscall3(sysn::MKDIR, path as u64, mode as u64, 0) }
    }
}

fn open_dir(path: *const u8) -> i64 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64,
                      O_RDONLY | O_DIRECTORY, 0) }
}

const PATH_MAX: usize = 1024;
const CP_MAX_DEPTH: usize = 32;

fn open_write(path: *const u8, no_clobber: bool) -> i32 {
    let flags = if no_clobber {
        O_WRONLY | O_CREAT | O_EXCL
    } else {
        O_WRONLY | O_CREAT | O_TRUNC
    };
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, flags, 0o644) as i32 }
}

fn arg_is(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

fn close_fd(fd: i32) {
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
}

fn copy_loop(src_fd: i32, dst_fd: i32) -> bool {
    let mut buf = [0u8; BUF];
    loop {
        let n = unsafe {
            syscall3(sysn::READ, src_fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 {
            return false;
        }
        if n == 0 {
            return true;
        }
        let mut off = 0i64;
        while off < n {
            let w = unsafe {
                syscall3(
                    sysn::WRITE,
                    dst_fd as u64,
                    (buf.as_ptr() as u64).wrapping_add(off as u64),
                    (n - off) as u64,
                )
            };
            if w <= 0 {
                return false;
            }
            off += w;
        }
    }
}

// Returns true on success. Reuses src_buf and dst_buf for the whole
// tree by appending "/<name>" and rewinding the lengths on return.
fn cp_tree(
    src_buf: &mut [u8; PATH_MAX], src_len: usize,
    dst_buf: &mut [u8; PATH_MAX], dst_len: usize,
    depth: usize,
    no_clobber: bool, verbose: bool,
) -> bool {
    if depth >= CP_MAX_DEPTH {
        write_str(STDERR, b"rust-cp: tree too deep at '");
        write_str(STDERR, &src_buf[..src_len]);
        write_str(STDERR, b"'\n");
        return false;
    }

    // Probe src as directory.
    let dfd = open_dir(src_buf.as_ptr());
    if dfd < 0 {
        // It's a regular file (or symlink to one) — single-file copy.
        let src_fd = open_read(src_buf.as_ptr());
        if src_fd < 0 {
            write_str(STDERR, b"rust-cp: cannot open '");
            write_str(STDERR, &src_buf[..src_len]);
            write_str(STDERR, b"'\n");
            return false;
        }
        let dst_fd = open_write(dst_buf.as_ptr(), no_clobber);
        if dst_fd < 0 {
            close_fd(src_fd);
            if no_clobber {
                write_str(STDERR, b"rust-cp: destination exists '");
            } else {
                write_str(STDERR, b"rust-cp: cannot create '");
            }
            write_str(STDERR, &dst_buf[..dst_len]);
            write_str(STDERR, b"'\n");
            return false;
        }
        let ok = copy_loop(src_fd, dst_fd);
        close_fd(src_fd);
        close_fd(dst_fd);
        if ok && verbose {
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, b"'".as_ptr() as u64, 1);
                let _ = syscall3(sysn::WRITE, STDOUT as u64, src_buf.as_ptr() as u64, src_len as u64);
                let _ = syscall3(sysn::WRITE, STDOUT as u64, b"' -> '".as_ptr() as u64, 6);
                let _ = syscall3(sysn::WRITE, STDOUT as u64, dst_buf.as_ptr() as u64, dst_len as u64);
                let _ = syscall3(sysn::WRITE, STDOUT as u64, b"'\n".as_ptr() as u64, 2);
            }
        }
        return ok;
    }

    let src_dir = dfd as i32;
    // Ensure dst directory exists. Ignore EEXIST.
    let _ = sys_mkdir(dst_buf.as_ptr(), 0o755);

    let mut had_error = false;
    let mut buf = [0u8; 4096];
    'read: loop {
        let n = unsafe {
            syscall3(sysn::GETDENTS64, src_dir as u64,
                     buf.as_mut_ptr() as u64, buf.len() as u64)
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
            let name_start = off + 19;
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            let nlen = name.len();
            let is_dot = nlen == 1 && name[0] == b'.';
            let is_dotdot = nlen == 2 && name[0] == b'.' && name[1] == b'.';
            if !(is_dot || is_dotdot) {
                // Compose src + dst child paths.
                let s_need_sep = src_len > 0 && src_buf[src_len - 1] != b'/';
                let d_need_sep = dst_len > 0 && dst_buf[dst_len - 1] != b'/';
                let s_total = src_len + (if s_need_sep { 1 } else { 0 }) + nlen;
                let d_total = dst_len + (if d_need_sep { 1 } else { 0 }) + nlen;
                if s_total + 1 > src_buf.len() || d_total + 1 > dst_buf.len() {
                    write_str(STDERR, b"rust-cp: composed path too long\n");
                    had_error = true;
                    break 'read;
                }
                let mut sp = src_len;
                if s_need_sep { src_buf[sp] = b'/'; sp += 1; }
                for i in 0..nlen { src_buf[sp + i] = name[i]; }
                src_buf[sp + nlen] = 0;
                let s_child = sp + nlen;

                let mut dp = dst_len;
                if d_need_sep { dst_buf[dp] = b'/'; dp += 1; }
                for i in 0..nlen { dst_buf[dp + i] = name[i]; }
                dst_buf[dp + nlen] = 0;
                let d_child = dp + nlen;

                if !cp_tree(src_buf, s_child, dst_buf, d_child,
                            depth + 1, no_clobber, verbose) {
                    had_error = true;
                }

                // Restore parent paths.
                src_buf[src_len] = 0;
                dst_buf[dst_len] = 0;
            }
            off += reclen;
        }
    }
    close_fd(src_dir);
    !had_error
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut no_clobber = false;
    let mut verbose = false;
    let mut recursive = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_is(p, b"-n") { no_clobber = true; idx += 1; continue; }
        if arg_is(p, b"-v") || arg_is(p, b"--verbose") {
            verbose = true; idx += 1; continue;
        }
        if arg_is(p, b"-r") || arg_is(p, b"-R") || arg_is(p, b"--recursive") {
            recursive = true; idx += 1; continue;
        }
        if arg_is(p, b"-nv") || arg_is(p, b"-vn") {
            no_clobber = true; verbose = true; idx += 1; continue;
        }
        if arg_is(p, b"-rv") || arg_is(p, b"-vr")
            || arg_is(p, b"-Rv") || arg_is(p, b"-vR") {
            recursive = true; verbose = true; idx += 1; continue;
        }
        if arg_is(p, b"--") { idx += 1; break; }
        break;
    }
    if argc - idx != 2 {
        write_str(STDERR, b"usage: rust-cp [-nrv] <src> <dst>\n");
        return 1;
    }
    let src = unsafe { *argv.add(idx as usize) };
    let dst = unsafe { *argv.add((idx + 1) as usize) };
    if src.is_null() || (src as usize) < 0x10000 || dst.is_null() || (dst as usize) < 0x10000 {
        write_str(STDERR, b"rust-cp: invalid arguments\n");
        return 1;
    }

    // Recursive path: build src/dst buffers and hand off to cp_tree.
    if recursive {
        let mut src_buf = [0u8; PATH_MAX];
        let mut dst_buf = [0u8; PATH_MAX];
        let mut s_n = 0usize;
        unsafe { while *src.add(s_n) != 0 && s_n < PATH_MAX - 1 {
            src_buf[s_n] = *src.add(s_n); s_n += 1; }
        }
        src_buf[s_n] = 0;

        // If dst is an existing directory, append basename(src) like
        // POSIX cp does. Otherwise dst is the new tree root.
        let dir_probe = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, dst as u64,
                     O_RDONLY | O_DIRECTORY, 0)
        };
        let mut d_n = 0usize;
        unsafe { while *dst.add(d_n) != 0 && d_n < PATH_MAX - 1 {
            dst_buf[d_n] = *dst.add(d_n); d_n += 1; }
        }
        if dir_probe >= 0 {
            close_fd(dir_probe as i32);
            // Append "/basename(src)".
            let mut bstart = s_n;
            while bstart > 0 && src_buf[bstart - 1] != b'/' { bstart -= 1; }
            let basename_len = s_n - bstart;
            if basename_len > 0 {
                let need_sep = d_n > 0 && dst_buf[d_n - 1] != b'/';
                if d_n + (if need_sep { 1 } else { 0 }) + basename_len + 1 > dst_buf.len() {
                    write_str(STDERR, b"rust-cp: composed path too long\n");
                    return 1;
                }
                if need_sep { dst_buf[d_n] = b'/'; d_n += 1; }
                for i in 0..basename_len { dst_buf[d_n + i] = src_buf[bstart + i]; }
                d_n += basename_len;
            }
        }
        dst_buf[d_n] = 0;

        let ok = cp_tree(&mut src_buf, s_n, &mut dst_buf, d_n,
                         0, no_clobber, verbose);
        return if ok { 0 } else { 1 };
    }

    let src_fd = open_read(src);
    if src_fd < 0 {
        write_str(STDERR, b"rust-cp: cannot open source\n");
        return 1;
    }

    // If DST is an existing directory, the actual write target is
    // "<dst>/<basename(src)>". Detect by trying to open it with
    // O_DIRECTORY — succeeds only for a real directory. Fall back to
    // treating DST as a literal path otherwise.
    let mut composed = [0u8; 1024];
    let mut composed_len = 0usize;
    let dst_open_path: *const u8 = {
        let dir_probe = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, dst as u64,
                     O_RDONLY | O_DIRECTORY, 0)
        };
        if dir_probe >= 0 {
            close_fd(dir_probe as i32);
            // Compose <dst>/<basename(src)>.
            let mut dlen = 0usize;
            unsafe { while *dst.add(dlen) != 0 { dlen += 1; } }
            let mut slen = 0usize;
            unsafe { while *src.add(slen) != 0 { slen += 1; } }
            let mut bstart = slen;
            while bstart > 0 && unsafe { *src.add(bstart - 1) } != b'/' {
                bstart -= 1;
            }
            let basename_len = slen - bstart;
            let need_sep = dlen > 0 && unsafe { *dst.add(dlen - 1) } != b'/';
            let total = dlen + (if need_sep { 1 } else { 0 }) + basename_len;
            if total + 1 > composed.len() || basename_len == 0 {
                close_fd(src_fd);
                write_str(STDERR, b"rust-cp: composed path too long or basename empty\n");
                return 1;
            }
            for i in 0..dlen { composed[i] = unsafe { *dst.add(i) }; }
            let mut pos = dlen;
            if need_sep { composed[pos] = b'/'; pos += 1; }
            for i in 0..basename_len {
                composed[pos + i] = unsafe { *src.add(bstart + i) };
            }
            composed[pos + basename_len] = 0;
            composed_len = pos + basename_len;
            composed.as_ptr()
        } else {
            dst
        }
    };
    let _ = composed_len;

    let dst_fd = open_write(dst_open_path, no_clobber);
    if dst_fd < 0 {
        close_fd(src_fd);
        if no_clobber {
            write_str(STDERR, b"rust-cp: destination exists (use without -n to overwrite)\n");
        } else {
            write_str(STDERR, b"rust-cp: cannot create destination\n");
        }
        return 1;
    }

    let ok = copy_loop(src_fd, dst_fd);
    close_fd(src_fd);
    close_fd(dst_fd);

    if !ok {
        write_str(STDERR, b"rust-cp: copy failed\n");
        return 1;
    }
    if verbose {
        // GNU cp -v: "'src' -> 'dst'\n" using the resolved dst path.
        let dst_used = dst_open_path;
        let mut dlen = 0usize;
        unsafe { while *dst_used.add(dlen) != 0 { dlen += 1; } }
        let mut slen = 0usize;
        unsafe { while *src.add(slen) != 0 { slen += 1; } }
        unsafe {
            let _ = syscall3(sysn::WRITE, STDOUT as u64, b"'".as_ptr() as u64, 1);
            let _ = syscall3(sysn::WRITE, STDOUT as u64, src as u64, slen as u64);
            let _ = syscall3(sysn::WRITE, STDOUT as u64, b"' -> '".as_ptr() as u64, 6);
            let _ = syscall3(sysn::WRITE, STDOUT as u64, dst_used as u64, dlen as u64);
            let _ = syscall3(sysn::WRITE, STDOUT as u64, b"'\n".as_ptr() as u64, 2);
        }
    }
    0
}
