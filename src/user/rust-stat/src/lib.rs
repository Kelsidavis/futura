// SPDX-License-Identifier: MPL-2.0
//
// rust-stat — print file metadata via newfstatat(2) (POSIX `stat`).
//
//   rust-stat <path> [<path>...]      stat each path (lstat: do NOT
//                                     follow a terminal symlink)
//   rust-stat -L <path> [<path>...]   follow terminal symlinks
//
// Default is lstat-style (matches GNU stat with no -L), so a symlink
// shows as type "symbolic link" rather than the target's type.
//
// Output format mirrors a compact `stat` summary:
//
//   File: <path>
//   Size: <bytes>   Blocks: <st_blocks>   IO Block: <st_blksize>   <type>
//   Mode: (<octal>/<rwxrwxrwx>)   Uid: <uid>   Gid: <gid>
//   Inode: <ino>   Links: <nlink>
//   Modify: <mtime epoch>
//
// Per-arch syscall dispatch:
//   aarch64 -> newfstatat(AT_FDCWD, path, &stat, 0) (SYS=79)
//   x86_64  -> stat(path, &stat)                   (SYS=4)
//
// stat-buffer layout follows the Linux x86_64 layout (matches what
// FuturaFS fills in). aarch64's struct stat layout is identical for
// every field we inspect.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const NEWFSTATAT: u64 = 79;
    pub const READLINKAT: u64 = 78;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const STAT: u64 = 4;
    pub const LSTAT: u64 = 6;
    pub const READLINK: u64 = 89;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
#[cfg(target_arch = "aarch64")]
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

// Matches the kernel's struct fut_stat (kernel/include/kernel/fut_vfs.h).
// Both the aarch64 newfstatat path and the x86_64 stat path write
// this layout, so we don't need per-arch shapes here.
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct StatBuf {
    st_dev:     u64,   //   0
    st_ino:     u64,   //   8
    st_mode:    u32,   //  16
    st_nlink:   u32,   //  20
    st_uid:     u32,   //  24
    st_gid:     u32,   //  28
    st_size:    u64,   //  32
    st_blksize: u64,   //  40
    st_blocks:  u64,   //  48
    st_atime:   u64,   //  56
    _atime_ns:  u32,   //  64
    _atime_pad: u32,   //  68
    st_mtime:   u64,   //  72
    _mtime_ns:  u32,   //  80
    _mtime_pad: u32,   //  84
    st_ctime:   u64,   //  88
    _ctime_ns:  u32,   //  96
    _ctime_pad: u32,   // 100
}                       // total 104 bytes

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

// Write the whole slice, retrying on partial writes. Returns false on
// any short/error return, so format renderers can bail early.
fn write_all(fd: i32, mut s: &[u8]) -> bool {
    while !s.is_empty() {
        let n = unsafe {
            syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64)
        };
        if n <= 0 { return false; }
        s = &s[n as usize..];
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-stat] panic\n");
    unsafe { sys_exit(1); }
}

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    n
}

// Render an unsigned u64 right-justified into a 24-byte scratch and
// return the slice that's actually populated.
fn fmt_u64(mut n: u64, buf: &mut [u8; 24]) -> &[u8] {
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    &buf[i..]
}


// Render mode as 4-char octal padded ("0644").
fn fmt_octal_mode(mode: u32, buf: &mut [u8; 6]) -> &[u8] {
    let m = mode & 0o7777;
    buf[0] = b'0';
    buf[1] = b'0' + ((m >> 9) & 0o7) as u8;
    buf[2] = b'0' + ((m >> 6) & 0o7) as u8;
    buf[3] = b'0' + ((m >> 3) & 0o7) as u8;
    buf[4] = b'0' + (m & 0o7) as u8;
    &buf[..5]
}

// Compose the rwx triplets for u/g/o into a 9-byte slice.
fn fmt_perms(mode: u32, buf: &mut [u8; 10]) -> &[u8] {
    let bits = [
        (0o400, b'r'), (0o200, b'w'), (0o100, b'x'),
        (0o040, b'r'), (0o020, b'w'), (0o010, b'x'),
        (0o004, b'r'), (0o002, b'w'), (0o001, b'x'),
    ];
    for (i, &(mask, ch)) in bits.iter().enumerate() {
        buf[i] = if mode & mask != 0 { ch } else { b'-' };
    }
    &buf[..9]
}

fn type_name(mode: u32) -> &'static [u8] {
    let t = mode & 0o170_000;
    match t {
        0o040_000 => b"directory",
        0o100_000 => b"regular file",
        0o020_000 => b"character device",
        0o060_000 => b"block device",
        0o120_000 => b"symbolic link",
        0o010_000 => b"fifo",
        0o140_000 => b"socket",
        _         => b"unknown",
    }
}

// First char of the perm-string (GNU `ls -l` / `stat` style).
fn type_char(mode: u32) -> u8 {
    match mode & 0o170_000 {
        0o040_000 => b'd',
        0o020_000 => b'c',
        0o060_000 => b'b',
        0o120_000 => b'l',
        0o010_000 => b'p',
        0o140_000 => b's',
        _         => b'-',  // regular file or unknown
    }
}

// Render `st` according to `format`. Conversions:
//   %n name     %s size     %a octal mode (no leading 0)
//   %A rwx perms (drwx...)   %u uid       %g gid
//   %i inode    %h links     %F type-name (e.g. "directory")
//   %Y mtime    %X atime     %Z ctime     %d device
//   %b blocks   %B blksize   %% literal %
// Backslash escapes: \n \t \\
fn render_format(format: &[u8], path: &[u8], st: &StatBuf) -> bool {
    let mut nb = [0u8; 24];
    let mut mb = [0u8; 6];
    let mut pb = [0u8; 10];
    let mut i = 0usize;
    while i < format.len() {
        let c = format[i];
        if c == b'%' && i + 1 < format.len() {
            let spec = format[i + 1];
            i += 2;
            match spec {
                b'n' => { if !write_all(STDOUT, path) { return false; } }
                b'N' => {
                    // GNU stat %N: shell-quoted file name. For symlinks
                    // also append ` -> '<target>'`. Quoting here is the
                    // simple form (single-quotes around the bytes); GNU
                    // also escapes embedded quotes — left out for now.
                    if !write_all(STDOUT, b"'")    { return false; }
                    if !write_all(STDOUT, path)    { return false; }
                    if !write_all(STDOUT, b"'")    { return false; }
                    let mode_bits = st.st_mode & 0o170000;
                    if mode_bits == 0o120000 {
                        // Read the symlink target. Best-effort — if
                        // readlinkat fails, just leave the arrow off.
                        let mut tgt = [0u8; 256];
                        // Build NUL-terminated path for readlinkat
                        let mut pbuf = [0u8; 512];
                        let mut k = 0usize;
                        while k < path.len() && k + 1 < pbuf.len() {
                            pbuf[k] = path[k]; k += 1;
                        }
                        pbuf[k] = 0;
                        let r = unsafe {
                            #[cfg(target_arch = "aarch64")]
                            { syscall4(sysn::READLINKAT, AT_FDCWD as u64,
                                       pbuf.as_ptr() as u64, tgt.as_mut_ptr() as u64,
                                       (tgt.len() - 1) as u64) }
                            #[cfg(target_arch = "x86_64")]
                            { syscall3(sysn::READLINK,
                                       pbuf.as_ptr() as u64, tgt.as_mut_ptr() as u64,
                                       (tgt.len() - 1) as u64) }
                        };
                        if r > 0 {
                            let n = r as usize;
                            if !write_all(STDOUT, b" -> '") { return false; }
                            if !write_all(STDOUT, &tgt[..n]) { return false; }
                            if !write_all(STDOUT, b"'") { return false; }
                        }
                    }
                }
                b's' => { if !write_all(STDOUT, fmt_u64(st.st_size, &mut nb))     { return false; } }
                b'a' => {
                    // GNU: octal mode without leading 0.
                    let s = fmt_octal_mode(st.st_mode, &mut mb);
                    if s.first() == Some(&b'0') && s.len() > 1 {
                        if !write_all(STDOUT, &s[1..]) { return false; }
                    } else {
                        if !write_all(STDOUT, s) { return false; }
                    }
                }
                b'A' => {
                    let tc = [type_char(st.st_mode)];
                    if !write_all(STDOUT, &tc) { return false; }
                    if !write_all(STDOUT, fmt_perms(st.st_mode, &mut pb)) { return false; }
                }
                b'u' => { if !write_all(STDOUT, fmt_u64(st.st_uid as u64, &mut nb)) { return false; } }
                b'U' => {
                    // No getpwuid wired up — render "root" for uid 0
                    // and fall back to the numeric form otherwise.
                    if st.st_uid == 0 {
                        if !write_all(STDOUT, b"root") { return false; }
                    } else if !write_all(STDOUT, fmt_u64(st.st_uid as u64, &mut nb)) {
                        return false;
                    }
                }
                b'g' => { if !write_all(STDOUT, fmt_u64(st.st_gid as u64, &mut nb)) { return false; } }
                b'G' => {
                    if st.st_gid == 0 {
                        if !write_all(STDOUT, b"root") { return false; }
                    } else if !write_all(STDOUT, fmt_u64(st.st_gid as u64, &mut nb)) {
                        return false;
                    }
                }
                b'i' => { if !write_all(STDOUT, fmt_u64(st.st_ino, &mut nb))        { return false; } }
                b'h' => { if !write_all(STDOUT, fmt_u64(st.st_nlink as u64, &mut nb)) { return false; } }
                b'F' => { if !write_all(STDOUT, type_name(st.st_mode))              { return false; } }
                b'Y' => { if !write_all(STDOUT, fmt_u64(st.st_mtime, &mut nb))      { return false; } }
                b'X' => { if !write_all(STDOUT, fmt_u64(st.st_atime, &mut nb))      { return false; } }
                b'Z' => { if !write_all(STDOUT, fmt_u64(st.st_ctime, &mut nb))      { return false; } }
                b'd' => { if !write_all(STDOUT, fmt_u64(st.st_dev, &mut nb))        { return false; } }
                b'b' => { if !write_all(STDOUT, fmt_u64(st.st_blocks, &mut nb))     { return false; } }
                b'B' => { if !write_all(STDOUT, fmt_u64(st.st_blksize, &mut nb))    { return false; } }
                b'%' => { if !write_all(STDOUT, b"%") { return false; } }
                other => {
                    // Unknown conversion — emit verbatim like GNU stat.
                    if !write_all(STDOUT, b"%") { return false; }
                    let one = [other];
                    if !write_all(STDOUT, &one) { return false; }
                }
            }
            continue;
        }
        if c == b'\\' && i + 1 < format.len() {
            let esc = format[i + 1];
            i += 2;
            let out: u8 = match esc {
                b'n' => b'\n',
                b't' => b'\t',
                b'\\' => b'\\',
                b'r' => b'\r',
                other => other,
            };
            let one = [out];
            if !write_all(STDOUT, &one) { return false; }
            continue;
        }
        let one = [c];
        if !write_all(STDOUT, &one) { return false; }
        i += 1;
    }
    true
}

fn do_stat(path: *const u8, follow: bool, format: Option<&[u8]>) -> bool {
    let st = StatBuf::default();
    let stp = &st as *const StatBuf as u64;
    let r;
    #[cfg(target_arch = "aarch64")]
    {
        let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        r = unsafe { syscall4(sysn::NEWFSTATAT, AT_FDCWD as u64, path as u64, stp, flags) };
    }
    #[cfg(target_arch = "x86_64")]
    {
        let nr = if follow { sysn::STAT } else { sysn::LSTAT };
        r = unsafe { syscall2(nr, path as u64, stp) };
    }
    if r < 0 {
        write_str(STDERR, b"rust-stat: cannot stat '");
        let n = cstr_len(path);
        write_str(STDERR, unsafe { core::slice::from_raw_parts(path, n) });
        write_str(STDERR, b"'\n");
        return false;
    }

    let n = cstr_len(path);
    let path_slice = unsafe { core::slice::from_raw_parts(path, n) };

    if let Some(f) = format {
        return render_format(f, path_slice, &st);
    }

    let mut nb = [0u8; 24];
    let mut mb = [0u8; 6];
    let mut pb = [0u8; 10];

    write_str(STDOUT, b"  File: ");
    write_str(STDOUT, path_slice);
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"  Size: ");
    write_str(STDOUT, fmt_u64(st.st_size, &mut nb));
    write_str(STDOUT, b"\tBlocks: ");
    write_str(STDOUT, fmt_u64(st.st_blocks, &mut nb));
    write_str(STDOUT, b"\tIO Block: ");
    write_str(STDOUT, fmt_u64(st.st_blksize, &mut nb));
    write_str(STDOUT, b"\t");
    write_str(STDOUT, type_name(st.st_mode));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Device: ");
    write_str(STDOUT, fmt_u64(st.st_dev, &mut nb));
    write_str(STDOUT, b"\tInode: ");
    write_str(STDOUT, fmt_u64(st.st_ino, &mut nb));
    write_str(STDOUT, b"\tLinks: ");
    write_str(STDOUT, fmt_u64(st.st_nlink as u64, &mut nb));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Access: (");
    write_str(STDOUT, fmt_octal_mode(st.st_mode, &mut mb));
    write_str(STDOUT, b"/");
    let tc = [type_char(st.st_mode)];
    write_str(STDOUT, &tc);
    write_str(STDOUT, fmt_perms(st.st_mode, &mut pb));
    write_str(STDOUT, b")\tUid: ");
    write_str(STDOUT, fmt_u64(st.st_uid as u64, &mut nb));
    write_str(STDOUT, b"\tGid: ");
    write_str(STDOUT, fmt_u64(st.st_gid as u64, &mut nb));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Modify: ");
    write_str(STDOUT, fmt_u64(st.st_mtime, &mut nb));
    write_str(STDOUT, b"\n");
    true
}

fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut follow = false;
    let mut format_ptr: Option<*const u8> = None;
    let mut terse = false;
    let mut printf_mode = false;  // --printf: skip the trailing newline per file
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_eq(p, b"-L") || arg_eq(p, b"--dereference") {
            follow = true; idx += 1; continue;
        }
        if arg_eq(p, b"-t") || arg_eq(p, b"--terse") {
            terse = true; idx += 1; continue;
        }
        if arg_eq(p, b"-c") || arg_eq(p, b"--format") || arg_eq(p, b"--printf") {
            // --printf is identical to -c except the per-file trailing
            // newline is suppressed (matches GNU stat). The user's
            // FORMAT can include \n explicitly if they want one.
            if arg_eq(p, b"--printf") {
                printf_mode = true;
            }
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-stat: format flag needs an argument\n");
                return 1;
            }
            let fp = unsafe { *argv.add((idx + 1) as usize) };
            if fp.is_null() || (fp as usize) < 0x10000 {
                return 1;
            }
            format_ptr = Some(fp);
            idx += 2;
            continue;
        }
        if arg_eq(p, b"--") { idx += 1; break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-stat [OPTION]... FILE [FILE...]
Display file metadata.

  -L, --dereference   follow links (default is lstat-style)
  -c, --format FMT    use FMT instead of the default summary
      --printf FMT    like -c but no trailing newline per file
  -t, --terse          shorthand for -c '%n %s %b %a %u %g %d %i %h %X %Y %Z %B'
      --help          show this help and exit

Format conversions: %n name, %N quoted name (with -> target for symlinks),
%s size, %a octal mode, %A rwx perms,
%u uid, %U user-name, %g gid, %G group-name, %i inode, %h links,
%F type-name, %d device, %b blocks, %B blksize, %X atime, %Y mtime,
%Z ctime, %% literal %.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }
    // -t is a built-in shorthand for a fixed format string; -c overrides
    // -t if both are given (matches GNU stat). The literal needs a
    // NUL terminator so cstr_len downstream finds the end.
    let terse_fmt: &[u8] = b"%n %s %b %a %u %g %d %i %h %X %Y %Z %B\0";
    if terse && format_ptr.is_none() {
        format_ptr = Some(terse_fmt.as_ptr());
    }

    if idx >= argc {
        write_str(STDERR, b"usage: rust-stat [-L] [-c FORMAT] <path> [<path>...]\n");
        return 1;
    }
    // GNU stat with -c emits a newline after each path's render, so we
    // splice one in ourselves rather than requiring the user to add \n.
    let mut had_error = false;
    let format_slice = format_ptr.map(|p| {
        let n = cstr_len(p);
        unsafe { core::slice::from_raw_parts(p, n) }
    });
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        if !do_stat(p, follow, format_slice) { had_error = true; }
        if format_slice.is_some() && !printf_mode {
            let _ = write_all(STDOUT, b"\n");
        }
    }
    if had_error { 1 } else { 0 }
}
