// SPDX-License-Identifier: MPL-2.0
//
// rust-ls — fourth user-space Rust program for Futura OS.
//
// Lists the entries of a directory using the openat(2)/getdents64(2)
// syscall pair. Default target is "." (i.e. AT_FDCWD on the cwd).
// Exit code 0 on success, 1 on any failure (open / read / write).
//
// Output is one entry per line, sorted by the order the kernel returns
// them. "." and ".." are filtered out so the output matches `ls`'s
// default behaviour.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const GETDENTS64: u64 = 61;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const GETDENTS64: u64 = 217;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200000; // Linux generic
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const BUF_LEN: usize = 4096;

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

fn write_all(fd: i32, mut s: &[u8]) -> bool {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return false;
        }
        s = &s[n as usize..];
    }
    true
}

fn write_str(fd: i32, s: &[u8]) {
    let _ = write_all(fd, s);
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-ls] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// bcmp(3) is provided by libfutura — required because libcore's
// slice-equality lowering on aarch64 emits direct calls to it.

// Hide-policy for dot-prefixed entries.
#[derive(Copy, Clone, PartialEq, Eq)]
enum DotMode { HideAll, ShowAlmostAll, ShowAll }

// Buffered-listing storage so we can sort before emitting (GNU ls
// default is alphabetical, not directory-stream order). Cap entries
// at ~1K names, total ~32 KiB of name bytes — fine for normal dirs;
// huge directories will fall through to "as many as fit" without
// erroring out.
const ENTRY_CAP: usize = 1024;
const NAME_BUF: usize  = 32 * 1024;

#[derive(Copy, Clone)]
struct Entry { name_off: u32, name_len: u32, d_type: u8, ino: u64 }

static mut ENTRIES: [Entry; ENTRY_CAP] = [Entry { name_off: 0, name_len: 0, d_type: 0, ino: 0 }; ENTRY_CAP];
static mut ENTRY_COUNT: usize = 0;
static mut NAMES: [u8; NAME_BUF] = [0; NAME_BUF];
static mut NAMES_USED: usize = 0;

fn entries_reset() {
    unsafe {
        ENTRY_COUNT = 0;
        NAMES_USED = 0;
    }
}

fn entries_push(name: &[u8], d_type: u8, ino: u64) {
    unsafe {
        if ENTRY_COUNT >= ENTRY_CAP { return; }
        if NAMES_USED + name.len() > NAME_BUF { return; }
        let off = NAMES_USED as u32;
        for (i, &b) in name.iter().enumerate() {
            NAMES[NAMES_USED + i] = b;
        }
        NAMES_USED += name.len();
        ENTRIES[ENTRY_COUNT] = Entry {
            name_off: off,
            name_len: name.len() as u32,
            d_type,
            ino,
        };
        ENTRY_COUNT += 1;
    }
}

fn entry_slice(e: Entry) -> &'static [u8] {
    unsafe {
        let p = (&raw const NAMES) as *const u8;
        core::slice::from_raw_parts(p.add(e.name_off as usize), e.name_len as usize)
    }
}

// Byte-wise lexicographic less-than. Matches the kernel's UTF-8-naive
// comparison; collation isn't locale-aware here either way.
fn entry_less(a: Entry, b: Entry) -> bool {
    let sa = entry_slice(a);
    let sb = entry_slice(b);
    let n = sa.len().min(sb.len());
    for i in 0..n {
        if sa[i] != sb[i] { return sa[i] < sb[i]; }
    }
    sa.len() < sb.len()
}

fn entries_sort() {
    // Insertion sort — fine for the entry counts we cap at.
    unsafe {
        let n = ENTRY_COUNT;
        for i in 1..n {
            let cur = ENTRIES[i];
            let mut j = i;
            while j > 0 && entry_less(cur, ENTRIES[j - 1]) {
                ENTRIES[j] = ENTRIES[j - 1];
                j -= 1;
            }
            ENTRIES[j] = cur;
        }
    }
}

fn arg_is(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Parse leading flags. Match GNU ls's default:
    //   no flag   ->  HideAll        (skip every dot-prefixed entry)
    //   -a        ->  ShowAll        (include '.' and '..')
    //   -A        ->  ShowAlmostAll  (include other dot-files but skip '.' and '..')
    // Earlier versions implicitly behaved like -A which surprised
    // anyone running 'ls /etc' and seeing hidden state files.
    let mut mode = DotMode::HideAll;
    let mut classify = false;
    let mut reverse = false;
    let mut unsorted = false;
    let mut show_ino = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if arg_is(p, b"-a") || arg_is(p, b"--all") {
            mode = DotMode::ShowAll;
            idx += 1;
        } else if arg_is(p, b"-A") || arg_is(p, b"--almost-all") {
            mode = DotMode::ShowAlmostAll;
            idx += 1;
        } else if arg_is(p, b"-F") || arg_is(p, b"--classify") {
            classify = true;
            idx += 1;
        } else if arg_is(p, b"-r") || arg_is(p, b"--reverse") {
            reverse = true;
            idx += 1;
        } else if arg_is(p, b"-f") {
            // GNU ls -f: don't sort, also implies -a. Useful when you
            // want raw directory-stream order (e.g. on huge dirs).
            unsorted = true;
            mode = DotMode::ShowAll;
            idx += 1;
        } else if arg_is(p, b"-i") || arg_is(p, b"--inode") {
            show_ino = true;
            idx += 1;
        } else if arg_is(p, b"-U") {
            // -U: don't sort (no other side effects), GNU extension.
            unsorted = true;
            idx += 1;
        } else if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-ls [OPTION]... [PATH]...
List directory contents (sorted alphabetically by default).

  -a, --all              do not ignore entries starting with .
  -A, --almost-all       like -a but skip '.' and '..'
  -F, --classify         append entry-type indicator (*/=@|)
  -i, --inode            print inode number before each name
  -r, --reverse          reverse the sort order
  -f                     do not sort, list raw directory order (implies -a)
  -U                     do not sort, but keep dot-file filtering
      --help             show this help and exit

With no PATH, list the current directory. Multiple PATHs are listed
each in turn with a \"<path>:\" header.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        } else {
            break;
        }
    }

    // Collect every non-flag argv into the path list. Multiple paths
    // each get listed in turn; if the path isn't a directory (e.g. a
    // regular file), GNU ls just echoes the name and that's what we
    // do here too. Without this, `rust-ls /bin/cat` previously failed
    // with "cannot open directory".
    let mut had_error = false;
    let mut paths_seen: i32 = 0;
    // Count first so we can decide whether to emit "<path>:" headers.
    let mut probe = idx as usize;
    while argv_get(argc, argv, probe).is_some() {
        paths_seen += 1;
        probe += 1;
    }

    let mut buf = [0u8; BUF_LEN];

    let list_one = |path_ptr: *const u8,
                    path_len: usize,
                    label_with_header: bool,
                    not_first: bool,
                    buf: &mut [u8; BUF_LEN]| -> bool {
        // Per-listing static buffers — reset before each path so a
        // multi-PATH invocation doesn't accumulate names across dirs.
        entries_reset();
        let fd = unsafe {
            syscall4(
                sysn::OPENAT,
                AT_FDCWD as u64,
                path_ptr as u64,
                O_RDONLY | O_DIRECTORY,
                0,
            )
        };
        if fd < 0 {
            // Not a directory? Try opening without O_DIRECTORY to see
            // if it's a regular file. If so, just echo the name —
            // matches `ls` on a non-dir argv.
            let plain = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, path_ptr as u64, O_RDONLY, 0)
            };
            if plain >= 0 {
                let _ = unsafe { syscall1(sysn::CLOSE, plain as u64) };
                if path_len > 0 {
                    if !write_all(STDOUT, unsafe {
                        core::slice::from_raw_parts(path_ptr, path_len)
                    }) {
                        return false;
                    }
                    if !write_all(STDOUT, b"\n") { return false; }
                }
                return true;
            }
            write_str(STDERR, b"rust-ls: cannot open '");
            unsafe {
                let _ = syscall3(sysn::WRITE, STDERR as u64, path_ptr as u64, path_len as u64);
            }
            write_str(STDERR, b"'\n");
            return false;
        }
        let fd = fd as i32;
        if label_with_header {
            if not_first { write_str(STDOUT, b"\n"); }
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, path_ptr as u64, path_len as u64);
            }
            write_str(STDOUT, b":\n");
        }

        let mut local_err = false;
        loop {
            let n = unsafe {
                syscall3(
                    sysn::GETDENTS64,
                    fd as u64,
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                )
            };
            if n < 0 { local_err = true; break; }
            if n == 0 { break; }
            let bytes = n as usize;
            let mut off = 0usize;
            while off < bytes {
                if off + 19 > bytes { break; }
                let lo = buf[off + 16] as usize;
                let hi = buf[off + 17] as usize;
                let reclen = lo | (hi << 8);
                if reclen < 19 || off + reclen > bytes { break; }
                // d_ino lives at offset 0 (8 bytes, little-endian).
                let mut ino: u64 = 0;
                for k in 0..8 {
                    ino |= (buf[off + k] as u64) << (k * 8);
                }
                let d_type = buf[off + 18];
                let name_start = off + 19;
                let mut name_end = name_start;
                while name_end < off + reclen && buf[name_end] != 0 {
                    name_end += 1;
                }
                let name = &buf[name_start..name_end];
                let nlen = name.len();
                let is_dot = nlen == 1 && name[0] == b'.';
                let is_dotdot = nlen == 2 && name[0] == b'.' && name[1] == b'.';
                let starts_with_dot = nlen > 0 && name[0] == b'.';
                let skip = match mode {
                    DotMode::HideAll => starts_with_dot,
                    DotMode::ShowAlmostAll => is_dot || is_dotdot,
                    DotMode::ShowAll => false,
                };
                if !skip && nlen > 0 {
                    entries_push(name, d_type, ino);
                }
                off += reclen;
            }
            if local_err { break; }
        }

        let _ = unsafe { syscall1(sysn::CLOSE, fd as u64) };

        // Sort + emit unless -f/-U asked for raw directory order.
        if !unsorted {
            entries_sort();
        }
        let count = unsafe { ENTRY_COUNT };
        // Emit forward by default; -r walks the array in reverse.
        for i in 0..count {
            let idx = if reverse { count - 1 - i } else { i };
            let e = unsafe { ENTRIES[idx] };
            let name = entry_slice(e);
            if show_ino {
                let mut numbuf = [0u8; 24];
                let mut k = numbuf.len();
                let mut v = e.ino;
                if v == 0 {
                    k -= 1;
                    numbuf[k] = b'0';
                } else {
                    while v > 0 {
                        k -= 1;
                        numbuf[k] = b'0' + (v % 10) as u8;
                        v /= 10;
                    }
                }
                if !write_all(STDOUT, &numbuf[k..]) { local_err = true; break; }
                if !write_all(STDOUT, b" ") { local_err = true; break; }
            }
            if !write_all(STDOUT, name) { local_err = true; break; }
            if classify {
                const DT_FIFO: u8 = 1;
                const DT_DIR:  u8 = 4;
                const DT_LNK:  u8 = 10;
                const DT_SOCK: u8 = 12;
                let suffix: &[u8] = match e.d_type {
                    DT_DIR  => b"/",
                    DT_LNK  => b"@",
                    DT_FIFO => b"|",
                    DT_SOCK => b"=",
                    _       => b"",
                };
                if !suffix.is_empty()
                    && !write_all(STDOUT, suffix) { local_err = true; break; }
            }
            if !write_all(STDOUT, b"\n") { local_err = true; break; }
        }
        !local_err
    };

    if paths_seen == 0 {
        let dot: [u8; 2] = [b'.', 0];
        if !list_one(dot.as_ptr(), 1, false, false, &mut buf) {
            had_error = true;
        }
    } else {
        let multi = paths_seen > 1;
        let mut printed = 0i32;
        let mut walk = idx as usize;
        while let Some(p) = argv_get(argc, argv, walk) {
            // Skip null/garbage argv entries defensively.
            if (p as usize) < 0x10000 { walk += 1; continue; }
            let mut plen = 0usize;
            unsafe { while *p.add(plen) != 0 { plen += 1; } }
            if !list_one(p, plen, multi, printed > 0, &mut buf) {
                had_error = true;
            }
            printed += 1;
            walk += 1;
        }
    }

    if had_error { 1 } else { 0 }
}
