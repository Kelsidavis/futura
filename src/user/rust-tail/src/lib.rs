// SPDX-License-Identifier: MPL-2.0
//
// rust-tail — fourteenth user-space Rust program for Futura OS.
//
// Prints the last N lines of each file (default 10). Implementation
// is a simple line-buffer ring: read the whole file in 4 KiB chunks,
// remember a fixed-size pool of the most recent line offsets so we
// can dump them at EOF. We keep the line-text storage in a single
// contiguous arena so we don't need an allocator.
//
// Tradeoffs: a single line longer than ARENA_BYTES bytes gets
// truncated. The default pool size (DEFAULT_LINES = 10) is plenty
// for typical log/text files; -n N adjusts it up to MAX_LINES.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const READ_BUF: usize = 4096;
const ARENA_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 4096;
const DEFAULT_LINES: usize = 10;

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
unsafe fn sys_open_ro(path: *const u8) -> i64 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY, 0) }
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
unsafe fn sys_open_ro(path: *const u8) -> i64 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY, 0) }
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

fn parse_usize(p: *const u8) -> Option<usize> {
    let n = cstr_len(p);
    if n == 0 {
        return None;
    }
    let mut v: usize = 0;
    for i in 0..n {
        let b = unsafe { *p.add(i) };
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(v)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-tail] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Streaming ring of the last `limit` lines.
//
// arena[] is a circular byte buffer. line_starts[] holds (start, len)
// for each captured line. When a line wins the eviction race, we
// re-use its slot and bump the wrap counter; we never compact arena
// on the fly — instead we tolerate fragmentation and just refuse to
// store a line whose tail wraps over the slot we'd need to read.
struct Tail {
    arena: [u8; ARENA_BYTES],
    arena_used: usize,
    starts: [u32; MAX_LINES],
    lens: [u32; MAX_LINES],
    next: usize,
    count: usize,
    limit: usize,
}

impl Tail {
    const fn new(limit: usize) -> Self {
        Self {
            arena: [0u8; ARENA_BYTES],
            arena_used: 0,
            starts: [0u32; MAX_LINES],
            lens: [0u32; MAX_LINES],
            next: 0,
            count: 0,
            limit,
        }
    }

    fn push_line(&mut self, line: &[u8]) {
        if self.limit == 0 {
            return;
        }
        // If line doesn't fit at the tail of arena, wrap to start.
        let need = line.len().min(ARENA_BYTES);
        if self.arena_used + need > ARENA_BYTES {
            self.arena_used = 0;
        }
        let start = self.arena_used;
        // Copy at most ARENA_BYTES bytes; truncate huge lines.
        let copy_len = need;
        for i in 0..copy_len {
            self.arena[start + i] = line[i];
        }
        self.arena_used += copy_len;
        self.starts[self.next] = start as u32;
        self.lens[self.next] = copy_len as u32;
        self.next = (self.next + 1) % self.limit;
        if self.count < self.limit {
            self.count += 1;
        }
    }

    fn drain(&self) {
        if self.count == 0 {
            return;
        }
        let start_slot = (self.next + self.limit - self.count) % self.limit;
        for i in 0..self.count {
            let slot = (start_slot + i) % self.limit;
            let s = self.starts[slot] as usize;
            let l = self.lens[slot] as usize;
            if !write_all(STDOUT, &self.arena[s..s + l]) {
                return;
            }
        }
    }
}

fn tail_fd(fd: i32, tail: &mut Tail, scratch: &mut [u8]) -> Result<(), ()> {
    let mut line_buf = [0u8; 4096];
    let mut line_len = 0usize;
    loop {
        let n = unsafe {
            syscall3(
                sysn::READ,
                fd as u64,
                scratch.as_mut_ptr() as u64,
                scratch.len() as u64,
            )
        };
        if n == 0 {
            break;
        }
        if n < 0 {
            return Err(());
        }
        let bytes = n as usize;
        for i in 0..bytes {
            let b = scratch[i];
            if line_len < line_buf.len() {
                line_buf[line_len] = b;
                line_len += 1;
            }
            if b == b'\n' {
                tail.push_line(&line_buf[..line_len]);
                line_len = 0;
            }
        }
    }
    if line_len > 0 {
        // Trailing partial line (no '\n').
        tail.push_line(&line_buf[..line_len]);
    }
    tail.drain();
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum HeaderMode { Auto, Quiet, Verbose }

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut limit: usize = DEFAULT_LINES;
    let mut hmode = HeaderMode::Auto;

    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-q") || arg_is(p, b"--quiet") || arg_is(p, b"--silent") {
            hmode = HeaderMode::Quiet; idx += 1; continue;
        }
        if arg_is(p, b"-v") || arg_is(p, b"--verbose") {
            hmode = HeaderMode::Verbose; idx += 1; continue;
        }
        if arg_is(p, b"-n") {
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(np) => match parse_usize(np) {
                    Some(v) => {
                        limit = v.min(MAX_LINES);
                        idx += 1;
                    }
                    None => {
                        write_str(STDERR, b"rust-tail: -n needs a non-negative integer\n");
                        return 1;
                    }
                },
                None => {
                    write_str(STDERR, b"rust-tail: -n needs an argument\n");
                    return 1;
                }
            }
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else {
            // -<NUM> shorthand. Bounds-check before reading p[1] so an
            // empty argv string can't trick us into reading past its
            // NUL into adjacent argv memory.
            let n = cstr_len(p);
            if n >= 2 && unsafe { *p } == b'-'
                && (b'0'..=b'9').contains(&unsafe { *p.add(1) })
            {
                let mut tmp = [0u8; 16];
                if n - 1 >= tmp.len() {
                    write_str(STDERR, b"rust-tail: numeric arg too long\n");
                    return 1;
                }
                for i in 1..n {
                    tmp[i - 1] = unsafe { *p.add(i) };
                }
                tmp[n - 1] = 0;
                match parse_usize(tmp.as_ptr()) {
                    Some(v) => {
                        limit = v.min(MAX_LINES);
                        idx += 1;
                    }
                    None => break,
                }
            } else {
                break;
            }
        }
    }

    // Static — both for arena footprint and to avoid a too-deep stack.
    // Initialize with limit=0 so the entire struct is zero-valued and the
    // linker emits it into .bss instead of .data; we set TAIL.limit
    // (and reset the rest) below before tail_fd() reads anything.
    // Without this, the [u8; 64K] arena carried 64 KiB of explicit
    // zero bytes in the binary image (the `limit: 10` field made the
    // initializer non-trivial).
    static mut TAIL: Tail = Tail::new(0);
    let mut scratch = [0u8; READ_BUF];
    let mut had_error = false;

    if (idx as i32) >= argc {
        unsafe {
            TAIL = Tail::new(limit);
            if tail_fd(STDIN, &mut *core::ptr::addr_of_mut!(TAIL), &mut scratch).is_err() {
                had_error = true;
            }
        }
    } else {
        let mut file_count: i32 = 0;
        let mut probe = idx;
        while argv_get(argc, argv, probe).is_some() {
            file_count += 1;
            probe += 1;
        }

        let mut first = true;
        let stdin_label: &[u8] = b"standard input";
        while let Some(p) = argv_get(argc, argv, idx) {
            let n = cstr_len(p);
            let is_dash = n == 1 && unsafe { *p } == b'-';
            let (fd, opened_owned, header_ptr, header_len) = if is_dash {
                (STDIN, false, stdin_label.as_ptr(), stdin_label.len())
            } else {
                let f = unsafe { sys_open_ro(p) };
                if f < 0 {
                    write_str(STDERR, b"rust-tail: cannot open '");
                    unsafe {
                        let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                    }
                    write_str(STDERR, b"'\n");
                    had_error = true;
                    idx += 1;
                    continue;
                }
                (f as i32, true, p, n)
            };
            let show_header = match hmode {
                HeaderMode::Quiet => false,
                HeaderMode::Verbose => true,
                HeaderMode::Auto => file_count > 1,
            };
            if show_header {
                if !first {
                    write_str(STDOUT, b"\n");
                }
                write_str(STDOUT, b"==> ");
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDOUT as u64, header_ptr as u64, header_len as u64);
                }
                write_str(STDOUT, b" <==\n");
            }
            first = false;
            unsafe {
                TAIL = Tail::new(limit);
                if tail_fd(fd, &mut *core::ptr::addr_of_mut!(TAIL), &mut scratch).is_err() {
                    had_error = true;
                }
                if opened_owned {
                    let _ = syscall1(sysn::CLOSE, fd as u64);
                }
            }
            idx += 1;
        }
    }

    if had_error { 1 } else { 0 }
}
