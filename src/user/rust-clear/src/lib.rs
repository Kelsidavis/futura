// SPDX-License-Identifier: MPL-2.0
//
// rust-clear — clear the terminal.
//
// Writes the standard ANSI sequence ESC [ 2 J  ESC [ H to stdout
// (clear screen + cursor home). Same effect as the C shell built-in
// `clear` and BSD/GNU `clear(1)` on a terminfo-less terminal.
//
// Single fd-1 write — no termcap probe, no termios fiddling.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
}

const STDOUT: i32 = 1;
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
    write_str(STDERR, b"[rust-clear] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // -x flag: skip the scrollback wipe, only clear the visible screen.
    // Mirrors GNU `clear -x`. Default behaviour also resets scrollback
    // so a wallclock screen-full of past output doesn't reappear when
    // the user scrolls up.
    let mut keep_scrollback = false;
    if argc >= 2 {
        let p = unsafe { *argv.add(1) };
        if !p.is_null() && (p as usize) >= 0x10000 {
            // --help short-circuit (length 6: '--help').
            let mut n = 0usize;
            unsafe { while *p.add(n) != 0 && n < 16 { n += 1; } }
            if n == 6
                && unsafe { *p == b'-' && *p.add(1) == b'-' && *p.add(2) == b'h'
                    && *p.add(3) == b'e' && *p.add(4) == b'l' && *p.add(5) == b'p' }
            {
                let help: &[u8] = b"\
Usage: rust-clear [-x]
Clear the terminal.

  -x        keep the scrollback buffer (only clear the visible screen)
      --help    show this help and exit
\0";
                let len = help.len() - 1;
                unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                          help.as_ptr() as u64, len as u64); }
                return 0;
            }
            // -x compare. Walk the bytes one at a time so we bail at
            // the NUL — a blanket *p.add(1)/*p.add(2) read on a 0- or
            // 1-byte argv runs past its NUL terminator.
            let b0 = unsafe { *p };
            if b0 == b'-' {
                let b1 = unsafe { *p.add(1) };
                if b1 == b'x' {
                    let b2 = unsafe { *p.add(2) };
                    if b2 == 0 {
                        keep_scrollback = true;
                    }
                }
            }
        }
    }
    if keep_scrollback {
        write_str(STDOUT, b"\x1b[H\x1b[2J");
    } else {
        // ESC [ 3 J  → clear scrollback buffer (xterm extension, widely supported)
        // ESC [ H    → cursor home
        // ESC [ 2 J  → clear visible screen
        write_str(STDOUT, b"\x1b[3J\x1b[H\x1b[2J");
    }
    0
}
