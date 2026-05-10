// SPDX-License-Identifier: MPL-2.0
//
// rust-sync — flush all in-memory filesystem state to disk.
//
//   rust-sync
//
// Single zero-arg sync(2) syscall. Per Linux ABI:
//   aarch64 -> SYS_sync = 81
//   x86_64  -> SYS_sync = 162  (hardcoded; sysnums.h doesn't export it
//                               since the kernel routes it directly)
//
// On FuturaFS this is a no-op for the tmpfs root, but it does
// prompt block-device-backed mounts to flush their write-back
// queues. Useful before reboot/poweroff or after a heavy write
// burst when you want the disk to settle.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const SYNC: u64 = 81;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const SYNC: u64 = 162;
}

const STDERR: i32 = 2;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall0(nr: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
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
unsafe fn syscall0(nr: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
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
    write_str(STDERR, b"[rust-sync] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc == 2 {
        let p = unsafe { *argv.add(1) };
        if !p.is_null() && (p as usize) >= 0x10000 {
            let want = b"--help";
            let mut n = 0; unsafe { while *p.add(n) != 0 { n += 1; } }
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *p.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-sync
Flush all in-memory filesystem state to disk via sync(2).

  --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    unsafe {
        let _ = syscall0(sysn::SYNC);
    }
    0
}
