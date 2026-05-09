// SPDX-License-Identifier: MPL-2.0
//
// rust-settings — TUI mirror of the Wayland wl-settings panel.
//
// Reads the same kernel + environment surface the GUI panel does
// (uname, hostname, env vars) and prints a labelled table to stdout.
// Useful for headless/serial sessions where the compositor isn't
// running but the user still wants the system summary.
//
// No allocator / no_std — everything fits in fixed-size buffers,
// matching the rest of the rust-* CLI suite.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const UNAME: u64 = 160;
    pub const GETCWD: u64 = 17;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const UNAME: u64 = 63;
    pub const GETCWD: u64 = 79;
}

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const UTS_LEN: usize = 65;

#[repr(C)]
struct Utsname {
    sysname: [u8; UTS_LEN],
    nodename: [u8; UTS_LEN],
    release: [u8; UTS_LEN],
    version: [u8; UTS_LEN],
    machine: [u8; UTS_LEN],
    domainname: [u8; UTS_LEN],
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
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
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

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

fn field_len(field: &[u8]) -> usize {
    let mut n = 0;
    while n < field.len() && field[n] != 0 {
        n += 1;
    }
    n
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-settings] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Look up an env var by name in envp. Returns None if missing.
fn env_lookup(envp: *const *const u8, key: &[u8]) -> Option<*const u8> {
    if envp.is_null() {
        return None;
    }
    let mut i = 0usize;
    loop {
        let entry = unsafe { *envp.add(i) };
        if entry.is_null() {
            return None;
        }
        if (entry as usize) < 0x10000 {
            return None;
        }
        let mut ok = true;
        for j in 0..key.len() {
            if unsafe { *entry.add(j) } != key[j] {
                ok = false;
                break;
            }
        }
        if ok && unsafe { *entry.add(key.len()) } == b'=' {
            return Some(unsafe { entry.add(key.len() + 1) });
        }
        i += 1;
    }
}

fn print_row(label: &[u8], value: &[u8]) {
    // 18-char left-aligned label, then ' : ', then value, then '\n'.
    let mut buf = [b' '; 22];
    let n = label.len().min(18);
    for i in 0..n {
        buf[i] = label[i];
    }
    buf[18] = b' ';
    buf[19] = b':';
    buf[20] = b' ';
    buf[21] = b' ';
    write_str(STDOUT, &buf[..21]);
    write_str(STDOUT, value);
    write_str(STDOUT, b"\n");
}

fn print_row_cstr(label: &[u8], cstr: *const u8) {
    if cstr.is_null() || (cstr as usize) < 0x10000 {
        print_row(label, b"(unset)");
        return;
    }
    let n = cstr_len(cstr);
    let s = unsafe { core::slice::from_raw_parts(cstr, n) };
    print_row(label, s);
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) -> i32 {
    let banner = b"\n--- Futura System Settings ---\n\n";
    write_str(STDOUT, banner);

    // uname
    let mut uts = Utsname {
        sysname: [0; UTS_LEN],
        nodename: [0; UTS_LEN],
        release: [0; UTS_LEN],
        version: [0; UTS_LEN],
        machine: [0; UTS_LEN],
        domainname: [0; UTS_LEN],
    };
    let rc = unsafe { syscall1(sysn::UNAME, &mut uts as *mut Utsname as u64) };
    if rc < 0 {
        write_str(STDERR, b"rust-settings: uname() failed\n");
        return 1;
    }

    print_row(b"OS Name", b"Futura / Horizon DE");
    print_row(b"Version", b"0.9.0");
    print_row(b"Kernel", &uts.sysname[..field_len(&uts.sysname)]);
    print_row(b"Release", &uts.release[..field_len(&uts.release)]);
    print_row(b"Build", &uts.version[..field_len(&uts.version)]);
    print_row(b"Architecture", &uts.machine[..field_len(&uts.machine)]);
    print_row(b"Hostname", &uts.nodename[..field_len(&uts.nodename)]);

    // cwd via getcwd
    let mut cwd_buf = [0u8; 256];
    let rc = unsafe { syscall2(sysn::GETCWD, cwd_buf.as_mut_ptr() as u64, cwd_buf.len() as u64) };
    if rc > 0 {
        let n = field_len(&cwd_buf);
        print_row(b"Current Dir", &cwd_buf[..n]);
    } else {
        print_row(b"Current Dir", b"(unknown)");
    }

    // Env-derived rows. Use the env_lookup helper so we don't depend
    // on libc's getenv plumbing — same as rust-env.
    print_row_cstr(b"User", env_lookup(envp, b"USER").unwrap_or(b"root\0".as_ptr()));
    print_row_cstr(b"Home", env_lookup(envp, b"HOME").unwrap_or(b"/\0".as_ptr()));
    print_row_cstr(b"PATH", env_lookup(envp, b"PATH").unwrap_or(core::ptr::null()));
    print_row_cstr(b"Shell", env_lookup(envp, b"SHELL").unwrap_or(b"/bin/shell\0".as_ptr()));
    print_row_cstr(b"Term", env_lookup(envp, b"TERM").unwrap_or(b"vt100\0".as_ptr()));
    print_row_cstr(b"TZ Offset", env_lookup(envp, b"TZ_OFFSET_SEC").unwrap_or(b"0 (UTC)\0".as_ptr()));
    print_row_cstr(b"Wayland", env_lookup(envp, b"WAYLAND_DISPLAY").unwrap_or(b"(none)\0".as_ptr()));
    print_row_cstr(b"Runtime Dir", env_lookup(envp, b"XDG_RUNTIME_DIR").unwrap_or(b"/run\0".as_ptr()));

    write_str(STDOUT, b"\n");
    0
}
