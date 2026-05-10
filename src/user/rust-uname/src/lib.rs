// SPDX-License-Identifier: MPL-2.0
//
// rust-uname — second user-space Rust program for Futura OS.
//
// Reads kernel/system identification via the uname(2) syscall and prints
// the canonical "uname -a" formatted line. Exercises a richer slice of
// the syscall ABI than rust-hello (uname returns a struct via pointer)
// while staying small enough to keep the build fast.
//
// Output format:  "<sysname> <nodename> <release> <version> <machine>"
//
// The crt0_arm64.S / crt0.S entry stub calls main(), so we expose
// #[unsafe(no_mangle)] pub extern "C" fn main(...) the same way
// rust-hello does.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

/// Linux/Futura syscall numbers. Match include/user/sysnums.h.
#[cfg(target_arch = "aarch64")]
const SYS_WRITE: u64 = 64;
#[cfg(target_arch = "aarch64")]
const SYS_EXIT: u64 = 93;
#[cfg(target_arch = "aarch64")]
const SYS_UNAME: u64 = 160;

#[cfg(target_arch = "x86_64")]
const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: u64 = 60;
#[cfg(target_arch = "x86_64")]
const SYS_UNAME: u64 = 63;

/// Linux struct utsname — six 65-byte fields (sysname, nodename, release,
/// version, machine, domainname). Total 390 bytes.
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
            in("x8") SYS_EXIT,
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
unsafe fn sys_exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

fn write_str(fd: i32, s: &[u8]) {
    // Best effort — short writes ignored in this small utility.
    unsafe {
        let _ = syscall3(SYS_WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

/// Length of a NUL-terminated field, capped at the field size.
fn field_len(field: &[u8]) -> usize {
    let mut n = 0;
    while n < field.len() && field[n] != 0 {
        n += 1;
    }
    n
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(2, b"[rust-uname] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Bitset of selected fields (GNU uname order).
    const F_SYS:  u32 = 1 << 0;  // -s (sysname)
    const F_NODE: u32 = 1 << 1;  // -n (nodename)
    const F_REL:  u32 = 1 << 2;  // -r (release)
    const F_VER:  u32 = 1 << 3;  // -v (version)
    const F_MACH: u32 = 1 << 4;  // -m (machine)
    const F_PROC: u32 = 1 << 5;  // -p (processor)
    const F_PLAT: u32 = 1 << 6;  // -i (hardware-platform)
    const F_OS:   u32 = 1 << 7;  // -o (operating system)
    const F_ALL:  u32 = F_SYS | F_NODE | F_REL | F_VER | F_MACH;

    let mut want: u32 = 0;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        let mut n = 0; unsafe { while *p.add(n) != 0 { n += 1; } }
        let s = unsafe { core::slice::from_raw_parts(p, n) };
        if s == b"--help" {
            let help: &[u8] = b"\
Usage: rust-uname [OPTION]...
Print system information from uname(2).

  -a, --all                 all fields except domainname
  -s, --kernel-name         kernel name (default)
  -n, --nodename            network node hostname
  -r, --kernel-release      kernel release
  -v, --kernel-version      kernel version
  -m, --machine             machine hardware name
  -p, --processor           processor type (or 'unknown')
  -i, --hardware-platform   hardware platform (or 'unknown')
  -o, --operating-system    operating system
      --help                show this help and exit

With no flag, equivalent to -s.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(SYS_WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if s == b"-a" || s == b"--all" {
            want |= F_ALL;
            idx += 1;
            continue;
        }
        if s == b"-s" || s == b"--kernel-name" { want |= F_SYS;  idx += 1; continue; }
        if s == b"-n" || s == b"--nodename"    { want |= F_NODE; idx += 1; continue; }
        if s == b"-r" || s == b"--kernel-release" { want |= F_REL; idx += 1; continue; }
        if s == b"-v" || s == b"--kernel-version" { want |= F_VER; idx += 1; continue; }
        if s == b"-m" || s == b"--machine"     { want |= F_MACH; idx += 1; continue; }
        if s == b"-p" || s == b"--processor"   { want |= F_PROC; idx += 1; continue; }
        if s == b"-i" || s == b"--hardware-platform" { want |= F_PLAT; idx += 1; continue; }
        if s == b"-o" || s == b"--operating-system"  { want |= F_OS;   idx += 1; continue; }
        // Combined short flags: -snrvm etc.
        if n >= 2 && s[0] == b'-' && s[1] != b'-' {
            let mut all_ok = true;
            for i in 1..n {
                match s[i] {
                    b'a' => want |= F_ALL,
                    b's' => want |= F_SYS,
                    b'n' => want |= F_NODE,
                    b'r' => want |= F_REL,
                    b'v' => want |= F_VER,
                    b'm' => want |= F_MACH,
                    b'p' => want |= F_PROC,
                    b'i' => want |= F_PLAT,
                    b'o' => want |= F_OS,
                    _ => { all_ok = false; break; }
                }
            }
            if all_ok { idx += 1; continue; }
        }
        break;
    }
    if want == 0 { want = F_SYS; }

    // Zero-initialize so any field the kernel doesn't write stays NUL.
    let mut uts = Utsname {
        sysname: [0; UTS_LEN],
        nodename: [0; UTS_LEN],
        release: [0; UTS_LEN],
        version: [0; UTS_LEN],
        machine: [0; UTS_LEN],
        domainname: [0; UTS_LEN],
    };

    let rc = unsafe { syscall1(SYS_UNAME, &mut uts as *mut Utsname as u64) };
    if rc < 0 {
        write_str(2, b"rust-uname: uname() failed\n");
        return 1;
    }

    let sys  = &uts.sysname[..field_len(&uts.sysname)];
    let node = &uts.nodename[..field_len(&uts.nodename)];
    let rel  = &uts.release[..field_len(&uts.release)];
    let ver  = &uts.version[..field_len(&uts.version)];
    let mach = &uts.machine[..field_len(&uts.machine)];
    // -p / -i don't have a kernel-side source; GNU prints "unknown".
    // -o is the userspace-vendor name; we use "Futura".
    let proc_name: &[u8] = b"unknown";
    let plat_name: &[u8] = b"unknown";
    let os_name: &[u8]   = b"Futura";

    let fields: [(u32, &[u8]); 8] = [
        (F_SYS,  sys),
        (F_NODE, node),
        (F_REL,  rel),
        (F_VER,  ver),
        (F_MACH, mach),
        (F_PROC, proc_name),
        (F_PLAT, plat_name),
        (F_OS,   os_name),
    ];
    let mut printed_any = false;
    for (mask, val) in fields.iter() {
        if want & mask == 0 { continue; }
        if printed_any { write_str(1, b" "); }
        if val.is_empty() {
            write_str(1, b"-");
        } else {
            write_str(1, val);
        }
        printed_any = true;
    }
    write_str(1, b"\n");
    0
}
