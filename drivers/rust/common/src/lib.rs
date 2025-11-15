// SPDX-License-Identifier: MPL-2.0
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

pub mod mmio;
pub mod net;
pub mod transport;

pub type FutStatus = i32;

pub const FUT_BLK_READ: u32 = 1 << 0;
pub const FUT_BLK_WRITE: u32 = 1 << 1;
pub const FUT_BLK_ADMIN: u32 = 1 << 2;

unsafe extern "C" {
    fn fut_log(msg: *const c_char);
    fn fut_alloc(size: usize) -> *mut c_void;
    fn fut_free(ptr: *mut c_void);
    fn fut_blk_register(dev: *mut FutBlkDev) -> FutStatus;
    fn fut_pmm_alloc_page() -> *mut c_void;
    fn fut_pmm_free_page(ptr: *mut c_void);
    fn fut_thread_yield();
}

#[repr(C)]
pub struct FutBlkBackend {
    pub read: Option<unsafe extern "C" fn(ctx: *mut c_void, lba: u64, nsectors: usize, buf: *mut c_void) -> FutStatus>,
    pub write: Option<unsafe extern "C" fn(ctx: *mut c_void, lba: u64, nsectors: usize, buf: *const c_void) -> FutStatus>,
    pub flush: Option<unsafe extern "C" fn(ctx: *mut c_void) -> FutStatus>,
}

#[repr(C)]
pub struct FutBlkDev {
    pub name: *const c_char,
    pub block_size: u32,
    pub block_count: u64,
    pub allowed_rights: u32,
    pub backend: *const FutBlkBackend,
    pub backend_ctx: *mut c_void,
    pub core: *mut c_void,
}

#[repr(C)]
pub struct FutBio {
    pub lba: u64,
    pub nsectors: usize,
    pub buf: *mut c_void,
    pub write: bool,
    pub on_complete: Option<unsafe extern "C" fn(this: *mut FutBio, status: FutStatus, bytes: usize)>,
}

pub fn log(msg: &str) {
    let mut buffer = [0u8; 256];
    let bytes = msg.as_bytes();
    let len = bytes.len().min(buffer.len() - 1);
    buffer[..len].copy_from_slice(&bytes[..len]);
    buffer[len] = 0;
    unsafe {
        fut_log(buffer.as_ptr() as *const c_char);
    }
}

pub fn register(dev: &mut FutBlkDev) -> Result<(), FutStatus> {
    let status = unsafe { fut_blk_register(dev as *mut FutBlkDev) };
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

pub unsafe fn alloc(size: usize) -> *mut u8 {
    unsafe { fut_alloc(size) as *mut u8 }
}

pub unsafe fn free(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { fut_free(ptr.cast()); }
    }
}

pub unsafe fn alloc_page() -> *mut u8 {
    unsafe { fut_pmm_alloc_page() as *mut u8 }
}

pub unsafe fn free_page(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { fut_pmm_free_page(ptr.cast()); }
    }
}

pub fn thread_yield() {
    unsafe { fut_thread_yield(); }
}

pub struct RawSpinLock {
    flag: AtomicBool,
}

impl RawSpinLock {
    pub const fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
        }
    }

    pub fn lock(&self) {
        while self.flag.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.flag.store(false, Ordering::Release);
    }
}

pub struct SpinLock<T> {
    lock: RawSpinLock,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            lock: RawSpinLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.lock.lock();
        let res = unsafe { f(&mut *self.value.get()) };
        self.lock.unlock();
        res
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log("rust panic");
    loop {
        core::hint::spin_loop();
    }
}

pub use mmio::{map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};
