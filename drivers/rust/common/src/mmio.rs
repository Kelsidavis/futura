// SPDX-License-Identifier: MPL-2.0
#![allow(dead_code)]

use core::ffi::c_void;

unsafe extern "C" {
    fn fut_kernel_map_physical(paddr: u64, size: usize, flags: u64) -> *mut c_void;
    fn fut_kernel_unmap(vaddr: *mut c_void, size: usize);
}

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_NX: u64 = 1 << 63;

pub const MMIO_DEFAULT_FLAGS: u64 =
    PTE_PRESENT | PTE_WRITABLE | PTE_CACHE_DISABLE | PTE_WRITE_THROUGH | PTE_NX;

pub unsafe fn map_mmio_region(paddr: u64, size: usize, flags: u64) -> *mut u8 {
    unsafe { fut_kernel_map_physical(paddr, size, flags) as *mut u8 }
}

pub unsafe fn unmap_mmio_region(vaddr: *mut u8, size: usize) {
    if !vaddr.is_null() && size != 0 {
        unsafe { fut_kernel_unmap(vaddr.cast(), size); }
    }
}
