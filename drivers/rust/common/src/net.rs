// SPDX-License-Identifier: MPL-2.0

#![allow(dead_code)]

use core::ffi::{c_char, c_void};

use crate::FutStatus;

#[repr(C)]
pub struct FutNetDevOps {
    pub tx: Option<
        unsafe extern "C" fn(dev: *mut FutNetDev, frame: *const c_void, len: usize) -> FutStatus,
    >,
}

#[repr(C)]
pub struct FutNetDev {
    pub name: *const c_char,
    pub mtu: u32,
    pub features: u32,
    pub driver_ctx: *mut c_void,
    pub ops: *const FutNetDevOps,
    pub handle: u64,
    pub next: *mut FutNetDev,
}

unsafe extern "C" {
    fn fut_net_register(dev: *mut FutNetDev) -> FutStatus;
    fn fut_net_rx(dev: *mut FutNetDev, frame: *const c_void, len: usize);
}

pub fn register(dev: &mut FutNetDev) -> Result<(), FutStatus> {
    let rc = unsafe { fut_net_register(dev as *mut FutNetDev) };
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

pub unsafe fn submit_rx(dev: *mut FutNetDev, frame: *const u8, len: usize) {
    unsafe { fut_net_rx(dev, frame.cast(), len) };
}
