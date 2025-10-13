// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![allow(unexpected_cfgs)]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use common::net::{self, FutNetDev, FutNetDevOps};
use common::{log, FutStatus};

const EINVAL: FutStatus = -22;

#[cfg(debug_net)]
const DEBUG_TRACE: bool = true;
#[cfg(not(debug_net))]
const DEBUG_TRACE: bool = false;

static DEVICE_NAME: &[u8] = b"net0\0";

struct VirtioNetState {
    dev: FutNetDev,
    ops: FutNetDevOps,
}

impl VirtioNetState {
    const fn uninit() -> Self {
        Self {
            dev: FutNetDev {
                name: ptr::null(),
                mtu: 0,
                features: 0,
                driver_ctx: ptr::null_mut(),
                ops: ptr::null(),
                handle: 0,
                next: ptr::null_mut(),
            },
            ops: FutNetDevOps { tx: None },
        }
    }
}

struct Holder {
    ready: AtomicBool,
    state: UnsafeCell<VirtioNetState>,
}

unsafe impl Sync for Holder {}

impl Holder {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            state: UnsafeCell::new(VirtioNetState::uninit()),
        }
    }
}

static DEVICE: Holder = Holder::new();

unsafe extern "C" fn tx(dev: *mut FutNetDev, frame: *const c_void, len: usize) -> FutStatus {
    if frame.is_null() || len == 0 {
        return EINVAL;
    }

    if DEBUG_TRACE {
        log("virtio-net: tx -> loopback");
    }

    unsafe {
        net::submit_rx(dev, frame.cast::<u8>(), len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn virtio_net_init() -> FutStatus {
    if DEVICE.ready.load(Ordering::SeqCst) {
        return 0;
    }

    unsafe {
        let state = &mut *DEVICE.state.get();
        state.ops = FutNetDevOps { tx: Some(tx) };
        state.dev = FutNetDev {
            name: DEVICE_NAME.as_ptr() as *const i8,
            mtu: 1500,
            features: 0,
            driver_ctx: state as *mut _ as *mut c_void,
            ops: &state.ops,
            handle: 0,
            next: ptr::null_mut(),
        };

        match net::register(&mut state.dev) {
            Ok(()) => {
                DEVICE.ready.store(true, Ordering::SeqCst);
                log("virtio-net: initialized OK");
                0
            }
            Err(err) => err,
        }
    }
}
