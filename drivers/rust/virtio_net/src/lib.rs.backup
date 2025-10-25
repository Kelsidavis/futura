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
const EMSGSIZE: FutStatus = -90;

const FALLBACK_MTU: u32 = 1500;
const MAX_FRAME: usize = 2048;

#[cfg(debug_net)]
const DEBUG_TRACE: bool = true;
#[cfg(not(debug_net))]
const DEBUG_TRACE: bool = false;

static DEVICE_NAME: &[u8] = b"virtio-net0\0";

struct VirtioNetState {
    dev: FutNetDev,
    ops: FutNetDevOps,
    rx_buf: [u8; MAX_FRAME],
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
            ops: FutNetDevOps { tx: None, irq_ack: None },
            rx_buf: [0u8; MAX_FRAME],
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

    let state = unsafe { &mut *((*dev).driver_ctx as *mut VirtioNetState) };
    let mtu = unsafe { (*dev).mtu as usize };
    if mtu > 0 && len > mtu {
        return EMSGSIZE;
    }
    if len > state.rx_buf.len() {
        return EMSGSIZE;
    }

    if DEBUG_TRACE {
        log("virtio-net: tx -> loopback");
    }

    unsafe {
        core::ptr::copy_nonoverlapping(frame as *const u8, state.rx_buf.as_mut_ptr(), len);
        net::submit_rx(dev, state.rx_buf.as_ptr(), len);
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
        state.ops = FutNetDevOps {
            tx: Some(tx),
            irq_ack: None,
        };
        state.dev = FutNetDev {
            name: DEVICE_NAME.as_ptr() as *const i8,
            mtu: FALLBACK_MTU,
            features: 0,
            driver_ctx: state as *mut _ as *mut c_void,
            ops: &state.ops,
            handle: 0,
            next: ptr::null_mut(),
        };

        match initialise_hardware(state) {
            Ok(()) => {
                DEVICE.ready.store(true, Ordering::SeqCst);
                log("virtio-net: initialized OK");
                0
            }
            Err(err) => err,
        }
    }
}

fn initialise_hardware(state: &mut VirtioNetState) -> Result<(), FutStatus> {
    match net::register(&mut state.dev) {
        Ok(()) => {
            if DEBUG_TRACE {
                log("virtio-net: using software loopback fallback");
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}
