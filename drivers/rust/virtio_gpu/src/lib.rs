// SPDX-License-Identifier: MPL-2.0
/*
 * virtio_gpu - ARM64 virtio-gpu driver using virtio-mmio transport
 *
 * Implements virtio-gpu protocol over virtio-mmio for ARM64 platform.
 * Provides framebuffer initialization and display output.
 */

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use common::{log, SpinLock};

/* virtio-mmio register offsets (from virtio v1.0 spec) */
const MMIO_MAGIC_VALUE: usize = 0x000;
const MMIO_VERSION: usize = 0x004;
const MMIO_DEVICE_ID: usize = 0x008;
const MMIO_VENDOR_ID: usize = 0x00c;
const MMIO_DEVICE_FEATURES: usize = 0x010;
const MMIO_DEVICE_FEATURES_SEL: usize = 0x014;
const MMIO_DRIVER_FEATURES: usize = 0x020;
const MMIO_DRIVER_FEATURES_SEL: usize = 0x024;
const MMIO_QUEUE_SEL: usize = 0x030;
const MMIO_QUEUE_NUM_MAX: usize = 0x034;
const MMIO_QUEUE_NUM: usize = 0x038;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_INTERRUPT_STATUS: usize = 0x060;
const MMIO_INTERRUPT_ACK: usize = 0x064;
const MMIO_STATUS: usize = 0x070;
const MMIO_QUEUE_DESC_LOW: usize = 0x080;
const MMIO_QUEUE_DESC_HIGH: usize = 0x084;
const MMIO_QUEUE_DRIVER_LOW: usize = 0x090;
const MMIO_QUEUE_DRIVER_HIGH: usize = 0x094;
const MMIO_QUEUE_DEVICE_LOW: usize = 0x0a0;
const MMIO_QUEUE_DEVICE_HIGH: usize = 0x0a4;

/* virtio status bits */
const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
const VIRTIO_STATUS_DRIVER: u32 = 2;
const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_STATUS_FEATURES_OK: u32 = 8;

/* virtio-gpu command types */
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0110;

/* virtio-gpu format */
const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;

/* virtio ring constants */
const VIRTIO_RING_SIZE: usize = 256;
const RESOURCE_ID_FB: u32 = 1;
const SCANOUT_ID: u32 = 0;

/* virtqueue descriptor flags */
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/* virtio-gpu protocol structures */
#[repr(C, packed)]
struct VirtioGpuCtrlHdr {
    type_: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
    padding: [u8; 3],
}

#[repr(C, packed)]
struct VirtioGpuResourceCreate2D {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C, packed)]
struct VirtioGpuMemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

#[repr(C, packed)]
struct VirtioGpuResourceAttachBacking {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    nr_entries: u32,
    entry: VirtioGpuMemEntry,
}

#[repr(C, packed)]
struct VirtioGpuRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C, packed)]
struct VirtioGpuSetScanout {
    hdr: VirtioGpuCtrlHdr,
    r: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C, packed)]
struct VirtioGpuTransferToHost2D {
    hdr: VirtioGpuCtrlHdr,
    offset: u64,
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    resource_id: u32,
    padding: u32,
}

#[repr(C, packed)]
struct VirtioGpuResourceFlush {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

/* virtqueue structures */
#[repr(C, packed)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; VIRTIO_RING_SIZE],
    used_event: u16,
}

#[repr(C, packed)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; VIRTIO_RING_SIZE],
    avail_event: u16,
}

/* Device state */
struct VirtioGpuDevice {
    mmio_base: *mut u8,
    desc_table: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    cmd_buffer: *mut u8,
    resp_buffer: *mut u8,
    framebuffer: *mut u8,
    fb_phys: u64,
    fb_size: usize,
    width: u32,
    height: u32,
    cmd_idx: u16,
}

unsafe impl Send for VirtioGpuDevice {}

static DEVICE: SpinLock<Option<VirtioGpuDevice>> = SpinLock::new(None);

/* MMIO access helpers with ARM64 memory barriers */
#[inline(always)]
unsafe fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u32) };
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn mmio_write32(base: *mut u8, offset: usize, value: u32) {
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u32, value); }
    unsafe { core::arch::asm!("dsb sy"); }
}

/* FFI declarations for kernel functions */
unsafe extern "C" {
    fn fut_log(msg: *const u8);
    fn fut_pmm_alloc_page() -> *mut c_void;
    fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
    fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
}

impl VirtioGpuDevice {
    unsafe fn new(mmio_base: *mut u8, width: u32, height: u32) -> Option<Self> {
        /* Verify virtio-mmio magic value */
        let magic = unsafe { mmio_read32(mmio_base, MMIO_MAGIC_VALUE) };
        if magic != 0x74726976 {
            log("[VIRTIO-GPU] Invalid magic value\n");
            return None;
        }

        /* Verify virtio-mmio version (should be 2) */
        let version = unsafe { mmio_read32(mmio_base, MMIO_VERSION) };
        if version != 2 {
            log("[VIRTIO-GPU] Unsupported virtio-mmio version\n");
            return None;
        }

        /* Verify device ID (16 = GPU) */
        let device_id = unsafe { mmio_read32(mmio_base, MMIO_DEVICE_ID) };
        if device_id != 16 {
            log("[VIRTIO-GPU] Not a GPU device\n");
            return None;
        }

        log("[VIRTIO-GPU] Found virtio-gpu device via virtio-mmio\n");

        Some(VirtioGpuDevice {
            mmio_base,
            desc_table: core::ptr::null_mut(),
            avail: core::ptr::null_mut(),
            used: core::ptr::null_mut(),
            cmd_buffer: core::ptr::null_mut(),
            resp_buffer: core::ptr::null_mut(),
            framebuffer: core::ptr::null_mut(),
            fb_phys: 0,
            fb_size: 0,
            width,
            height,
            cmd_idx: 0,
        })
    }

    unsafe fn init_device(&mut self) -> Result<(), ()> {
        /* Reset device */
        unsafe { mmio_write32(self.mmio_base, MMIO_STATUS, 0); }

        /* Set ACKNOWLEDGE */
        unsafe { mmio_write32(self.mmio_base, MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE); }

        /* Set DRIVER */
        let mut status = unsafe { mmio_read32(self.mmio_base, MMIO_STATUS) };
        status |= VIRTIO_STATUS_DRIVER;
        unsafe { mmio_write32(self.mmio_base, MMIO_STATUS, status); }

        /* Negotiate features - read device features */
        unsafe { mmio_write32(self.mmio_base, MMIO_DEVICE_FEATURES_SEL, 0); }
        let features_lo = unsafe { mmio_read32(self.mmio_base, MMIO_DEVICE_FEATURES) };
        unsafe { mmio_write32(self.mmio_base, MMIO_DEVICE_FEATURES_SEL, 1); }
        let _features_hi = unsafe { mmio_read32(self.mmio_base, MMIO_DEVICE_FEATURES) };

        log("[VIRTIO-GPU] Device features read\n");

        /* Write features we understand (accept all lower 32 bits) */
        unsafe { mmio_write32(self.mmio_base, MMIO_DRIVER_FEATURES_SEL, 0); }
        unsafe { mmio_write32(self.mmio_base, MMIO_DRIVER_FEATURES, features_lo); }
        unsafe { mmio_write32(self.mmio_base, MMIO_DRIVER_FEATURES_SEL, 1); }
        unsafe { mmio_write32(self.mmio_base, MMIO_DRIVER_FEATURES, 0); }

        /* Set FEATURES_OK */
        status = unsafe { mmio_read32(self.mmio_base, MMIO_STATUS) };
        status |= VIRTIO_STATUS_FEATURES_OK;
        unsafe { mmio_write32(self.mmio_base, MMIO_STATUS, status); }

        /* Verify FEATURES_OK */
        status = unsafe { mmio_read32(self.mmio_base, MMIO_STATUS) };
        if (status & VIRTIO_STATUS_FEATURES_OK) == 0 {
            log("[VIRTIO-GPU] Features rejected\n");
            return Err(());
        }

        log("[VIRTIO-GPU] Features negotiated\n");
        Ok(())
    }

    unsafe fn alloc_queues(&mut self) -> Result<(), ()> {
        /* Allocate physical pages for virtqueue structures */
        let desc_page = unsafe { fut_pmm_alloc_page() as *mut VirtqDesc };
        let avail_page = unsafe { fut_pmm_alloc_page() as *mut VirtqAvail };
        let used_page = unsafe { fut_pmm_alloc_page() as *mut VirtqUsed };

        if desc_page.is_null() || avail_page.is_null() || used_page.is_null() {
            log("[VIRTIO-GPU] Failed to allocate queue pages\n");
            return Err(());
        }

        self.desc_table = desc_page;
        self.avail = avail_page;
        self.used = used_page;

        /* Zero out queue structures */
        unsafe { memset(desc_page as *mut c_void, 0, 4096); }
        unsafe { memset(avail_page as *mut c_void, 0, 4096); }
        unsafe { memset(used_page as *mut c_void, 0, 4096); }

        /* ARM64 uses physical addressing since MMU is disabled */
        let desc_phys = desc_page as u64;
        let avail_phys = avail_page as u64;
        let used_phys = used_page as u64;

        /* Select queue 0 (control queue) */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_SEL, 0); }

        /* Check max queue size */
        let max_queue_size = unsafe { mmio_read32(self.mmio_base, MMIO_QUEUE_NUM_MAX) };
        if max_queue_size < VIRTIO_RING_SIZE as u32 {
            log("[VIRTIO-GPU] Queue size too small\n");
            return Err(());
        }

        /* Set queue size */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_NUM, VIRTIO_RING_SIZE as u32); }

        /* Set descriptor table address */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_DESC_LOW, (desc_phys & 0xFFFFFFFF) as u32); }
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_DESC_HIGH, (desc_phys >> 32) as u32); }

        /* Set available ring address */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_DRIVER_LOW, (avail_phys & 0xFFFFFFFF) as u32); }
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_DRIVER_HIGH, (avail_phys >> 32) as u32); }

        /* Set used ring address */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_DEVICE_LOW, (used_phys & 0xFFFFFFFF) as u32); }
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_DEVICE_HIGH, (used_phys >> 32) as u32); }

        /* Enable queue */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_READY, 1); }

        log("[VIRTIO-GPU] Queue configured\n");
        Ok(())
    }

    unsafe fn alloc_buffers(&mut self) -> Result<(), ()> {
        /* Allocate command buffer */
        let cmd_page = unsafe { fut_pmm_alloc_page() as *mut u8 };
        if cmd_page.is_null() {
            log("[VIRTIO-GPU] Failed to allocate command buffer\n");
            return Err(());
        }
        self.cmd_buffer = cmd_page;
        unsafe { memset(cmd_page as *mut c_void, 0, 4096); }

        /* Allocate response buffer */
        let resp_page = unsafe { fut_pmm_alloc_page() as *mut u8 };
        if resp_page.is_null() {
            log("[VIRTIO-GPU] Failed to allocate response buffer\n");
            return Err(());
        }
        self.resp_buffer = resp_page;
        unsafe { memset(resp_page as *mut c_void, 0, 4096); }

        /* Allocate framebuffer (multiple pages for large displays) */
        self.fb_size = (self.width * self.height * 4) as usize;
        let num_pages = (self.fb_size + 4095) / 4096;

        /* Allocate first page */
        let fb_page = unsafe { fut_pmm_alloc_page() as *mut u8 };
        if fb_page.is_null() {
            log("[VIRTIO-GPU] Failed to allocate framebuffer\n");
            return Err(());
        }

        self.framebuffer = fb_page;
        self.fb_phys = fb_page as u64;

        /* Zero framebuffer pages */
        for i in 0..num_pages {
            let page_addr = unsafe { self.framebuffer.add(i * 4096) };
            unsafe { memset(page_addr as *mut c_void, 0, 4096); }
        }

        log("[VIRTIO-GPU] Buffers allocated\n");
        Ok(())
    }

    unsafe fn submit_command(&mut self, cmd: *const u8, cmd_size: usize) {
        /* Copy command to buffer */
        unsafe { memcpy(self.cmd_buffer as *mut c_void, cmd as *const c_void, cmd_size); }

        /* Clear response */
        unsafe { memset(self.resp_buffer as *mut c_void, 0, 4096); }

        /* Create descriptor chain */
        let cmd_desc_idx = (self.cmd_idx * 2) % VIRTIO_RING_SIZE as u16;
        let resp_desc_idx = (self.cmd_idx * 2 + 1) % VIRTIO_RING_SIZE as u16;

        /* Command descriptor */
        unsafe {
            let desc = &mut *self.desc_table.add(cmd_desc_idx as usize);
            desc.addr = self.cmd_buffer as u64;
            desc.len = cmd_size as u32;
            desc.flags = VIRTQ_DESC_F_NEXT;
            desc.next = resp_desc_idx;
        }

        /* Response descriptor */
        unsafe {
            let desc = &mut *self.desc_table.add(resp_desc_idx as usize);
            desc.addr = self.resp_buffer as u64;
            desc.len = 4096;
            desc.flags = VIRTQ_DESC_F_WRITE;
            desc.next = 0;
        }

        /* Add to available ring */
        unsafe {
            let avail_idx = ((*self.avail).idx % VIRTIO_RING_SIZE as u16) as usize;
            (*self.avail).ring[avail_idx] = cmd_desc_idx;
            unsafe { core::arch::asm!("dsb sy"); }
            (*self.avail).idx = (*self.avail).idx.wrapping_add(1);
            unsafe { core::arch::asm!("dsb sy"); }
        }

        /* Notify device */
        unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_NOTIFY, 0); }

        /* Wait for response */
        let last_used_idx = unsafe { (*self.used).idx };
        let mut timeout = 1000000;
        while unsafe { (*self.used).idx } == last_used_idx && timeout > 0 {
            unsafe { core::arch::asm!("dsb sy"); }
            timeout -= 1;
        }

        self.cmd_idx = self.cmd_idx.wrapping_add(1);
    }

    unsafe fn init_display(&mut self) {
        log("[VIRTIO-GPU] Initializing display\n");

        /* Fill framebuffer with white for test pattern */
        let pixels = (self.width * self.height) as usize;
        let fb = self.framebuffer as *mut u32;
        for i in 0..pixels {
            unsafe { write_volatile(fb.add(i), 0xFFFFFFFF); }
        }

        /* Create 2D resource */
        let create_cmd = VirtioGpuResourceCreate2D {
            hdr: VirtioGpuCtrlHdr {
                type_: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            resource_id: RESOURCE_ID_FB,
            format: VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
            width: self.width,
            height: self.height,
        };
        unsafe { self.submit_command(&create_cmd as *const _ as *const u8, core::mem::size_of_val(&create_cmd)); }

        /* Attach backing memory */
        let attach_cmd = VirtioGpuResourceAttachBacking {
            hdr: VirtioGpuCtrlHdr {
                type_: VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            resource_id: RESOURCE_ID_FB,
            nr_entries: 1,
            entry: VirtioGpuMemEntry {
                addr: self.fb_phys,
                length: self.fb_size as u32,
                padding: 0,
            },
        };
        unsafe { self.submit_command(&attach_cmd as *const _ as *const u8, core::mem::size_of_val(&attach_cmd)); }

        /* Set scanout */
        let scanout_cmd = VirtioGpuSetScanout {
            hdr: VirtioGpuCtrlHdr {
                type_: VIRTIO_GPU_CMD_SET_SCANOUT,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            r: VirtioGpuRect {
                x: 0,
                y: 0,
                width: self.width,
                height: self.height,
            },
            scanout_id: SCANOUT_ID,
            resource_id: RESOURCE_ID_FB,
        };
        unsafe { self.submit_command(&scanout_cmd as *const _ as *const u8, core::mem::size_of_val(&scanout_cmd)); }

        /* Transfer to host */
        let transfer_cmd = VirtioGpuTransferToHost2D {
            hdr: VirtioGpuCtrlHdr {
                type_: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            offset: 0,
            width: self.width,
            height: self.height,
            x: 0,
            y: 0,
            resource_id: RESOURCE_ID_FB,
            padding: 0,
        };
        unsafe { self.submit_command(&transfer_cmd as *const _ as *const u8, core::mem::size_of_val(&transfer_cmd)); }

        /* Flush to display */
        let flush_cmd = VirtioGpuResourceFlush {
            hdr: VirtioGpuCtrlHdr {
                type_: VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            resource_id: RESOURCE_ID_FB,
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        };
        unsafe { self.submit_command(&flush_cmd as *const _ as *const u8, core::mem::size_of_val(&flush_cmd)); }

        /* Set DRIVER_OK */
        let mut status = unsafe { mmio_read32(self.mmio_base, MMIO_STATUS) };
        status |= VIRTIO_STATUS_DRIVER_OK;
        unsafe { mmio_write32(self.mmio_base, MMIO_STATUS, status); }

        log("[VIRTIO-GPU] Display initialized\n");
    }
}

/* FFI exports for C kernel code */
#[unsafe(no_mangle)]
pub extern "C" fn virtio_gpu_init_arm64(
    mmio_base: u64,
    out_fb_phys: *mut u64,
    width: u32,
    height: u32,
) -> i32 {
    log("[VIRTIO-GPU] ARM64 virtio-gpu driver starting\n");

    let dev = unsafe { VirtioGpuDevice::new(mmio_base as *mut u8, width, height) };
    if dev.is_none() {
        log("[VIRTIO-GPU] Device initialization failed\n");
        return -1;
    }

    let mut dev = dev.unwrap();

    if unsafe { dev.init_device().is_err() } {
        log("[VIRTIO-GPU] Device setup failed\n");
        return -1;
    }

    if unsafe { dev.alloc_queues().is_err() } {
        log("[VIRTIO-GPU] Queue allocation failed\n");
        return -1;
    }

    if unsafe { dev.alloc_buffers().is_err() } {
        log("[VIRTIO-GPU] Buffer allocation failed\n");
        return -1;
    }

    unsafe { dev.init_display(); }

    /* Return framebuffer address */
    if !out_fb_phys.is_null() {
        unsafe { *out_fb_phys = dev.fb_phys; }
    }

    /* Store device state */
    DEVICE.with(|slot| *slot = Some(dev));

    log("[VIRTIO-GPU] ARM64 driver initialized successfully\n");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn virtio_gpu_flush_arm64() {
    DEVICE.with(|dev_opt| {
        if let Some(dev) = dev_opt {
            /* Transfer and flush */
            let transfer_cmd = VirtioGpuTransferToHost2D {
                hdr: VirtioGpuCtrlHdr {
                    type_: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
                    flags: 0,
                    fence_id: 0,
                    ctx_id: 0,
                    ring_idx: 0,
                    padding: [0; 3],
                },
                offset: 0,
                width: dev.width,
                height: dev.height,
                x: 0,
                y: 0,
                resource_id: RESOURCE_ID_FB,
                padding: 0,
            };
            unsafe {
                let dev_mut = dev as *const VirtioGpuDevice as *mut VirtioGpuDevice;
                (*dev_mut).submit_command(&transfer_cmd as *const _ as *const u8, core::mem::size_of_val(&transfer_cmd));
            }

            let flush_cmd = VirtioGpuResourceFlush {
                hdr: VirtioGpuCtrlHdr {
                    type_: VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                    flags: 0,
                    fence_id: 0,
                    ctx_id: 0,
                    ring_idx: 0,
                    padding: [0; 3],
                },
                resource_id: RESOURCE_ID_FB,
                x: 0,
                y: 0,
                width: dev.width,
                height: dev.height,
            };
            unsafe {
                let dev_mut = dev as *const VirtioGpuDevice as *mut VirtioGpuDevice;
                (*dev_mut).submit_command(&flush_cmd as *const _ as *const u8, core::mem::size_of_val(&flush_cmd));
            }
        }
    });
}
