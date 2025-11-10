// SPDX-License-Identifier: MPL-2.0
/*
 * virtio_gpu - ARM64 virtio-gpu driver using virtio-pci transport
 *
 * Implements virtio-gpu protocol over virtio-pci for ARM64 platform.
 * Provides framebuffer initialization and display output.
 */

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use common::{log, SpinLock};

/* PCI capability types (virtio 1.0 spec) */
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
const PCI_CAP_ID_VNDR: u8 = 0x09;

/* Virtio 1.0 common configuration structure offsets */
const VIRTIO_PCI_COMMON_DFSELECT: usize = 0x00;
const VIRTIO_PCI_COMMON_DF: usize = 0x04;
const VIRTIO_PCI_COMMON_GFSELECT: usize = 0x08;
const VIRTIO_PCI_COMMON_GF: usize = 0x0c;
const VIRTIO_PCI_COMMON_STATUS: usize = 0x14;
const VIRTIO_PCI_COMMON_Q_SELECT: usize = 0x16;
const VIRTIO_PCI_COMMON_Q_SIZE: usize = 0x18;
const VIRTIO_PCI_COMMON_Q_ENABLE: usize = 0x1c;
const VIRTIO_PCI_COMMON_Q_DESCLO: usize = 0x20;
const VIRTIO_PCI_COMMON_Q_DESCHI: usize = 0x24;
const VIRTIO_PCI_COMMON_Q_AVAILLO: usize = 0x28;
const VIRTIO_PCI_COMMON_Q_AVAILHI: usize = 0x2c;
const VIRTIO_PCI_COMMON_Q_USEDLO: usize = 0x30;
const VIRTIO_PCI_COMMON_Q_USEDHI: usize = 0x34;

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
    bus: u8,
    dev: u8,
    func: u8,
    common_cfg: *mut u8,
    notify_base: *mut u8,
    isr_base: *mut u8,
    device_cfg: *mut u8,
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

/* PCI common config access helpers with ARM64 memory barriers */
#[inline(always)]
unsafe fn common_read8(base: *mut u8, offset: usize) -> u8 {
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u8) };
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn common_write8(base: *mut u8, offset: usize, value: u8) {
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u8, value); }
    unsafe { core::arch::asm!("dsb sy"); }
}

#[inline(always)]
unsafe fn common_read16(base: *mut u8, offset: usize) -> u16 {
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u16) };
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn common_write16(base: *mut u8, offset: usize, value: u16) {
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u16, value); }
    unsafe { core::arch::asm!("dsb sy"); }
}

#[inline(always)]
unsafe fn common_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u32) };
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn common_write32(base: *mut u8, offset: usize, value: u32) {
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u32, value); }
    unsafe { core::arch::asm!("dsb sy"); }
}

#[inline(always)]
unsafe fn common_write64(base: *mut u8, offset: usize, value: u64) {
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u64, value); }
    unsafe { core::arch::asm!("dsb sy"); }
}

/* FFI declarations for kernel functions */
unsafe extern "C" {
    fn fut_log(msg: *const u8);
    fn fut_pmm_alloc_page() -> *mut c_void;
    fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
    fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;

    /* ARM64 PCI ECAM functions */
    fn arm64_pci_read32(bus: u8, dev: u8, func: u8, reg: u16) -> u32;
    fn arm64_pci_read8(bus: u8, dev: u8, func: u8, reg: u16) -> u8;
}

impl VirtioGpuDevice {
    unsafe fn new(bus: u8, dev: u8, func: u8, width: u32, height: u32) -> Option<Self> {
        log("[VIRTIO-GPU] Creating device for PCI BDF\n");

        Some(VirtioGpuDevice {
            bus,
            dev,
            func,
            common_cfg: core::ptr::null_mut(),
            notify_base: core::ptr::null_mut(),
            isr_base: core::ptr::null_mut(),
            device_cfg: core::ptr::null_mut(),
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

    /* Scan PCI capabilities to find virtio 1.0 structures */
    unsafe fn scan_capabilities(&mut self) -> Result<(), ()> {
        log("[VIRTIO-GPU] Scanning PCI capabilities\n");

        /* Read capabilities pointer from offset 0x34 */
        let mut cap_ptr = unsafe { arm64_pci_read8(self.bus, self.dev, self.func, 0x34) };
        if cap_ptr == 0 {
            log("[VIRTIO-GPU] No PCI capabilities found\n");
            return Err(());
        }

        /* Track BAR addresses */
        let mut bar_addrs: [u64; 6] = [0; 6];

        /* Scan capability list */
        let mut cap_count = 0;
        while cap_ptr != 0 && cap_count < 32 {
            cap_count += 1;

            /* Read capability header */
            let cap_id = unsafe { arm64_pci_read8(self.bus, self.dev, self.func, cap_ptr as u16) };
            let cap_next = unsafe { arm64_pci_read8(self.bus, self.dev, self.func, (cap_ptr + 1) as u16) };

            /* Check for vendor-specific capability */
            if cap_id == PCI_CAP_ID_VNDR {
                let cfg_type = unsafe { arm64_pci_read8(self.bus, self.dev, self.func, (cap_ptr + 3) as u16) };
                let bar_idx = unsafe { arm64_pci_read8(self.bus, self.dev, self.func, (cap_ptr + 4) as u16) };
                let cap_offset = unsafe { arm64_pci_read32(self.bus, self.dev, self.func, (cap_ptr + 8) as u16) };

                if bar_idx < 6 {
                    /* Read BAR address if not already read */
                    if bar_addrs[bar_idx as usize] == 0 {
                        let bar_reg = 0x10 + (bar_idx as u16 * 4);
                        let bar_val = unsafe { arm64_pci_read32(self.bus, self.dev, self.func, bar_reg) };
                        if (bar_val & 0x1) == 0 {  /* MMIO BAR */
                            bar_addrs[bar_idx as usize] = (bar_val & !0xF) as u64;
                        }
                    }

                    /* Calculate virtual address for this capability */
                    if bar_addrs[bar_idx as usize] != 0 {
                        let virt_addr = (bar_addrs[bar_idx as usize] + cap_offset as u64) as *mut u8;

                        /* Store capability pointer */
                        match cfg_type {
                            VIRTIO_PCI_CAP_COMMON_CFG => {
                                self.common_cfg = virt_addr;
                                log("[VIRTIO-GPU] Found common config\n");
                            }
                            VIRTIO_PCI_CAP_NOTIFY_CFG => {
                                self.notify_base = virt_addr;
                                log("[VIRTIO-GPU] Found notify region\n");
                            }
                            VIRTIO_PCI_CAP_ISR_CFG => {
                                self.isr_base = virt_addr;
                                log("[VIRTIO-GPU] Found ISR region\n");
                            }
                            VIRTIO_PCI_CAP_DEVICE_CFG => {
                                self.device_cfg = virt_addr;
                                log("[VIRTIO-GPU] Found device config\n");
                            }
                            _ => {}
                        }
                    }
                }
            }

            cap_ptr = cap_next;
        }

        /* Verify essential structures found */
        if self.common_cfg.is_null() {
            log("[VIRTIO-GPU] ERROR: Common config not found\n");
            return Err(());
        }

        log("[VIRTIO-GPU] Capability scan complete\n");
        Ok(())
    }

    unsafe fn init_device(&mut self) -> Result<(), ()> {
        log("[VIRTIO-GPU] Initializing device\n");

        /* Set ACKNOWLEDGE */
        unsafe { common_write8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8); }

        /* Set DRIVER */
        let mut status = unsafe { common_read8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS) };
        status |= VIRTIO_STATUS_DRIVER as u8;
        unsafe { common_write8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS, status); }

        /* Negotiate features - read device features */
        unsafe { common_write32(self.common_cfg, VIRTIO_PCI_COMMON_DFSELECT, 0); }
        let features_lo = unsafe { common_read32(self.common_cfg, VIRTIO_PCI_COMMON_DF) };
        unsafe { common_write32(self.common_cfg, VIRTIO_PCI_COMMON_DFSELECT, 1); }
        let _features_hi = unsafe { common_read32(self.common_cfg, VIRTIO_PCI_COMMON_DF) };

        log("[VIRTIO-GPU] Device features read\n");

        /* Write features we understand (accept all lower 32 bits) */
        unsafe { common_write32(self.common_cfg, VIRTIO_PCI_COMMON_GFSELECT, 0); }
        unsafe { common_write32(self.common_cfg, VIRTIO_PCI_COMMON_GF, features_lo); }
        unsafe { common_write32(self.common_cfg, VIRTIO_PCI_COMMON_GFSELECT, 1); }
        unsafe { common_write32(self.common_cfg, VIRTIO_PCI_COMMON_GF, 0); }

        /* Set FEATURES_OK */
        status = unsafe { common_read8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS) };
        status |= VIRTIO_STATUS_FEATURES_OK as u8;
        unsafe { common_write8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS, status); }

        /* Verify FEATURES_OK */
        status = unsafe { common_read8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS) };
        if (status & VIRTIO_STATUS_FEATURES_OK as u8) == 0 {
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
        unsafe { common_write16(self.common_cfg, VIRTIO_PCI_COMMON_Q_SELECT, 0); }

        /* Set queue size */
        unsafe { common_write16(self.common_cfg, VIRTIO_PCI_COMMON_Q_SIZE, VIRTIO_RING_SIZE as u16); }

        /* Set descriptor table address (64-bit) */
        unsafe { common_write64(self.common_cfg, VIRTIO_PCI_COMMON_Q_DESCLO, desc_phys); }

        /* Set available ring address (64-bit) */
        unsafe { common_write64(self.common_cfg, VIRTIO_PCI_COMMON_Q_AVAILLO, avail_phys); }

        /* Set used ring address (64-bit) */
        unsafe { common_write64(self.common_cfg, VIRTIO_PCI_COMMON_Q_USEDLO, used_phys); }

        /* Enable queue */
        unsafe { common_write16(self.common_cfg, VIRTIO_PCI_COMMON_Q_ENABLE, 1); }

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

        /* Allocate all framebuffer pages contiguously */
        let fb_page = unsafe { fut_pmm_alloc_page() as *mut u8 };
        if fb_page.is_null() {
            log("[VIRTIO-GPU] Failed to allocate framebuffer page 0\n");
            return Err(());
        }

        self.framebuffer = fb_page;
        self.fb_phys = fb_page as u64;

        /* Allocate and zero remaining pages */
        for i in 0..num_pages {
            if i > 0 {
                /* Allocate additional pages */
                let page = unsafe { fut_pmm_alloc_page() as *mut u8 };
                if page.is_null() {
                    log("[VIRTIO-GPU] Failed to allocate framebuffer page\n");
                    return Err(());
                }

                /* Verify contiguous allocation */
                let expected_addr = (self.fb_phys as usize) + (i * 4096);
                if page as usize != expected_addr {
                    log("[VIRTIO-GPU] WARNING: Non-contiguous framebuffer allocation\n");
                }
            }

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
        let avail_idx = unsafe { ((*self.avail).idx % VIRTIO_RING_SIZE as u16) as usize };
        unsafe { (*self.avail).ring[avail_idx] = cmd_desc_idx; }
        unsafe { core::arch::asm!("dsb sy"); }
        unsafe { (*self.avail).idx = (*self.avail).idx.wrapping_add(1); }
        unsafe { core::arch::asm!("dsb sy"); }

        /* Notify device via notify region */
        if !self.notify_base.is_null() {
            unsafe { write_volatile(self.notify_base as *mut u16, 0); }
        }

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
        let mut status = unsafe { common_read8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS) };
        status |= VIRTIO_STATUS_DRIVER_OK as u8;
        unsafe { common_write8(self.common_cfg, VIRTIO_PCI_COMMON_STATUS, status); }

        log("[VIRTIO-GPU] Display initialized\n");
    }
}

/* FFI exports for C kernel code */
#[unsafe(no_mangle)]
pub extern "C" fn virtio_gpu_init_arm64_pci(
    bus: u8,
    dev: u8,
    func: u8,
    out_fb_phys: *mut u64,
    width: u32,
    height: u32,
) -> i32 {
    log("[VIRTIO-GPU] ARM64 virtio-gpu-pci driver starting\n");

    let device = unsafe { VirtioGpuDevice::new(bus, dev, func, width, height) };
    if device.is_none() {
        log("[VIRTIO-GPU] Device creation failed\n");
        return -1;
    }

    let mut device = device.unwrap();

    if unsafe { device.scan_capabilities().is_err() } {
        log("[VIRTIO-GPU] PCI capability scan failed\n");
        return -1;
    }

    if unsafe { device.init_device().is_err() } {
        log("[VIRTIO-GPU] Device setup failed\n");
        return -1;
    }

    if unsafe { device.alloc_queues().is_err() } {
        log("[VIRTIO-GPU] Queue allocation failed\n");
        return -1;
    }

    if unsafe { device.alloc_buffers().is_err() } {
        log("[VIRTIO-GPU] Buffer allocation failed\n");
        return -1;
    }

    unsafe { device.init_display(); }

    /* Return framebuffer address */
    if !out_fb_phys.is_null() {
        unsafe { *out_fb_phys = device.fb_phys; }
    }

    /* Store device state */
    DEVICE.with(|slot| *slot = Some(device));

    log("[VIRTIO-GPU] ARM64 PCI driver initialized successfully\n");
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
