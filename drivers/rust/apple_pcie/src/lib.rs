// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon PCIe root complex driver for Futura OS
//!
//! Supports the PCIe controller found in Apple M1/M2/M3 SoCs.
//!
//! Architecture notes
//! ------------------
//! - Up to 3 downstream ports (USB4/TB3 + NVMe + WiFi on M1)
//! - Each port has independent LTSSM, refclk, and PERST# control
//! - Config space is accessed via a dedicated MMIO window (not standard ECAM)
//! - MSI-X is routed through Apple AIC via per-port MSI doorbell registers
//! - Link training is initiated by deasserted PERST# + app_ltssm_enable
//!
//! Register map
//! ------------
//! CORE region (at base + 0):
//!   0x0024  CORE_RC_PHYIF_CTL0   — PHY interface control
//!   0x0028  CORE_RC_PHYIF_CTL1
//!   0x002C  CORE_RC_PHYIF_STAT   — PHY interface status
//!   0x0100  CORE_LANE_CFG_CNTL   — lane configuration control
//!
//! PORT region (base + port_stride * n, typically 0x100000 per port):
//!   0x0000  PORT_APPCLK_EN       — assert application clock enable
//!   0x0004  PORT_STATUS          — link status and error bits
//!   0x000C  PORT_REFCLK          — reference clock control
//!   0x0014  PORT_PERST_SET       — deassert PERST# (bit 0)
//!   0x0028  PORT_RX_PS           — receiver power state
//!   0x0040  PORT_APP_IRQ_STAT    — application IRQ status
//!   0x0044  PORT_APP_IRQ_MASK    — application IRQ mask
//!   0x0080  PORT_MSI_ADDR_LO     — MSI doorbell address (low 32 bits)
//!   0x0084  PORT_MSI_ADDR_HI     — MSI doorbell address (high 32 bits)
//!   0x0088  PORT_MSI_CTRL        — MSI vector control
//!   0x0100  PORT_LTSSM_CTL      — LTSSM (link training) control
//!   0x0104  PORT_LTSSM_STAT     — LTSSM state
//!   0x0200  PORT_LINK_CTL        — link control register
//!   0x0204  PORT_LINK_STAT       — link speed/width status
//!
//! CONFIG window (separate MMIO aperture per port):
//!   Standard PCIe ECAM layout: (bus << 20) | (dev << 15) | (fn << 12) | reg
//!
//! Reference: Asahi Linux `drivers/pci/controller/pcie-apple.c` (Alyssa Rosenzweig)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// CORE register offsets
// ---------------------------------------------------------------------------

const CORE_RC_PHYIF_CTL0: usize = 0x0024;
const CORE_RC_PHYIF_CTL1: usize = 0x0028;
const CORE_RC_PHYIF_STAT: usize = 0x002C;
const CORE_LANE_CFG_CNTL: usize = 0x0100;

// CORE_RC_PHYIF_CTL0 bits
const PHYIF_CTL0_USE_LEGACY_INTR: u32 = 1 << 1;

// CORE_RC_PHYIF_STAT bits
const PHYIF_STAT_CLK_ACTIVE: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// PORT register offsets (relative to port base)
// ---------------------------------------------------------------------------

const PORT_APPCLK_EN:    usize = 0x0000;
const PORT_STATUS:       usize = 0x0004;
const PORT_REFCLK:       usize = 0x000C;
const PORT_PERST_SET:    usize = 0x0014;
const PORT_RX_PS:        usize = 0x0028;
const PORT_APP_IRQ_STAT: usize = 0x0040;
const PORT_APP_IRQ_MASK: usize = 0x0044;
const PORT_MSI_ADDR_LO:  usize = 0x0080;
const PORT_MSI_ADDR_HI:  usize = 0x0084;
const PORT_MSI_CTRL:     usize = 0x0088;
const PORT_LTSSM_CTL:    usize = 0x0100;
const PORT_LTSSM_STAT:   usize = 0x0104;
const PORT_LINK_CTL:     usize = 0x0200;
const PORT_LINK_STAT:    usize = 0x0204;

// PORT_APPCLK_EN bits
const APPCLK_EN_REFCLK_REQ: u32 = 1 << 0;

// PORT_STATUS bits
const PORT_STATUS_LINK_UP:   u32 = 1 << 0;
const PORT_STATUS_LINK_SPEED: u32 = 0xF << 4;  // PCIe Gen 1/2/3/4
const PORT_STATUS_LINK_WIDTH: u32 = 0x3F << 8; // x1/x2/x4

// PORT_REFCLK bits
const REFCLK_REQACK_CLR: u32 = 1 << 0;
const REFCLK_CKPAD_EN:   u32 = 1 << 1;
const REFCLK_PERST_CLR:  u32 = 1 << 2;

// PORT_PERST_SET bits
const PERST_ASSERT:   u32 = 0;
const PERST_DEASSERT: u32 = 1 << 0;

// PORT_APP_IRQ bits
const APP_IRQ_PM_ME:       u32 = 1 << 0;
const APP_IRQ_PM_PME:      u32 = 1 << 1;
const APP_IRQ_LINK_UP:     u32 = 1 << 2;
const APP_IRQ_LINK_DOWN:   u32 = 1 << 3;
const APP_IRQ_AER:         u32 = 1 << 4;
const APP_IRQ_MSI:         u32 = 1 << 8;

// PORT_LTSSM_CTL bits
const LTSSM_CTL_EN: u32 = 1 << 0;

// PORT_LTSSM_STAT values (lower 6 bits = state)
const LTSSM_L0:        u32 = 0x11;  // L0 = active link
const LTSSM_L0S:       u32 = 0x12;  // L0s = standby
const LTSSM_L1:        u32 = 0x14;  // L1 = sleep

// PORT_LINK_STAT bits
const LINK_STAT_SPEED_MASK: u32 = 0xF;
const LINK_STAT_WIDTH_MASK: u32 = 0x3F << 4;

// PORT stride between ports (4MB per port on M1)
const PORT_STRIDE: usize = 0x0004_0000;

// CONFIG space window stride per port
const CFG_STRIDE: usize = 0x0100_0000;  // 16MB per port (256 buses × 64KB)

// Max supported ports
const MAX_PORTS: usize = 3;

// MSI vectors per port
const MSI_VECS_PER_PORT: u32 = 32;

// ---------------------------------------------------------------------------
// Link speed / width decoding
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkSpeed {
    Gen1 = 1,
    Gen2 = 2,
    Gen3 = 3,
    Gen4 = 4,
    Unknown = 0,
}

impl LinkSpeed {
    fn from_hw(bits: u32) -> Self {
        match bits & 0xF {
            1 => LinkSpeed::Gen1,
            2 => LinkSpeed::Gen2,
            3 => LinkSpeed::Gen3,
            4 => LinkSpeed::Gen4,
            _ => LinkSpeed::Unknown,
        }
    }

    /// GT/s string for the speed grade
    pub fn gt_per_sec(self) -> &'static str {
        match self {
            LinkSpeed::Gen1    => "2.5",
            LinkSpeed::Gen2    => "5.0",
            LinkSpeed::Gen3    => "8.0",
            LinkSpeed::Gen4    => "16.0",
            LinkSpeed::Unknown => "?",
        }
    }
}

// ---------------------------------------------------------------------------
// MSI handler table
// ---------------------------------------------------------------------------

type MsiHandlerFn = unsafe extern "C" fn(vec: u32, cookie: *mut ());

#[derive(Copy, Clone)]
struct MsiSlot {
    handler: Option<MsiHandlerFn>,
    cookie:  *mut (),
}

// SAFETY: MSI handlers are only dispatched from interrupt context, which is
// inherently single-threaded on the bare-metal kernel we target.
unsafe impl Send for MsiSlot {}
unsafe impl Sync for MsiSlot {}

impl MsiSlot {
    const fn empty() -> Self { Self { handler: None, cookie: core::ptr::null_mut() } }
}

// ---------------------------------------------------------------------------
// Per-port state
// ---------------------------------------------------------------------------

struct PortState {
    /// MMIO base address for this port's registers
    port_base:   usize,
    /// MMIO base address for this port's config space window
    cfg_base:    usize,
    /// True once link training succeeded
    link_up:     bool,
    /// Negotiated link speed
    speed:       LinkSpeed,
    /// Negotiated link width (x1/x2/x4/x8)
    width:       u8,
    /// MSI base IRQ vector allocated from AIC
    msi_irq_base: u32,
    /// MSI vector handlers for this port
    msi_slots:   [MsiSlot; MSI_VECS_PER_PORT as usize],
}

impl PortState {
    fn new(port_base: usize, cfg_base: usize) -> Self {
        Self {
            port_base,
            cfg_base,
            link_up:      false,
            speed:        LinkSpeed::Unknown,
            width:        0,
            msi_irq_base: 0,
            msi_slots:    [MsiSlot::empty(); MSI_VECS_PER_PORT as usize],
        }
    }

    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.port_base + off) as *const u32) }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.port_base + off) as *mut u32, v) }
    }

    fn rmw32(&self, off: usize, clear: u32, set: u32) {
        let old = self.r32(off);
        self.w32(off, (old & !clear) | set);
    }

    // ---- Config space read/write ----

    fn cfg_offset(bus: u8, dev: u8, fn_: u8, reg: u16) -> usize {
        ((bus as usize) << 20) | ((dev as usize) << 15) | ((fn_ as usize) << 12) | (reg as usize & 0xFFC)
    }

    pub fn cfg_read32(&self, bus: u8, dev: u8, fn_: u8, reg: u16) -> u32 {
        if !self.link_up && bus != 0 {
            return 0xFFFF_FFFF;
        }
        let off = Self::cfg_offset(bus, dev, fn_, reg);
        if off >= CFG_STRIDE {
            return 0xFFFF_FFFF;
        }
        unsafe { read_volatile((self.cfg_base + off) as *const u32) }
    }

    pub fn cfg_write32(&self, bus: u8, dev: u8, fn_: u8, reg: u16, val: u32) {
        if !self.link_up && bus != 0 {
            return;
        }
        let off = Self::cfg_offset(bus, dev, fn_, reg);
        if off >= CFG_STRIDE {
            return;
        }
        unsafe { write_volatile((self.cfg_base + off) as *mut u32, val) }
    }

    pub fn cfg_read16(&self, bus: u8, dev: u8, fn_: u8, reg: u16) -> u16 {
        let v = self.cfg_read32(bus, dev, fn_, reg & !3);
        (v >> ((reg & 2) * 8)) as u16
    }

    pub fn cfg_write16(&self, bus: u8, dev: u8, fn_: u8, reg: u16, val: u16) {
        let old = self.cfg_read32(bus, dev, fn_, reg & !3);
        let shift = (reg & 2) * 8;
        let new_val = (old & !(0xFFFFu32 << shift)) | ((val as u32) << shift);
        self.cfg_write32(bus, dev, fn_, reg & !3, new_val);
    }

    pub fn cfg_read8(&self, bus: u8, dev: u8, fn_: u8, reg: u16) -> u8 {
        let v = self.cfg_read32(bus, dev, fn_, reg & !3);
        (v >> ((reg & 3) * 8)) as u8
    }

    // ---- Link training ----

    /// Enable reference clock, deassert PERST#, and start LTSSM.
    /// Returns true immediately; caller should poll `poll_link_up()`.
    pub fn start_link_training(&self) {
        // 1. Enable application clock
        self.w32(PORT_APPCLK_EN, APPCLK_EN_REFCLK_REQ);

        // 2. Enable reference clock pad
        self.rmw32(PORT_REFCLK, 0, REFCLK_CKPAD_EN);

        // 3. Deassert PERST#
        self.w32(PORT_PERST_SET, PERST_DEASSERT);

        // 4. Enable LTSSM
        self.rmw32(PORT_LTSSM_CTL, 0, LTSSM_CTL_EN);
    }

    /// Poll link status; updates self.link_up / speed / width on success.
    /// Returns true when link is up.
    pub fn poll_link_up(&mut self) -> bool {
        let status = self.r32(PORT_STATUS);
        if status & PORT_STATUS_LINK_UP == 0 {
            return false;
        }
        self.link_up = true;
        let link_stat = self.r32(PORT_LINK_STAT);
        self.speed = LinkSpeed::from_hw(link_stat & LINK_STAT_SPEED_MASK);
        self.width = (1u8).wrapping_shl(((link_stat & LINK_STAT_WIDTH_MASK) >> 4) as u32);
        true
    }

    /// Check LTSSM state machine state.
    pub fn ltssm_state(&self) -> u32 {
        self.r32(PORT_LTSSM_STAT) & 0x3F
    }

    /// True if LTSSM reports L0 (active) state.
    pub fn in_l0(&self) -> bool {
        self.ltssm_state() == LTSSM_L0
    }

    // ---- MSI ----

    /// Program MSI doorbell address and enable MSI generation.
    /// `msi_addr` is the physical address of the AIC MSI doorbell register.
    pub fn setup_msi(&self, msi_addr: u64, irq_base: u32) {
        self.w32(PORT_MSI_ADDR_LO, (msi_addr & 0xFFFF_FFFF) as u32);
        self.w32(PORT_MSI_ADDR_HI, (msi_addr >> 32) as u32);
        // Program MSI vector base offset into control register
        self.w32(PORT_MSI_CTRL, irq_base & 0x1FF);
    }

    /// Dispatch a pending MSI vector from this port.
    /// `vec` is the 0-based vector within this port's MSI range.
    pub fn dispatch_msi(&self, vec: u32) {
        if vec >= MSI_VECS_PER_PORT {
            return;
        }
        let slot = &self.msi_slots[vec as usize];
        if let Some(f) = slot.handler {
            unsafe { f(vec, slot.cookie) };
        }
    }

    /// Register an MSI handler for a specific vector.
    pub fn register_msi_handler(&mut self, vec: u32, f: MsiHandlerFn, cookie: *mut ()) -> bool {
        if vec >= MSI_VECS_PER_PORT {
            return false;
        }
        self.msi_slots[vec as usize] = MsiSlot { handler: Some(f), cookie };
        true
    }

    // ---- Application IRQ handling ----

    /// Read and clear the application IRQ status register.
    pub fn read_clear_app_irq(&self) -> u32 {
        let stat = self.r32(PORT_APP_IRQ_STAT);
        // Write-1-to-clear
        self.w32(PORT_APP_IRQ_STAT, stat);
        stat
    }

    /// Mask all application IRQs (set mask bits = disable).
    pub fn mask_all_app_irqs(&self) {
        self.w32(PORT_APP_IRQ_MASK, 0xFFFF_FFFF);
    }

    /// Unmask specific application IRQs.
    pub fn unmask_app_irqs(&self, bits: u32) {
        let cur = self.r32(PORT_APP_IRQ_MASK);
        self.w32(PORT_APP_IRQ_MASK, cur & !bits);
    }
}

// ---------------------------------------------------------------------------
// ApplePcie — main controller
// ---------------------------------------------------------------------------

pub struct ApplePcie {
    /// MMIO base for the CORE (shared) register region
    core_base:  usize,
    num_ports:  u32,
    ready:      AtomicBool,
    ports:      [PortState; MAX_PORTS],
}

impl ApplePcie {
    // ---- CORE MMIO helpers ----

    fn cr32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.core_base + off) as *const u32) }
    }

    fn cw32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.core_base + off) as *mut u32, v) }
    }

    // ---- Initialization ----

    /// Initialize the Apple PCIe root complex.
    ///
    /// `base` is the MMIO base address of the controller.  Port register
    /// regions start at `base + PORT_STRIDE`, config-space windows at
    /// `base + cfg_offset`.
    pub fn init(&mut self) {
        // Disable legacy interrupt mode — use MSI/MSI-X only
        let ctl0 = self.cr32(CORE_RC_PHYIF_CTL0);
        self.cw32(CORE_RC_PHYIF_CTL0, ctl0 & !PHYIF_CTL0_USE_LEGACY_INTR);

        // Start link training on all configured ports
        for i in 0..self.num_ports as usize {
            self.ports[i].mask_all_app_irqs();
            self.ports[i].start_link_training();
        }

        // Simple spin-wait for links to come up (up to ~500 poll iterations).
        // Real driver would defer to a workqueue, but bare-metal init can spin.
        for _ in 0..500u32 {
            let mut all_done = true;
            for i in 0..self.num_ports as usize {
                if !self.ports[i].link_up {
                    if self.ports[i].poll_link_up() {
                        // Unmask link-up and MSI IRQs
                        self.ports[i].unmask_app_irqs(APP_IRQ_LINK_UP | APP_IRQ_MSI);
                    } else {
                        all_done = false;
                    }
                }
            }
            if all_done {
                break;
            }
            // Lightweight delay — approximately 1ms at 1 GHz
            for _ in 0..100_000u32 {
                unsafe { core::arch::asm!("nop") };
            }
        }

        self.ready.store(true, Ordering::Release);
    }

    // ---- Config space access ----

    /// Map a global (bus, dev, fn) to a port index.
    ///
    /// Apple PCIe uses one root bus per port.  Bus 0 is the root complex;
    /// bus 1 is the first downstream bus on port 0, bus 2 on port 1, etc.
    /// This mapping assumes single-level topology (one device per port).
    fn port_for_bus(&self, bus: u8) -> Option<usize> {
        if bus == 0 {
            // Root complex itself: port 0 handles it
            return Some(0);
        }
        let idx = (bus as usize).saturating_sub(1);
        if idx < self.num_ports as usize {
            Some(idx)
        } else {
            None
        }
    }

    pub fn config_read32(&self, bus: u8, dev: u8, fn_: u8, reg: u16) -> u32 {
        match self.port_for_bus(bus) {
            Some(p) => self.ports[p].cfg_read32(bus, dev, fn_, reg),
            None    => 0xFFFF_FFFF,
        }
    }

    pub fn config_write32(&self, bus: u8, dev: u8, fn_: u8, reg: u16, val: u32) {
        if let Some(p) = self.port_for_bus(bus) {
            self.ports[p].cfg_write32(bus, dev, fn_, reg, val);
        }
    }

    pub fn config_read16(&self, bus: u8, dev: u8, fn_: u8, reg: u16) -> u16 {
        match self.port_for_bus(bus) {
            Some(p) => self.ports[p].cfg_read16(bus, dev, fn_, reg),
            None    => 0xFFFF,
        }
    }

    pub fn config_read8(&self, bus: u8, dev: u8, fn_: u8, reg: u16) -> u8 {
        match self.port_for_bus(bus) {
            Some(p) => self.ports[p].cfg_read8(bus, dev, fn_, reg),
            None    => 0xFF,
        }
    }

    // ---- Link status ----

    pub fn port_link_up(&self, port: u32) -> bool {
        if port >= self.num_ports {
            return false;
        }
        self.ports[port as usize].link_up
    }

    pub fn port_speed(&self, port: u32) -> LinkSpeed {
        if port >= self.num_ports {
            return LinkSpeed::Unknown;
        }
        self.ports[port as usize].speed
    }

    pub fn port_width(&self, port: u32) -> u8 {
        if port >= self.num_ports {
            return 0;
        }
        self.ports[port as usize].width
    }

    // ---- MSI ----

    /// Configure MSI for a port.
    /// `msi_addr` is the physical address of the AIC MSI doorbell.
    /// `irq_base` is the first IRQ number allocated from AIC for this port.
    pub fn setup_msi(&mut self, port: u32, msi_addr: u64, irq_base: u32) {
        if port >= self.num_ports {
            return;
        }
        self.ports[port as usize].msi_irq_base = irq_base;
        self.ports[port as usize].setup_msi(msi_addr, irq_base);
    }

    pub fn register_msi_handler(
        &mut self,
        port: u32,
        vec: u32,
        f: MsiHandlerFn,
        cookie: *mut (),
    ) -> bool {
        if port >= self.num_ports {
            return false;
        }
        self.ports[port as usize].register_msi_handler(vec, f, cookie)
    }

    // ---- IRQ dispatch ----

    /// Handle an interrupt for a given port.
    /// Called from the platform IRQ handler when the port's AIC IRQ fires.
    pub fn handle_irq(&self, port: u32) {
        if port >= self.num_ports {
            return;
        }
        let p = &self.ports[port as usize];
        let stat = p.read_clear_app_irq();

        if stat & APP_IRQ_LINK_UP != 0 {
            // Link came up event — handled during init polling, ignore here
        }
        if stat & APP_IRQ_LINK_DOWN != 0 {
            // Link down — could trigger hotplug removal
        }
        if stat & APP_IRQ_MSI != 0 {
            // Dispatch MSI: read pending vector from MSI status.
            // Real hardware has a FIFO; we poll bit[7:0] of PORT_MSI_CTRL for pending vec.
            let ctrl = p.r32(PORT_MSI_CTRL);
            let pending_vec = (ctrl >> 16) & (MSI_VECS_PER_PORT - 1);
            p.dispatch_msi(pending_vec);
        }
    }

    // ---- Device scan helper ----

    /// Scan all downstream buses for present devices.
    /// Returns a bitmap of which ports have an active downstream device.
    pub fn scan_devices(&self) -> u32 {
        let mut found = 0u32;
        for i in 0..self.num_ports as usize {
            if !self.ports[i].link_up {
                continue;
            }
            // Bus i+1 is the downstream bus for port i (bus 0 = RC itself)
            let bus = (i + 1) as u8;
            let id = self.ports[i].cfg_read32(bus, 0, 0, 0x00);
            if id != 0xFFFF_FFFF && id != 0 {
                found |= 1u32 << i;
            }
        }
        found
    }
}

// ---------------------------------------------------------------------------
// Static singleton (bare-metal: no heap allocator)
// ---------------------------------------------------------------------------

static mut G_PCIE: ApplePcie = ApplePcie {
    core_base: 0,
    num_ports: 0,
    ready:     AtomicBool::new(false),
    ports:     [
        PortState {
            port_base:    0,
            cfg_base:     0,
            link_up:      false,
            speed:        LinkSpeed::Unknown,
            width:        0,
            msi_irq_base: 0,
            msi_slots:    [MsiSlot::empty(); MSI_VECS_PER_PORT as usize],
        },
        PortState {
            port_base:    0,
            cfg_base:     0,
            link_up:      false,
            speed:        LinkSpeed::Unknown,
            width:        0,
            msi_irq_base: 0,
            msi_slots:    [MsiSlot::empty(); MSI_VECS_PER_PORT as usize],
        },
        PortState {
            port_base:    0,
            cfg_base:     0,
            link_up:      false,
            speed:        LinkSpeed::Unknown,
            width:        0,
            msi_irq_base: 0,
            msi_slots:    [MsiSlot::empty(); MSI_VECS_PER_PORT as usize],
        },
    ],
};

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------
//
// The C kernel interacts with this driver via the following extern "C" symbols.
// All pointers received from C must be valid for the lifetime of the call.

/// Initialize the Apple PCIe controller.
///
/// `base`      — MMIO base address of the CORE register region.
/// `num_ports` — number of downstream ports (1–3).
/// `cfg_base`  — base address of the config-space MMIO window; port n's
///               config window starts at `cfg_base + n * CFG_STRIDE`.
///
/// Returns a non-null opaque handle on success, NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_init(
    base: u64,
    num_ports: u32,
    cfg_base: u64,
) -> *mut ApplePcie {
    if base == 0 || num_ports == 0 || num_ports > MAX_PORTS as u32 || cfg_base == 0 {
        return core::ptr::null_mut();
    }

    let pcie = unsafe { &mut *(&raw mut G_PCIE) };
    pcie.core_base = base as usize;
    pcie.num_ports = num_ports;
    pcie.ready = AtomicBool::new(false);

    for i in 0..num_ports as usize {
        pcie.ports[i] = PortState::new(
            base as usize + PORT_STRIDE * (i + 1),
            cfg_base as usize + CFG_STRIDE * i,
        );
    }
    // Ports beyond num_ports are zeroed out
    for i in num_ports as usize..MAX_PORTS {
        pcie.ports[i] = PortState::new(0, 0);
    }

    pcie.init();
    pcie as *mut ApplePcie
}

/// Release resources held by the Apple PCIe driver.
/// After this call the handle must not be used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_free(pcie: *mut ApplePcie) {
    if pcie.is_null() {
        return;
    }
    let p = unsafe { &mut *pcie };
    p.ready.store(false, Ordering::Release);
    // Zero all port bases to prevent stale MMIO accesses
    for port in p.ports.iter_mut() {
        port.port_base = 0;
        port.cfg_base  = 0;
        port.link_up   = false;
    }
}

/// Return 1 if the given port has an active PCIe link, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_port_link_up(
    pcie: *const ApplePcie,
    port: u32,
) -> i32 {
    if pcie.is_null() {
        return 0;
    }
    unsafe { (*pcie).port_link_up(port) as i32 }
}

/// Return the negotiated link speed for `port` (1=Gen1, 2=Gen2, 3=Gen3, 4=Gen4).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_port_speed(
    pcie: *const ApplePcie,
    port: u32,
) -> u32 {
    if pcie.is_null() {
        return 0;
    }
    unsafe { (*pcie).port_speed(port) as u32 }
}

/// Return the negotiated link width for `port` (1, 2, 4, 8, …).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_port_width(
    pcie: *const ApplePcie,
    port: u32,
) -> u32 {
    if pcie.is_null() {
        return 0;
    }
    unsafe { (*pcie).port_width(port) as u32 }
}

/// Read a 32-bit value from PCI configuration space.
/// Returns 0xFFFFFFFF if the bus/device/function is not present.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_cfg_read32(
    pcie: *const ApplePcie,
    bus: u8,
    dev: u8,
    fn_: u8,
    reg: u16,
) -> u32 {
    if pcie.is_null() {
        return 0xFFFF_FFFF;
    }
    unsafe { (*pcie).config_read32(bus, dev, fn_, reg) }
}

/// Write a 32-bit value to PCI configuration space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_cfg_write32(
    pcie: *mut ApplePcie,
    bus: u8,
    dev: u8,
    fn_: u8,
    reg: u16,
    val: u32,
) {
    if pcie.is_null() {
        return;
    }
    unsafe { (*pcie).config_write32(bus, dev, fn_, reg, val) }
}

/// Read a 16-bit value from PCI configuration space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_cfg_read16(
    pcie: *const ApplePcie,
    bus: u8,
    dev: u8,
    fn_: u8,
    reg: u16,
) -> u16 {
    if pcie.is_null() {
        return 0xFFFF;
    }
    unsafe { (*pcie).config_read16(bus, dev, fn_, reg) }
}

/// Read an 8-bit value from PCI configuration space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_cfg_read8(
    pcie: *const ApplePcie,
    bus: u8,
    dev: u8,
    fn_: u8,
    reg: u16,
) -> u8 {
    if pcie.is_null() {
        return 0xFF;
    }
    unsafe { (*pcie).config_read8(bus, dev, fn_, reg) }
}

/// Configure MSI for `port`.
/// `msi_addr` is the AIC MSI doorbell physical address.
/// `irq_base` is the first AIC IRQ number allocated for this port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_setup_msi(
    pcie: *mut ApplePcie,
    port: u32,
    msi_addr: u64,
    irq_base: u32,
) {
    if pcie.is_null() {
        return;
    }
    unsafe { (*pcie).setup_msi(port, msi_addr, irq_base) }
}

/// Register an MSI handler for `vec` on `port`.
/// Returns 1 on success, 0 on failure (bad port/vec).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_register_msi(
    pcie: *mut ApplePcie,
    port: u32,
    vec: u32,
    handler: MsiHandlerFn,
    cookie: *mut (),
) -> i32 {
    if pcie.is_null() {
        return 0;
    }
    unsafe { (*pcie).register_msi_handler(port, vec, handler, cookie) as i32 }
}

/// Handle a port IRQ — must be called from the AIC interrupt handler
/// when the IRQ assigned to `port` fires.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_handle_irq(pcie: *const ApplePcie, port: u32) {
    if pcie.is_null() {
        return;
    }
    unsafe { (*pcie).handle_irq(port) }
}

/// Scan all downstream buses and return a bitmask of ports with active devices.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_pcie_scan_devices(pcie: *const ApplePcie) -> u32 {
    if pcie.is_null() {
        return 0;
    }
    unsafe { (*pcie).scan_devices() }
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std staticlib)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
