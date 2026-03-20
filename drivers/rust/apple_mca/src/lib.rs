// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon MCA (Multi-Channel Audio) controller driver for Futura OS
//!
//! MCA is the multi-channel I2S/TDM audio serializer/deserializer embedded
//! in Apple M1/M2/M3 SoCs.  It connects the CPU-side DMA engine to external
//! audio codecs (speaker amplifiers, headphone DAC, microphone ADC).
//!
//! Architecture notes
//! ------------------
//! - Up to 6 clusters; each cluster has one serializer (TX) and one
//!   deserializer (RX) connected to a shared I2S bus
//! - Each cluster is clocked by one of two PLLs: MCLK0 or MCLK1
//! - DMA is performed via Apple's ADMAC (Audio DMA Controller), which
//!   feeds/drains 4KB ring buffers shared with the MCA FIFO
//! - Sample formats: I2S, left-justified, TDM (1–8 slots × 32-bit)
//! - Word clock (FSYNC) and bit clock (BCLK) can be master or slave
//!
//! Register map (relative to cluster base = mca_base + cluster * CLUSTER_STRIDE)
//! -------------------------------------------------------------------------------
//! CLUSTER_CTRL:    0x0000  — cluster enable + reset
//! MCLK_CONF:       0x0004  — MCLK source select (0=MCLK0, 1=MCLK1)
//! SYNCGEN_CTRL:    0x0008  — FSYNC + BCLK generator enable/mode
//! SYNCGEN_MCKDIV:  0x000C  — MCLK divider for BCLK (= MCLK / (2*(div+1)))
//! SYNCGEN_FSYNC:   0x0010  — FSYNC width (number of BCLK cycles per frame)
//! SERDES_CTRL:     0x0020  — TX serializer control (enable, format, slots)
//! SERDES_CONF:     0x0024  — TX slot mask + word length
//! DESERDES_CTRL:   0x0030  — RX deserializer control
//! DESERDES_CONF:   0x0034  — RX slot mask + word length
//! FIFO_CTRL:       0x0040  — TX/RX FIFO enable + threshold
//! FIFO_STAT:       0x0044  — FIFO level + overflow/underflow flags
//! TX_DATA:         0x0050  — Write 32-bit PCM sample into TX FIFO
//! RX_DATA:         0x0054  — Read 32-bit PCM sample from RX FIFO
//! IRQ_STAT:        0x0060  — Interrupt status (write-1-to-clear)
//! IRQ_MASK:        0x0064  — Interrupt mask (1=enabled)
//! DMA_TX_ADDR_LO:  0x0080  — TX DMA buffer physical address (low 32)
//! DMA_TX_ADDR_HI:  0x0084  — TX DMA buffer physical address (high 32)
//! DMA_TX_LEN:      0x0088  — TX DMA transfer length in bytes
//! DMA_RX_ADDR_LO:  0x0090  — RX DMA buffer physical address
//! DMA_RX_ADDR_HI:  0x0094
//! DMA_RX_LEN:      0x0098  — RX DMA transfer length in bytes
//! DMA_CTRL:        0x00A0  — DMA start/stop (bit 0=TX, bit 1=RX)
//!
//! Reference: Asahi Linux `sound/soc/apple/mca.c` (Martin Povišer)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Register offsets (relative to cluster base)
// ---------------------------------------------------------------------------

const CLUSTER_CTRL:     usize = 0x0000;
const MCLK_CONF:        usize = 0x0004;
const SYNCGEN_CTRL:     usize = 0x0008;
const SYNCGEN_MCKDIV:   usize = 0x000C;
const SYNCGEN_FSYNC:    usize = 0x0010;
const SERDES_CTRL:      usize = 0x0020;
const SERDES_CONF:      usize = 0x0024;
const DESERDES_CTRL:    usize = 0x0030;
const DESERDES_CONF:    usize = 0x0034;
const FIFO_CTRL:        usize = 0x0040;
const FIFO_STAT:        usize = 0x0044;
const TX_DATA:          usize = 0x0050;
const RX_DATA:          usize = 0x0054;
const IRQ_STAT:         usize = 0x0060;
const IRQ_MASK:         usize = 0x0064;
const DMA_TX_ADDR_LO:   usize = 0x0080;
const DMA_TX_ADDR_HI:   usize = 0x0084;
const DMA_TX_LEN:       usize = 0x0088;
const DMA_RX_ADDR_LO:   usize = 0x0090;
const DMA_RX_ADDR_HI:   usize = 0x0094;
const DMA_RX_LEN:       usize = 0x0098;
const DMA_CTRL:         usize = 0x00A0;

// Cluster stride (4MB per cluster on M1)
const CLUSTER_STRIDE:   usize = 0x4000;
const MAX_CLUSTERS:     usize = 6;

// ---------------------------------------------------------------------------
// Register bits
// ---------------------------------------------------------------------------

// CLUSTER_CTRL
const CLUSTER_ENABLE: u32 = 1 << 0;
const CLUSTER_RESET:  u32 = 1 << 1;

// SYNCGEN_CTRL
const SYNCGEN_ENABLE:  u32 = 1 << 0;
const SYNCGEN_MASTER:  u32 = 1 << 1;  // 1 = this cluster generates BCLK+FSYNC

// SERDES_CTRL / DESERDES_CTRL
const SERDES_ENABLE:   u32 = 1 << 0;
const SERDES_I2S:      u32 = 0 << 4;  // I2S mode
const SERDES_LJ:       u32 = 1 << 4;  // Left-justified
const SERDES_TDM:      u32 = 2 << 4;  // TDM multi-slot

// FIFO_CTRL
const FIFO_TX_ENABLE:  u32 = 1 << 0;
const FIFO_RX_ENABLE:  u32 = 1 << 1;
const FIFO_TX_FLUSH:   u32 = 1 << 4;
const FIFO_RX_FLUSH:   u32 = 1 << 5;
const FIFO_TX_THRES:   u32 = 8 << 8;  // TX threshold: half-full (8 words)
const FIFO_RX_THRES:   u32 = 8 << 16; // RX threshold: half-full

// FIFO_STAT
const FIFO_TX_LEVEL_MASK:  u32 = 0xFF;
const FIFO_RX_LEVEL_MASK:  u32 = 0xFF00;
const FIFO_TX_OVERFLOW:    u32 = 1 << 16;
const FIFO_RX_UNDERFLOW:   u32 = 1 << 17;
const FIFO_TX_EMPTY:       u32 = 1 << 20;
const FIFO_RX_FULL:        u32 = 1 << 21;

// IRQ bits
const IRQ_TX_THRESHOLD:    u32 = 1 << 0;
const IRQ_RX_THRESHOLD:    u32 = 1 << 1;
const IRQ_TX_OVERFLOW:     u32 = 1 << 2;
const IRQ_RX_UNDERFLOW:    u32 = 1 << 3;
const IRQ_DMA_TX_DONE:     u32 = 1 << 4;
const IRQ_DMA_RX_DONE:     u32 = 1 << 5;

// DMA_CTRL
const DMA_TX_START:  u32 = 1 << 0;
const DMA_RX_START:  u32 = 1 << 1;
const DMA_TX_STOP:   u32 = 0;

// ---------------------------------------------------------------------------
// Audio format configuration
// ---------------------------------------------------------------------------

/// Sample format for I2S/TDM serialization
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum AudioFormat {
    I2S   = 0,  // Standard I2S (MSB first, 1-bit delay after FSYNC)
    LeftJ = 1,  // Left-justified (MSB on FSYNC edge)
    Tdm   = 2,  // TDM multi-slot (multiple channels per frame)
}

/// Word length (bit depth per sample)
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum WordLen {
    Bits16 = 15,  // 16-bit (value = bits - 1)
    Bits20 = 19,  // 20-bit
    Bits24 = 23,  // 24-bit
    Bits32 = 31,  // 32-bit
}

/// DMA callback type: fn(cluster, is_rx, cookie)
pub type DmaCallbackFn = unsafe extern "C" fn(cluster: u32, is_rx: bool, cookie: *mut ());

#[derive(Copy, Clone)]
struct DmaSlot {
    callback: Option<DmaCallbackFn>,
    cookie:   *mut (),
}

unsafe impl Send for DmaSlot {}
unsafe impl Sync for DmaSlot {}

impl DmaSlot {
    const fn empty() -> Self { Self { callback: None, cookie: core::ptr::null_mut() } }
}

// ---------------------------------------------------------------------------
// Per-cluster state
// ---------------------------------------------------------------------------

struct ClusterState {
    /// MMIO base of this cluster's register block
    base:         usize,
    enabled:      bool,
    tx_running:   bool,
    rx_running:   bool,
    tx_dma_cb:    DmaSlot,
    rx_dma_cb:    DmaSlot,
}

impl ClusterState {
    fn new(base: usize) -> Self {
        Self {
            base,
            enabled:    false,
            tx_running: false,
            rx_running: false,
            tx_dma_cb:  DmaSlot::empty(),
            rx_dma_cb:  DmaSlot::empty(),
        }
    }

    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }

    // ---- Cluster control ----

    /// Reset and then enable the cluster.
    pub fn reset_and_enable(&mut self) {
        self.w32(CLUSTER_CTRL, CLUSTER_RESET);
        // Short spin for reset pulse
        for _ in 0..1_000u32 { unsafe { core::arch::asm!("nop") }; }
        self.w32(CLUSTER_CTRL, CLUSTER_ENABLE);
        self.enabled = true;
    }

    /// Disable the cluster (stop all clocks and FIFOs).
    pub fn disable(&mut self) {
        self.w32(DMA_CTRL, 0);
        self.w32(FIFO_CTRL, FIFO_TX_FLUSH | FIFO_RX_FLUSH);
        self.w32(SYNCGEN_CTRL, 0);
        self.w32(CLUSTER_CTRL, 0);
        self.enabled    = false;
        self.tx_running = false;
        self.rx_running = false;
    }

    /// Configure the clock generator as master.
    ///
    /// `mclk_div` — MCLK → BCLK divider (BCLK = MCLK / (2*(div+1)))
    /// `fsync_width` — number of BCLK cycles per audio frame
    /// `mclk_sel`    — 0 = MCLK0, 1 = MCLK1
    pub fn setup_clock_master(&self, mclk_sel: u32, mclk_div: u32, fsync_width: u32) {
        self.w32(MCLK_CONF, mclk_sel & 1);
        self.w32(SYNCGEN_MCKDIV, mclk_div & 0x3FF);
        self.w32(SYNCGEN_FSYNC, fsync_width & 0x3FF);
        self.w32(SYNCGEN_CTRL, SYNCGEN_ENABLE | SYNCGEN_MASTER);
    }

    /// Configure the serializer (TX path).
    pub fn setup_tx(&self, fmt: AudioFormat, word_len: WordLen, slot_mask: u32) {
        let mode_bits = match fmt {
            AudioFormat::I2S   => SERDES_I2S,
            AudioFormat::LeftJ => SERDES_LJ,
            AudioFormat::Tdm   => SERDES_TDM,
        };
        self.w32(SERDES_CTRL, SERDES_ENABLE | mode_bits);
        // SERDES_CONF: [31:16]=slot_mask [7:0]=word_len
        let conf = (slot_mask << 16) | (word_len as u32);
        self.w32(SERDES_CONF, conf);
    }

    /// Configure the deserializer (RX path).
    pub fn setup_rx(&self, fmt: AudioFormat, word_len: WordLen, slot_mask: u32) {
        let mode_bits = match fmt {
            AudioFormat::I2S   => SERDES_I2S,
            AudioFormat::LeftJ => SERDES_LJ,
            AudioFormat::Tdm   => SERDES_TDM,
        };
        self.w32(DESERDES_CTRL, SERDES_ENABLE | mode_bits);
        let conf = (slot_mask << 16) | (word_len as u32);
        self.w32(DESERDES_CONF, conf);
    }

    /// Enable TX and/or RX FIFOs.
    pub fn enable_fifos(&self, tx: bool, rx: bool) {
        let mut ctrl = FIFO_TX_THRES | FIFO_RX_THRES;
        if tx { ctrl |= FIFO_TX_ENABLE; }
        if rx { ctrl |= FIFO_RX_ENABLE; }
        self.w32(FIFO_CTRL, ctrl);
    }

    // ---- Polled I/O ----

    /// Write one 32-bit PCM sample into the TX FIFO (polled, with timeout).
    pub fn tx_write_sample(&self, sample: u32) -> bool {
        for _ in 0..10_000u32 {
            if self.r32(FIFO_STAT) & FIFO_TX_EMPTY == 0 ||
               (self.r32(FIFO_STAT) & FIFO_TX_LEVEL_MASK) < 16 {
                self.w32(TX_DATA, sample);
                return true;
            }
        }
        false
    }

    /// Read one 32-bit PCM sample from the RX FIFO (polled, with timeout).
    pub fn rx_read_sample(&self) -> Option<u32> {
        for _ in 0..10_000u32 {
            let stat = self.r32(FIFO_STAT);
            if (stat & FIFO_RX_LEVEL_MASK) >> 8 > 0 {
                return Some(self.r32(RX_DATA));
            }
        }
        None
    }

    // ---- DMA ----

    /// Start TX DMA from `phys_addr` for `len_bytes` bytes.
    pub fn start_tx_dma(&mut self, phys_addr: u64, len_bytes: u32,
                        cb: DmaCallbackFn, cookie: *mut ()) {
        self.w32(DMA_TX_ADDR_LO, (phys_addr & 0xFFFF_FFFF) as u32);
        self.w32(DMA_TX_ADDR_HI, (phys_addr >> 32) as u32);
        self.w32(DMA_TX_LEN, len_bytes);
        self.tx_dma_cb = DmaSlot { callback: Some(cb), cookie };
        // Enable TX DMA
        let ctrl = self.r32(DMA_CTRL);
        self.w32(DMA_CTRL, ctrl | DMA_TX_START);
        self.tx_running = true;
    }

    /// Start RX DMA into `phys_addr` for `len_bytes` bytes.
    pub fn start_rx_dma(&mut self, phys_addr: u64, len_bytes: u32,
                        cb: DmaCallbackFn, cookie: *mut ()) {
        self.w32(DMA_RX_ADDR_LO, (phys_addr & 0xFFFF_FFFF) as u32);
        self.w32(DMA_RX_ADDR_HI, (phys_addr >> 32) as u32);
        self.w32(DMA_RX_LEN, len_bytes);
        self.rx_dma_cb = DmaSlot { callback: Some(cb), cookie };
        let ctrl = self.r32(DMA_CTRL);
        self.w32(DMA_CTRL, ctrl | DMA_RX_START);
        self.rx_running = true;
    }

    /// Stop both TX and RX DMA.
    pub fn stop_dma(&mut self) {
        self.w32(DMA_CTRL, DMA_TX_STOP);
        self.tx_running = false;
        self.rx_running = false;
    }

    // ---- IRQ ----

    /// Read and clear interrupt status.
    pub fn read_clear_irq(&self) -> u32 {
        let stat = self.r32(IRQ_STAT);
        self.w32(IRQ_STAT, stat);
        stat
    }

    /// Dispatch callbacks for pending IRQs.  Must be called from the
    /// platform interrupt handler.
    pub fn handle_irq(&mut self, cluster_idx: u32) {
        let stat = self.read_clear_irq();

        if stat & IRQ_DMA_TX_DONE != 0 {
            self.tx_running = false;
            if let Some(cb) = self.tx_dma_cb.callback {
                unsafe { cb(cluster_idx, false, self.tx_dma_cb.cookie) };
            }
        }
        if stat & IRQ_DMA_RX_DONE != 0 {
            self.rx_running = false;
            if let Some(cb) = self.rx_dma_cb.callback {
                unsafe { cb(cluster_idx, true, self.rx_dma_cb.cookie) };
            }
        }
    }

    /// Enable specific IRQ sources.
    pub fn enable_irqs(&self, mask: u32) {
        let cur = self.r32(IRQ_MASK);
        self.w32(IRQ_MASK, cur | mask);
    }

    /// Disable all IRQ sources.
    pub fn disable_irqs(&self) {
        self.w32(IRQ_MASK, 0);
    }
}

// ---------------------------------------------------------------------------
// AppleMca — main driver state
// ---------------------------------------------------------------------------

pub struct AppleMca {
    base:         usize,
    num_clusters: u32,
    ready:        AtomicBool,
    clusters:     [ClusterState; MAX_CLUSTERS],
}

impl AppleMca {
    pub fn init(&mut self) {
        for i in 0..self.num_clusters as usize {
            self.clusters[i].reset_and_enable();
            self.clusters[i].disable_irqs();
        }
        self.ready.store(true, Ordering::Release);
    }

    /// Configure a cluster for playback (TX) at standard 48 kHz stereo I2S.
    ///
    /// `cluster`   — cluster index (0-based).
    /// `mclk_sel`  — 0 = MCLK0, 1 = MCLK1.
    /// `mclk_hz`   — MCLK frequency in Hz (e.g., 49_152_000).
    /// `sample_hz` — target sample rate (e.g., 48_000).
    pub fn setup_playback_i2s(
        &mut self,
        cluster:   u32,
        mclk_sel:  u32,
        mclk_hz:   u32,
        sample_hz: u32,
    ) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        let c = &mut self.clusters[cluster as usize];

        // BCLK = sample_hz * 64 (32 bits × 2 channels)
        // mclk_div = mclk_hz / (2 * bclk) - 1
        let bclk_hz = sample_hz.saturating_mul(64);
        if bclk_hz == 0 { return -22; }
        let mclk_div = mclk_hz / (2 * bclk_hz);
        let mclk_div = if mclk_div > 0 { mclk_div - 1 } else { 0 };

        // Frame length = 64 BCLK cycles (stereo × 32-bit)
        c.setup_clock_master(mclk_sel, mclk_div, 63);
        // Stereo: slot 0 (L) + slot 1 (R)
        c.setup_tx(AudioFormat::I2S, WordLen::Bits32, 0x0003);
        c.enable_fifos(true, false);
        c.enable_irqs(IRQ_DMA_TX_DONE | IRQ_TX_OVERFLOW);
        0
    }

    /// Configure a cluster for capture (RX) at standard 48 kHz stereo I2S.
    pub fn setup_capture_i2s(
        &mut self,
        cluster:   u32,
        mclk_sel:  u32,
        mclk_hz:   u32,
        sample_hz: u32,
    ) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        let c = &mut self.clusters[cluster as usize];

        let bclk_hz = sample_hz.saturating_mul(64);
        if bclk_hz == 0 { return -22; }
        let mclk_div = mclk_hz / (2 * bclk_hz);
        let mclk_div = if mclk_div > 0 { mclk_div - 1 } else { 0 };

        c.setup_clock_master(mclk_sel, mclk_div, 63);
        c.setup_rx(AudioFormat::I2S, WordLen::Bits32, 0x0003);
        c.enable_fifos(false, true);
        c.enable_irqs(IRQ_DMA_RX_DONE | IRQ_RX_UNDERFLOW);
        0
    }

    pub fn start_tx_dma(
        &mut self,
        cluster:    u32,
        phys_addr:  u64,
        len_bytes:  u32,
        callback:   DmaCallbackFn,
        cookie:     *mut (),
    ) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        self.clusters[cluster as usize].start_tx_dma(phys_addr, len_bytes, callback, cookie);
        0
    }

    pub fn start_rx_dma(
        &mut self,
        cluster:    u32,
        phys_addr:  u64,
        len_bytes:  u32,
        callback:   DmaCallbackFn,
        cookie:     *mut (),
    ) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        self.clusters[cluster as usize].start_rx_dma(phys_addr, len_bytes, callback, cookie);
        0
    }

    pub fn stop_cluster(&mut self, cluster: u32) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        self.clusters[cluster as usize].stop_dma();
        0
    }

    pub fn handle_irq(&mut self, cluster: u32) {
        if cluster >= self.num_clusters { return; }
        self.clusters[cluster as usize].handle_irq(cluster);
    }

    /// Poll a TX write (no-DMA path): push `samples` into cluster TX FIFO.
    pub fn tx_write(&self, cluster: u32, samples: &[u32]) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        let c = &self.clusters[cluster as usize];
        let mut written = 0i32;
        for &s in samples {
            if !c.tx_write_sample(s) { break; }
            written += 1;
        }
        written
    }

    /// Poll an RX read (no-DMA path): drain RX FIFO into `buf`.
    pub fn rx_read(&self, cluster: u32, buf: &mut [u32]) -> i32 {
        if cluster >= self.num_clusters { return -22; }
        let c = &self.clusters[cluster as usize];
        let mut read = 0i32;
        for slot in buf.iter_mut() {
            match c.rx_read_sample() {
                Some(s) => { *slot = s; read += 1; }
                None    => break,
            }
        }
        read
    }
}

// ---------------------------------------------------------------------------
// Static singleton
// ---------------------------------------------------------------------------

static mut G_MCA: AppleMca = AppleMca {
    base:         0,
    num_clusters: 0,
    ready:        AtomicBool::new(false),
    clusters:     [
        ClusterState { base: 0, enabled: false, tx_running: false, rx_running: false,
                       tx_dma_cb: DmaSlot::empty(), rx_dma_cb: DmaSlot::empty() },
        ClusterState { base: 0, enabled: false, tx_running: false, rx_running: false,
                       tx_dma_cb: DmaSlot::empty(), rx_dma_cb: DmaSlot::empty() },
        ClusterState { base: 0, enabled: false, tx_running: false, rx_running: false,
                       tx_dma_cb: DmaSlot::empty(), rx_dma_cb: DmaSlot::empty() },
        ClusterState { base: 0, enabled: false, tx_running: false, rx_running: false,
                       tx_dma_cb: DmaSlot::empty(), rx_dma_cb: DmaSlot::empty() },
        ClusterState { base: 0, enabled: false, tx_running: false, rx_running: false,
                       tx_dma_cb: DmaSlot::empty(), rx_dma_cb: DmaSlot::empty() },
        ClusterState { base: 0, enabled: false, tx_running: false, rx_running: false,
                       tx_dma_cb: DmaSlot::empty(), rx_dma_cb: DmaSlot::empty() },
    ],
};

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Initialize the Apple MCA audio controller.
///
/// `base`         — MMIO base address (cluster 0 is at `base + CLUSTER_STRIDE`).
/// `num_clusters` — number of audio clusters (1–6).
///
/// Returns a non-null handle on success, NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_init(base: u64, num_clusters: u32) -> *mut AppleMca {
    if base == 0 || num_clusters == 0 || num_clusters > MAX_CLUSTERS as u32 {
        return core::ptr::null_mut();
    }
    let mca = unsafe { &mut *(&raw mut G_MCA) };
    mca.base         = base as usize;
    mca.num_clusters = num_clusters;
    mca.ready        = AtomicBool::new(false);

    for i in 0..num_clusters as usize {
        mca.clusters[i] = ClusterState::new(base as usize + CLUSTER_STRIDE * (i + 1));
    }
    for i in num_clusters as usize..MAX_CLUSTERS {
        mca.clusters[i] = ClusterState::new(0);
    }

    mca.init();
    mca as *mut AppleMca
}

/// Release resources held by the MCA driver.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_free(mca: *mut AppleMca) {
    if mca.is_null() { return; }
    let m = unsafe { &mut *mca };
    m.ready.store(false, Ordering::Release);
    for c in m.clusters.iter_mut() {
        c.disable();
    }
    m.base = 0;
}

/// Configure a cluster for I2S playback (TX).
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_setup_playback(
    mca:       *mut AppleMca,
    cluster:   u32,
    mclk_sel:  u32,
    mclk_hz:   u32,
    sample_hz: u32,
) -> i32 {
    if mca.is_null() { return -22; }
    unsafe { (*mca).setup_playback_i2s(cluster, mclk_sel, mclk_hz, sample_hz) }
}

/// Configure a cluster for I2S capture (RX).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_setup_capture(
    mca:       *mut AppleMca,
    cluster:   u32,
    mclk_sel:  u32,
    mclk_hz:   u32,
    sample_hz: u32,
) -> i32 {
    if mca.is_null() { return -22; }
    unsafe { (*mca).setup_capture_i2s(cluster, mclk_sel, mclk_hz, sample_hz) }
}

/// Start TX DMA for `cluster`. `callback` is called on completion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_start_tx_dma(
    mca:       *mut AppleMca,
    cluster:   u32,
    phys_addr: u64,
    len_bytes: u32,
    callback:  DmaCallbackFn,
    cookie:    *mut (),
) -> i32 {
    if mca.is_null() { return -22; }
    unsafe { (*mca).start_tx_dma(cluster, phys_addr, len_bytes, callback, cookie) }
}

/// Start RX DMA for `cluster`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_start_rx_dma(
    mca:       *mut AppleMca,
    cluster:   u32,
    phys_addr: u64,
    len_bytes: u32,
    callback:  DmaCallbackFn,
    cookie:    *mut (),
) -> i32 {
    if mca.is_null() { return -22; }
    unsafe { (*mca).start_rx_dma(cluster, phys_addr, len_bytes, callback, cookie) }
}

/// Stop DMA on `cluster`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_stop(mca: *mut AppleMca, cluster: u32) -> i32 {
    if mca.is_null() { return -22; }
    unsafe { (*mca).stop_cluster(cluster) }
}

/// Handle interrupt for `cluster` — must be called from the AIC IRQ handler.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_handle_irq(mca: *mut AppleMca, cluster: u32) {
    if mca.is_null() { return; }
    unsafe { (*mca).handle_irq(cluster) }
}

/// Polled TX write: push up to `count` 32-bit samples from `buf`.
/// Returns number of samples written, or negative errno on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_tx_write(
    mca:     *const AppleMca,
    cluster: u32,
    buf:     *const u32,
    count:   usize,
) -> i32 {
    if mca.is_null() || buf.is_null() { return -22; }
    let slice = unsafe { core::slice::from_raw_parts(buf, count) };
    unsafe { (*mca).tx_write(cluster, slice) }
}

/// Polled RX read: drain up to `count` 32-bit samples into `buf`.
/// Returns number of samples read, or negative errno on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_mca_rx_read(
    mca:     *const AppleMca,
    cluster: u32,
    buf:     *mut u32,
    count:   usize,
) -> i32 {
    if mca.is_null() || buf.is_null() { return -22; }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, count) };
    unsafe { (*mca).rx_read(cluster, slice) }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
