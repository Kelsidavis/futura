// SPDX-License-Identifier: MPL-2.0
//
// Intel/AMD High Definition Audio (HDA) Controller Driver
//
// Implements the Intel HDA specification Rev 1.0a for PCIe-attached
// audio controllers, targeting AMD Ryzen AM4/AM5 platforms (ALC887,
// ALC1200, ALC1220, etc. commonly paired with AMD chipsets).
//
// Architecture:
//   - CORB/RIRB command transport (256-entry ring buffers)
//   - Codec discovery via STATESTS after controller reset
//   - Widget tree enumeration (root -> AFG -> DAC/Pin widgets)
//   - Output stream descriptor with BDL for PCM playback
//   - Polling-based completion (interrupt support planned)
//
// PCI class: 04h (Multimedia), subclass 03h (HD Audio)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ffi::c_void;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use common::{
    alloc, alloc_page, free, log, map_mmio_region, unmap_mmio_region,
    thread_yield, MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
}

// ── PCI device structure (mirrors kernel/pci.h) ──

#[repr(C)]
struct PciDevice {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    revision: u8,
    header_type: u8,
    subsys_vendor: u16,
    subsys_id: u16,
    irq_line: u8,
}

// ── PCI configuration space I/O ──

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;

fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        let val: u32;
        core::arch::asm!("in eax, dx", in("dx") PCI_CONFIG_DATA, out("eax") val);
        val
    }
}

fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

// ── HDA Controller Registers (MMIO BAR0) ──
// Intel HD Audio Specification Rev 1.0a, Section 3

const HDA_REG_GCAP: usize = 0x00;       // Global Capabilities (16-bit)
const HDA_REG_VMIN: usize = 0x02;       // Minor Version (8-bit)
const HDA_REG_VMAJ: usize = 0x03;       // Major Version (8-bit)
const HDA_REG_OUTPAY: usize = 0x04;     // Output Payload Capability (16-bit)
const HDA_REG_INPAY: usize = 0x06;      // Input Payload Capability (16-bit)
const HDA_REG_GCTL: usize = 0x08;       // Global Control (32-bit)
const HDA_REG_WAKEEN: usize = 0x0C;     // Wake Enable (16-bit)
const HDA_REG_STATESTS: usize = 0x0E;   // State Change Status (16-bit)
const HDA_REG_GSTS: usize = 0x10;       // Global Status (16-bit)
const HDA_REG_INTCTL: usize = 0x20;     // Interrupt Control (32-bit)
const HDA_REG_INTSTS: usize = 0x24;     // Interrupt Status (32-bit)
const HDA_REG_WALCLK: usize = 0x30;     // Wall Clock Counter (32-bit)
const HDA_REG_SSYNC: usize = 0x38;      // Stream Synchronization (32-bit)

// CORB registers
const HDA_REG_CORBLBASE: usize = 0x40;  // CORB Lower Base Address (32-bit)
const HDA_REG_CORBUBASE: usize = 0x44;  // CORB Upper Base Address (32-bit)
const HDA_REG_CORBWP: usize = 0x48;     // CORB Write Pointer (16-bit)
const HDA_REG_CORBRP: usize = 0x4A;     // CORB Read Pointer (16-bit)
const HDA_REG_CORBCTL: usize = 0x4C;    // CORB Control (8-bit)
const HDA_REG_CORBSTS: usize = 0x4D;    // CORB Status (8-bit)
const HDA_REG_CORBSIZE: usize = 0x4E;   // CORB Size (8-bit)

// RIRB registers
const HDA_REG_RIRBLBASE: usize = 0x50;  // RIRB Lower Base Address (32-bit)
const HDA_REG_RIRBUBASE: usize = 0x54;  // RIRB Upper Base Address (32-bit)
const HDA_REG_RIRBWP: usize = 0x58;     // RIRB Write Pointer (16-bit)
const HDA_REG_RINTCNT: usize = 0x5A;    // Response Interrupt Count (16-bit)
const HDA_REG_RIRBCTL: usize = 0x5C;    // RIRB Control (8-bit)
const HDA_REG_RIRBSTS: usize = 0x5D;    // RIRB Status (8-bit)
const HDA_REG_RIRBSIZE: usize = 0x5E;   // RIRB Size (8-bit)

// GCTL bits
const GCTL_CRST: u32 = 1 << 0;          // Controller Reset
const GCTL_FCNTRL: u32 = 1 << 1;        // Flush Control
const GCTL_UNSOL: u32 = 1 << 8;         // Accept Unsolicited Responses

// CORBCTL bits
const CORBCTL_MEIE: u8 = 1 << 0;        // Memory Error Interrupt Enable
const CORBCTL_RUN: u8 = 1 << 1;         // CORB DMA Engine Run

// CORBRP bits
const CORBRP_RST: u16 = 1 << 15;        // CORB Read Pointer Reset

// RIRBCTL bits
const RIRBCTL_RINTCTL: u8 = 1 << 0;     // Response Interrupt Control
const RIRBCTL_RUN: u8 = 1 << 1;         // RIRB DMA Engine Run
const RIRBCTL_OIC: u8 = 1 << 2;         // Overrun Interrupt Control

// RIRBSTS bits
const RIRBSTS_RINTFL: u8 = 1 << 0;      // Response Interrupt
const RIRBSTS_OIS: u8 = 1 << 2;         // Overrun Interrupt Status

// RIRBWP bits
const RIRBWP_RST: u16 = 1 << 15;        // RIRB Write Pointer Reset

// INTCTL bits
const INTCTL_GIE: u32 = 1 << 31;        // Global Interrupt Enable
const INTCTL_CIE: u32 = 1 << 30;        // Controller Interrupt Enable

// Stream Descriptor offsets (each descriptor block is 0x20 bytes)
// First output stream base = 0x80 + (num_iss * 0x20)
const SD_CTL: usize = 0x00;             // Stream Descriptor Control (24-bit, access as 16+8)
const SD_CTL_STS: usize = 0x03;         // SD_CTL upper byte / SD_STS (8-bit)
const SD_STS: usize = 0x03;             // Stream Descriptor Status (8-bit)
const SD_LPIB: usize = 0x04;            // Link Position In Buffer (32-bit)
const SD_CBL: usize = 0x08;             // Cyclic Buffer Length (32-bit)
const SD_LVI: usize = 0x0C;             // Last Valid Index (16-bit)
const SD_FIFOS: usize = 0x10;           // FIFO Size (16-bit)
const SD_FMT: usize = 0x12;             // Stream Format (16-bit)
const SD_BDLPL: usize = 0x18;           // BDL Pointer Lower (32-bit)
const SD_BDLPU: usize = 0x1C;           // BDL Pointer Upper (32-bit)

// SD_CTL bits (lower 16 bits at offset +0x00)
const SD_CTL_SRST: u32 = 1 << 0;        // Stream Reset
const SD_CTL_RUN: u32 = 1 << 1;         // Stream Run
const SD_CTL_IOCE: u32 = 1 << 2;        // Interrupt on Completion Enable
const SD_CTL_FEIE: u32 = 1 << 3;        // FIFO Error Interrupt Enable
const SD_CTL_DEIE: u32 = 1 << 4;        // Descriptor Error Interrupt Enable
// Bits 20:23 = Stream Number (in the upper byte at offset +0x02)
const SD_CTL_STRIPE_SHIFT: u32 = 16;    // Stripe Control (bits 17:16)
const SD_CTL_TP: u32 = 1 << 18;         // Traffic Priority
const SD_CTL_DIR: u32 = 1 << 19;        // Bidirectional Direction Control
const SD_CTL_STRM_SHIFT: u32 = 20;      // Stream Number (bits 23:20)

// SD_STS bits
const SD_STS_BCIS: u8 = 1 << 2;         // Buffer Completion Interrupt Status
const SD_STS_FIFOE: u8 = 1 << 3;        // FIFO Error
const SD_STS_DESE: u8 = 1 << 4;         // Descriptor Error

// ── Stream Format (SD_FMT / verb SET_STREAM_FORMAT) ──
// Intel HDA Spec Rev 1.0a, Section 3.7.1
//
// Bits [15]    : Stream Type (0 = PCM, 1 = non-PCM)
// Bits [14]    : Sample Base Rate (0 = 48 kHz, 1 = 44.1 kHz)
// Bits [13:11] : Sample Base Rate Multiple (0=x1, 1=x2, 2=x3, 3=x4)
// Bits [10:8]  : Sample Base Rate Divisor (0=/1, 1=/2, 2=/3, ..., 7=/8)
// Bits [7:4]   : Bits Per Sample (000=8, 001=16, 010=20, 011=24, 100=32)
// Bits [3:0]   : Number of Channels - 1

const FMT_BASE_48K: u16 = 0 << 14;
const FMT_BASE_44K: u16 = 1 << 14;
const FMT_MULT_X1: u16 = 0 << 11;
const FMT_MULT_X2: u16 = 1 << 11;
const FMT_MULT_X4: u16 = 3 << 11;
const FMT_DIV_1: u16 = 0 << 8;
const FMT_DIV_2: u16 = 1 << 8;
const FMT_DIV_3: u16 = 2 << 8;
const FMT_BITS_8: u16 = 0 << 4;
const FMT_BITS_16: u16 = 1 << 4;
const FMT_BITS_20: u16 = 2 << 4;
const FMT_BITS_24: u16 = 3 << 4;
const FMT_BITS_32: u16 = 4 << 4;
const FMT_CHAN_STEREO: u16 = 1;          // channels - 1

// Default format: 48 kHz, 16-bit, stereo
const FMT_DEFAULT: u16 = FMT_BASE_48K | FMT_MULT_X1 | FMT_DIV_1 | FMT_BITS_16 | FMT_CHAN_STEREO;

// ── HDA Codec Verbs ──
// Intel HDA Spec Rev 1.0a, Section 7

// GET verbs (12-bit verb ID, 8-bit payload for get-parameter)
const VERB_GET_PARAMETER: u32 = 0xF0000;
const VERB_GET_CONN_SELECT: u32 = 0xF0100;
const VERB_GET_CONN_LIST: u32 = 0xF0200;
const VERB_GET_AMP_GAIN_MUTE: u32 = 0xB0000;
const VERB_GET_STREAM_FORMAT: u32 = 0xA0000;
const VERB_GET_PIN_WIDGET_CTL: u32 = 0xF0700;
const VERB_GET_PIN_SENSE: u32 = 0xF0900;
const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C00;
const VERB_GET_EAPD_BTLENABLE: u32 = 0xF0C00;
const VERB_GET_POWER_STATE: u32 = 0xF0500;

// SET verbs (4-bit verb ID, 16-bit or 8-bit payload)
const VERB_SET_STREAM_FORMAT: u32 = 0x20000;
const VERB_SET_AMP_GAIN_MUTE: u32 = 0x30000;
const VERB_SET_PIN_WIDGET_CTL: u32 = 0x70700;
const VERB_SET_CONN_SELECT: u32 = 0x70100;
const VERB_SET_EAPD_BTLENABLE: u32 = 0x70C00;
const VERB_SET_POWER_STATE: u32 = 0x70500;
const VERB_SET_CHANNEL_STREAM_ID: u32 = 0x70600;

// Parameter IDs (used with GET_PARAMETER)
const PARAM_VENDOR_ID: u32 = 0x00;
const PARAM_REVISION_ID: u32 = 0x02;
const PARAM_SUB_NODE_COUNT: u32 = 0x04;
const PARAM_FUNC_GROUP_TYPE: u32 = 0x05;
const PARAM_AUDIO_WIDGET_CAP: u32 = 0x09;
const PARAM_PCM_SIZES_RATES: u32 = 0x0A;
const PARAM_STREAM_FORMATS: u32 = 0x0B;
const PARAM_PIN_CAPS: u32 = 0x0C;
const PARAM_IN_AMP_CAP: u32 = 0x0D;
const PARAM_OUT_AMP_CAP: u32 = 0x12;
const PARAM_CONN_LIST_LEN: u32 = 0x0E;
const PARAM_POWER_STATES: u32 = 0x0F;
const PARAM_GPIO_COUNT: u32 = 0x11;
const PARAM_VOLUME_KNOB_CAP: u32 = 0x13;

// Widget types (from Audio Widget Capabilities parameter, bits 23:20)
const WIDGET_TYPE_AUDIO_OUTPUT: u8 = 0x0;
const WIDGET_TYPE_AUDIO_INPUT: u8 = 0x1;
const WIDGET_TYPE_AUDIO_MIXER: u8 = 0x2;
const WIDGET_TYPE_AUDIO_SELECTOR: u8 = 0x3;
const WIDGET_TYPE_PIN_COMPLEX: u8 = 0x4;
const WIDGET_TYPE_POWER_WIDGET: u8 = 0x5;
const WIDGET_TYPE_VOLUME_KNOB: u8 = 0x6;
const WIDGET_TYPE_BEEP_GEN: u8 = 0x7;
const WIDGET_TYPE_VENDOR: u8 = 0xF;

// Pin configuration default register fields
// Bits [31:30] = Port Connectivity (0=jack, 1=none, 2=fixed, 3=both)
// Bits [29:28] = Location (gross)
// Bits [27:24] = Location (fine)
// Bits [23:20] = Default Device (0=line-out, 1=speaker, 2=hp-out, ...)
// Bits [19:16] = Connection Type
// Bits [15:12] = Color
// Bits [11:8]  = Misc
// Bits [7:4]   = Default Association
// Bits [3:0]   = Sequence

const PIN_DEV_LINE_OUT: u8 = 0x0;
const PIN_DEV_SPEAKER: u8 = 0x1;
const PIN_DEV_HP_OUT: u8 = 0x2;
const PIN_DEV_CD: u8 = 0x3;
const PIN_DEV_SPDIF_OUT: u8 = 0x4;
const PIN_DEV_DIG_OTHER_OUT: u8 = 0x5;
const PIN_DEV_MODEM_LINE_SIDE: u8 = 0x6;
const PIN_DEV_MODEM_HANDSET_SIDE: u8 = 0x7;
const PIN_DEV_LINE_IN: u8 = 0x8;
const PIN_DEV_AUX: u8 = 0x9;
const PIN_DEV_MIC_IN: u8 = 0xA;

// Pin widget control bits
const PIN_CTL_OUT_EN: u8 = 1 << 6;      // Output Enable
const PIN_CTL_IN_EN: u8 = 1 << 5;       // Input Enable
const PIN_CTL_HP_EN: u8 = 1 << 7;       // Headphone Amplifier Enable

// AMP gain/mute verb payload bits
const AMP_SET_OUTPUT: u32 = 1 << 15;
const AMP_SET_INPUT: u32 = 1 << 14;
const AMP_SET_LEFT: u32 = 1 << 13;
const AMP_SET_RIGHT: u32 = 1 << 12;
const AMP_SET_INDEX_SHIFT: u32 = 8;
const AMP_MUTE: u32 = 1 << 7;

// EAPD/BTL Enable bits
const EAPD_BTL_ENABLE_EAPD: u32 = 1 << 1;

// ── Buffer Descriptor List Entry ──
// Intel HDA Spec Rev 1.0a, Section 3.6.3

#[repr(C)]
#[derive(Clone, Copy)]
struct BdlEntry {
    addr: u64,      // Physical address of buffer
    length: u32,    // Buffer length in bytes
    ioc: u32,       // Bit 0 = Interrupt on Completion
}

const _: () = assert!(core::mem::size_of::<BdlEntry>() == 16);

// ── CORB/RIRB entry types ──

// CORB entry: 32-bit verb (codec_addr[31:28] | node_id[27:20] | verb_payload[19:0])
// RIRB entry: 64-bit response (response[31:0] | response_ex[63:32])
//   response_ex: codec_addr[3:0] in bits [3:0], unsolicited flag in bit 4

#[repr(C)]
#[derive(Clone, Copy)]
struct RirbEntry {
    response: u32,
    response_ex: u32,
}

const _: () = assert!(core::mem::size_of::<RirbEntry>() == 8);

// ── Audio stream configuration ──

const MAX_CODECS: usize = 15;
const MAX_WIDGETS: usize = 128;
const MAX_CONN_LIST: usize = 16;
const BDL_ENTRIES: usize = 32;
const CORB_ENTRIES: usize = 256;
const RIRB_ENTRIES: usize = 256;

// Audio buffer: 32 BDL entries, each pointing to a 4 KiB fragment = 128 KiB total
const FRAG_SIZE: usize = 4096;
const TOTAL_BUF_SIZE: usize = BDL_ENTRIES * FRAG_SIZE;

// ── Widget descriptor ──

#[derive(Clone, Copy)]
struct Widget {
    nid: u8,
    wtype: u8,
    caps: u32,
    pin_cfg: u32,
    pin_caps: u32,
    amp_out_cap: u32,
    amp_in_cap: u32,
    conn_list_len: u8,
    conn_list: [u8; MAX_CONN_LIST],
}

impl Widget {
    const fn zeroed() -> Self {
        Self {
            nid: 0,
            wtype: 0,
            caps: 0,
            pin_cfg: 0,
            pin_caps: 0,
            amp_out_cap: 0,
            amp_in_cap: 0,
            conn_list_len: 0,
            conn_list: [0; MAX_CONN_LIST],
        }
    }
}

// ── Codec descriptor ──

struct Codec {
    addr: u8,
    vendor_id: u32,
    revision_id: u32,
    afg_nid: u8,              // Audio Function Group node ID
    afg_start_nid: u8,        // First widget NID in AFG
    afg_num_nodes: u8,        // Number of widgets in AFG
    widgets: [Widget; MAX_WIDGETS],
    num_widgets: usize,
    // Discovered output path
    dac_nid: u8,              // DAC widget for output
    pin_nid: u8,              // Output pin widget
    mixer_nid: u8,            // Optional mixer in the path
}

impl Codec {
    const fn zeroed() -> Self {
        Self {
            addr: 0,
            vendor_id: 0,
            revision_id: 0,
            afg_nid: 0,
            afg_start_nid: 0,
            afg_num_nodes: 0,
            widgets: [Widget::zeroed(); MAX_WIDGETS],
            num_widgets: 0,
            dac_nid: 0,
            pin_nid: 0,
            mixer_nid: 0,
        }
    }
}

// ── Controller state ──

struct HdaController {
    bar0: *mut u8,
    bar0_size: usize,
    bus: u8,
    dev: u8,
    func: u8,

    // GCAP decoded
    num_oss: u8,              // Number of Output Streams
    num_iss: u8,              // Number of Input Streams
    num_bss: u8,              // Number of Bidirectional Streams

    // CORB/RIRB
    corb: *mut u32,           // CORB buffer (256 x 4 bytes = 1 KiB)
    corb_phys: u64,
    corb_wp: u16,
    rirb: *mut RirbEntry,     // RIRB buffer (256 x 8 bytes = 2 KiB)
    rirb_phys: u64,
    rirb_rp: u16,

    // Codecs
    codecs: [Codec; MAX_CODECS],
    num_codecs: u32,

    // Output stream (first output SD)
    out_sd_base: usize,       // MMIO offset of the output stream descriptor
    out_stream_num: u8,       // Stream number (1-15) assigned to output
    out_stream_tag: u8,       // Stream tag for codec channel/stream verb

    // BDL and audio buffer
    bdl: *mut BdlEntry,       // BDL (32 entries x 16 bytes = 512 bytes)
    bdl_phys: u64,
    audio_buf: *mut u8,       // Audio buffer (32 x 4 KiB = 128 KiB)
    audio_buf_phys: u64,

    // Current format
    sample_rate: u32,
    bits: u32,
    channels: u32,
    stream_fmt: u16,

    // Write cursor within the audio buffer
    write_pos: usize,

    // Active codec index for output
    active_codec: usize,

    // Playback state
    playing: bool,
}

struct HdaGlobal(UnsafeCell<Option<HdaController>>);
unsafe impl Sync for HdaGlobal {}

static HDA: HdaGlobal = HdaGlobal(UnsafeCell::new(None));

// ── MMIO helpers ──

fn mmio_read8(base: *mut u8, offset: usize) -> u8 {
    unsafe { read_volatile(base.add(offset)) }
}

fn mmio_write8(base: *mut u8, offset: usize, val: u8) {
    unsafe { write_volatile(base.add(offset), val) }
}

fn mmio_read16(base: *mut u8, offset: usize) -> u16 {
    unsafe { read_volatile(base.add(offset) as *const u16) }
}

fn mmio_write16(base: *mut u8, offset: usize, val: u16) {
    unsafe { write_volatile(base.add(offset) as *mut u16, val) }
}

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Physical address helper ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { rust_virt_to_phys(ptr as *const c_void) }
}

// ── Delay helper (busy-wait spin, ~microsecond granularity) ──

fn delay_us(us: u32) {
    // Rough busy-wait; actual timing depends on CPU frequency.
    // Each iteration is a few nanoseconds on a multi-GHz CPU.
    for _ in 0..(us as u64 * 100) {
        core::hint::spin_loop();
    }
}

// ── PCI discovery ──

fn find_hda_pci() -> Option<(u8, u8, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        // HD Audio: class=04 (Multimedia), subclass=03 (HD Audio)
        if dev.class_code == 0x04 && dev.subclass == 0x03 {
            return Some((dev.bus, dev.dev, dev.func));
        }
    }
    None
}

// ── Controller reset ──
// Intel HDA Spec Rev 1.0a, Section 3.3.7 (GCTL)

fn controller_reset(bar0: *mut u8) -> bool {
    // Enter reset: clear CRST bit
    let gctl = mmio_read32(bar0, HDA_REG_GCTL);
    mmio_write32(bar0, HDA_REG_GCTL, gctl & !GCTL_CRST);

    // Wait for CRST to read 0 (controller in reset)
    for _ in 0..1000u32 {
        if mmio_read32(bar0, HDA_REG_GCTL) & GCTL_CRST == 0 {
            break;
        }
        delay_us(10);
    }

    if mmio_read32(bar0, HDA_REG_GCTL) & GCTL_CRST != 0 {
        log("hda: failed to enter reset");
        return false;
    }

    // Spec requires minimum 100us in reset for codec PLL lock
    delay_us(500);

    // Exit reset: set CRST bit
    let gctl = mmio_read32(bar0, HDA_REG_GCTL);
    mmio_write32(bar0, HDA_REG_GCTL, gctl | GCTL_CRST);

    // Wait for CRST to read 1 (controller out of reset)
    for _ in 0..1000u32 {
        if mmio_read32(bar0, HDA_REG_GCTL) & GCTL_CRST != 0 {
            break;
        }
        delay_us(100);
    }

    if mmio_read32(bar0, HDA_REG_GCTL) & GCTL_CRST == 0 {
        log("hda: failed to exit reset");
        return false;
    }

    // Spec: wait at least 521us (25 frames) after CRST=1 for codecs to
    // enumerate and send status change notifications
    delay_us(1000);

    true
}

// ── CORB setup ──
// Intel HDA Spec Rev 1.0a, Section 3.4 (CORB)

fn corb_init(ctrl: &mut HdaController) -> bool {
    let bar0 = ctrl.bar0;

    // Stop CORB DMA
    mmio_write8(bar0, HDA_REG_CORBCTL, 0);
    for _ in 0..1000u32 {
        if mmio_read8(bar0, HDA_REG_CORBCTL) & CORBCTL_RUN == 0 {
            break;
        }
        delay_us(10);
    }

    // Read CORBSIZE register to check supported sizes
    let corbsize = mmio_read8(bar0, HDA_REG_CORBSIZE);
    let size_cap = (corbsize >> 4) & 0x0F;
    // Select 256 entries if supported, else 16, else 2
    let size_sel: u8;
    if size_cap & 0x04 != 0 {
        size_sel = 0x02; // 256 entries
    } else if size_cap & 0x02 != 0 {
        size_sel = 0x01; // 16 entries
    } else {
        size_sel = 0x00; // 2 entries
    }
    mmio_write8(bar0, HDA_REG_CORBSIZE, size_sel);

    // Set CORB base address (must be 128-byte aligned; page-aligned is fine)
    mmio_write32(bar0, HDA_REG_CORBLBASE, ctrl.corb_phys as u32);
    mmio_write32(bar0, HDA_REG_CORBUBASE, (ctrl.corb_phys >> 32) as u32);

    // Reset CORB Read Pointer:
    // Set CORBRP Reset bit, wait for it to read 1, then clear it, wait for 0
    mmio_write16(bar0, HDA_REG_CORBRP, CORBRP_RST);
    for _ in 0..1000u32 {
        if mmio_read16(bar0, HDA_REG_CORBRP) & CORBRP_RST != 0 {
            break;
        }
        delay_us(10);
    }
    mmio_write16(bar0, HDA_REG_CORBRP, 0);
    for _ in 0..1000u32 {
        if mmio_read16(bar0, HDA_REG_CORBRP) & CORBRP_RST == 0 {
            break;
        }
        delay_us(10);
    }

    // Reset CORB Write Pointer
    ctrl.corb_wp = 0;
    mmio_write16(bar0, HDA_REG_CORBWP, 0);

    // Start CORB DMA engine
    mmio_write8(bar0, HDA_REG_CORBCTL, CORBCTL_RUN);
    for _ in 0..1000u32 {
        if mmio_read8(bar0, HDA_REG_CORBCTL) & CORBCTL_RUN != 0 {
            return true;
        }
        delay_us(10);
    }

    log("hda: CORB DMA engine failed to start");
    false
}

// ── RIRB setup ──
// Intel HDA Spec Rev 1.0a, Section 3.5 (RIRB)

fn rirb_init(ctrl: &mut HdaController) -> bool {
    let bar0 = ctrl.bar0;

    // Stop RIRB DMA
    mmio_write8(bar0, HDA_REG_RIRBCTL, 0);
    for _ in 0..1000u32 {
        if mmio_read8(bar0, HDA_REG_RIRBCTL) & RIRBCTL_RUN == 0 {
            break;
        }
        delay_us(10);
    }

    // Read RIRBSIZE register to check supported sizes
    let rirbsize = mmio_read8(bar0, HDA_REG_RIRBSIZE);
    let size_cap = (rirbsize >> 4) & 0x0F;
    let size_sel: u8;
    if size_cap & 0x04 != 0 {
        size_sel = 0x02; // 256 entries
    } else if size_cap & 0x02 != 0 {
        size_sel = 0x01; // 16 entries
    } else {
        size_sel = 0x00; // 2 entries
    }
    mmio_write8(bar0, HDA_REG_RIRBSIZE, size_sel);

    // Set RIRB base address
    mmio_write32(bar0, HDA_REG_RIRBLBASE, ctrl.rirb_phys as u32);
    mmio_write32(bar0, HDA_REG_RIRBUBASE, (ctrl.rirb_phys >> 32) as u32);

    // Reset RIRB Write Pointer
    mmio_write16(bar0, HDA_REG_RIRBWP, RIRBWP_RST);

    // Set RINTCNT to 1 (generate interrupt after each response)
    mmio_write16(bar0, HDA_REG_RINTCNT, 1);

    // Initialize our read pointer to 0
    ctrl.rirb_rp = 0;

    // Start RIRB DMA engine with response interrupt control enabled
    mmio_write8(bar0, HDA_REG_RIRBCTL, RIRBCTL_RUN | RIRBCTL_RINTCTL);
    for _ in 0..1000u32 {
        if mmio_read8(bar0, HDA_REG_RIRBCTL) & RIRBCTL_RUN != 0 {
            return true;
        }
        delay_us(10);
    }

    log("hda: RIRB DMA engine failed to start");
    false
}

// ── Verb send/receive via CORB/RIRB ──

/// Build a codec verb command word.
/// Format: [31:28] codec address, [27:20] NID, [19:0] verb+payload
fn make_verb(codec_addr: u8, nid: u8, verb: u32) -> u32 {
    ((codec_addr as u32 & 0x0F) << 28) | ((nid as u32) << 20) | (verb & 0x000FFFFF)
}

/// Send a verb command via CORB and wait for the response from RIRB.
/// Returns the 32-bit response or 0xFFFFFFFF on timeout.
fn codec_verb(ctrl: &mut HdaController, codec_addr: u8, nid: u8, verb: u32) -> u32 {
    let cmd = make_verb(codec_addr, nid, verb);
    let bar0 = ctrl.bar0;

    // Write command to CORB
    let wp = (ctrl.corb_wp + 1) % CORB_ENTRIES as u16;
    unsafe {
        write_volatile(ctrl.corb.add(wp as usize), cmd);
    }
    fence(Ordering::SeqCst);
    ctrl.corb_wp = wp;
    mmio_write16(bar0, HDA_REG_CORBWP, wp);

    // Poll RIRB for response
    for _ in 0..100_000u32 {
        // Clear RIRBSTS interrupt flag if set
        let sts = mmio_read8(bar0, HDA_REG_RIRBSTS);
        if sts & RIRBSTS_RINTFL != 0 {
            mmio_write8(bar0, HDA_REG_RIRBSTS, RIRBSTS_RINTFL);
        }

        let rirb_wp = mmio_read16(bar0, HDA_REG_RIRBWP) & 0xFF;
        if rirb_wp != ctrl.rirb_rp {
            // Advance our read pointer
            ctrl.rirb_rp = (ctrl.rirb_rp + 1) % RIRB_ENTRIES as u16;
            let entry = unsafe { read_volatile(ctrl.rirb.add(ctrl.rirb_rp as usize)) };

            // Verify this response is from the expected codec
            let resp_codec = entry.response_ex & 0x0F;
            if resp_codec == codec_addr as u32 {
                return entry.response;
            }
            // If unsolicited (bit 4 set), discard and keep waiting
            if entry.response_ex & 0x10 != 0 {
                continue;
            }
            // Response from different codec; return it anyway (caller
            // typically only talks to one codec at a time)
            return entry.response;
        }
        delay_us(1);
    }

    // Timeout
    0xFFFFFFFF
}

/// Convenience: send GET_PARAMETER verb
fn codec_get_param(ctrl: &mut HdaController, codec_addr: u8, nid: u8, param: u32) -> u32 {
    codec_verb(ctrl, codec_addr, nid, VERB_GET_PARAMETER | (param & 0xFF))
}

// ── Codec discovery via STATESTS ──

fn discover_codecs(ctrl: &mut HdaController) -> u32 {
    let statests = mmio_read16(ctrl.bar0, HDA_REG_STATESTS);
    let mut count = 0u32;

    for addr in 0..MAX_CODECS {
        if statests & (1 << addr) != 0 {
            let vendor = codec_get_param(ctrl, addr as u8, 0, PARAM_VENDOR_ID);
            if vendor == 0 || vendor == 0xFFFFFFFF {
                continue;
            }
            let revision = codec_get_param(ctrl, addr as u8, 0, PARAM_REVISION_ID);

            unsafe {
                fut_printf(
                    b"hda: codec %d: vendor=%04x:%04x rev=%08x\n\0".as_ptr(),
                    addr as u32,
                    (vendor >> 16) & 0xFFFF,
                    vendor & 0xFFFF,
                    revision,
                );
            }

            ctrl.codecs[count as usize].addr = addr as u8;
            ctrl.codecs[count as usize].vendor_id = vendor;
            ctrl.codecs[count as usize].revision_id = revision;

            // Get subordinate node count from root (NID 0)
            let sub = codec_get_param(ctrl, addr as u8, 0, PARAM_SUB_NODE_COUNT);
            let start_nid = ((sub >> 16) & 0xFF) as u8;
            let num_nodes = (sub & 0xFF) as u8;

            // Find Audio Function Group (type=0x01)
            for n in 0..num_nodes {
                let nid = start_nid + n;
                let ftype = codec_get_param(ctrl, addr as u8, nid, PARAM_FUNC_GROUP_TYPE);
                let node_type = ftype & 0xFF;
                if node_type == 0x01 {
                    // Audio Function Group found
                    ctrl.codecs[count as usize].afg_nid = nid;

                    // Power up the AFG (set power state D0)
                    codec_verb(ctrl, addr as u8, nid, VERB_SET_POWER_STATE | 0x00);
                    delay_us(100);

                    unsafe {
                        fut_printf(
                            b"hda: codec %d: AFG at NID %d\n\0".as_ptr(),
                            addr as u32,
                            nid as u32,
                        );
                    }
                    break;
                }
            }

            count += 1;
        }
    }

    // Clear STATESTS by writing 1s to handled bits
    mmio_write16(ctrl.bar0, HDA_REG_STATESTS, statests);

    ctrl.num_codecs = count;
    count
}

// ── Widget enumeration ──

fn enumerate_widgets(ctrl: &mut HdaController, codec_idx: usize) {
    let codec_addr = ctrl.codecs[codec_idx].addr;
    let afg_nid = ctrl.codecs[codec_idx].afg_nid;

    if afg_nid == 0 {
        return;
    }

    // Get widgets under the AFG
    let sub = codec_get_param(ctrl, codec_addr, afg_nid, PARAM_SUB_NODE_COUNT);
    let start_nid = ((sub >> 16) & 0xFF) as u8;
    let num_nodes = (sub & 0xFF) as u8;

    ctrl.codecs[codec_idx].afg_start_nid = start_nid;
    ctrl.codecs[codec_idx].afg_num_nodes = num_nodes;

    let mut widx = 0usize;

    for n in 0..num_nodes as usize {
        if widx >= MAX_WIDGETS {
            break;
        }
        let nid = start_nid + n as u8;

        let caps = codec_get_param(ctrl, codec_addr, nid, PARAM_AUDIO_WIDGET_CAP);
        let wtype = ((caps >> 20) & 0x0F) as u8;

        let mut w = Widget::zeroed();
        w.nid = nid;
        w.wtype = wtype;
        w.caps = caps;

        // Get connection list
        let conn_len_raw = codec_get_param(ctrl, codec_addr, nid, PARAM_CONN_LIST_LEN);
        let long_form = (conn_len_raw >> 7) & 1;
        let conn_len = (conn_len_raw & 0x7F) as u8;
        w.conn_list_len = conn_len.min(MAX_CONN_LIST as u8);

        if conn_len > 0 && long_form == 0 {
            // Short form: 4 entries per 32-bit response
            let mut fetched = 0u8;
            let mut offset = 0u32;
            while fetched < w.conn_list_len {
                let resp = codec_verb(
                    ctrl,
                    codec_addr,
                    nid,
                    VERB_GET_CONN_LIST | (offset & 0xFF),
                );
                for j in 0..4u8 {
                    if fetched >= w.conn_list_len {
                        break;
                    }
                    w.conn_list[fetched as usize] = ((resp >> (j * 8)) & 0xFF) as u8;
                    fetched += 1;
                }
                offset += 4;
            }
        } else if conn_len > 0 && long_form != 0 {
            // Long form: 2 entries per 32-bit response (16-bit NIDs)
            let mut fetched = 0u8;
            let mut offset = 0u32;
            while fetched < w.conn_list_len {
                let resp = codec_verb(
                    ctrl,
                    codec_addr,
                    nid,
                    VERB_GET_CONN_LIST | (offset & 0xFF),
                );
                for j in 0..2u8 {
                    if fetched >= w.conn_list_len {
                        break;
                    }
                    w.conn_list[fetched as usize] = ((resp >> (j * 16)) & 0xFF) as u8;
                    fetched += 1;
                }
                offset += 2;
            }
        }

        match wtype {
            WIDGET_TYPE_PIN_COMPLEX => {
                w.pin_cfg = codec_verb(ctrl, codec_addr, nid, VERB_GET_CONFIG_DEFAULT);
                w.pin_caps = codec_get_param(ctrl, codec_addr, nid, PARAM_PIN_CAPS);
            }
            WIDGET_TYPE_AUDIO_OUTPUT | WIDGET_TYPE_AUDIO_MIXER => {
                w.amp_out_cap = codec_get_param(ctrl, codec_addr, nid, PARAM_OUT_AMP_CAP);
                w.amp_in_cap = codec_get_param(ctrl, codec_addr, nid, PARAM_IN_AMP_CAP);
            }
            _ => {}
        }

        ctrl.codecs[codec_idx].widgets[widx] = w;
        widx += 1;
    }

    ctrl.codecs[codec_idx].num_widgets = widx;

    unsafe {
        fut_printf(
            b"hda: codec %d: enumerated %d widgets (NID %d..%d)\n\0".as_ptr(),
            codec_addr as u32,
            widx as u32,
            start_nid as u32,
            (start_nid as u32) + (num_nodes as u32) - 1,
        );
    }
}

// ── Output path discovery ──
// Walk the codec graph to find: Pin (output) -> [Mixer] -> DAC

fn find_widget(codec: &Codec, nid: u8) -> Option<usize> {
    for i in 0..codec.num_widgets {
        if codec.widgets[i].nid == nid {
            return Some(i);
        }
    }
    None
}

fn find_output_path(ctrl: &mut HdaController, codec_idx: usize) -> bool {
    let codec = &ctrl.codecs[codec_idx];

    // First pass: find output pin widgets (headphone or line-out or speaker)
    // Prefer headphone, then line-out, then speaker
    let mut best_pin_idx: Option<usize> = None;
    let mut best_priority: u8 = 255;

    for i in 0..codec.num_widgets {
        let w = &codec.widgets[i];
        if w.wtype != WIDGET_TYPE_PIN_COMPLEX {
            continue;
        }

        let connectivity = (w.pin_cfg >> 30) & 0x03;
        if connectivity == 1 {
            // No physical connection
            continue;
        }

        let default_device = ((w.pin_cfg >> 20) & 0x0F) as u8;
        let priority = match default_device {
            PIN_DEV_HP_OUT => 0,
            PIN_DEV_LINE_OUT => 1,
            PIN_DEV_SPEAKER => 2,
            _ => continue,
        };

        if priority < best_priority {
            best_priority = priority;
            best_pin_idx = Some(i);
        }
    }

    let pin_idx = match best_pin_idx {
        Some(idx) => idx,
        None => {
            log("hda: no output pin widget found");
            return false;
        }
    };

    let pin_nid = codec.widgets[pin_idx].nid;

    // Walk the connection list from the pin to find a DAC
    // The path is typically: Pin -> Mixer -> DAC, or Pin -> DAC
    let mut dac_nid: u8 = 0;
    let mut mixer_nid: u8 = 0;

    let pin_conn_len = codec.widgets[pin_idx].conn_list_len;
    for c in 0..pin_conn_len as usize {
        let connected_nid = codec.widgets[pin_idx].conn_list[c];
        if let Some(widx) = find_widget(codec, connected_nid) {
            let w = &codec.widgets[widx];
            match w.wtype {
                WIDGET_TYPE_AUDIO_OUTPUT => {
                    // Direct pin -> DAC connection
                    dac_nid = connected_nid;
                    break;
                }
                WIDGET_TYPE_AUDIO_MIXER | WIDGET_TYPE_AUDIO_SELECTOR => {
                    // Pin -> Mixer/Selector, now look for DAC in its connections
                    mixer_nid = connected_nid;
                    let mix_conn_len = w.conn_list_len;
                    for mc in 0..mix_conn_len as usize {
                        let mix_connected = w.conn_list[mc];
                        if let Some(midx) = find_widget(codec, mix_connected) {
                            if codec.widgets[midx].wtype == WIDGET_TYPE_AUDIO_OUTPUT {
                                dac_nid = mix_connected;
                                break;
                            }
                        }
                    }
                    if dac_nid != 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    if dac_nid == 0 {
        // Fallback: scan all widgets for any Audio Output and hope it connects
        for i in 0..codec.num_widgets {
            if codec.widgets[i].wtype == WIDGET_TYPE_AUDIO_OUTPUT {
                dac_nid = codec.widgets[i].nid;
                break;
            }
        }
    }

    if dac_nid == 0 {
        log("hda: no DAC widget found");
        return false;
    }

    ctrl.codecs[codec_idx].pin_nid = pin_nid;
    ctrl.codecs[codec_idx].dac_nid = dac_nid;
    ctrl.codecs[codec_idx].mixer_nid = mixer_nid;

    let dev_name = match best_priority {
        0 => b"headphone\0".as_ptr(),
        1 => b"line-out\0".as_ptr(),
        _ => b"speaker\0".as_ptr(),
    };

    unsafe {
        fut_printf(
            b"hda: codec %d: output path: Pin NID %d (%s)\0".as_ptr(),
            ctrl.codecs[codec_idx].addr as u32,
            pin_nid as u32,
            dev_name,
        );
        if mixer_nid != 0 {
            fut_printf(
                b" -> Mixer NID %d\0".as_ptr(),
                mixer_nid as u32,
            );
        }
        fut_printf(
            b" -> DAC NID %d\n\0".as_ptr(),
            dac_nid as u32,
        );
    }

    true
}

// ── Stream format encoding ──

fn encode_stream_format(sample_rate: u32, bits: u32, channels: u32) -> u16 {
    // Base rate and multiplier/divisor
    let rate_bits: u16 = match sample_rate {
        8000 => FMT_BASE_48K | (5 << 8),           // 48000 / 6
        11025 => FMT_BASE_44K | (3 << 8),           // 44100 / 4
        16000 => FMT_BASE_48K | (2 << 8),           // 48000 / 3
        22050 => FMT_BASE_44K | (1 << 8),           // 44100 / 2
        32000 => FMT_BASE_48K | FMT_MULT_X2 | (2 << 8), // 48000 * 2 / 3
        44100 => FMT_BASE_44K,                       // 44100 x 1
        48000 => FMT_BASE_48K,                       // 48000 x 1
        88200 => FMT_BASE_44K | FMT_MULT_X2,        // 44100 x 2
        96000 => FMT_BASE_48K | FMT_MULT_X2,        // 48000 x 2
        176400 => FMT_BASE_44K | FMT_MULT_X4,       // 44100 x 4
        192000 => FMT_BASE_48K | FMT_MULT_X4,       // 48000 x 4
        _ => FMT_BASE_48K,                           // Default to 48k
    };

    let bits_field: u16 = match bits {
        8 => FMT_BITS_8,
        16 => FMT_BITS_16,
        20 => FMT_BITS_20,
        24 => FMT_BITS_24,
        32 => FMT_BITS_32,
        _ => FMT_BITS_16,
    };

    let chan_field = (channels.max(1).min(16) - 1) as u16;

    rate_bits | bits_field | chan_field
}

// ── Configure output DAC path ──

fn configure_output_path(ctrl: &mut HdaController, codec_idx: usize) {
    let codec_addr = ctrl.codecs[codec_idx].addr;
    let pin_nid = ctrl.codecs[codec_idx].pin_nid;
    let dac_nid = ctrl.codecs[codec_idx].dac_nid;
    let mixer_nid = ctrl.codecs[codec_idx].mixer_nid;
    let stream_tag = ctrl.out_stream_tag;
    let stream_fmt = ctrl.stream_fmt;

    if pin_nid == 0 || dac_nid == 0 {
        return;
    }

    // 1. Power up DAC
    codec_verb(ctrl, codec_addr, dac_nid, VERB_SET_POWER_STATE | 0x00);

    // 2. Set converter stream and channel
    // Verb payload: [7:4] = stream tag, [3:0] = channel (0 for first pair)
    let stream_chan = ((stream_tag as u32) << 4) | 0;
    codec_verb(ctrl, codec_addr, dac_nid, VERB_SET_CHANNEL_STREAM_ID | stream_chan);

    // 3. Set converter stream format
    codec_verb(ctrl, codec_addr, dac_nid, VERB_SET_STREAM_FORMAT | stream_fmt as u32);

    // 4. Unmute and set DAC output amplifier to reasonable level
    let amp_caps = codec_get_param(ctrl, codec_addr, dac_nid, PARAM_OUT_AMP_CAP);
    if amp_caps != 0 {
        // amp_caps: [22:16]=offset, [14:8]=num_steps, [7]=step_size, [6:0]=0-dB step
        let num_steps = (amp_caps >> 8) & 0x7F;
        // Set to ~75% of max gain, unmuted
        let gain = ((num_steps * 3) / 4).min(0x7F);
        let amp_verb = AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | gain;
        codec_verb(ctrl, codec_addr, dac_nid, VERB_SET_AMP_GAIN_MUTE | amp_verb);
    }

    // 5. If there's a mixer in the path, unmute its input connected to the DAC
    if mixer_nid != 0 {
        // Power up mixer
        codec_verb(ctrl, codec_addr, mixer_nid, VERB_SET_POWER_STATE | 0x00);

        // Find which input index of the mixer connects to our DAC
        if let Some(midx) = find_widget(&ctrl.codecs[codec_idx], mixer_nid) {
            let mixer = &ctrl.codecs[codec_idx].widgets[midx];
            for ci in 0..mixer.conn_list_len as usize {
                if mixer.conn_list[ci] == dac_nid {
                    // Unmute this input
                    let amp_verb = AMP_SET_INPUT | AMP_SET_LEFT | AMP_SET_RIGHT
                        | ((ci as u32) << AMP_SET_INDEX_SHIFT) | 0x7F;
                    codec_verb(ctrl, codec_addr, mixer_nid, VERB_SET_AMP_GAIN_MUTE | amp_verb);
                    break;
                }
            }
        }

        // Unmute mixer output amplifier
        let mixer_out_cap = codec_get_param(ctrl, codec_addr, mixer_nid, PARAM_OUT_AMP_CAP);
        if mixer_out_cap != 0 {
            let num_steps = (mixer_out_cap >> 8) & 0x7F;
            let gain = ((num_steps * 3) / 4).min(0x7F);
            let amp_verb = AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | gain;
            codec_verb(ctrl, codec_addr, mixer_nid, VERB_SET_AMP_GAIN_MUTE | amp_verb);
        }
    }

    // 6. Configure pin widget
    // Power up pin
    codec_verb(ctrl, codec_addr, pin_nid, VERB_SET_POWER_STATE | 0x00);

    // Determine pin control based on pin type
    let pin_cfg = ctrl.codecs[codec_idx].widgets
        .iter()
        .find(|w| w.nid == pin_nid)
        .map(|w| w.pin_cfg)
        .unwrap_or(0);
    let default_device = ((pin_cfg >> 20) & 0x0F) as u8;

    let mut pin_ctl = PIN_CTL_OUT_EN;
    if default_device == PIN_DEV_HP_OUT {
        pin_ctl |= PIN_CTL_HP_EN;
    }
    codec_verb(ctrl, codec_addr, pin_nid, VERB_SET_PIN_WIDGET_CTL | pin_ctl as u32);

    // 7. Enable EAPD if the pin supports it (common on Realtek codecs)
    let pin_caps = ctrl.codecs[codec_idx].widgets
        .iter()
        .find(|w| w.nid == pin_nid)
        .map(|w| w.pin_caps)
        .unwrap_or(0);
    if pin_caps & (1 << 16) != 0 {
        // EAPD capable
        let eapd = codec_verb(ctrl, codec_addr, pin_nid, VERB_GET_EAPD_BTLENABLE);
        codec_verb(
            ctrl,
            codec_addr,
            pin_nid,
            VERB_SET_EAPD_BTLENABLE | (eapd | EAPD_BTL_ENABLE_EAPD),
        );
    }

    // 8. If pin has an output amplifier, unmute it
    let pin_out_amp = codec_get_param(ctrl, codec_addr, pin_nid, PARAM_OUT_AMP_CAP);
    if pin_out_amp != 0 {
        let amp_verb = AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | 0x7F;
        codec_verb(ctrl, codec_addr, pin_nid, VERB_SET_AMP_GAIN_MUTE | amp_verb);
    }

    // 9. If the pin has a connection list with our mixer, select it
    if mixer_nid != 0 {
        if let Some(pidx) = find_widget(&ctrl.codecs[codec_idx], pin_nid) {
            let pin = &ctrl.codecs[codec_idx].widgets[pidx];
            for ci in 0..pin.conn_list_len as usize {
                if pin.conn_list[ci] == mixer_nid {
                    codec_verb(
                        ctrl,
                        codec_addr,
                        pin_nid,
                        VERB_SET_CONN_SELECT | ci as u32,
                    );
                    break;
                }
            }
        }
    }
}

// ── Stream descriptor setup ──

fn stream_reset(ctrl: &HdaController) {
    let bar0 = ctrl.bar0;
    let sd = ctrl.out_sd_base;

    // Set stream reset bit
    let ctl = mmio_read8(bar0, sd + SD_CTL);
    mmio_write8(bar0, sd + SD_CTL, ctl | SD_CTL_SRST as u8);

    // Wait for reset bit to read 1
    for _ in 0..1000u32 {
        if mmio_read8(bar0, sd + SD_CTL) & SD_CTL_SRST as u8 != 0 {
            break;
        }
        delay_us(10);
    }

    // Clear stream reset bit
    let ctl = mmio_read8(bar0, sd + SD_CTL);
    mmio_write8(bar0, sd + SD_CTL, ctl & !(SD_CTL_SRST as u8));

    // Wait for reset bit to read 0
    for _ in 0..1000u32 {
        if mmio_read8(bar0, sd + SD_CTL) & SD_CTL_SRST as u8 == 0 {
            break;
        }
        delay_us(10);
    }
}

fn setup_output_stream(ctrl: &mut HdaController) -> bool {
    let bar0 = ctrl.bar0;
    let sd = ctrl.out_sd_base;

    // Reset the stream descriptor
    stream_reset(ctrl);

    // Clear status bits (write 1 to clear)
    mmio_write8(bar0, sd + SD_STS, SD_STS_BCIS | SD_STS_FIFOE | SD_STS_DESE);

    // Set stream format
    mmio_write16(bar0, sd + SD_FMT, ctrl.stream_fmt);

    // Set Cyclic Buffer Length (total size of all BDL buffers)
    mmio_write32(bar0, sd + SD_CBL, TOTAL_BUF_SIZE as u32);

    // Set Last Valid Index (number of BDL entries - 1)
    mmio_write16(bar0, sd + SD_LVI, (BDL_ENTRIES - 1) as u16);

    // Set BDL pointer (physical address, must be 128-byte aligned)
    mmio_write32(bar0, sd + SD_BDLPL, ctrl.bdl_phys as u32);
    mmio_write32(bar0, sd + SD_BDLPU, (ctrl.bdl_phys >> 32) as u32);

    // Set stream number and direction in SD_CTL
    // SD_CTL is a 24-bit register: we write the lower 16 bits and upper 8 bits
    // Upper byte (offset +0x02) contains: [3:0]=stream number
    let stream_num = ctrl.out_stream_num;
    let ctl_upper = (stream_num & 0x0F) << 4;
    mmio_write8(bar0, sd + SD_CTL + 2, ctl_upper);

    true
}

fn setup_bdl(ctrl: &mut HdaController) {
    // Configure BDL entries, each pointing to a FRAG_SIZE chunk
    for i in 0..BDL_ENTRIES {
        let offset = (i * FRAG_SIZE) as u64;
        let entry = BdlEntry {
            addr: ctrl.audio_buf_phys + offset,
            length: FRAG_SIZE as u32,
            // Set IOC on the last entry for wrap-around notification
            ioc: if i == BDL_ENTRIES - 1 { 1 } else { 0 },
        };
        unsafe {
            write_volatile(ctrl.bdl.add(i), entry);
        }
    }
}

// ── Allocate audio resources ──

fn alloc_audio_resources(ctrl: &mut HdaController) -> bool {
    // Allocate CORB buffer (256 * 4 = 1024 bytes, needs page alignment)
    let corb = unsafe { alloc_page() };
    if corb.is_null() {
        log("hda: failed to allocate CORB");
        return false;
    }
    unsafe { core::ptr::write_bytes(corb, 0, 4096); }
    ctrl.corb = corb as *mut u32;
    ctrl.corb_phys = virt_to_phys(corb);

    // Allocate RIRB buffer (256 * 8 = 2048 bytes, needs page alignment)
    let rirb = unsafe { alloc_page() };
    if rirb.is_null() {
        log("hda: failed to allocate RIRB");
        return false;
    }
    unsafe { core::ptr::write_bytes(rirb, 0, 4096); }
    ctrl.rirb = rirb as *mut RirbEntry;
    ctrl.rirb_phys = virt_to_phys(rirb);

    // Allocate BDL (32 * 16 = 512 bytes, needs 128-byte alignment; page is fine)
    let bdl = unsafe { alloc_page() };
    if bdl.is_null() {
        log("hda: failed to allocate BDL");
        return false;
    }
    unsafe { core::ptr::write_bytes(bdl, 0, 4096); }
    ctrl.bdl = bdl as *mut BdlEntry;
    ctrl.bdl_phys = virt_to_phys(bdl);

    // Allocate audio DMA buffer (32 * 4 KiB = 128 KiB)
    // We allocate individual pages and they must be physically contiguous
    // for the simple BDL layout. Use alloc() for a contiguous block.
    let buf_size = TOTAL_BUF_SIZE;
    let audio_buf = unsafe { alloc(buf_size) };
    if audio_buf.is_null() {
        log("hda: failed to allocate audio buffer");
        return false;
    }
    unsafe { core::ptr::write_bytes(audio_buf, 0, buf_size); }
    ctrl.audio_buf = audio_buf;
    ctrl.audio_buf_phys = virt_to_phys(audio_buf);

    true
}

// ── FFI exports ──

/// Initialize the HDA controller: PCI probe, reset, CORB/RIRB setup,
/// codec discovery, widget enumeration, and output path configuration.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_init() -> i32 {
    log("hda: scanning PCI for HD Audio controllers...");

    let (bus, dev, func) = match find_hda_pci() {
        Some(bdf) => bdf,
        None => {
            log("hda: no HD Audio controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"hda: found controller at PCI %02x:%02x.%x\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable bus mastering and memory space in PCI command register
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06);

    // Read BAR0 (64-bit MMIO)
    let bar0_lo = pci_read32(bus, dev, func, 0x10) & !0xF;
    let bar0_hi = pci_read32(bus, dev, func, 0x14);
    let bar0_phys = (bar0_lo as u64) | ((bar0_hi as u64) << 32);

    if bar0_phys == 0 {
        log("hda: BAR0 not configured");
        return -2;
    }

    unsafe {
        fut_printf(b"hda: BAR0 = 0x%llx\n\0".as_ptr(), bar0_phys);
    }

    // Map BAR0 MMIO region
    // HDA controllers typically need at least 0x4000 bytes for registers
    // (global regs + stream descriptors). Some need more for the DMA position buffer.
    let bar0_size = 0x4000usize;
    let bar0 = unsafe { map_mmio_region(bar0_phys, bar0_size, MMIO_DEFAULT_FLAGS) };
    if bar0.is_null() {
        log("hda: failed to map BAR0");
        return -3;
    }

    // Read GCAP to determine stream counts
    let gcap = mmio_read16(bar0, HDA_REG_GCAP);
    let num_oss = ((gcap >> 12) & 0x0F) as u8; // Output Streams
    let num_iss = ((gcap >> 8) & 0x0F) as u8;  // Input Streams
    let num_bss = ((gcap >> 3) & 0x1F) as u8;  // Bidirectional Streams
    let _64ok = (gcap >> 0) & 1;                 // 64-bit Address Supported

    let vmaj = mmio_read8(bar0, HDA_REG_VMAJ);
    let vmin = mmio_read8(bar0, HDA_REG_VMIN);

    unsafe {
        fut_printf(
            b"hda: version %d.%d, GCAP=0x%04x (OSS=%d ISS=%d BSS=%d)\n\0".as_ptr(),
            vmaj as u32,
            vmin as u32,
            gcap as u32,
            num_oss as u32,
            num_iss as u32,
            num_bss as u32,
        );
    }

    if num_oss == 0 {
        log("hda: no output streams available");
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -4;
    }

    // Calculate output stream descriptor base offset
    // Input streams start at 0x80, output streams follow
    let out_sd_base = 0x80 + (num_iss as usize) * 0x20;

    // Initialize controller state
    let mut ctrl = HdaController {
        bar0,
        bar0_size,
        bus,
        dev,
        func,
        num_oss,
        num_iss,
        num_bss,
        corb: core::ptr::null_mut(),
        corb_phys: 0,
        corb_wp: 0,
        rirb: core::ptr::null_mut(),
        rirb_phys: 0,
        rirb_rp: 0,
        // SAFETY: Codec::zeroed() produces the same bit pattern as all-zeroes,
        // so zero-initializing the array is correct.
        codecs: unsafe { core::mem::zeroed() },
        num_codecs: 0,
        out_sd_base,
        out_stream_num: 1,    // Use stream number 1 (0 is reserved)
        out_stream_tag: 1,    // Stream tag matches stream number
        bdl: core::ptr::null_mut(),
        bdl_phys: 0,
        audio_buf: core::ptr::null_mut(),
        audio_buf_phys: 0,
        sample_rate: 48000,
        bits: 16,
        channels: 2,
        stream_fmt: FMT_DEFAULT,
        write_pos: 0,
        active_codec: 0,
        playing: false,
    };

    // Allocate DMA resources (CORB, RIRB, BDL, audio buffer)
    if !alloc_audio_resources(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -5;
    }

    // Reset the controller
    if !controller_reset(bar0) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -6;
    }
    log("hda: controller reset complete");

    // Enable unsolicited response handling
    let gctl = mmio_read32(bar0, HDA_REG_GCTL);
    mmio_write32(bar0, HDA_REG_GCTL, gctl | GCTL_UNSOL);

    // Initialize CORB and RIRB
    if !corb_init(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -7;
    }
    log("hda: CORB initialized");

    if !rirb_init(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -8;
    }
    log("hda: RIRB initialized");

    // Discover codecs
    let codec_count = discover_codecs(&mut ctrl);
    if codec_count == 0 {
        log("hda: no codecs found");
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -9;
    }

    unsafe {
        fut_printf(b"hda: discovered %d codec(s)\n\0".as_ptr(), codec_count);
    }

    // Enumerate widgets and find output path for each codec
    let mut found_output = false;
    for i in 0..codec_count as usize {
        enumerate_widgets(&mut ctrl, i);
        if find_output_path(&mut ctrl, i) {
            if !found_output {
                ctrl.active_codec = i;
                found_output = true;
            }
        }
    }

    if !found_output {
        log("hda: no usable output path found");
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -10;
    }

    // Setup BDL entries
    setup_bdl(&mut ctrl);

    // Setup output stream descriptor
    if !setup_output_stream(&mut ctrl) {
        log("hda: failed to setup output stream");
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -11;
    }

    // Configure codec output path (DAC -> mixer -> pin)
    let codec = ctrl.active_codec;
    configure_output_path(&mut ctrl, codec);

    log("hda: initialization complete");

    // Store controller state
    unsafe { *HDA.0.get() = Some(ctrl); }

    0
}

/// Return the number of discovered codecs.
#[unsafe(no_mangle)]
pub extern "C" fn hda_get_codec_count() -> u32 {
    unsafe { (*HDA.0.get()).as_ref().map_or(0, |c| c.num_codecs) }
}

/// Configure output stream format.
/// sample_rate: 8000, 11025, 16000, 22050, 32000, 44100, 48000, 88200, 96000, 176400, 192000
/// bits: 8, 16, 20, 24, 32
/// channels: 1-16
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_setup_output(sample_rate: u32, bits: u32, channels: u32) -> i32 {
    let ctrl = match unsafe { (*HDA.0.get()).as_mut() } {
        Some(c) => c,
        None => return -1,
    };

    // Validate parameters
    let rate = if sample_rate == 0 { 48000 } else { sample_rate };
    let b = if bits == 0 { 16 } else { bits };
    let ch = if channels == 0 { 2 } else { channels.min(16) };

    let fmt = encode_stream_format(rate, b, ch);

    // Stop playback if running
    if ctrl.playing {
        let bar0 = ctrl.bar0;
        let sd = ctrl.out_sd_base;
        let ctl = mmio_read8(bar0, sd + SD_CTL);
        mmio_write8(bar0, sd + SD_CTL, ctl & !(SD_CTL_RUN as u8));
        for _ in 0..1000u32 {
            if mmio_read8(bar0, sd + SD_CTL) & SD_CTL_RUN as u8 == 0 {
                break;
            }
            delay_us(10);
        }
        ctrl.playing = false;
    }

    ctrl.sample_rate = rate;
    ctrl.bits = b;
    ctrl.channels = ch;
    ctrl.stream_fmt = fmt;
    ctrl.write_pos = 0;

    // Reset and reconfigure the stream
    stream_reset(ctrl);
    mmio_write8(ctrl.bar0, ctrl.out_sd_base + SD_STS,
                SD_STS_BCIS | SD_STS_FIFOE | SD_STS_DESE);
    mmio_write16(ctrl.bar0, ctrl.out_sd_base + SD_FMT, fmt);
    mmio_write32(ctrl.bar0, ctrl.out_sd_base + SD_CBL, TOTAL_BUF_SIZE as u32);
    mmio_write16(ctrl.bar0, ctrl.out_sd_base + SD_LVI, (BDL_ENTRIES - 1) as u16);
    mmio_write32(ctrl.bar0, ctrl.out_sd_base + SD_BDLPL, ctrl.bdl_phys as u32);
    mmio_write32(ctrl.bar0, ctrl.out_sd_base + SD_BDLPU, (ctrl.bdl_phys >> 32) as u32);

    // Set stream number
    let ctl_upper = (ctrl.out_stream_num & 0x0F) << 4;
    mmio_write8(ctrl.bar0, ctrl.out_sd_base + SD_CTL + 2, ctl_upper);

    // Reconfigure codec DAC with new format
    let codec_idx = ctrl.active_codec;
    configure_output_path(ctrl, codec_idx);

    // Clear audio buffer
    unsafe {
        core::ptr::write_bytes(ctrl.audio_buf, 0, TOTAL_BUF_SIZE);
    }

    unsafe {
        fut_printf(
            b"hda: output configured: %d Hz, %d-bit, %d ch (fmt=0x%04x)\n\0".as_ptr(),
            rate,
            b,
            ch,
            fmt as u32,
        );
    }

    0
}

/// Start audio playback on the output stream.
/// The stream must be configured first with hda_setup_output() or hda_init() defaults.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_start_playback() -> i32 {
    let ctrl = match unsafe { (*HDA.0.get()).as_mut() } {
        Some(c) => c,
        None => return -1,
    };

    if ctrl.playing {
        return 0; // Already playing
    }

    let bar0 = ctrl.bar0;
    let sd = ctrl.out_sd_base;

    // Enable interrupt on completion for the stream in INTCTL
    // Bit 0..29 = stream interrupt enable (bit N = stream N)
    // We need the stream index (not stream number). First output stream index
    // = num_iss. Our output is at index num_iss + 0.
    let stream_idx = ctrl.num_iss as u32;
    let intctl = mmio_read32(bar0, HDA_REG_INTCTL);
    mmio_write32(
        bar0,
        HDA_REG_INTCTL,
        intctl | (1 << stream_idx) | INTCTL_GIE | INTCTL_CIE,
    );

    // Set the Run bit and IOC enable in SD_CTL
    let ctl_lo = mmio_read16(bar0, sd + SD_CTL);
    mmio_write16(bar0, sd + SD_CTL, ctl_lo | SD_CTL_RUN as u16 | SD_CTL_IOCE as u16);

    ctrl.playing = true;
    log("hda: playback started");

    0
}

/// Stop audio playback.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_stop_playback() -> i32 {
    let ctrl = match unsafe { (*HDA.0.get()).as_mut() } {
        Some(c) => c,
        None => return -1,
    };

    if !ctrl.playing {
        return 0; // Already stopped
    }

    let bar0 = ctrl.bar0;
    let sd = ctrl.out_sd_base;

    // Clear Run bit in SD_CTL
    let ctl_lo = mmio_read16(bar0, sd + SD_CTL);
    mmio_write16(bar0, sd + SD_CTL, ctl_lo & !(SD_CTL_RUN as u16));

    // Wait for Run bit to clear (DMA engine fully stopped)
    for _ in 0..1000u32 {
        if mmio_read16(bar0, sd + SD_CTL) & SD_CTL_RUN as u16 == 0 {
            break;
        }
        delay_us(10);
    }

    // Clear status bits
    mmio_write8(bar0, sd + SD_STS, SD_STS_BCIS | SD_STS_FIFOE | SD_STS_DESE);

    // Disable stream interrupt
    let stream_idx = ctrl.num_iss as u32;
    let intctl = mmio_read32(bar0, HDA_REG_INTCTL);
    mmio_write32(bar0, HDA_REG_INTCTL, intctl & !(1 << stream_idx));

    ctrl.playing = false;
    ctrl.write_pos = 0;
    log("hda: playback stopped");

    0
}

/// Write PCM audio samples to the playback buffer.
///
/// buf: pointer to raw PCM sample data (format must match hda_setup_output)
/// len: number of bytes to write
///
/// Samples are written to a circular DMA buffer. If the buffer is full,
/// this function will write as many bytes as space allows.
///
/// Returns the number of bytes actually written, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hda_write_samples(buf: *const u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return 0;
    }

    let ctrl = match unsafe { (*HDA.0.get()).as_mut() } {
        Some(c) => c,
        None => return -1,
    };

    let buf_total = TOTAL_BUF_SIZE;
    let mut remaining = len as usize;
    let mut src_offset = 0usize;
    let mut written = 0usize;

    // Read the current DMA position (link position) to avoid overwriting
    // data that the controller hasn't played yet.
    let lpib = if ctrl.playing {
        mmio_read32(ctrl.bar0, ctrl.out_sd_base + SD_LPIB) as usize
    } else {
        // If not playing, the whole buffer is available
        0
    };

    // Calculate available space in the circular buffer.
    // We keep a safety margin of one fragment to avoid the write cursor
    // catching the DMA read position.
    let available = if ctrl.playing {
        let read_pos = lpib;
        let write_pos = ctrl.write_pos;
        if write_pos >= read_pos {
            buf_total - (write_pos - read_pos) - FRAG_SIZE
        } else {
            (read_pos - write_pos) - FRAG_SIZE
        }
    } else {
        buf_total
    };

    if available == 0 {
        return 0;
    }

    remaining = remaining.min(available);

    while remaining > 0 {
        let chunk = remaining.min(buf_total - ctrl.write_pos);
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.add(src_offset),
                ctrl.audio_buf.add(ctrl.write_pos),
                chunk,
            );
        }
        ctrl.write_pos = (ctrl.write_pos + chunk) % buf_total;
        src_offset += chunk;
        remaining -= chunk;
        written += chunk;
    }

    written as i32
}
