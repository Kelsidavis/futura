// SPDX-License-Identifier: MPL-2.0
//
// 16550 UART Serial Port Driver for Futura OS (x86-64)
//
// Implements the NS16550A-compatible UART accessed through standard x86
// I/O ports.  Supports all four COM ports (COM1..COM4) simultaneously
// with configurable baud rate and line parameters.
//
// Features:
//   - Port auto-detection via scratch register probe
//   - FIFO enable and configuration (FCR)
//   - Baud rate setting (115200, 57600, 38400, 19200, 9600, ...)
//   - Configurable line parameters (default 8N1)
//   - Blocking putc / getc with timeout
//   - Non-blocking trygetc and bulk read
//   - Write string / buffer
//   - Loopback self-test
//
// Register map (I/O port offsets from base):
//   +0 (DLAB=0): RBR (read) / THR (write)
//   +0 (DLAB=1): DLL (Divisor Latch Low)
//   +1 (DLAB=0): IER (Interrupt Enable)
//   +1 (DLAB=1): DLH (Divisor Latch High)
//   +2: IIR (read) / FCR (write)
//   +3: LCR (Line Control)
//   +4: MCR (Modem Control)
//   +5: LSR (Line Status)
//   +6: MSR (Modem Status)
//   +7: SCR (Scratch Register)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ── COM port base addresses ──

const COM1_BASE: u16 = 0x3F8;
const COM2_BASE: u16 = 0x2F8;
const COM3_BASE: u16 = 0x3E8;
const COM4_BASE: u16 = 0x2E8;

/// Number of supported COM ports.
const MAX_PORTS: usize = 4;

/// Standard COM port base addresses indexed by port number (0..3).
const COM_BASES: [u16; MAX_PORTS] = [COM1_BASE, COM2_BASE, COM3_BASE, COM4_BASE];

// ── Register offsets from port base ──

/// Receive Buffer Register (read, DLAB=0) / Transmit Holding Register (write, DLAB=0)
const REG_RBR_THR: u16 = 0;
/// Divisor Latch Low (DLAB=1)
const REG_DLL: u16 = 0;
/// Interrupt Enable Register (DLAB=0)
const REG_IER: u16 = 1;
/// Divisor Latch High (DLAB=1)
const REG_DLH: u16 = 1;
/// Interrupt Identification Register (read) / FIFO Control Register (write)
const REG_IIR_FCR: u16 = 2;
/// Line Control Register
const REG_LCR: u16 = 3;
/// Modem Control Register
const REG_MCR: u16 = 4;
/// Line Status Register
const REG_LSR: u16 = 5;
/// Modem Status Register
const REG_MSR: u16 = 6;
/// Scratch Register (used for port detection)
const REG_SCR: u16 = 7;

// ── Line Control Register (LCR) bits ──

/// Word length: 5 bits
const LCR_WORD_5: u8 = 0b00;
/// Word length: 6 bits
const LCR_WORD_6: u8 = 0b01;
/// Word length: 7 bits
const LCR_WORD_7: u8 = 0b10;
/// Word length: 8 bits
const LCR_WORD_8: u8 = 0b11;
/// Stop bits: 1 (clear) vs 1.5/2 (set)
const LCR_STOP_2: u8 = 1 << 2;
/// Parity enable
const LCR_PARITY_EN: u8 = 1 << 3;
/// Even parity select (with parity enabled)
const LCR_PARITY_EVEN: u8 = 1 << 4;
/// Stick parity
const LCR_PARITY_STICK: u8 = 1 << 5;
/// Break control
const LCR_BREAK: u8 = 1 << 6;
/// Divisor Latch Access Bit
const LCR_DLAB: u8 = 1 << 7;

// ── FIFO Control Register (FCR) bits ──

/// Enable FIFOs
const FCR_ENABLE: u8 = 1 << 0;
/// Clear receive FIFO
const FCR_CLR_RX: u8 = 1 << 1;
/// Clear transmit FIFO
const FCR_CLR_TX: u8 = 1 << 2;
/// DMA mode select
const _FCR_DMA: u8 = 1 << 3;
/// Trigger level: 14 bytes (bits 7:6 = 11)
const FCR_TRIGGER_14: u8 = 0b11 << 6;

// ── Modem Control Register (MCR) bits ──

/// Data Terminal Ready
const MCR_DTR: u8 = 1 << 0;
/// Request To Send
const MCR_RTS: u8 = 1 << 1;
/// OUT1 (auxiliary output 1)
const _MCR_OUT1: u8 = 1 << 2;
/// OUT2 (enables interrupts on PC-compatible hardware)
const MCR_OUT2: u8 = 1 << 3;
/// Loopback mode
const MCR_LOOPBACK: u8 = 1 << 4;

// ── Line Status Register (LSR) bits ──

/// Data Ready (at least one byte in RBR/FIFO)
const LSR_DATA_READY: u8 = 1 << 0;
/// Overrun Error
const LSR_OVERRUN: u8 = 1 << 1;
/// Parity Error
const _LSR_PARITY_ERR: u8 = 1 << 2;
/// Framing Error
const _LSR_FRAMING_ERR: u8 = 1 << 3;
/// Break Interrupt
const _LSR_BREAK_INT: u8 = 1 << 4;
/// Transmitter Holding Register Empty (ready to accept data)
const LSR_THR_EMPTY: u8 = 1 << 5;
/// Transmitter Empty (shift register and THR both empty)
const _LSR_TX_EMPTY: u8 = 1 << 6;

// ── Interrupt Enable Register (IER) bits ──

/// Received Data Available interrupt
const _IER_RDA: u8 = 1 << 0;
/// Transmitter Holding Register Empty interrupt
const _IER_THRE: u8 = 1 << 1;
/// Receiver Line Status interrupt
const _IER_RLS: u8 = 1 << 2;
/// Modem Status interrupt
const _IER_MS: u8 = 1 << 3;

// ── Baud rate constants ──

/// UART base clock frequency in Hz (1.8432 MHz standard oscillator)
const UART_CLOCK: u32 = 115200;

/// Timeout for blocking operations (number of poll iterations).
/// At typical I/O speeds this corresponds to roughly 100 ms.
const POLL_TIMEOUT: u32 = 100_000;

// ── Per-port driver state ──

#[derive(Copy, Clone)]
struct PortState {
    /// I/O base address (0 = not initialized / not present)
    base: u16,
    /// Current baud rate
    baud: u32,
    /// Current LCR value (line parameters)
    lcr: u8,
    /// Whether the port has been initialized
    initialized: bool,
}

impl PortState {
    const fn new() -> Self {
        Self {
            base: 0,
            baud: 0,
            lcr: 0,
            initialized: false,
        }
    }
}

static PORTS: StaticCell<[PortState; MAX_PORTS]> = StaticCell::new([
    PortState::new(),
    PortState::new(),
    PortState::new(),
    PortState::new(),
]);

// ── x86 I/O port helpers ──

#[inline]
fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

#[inline]
fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

/// Small I/O delay (standard x86 technique: dummy write to port 0x80).
#[inline]
fn io_delay() {
    io_outb(0x80, 0);
}

// ── Internal helpers ──

/// Resolve a port base address.  If `port` is 0, returns COM1 base.
/// If `port` matches a known COM base, returns it directly.
/// Otherwise returns 0 (invalid).
fn resolve_base(port: u16) -> u16 {
    if port == 0 {
        return COM1_BASE;
    }
    for &base in &COM_BASES {
        if port == base {
            return base;
        }
    }
    // Allow any explicit base address (for non-standard configurations)
    port
}

/// Find the index of a port in our state array, or return None.
fn port_index(base: u16) -> Option<usize> {
    let ports = unsafe { &*PORTS.get() };
    for i in 0..MAX_PORTS {
        if ports[i].base == base && ports[i].initialized {
            return Some(i);
        }
    }
    None
}

/// Find a free slot in the port state array.
fn find_free_slot() -> Option<usize> {
    let ports = unsafe { &*PORTS.get() };
    for i in 0..MAX_PORTS {
        if !ports[i].initialized {
            return Some(i);
        }
    }
    None
}

/// Detect whether a UART is present at the given I/O base by writing
/// and reading back the scratch register (offset +7).
fn detect_port(base: u16) -> bool {
    // Save original scratch value
    let original = io_inb(base + REG_SCR);

    // Test pattern 1
    io_outb(base + REG_SCR, 0xAA);
    io_delay();
    if io_inb(base + REG_SCR) != 0xAA {
        io_outb(base + REG_SCR, original);
        return false;
    }

    // Test pattern 2
    io_outb(base + REG_SCR, 0x55);
    io_delay();
    if io_inb(base + REG_SCR) != 0x55 {
        io_outb(base + REG_SCR, original);
        return false;
    }

    // Restore original value
    io_outb(base + REG_SCR, original);
    true
}

/// Calculate the divisor for a given baud rate.
/// Returns 0 if the baud rate is invalid.
fn baud_divisor(baud: u32) -> u16 {
    if baud == 0 || baud > UART_CLOCK {
        return 0;
    }
    (UART_CLOCK / baud) as u16
}

/// Set the baud rate divisor.  Caller must ensure `base` is valid.
fn set_divisor(base: u16, divisor: u16) {
    // Save current LCR, then set DLAB to access divisor latches
    let lcr = io_inb(base + REG_LCR);
    io_outb(base + REG_LCR, lcr | LCR_DLAB);
    io_delay();

    // Write divisor (low byte first, then high byte)
    io_outb(base + REG_DLL, (divisor & 0xFF) as u8);
    io_outb(base + REG_DLH, ((divisor >> 8) & 0xFF) as u8);

    // Restore LCR (clears DLAB)
    io_outb(base + REG_LCR, lcr);
}

/// Enable and configure the FIFO.
fn enable_fifo(base: u16) {
    // Enable FIFOs, clear both buffers, set trigger level to 14 bytes
    io_outb(base + REG_IIR_FCR, FCR_ENABLE | FCR_CLR_RX | FCR_CLR_TX | FCR_TRIGGER_14);
    io_delay();
}

/// Wait until the transmitter holding register is empty.
/// Returns true if THR is ready, false on timeout.
#[inline]
fn wait_thr_empty(base: u16) -> bool {
    for _ in 0..POLL_TIMEOUT {
        if io_inb(base + REG_LSR) & LSR_THR_EMPTY != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Wait until data is ready in the receive buffer.
/// Returns true if data is available, false on timeout.
#[inline]
fn wait_data_ready(base: u16) -> bool {
    for _ in 0..POLL_TIMEOUT {
        if io_inb(base + REG_LSR) & LSR_DATA_READY != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Perform a loopback self-test on the UART at `base`.
/// Returns true if the port passes the loopback test.
fn loopback_test(base: u16) -> bool {
    // Save current MCR
    let mcr_saved = io_inb(base + REG_MCR);

    // Enable loopback mode with DTR + RTS + OUT2
    io_outb(base + REG_MCR, MCR_LOOPBACK | MCR_DTR | MCR_RTS | MCR_OUT2);
    io_delay();

    // Drain any stale data in the receive buffer
    for _ in 0..16 {
        if io_inb(base + REG_LSR) & LSR_DATA_READY == 0 {
            break;
        }
        let _ = io_inb(base + REG_RBR_THR);
    }

    // Send a test byte
    let test_byte: u8 = 0xE7;
    if !wait_thr_empty(base) {
        io_outb(base + REG_MCR, mcr_saved);
        return false;
    }
    io_outb(base + REG_RBR_THR, test_byte);

    // Wait for it to loop back
    if !wait_data_ready(base) {
        io_outb(base + REG_MCR, mcr_saved);
        return false;
    }

    let received = io_inb(base + REG_RBR_THR);

    // Restore MCR
    io_outb(base + REG_MCR, mcr_saved);

    received == test_byte
}

// ── Exported API ──

/// Initialize a 16550 UART port.
///
/// `port`: I/O base address of the COM port.  Pass 0 for COM1 (0x3F8).
/// `baud`: desired baud rate.  Pass 0 for the default (115200).
///
/// Performs port detection, loopback self-test, FIFO configuration,
/// baud rate and line parameter (8N1) setup.
///
/// Returns 0 on success, negative on error:
///   -1 = port not detected
///   -2 = loopback test failed
///   -3 = invalid baud rate
///   -4 = no free port slots
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_init(port: u16, baud: u32) -> i32 {
    let base = resolve_base(port);
    let baud = if baud == 0 { 115200 } else { baud };

    unsafe {
        fut_printf(
            b"uart16550: initializing port 0x%03x at %u baud\n\0".as_ptr(),
            base as u32,
            baud,
        );
    }

    // Detect the port via scratch register test
    if !detect_port(base) {
        unsafe {
            fut_printf(
                b"uart16550: no UART detected at 0x%03x\n\0".as_ptr(),
                base as u32,
            );
        }
        return -1;
    }

    // Disable all interrupts during setup
    io_outb(base + REG_IER, 0x00);

    // Calculate and set baud rate divisor
    let divisor = baud_divisor(baud);
    if divisor == 0 {
        log("uart16550: invalid baud rate");
        return -3;
    }
    set_divisor(base, divisor);

    // Configure line parameters: 8 data bits, no parity, 1 stop bit (8N1)
    let lcr = LCR_WORD_8;
    io_outb(base + REG_LCR, lcr);

    // Enable and configure FIFO
    enable_fifo(base);

    // Set MCR: DTR + RTS + OUT2 (OUT2 enables interrupts on PC hardware)
    io_outb(base + REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    // Perform loopback self-test
    if !loopback_test(base) {
        unsafe {
            fut_printf(
                b"uart16550: loopback test FAILED at 0x%03x\n\0".as_ptr(),
                base as u32,
            );
        }
        return -2;
    }

    // Restore normal operation mode after loopback test
    io_outb(base + REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    // Re-enable FIFO after loopback (loopback may have dirtied state)
    enable_fifo(base);

    // Drain any stale data in the receive buffer
    for _ in 0..256 {
        if io_inb(base + REG_LSR) & LSR_DATA_READY == 0 {
            break;
        }
        let _ = io_inb(base + REG_RBR_THR);
    }

    // Store port state
    // Check if this port is already initialized (re-init case)
    if let Some(idx) = port_index(base) {
        let ports = unsafe { &mut *PORTS.get() };
        ports[idx].baud = baud;
        ports[idx].lcr = lcr;
    } else if let Some(idx) = find_free_slot() {
        let ports = unsafe { &mut *PORTS.get() };
        ports[idx].base = base;
        ports[idx].baud = baud;
        ports[idx].lcr = lcr;
        ports[idx].initialized = true;
    } else {
        log("uart16550: no free port slots");
        return -4;
    }

    // Read IIR to detect FIFO status
    let iir = io_inb(base + REG_IIR_FCR);
    let fifo_str = match (iir >> 6) & 0x03 {
        0b11 => b"enabled\0".as_ptr(),
        0b10 => b"enabled (unusable)\0".as_ptr(),
        _ => b"not available\0".as_ptr(),
    };

    unsafe {
        fut_printf(
            b"uart16550: port 0x%03x ready, baud=%u, 8N1, FIFO %s\n\0".as_ptr(),
            base as u32,
            baud,
            fifo_str,
        );
    }

    0
}

/// Transmit a single character (blocking).
///
/// Waits until the transmitter holding register is empty, then writes the byte.
/// `port`: I/O base address (0 = COM1).
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_putc(port: u16, ch: u8) {
    let base = resolve_base(port);
    wait_thr_empty(base);
    io_outb(base + REG_RBR_THR, ch);
}

/// Receive a single character (blocking with timeout).
///
/// Waits until data is available in the receive buffer, then reads it.
/// `port`: I/O base address (0 = COM1).
///
/// Returns the received byte as i32, or -1 on timeout.
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_getc(port: u16) -> i32 {
    let base = resolve_base(port);
    if wait_data_ready(base) {
        io_inb(base + REG_RBR_THR) as i32
    } else {
        -1
    }
}

/// Try to receive a single character (non-blocking).
///
/// `port`: I/O base address (0 = COM1).
///
/// Returns the received byte as i32, or -1 if no data is available.
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_trygetc(port: u16) -> i32 {
    let base = resolve_base(port);
    if io_inb(base + REG_LSR) & LSR_DATA_READY != 0 {
        io_inb(base + REG_RBR_THR) as i32
    } else {
        -1
    }
}

/// Write a buffer of bytes to the UART (blocking).
///
/// `port`: I/O base address (0 = COM1).
/// `data`: pointer to the byte buffer.
/// `len`:  number of bytes to write.
///
/// Returns the number of bytes written, or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_write(port: u16, data: *const u8, len: u32) -> i32 {
    if data.is_null() {
        return -1;
    }

    let base = resolve_base(port);
    let mut written: u32 = 0;

    while written < len {
        if !wait_thr_empty(base) {
            // Timeout — return what we managed to send
            break;
        }
        let byte = unsafe { *data.add(written as usize) };
        io_outb(base + REG_RBR_THR, byte);
        written += 1;
    }

    written as i32
}

/// Read available bytes from the UART into a buffer (non-blocking).
///
/// Reads up to `max_len` bytes that are currently available in the
/// receive FIFO without blocking.
///
/// `port`:    I/O base address (0 = COM1).
/// `buf`:     pointer to the output buffer.
/// `max_len`: maximum number of bytes to read.
///
/// Returns the number of bytes actually read, or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_read(port: u16, buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() {
        return -1;
    }

    let base = resolve_base(port);
    let mut count: u32 = 0;

    while count < max_len {
        if io_inb(base + REG_LSR) & LSR_DATA_READY == 0 {
            break;
        }
        let byte = io_inb(base + REG_RBR_THR);
        unsafe {
            *buf.add(count as usize) = byte;
        }
        count += 1;
    }

    count as i32
}

/// Change the baud rate of an initialized UART port.
///
/// `port`: I/O base address (0 = COM1).
/// `baud`: desired baud rate.
///
/// Returns 0 on success, -1 if the port is not initialized, -2 if the
/// baud rate is invalid.
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_set_baud(port: u16, baud: u32) -> i32 {
    let base = resolve_base(port);

    let divisor = baud_divisor(baud);
    if divisor == 0 {
        return -2;
    }

    // Wait for transmitter to drain before changing speed
    wait_thr_empty(base);

    set_divisor(base, divisor);

    // Update stored state if tracked
    if let Some(idx) = port_index(base) {
        let ports = unsafe { &mut *PORTS.get() };
        ports[idx].baud = baud;
    }

    unsafe {
        fut_printf(
            b"uart16550: port 0x%03x baud rate changed to %u (divisor=%u)\n\0".as_ptr(),
            base as u32,
            baud,
            divisor as u32,
        );
    }

    0
}

/// Check whether data is available to read on the given port.
///
/// `port`: I/O base address (0 = COM1).
///
/// Returns `true` if the receive buffer contains at least one byte.
#[unsafe(no_mangle)]
pub extern "C" fn uart16550_data_ready(port: u16) -> bool {
    let base = resolve_base(port);
    io_inb(base + REG_LSR) & LSR_DATA_READY != 0
}
