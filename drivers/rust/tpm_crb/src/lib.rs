// SPDX-License-Identifier: MPL-2.0
//
// TPM 2.0 CRB (Command Response Buffer) Interface Driver for Futura OS
//
// Implements the TCG PC Client Platform TPM Profile (PTP) Specification
// for the CRB (Command Response Buffer) interface. The CRB interface is
// the preferred TPM 2.0 access mechanism on modern x86 platforms,
// replacing the older TIS (TPM Interface Specification) FIFO model.
//
// Architecture:
//   - Memory-mapped CRB Control Area at 0xFED4_0000 (standard, via ACPI TPM2)
//   - Locality 0 access with request/relinquish protocol
//   - Command submission: write to command buffer, set CRB_CTRL_START, poll
//   - Response read from response buffer after command completion
//   - Support for TPM2_Startup, TPM2_SelfTest, TPM2_GetRandom, TPM2_GetCapability
//
// CRB Control Area register map (offsets from locality base):
//   0x000  LOC_STATE           Locality state (RO)
//   0x004  LOC_CTRL            Locality control (RW)
//   0x008  LOC_STS             Locality status (RO)
//   0x014  CRB_INTF_ID         Interface type identifier (RO)
//   0x030  CRB_CTRL_REQ        Control request: goReady/goIdle (RW)
//   0x034  CRB_CTRL_STS        Control status: tpmIdle/tpmSts (RO)
//   0x038  CRB_CTRL_CANCEL     Cancel current command (RW)
//   0x03C  CRB_CTRL_START      Start command processing (RW)
//   0x040  CRB_INT_ENABLE      Interrupt enable (RW)
//   0x044  CRB_INT_STS         Interrupt status (R/WC)
//   0x048  CRB_CTRL_CMD_SIZE   Command buffer size (RO)
//   0x04C  CRB_CTRL_CMD_LADDR  Command buffer low address (RO)
//   0x050  CRB_CTRL_CMD_HADDR  Command buffer high address (RO)
//   0x054  CRB_CTRL_RSP_SIZE   Response buffer size (RO)
//   0x058  CRB_CTRL_RSP_ADDR   Response buffer address (RO)
//   0x080  CRB_DATA_BUFFER     Start of shared data buffer

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile, copy_nonoverlapping};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS, thread_yield};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── CRB Control Area register offsets ──

/// Locality state register (RO).
/// Bit 7 = tpmRegValidSts, Bit 5 = activeLocality valid, Bits [4:2] = activeLocality,
/// Bit 1 = locAssigned, Bit 0 = tpmEstablishment.
const CRB_LOC_STATE: usize = 0x000;

/// Locality control register (RW).
/// Bit 3 = resetEstablishmentBit, Bit 2 = relinquish, Bit 1 = seize, Bit 0 = requestAccess.
const CRB_LOC_CTRL: usize = 0x004;

/// Locality status register (RO).
/// Bit 1 = beenSeized, Bit 0 = granted.
const CRB_LOC_STS: usize = 0x008;

/// Interface identifier register (RO).
/// Bits [3:0] = interface type: 0x7 = CRB active, 0xF = TIS active.
const CRB_INTF_ID: usize = 0x014;

/// Control request register (RW).
/// Bit 1 = goIdle, Bit 0 = cmdReady.
const CRB_CTRL_REQ: usize = 0x030;

/// Control status register (RO).
/// Bit 1 = tpmIdle, Bit 0 = tpmSts (error).
const CRB_CTRL_STS: usize = 0x034;

/// Cancel register (RW). Write 1 to cancel the current command.
const CRB_CTRL_CANCEL: usize = 0x038;

/// Start register (RW). Write 1 to begin command processing.
/// Reads 0 when the TPM has completed the command.
const CRB_CTRL_START: usize = 0x03C;

/// Interrupt enable register (RW).
const _CRB_INT_ENABLE: usize = 0x040;

/// Interrupt status register (R/WC).
const _CRB_INT_STS: usize = 0x044;

/// Command buffer size register (RO, 32-bit).
const CRB_CTRL_CMD_SIZE: usize = 0x048;

/// Command buffer low address register (RO, 32-bit).
const CRB_CTRL_CMD_LADDR: usize = 0x04C;

/// Command buffer high address register (RO, 32-bit).
const CRB_CTRL_CMD_HADDR: usize = 0x050;

/// Response buffer size register (RO, 32-bit).
const CRB_CTRL_RSP_SIZE: usize = 0x054;

/// Response buffer address register (RO, 32-bit — low 32 bits).
const CRB_CTRL_RSP_ADDR: usize = 0x058;

/// Start of the data buffer (command/response share this region).
const CRB_DATA_BUFFER: usize = 0x080;

// ── CRB register bit definitions ──

// LOC_STATE bits
const LOC_STATE_TPM_REG_VALID_STS: u32 = 1 << 7;
const LOC_STATE_LOC_ASSIGNED: u32 = 1 << 1;

// LOC_CTRL bits
const LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
const LOC_CTRL_RELINQUISH: u32 = 1 << 2;

// LOC_STS bits
const LOC_STS_GRANTED: u32 = 1 << 0;

// CRB_INTF_ID bits
const CRB_INTF_ID_TYPE_MASK: u32 = 0x0F;
const CRB_INTF_ID_TYPE_CRB: u32 = 0x07;

// CRB_CTRL_REQ bits
const CRB_CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CRB_CTRL_REQ_GO_IDLE: u32 = 1 << 1;

// CRB_CTRL_STS bits
const CRB_CTRL_STS_TPM_IDLE: u32 = 1 << 1;
const CRB_CTRL_STS_TPM_STS_ERROR: u32 = 1 << 0;

// CRB_CTRL_START bits
const CRB_CTRL_START_CMD: u32 = 1 << 0;

// ── TPM2 command/response structures ──

/// TPM2 command tags
const TPM2_ST_NO_SESSIONS: u16 = 0x8001;

/// TPM2 command codes
const TPM2_CC_STARTUP: u32 = 0x0000_0144;
const TPM2_CC_SELF_TEST: u32 = 0x0000_0143;
const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM2_CC_GET_RANDOM: u32 = 0x0000_017B;

/// TPM2 Startup types
const TPM2_SU_CLEAR: u16 = 0x0000;

/// TPM2 response codes
const TPM2_RC_SUCCESS: u32 = 0x0000_0000;
const TPM2_RC_INITIALIZE: u32 = 0x0000_0100;

/// TPM2 capability types
const TPM2_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

/// TPM2 property tags
const TPM2_PT_MANUFACTURER: u32 = 0x0000_0105;

/// TPM2 command header size (tag + commandSize + commandCode)
const TPM2_HDR_SIZE: usize = 10;

/// TPM2 response header size (tag + responseSize + responseCode)
const TPM2_RSP_HDR_SIZE: usize = 10;

// ── Default MMIO base and sizing ──

/// Standard TPM CRB MMIO base address (per TCG PTP specification).
const TPM_CRB_DEFAULT_BASE: u64 = 0xFED4_0000;

/// Size of the CRB MMIO region to map. Covers control area + data buffer.
/// The data buffer starts at 0x080 and is typically 3968 bytes (to fill 4K page).
const TPM_CRB_MMIO_SIZE: usize = 0x1000;

/// Maximum data buffer size (4096 - 0x80 = 3968 bytes).
const TPM_CRB_DATA_BUF_SIZE: usize = TPM_CRB_MMIO_SIZE - CRB_DATA_BUFFER;

/// Timeout for locality grant (in poll iterations).
const LOCALITY_TIMEOUT_ITERS: u32 = 200_000;

/// Timeout for command completion (in poll iterations).
const CMD_TIMEOUT_ITERS: u32 = 2_000_000;

/// Timeout for goReady/goIdle transitions (in poll iterations).
const READY_TIMEOUT_ITERS: u32 = 200_000;

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

// ── Driver state ──

struct TpmCrbState {
    /// Virtual address of CRB control area base.
    base: *mut u8,
    /// Physical address used for MMIO mapping.
    phys_base: u64,
    /// Command buffer size reported by hardware.
    cmd_buf_size: u32,
    /// Response buffer size reported by hardware.
    rsp_buf_size: u32,
    /// Whether locality 0 is currently held.
    locality_granted: bool,
    /// Whether the driver has been successfully initialized.
    initialized: bool,
}

impl TpmCrbState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            cmd_buf_size: 0,
            rsp_buf_size: 0,
            locality_granted: false,
            initialized: false,
        }
    }
}

static STATE: StaticCell<TpmCrbState> = StaticCell::new(TpmCrbState::new());

// ── MMIO helpers ──

#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

#[inline]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Internal helpers ──

/// Request locality 0 access from the TPM.
/// Returns 0 on success, -1 on timeout.
fn crb_request_locality(base: *mut u8) -> i32 {
    // Check if locality is already granted
    let loc_sts = mmio_read32(base, CRB_LOC_STS);
    if loc_sts & LOC_STS_GRANTED != 0 {
        return 0;
    }

    // Request access to locality 0
    mmio_write32(base, CRB_LOC_CTRL, LOC_CTRL_REQUEST_ACCESS);
    fence(Ordering::SeqCst);

    // Poll for grant
    for _ in 0..LOCALITY_TIMEOUT_ITERS {
        let sts = mmio_read32(base, CRB_LOC_STS);
        if sts & LOC_STS_GRANTED != 0 {
            return 0;
        }
        core::hint::spin_loop();
    }

    log("tpm_crb: locality request timeout");
    -1
}

/// Relinquish locality 0 access.
fn crb_relinquish_locality(base: *mut u8) {
    mmio_write32(base, CRB_LOC_CTRL, LOC_CTRL_RELINQUISH);
    fence(Ordering::SeqCst);
}

/// Transition TPM from idle to ready state (cmdReady).
/// Returns 0 on success, -1 on timeout.
fn crb_go_ready(base: *mut u8) -> i32 {
    // Check if already ready (not idle)
    let sts = mmio_read32(base, CRB_CTRL_STS);
    if sts & CRB_CTRL_STS_TPM_IDLE == 0 {
        return 0;
    }

    // Request transition to ready
    mmio_write32(base, CRB_CTRL_REQ, CRB_CTRL_REQ_CMD_READY);
    fence(Ordering::SeqCst);

    // Poll for idle bit to clear
    for _ in 0..READY_TIMEOUT_ITERS {
        let sts = mmio_read32(base, CRB_CTRL_STS);
        if sts & CRB_CTRL_STS_TPM_IDLE == 0 {
            return 0;
        }
        core::hint::spin_loop();
    }

    log("tpm_crb: goReady timeout");
    -1
}

/// Transition TPM to idle state.
/// Returns 0 on success, -1 on timeout.
fn crb_go_idle(base: *mut u8) -> i32 {
    // Request transition to idle
    mmio_write32(base, CRB_CTRL_REQ, CRB_CTRL_REQ_GO_IDLE);
    fence(Ordering::SeqCst);

    // Poll for idle bit to set
    for _ in 0..READY_TIMEOUT_ITERS {
        let sts = mmio_read32(base, CRB_CTRL_STS);
        if sts & CRB_CTRL_STS_TPM_IDLE != 0 {
            return 0;
        }
        core::hint::spin_loop();
    }

    log("tpm_crb: goIdle timeout");
    -1
}

/// Write a big-endian u16 into a byte buffer.
#[inline]
fn put_be16(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

/// Write a big-endian u32 into a byte buffer.
#[inline]
fn put_be32(buf: &mut [u8], val: u32) {
    buf[0] = (val >> 24) as u8;
    buf[1] = (val >> 16) as u8;
    buf[2] = (val >> 8) as u8;
    buf[3] = val as u8;
}

/// Read a big-endian u16 from a byte buffer.
#[inline]
fn get_be16(buf: &[u8]) -> u16 {
    (buf[0] as u16) << 8 | buf[1] as u16
}

/// Read a big-endian u32 from a byte buffer.
#[inline]
fn get_be32(buf: &[u8]) -> u32 {
    (buf[0] as u32) << 24
        | (buf[1] as u32) << 16
        | (buf[2] as u32) << 8
        | buf[3] as u32
}

/// Build a TPM2 command header in the given buffer.
/// Returns the header size (always TPM2_HDR_SIZE = 10).
fn build_cmd_header(buf: &mut [u8], tag: u16, cmd_size: u32, cmd_code: u32) {
    put_be16(&mut buf[0..2], tag);
    put_be32(&mut buf[2..6], cmd_size);
    put_be32(&mut buf[6..10], cmd_code);
}

/// Submit a command to the TPM via CRB and read the response.
///
/// `cmd` / `cmd_len`: command buffer and length (must include full TPM2 header).
/// `rsp` / `rsp_size`: response buffer and its capacity.
///
/// On success, `*rsp_size` is updated to the actual response length.
/// Returns 0 on success, negative on error:
///   -1 = not initialized
///   -2 = command too large for hardware buffer
///   -3 = response buffer too small
///   -4 = goReady failed
///   -5 = command start timeout
///   -6 = TPM status error after command
fn crb_submit_command(
    base: *mut u8,
    cmd: *const u8,
    cmd_len: u32,
    rsp: *mut u8,
    rsp_size: *mut u32,
    hw_cmd_size: u32,
    hw_rsp_size: u32,
) -> i32 {
    let cmd_len_usize = cmd_len as usize;

    // Validate command fits in hardware command buffer
    if cmd_len > hw_cmd_size {
        log("tpm_crb: command too large for hardware buffer");
        return -2;
    }

    // Ensure TPM is in ready state
    if crb_go_ready(base) != 0 {
        return -4;
    }

    // Write command bytes to the data buffer using volatile byte writes
    // to ensure each byte hits MMIO properly
    let data_buf = unsafe { base.add(CRB_DATA_BUFFER) };
    for i in 0..cmd_len_usize {
        unsafe {
            write_volatile(data_buf.add(i), *cmd.add(i));
        }
    }
    fence(Ordering::SeqCst);

    // Clear any previous cancel
    mmio_write32(base, CRB_CTRL_CANCEL, 0);

    // Start command processing
    mmio_write32(base, CRB_CTRL_START, CRB_CTRL_START_CMD);
    fence(Ordering::SeqCst);

    // Poll for completion: CRB_CTRL_START reads 0 when done
    let mut completed = false;
    for i in 0..CMD_TIMEOUT_ITERS {
        let start_val = mmio_read32(base, CRB_CTRL_START);
        if start_val & CRB_CTRL_START_CMD == 0 {
            completed = true;
            break;
        }
        // Yield periodically to avoid starving other threads
        if i % 1024 == 0 && i > 0 {
            thread_yield();
        }
        core::hint::spin_loop();
    }

    if !completed {
        // Attempt to cancel the command
        mmio_write32(base, CRB_CTRL_CANCEL, 1);
        fence(Ordering::SeqCst);
        log("tpm_crb: command completion timeout");
        let _ = crb_go_idle(base);
        return -5;
    }

    // Check for TPM status error
    let sts = mmio_read32(base, CRB_CTRL_STS);
    if sts & CRB_CTRL_STS_TPM_STS_ERROR != 0 {
        log("tpm_crb: TPM status error after command");
        let _ = crb_go_idle(base);
        return -6;
    }

    // Read response header to determine total response size
    // Response is in the data buffer (same as command buffer for CRB)
    let mut rsp_hdr = [0u8; TPM2_RSP_HDR_SIZE];
    for i in 0..TPM2_RSP_HDR_SIZE {
        rsp_hdr[i] = unsafe { read_volatile(data_buf.add(i)) };
    }

    let rsp_total = get_be32(&rsp_hdr[2..6]) as usize;

    // Validate response size
    if rsp_total < TPM2_RSP_HDR_SIZE {
        log("tpm_crb: invalid response size from TPM");
        let _ = crb_go_idle(base);
        return -6;
    }

    let rsp_cap = unsafe { *rsp_size } as usize;
    let copy_len = if rsp_total > rsp_cap { rsp_cap } else { rsp_total };

    // Validate response fits within hardware response buffer
    if rsp_total > hw_rsp_size as usize {
        log("tpm_crb: response exceeds hardware buffer size");
        let _ = crb_go_idle(base);
        return -6;
    }

    // Copy response data from data buffer to caller's buffer
    for i in 0..copy_len {
        unsafe {
            *rsp.add(i) = read_volatile(data_buf.add(i));
        }
    }

    unsafe {
        *rsp_size = copy_len as u32;
    }

    // Transition back to idle
    let _ = crb_go_idle(base);

    if rsp_total > rsp_cap {
        return -3; // Response truncated
    }

    0
}

/// Execute a simple TPM2 command with a local stack buffer for the response.
/// Returns the TPM2 response code, or a negative error code.
fn execute_simple_command(cmd: &[u8], rsp: &mut [u8; 4096]) -> i32 {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;
        let hw_cmd_size = (*state).cmd_buf_size;
        let hw_rsp_size = (*state).rsp_buf_size;

        let mut rsp_len: u32 = 4096;
        let rc = crb_submit_command(
            base,
            cmd.as_ptr(),
            cmd.len() as u32,
            rsp.as_mut_ptr(),
            &mut rsp_len as *mut u32,
            hw_cmd_size,
            hw_rsp_size,
        );
        if rc < 0 {
            return rc;
        }

        if rsp_len < TPM2_RSP_HDR_SIZE as u32 {
            return -6;
        }

        // Extract TPM2 response code
        get_be32(&rsp[6..10]) as i32
    }
}

// ── FFI exports ──

/// Initialize the TPM 2.0 CRB interface driver.
///
/// Detects and validates the CRB interface, requests locality 0,
/// and reads hardware buffer sizes.
///
/// Returns 0 on success, negative on error:
///   -1 = MMIO mapping failed
///   -2 = not a CRB interface (TIS or absent)
///   -3 = TPM register not valid
///   -4 = locality request failed
///   -5 = invalid buffer configuration
#[unsafe(no_mangle)]
pub extern "C" fn tpm_crb_init() -> i32 {
    log("tpm_crb: initializing TPM 2.0 CRB interface");

    // Map CRB MMIO region
    let base = unsafe { map_mmio_region(TPM_CRB_DEFAULT_BASE, TPM_CRB_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("tpm_crb: failed to map MMIO region");
        return -1;
    }

    // Check interface type
    let intf_id = mmio_read32(base, CRB_INTF_ID);
    let intf_type = intf_id & CRB_INTF_ID_TYPE_MASK;

    if intf_type != CRB_INTF_ID_TYPE_CRB {
        unsafe {
            fut_printf(
                b"tpm_crb: not a CRB interface (type=0x%x)\n\0".as_ptr(),
                intf_type,
            );
            unmap_mmio_region(base, TPM_CRB_MMIO_SIZE);
        }
        return -2;
    }

    // Verify TPM register validity
    let loc_state = mmio_read32(base, CRB_LOC_STATE);
    if loc_state & LOC_STATE_TPM_REG_VALID_STS == 0 {
        log("tpm_crb: TPM registers not valid");
        unsafe { unmap_mmio_region(base, TPM_CRB_MMIO_SIZE); }
        return -3;
    }

    // Request locality 0
    if crb_request_locality(base) != 0 {
        log("tpm_crb: failed to acquire locality 0");
        unsafe { unmap_mmio_region(base, TPM_CRB_MMIO_SIZE); }
        return -4;
    }

    // Read command and response buffer configuration
    let cmd_buf_size = mmio_read32(base, CRB_CTRL_CMD_SIZE);
    let rsp_buf_size = mmio_read32(base, CRB_CTRL_RSP_SIZE);
    let cmd_laddr = mmio_read32(base, CRB_CTRL_CMD_LADDR);
    let cmd_haddr = mmio_read32(base, CRB_CTRL_CMD_HADDR);
    let rsp_addr = mmio_read32(base, CRB_CTRL_RSP_ADDR);

    if cmd_buf_size == 0 || rsp_buf_size == 0 {
        log("tpm_crb: invalid buffer sizes reported by hardware");
        crb_relinquish_locality(base);
        unsafe { unmap_mmio_region(base, TPM_CRB_MMIO_SIZE); }
        return -5;
    }

    // Log interface details
    unsafe {
        fut_printf(
            b"tpm_crb: CRB interface detected (intf_id=0x%08x)\n\0".as_ptr(),
            intf_id,
        );
        fut_printf(
            b"tpm_crb: cmd buffer: addr=0x%08x%08x size=%u\n\0".as_ptr(),
            cmd_haddr,
            cmd_laddr,
            cmd_buf_size,
        );
        fut_printf(
            b"tpm_crb: rsp buffer: addr=0x%08x size=%u\n\0".as_ptr(),
            rsp_addr,
            rsp_buf_size,
        );
    }

    // Transition TPM to idle, then ready, to ensure clean state
    let _ = crb_go_idle(base);
    if crb_go_ready(base) != 0 {
        log("tpm_crb: WARNING — could not transition to ready state");
    }
    let _ = crb_go_idle(base);

    // Store driver state
    let state = STATE.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = TPM_CRB_DEFAULT_BASE;
        (*state).cmd_buf_size = cmd_buf_size;
        (*state).rsp_buf_size = rsp_buf_size;
        (*state).locality_granted = true;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    log("tpm_crb: driver initialized successfully");
    0
}

/// Send TPM2_Startup(TPM_SU_CLEAR) command.
///
/// This should be called once after platform reset to transition the TPM
/// from the initialization state to operational state.
///
/// Returns 0 on success, negative on error.
/// Returns 0 also if TPM responds with TPM_RC_INITIALIZE (already started).
#[unsafe(no_mangle)]
pub extern "C" fn tpm_crb_startup() -> i32 {
    log("tpm_crb: sending TPM2_Startup(CLEAR)");

    // TPM2_Startup: header(10) + startupType(2) = 12 bytes
    let mut cmd = [0u8; 12];
    build_cmd_header(&mut cmd, TPM2_ST_NO_SESSIONS, 12, TPM2_CC_STARTUP);
    put_be16(&mut cmd[10..12], TPM2_SU_CLEAR);

    let mut rsp = [0u8; 4096];
    let rc = execute_simple_command(&cmd, &mut rsp);

    if rc < 0 {
        unsafe {
            fut_printf(b"tpm_crb: TPM2_Startup failed (rc=%d)\n\0".as_ptr(), rc);
        }
        return rc;
    }

    let tpm_rc = rc as u32;
    if tpm_rc == TPM2_RC_SUCCESS {
        log("tpm_crb: TPM2_Startup successful");
        0
    } else if tpm_rc == TPM2_RC_INITIALIZE {
        log("tpm_crb: TPM already started (RC_INITIALIZE)");
        0
    } else {
        unsafe {
            fut_printf(
                b"tpm_crb: TPM2_Startup returned 0x%08x\n\0".as_ptr(),
                tpm_rc,
            );
        }
        -1
    }
}

/// Send TPM2_SelfTest(fullTest=YES) command.
///
/// Causes the TPM to perform a full self-test of all algorithms and functions.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn tpm_crb_self_test() -> i32 {
    log("tpm_crb: sending TPM2_SelfTest(full)");

    // TPM2_SelfTest: header(10) + fullTest(1) = 11 bytes
    let mut cmd = [0u8; 11];
    build_cmd_header(&mut cmd, TPM2_ST_NO_SESSIONS, 11, TPM2_CC_SELF_TEST);
    cmd[10] = 1; // fullTest = YES

    let mut rsp = [0u8; 4096];
    let rc = execute_simple_command(&cmd, &mut rsp);

    if rc < 0 {
        unsafe {
            fut_printf(b"tpm_crb: TPM2_SelfTest failed (rc=%d)\n\0".as_ptr(), rc);
        }
        return rc;
    }

    let tpm_rc = rc as u32;
    if tpm_rc == TPM2_RC_SUCCESS {
        log("tpm_crb: TPM2_SelfTest passed");
        0
    } else {
        unsafe {
            fut_printf(
                b"tpm_crb: TPM2_SelfTest returned 0x%08x\n\0".as_ptr(),
                tpm_rc,
            );
        }
        -1
    }
}

/// Request random bytes from the TPM via TPM2_GetRandom.
///
/// `buf`: output buffer for random bytes.
/// `len`: number of random bytes requested (max 32 per call per TPM spec).
///
/// Returns the number of bytes actually written on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn tpm_crb_get_random(buf: *mut u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -1;
    }

    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
    }

    // TPM2_GetRandom: header(10) + bytesRequested(2) = 12 bytes
    let mut cmd = [0u8; 12];
    build_cmd_header(&mut cmd, TPM2_ST_NO_SESSIONS, 12, TPM2_CC_GET_RANDOM);
    // bytesRequested is a u16 in the spec; clamp to reasonable maximum
    let req_bytes = if len > 32 { 32u16 } else { len as u16 };
    put_be16(&mut cmd[10..12], req_bytes);

    let mut rsp = [0u8; 4096];
    let rc = execute_simple_command(&cmd, &mut rsp);

    if rc < 0 {
        return rc;
    }

    let tpm_rc = rc as u32;
    if tpm_rc != TPM2_RC_SUCCESS {
        unsafe {
            fut_printf(
                b"tpm_crb: TPM2_GetRandom returned 0x%08x\n\0".as_ptr(),
                tpm_rc,
            );
        }
        return -1;
    }

    // Response format after header: TPM2B_DIGEST { size(u16), buffer[size] }
    if rsp.len() < TPM2_RSP_HDR_SIZE + 2 {
        return -1;
    }

    let digest_size = get_be16(&rsp[TPM2_RSP_HDR_SIZE..TPM2_RSP_HDR_SIZE + 2]) as usize;

    if digest_size == 0 {
        return 0;
    }

    let data_start = TPM2_RSP_HDR_SIZE + 2;
    let available = digest_size.min(len as usize);

    if data_start + available > rsp.len() {
        return -1;
    }

    // Copy random bytes to caller's buffer
    unsafe {
        copy_nonoverlapping(rsp[data_start..].as_ptr(), buf, available);
    }

    available as i32
}

/// Send a raw TPM2 command and receive the response.
///
/// `cmd` / `cmd_len`: complete TPM2 command (including header).
/// `rsp` / `rsp_len`: response buffer and its capacity. On return,
///   `*rsp_len` is updated to the actual response length.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn tpm_crb_send_command(
    cmd: *const u8,
    cmd_len: u32,
    rsp: *mut u8,
    rsp_len: *mut u32,
) -> i32 {
    if cmd.is_null() || rsp.is_null() || rsp_len.is_null() {
        return -1;
    }

    if cmd_len < TPM2_HDR_SIZE as u32 {
        log("tpm_crb: command too short (missing header)");
        return -1;
    }

    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;
        let hw_cmd_size = (*state).cmd_buf_size;
        let hw_rsp_size = (*state).rsp_buf_size;

        crb_submit_command(base, cmd, cmd_len, rsp, rsp_len, hw_cmd_size, hw_rsp_size)
    }
}

/// Check whether a TPM 2.0 CRB interface is present and initialized.
///
/// Returns `true` if the driver has been successfully initialized.
#[unsafe(no_mangle)]
pub extern "C" fn tpm_crb_is_present() -> bool {
    let state = STATE.get();
    unsafe { (*state).initialized }
}
