// SPDX-License-Identifier: MPL-2.0
//
// ChromeOS Embedded Controller (cros_ec) -- LPC transport.
//
// Validates the host-command interface end-to-end on Chromebook
// hardware. Probes four commands in order: HELLO, GET_PROTOCOL_INFO,
// GET_VERSION, GET_BOARD_VERSION. The version string carries the EC
// firmware codename (e.g. "meep" = HP Chromebook 11 G7 EE, octopus
// family), which is the primary key for looking up board-specific
// behavior in coreboot / chromeos-ec sources.
//
// Originally written to chase SD card VDD gating on the HP Chromebook
// 11 G7. That turned out to be misdirected: on octopus boards the
// physical microSD slot is wired to a USB Mass Storage bridge on
// usb2_port6/usb3_port6, NOT to the SDHC PCI controller at 00:1c.0.
// The EC has no SD-related GPIOs. The driver is kept because the
// host-command interface is still the right path for future work on
// battery, thermal, keyboard backlight, and USB-PD on Chromebooks.
//
// LPC bus layout (Apollo / Gemini Lake era):
//   0x800–0x8FF    HOST_PACKET region (v3 protocol)
//   0x900–0x9FF    MEMMAP (status / sensors / id)
//   0x204          Host command/status register
//   0x200          Host data register (legacy v1 args)
//
// Protocol v3 packet flow (the modern path):
//   1. Build ec_host_request header (8 bytes) + payload, place at 0x800+
//   2. Write 0xda (EC_COMMAND_PROTOCOL_3) to 0x204 to trigger
//   3. Poll 0x204 until BUSY (bit 1 IBF | bit 2 PROC) clears
//   4. Read ec_host_response header (8 bytes) + payload from 0x800+
//   5. Verify checksum, return data
//
// This pass is still read-only with respect to platform state: every
// command we send is a query, not a control op.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── LPC port layout ──────────────────────────────────────────────────────────

const EC_LPC_ADDR_HOST_PACKET: u16 = 0x800;
const EC_LPC_ADDR_HOST_CMD: u16 = 0x204;
const EC_LPC_ADDR_MEMMAP: u16 = 0x900;
const EC_LPC_HOST_PACKET_SIZE: usize = 256;

const EC_MEMMAP_ID_OFF: u16 = 0x20;
const EC_MEMMAP_ID_VERSION_OFF: u16 = 0x22;

// EC status byte bits (read from EC_LPC_ADDR_HOST_CMD)
const EC_LPC_STATUS_FROM_HOST: u8 = 0x02; // IBF
const EC_LPC_STATUS_PROCESSING: u8 = 0x04;
const EC_LPC_STATUS_BUSY_MASK: u8 = EC_LPC_STATUS_FROM_HOST | EC_LPC_STATUS_PROCESSING;

// v3 protocol trigger
const EC_COMMAND_PROTOCOL_3: u8 = 0xda;

// Command codes (subset)
const EC_CMD_HELLO: u16 = 0x0001;
const EC_CMD_GET_VERSION: u16 = 0x0002;
const EC_CMD_GET_BOARD_VERSION: u16 = 0x0006;
const EC_CMD_GET_PROTOCOL_INFO: u16 = 0x000b;

// Result codes (subset --see ec_commands.h enum ec_status)
const EC_RES_SUCCESS: u16 = 0;

// ── x86 I/O port helpers ─────────────────────────────────────────────────────

fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

// ── v3 packet protocol ──────────────────────────────────────────────────────

/// ec_host_request header --8 bytes, little-endian, packed.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EcHostRequest {
    struct_version: u8, // = 3
    checksum: u8,       // two's complement of sum of all bytes (header + data)
    command: u16,
    command_version: u8,
    reserved: u8,
    data_len: u16,
}

/// ec_host_response header --8 bytes, little-endian, packed.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct EcHostResponse {
    struct_version: u8,
    checksum: u8,
    result: u16,
    data_len: u16,
    reserved: u16,
}

/// Wait for the EC's busy bits to clear, with a bounded polling loop.
/// Each iteration is one port read (~1 µs) so 200_000 ≈ 200 ms --plenty
/// for the slow commands and we return promptly for quick ones.
fn wait_ready() -> Result<(), i32> {
    for _ in 0..200_000 {
        let s = io_inb(EC_LPC_ADDR_HOST_CMD);
        if s & EC_LPC_STATUS_BUSY_MASK == 0 {
            return Ok(());
        }
    }
    Err(-110) // ETIMEDOUT
}

/// Send a v3 packet command. `params` is the request payload (after
/// the 8-byte header); `result` is the buffer for the response payload
/// (after the 8-byte header). Returns the response data length on
/// success, or a negative errno on failure.
fn send_v3(cmd: u16, version: u8, params: &[u8], result: &mut [u8]) -> Result<usize, i32> {
    if params.len() > EC_LPC_HOST_PACKET_SIZE - 8 {
        return Err(-22); // EINVAL
    }

    wait_ready()?;

    // Compose the request header in a local stack buffer.
    let mut req = EcHostRequest {
        struct_version: 3,
        checksum: 0,
        command: cmd,
        command_version: version,
        reserved: 0,
        data_len: params.len() as u16,
    };

    // Compute checksum: sum of all bytes (header + payload) must equal 0
    // (two's complement). Build a local 8-byte serialization to sum.
    let header_bytes: [u8; 8] = unsafe {
        core::mem::transmute::<EcHostRequest, [u8; 8]>(req)
    };
    let mut sum: u8 = 0;
    for &b in header_bytes.iter() {
        sum = sum.wrapping_add(b);
    }
    for &b in params.iter() {
        sum = sum.wrapping_add(b);
    }
    req.checksum = (0u8).wrapping_sub(sum);

    // Write header + payload to the host packet region.
    let header_bytes: [u8; 8] = unsafe {
        core::mem::transmute::<EcHostRequest, [u8; 8]>(req)
    };
    for (i, &b) in header_bytes.iter().enumerate() {
        io_outb(EC_LPC_ADDR_HOST_PACKET + i as u16, b);
    }
    for (i, &b) in params.iter().enumerate() {
        io_outb(EC_LPC_ADDR_HOST_PACKET + 8 + i as u16, b);
    }

    // Trigger.
    io_outb(EC_LPC_ADDR_HOST_CMD, EC_COMMAND_PROTOCOL_3);

    wait_ready()?;

    // Read response header.
    let mut resp_bytes = [0u8; 8];
    for i in 0..8 {
        resp_bytes[i] = io_inb(EC_LPC_ADDR_HOST_PACKET + i as u16);
    }
    let resp: EcHostResponse =
        unsafe { core::mem::transmute::<[u8; 8], EcHostResponse>(resp_bytes) };

    let resp_struct_ver = resp.struct_version;
    let resp_result = resp.result;
    let resp_data_len = resp.data_len;

    if resp_struct_ver != 3 {
        unsafe {
            fut_printf(
                b"[CROS-EC]  unexpected response struct_version=%u\n\0".as_ptr(),
                resp_struct_ver as u32,
            );
        }
        return Err(-71); // EPROTO
    }
    if resp_result != EC_RES_SUCCESS {
        return Err(-(1000 + resp_result as i32));
    }
    if resp_data_len as usize > result.len()
        || (resp_data_len as usize) > (EC_LPC_HOST_PACKET_SIZE - 8)
    {
        return Err(-90); // EMSGSIZE
    }

    for i in 0..resp_data_len as usize {
        result[i] = io_inb(EC_LPC_ADDR_HOST_PACKET + 8 + i as u16);
    }
    Ok(resp_data_len as usize)
}

// ── Memmap detection + dump (carried over from the previous pass) ───────────

fn detect() -> bool {
    let id0 = io_inb(EC_LPC_ADDR_MEMMAP + EC_MEMMAP_ID_OFF);
    let id1 = io_inb(EC_LPC_ADDR_MEMMAP + EC_MEMMAP_ID_OFF + 1);
    unsafe {
        fut_printf(
            b"[CROS-EC] memmap[0x20..0x22] = 0x%02x 0x%02x (expect 0x45='E' 0x43='C')\n\0".as_ptr(),
            id0 as u32, id1 as u32,
        );
    }
    id0 == b'E' && id1 == b'C'
}

// ── Command probes (HELLO, PROTOCOL_INFO, VERSION, BOARD_VERSION) ───────────

fn probe_hello() -> Result<(), i32> {
    /* HELLO: send 4-byte in_data, expect out_data = in_data + 0x01020304 */
    let in_data: u32 = 0xa0b0_c0d0;
    let params = in_data.to_le_bytes();
    let mut result = [0u8; 8];
    let n = send_v3(EC_CMD_HELLO, 0, &params, &mut result)?;
    if n != 4 {
        unsafe {
            fut_printf(
                b"[CROS-EC]  HELLO: unexpected response length %u (want 4)\n\0".as_ptr(),
                n as u32,
            );
        }
        return Err(-71);
    }
    let out_data = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
    let expect = in_data.wrapping_add(0x0102_0304);
    unsafe {
        fut_printf(
            b"[CROS-EC]  HELLO: in=0x%08x out=0x%08x expect=0x%08x %s\n\0".as_ptr(),
            in_data,
            out_data,
            expect,
            if out_data == expect { b"OK\0".as_ptr() } else { b"MISMATCH\0".as_ptr() },
        );
    }
    if out_data == expect { Ok(()) } else { Err(-71) }
}

fn probe_protocol_info() {
    let mut result = [0u8; 32];
    match send_v3(EC_CMD_GET_PROTOCOL_INFO, 0, &[], &mut result) {
        Ok(n) if n >= 12 => {
            let proto_vers = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
            let max_req = u16::from_le_bytes([result[4], result[5]]);
            let max_resp = u16::from_le_bytes([result[6], result[7]]);
            let flags = u32::from_le_bytes([result[8], result[9], result[10], result[11]]);
            unsafe {
                fut_printf(
                    b"[CROS-EC]  PROTOCOL_INFO: versions=0x%08x max_req=%u max_resp=%u flags=0x%08x\n\0".as_ptr(),
                    proto_vers, max_req as u32, max_resp as u32, flags,
                );
            }
        }
        Ok(n) => unsafe {
            fut_printf(
                b"[CROS-EC]  PROTOCOL_INFO: short response (%u bytes)\n\0".as_ptr(),
                n as u32,
            );
        },
        Err(rc) => unsafe {
            fut_printf(b"[CROS-EC]  PROTOCOL_INFO: failed rc=%d\n\0".as_ptr(), rc);
        },
    }
}

fn probe_version() {
    /* GET_VERSION: response is 3 x 32-byte strings + 4-byte current_image */
    let mut result = [0u8; 32 * 3 + 4];
    match send_v3(EC_CMD_GET_VERSION, 0, &[], &mut result) {
        Ok(n) if n >= 96 => {
            /* Ensure trailing NUL so printf %s is safe. */
            let mut ro = [0u8; 33]; ro[..32].copy_from_slice(&result[0..32]);
            let mut rw = [0u8; 33]; rw[..32].copy_from_slice(&result[32..64]);
            let cur = if n >= 100 {
                u32::from_le_bytes([result[96], result[97], result[98], result[99]])
            } else { 0 };
            unsafe {
                fut_printf(
                    b"[CROS-EC]  VERSION: RO='%s' RW='%s' current_image=%u (1=RO 2=RW)\n\0".as_ptr(),
                    ro.as_ptr(), rw.as_ptr(), cur,
                );
            }
        }
        Ok(n) => unsafe {
            fut_printf(b"[CROS-EC]  VERSION: short response (%u bytes)\n\0".as_ptr(), n as u32);
        },
        Err(rc) => unsafe {
            fut_printf(b"[CROS-EC]  VERSION: failed rc=%d\n\0".as_ptr(), rc);
        },
    }
}

fn probe_board_version() {
    let mut result = [0u8; 2];
    match send_v3(EC_CMD_GET_BOARD_VERSION, 0, &[], &mut result) {
        Ok(n) if n >= 2 => {
            let bv = u16::from_le_bytes([result[0], result[1]]);
            unsafe {
                fut_printf(b"[CROS-EC]  BOARD_VERSION: %u\n\0".as_ptr(), bv as u32);
            }
        }
        Ok(_) => unsafe {
            fut_printf(b"[CROS-EC]  BOARD_VERSION: short response\n\0".as_ptr());
        },
        Err(rc) => unsafe {
            fut_printf(b"[CROS-EC]  BOARD_VERSION: failed rc=%d\n\0".as_ptr(), rc);
        },
    }
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Probe + identify the ChromeOS EC. Returns 0 if the EC responded to
/// at least HELLO; -1 if no signature was found at the memmap region;
/// negative errno from HELLO if the signature was there but command
/// transport doesn't work.
#[unsafe(no_mangle)]
pub extern "C" fn cros_ec_init() -> i32 {
    log("[CROS-EC] probing LPC memmap at 0x900 for ChromeOS EC signature");
    if !detect() {
        log("[CROS-EC] no ChromeOS EC signature --not a Chromebook or EC uses SPI/I2C transport");
        return -1;
    }
    let mver = io_inb(EC_LPC_ADDR_MEMMAP + EC_MEMMAP_ID_VERSION_OFF);
    unsafe {
        fut_printf(
            b"[CROS-EC] ChromeOS EC detected, memmap version=%u --issuing host commands\n\0".as_ptr(),
            mver as u32,
        );
    }

    match probe_hello() {
        Ok(()) => {
            /* HELLO worked → v3 packet protocol is live. Pull more info. */
            probe_protocol_info();
            probe_version();
            probe_board_version();
            0
        }
        Err(rc) => {
            unsafe {
                fut_printf(
                    b"[CROS-EC]  HELLO failed rc=%d --v3 packet protocol not supported on this EC; subsequent commands skipped\n\0".as_ptr(),
                    rc,
                );
            }
            rc
        }
    }
}
