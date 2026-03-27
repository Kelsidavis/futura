// SPDX-License-Identifier: MPL-2.0
//
// EDID (Extended Display Identification Data) Parser for Futura OS
//
// Parses the 128-byte (base) or 256-byte (with extensions) EDID data block
// read from a display monitor via DDC/I2C (address 0x50).
//
// Implements:
//   - Header validation (magic 00 FF FF FF FF FF FF 00)
//   - Checksum verification (sum of all bytes mod 256 == 0)
//   - Manufacturer ID decoding (3 compressed ASCII chars from 2 bytes)
//   - Preferred timing extraction from first detailed timing descriptor
//   - Monitor name extraction from display descriptor 0xFC
//   - Standard timing parsing (8 entries, 2 bytes each)
//   - Established timing support bitmask
//   - Extension block detection (CEA-861 for HDMI)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── EDID constants ──

/// Minimum EDID base block size.
const EDID_BASE_LEN: u32 = 128;

/// EDID with one extension block.
const EDID_EXT_LEN: u32 = 256;

/// EDID header magic bytes.
const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

// ── Display descriptor tag definitions ──

/// Monitor name descriptor tag.
const DESC_TAG_MONITOR_NAME: u8 = 0xFC;
/// Monitor range limits descriptor tag.
const _DESC_TAG_MONITOR_RANGE: u8 = 0xFD;
/// ASCII string descriptor tag.
const _DESC_TAG_STRING: u8 = 0xFE;
/// Serial number string descriptor tag.
const _DESC_TAG_SERIAL: u8 = 0xFF;

// ── CEA extension constants ──

/// CEA-861 extension block tag.
const CEA_EXT_TAG: u8 = 0x02;

/// HDMI vendor-specific IEEE OUI (in LE order): 00-0C-03 -> bytes 03, 0C, 00.
const HDMI_IEEE_OUI: [u8; 3] = [0x03, 0x0C, 0x00];

// ── EdidInfo structure ──

/// Parsed EDID information returned to C callers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct EdidInfo {
    /// 3-character manufacturer ID plus null terminator.
    pub manufacturer: [u8; 4],
    /// Manufacturer product code (little-endian from EDID).
    pub product_code: u16,
    /// Serial number (32-bit LE from EDID).
    pub serial: u32,
    /// Year of manufacture (byte 17 + 1990).
    pub year: u16,
    /// Week of manufacture.
    pub week: u8,
    /// EDID version major.
    pub version: u8,
    /// EDID revision.
    pub revision: u8,
    /// True if digital video input (bit 7 of byte 20).
    pub digital: bool,
    /// Horizontal screen size in cm.
    pub width_cm: u8,
    /// Vertical screen size in cm.
    pub height_cm: u8,
    /// Preferred horizontal resolution in pixels.
    pub preferred_width: u32,
    /// Preferred vertical resolution in pixels.
    pub preferred_height: u32,
    /// Preferred refresh rate in Hz.
    pub preferred_refresh: u32,
    /// Monitor name from descriptor 0xFC (null-terminated, up to 13 chars).
    pub monitor_name: [u8; 14],
    /// Display gamma value (raw: (gamma*100)-100, so 120 = 2.2).
    pub gamma: u8,
    /// True if HDMI detected in CEA extension.
    pub hdmi: bool,
    /// True if digital input suggests DisplayPort (digital + no HDMI).
    pub dp: bool,
}

impl EdidInfo {
    const fn zero() -> Self {
        Self {
            manufacturer: [0; 4],
            product_code: 0,
            serial: 0,
            year: 0,
            week: 0,
            version: 0,
            revision: 0,
            digital: false,
            width_cm: 0,
            height_cm: 0,
            preferred_width: 0,
            preferred_height: 0,
            preferred_refresh: 0,
            monitor_name: [0; 14],
            gamma: 0,
            hdmi: false,
            dp: false,
        }
    }
}

// ── Internal helpers ──

/// Read a single byte from the EDID data buffer with bounds checking.
/// Returns 0 if out of bounds.
#[inline]
fn edid_byte(data: *const u8, len: u32, offset: u32) -> u8 {
    if offset >= len {
        return 0;
    }
    unsafe { *data.add(offset as usize) }
}

/// Read a 16-bit little-endian value from the EDID data buffer.
#[inline]
fn edid_le16(data: *const u8, len: u32, offset: u32) -> u16 {
    let lo = edid_byte(data, len, offset) as u16;
    let hi = edid_byte(data, len, offset + 1) as u16;
    lo | (hi << 8)
}

/// Read a 32-bit little-endian value from the EDID data buffer.
#[inline]
fn edid_le32(data: *const u8, len: u32, offset: u32) -> u32 {
    let b0 = edid_byte(data, len, offset) as u32;
    let b1 = edid_byte(data, len, offset + 1) as u32;
    let b2 = edid_byte(data, len, offset + 2) as u32;
    let b3 = edid_byte(data, len, offset + 3) as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Validate the 8-byte EDID header.
fn validate_header(data: *const u8, len: u32) -> bool {
    if len < EDID_BASE_LEN {
        return false;
    }
    for i in 0..8u32 {
        if edid_byte(data, len, i) != EDID_HEADER[i as usize] {
            return false;
        }
    }
    true
}

/// Verify the EDID checksum (sum of all bytes in a 128-byte block must be 0 mod 256).
fn verify_checksum(data: *const u8, len: u32, block_start: u32) -> bool {
    if block_start + 128 > len {
        return false;
    }
    let mut sum: u8 = 0;
    for i in 0..128u32 {
        sum = sum.wrapping_add(edid_byte(data, len, block_start + i));
    }
    sum == 0
}

/// Decode the 3-character manufacturer ID from bytes 8-9.
///
/// The 2 bytes encode 3 letters (A=1 .. Z=26) in 5-bit groups:
///   byte8[6:2] = char1, byte8[1:0]<<3 | byte9[7:5] = char2, byte9[4:0] = char3
fn decode_manufacturer(data: *const u8, len: u32, out: &mut [u8; 4]) {
    let b0 = edid_byte(data, len, 8);
    let b1 = edid_byte(data, len, 9);

    let c1 = ((b0 >> 2) & 0x1F).wrapping_sub(1).wrapping_add(b'A');
    let c2 = (((b0 & 0x03) << 3) | ((b1 >> 5) & 0x07)).wrapping_sub(1).wrapping_add(b'A');
    let c3 = (b1 & 0x1F).wrapping_sub(1).wrapping_add(b'A');

    // Validate that each character is in A-Z range.
    out[0] = if c1 >= b'A' && c1 <= b'Z' { c1 } else { b'?' };
    out[1] = if c2 >= b'A' && c2 <= b'Z' { c2 } else { b'?' };
    out[2] = if c3 >= b'A' && c3 <= b'Z' { c3 } else { b'?' };
    out[3] = 0;
}

/// Extract the preferred (first) detailed timing descriptor.
///
/// Detailed timing descriptors start at byte 54 and are 18 bytes each.
/// A valid timing descriptor has a non-zero pixel clock (first 2 bytes).
///
/// Returns (width, height, refresh_hz) or (0, 0, 0) if not found.
fn parse_preferred_timing(data: *const u8, len: u32) -> (u32, u32, u32) {
    // Iterate over the 4 detailed timing descriptor slots.
    for i in 0..4u32 {
        let base = 54 + i * 18;

        // Pixel clock in 10 kHz units (2 bytes LE). Zero means display descriptor.
        let pixel_clock_10khz = edid_le16(data, len, base) as u32;
        if pixel_clock_10khz == 0 {
            continue;
        }

        // Horizontal active pixels: byte[2] + upper nibble of byte[4].
        let h_active_lo = edid_byte(data, len, base + 2) as u32;
        let h_blanking_lo = edid_byte(data, len, base + 3) as u32;
        let h_hi = edid_byte(data, len, base + 4) as u32;
        let h_active = h_active_lo | ((h_hi >> 4) << 8);
        let h_blanking = h_blanking_lo | ((h_hi & 0x0F) << 8);

        // Vertical active lines: byte[5] + upper nibble of byte[7].
        let v_active_lo = edid_byte(data, len, base + 5) as u32;
        let v_blanking_lo = edid_byte(data, len, base + 6) as u32;
        let v_hi = edid_byte(data, len, base + 7) as u32;
        let v_active = v_active_lo | ((v_hi >> 4) << 8);
        let v_blanking = v_blanking_lo | ((v_hi & 0x0F) << 8);

        // Calculate refresh rate: pixel_clock / (h_total * v_total).
        let h_total = h_active + h_blanking;
        let v_total = v_active + v_blanking;

        let refresh = if h_total > 0 && v_total > 0 {
            // pixel_clock is in 10 kHz units = pixel_clock_10khz * 10000 Hz.
            // refresh = pixel_clock / (h_total * v_total)
            let pixel_clock_hz = pixel_clock_10khz * 10_000;
            let total_pixels = h_total * v_total;
            // Round to nearest integer Hz.
            (pixel_clock_hz + total_pixels / 2) / total_pixels
        } else {
            0
        };

        return (h_active, v_active, refresh);
    }

    (0, 0, 0)
}

/// Extract the monitor name from display descriptor tag 0xFC.
///
/// The name is up to 13 characters, padded with spaces or terminated by 0x0A.
/// We strip trailing spaces/newlines and null-terminate.
fn extract_monitor_name(data: *const u8, len: u32, out: &mut [u8; 14]) {
    *out = [0u8; 14];

    for i in 0..4u32 {
        let base = 54 + i * 18;

        // Display descriptor: first two bytes (pixel clock) are 0.
        if edid_le16(data, len, base) != 0 {
            continue;
        }

        // Byte 3 of the descriptor is the tag type.
        let tag = edid_byte(data, len, base + 3);
        if tag != DESC_TAG_MONITOR_NAME {
            continue;
        }

        // Name payload is at bytes 5..17 (13 bytes) of the descriptor.
        let mut name_len = 0usize;
        for j in 0..13u32 {
            let c = edid_byte(data, len, base + 5 + j);
            if c == 0x0A || c == 0x00 {
                break;
            }
            out[name_len] = c;
            name_len += 1;
        }

        // Strip trailing spaces.
        while name_len > 0 && out[name_len - 1] == b' ' {
            name_len -= 1;
        }

        // Null-terminate.
        out[name_len] = 0;
        return;
    }
}

/// Parse the established timings bitmask from bytes 35-37.
///
/// Returns a 24-bit bitmask where each bit corresponds to a standard timing:
///   Bit 0:  720x400 @ 70 Hz
///   Bit 1:  720x400 @ 88 Hz
///   Bit 2:  640x480 @ 60 Hz
///   Bit 3:  640x480 @ 67 Hz
///   Bit 4:  640x480 @ 72 Hz
///   Bit 5:  640x480 @ 75 Hz
///   Bit 6:  800x600 @ 56 Hz
///   Bit 7:  800x600 @ 60 Hz
///   Bit 8:  800x600 @ 72 Hz
///   Bit 9:  800x600 @ 75 Hz
///   Bit 10: 832x624 @ 75 Hz
///   Bit 11: 1024x768 @ 87 Hz (interlaced)
///   Bit 12: 1024x768 @ 60 Hz
///   Bit 13: 1024x768 @ 70 Hz
///   Bit 14: 1024x768 @ 75 Hz
///   Bit 15: 1280x1024 @ 75 Hz
///   Bit 16: 1152x870 @ 75 Hz (manufacturer timing, byte 37 bit 7)
///   Bits 17-23: manufacturer-specific (byte 37 bits 6-0)
fn parse_established_timings(data: *const u8, len: u32) -> u32 {
    let b0 = edid_byte(data, len, 35) as u32;
    let b1 = edid_byte(data, len, 36) as u32;
    let b2 = edid_byte(data, len, 37) as u32;
    b0 | (b1 << 8) | (b2 << 16)
}

/// Check CEA-861 extension block for HDMI Vendor Specific Data Block.
///
/// The CEA extension starts at byte 128 (if extension count >= 1).
/// Data blocks start at byte 4 of the extension (byte 132 absolute)
/// and continue up to the DTD offset stored in byte 2 of the extension.
fn detect_hdmi_in_cea(data: *const u8, len: u32) -> bool {
    // Need at least a full extension block.
    if len < EDID_EXT_LEN {
        return false;
    }

    // Check that extension count is >= 1 and extension tag is CEA.
    let ext_count = edid_byte(data, len, 126);
    if ext_count == 0 {
        return false;
    }

    let ext_tag = edid_byte(data, len, 128);
    if ext_tag != CEA_EXT_TAG {
        return false;
    }

    // Verify extension block checksum.
    if !verify_checksum(data, len, 128) {
        return false;
    }

    // DTD offset within the extension block (relative to extension start).
    let dtd_offset = edid_byte(data, len, 130) as u32;
    if dtd_offset < 4 {
        return false;
    }

    // Parse data blocks within the CEA extension.
    let mut pos: u32 = 132; // absolute offset = 128 + 4
    let end = 128 + dtd_offset;

    while pos < end && pos + 1 < len {
        let header = edid_byte(data, len, pos);
        let tag = (header >> 5) & 0x07;
        let block_len = (header & 0x1F) as u32;

        // Tag 3 = Vendor Specific Data Block.
        if tag == 3 && block_len >= 3 {
            // Check IEEE OUI (bytes 1-3 of the data block, LE order).
            let oui0 = edid_byte(data, len, pos + 1);
            let oui1 = edid_byte(data, len, pos + 2);
            let oui2 = edid_byte(data, len, pos + 3);
            if oui0 == HDMI_IEEE_OUI[0]
                && oui1 == HDMI_IEEE_OUI[1]
                && oui2 == HDMI_IEEE_OUI[2]
            {
                return true;
            }
        }

        pos += 1 + block_len;
    }

    false
}

// ── Exported C API ──

/// Parse a complete EDID data block into an EdidInfo structure.
///
/// Returns 0 on success, -1 on invalid input, -2 on bad header, -3 on bad checksum.
#[unsafe(no_mangle)]
pub extern "C" fn edid_parse(data: *const u8, len: u32, info: *mut EdidInfo) -> i32 {
    if data.is_null() || info.is_null() || len < EDID_BASE_LEN {
        return -1;
    }

    if !validate_header(data, len) {
        log("edid: invalid EDID header");
        return -2;
    }

    if !verify_checksum(data, len, 0) {
        log("edid: base block checksum failed");
        return -3;
    }

    let mut result = EdidInfo::zero();

    // Manufacturer ID (bytes 8-9).
    decode_manufacturer(data, len, &mut result.manufacturer);

    // Product code (bytes 10-11, LE).
    result.product_code = edid_le16(data, len, 10);

    // Serial number (bytes 12-15, 32-bit LE).
    result.serial = edid_le32(data, len, 12);

    // Manufacture week and year.
    result.week = edid_byte(data, len, 16);
    let year_raw = edid_byte(data, len, 17) as u16;
    result.year = year_raw + 1990;

    // EDID version and revision.
    result.version = edid_byte(data, len, 18);
    result.revision = edid_byte(data, len, 19);

    // Video input definition (byte 20).
    let video_input = edid_byte(data, len, 20);
    result.digital = (video_input & 0x80) != 0;

    // Screen size (bytes 21-22).
    result.width_cm = edid_byte(data, len, 21);
    result.height_cm = edid_byte(data, len, 22);

    // Gamma (byte 23).
    result.gamma = edid_byte(data, len, 23);

    // Preferred timing from first detailed timing descriptor.
    let (pw, ph, pr) = parse_preferred_timing(data, len);
    result.preferred_width = pw;
    result.preferred_height = ph;
    result.preferred_refresh = pr;

    // Monitor name from display descriptor 0xFC.
    extract_monitor_name(data, len, &mut result.monitor_name);

    // HDMI detection via CEA extension.
    result.hdmi = detect_hdmi_in_cea(data, len);

    // Infer DisplayPort: digital input without HDMI VSDB in CEA.
    result.dp = result.digital && !result.hdmi;

    // Log parsed information.
    unsafe {
        fut_printf(
            b"edid: %s product=0x%04X serial=0x%08X year=%u\n\0".as_ptr(),
            result.manufacturer.as_ptr(),
            result.product_code as u32,
            result.serial,
            result.year as u32,
        );
        fut_printf(
            b"edid: v%u.%u %s %ux%u cm gamma=%u\n\0".as_ptr(),
            result.version as u32,
            result.revision as u32,
            if result.digital {
                b"digital\0".as_ptr()
            } else {
                b"analog\0".as_ptr()
            },
            result.width_cm as u32,
            result.height_cm as u32,
            result.gamma as u32,
        );
        if result.preferred_width > 0 {
            fut_printf(
                b"edid: preferred mode: %ux%u @ %u Hz\n\0".as_ptr(),
                result.preferred_width,
                result.preferred_height,
                result.preferred_refresh,
            );
        }
        if result.monitor_name[0] != 0 {
            fut_printf(
                b"edid: monitor name: %s\n\0".as_ptr(),
                result.monitor_name.as_ptr(),
            );
        }
        if result.hdmi {
            log("edid: HDMI sink detected (CEA VSDB)");
        } else if result.digital {
            log("edid: digital sink (DisplayPort assumed)");
        }
    }

    unsafe {
        *info = result;
    }
    0
}

/// Validate an EDID data block (header + checksum).
///
/// Returns true if the EDID data passes header and checksum validation.
#[unsafe(no_mangle)]
pub extern "C" fn edid_validate(data: *const u8, len: u32) -> bool {
    if data.is_null() || len < EDID_BASE_LEN {
        return false;
    }
    if !validate_header(data, len) {
        return false;
    }
    if !verify_checksum(data, len, 0) {
        return false;
    }
    // If extension blocks are present, validate them too.
    let ext_count = edid_byte(data, len, 126) as u32;
    for i in 1..=ext_count {
        let block_start = i * 128;
        if block_start + 128 > len {
            break;
        }
        if !verify_checksum(data, len, block_start) {
            return false;
        }
    }
    true
}

/// Extract the preferred display mode from the first detailed timing descriptor.
///
/// Writes width, height, and refresh rate to the provided pointers.
/// Returns 0 on success, -1 on invalid input, -2 on no timing found.
#[unsafe(no_mangle)]
pub extern "C" fn edid_preferred_mode(
    data: *const u8,
    width: *mut u32,
    height: *mut u32,
    refresh: *mut u32,
) -> i32 {
    if data.is_null() || width.is_null() || height.is_null() || refresh.is_null() {
        return -1;
    }

    // Assume at least 128 bytes available.
    let (w, h, r) = parse_preferred_timing(data, EDID_BASE_LEN);
    if w == 0 && h == 0 {
        return -2;
    }

    unsafe {
        *width = w;
        *height = h;
        *refresh = r;
    }
    0
}

/// Extract the monitor name from the EDID display descriptor 0xFC.
///
/// Copies the name into the provided buffer (up to max_len - 1 chars + null).
/// Returns the number of characters written (excluding null), or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn edid_monitor_name(data: *const u8, name: *mut u8, max_len: u32) -> i32 {
    if data.is_null() || name.is_null() || max_len == 0 {
        return -1;
    }

    let mut buf = [0u8; 14];
    extract_monitor_name(data, EDID_BASE_LEN, &mut buf);

    // Find the length of the extracted name.
    let mut name_len = 0u32;
    while name_len < 13 && buf[name_len as usize] != 0 {
        name_len += 1;
    }

    if name_len == 0 {
        unsafe {
            *name = 0;
        }
        return 0;
    }

    // Copy up to max_len - 1 characters.
    let copy_len = if name_len < max_len {
        name_len
    } else {
        max_len - 1
    };

    for i in 0..copy_len {
        unsafe {
            *name.add(i as usize) = buf[i as usize];
        }
    }
    unsafe {
        *name.add(copy_len as usize) = 0;
    }

    copy_len as i32
}

/// Extract the 3-character manufacturer ID from the EDID data.
///
/// Writes 3 ASCII characters plus a null terminator to the provided buffer.
/// The buffer must be at least 4 bytes.
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn edid_manufacturer(data: *const u8, mfr: *mut u8) -> i32 {
    if data.is_null() || mfr.is_null() {
        return -1;
    }

    let mut buf = [0u8; 4];
    decode_manufacturer(data, EDID_BASE_LEN, &mut buf);

    unsafe {
        *mfr = buf[0];
        *mfr.add(1) = buf[1];
        *mfr.add(2) = buf[2];
        *mfr.add(3) = 0;
    }
    0
}

/// Return the established timings bitmask from the EDID data.
///
/// Returns a 24-bit bitmask (bytes 35-37) where each bit corresponds to a
/// pre-defined standard timing mode. Returns 0 if data is null.
#[unsafe(no_mangle)]
pub extern "C" fn edid_established_timings(data: *const u8) -> u32 {
    if data.is_null() {
        return 0;
    }
    parse_established_timings(data, EDID_BASE_LEN)
}
