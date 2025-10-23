//! Type-safe register abstractions for embedded hardware access.
//!
//! This module provides utilities for safe access to memory-mapped I/O registers
//! using the `volatile` crate for correct semantics.

/// Trait for register bit field operations
pub trait BitField: Sized {
    /// Extract a bit field value from a register
    fn get_bits(&self, offset: usize, width: usize) -> Self;

    /// Set a bit field value in a register
    fn set_bits(&mut self, offset: usize, width: usize, value: Self);

    /// Check if a specific bit is set
    fn is_bit_set(&self, bit: usize) -> bool;

    /// Set a specific bit
    fn set_bit(&mut self, bit: usize);

    /// Clear a specific bit
    fn clear_bit(&mut self, bit: usize);
}

impl BitField for u32 {
    fn get_bits(&self, offset: usize, width: usize) -> u32 {
        let mask = ((1u32 << width) - 1) << offset;
        (self & mask) >> offset
    }

    fn set_bits(&mut self, offset: usize, width: usize, value: u32) {
        let mask = ((1u32 << width) - 1) << offset;
        *self = (*self & !mask) | ((value << offset) & mask);
    }

    fn is_bit_set(&self, bit: usize) -> bool {
        (self >> bit) & 1 == 1
    }

    fn set_bit(&mut self, bit: usize) {
        *self |= 1u32 << bit;
    }

    fn clear_bit(&mut self, bit: usize) {
        *self &= !(1u32 << bit);
    }
}

impl BitField for u64 {
    fn get_bits(&self, offset: usize, width: usize) -> u64 {
        let mask = ((1u64 << width) - 1) << offset;
        (self & mask) >> offset
    }

    fn set_bits(&mut self, offset: usize, width: usize, value: u64) {
        let mask = ((1u64 << width) - 1) << offset;
        *self = (*self & !mask) | ((value << offset) & mask);
    }

    fn is_bit_set(&self, bit: usize) -> bool {
        (self >> bit) & 1 == 1
    }

    fn set_bit(&mut self, bit: usize) {
        *self |= 1u64 << bit;
    }

    fn clear_bit(&mut self, bit: usize) {
        *self &= !(1u64 << bit);
    }
}

/// Helper macro for reading a volatile register safely
#[macro_export]
macro_rules! vol_read {
    ($vol:expr) => {{
        unsafe { core::ptr::read_volatile($vol as *const _ as *const _) }
    }};
}

/// Helper macro for writing a volatile register safely
#[macro_export]
macro_rules! vol_write {
    ($vol:expr, $val:expr) => {{
        unsafe { core::ptr::write_volatile($vol as *mut _ as *mut _, $val) }
    }};
}
