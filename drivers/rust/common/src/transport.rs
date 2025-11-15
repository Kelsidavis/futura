// SPDX-License-Identifier: MPL-2.0
//
// VirtIO Transport Abstraction
//
// Provides a unified interface for VirtIO devices across different
// transport mechanisms (PCI on x86-64, MMIO on ARM64).

use core::ffi::c_void;

/// Opaque handle to a VirtIO device (transport-specific)
#[repr(C)]
pub struct VirtioDeviceHandle(*mut c_void);

unsafe impl Send for VirtioDeviceHandle {}
unsafe impl Sync for VirtioDeviceHandle {}

impl VirtioDeviceHandle {
    pub fn new(ptr: *mut c_void) -> Self {
        Self(ptr)
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

/// VirtIO transport abstraction trait
///
/// This trait provides a common interface for interacting with VirtIO devices
/// regardless of the underlying transport (PCI, MMIO, etc.).
pub trait VirtioTransport: Send + Sync {
    /// Read 8 bits from device configuration space
    fn read_config8(&self, offset: u32) -> u8;

    /// Read 16 bits from device configuration space
    fn read_config16(&self, offset: u32) -> u16;

    /// Read 32 bits from device configuration space
    fn read_config32(&self, offset: u32) -> u32;

    /// Read 64 bits from device configuration space
    fn read_config64(&self, offset: u32) -> u64;

    /// Write 16 bits to device configuration space
    fn write_config16(&mut self, offset: u32, value: u16);

    /// Write 32 bits to device configuration space
    fn write_config32(&mut self, offset: u32, value: u32);

    /// Get device status register
    fn get_status(&self) -> u8;

    /// Set device status register
    fn set_status(&mut self, status: u8);

    /// Setup a virtqueue
    fn setup_queue(&mut self, queue_idx: u16, queue_size: u16, desc_addr: u64, driver_addr: u64, device_addr: u64);

    /// Notify device that queue has new buffers
    fn notify_queue(&self, queue_idx: u16);

    /// Get device IRQ number (if available)
    fn get_irq(&self) -> Option<u32>;
}

// FFI bindings for ARM64 MMIO transport
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn virtio_mmio_find_device(device_type: u32) -> i32;
    fn virtio_mmio_get_device(device_idx: i32) -> *mut c_void;
    fn virtio_mmio_read_config32(dev: *mut c_void, offset: u32) -> u32;
    fn virtio_mmio_read_config64(dev: *mut c_void, offset: u32) -> u64;
    fn virtio_mmio_setup_device(dev: *mut c_void, features: u32, queue_size: u32) -> i32;
    fn virtio_mmio_notify(dev: *mut c_void, queue_idx: u32);
}

/// MMIO Transport implementation for ARM64
#[cfg(target_arch = "aarch64")]
pub struct MmioTransport {
    device: VirtioDeviceHandle,
    base_addr: u64,
}

#[cfg(target_arch = "aarch64")]
impl MmioTransport {
    /// Find a VirtIO MMIO device by device type
    pub fn find_device(device_type: u32) -> Option<Self> {
        let device_idx = unsafe { virtio_mmio_find_device(device_type) };
        if device_idx < 0 {
            None
        } else {
            let dev = unsafe { virtio_mmio_get_device(device_idx) };
            if dev.is_null() {
                None
            } else {
                Some(Self {
                    device: VirtioDeviceHandle::new(dev),
                    base_addr: dev as u64,
                })
            }
        }
    }

    /// Get the device handle pointer for passing to C functions
    pub fn as_ptr(&self) -> *mut c_void {
        self.device.as_ptr()
    }
}

#[cfg(target_arch = "aarch64")]
impl VirtioTransport for MmioTransport {
    fn read_config8(&self, offset: u32) -> u8 {
        (self.read_config32(offset & !3) >> ((offset & 3) * 8)) as u8
    }

    fn read_config16(&self, offset: u32) -> u16 {
        (self.read_config32(offset & !3) >> ((offset & 2) * 8)) as u16
    }

    fn read_config32(&self, offset: u32) -> u32 {
        unsafe { virtio_mmio_read_config32(self.device.as_ptr(), offset) }
    }

    fn read_config64(&self, offset: u32) -> u64 {
        unsafe { virtio_mmio_read_config64(self.device.as_ptr(), offset) }
    }

    fn write_config16(&mut self, offset: u32, value: u16) {
        // MMIO write via read-modify-write
        let aligned_offset = offset & !3;
        let shift = (offset & 2) * 8;
        let mut val = self.read_config32(aligned_offset);
        val = (val & !(0xFFFF << shift)) | ((value as u32) << shift);
        self.write_config32(aligned_offset, val);
    }

    fn write_config32(&mut self, _offset: u32, _value: u32) {
        // Most writes go through specific MMIO registers
        // This is handled by the C layer
    }

    fn get_status(&self) -> u8 {
        self.read_config8(0x70)  // VIRTIO_MMIO_STATUS offset
    }

    fn set_status(&mut self, status: u8) {
        self.write_config32(0x70, status as u32);
    }

    fn setup_queue(&mut self, _queue_idx: u16, queue_size: u16, _desc_addr: u64, _driver_addr: u64, _device_addr: u64) {
        // Setup is handled by virtio_mmio_setup_device in C
        unsafe {
            virtio_mmio_setup_device(self.device.as_ptr(), 0, queue_size as u32);
        }
    }

    fn notify_queue(&self, queue_idx: u16) {
        unsafe {
            virtio_mmio_notify(self.device.as_ptr(), queue_idx as u32);
        }
    }

    fn get_irq(&self) -> Option<u32> {
        // IRQ info is stored in the device structure in C
        // For now, return None - can be extended later
        None
    }
}

/// PCI Transport implementation for x86-64
#[cfg(target_arch = "x86_64")]
pub struct PciTransport {
    bus: u8,
    device: u8,
    function: u8,
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn inl(port: u16) -> u32;
    fn outl(port: u16, val: u32);
}

#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0xCFC;

#[cfg(target_arch = "x86_64")]
impl PciTransport {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }

    fn make_config_address(&self, offset: u32) -> u32 {
        0x80000000u32
            | ((self.bus as u32) << 16)
            | ((self.device as u32) << 11)
            | ((self.function as u32) << 8)
            | (offset & 0xFC)
    }

    fn pci_read32(&self, offset: u32) -> u32 {
        unsafe {
            outl(PCI_CONFIG_ADDRESS, self.make_config_address(offset));
            inl(PCI_CONFIG_DATA)
        }
    }

    fn pci_write32(&mut self, offset: u32, value: u32) {
        unsafe {
            outl(PCI_CONFIG_ADDRESS, self.make_config_address(offset));
            outl(PCI_CONFIG_DATA, value);
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl VirtioTransport for PciTransport {
    fn read_config8(&self, offset: u32) -> u8 {
        let val = self.pci_read32(offset);
        (val >> ((offset & 3) * 8)) as u8
    }

    fn read_config16(&self, offset: u32) -> u16 {
        let val = self.pci_read32(offset);
        (val >> ((offset & 2) * 8)) as u16
    }

    fn read_config32(&self, offset: u32) -> u32 {
        self.pci_read32(offset)
    }

    fn read_config64(&self, offset: u32) -> u64 {
        let low = self.pci_read32(offset);
        let high = self.pci_read32(offset + 4);
        ((high as u64) << 32) | (low as u64)
    }

    fn write_config16(&mut self, offset: u32, value: u16) {
        let aligned_offset = offset & !3;
        let shift = (offset & 2) * 8;
        let mut val = self.pci_read32(aligned_offset);
        val = (val & !(0xFFFF << shift)) | ((value as u32) << shift);
        self.pci_write32(aligned_offset, val);
    }

    fn write_config32(&mut self, offset: u32, value: u32) {
        self.pci_write32(offset, value);
    }

    fn get_status(&self) -> u8 {
        self.read_config8(0x12)  // PCI Status register
    }

    fn set_status(&mut self, status: u8) {
        self.write_config32(0x10, status as u32);
    }

    fn setup_queue(&mut self, _queue_idx: u16, _queue_size: u16, _desc_addr: u64, _driver_addr: u64, _device_addr: u64) {
        // PCI-specific queue setup would go here
        // This is typically done through BAR-mapped MMIO regions
    }

    fn notify_queue(&self, _queue_idx: u16) {
        // PCI notification would go here
    }

    fn get_irq(&self) -> Option<u32> {
        Some(self.read_config8(0x3C) as u32)  // PCI Interrupt Line register
    }
}
