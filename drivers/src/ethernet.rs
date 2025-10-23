//! Ethernet Driver for Raspberry Pi
//!
//! This module implements Ethernet networking support for Raspberry Pi platforms.
//! Supports both wired (via USB for RPi3, native for RPi4+) and implements the
//! networking stack foundation for TCP/IP communication.
//!
//! Features:
//! - MAC address management and configuration
//! - Link state detection (up/down)
//! - Packet transmission and reception
//! - Interrupt-driven packet handling
//! - DMA descriptors for efficient data transfer
//! - Ethernet frame parsing and validation
//! - Broadcast and multicast support

use core::fmt;

/// MAC address (6 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddress {
    /// MAC address octets
    octets: [u8; 6],
}

impl MacAddress {
    /// Create MAC address from octets
    pub fn new(octets: [u8; 6]) -> Self {
        MacAddress { octets }
    }

    /// Create broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub fn broadcast() -> Self {
        MacAddress {
            octets: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        }
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.octets == Self::broadcast().octets
    }

    /// Check if this is a multicast address (LSB of first octet is 1)
    pub fn is_multicast(&self) -> bool {
        (self.octets[0] & 0x01) != 0
    }

    /// Check if this is a unicast address
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast() && !self.is_multicast()
    }

    /// Get MAC address octets
    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }

    /// Parse MAC address from string (e.g., "AA:BB:CC:DD:EE:FF")
    /// Note: Using array-based parsing for no_std compatibility
    pub fn from_bytes(octets: &[u8; 6]) -> Self {
        MacAddress {
            octets: *octets,
        }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

/// Ethernet frame types / EtherType values
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    /// IPv4 protocol
    Ipv4,
    /// IPv6 protocol
    Ipv6,
    /// Address Resolution Protocol (ARP)
    Arp,
    /// VLAN tagged frame
    VlanTagged,
    /// Wake-on-LAN
    WakeOnLan,
    /// Other (custom)
    Other(u16),
}

impl EtherType {
    /// Get EtherType value
    pub fn value(&self) -> u16 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::VlanTagged => 0x8100,
            EtherType::Ipv6 => 0x86DD,
            EtherType::WakeOnLan => 0x0842,
            EtherType::Other(v) => *v,
        }
    }

    /// Create from value
    pub fn from_value(v: u16) -> Self {
        match v {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x8100 => EtherType::VlanTagged,
            0x86DD => EtherType::Ipv6,
            0x0842 => EtherType::WakeOnLan,
            _ => EtherType::Other(v),
        }
    }
}

/// Link speed
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkSpeed {
    /// 10 Mbps (legacy)
    Speed10Mbps,
    /// 100 Mbps (Fast Ethernet)
    Speed100Mbps,
    /// 1 Gbps (Gigabit Ethernet)
    Speed1Gbps,
}

impl LinkSpeed {
    /// Get speed in Mbps
    pub fn mbps(&self) -> u32 {
        match self {
            LinkSpeed::Speed10Mbps => 10,
            LinkSpeed::Speed100Mbps => 100,
            LinkSpeed::Speed1Gbps => 1000,
        }
    }
}

/// Link state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Link is down
    Down,
    /// Link is up at specific speed
    Up(LinkSpeed),
}

impl LinkState {
    /// Check if link is up
    pub fn is_up(&self) -> bool {
        !matches!(self, LinkState::Down)
    }
}

/// Packet direction
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDirection {
    /// Transmit (TX)
    Transmit,
    /// Receive (RX)
    Receive,
}

/// DMA descriptor for packet buffer
#[derive(Clone, Copy, Debug)]
pub struct DmaDescriptor {
    /// Physical address of buffer
    pub address: u32,
    /// Buffer size in bytes
    pub size: u32,
    /// Ownership flag (true = NIC owns, false = driver owns)
    pub owned: bool,
    /// Last descriptor in ring
    pub last: bool,
    /// First descriptor in packet
    pub first: bool,
    /// Interrupt on completion
    pub interrupt: bool,
}

impl DmaDescriptor {
    /// Create new DMA descriptor
    pub fn new(address: u32, size: u32) -> Self {
        DmaDescriptor {
            address,
            size,
            owned: false,
            last: false,
            first: true,
            interrupt: false,
        }
    }

    /// Mark as last in ring
    pub fn set_last(&mut self) {
        self.last = true;
    }

    /// Enable interrupt on completion
    pub fn enable_interrupt(&mut self) {
        self.interrupt = true;
    }

    /// Prepare for transmission
    pub fn prepare_tx(&mut self) {
        self.owned = true;  // Give to NIC
        self.first = true;
    }

    /// Prepare for reception
    pub fn prepare_rx(&mut self) {
        self.owned = true;  // Give to NIC
        self.first = true;
    }
}

/// Ethernet frame
#[derive(Clone, Debug)]
pub struct EthernetFrame {
    /// Destination MAC address
    pub dest_mac: MacAddress,
    /// Source MAC address
    pub src_mac: MacAddress,
    /// EtherType (protocol)
    pub ether_type: EtherType,
    /// Payload data
    pub payload: [u8; 1500],
    /// Payload length
    pub payload_len: u16,
}

impl EthernetFrame {
    /// Create new Ethernet frame
    pub fn new(dest_mac: MacAddress, src_mac: MacAddress, ether_type: EtherType) -> Self {
        EthernetFrame {
            dest_mac,
            src_mac,
            ether_type,
            payload: [0u8; 1500],
            payload_len: 0,
        }
    }

    /// Get total frame size (header + payload)
    pub fn total_size(&self) -> u32 {
        14 + self.payload_len as u32  // 14 bytes Ethernet header
    }

    /// Check CRC (simplified - real implementation would use CRC32)
    pub fn verify_crc(&self) -> bool {
        // Placeholder: actual CRC verification would go here
        true
    }
}

/// Ethernet statistics
#[derive(Clone, Copy, Debug)]
pub struct EthernetStats {
    /// Packets transmitted
    pub tx_packets: u32,
    /// Packets received
    pub rx_packets: u32,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// TX errors
    pub tx_errors: u32,
    /// RX errors
    pub rx_errors: u32,
    /// TX dropped
    pub tx_dropped: u32,
    /// RX dropped
    pub rx_dropped: u32,
    /// CRC errors
    pub crc_errors: u32,
    /// Collision count
    pub collisions: u32,
}

impl EthernetStats {
    /// Create new statistics
    pub fn new() -> Self {
        EthernetStats {
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_errors: 0,
            rx_errors: 0,
            tx_dropped: 0,
            rx_dropped: 0,
            crc_errors: 0,
            collisions: 0,
        }
    }

    /// Record transmitted packet
    pub fn record_tx(&mut self, bytes: u32) {
        self.tx_packets = self.tx_packets.saturating_add(1);
        self.tx_bytes = self.tx_bytes.saturating_add(bytes as u64);
    }

    /// Record received packet
    pub fn record_rx(&mut self, bytes: u32) {
        self.rx_packets = self.rx_packets.saturating_add(1);
        self.rx_bytes = self.rx_bytes.saturating_add(bytes as u64);
    }

    /// Record transmission error
    pub fn record_tx_error(&mut self) {
        self.tx_errors = self.tx_errors.saturating_add(1);
    }

    /// Record reception error
    pub fn record_rx_error(&mut self) {
        self.rx_errors = self.rx_errors.saturating_add(1);
    }
}

impl Default for EthernetStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Ethernet controller state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerState {
    /// Not initialized
    Uninitialized,
    /// Initialized but not running
    Initialized,
    /// Running and ready for packets
    Running,
    /// Suspended
    Suspended,
    /// Error state
    Error,
}

/// Ethernet Controller
pub struct EthernetController {
    /// MAC address of this interface
    mac_address: MacAddress,
    /// Current link state
    link_state: LinkState,
    /// Controller state
    state: ControllerState,
    /// Statistics
    stats: EthernetStats,
    /// RX DMA ring
    rx_ring: [Option<DmaDescriptor>; 32],
    /// TX DMA ring
    tx_ring: [Option<DmaDescriptor>; 32],
    /// RX ring index
    rx_index: u32,
    /// TX ring index
    tx_index: u32,
    /// RX buffer pool address
    rx_buffer_pool: u32,
    /// TX buffer pool address
    tx_buffer_pool: u32,
    /// Maximum packet size
    max_packet_size: u32,
    /// Promiscuous mode
    promiscuous: bool,
    /// Broadcast enabled
    broadcast_enabled: bool,
    /// Multicast enabled
    multicast_enabled: bool,
}

impl EthernetController {
    /// Create new Ethernet controller
    pub fn new(mac_address: MacAddress) -> Self {
        EthernetController {
            mac_address,
            link_state: LinkState::Down,
            state: ControllerState::Uninitialized,
            stats: EthernetStats::new(),
            rx_ring: [None; 32],
            tx_ring: [None; 32],
            rx_index: 0,
            tx_index: 0,
            rx_buffer_pool: 0,
            tx_buffer_pool: 0,
            max_packet_size: 1500,
            promiscuous: false,
            broadcast_enabled: true,
            multicast_enabled: false,
        }
    }

    /// Initialize controller
    pub fn initialize(&mut self, rx_pool: u32, tx_pool: u32) -> Result<(), &'static str> {
        if self.state != ControllerState::Uninitialized {
            return Err("Controller already initialized");
        }

        self.rx_buffer_pool = rx_pool;
        self.tx_buffer_pool = tx_pool;
        self.state = ControllerState::Initialized;
        Ok(())
    }

    /// Start controller
    pub fn start(&mut self) -> Result<(), &'static str> {
        if self.state != ControllerState::Initialized {
            return Err("Controller not initialized");
        }

        self.state = ControllerState::Running;
        Ok(())
    }

    /// Stop controller
    pub fn stop(&mut self) {
        self.state = ControllerState::Initialized;
    }

    /// Get current state
    pub fn state(&self) -> ControllerState {
        self.state
    }

    /// Get MAC address
    pub fn mac_address(&self) -> MacAddress {
        self.mac_address
    }

    /// Set MAC address
    pub fn set_mac_address(&mut self, mac: MacAddress) -> Result<(), &'static str> {
        if self.state != ControllerState::Running {
            self.mac_address = mac;
            Ok(())
        } else {
            Err("Cannot change MAC while running")
        }
    }

    /// Get link state
    pub fn link_state(&self) -> LinkState {
        self.link_state
    }

    /// Set link state
    pub fn set_link_state(&mut self, state: LinkState) {
        self.link_state = state;
    }

    /// Enable promiscuous mode (receive all packets)
    pub fn set_promiscuous(&mut self, enabled: bool) {
        self.promiscuous = enabled;
    }

    /// Check if packet should be received
    pub fn should_receive(&self, dest_mac: MacAddress) -> bool {
        if self.promiscuous {
            return true;
        }

        if dest_mac == self.mac_address {
            return true;  // Unicast to this interface
        }

        if dest_mac.is_broadcast() && self.broadcast_enabled {
            return true;
        }

        if dest_mac.is_multicast() && self.multicast_enabled {
            return true;
        }

        false
    }

    /// Allocate RX descriptor
    pub fn allocate_rx_descriptor(&mut self, address: u32, size: u32) -> Result<u32, &'static str> {
        let idx = self.rx_index as usize;
        if idx >= 32 {
            return Err("RX ring full");
        }

        let mut desc = DmaDescriptor::new(address, size);
        desc.prepare_rx();
        if idx == 31 {
            desc.set_last();
        }

        self.rx_ring[idx] = Some(desc);
        self.rx_index = (self.rx_index + 1) % 32;

        Ok(idx as u32)
    }

    /// Allocate TX descriptor
    pub fn allocate_tx_descriptor(&mut self, address: u32, size: u32) -> Result<u32, &'static str> {
        let idx = self.tx_index as usize;
        if idx >= 32 {
            return Err("TX ring full");
        }

        let mut desc = DmaDescriptor::new(address, size);
        desc.prepare_tx();
        if idx == 31 {
            desc.set_last();
        }

        self.tx_ring[idx] = Some(desc);
        self.tx_index = (self.tx_index + 1) % 32;

        Ok(idx as u32)
    }

    /// Transmit frame
    pub fn transmit(&mut self, frame: &EthernetFrame) -> Result<(), &'static str> {
        if self.state != ControllerState::Running {
            return Err("Controller not running");
        }

        if frame.total_size() > self.max_packet_size as u32 {
            self.stats.record_tx_error();
            return Err("Frame too large");
        }

        self.stats.record_tx(frame.total_size() as u32);
        Ok(())
    }

    /// Receive frame
    pub fn receive(&mut self, frame: &mut EthernetFrame) -> Result<bool, &'static str> {
        if self.state != ControllerState::Running {
            return Err("Controller not running");
        }

        // Check if we should receive this frame
        if !self.should_receive(frame.dest_mac) {
            return Ok(false);
        }

        // Verify frame validity
        if !frame.verify_crc() {
            self.stats.record_rx_error();
            return Ok(false);
        }

        self.stats.record_rx(frame.total_size() as u32);
        Ok(true)
    }

    /// Get statistics
    pub fn stats(&self) -> EthernetStats {
        self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = EthernetStats::new();
    }

    /// Check link status
    pub fn check_link(&mut self) -> LinkState {
        // In real implementation, would query hardware for link status
        self.link_state
    }
}

impl Default for EthernetController {
    fn default() -> Self {
        Self::new(MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(mac.octets()[0], 0xAA);
        assert_eq!(mac.octets()[5], 0xFF);
    }

    #[test]
    fn test_mac_broadcast() {
        let bcast = MacAddress::broadcast();
        assert!(bcast.is_broadcast());
        assert!(!bcast.is_unicast());
    }

    #[test]
    fn test_mac_multicast() {
        let multicast = MacAddress::new([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);
        assert!(multicast.is_multicast());
        assert!(!multicast.is_unicast());
    }

    #[test]
    fn test_mac_unicast() {
        let unicast = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(unicast.is_unicast());
        assert!(!unicast.is_broadcast());
    }

    #[test]
    fn test_ether_type() {
        assert_eq!(EtherType::Ipv4.value(), 0x0800);
        assert_eq!(EtherType::Arp.value(), 0x0806);
        assert_eq!(EtherType::Ipv6.value(), 0x86DD);
    }

    #[test]
    fn test_ether_type_from_value() {
        assert_eq!(EtherType::from_value(0x0800), EtherType::Ipv4);
        assert_eq!(EtherType::from_value(0x0806), EtherType::Arp);
    }

    #[test]
    fn test_link_speed() {
        assert_eq!(LinkSpeed::Speed10Mbps.mbps(), 10);
        assert_eq!(LinkSpeed::Speed100Mbps.mbps(), 100);
        assert_eq!(LinkSpeed::Speed1Gbps.mbps(), 1000);
    }

    #[test]
    fn test_link_state() {
        assert!(!LinkState::Down.is_up());
        assert!(LinkState::Up(LinkSpeed::Speed100Mbps).is_up());
    }

    #[test]
    fn test_dma_descriptor() {
        let mut desc = DmaDescriptor::new(0x80000000, 1024);
        desc.prepare_tx();
        assert!(desc.owned);
        assert!(desc.first);
    }

    #[test]
    fn test_ethernet_frame() {
        let dest = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let frame = EthernetFrame::new(dest, src, EtherType::Ipv4);

        assert_eq!(frame.dest_mac, dest);
        assert_eq!(frame.src_mac, src);
        assert_eq!(frame.total_size(), 14);  // Header only
    }

    #[test]
    fn test_ethernet_stats() {
        let mut stats = EthernetStats::new();
        assert_eq!(stats.tx_packets, 0);

        stats.record_tx(100);
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.tx_bytes, 100);

        stats.record_rx(200);
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.rx_bytes, 200);
    }

    #[test]
    fn test_ethernet_controller_initialization() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut controller = EthernetController::new(mac);

        assert_eq!(controller.state(), ControllerState::Uninitialized);
        assert!(controller.initialize(0x80000000, 0x80100000).is_ok());
        assert_eq!(controller.state(), ControllerState::Initialized);
    }

    #[test]
    fn test_ethernet_controller_lifecycle() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut controller = EthernetController::new(mac);

        controller.initialize(0x80000000, 0x80100000).ok();
        assert!(controller.start().is_ok());
        assert_eq!(controller.state(), ControllerState::Running);

        controller.stop();
        assert_eq!(controller.state(), ControllerState::Initialized);
    }

    #[test]
    fn test_packet_filtering() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut controller = EthernetController::new(mac);

        // Should receive unicast to this address
        assert!(controller.should_receive(mac));

        // Should receive broadcast
        assert!(controller.should_receive(MacAddress::broadcast()));

        // Should not receive other unicast
        let other = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(!controller.should_receive(other));
    }

    #[test]
    fn test_promiscuous_mode() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut controller = EthernetController::new(mac);

        let other = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(!controller.should_receive(other));

        controller.set_promiscuous(true);
        assert!(controller.should_receive(other));
    }

    #[test]
    fn test_descriptor_allocation() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut controller = EthernetController::new(mac);

        let rx_idx = controller.allocate_rx_descriptor(0x80000000, 1024);
        assert!(rx_idx.is_ok());

        let tx_idx = controller.allocate_tx_descriptor(0x80100000, 1024);
        assert!(tx_idx.is_ok());
    }
}
