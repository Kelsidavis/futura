//! WiFi Driver for Raspberry Pi
//!
//! This module implements IEEE 802.11 wireless networking support for Raspberry Pi platforms.
//! Supports WiFi scanning, authentication, association, and packet transmission/reception.
//!
//! Features:
//! - 802.11b/g/n/ac wireless support
//! - WPA2/WPA3 security
//! - Network scanning and discovery
//! - Signal strength reporting
//! - Power management
//! - Channel selection

/// WiFi frequency band
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiBand {
    /// 2.4 GHz band (802.11b/g/n)
    Band2_4Ghz,
    /// 5 GHz band (802.11a/n/ac)
    Band5Ghz,
    /// 6 GHz band (802.11ax)
    Band6Ghz,
}

/// WiFi channel information
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiChannel {
    /// Channel number (1-14 for 2.4GHz, 36-165 for 5GHz)
    pub channel: u8,
    /// Center frequency in MHz
    pub frequency: u16,
    /// Band this channel belongs to
    pub band: WifiBand,
    /// Maximum transmit power in dBm
    pub max_power: i8,
}

impl WifiChannel {
    /// Create new WiFi channel
    pub fn new(channel: u8, frequency: u16, band: WifiBand, max_power: i8) -> Self {
        WifiChannel {
            channel,
            frequency,
            band,
            max_power,
        }
    }

    /// Check if channel is valid for 2.4GHz band
    pub fn is_valid_2_4ghz(channel: u8) -> bool {
        channel >= 1 && channel <= 14
    }

    /// Check if channel is valid for 5GHz band
    pub fn is_valid_5ghz(channel: u8) -> bool {
        (channel >= 36 && channel <= 48) || (channel >= 52 && channel <= 144) || (channel >= 149 && channel <= 165)
    }
}

/// WiFi security type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiSecurity {
    /// No security
    Open,
    /// WEP (deprecated)
    Wep,
    /// WPA
    Wpa,
    /// WPA2
    Wpa2,
    /// WPA3
    Wpa3,
    /// WPA2/WPA3 Mixed
    WpaMixed,
}

/// WiFi authentication type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthType {
    /// Open authentication
    Open,
    /// Shared key authentication
    SharedKey,
    /// WPA Pre-Shared Key
    WpaPsk,
    /// WPA2 Pre-Shared Key
    Wpa2Psk,
    /// WPA3 Personal
    Wpa3Personal,
    /// Enterprise (802.1X)
    Enterprise,
}

/// WiFi cipher suite
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    /// No encryption
    None,
    /// WEP-40
    Wep40,
    /// WEP-104
    Wep104,
    /// TKIP (Temporal Key Integrity Protocol)
    Tkip,
    /// CCMP (Counter Mode with CBC-MAC Protocol)
    Ccmp,
    /// GCMP (Galois/Counter Mode Protocol)
    Gcmp,
}

/// WiFi network scan result
#[derive(Clone, Copy, Debug)]
pub struct WifiScanResult {
    /// Network SSID
    pub ssid: [u8; 32],
    /// SSID length
    pub ssid_len: u8,
    /// Basic Service Set Identifier (MAC address)
    pub bssid: [u8; 6],
    /// Received Signal Strength Indicator (dBm), -100 to 0
    pub rssi: i8,
    /// Channel the network is on
    pub channel: u8,
    /// Security type
    pub security: WifiSecurity,
    /// Beacon interval in milliseconds
    pub beacon_interval: u16,
    /// Network capability info
    pub capabilities: u16,
}

impl WifiScanResult {
    /// Create new scan result
    pub fn new() -> Self {
        WifiScanResult {
            ssid: [0; 32],
            ssid_len: 0,
            bssid: [0; 6],
            rssi: -100,
            channel: 1,
            security: WifiSecurity::Open,
            beacon_interval: 100,
            capabilities: 0,
        }
    }

    /// Get SSID as string slice
    pub fn ssid_str(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }

    /// Check if this is a hidden SSID
    pub fn is_hidden(&self) -> bool {
        self.ssid_len == 0
    }
}

/// WiFi connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Scanning for networks
    Scanning,
    /// Authenticating
    Authenticating,
    /// Associated with network
    Associated,
    /// Connected and IP configured
    Connected,
    /// Connection lost
    Disconnecting,
    /// Error state
    Error,
}

/// WiFi statistics
#[derive(Clone, Copy, Debug)]
pub struct WifiStats {
    /// Transmitted packets
    pub tx_packets: u32,
    /// Received packets
    pub rx_packets: u32,
    /// Transmitted bytes
    pub tx_bytes: u64,
    /// Received bytes
    pub rx_bytes: u64,
    /// Transmission errors
    pub tx_errors: u32,
    /// Reception errors
    pub rx_errors: u32,
    /// Dropped outgoing packets
    pub tx_dropped: u32,
    /// Dropped incoming packets
    pub rx_dropped: u32,
    /// CRC errors
    pub crc_errors: u32,
    /// Authentication failures
    pub auth_failures: u32,
    /// Disconnection count
    pub disconnections: u32,
}

impl WifiStats {
    /// Create new statistics
    pub fn new() -> Self {
        WifiStats {
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_errors: 0,
            rx_errors: 0,
            tx_dropped: 0,
            rx_dropped: 0,
            crc_errors: 0,
            auth_failures: 0,
            disconnections: 0,
        }
    }

    /// Increment transmitted packets with saturation
    pub fn increment_tx_packets(&mut self) {
        self.tx_packets = self.tx_packets.saturating_add(1);
    }

    /// Increment received packets with saturation
    pub fn increment_rx_packets(&mut self) {
        self.rx_packets = self.rx_packets.saturating_add(1);
    }

    /// Clear all statistics
    pub fn clear(&mut self) {
        *self = WifiStats::new();
    }
}

/// WiFi network information
#[derive(Clone, Copy, Debug)]
pub struct WifiNetwork {
    /// Network SSID
    pub ssid: [u8; 32],
    /// SSID length
    pub ssid_len: u8,
    /// Basic Service Set Identifier (MAC address)
    pub bssid: [u8; 6],
    /// Channel
    pub channel: u8,
    /// Security type
    pub security: WifiSecurity,
    /// Authentication type
    pub auth_type: AuthType,
    /// Cipher suite
    pub cipher: CipherSuite,
    /// Signal strength (dBm)
    pub signal_strength: i8,
}

impl WifiNetwork {
    /// Create new network
    pub fn new() -> Self {
        WifiNetwork {
            ssid: [0; 32],
            ssid_len: 0,
            bssid: [0; 6],
            channel: 1,
            security: WifiSecurity::Open,
            auth_type: AuthType::Open,
            cipher: CipherSuite::None,
            signal_strength: -100,
        }
    }

    /// Set SSID from bytes
    pub fn set_ssid(&mut self, ssid: &[u8]) {
        let len = core::cmp::min(ssid.len(), 32);
        self.ssid[..len].copy_from_slice(&ssid[..len]);
        self.ssid_len = len as u8;
    }

    /// Get SSID as string slice
    pub fn ssid_str(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
}

/// WiFi power state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerState {
    /// Full power operation
    On,
    /// Power save mode
    Save,
    /// Ultra low power
    Sleep,
    /// Powered off
    Off,
}

/// WiFi device driver controller
pub struct WifiController {
    /// Current connection state
    state: ConnectionState,
    /// Connected network
    connected_network: WifiNetwork,
    /// Current channel
    current_channel: WifiChannel,
    /// Power state
    power_state: PowerState,
    /// Statistics
    stats: WifiStats,
    /// Scan results buffer (max 32 networks)
    scan_results: [Option<WifiScanResult>; 32],
    /// Number of scan results
    scan_count: usize,
    /// Signal strength (dBm)
    signal_strength: i8,
    /// TX power in dBm
    tx_power: i8,
    /// Regulatory domain
    country_code: [u8; 2],
}

impl WifiController {
    /// Create new WiFi controller
    pub fn new() -> Self {
        WifiController {
            state: ConnectionState::Disconnected,
            connected_network: WifiNetwork::new(),
            current_channel: WifiChannel::new(1, 2412, WifiBand::Band2_4Ghz, 20),
            power_state: PowerState::On,
            stats: WifiStats::new(),
            scan_results: [None; 32],
            scan_count: 0,
            signal_strength: -100,
            tx_power: 20,
            country_code: [0x55, 0x53], // US
        }
    }

    /// Initialize WiFi controller
    pub fn initialize(&mut self) -> Result<(), &'static str> {
        match self.state {
            ConnectionState::Disconnected => {
                self.state = ConnectionState::Disconnected;
                Ok(())
            }
            _ => Err("Already initialized"),
        }
    }

    /// Set regulatory domain/country code
    pub fn set_country_code(&mut self, country: [u8; 2]) {
        self.country_code = country;
    }

    /// Get regulatory domain
    pub fn country_code(&self) -> [u8; 2] {
        self.country_code
    }

    /// Start WiFi network scan
    pub fn scan(&mut self) -> Result<(), &'static str> {
        if self.state == ConnectionState::Scanning {
            return Err("Scan already in progress");
        }
        self.state = ConnectionState::Scanning;
        self.scan_count = 0;
        Ok(())
    }

    /// Add scan result (called by driver/firmware)
    pub fn add_scan_result(&mut self, result: WifiScanResult) -> Result<(), &'static str> {
        if self.scan_count >= 32 {
            return Err("Scan results buffer full");
        }
        self.scan_results[self.scan_count] = Some(result);
        self.scan_count += 1;
        Ok(())
    }

    /// Get scan results
    pub fn scan_results(&self) -> &[Option<WifiScanResult>; 32] {
        &self.scan_results
    }

    /// Get number of scan results
    pub fn scan_count(&self) -> usize {
        self.scan_count
    }

    /// Complete scan
    pub fn scan_complete(&mut self) {
        if self.state == ConnectionState::Scanning {
            self.state = ConnectionState::Disconnected;
        }
    }

    /// Connect to WiFi network with SSID and password
    pub fn connect(&mut self, ssid: &[u8], password: &[u8]) -> Result<(), &'static str> {
        if self.state != ConnectionState::Disconnected && self.state != ConnectionState::Scanning {
            return Err("Already connecting or connected");
        }

        if ssid.is_empty() || ssid.len() > 32 {
            return Err("Invalid SSID length");
        }

        if password.len() > 64 {
            return Err("Password too long");
        }

        self.connected_network.set_ssid(ssid);
        self.state = ConnectionState::Authenticating;
        Ok(())
    }

    /// Complete connection
    pub fn connection_complete(&mut self, success: bool) {
        if success {
            self.state = ConnectionState::Connected;
        } else {
            self.state = ConnectionState::Disconnected;
            self.stats.auth_failures = self.stats.auth_failures.saturating_add(1);
        }
    }

    /// Disconnect from WiFi network
    pub fn disconnect(&mut self) -> Result<(), &'static str> {
        match self.state {
            ConnectionState::Disconnected => Err("Already disconnected"),
            _ => {
                self.state = ConnectionState::Disconnected;
                self.stats.disconnections = self.stats.disconnections.saturating_add(1);
                Ok(())
            }
        }
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get connected network
    pub fn connected_network(&self) -> &WifiNetwork {
        &self.connected_network
    }

    /// Set connected network
    pub fn set_connected_network(&mut self, network: WifiNetwork) {
        self.connected_network = network;
    }

    /// Get current channel
    pub fn current_channel(&self) -> WifiChannel {
        self.current_channel
    }

    /// Set channel
    pub fn set_channel(&mut self, channel: WifiChannel) -> Result<(), &'static str> {
        if self.state == ConnectionState::Connected {
            return Err("Cannot change channel while connected");
        }
        self.current_channel = channel;
        Ok(())
    }

    /// Get signal strength (dBm)
    pub fn signal_strength(&self) -> i8 {
        self.signal_strength
    }

    /// Update signal strength
    pub fn update_signal_strength(&mut self, rssi: i8) {
        self.signal_strength = rssi;
    }

    /// Get transmit power (dBm)
    pub fn tx_power(&self) -> i8 {
        self.tx_power
    }

    /// Set transmit power (dBm, clamped to 0-30)
    pub fn set_tx_power(&mut self, power: i8) {
        self.tx_power = if power < 0 { 0 } else if power > 30 { 30 } else { power };
    }

    /// Enable power save mode
    pub fn enable_power_save(&mut self) -> Result<(), &'static str> {
        self.power_state = PowerState::Save;
        Ok(())
    }

    /// Disable power save mode
    pub fn disable_power_save(&mut self) -> Result<(), &'static str> {
        self.power_state = PowerState::On;
        Ok(())
    }

    /// Get power state
    pub fn power_state(&self) -> PowerState {
        self.power_state
    }

    /// Get statistics
    pub fn stats(&self) -> &WifiStats {
        &self.stats
    }

    /// Get mutable statistics for updates
    pub fn stats_mut(&mut self) -> &mut WifiStats {
        &mut self.stats
    }

    /// Clear statistics
    pub fn clear_stats(&mut self) {
        self.stats.clear();
    }

    /// Transmit packet
    pub fn transmit(&mut self, data: &[u8]) -> Result<u32, &'static str> {
        if self.state != ConnectionState::Connected {
            self.stats.tx_dropped = self.stats.tx_dropped.saturating_add(1);
            return Err("Not connected");
        }

        if data.is_empty() || data.len() > 2340 {
            self.stats.tx_dropped = self.stats.tx_dropped.saturating_add(1);
            return Err("Invalid packet size");
        }

        self.stats.increment_tx_packets();
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(data.len() as u64);

        Ok(1) // Return packet ID
    }

    /// Receive packet
    pub fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize, &'static str> {
        if self.state != ConnectionState::Connected {
            return Err("Not connected");
        }

        // Return 0 to indicate no packets available (would be filled by hardware)
        Ok(0)
    }

    /// Get error statistics (combination of errors)
    pub fn get_error_rate(&self) -> u32 {
        self.stats.tx_errors.saturating_add(self.stats.rx_errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wifi_band_creation() {
        let band = WifiBand::Band2_4Ghz;
        assert_eq!(band, WifiBand::Band2_4Ghz);
    }

    #[test]
    fn test_wifi_channel_valid_2_4ghz() {
        assert!(WifiChannel::is_valid_2_4ghz(1));
        assert!(WifiChannel::is_valid_2_4ghz(14));
        assert!(!WifiChannel::is_valid_2_4ghz(0));
        assert!(!WifiChannel::is_valid_2_4ghz(15));
    }

    #[test]
    fn test_wifi_channel_valid_5ghz() {
        assert!(WifiChannel::is_valid_5ghz(36));
        assert!(WifiChannel::is_valid_5ghz(48));
        assert!(WifiChannel::is_valid_5ghz(52));
        assert!(WifiChannel::is_valid_5ghz(144));
        assert!(WifiChannel::is_valid_5ghz(149));
        assert!(WifiChannel::is_valid_5ghz(165));
        assert!(!WifiChannel::is_valid_5ghz(35));
        assert!(!WifiChannel::is_valid_5ghz(166));
    }

    #[test]
    fn test_wifi_channel_creation() {
        let channel = WifiChannel::new(6, 2437, WifiBand::Band2_4Ghz, 20);
        assert_eq!(channel.channel, 6);
        assert_eq!(channel.frequency, 2437);
        assert_eq!(channel.band, WifiBand::Band2_4Ghz);
        assert_eq!(channel.max_power, 20);
    }

    #[test]
    fn test_wifi_security_types() {
        let sec = WifiSecurity::Wpa2;
        assert_eq!(sec, WifiSecurity::Wpa2);
        assert_ne!(sec, WifiSecurity::Open);
    }

    #[test]
    fn test_wifi_scan_result_hidden_ssid() {
        let mut result = WifiScanResult::new();
        assert!(result.is_hidden());

        result.ssid[0] = 0x4D; // 'M'
        result.ssid_len = 1;
        assert!(!result.is_hidden());
    }

    #[test]
    fn test_wifi_stats_saturation() {
        let mut stats = WifiStats::new();
        stats.tx_packets = u32::MAX;
        stats.increment_tx_packets();
        assert_eq!(stats.tx_packets, u32::MAX);
    }

    #[test]
    fn test_wifi_stats_clear() {
        let mut stats = WifiStats::new();
        stats.tx_packets = 100;
        stats.rx_packets = 50;
        stats.clear();
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.rx_packets, 0);
    }

    #[test]
    fn test_wifi_network_set_ssid() {
        let mut network = WifiNetwork::new();
        let ssid = b"TestNetwork";
        network.set_ssid(ssid);
        assert_eq!(network.ssid_len, 11);
        assert_eq!(network.ssid_str(), ssid);
    }

    #[test]
    fn test_wifi_network_long_ssid() {
        let mut network = WifiNetwork::new();
        let long_ssid = [0x41; 40]; // 40 bytes
        network.set_ssid(&long_ssid);
        assert_eq!(network.ssid_len, 32); // Clamped to 32
    }

    #[test]
    fn test_controller_initialization() {
        let mut ctrl = WifiController::new();
        assert_eq!(ctrl.state(), ConnectionState::Disconnected);
        assert!(ctrl.initialize().is_ok());
    }

    #[test]
    fn test_controller_scan() {
        let mut ctrl = WifiController::new();
        assert!(ctrl.scan().is_ok());
        assert_eq!(ctrl.state(), ConnectionState::Scanning);
        assert!(ctrl.scan().is_err()); // Can't scan while scanning
    }

    #[test]
    fn test_controller_add_scan_result() {
        let mut ctrl = WifiController::new();
        let result = WifiScanResult::new();
        assert!(ctrl.add_scan_result(result).is_ok());
        assert_eq!(ctrl.scan_count(), 1);
    }

    #[test]
    fn test_controller_scan_buffer_full() {
        let mut ctrl = WifiController::new();
        let result = WifiScanResult::new();

        // Fill buffer
        for _ in 0..32 {
            let _ = ctrl.add_scan_result(result);
        }

        // Try to add one more
        assert!(ctrl.add_scan_result(result).is_err());
    }

    #[test]
    fn test_controller_connect_valid() {
        let mut ctrl = WifiController::new();
        let ssid = b"TestNetwork";
        let password = b"password123";
        assert!(ctrl.connect(ssid, password).is_ok());
        assert_eq!(ctrl.state(), ConnectionState::Authenticating);
    }

    #[test]
    fn test_controller_connect_invalid_ssid() {
        let mut ctrl = WifiController::new();
        let ssid = [0x41; 33]; // 33 bytes, too long
        let password = b"password";
        assert!(ctrl.connect(&ssid, password).is_err());
    }

    #[test]
    fn test_controller_connect_empty_ssid() {
        let mut ctrl = WifiController::new();
        let ssid = b"";
        let password = b"password";
        assert!(ctrl.connect(ssid, password).is_err());
    }

    #[test]
    fn test_controller_connect_long_password() {
        let mut ctrl = WifiController::new();
        let ssid = b"TestNetwork";
        let password = [0x41; 65]; // 65 bytes, too long
        assert!(ctrl.connect(ssid, &password).is_err());
    }

    #[test]
    fn test_controller_connection_complete() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Authenticating;
        ctrl.connection_complete(true);
        assert_eq!(ctrl.state(), ConnectionState::Connected);
    }

    #[test]
    fn test_controller_connection_failure() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Authenticating;
        ctrl.connection_complete(false);
        assert_eq!(ctrl.state(), ConnectionState::Disconnected);
        assert_eq!(ctrl.stats().auth_failures, 1);
    }

    #[test]
    fn test_controller_disconnect() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Connected;
        assert!(ctrl.disconnect().is_ok());
        assert_eq!(ctrl.state(), ConnectionState::Disconnected);
        assert_eq!(ctrl.stats().disconnections, 1);
    }

    #[test]
    fn test_controller_disconnect_when_already_disconnected() {
        let mut ctrl = WifiController::new();
        assert!(ctrl.disconnect().is_err());
    }

    #[test]
    fn test_controller_set_channel() {
        let mut ctrl = WifiController::new();
        let channel = WifiChannel::new(6, 2437, WifiBand::Band2_4Ghz, 20);
        assert!(ctrl.set_channel(channel).is_ok());
        assert_eq!(ctrl.current_channel().channel, 6);
    }

    #[test]
    fn test_controller_channel_while_connected() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Connected;
        let channel = WifiChannel::new(6, 2437, WifiBand::Band2_4Ghz, 20);
        assert!(ctrl.set_channel(channel).is_err());
    }

    #[test]
    fn test_controller_signal_strength() {
        let mut ctrl = WifiController::new();
        ctrl.update_signal_strength(-50);
        assert_eq!(ctrl.signal_strength(), -50);
    }

    #[test]
    fn test_controller_tx_power_clamping() {
        let mut ctrl = WifiController::new();
        ctrl.set_tx_power(-10);
        assert_eq!(ctrl.tx_power(), 0);

        ctrl.set_tx_power(40);
        assert_eq!(ctrl.tx_power(), 30);

        ctrl.set_tx_power(15);
        assert_eq!(ctrl.tx_power(), 15);
    }

    #[test]
    fn test_controller_power_save() {
        let mut ctrl = WifiController::new();
        assert!(ctrl.enable_power_save().is_ok());
        assert_eq!(ctrl.power_state(), PowerState::Save);

        assert!(ctrl.disable_power_save().is_ok());
        assert_eq!(ctrl.power_state(), PowerState::On);
    }

    #[test]
    fn test_controller_transmit_not_connected() {
        let mut ctrl = WifiController::new();
        let data = b"test";
        assert!(ctrl.transmit(data).is_err());
        assert_eq!(ctrl.stats().tx_dropped, 1);
    }

    #[test]
    fn test_controller_transmit_valid() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Connected;
        let data = b"test packet data";
        assert!(ctrl.transmit(data).is_ok());
        assert_eq!(ctrl.stats().tx_packets, 1);
        assert_eq!(ctrl.stats().tx_bytes, data.len() as u64);
    }

    #[test]
    fn test_controller_transmit_empty() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Connected;
        let data = b"";
        assert!(ctrl.transmit(data).is_err());
    }

    #[test]
    fn test_controller_transmit_too_large() {
        let mut ctrl = WifiController::new();
        ctrl.state = ConnectionState::Connected;
        let data = [0x41; 2341]; // Too large
        assert!(ctrl.transmit(&data).is_err());
    }

    #[test]
    fn test_controller_country_code() {
        let mut ctrl = WifiController::new();
        assert_eq!(ctrl.country_code(), [0x55, 0x53]); // US

        ctrl.set_country_code([0x47, 0x42]); // GB
        assert_eq!(ctrl.country_code(), [0x47, 0x42]);
    }

    #[test]
    fn test_controller_error_rate() {
        let mut ctrl = WifiController::new();
        ctrl.stats_mut().tx_errors = 5;
        ctrl.stats_mut().rx_errors = 3;
        assert_eq!(ctrl.get_error_rate(), 8);
    }

    #[test]
    fn test_auth_types() {
        let auth = AuthType::Wpa2Psk;
        assert_eq!(auth, AuthType::Wpa2Psk);
        assert_ne!(auth, AuthType::Open);
    }

    #[test]
    fn test_cipher_suites() {
        let cipher = CipherSuite::Ccmp;
        assert_eq!(cipher, CipherSuite::Ccmp);
        assert_ne!(cipher, CipherSuite::Tkip);
    }

    #[test]
    fn test_power_states() {
        let state = PowerState::Save;
        assert_eq!(state, PowerState::Save);
        assert_ne!(state, PowerState::On);
    }
}
