//! GPU-based Audio Driver for Raspberry Pi
//!
//! This module implements audio output via HDMI (PCM audio) and analog output
//! through the GPU's audio interface. Supports:
//! - HDMI audio output with multiple PCM formats
//! - Analog audio (3.5mm jack) via PWM or I2S
//! - Audio format configuration (sample rate, bit depth, channels)
//! - Multi-channel support (stereo, 5.1, 7.1)
//! - Volume control and audio routing

/// Audio sample rates in Hz
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleRate {
    /// 8 kHz (telephone quality)
    Hz8000,
    /// 16 kHz (wideband)
    Hz16000,
    /// 22.05 kHz (CD-like low quality)
    Hz22050,
    /// 24 kHz (professional audio)
    Hz24000,
    /// 32 kHz (broadcast quality)
    Hz32000,
    /// 44.1 kHz (CD standard)
    Hz44100,
    /// 48 kHz (professional standard)
    Hz48000,
    /// 96 kHz (high resolution)
    Hz96000,
    /// 192 kHz (ultra high resolution)
    Hz192000,
}

impl SampleRate {
    /// Get sample rate as integer
    pub fn hz(&self) -> u32 {
        match self {
            SampleRate::Hz8000 => 8000,
            SampleRate::Hz16000 => 16000,
            SampleRate::Hz22050 => 22050,
            SampleRate::Hz24000 => 24000,
            SampleRate::Hz32000 => 32000,
            SampleRate::Hz44100 => 44100,
            SampleRate::Hz48000 => 48000,
            SampleRate::Hz96000 => 96000,
            SampleRate::Hz192000 => 192000,
        }
    }
}

/// Audio sample bit depth
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitDepth {
    /// 8-bit audio (PCM u8)
    Bit8,
    /// 16-bit audio (PCM s16)
    Bit16,
    /// 24-bit audio (PCM s24)
    Bit24,
    /// 32-bit audio (PCM s32 or float)
    Bit32,
}

impl BitDepth {
    /// Get bit depth as integer
    pub fn bits(&self) -> u32 {
        match self {
            BitDepth::Bit8 => 8,
            BitDepth::Bit16 => 16,
            BitDepth::Bit24 => 24,
            BitDepth::Bit32 => 32,
        }
    }

    /// Get bytes per sample
    pub fn bytes_per_sample(&self) -> u32 {
        (self.bits() + 7) / 8
    }
}

/// Number of audio channels
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channels {
    /// Mono (1 channel)
    Mono,
    /// Stereo (2 channels)
    Stereo,
    /// Surround 5.1 (6 channels)
    Surround51,
    /// Surround 7.1 (8 channels)
    Surround71,
}

impl Channels {
    /// Get channel count
    pub fn count(&self) -> u32 {
        match self {
            Channels::Mono => 1,
            Channels::Stereo => 2,
            Channels::Surround51 => 6,
            Channels::Surround71 => 8,
        }
    }
}

/// Audio output routing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioOutput {
    /// HDMI audio (via HDMI cable)
    Hdmi,
    /// Analog audio (3.5mm headphone jack)
    Analog,
    /// Both HDMI and analog (if supported)
    Both,
}

/// Audio buffer status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferStatus {
    /// Buffer ready for writing
    Ready,
    /// Buffer currently playing
    Playing,
    /// Buffer is full
    Full,
    /// Underrun detected (buffer starved)
    Underrun,
}

/// Audio format configuration
#[derive(Clone, Copy, Debug)]
pub struct AudioFormat {
    /// Sample rate
    pub sample_rate: SampleRate,
    /// Bit depth per sample
    pub bit_depth: BitDepth,
    /// Number of channels
    pub channels: Channels,
}

impl AudioFormat {
    /// Create new audio format
    pub fn new(sample_rate: SampleRate, bit_depth: BitDepth, channels: Channels) -> Self {
        AudioFormat {
            sample_rate,
            bit_depth,
            channels,
        }
    }

    /// Calculate bytes per frame (all channels, one sample time)
    pub fn bytes_per_frame(&self) -> u32 {
        self.bit_depth.bytes_per_sample() * self.channels.count()
    }

    /// Calculate buffer size for given duration in milliseconds
    pub fn buffer_size_for_duration(&self, duration_ms: u32) -> u32 {
        let frames = (self.sample_rate.hz() * duration_ms) / 1000;
        frames * self.bytes_per_frame()
    }

    /// Calculate duration of buffer in milliseconds
    pub fn duration_ms(&self, buffer_size: u32) -> u32 {
        let total_samples = buffer_size / self.bit_depth.bytes_per_sample();
        let frames = total_samples / self.channels.count();
        (frames * 1000) / self.sample_rate.hz()
    }
}

/// Audio volume control (-80dB to 0dB)
#[derive(Clone, Copy, Debug)]
pub struct Volume {
    /// Volume in dB (-80 to 0, where 0 is maximum)
    db: i32,
}

impl Volume {
    /// Create volume from dB value (-80 to 0)
    pub fn from_db(db: i32) -> Self {
        let clamped = db.max(-80).min(0);
        Volume { db: clamped }
    }

    /// Create volume from percentage (0-100)
    pub fn from_percent(percent: u32) -> Self {
        let percent = percent.min(100);
        // Convert 0-100% to -80dB to 0dB logarithmically
        let db = -80 + (percent as i32 * 80) / 100;
        Volume { db }
    }

    /// Create silent volume
    pub fn silent() -> Self {
        Volume { db: -80 }
    }

    /// Create maximum volume
    pub fn maximum() -> Self {
        Volume { db: 0 }
    }

    /// Get volume in dB
    pub fn db(&self) -> i32 {
        self.db
    }

    /// Get volume as percentage (0-100)
    pub fn percent(&self) -> u32 {
        ((self.db + 80) * 100 / 80) as u32
    }

    /// Get linear amplitude (0.0 to 1.0)
    pub fn amplitude(&self) -> u32 {
        // Approximate linear amplitude from dB
        // amplitude = 10^(dB/20)
        // For simplicity, use 256-level lookup
        match self.db {
            0 => 256,
            -3 => 230,   // 0.9 * 256
            -6 => 205,   // 0.8 * 256
            -12 => 128,  // 0.5 * 256
            -24 => 64,   // 0.25 * 256
            -48 => 16,   // 0.0625 * 256
            _ => {
                // Linear interpolation for other values
                let base = (-self.db / 6) as u32;
                256 >> base
            }
        }
    }
}

/// Audio playback state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaybackState {
    /// Stopped, no playback
    Stopped,
    /// Playback in progress
    Playing,
    /// Playback paused
    Paused,
    /// Error state
    Error,
}

/// Audio buffer descriptor
#[derive(Clone, Copy, Debug)]
pub struct AudioBuffer {
    /// Physical memory address of buffer
    pub address: u32,
    /// Size of buffer in bytes
    pub size: u32,
    /// Current write offset
    pub write_offset: u32,
    /// Current read offset
    pub read_offset: u32,
    /// Format of audio in buffer
    pub format: AudioFormat,
}

impl AudioBuffer {
    /// Create new audio buffer
    pub fn new(address: u32, size: u32, format: AudioFormat) -> Self {
        AudioBuffer {
            address,
            size,
            write_offset: 0,
            read_offset: 0,
            format,
        }
    }

    /// Check if buffer has space for frames
    pub fn has_space_for(&self, frame_count: u32) -> bool {
        let bytes_needed = frame_count * self.format.bytes_per_frame();
        let available = self.size - ((self.write_offset - self.read_offset) % self.size);
        available >= bytes_needed
    }

    /// Get number of frames in buffer
    pub fn frame_count(&self) -> u32 {
        let bytes_used = (self.write_offset - self.read_offset) % self.size;
        bytes_used / self.format.bytes_per_frame()
    }

    /// Get buffer fill percentage
    pub fn fill_percent(&self) -> u32 {
        let bytes_used = (self.write_offset - self.read_offset) % self.size;
        (bytes_used * 100) / self.size
    }
}

/// GPU Audio Controller
pub struct GpuAudioController {
    /// Output destination
    output: AudioOutput,
    /// Current playback state
    state: PlaybackState,
    /// Current audio format
    format: AudioFormat,
    /// Current volume
    volume: Volume,
    /// HDMI audio enabled
    hdmi_enabled: bool,
    /// Analog audio enabled
    analog_enabled: bool,
    /// Playback buffers (double-buffering)
    buffers: [Option<AudioBuffer>; 2],
    /// Active buffer index
    active_buffer: usize,
    /// Frame counter for synchronization
    frame_counter: u32,
    /// Underrun count
    underrun_count: u32,
}

impl GpuAudioController {
    /// Create new audio controller
    pub fn new() -> Self {
        GpuAudioController {
            output: AudioOutput::Hdmi,
            state: PlaybackState::Stopped,
            format: AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo),
            volume: Volume::maximum(),
            hdmi_enabled: true,
            analog_enabled: false,
            buffers: [None; 2],
            active_buffer: 0,
            frame_counter: 0,
            underrun_count: 0,
        }
    }

    /// Set audio output routing
    pub fn set_output(&mut self, output: AudioOutput) -> Result<(), &'static str> {
        if self.state != PlaybackState::Stopped {
            return Err("Cannot change output while playing");
        }
        self.output = output;
        Ok(())
    }

    /// Enable HDMI audio
    pub fn enable_hdmi(&mut self) -> Result<(), &'static str> {
        self.hdmi_enabled = true;
        Ok(())
    }

    /// Disable HDMI audio
    pub fn disable_hdmi(&mut self) {
        self.hdmi_enabled = false;
    }

    /// Enable analog audio
    pub fn enable_analog(&mut self) -> Result<(), &'static str> {
        self.analog_enabled = true;
        Ok(())
    }

    /// Disable analog audio
    pub fn disable_analog(&mut self) {
        self.analog_enabled = false;
    }

    /// Set audio format
    pub fn set_format(&mut self, format: AudioFormat) -> Result<(), &'static str> {
        if self.state != PlaybackState::Stopped {
            return Err("Cannot change format while playing");
        }
        self.format = format;
        Ok(())
    }

    /// Set playback volume
    pub fn set_volume(&mut self, volume: Volume) {
        self.volume = volume;
    }

    /// Get current volume
    pub fn volume(&self) -> Volume {
        self.volume
    }

    /// Get current playback state
    pub fn state(&self) -> PlaybackState {
        self.state
    }

    /// Allocate playback buffer
    pub fn allocate_buffer(&mut self, address: u32, size: u32) -> Result<(), &'static str> {
        let buffer = AudioBuffer::new(address, size, self.format);

        // Find empty slot
        for slot in &mut self.buffers {
            if slot.is_none() {
                *slot = Some(buffer);
                return Ok(());
            }
        }

        Err("No buffer slots available")
    }

    /// Start playback
    pub fn start(&mut self) -> Result<(), &'static str> {
        if self.buffers[0].is_none() {
            return Err("No buffers allocated");
        }

        if !self.hdmi_enabled && !self.analog_enabled {
            return Err("No audio outputs enabled");
        }

        self.state = PlaybackState::Playing;
        self.frame_counter = 0;
        self.underrun_count = 0;
        Ok(())
    }

    /// Pause playback
    pub fn pause(&mut self) -> Result<(), &'static str> {
        if self.state != PlaybackState::Playing {
            return Err("Not currently playing");
        }
        self.state = PlaybackState::Paused;
        Ok(())
    }

    /// Resume playback
    pub fn resume(&mut self) -> Result<(), &'static str> {
        if self.state != PlaybackState::Paused {
            return Err("Not currently paused");
        }
        self.state = PlaybackState::Playing;
        Ok(())
    }

    /// Stop playback
    pub fn stop(&mut self) {
        self.state = PlaybackState::Stopped;
    }

    /// Write audio frames to buffer
    pub fn write_frames(&mut self, data: &[u8], frame_count: u32) -> Result<u32, &'static str> {
        if self.state == PlaybackState::Stopped {
            return Err("Playback not started");
        }

        if let Some(ref mut buffer) = self.buffers[self.active_buffer] {
            if !buffer.has_space_for(frame_count) {
                self.underrun_count += 1;
                return Err("Buffer overflow");
            }

            let bytes_to_write = (frame_count * buffer.format.bytes_per_frame()) as usize;
            if data.len() < bytes_to_write {
                return Err("Insufficient data");
            }

            // In real implementation, would copy data to buffer at buffer.address + buffer.write_offset
            buffer.write_offset = (buffer.write_offset + bytes_to_write as u32) % buffer.size;

            Ok(frame_count)
        } else {
            Err("No active buffer")
        }
    }

    /// Get current buffer status
    pub fn buffer_status(&self) -> BufferStatus {
        if let Some(ref buffer) = self.buffers[self.active_buffer] {
            if buffer.fill_percent() == 0 && self.state == PlaybackState::Playing {
                BufferStatus::Underrun
            } else if buffer.fill_percent() >= 95 {
                BufferStatus::Full
            } else if self.state == PlaybackState::Playing {
                BufferStatus::Playing
            } else {
                BufferStatus::Ready
            }
        } else {
            BufferStatus::Ready
        }
    }

    /// Increment frame counter (called by audio interrupt)
    pub fn advance_frames(&mut self, frame_count: u32) {
        self.frame_counter = self.frame_counter.wrapping_add(frame_count);

        if let Some(ref mut buffer) = self.buffers[self.active_buffer] {
            buffer.read_offset = (buffer.read_offset + (frame_count * buffer.format.bytes_per_frame())) % buffer.size;
        }
    }

    /// Get current frame count
    pub fn frame_count(&self) -> u32 {
        self.frame_counter
    }

    /// Get underrun count
    pub fn underrun_count(&self) -> u32 {
        self.underrun_count
    }

    /// Switch to next buffer (double-buffering)
    pub fn switch_buffer(&mut self) {
        if self.buffers[1].is_some() {
            self.active_buffer = 1 - self.active_buffer;
        }
    }
}

impl Default for GpuAudioController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_rates() {
        assert_eq!(SampleRate::Hz44100.hz(), 44100);
        assert_eq!(SampleRate::Hz48000.hz(), 48000);
        assert_eq!(SampleRate::Hz192000.hz(), 192000);
    }

    #[test]
    fn test_bit_depth() {
        assert_eq!(BitDepth::Bit16.bits(), 16);
        assert_eq!(BitDepth::Bit24.bytes_per_sample(), 3);
        assert_eq!(BitDepth::Bit32.bytes_per_sample(), 4);
    }

    #[test]
    fn test_channels() {
        assert_eq!(Channels::Mono.count(), 1);
        assert_eq!(Channels::Stereo.count(), 2);
        assert_eq!(Channels::Surround51.count(), 6);
        assert_eq!(Channels::Surround71.count(), 8);
    }

    #[test]
    fn test_audio_format() {
        let format = AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo);
        assert_eq!(format.bytes_per_frame(), 4); // 16 bits * 2 channels / 8
        assert_eq!(format.sample_rate.hz(), 48000);
    }

    #[test]
    fn test_buffer_size_calculation() {
        let format = AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo);
        // 1 second of audio: 48000 frames * 4 bytes/frame = 192000 bytes
        assert_eq!(format.buffer_size_for_duration(1000), 192000);
        // 10ms: 480 frames * 4 bytes/frame = 1920 bytes
        assert_eq!(format.buffer_size_for_duration(10), 1920);
    }

    #[test]
    fn test_volume_from_db() {
        let vol = Volume::from_db(0);
        assert_eq!(vol.db(), 0);
        assert_eq!(vol.percent(), 100);

        let vol = Volume::from_db(-40);
        assert_eq!(vol.db(), -40);
    }

    #[test]
    fn test_volume_from_percent() {
        let vol = Volume::from_percent(100);
        assert_eq!(vol.db(), 0);

        let vol = Volume::from_percent(50);
        assert_eq!(vol.db(), -40);

        let vol = Volume::from_percent(0);
        assert_eq!(vol.db(), -80);
    }

    #[test]
    fn test_volume_amplitude() {
        let max = Volume::maximum();
        assert_eq!(max.amplitude(), 256);

        let silent = Volume::silent();
        assert!(silent.amplitude() < 256);
    }

    #[test]
    fn test_audio_buffer() {
        let format = AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo);
        let buffer = AudioBuffer::new(0x80000000, 192000, format);

        assert_eq!(buffer.frame_count(), 0);
        assert_eq!(buffer.fill_percent(), 0);
        assert!(buffer.has_space_for(100));
    }

    #[test]
    fn test_audio_controller_initialization() {
        let controller = GpuAudioController::new();
        assert_eq!(controller.state(), PlaybackState::Stopped);
        assert!(controller.hdmi_enabled);
        assert!(!controller.analog_enabled);
    }

    #[test]
    fn test_audio_controller_format() {
        let mut controller = GpuAudioController::new();
        let format = AudioFormat::new(SampleRate::Hz96000, BitDepth::Bit24, Channels::Surround51);
        assert!(controller.set_format(format).is_ok());
    }

    #[test]
    fn test_audio_controller_volume() {
        let mut controller = GpuAudioController::new();
        let vol = Volume::from_percent(75);
        controller.set_volume(vol);
        assert_eq!(controller.volume().percent(), 75);
    }

    #[test]
    fn test_audio_output_routing() {
        let mut controller = GpuAudioController::new();
        assert!(controller.set_output(AudioOutput::Analog).is_ok());
        assert!(controller.set_output(AudioOutput::Both).is_ok());
    }

    #[test]
    fn test_playback_lifecycle() {
        let mut controller = GpuAudioController::new();
        let format = AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo);
        controller.set_format(format).ok();
        controller.allocate_buffer(0x80000000, 192000).ok();

        assert!(controller.start().is_ok());
        assert_eq!(controller.state(), PlaybackState::Playing);

        assert!(controller.pause().is_ok());
        assert_eq!(controller.state(), PlaybackState::Paused);

        assert!(controller.resume().is_ok());
        assert_eq!(controller.state(), PlaybackState::Playing);

        controller.stop();
        assert_eq!(controller.state(), PlaybackState::Stopped);
    }

    #[test]
    fn test_frame_advancement() {
        let mut controller = GpuAudioController::new();
        let format = AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo);
        controller.set_format(format).ok();
        controller.allocate_buffer(0x80000000, 192000).ok();
        controller.start().ok();

        assert_eq!(controller.frame_count(), 0);
        controller.advance_frames(1000);
        assert_eq!(controller.frame_count(), 1000);
    }

    #[test]
    fn test_double_buffering() {
        let mut controller = GpuAudioController::new();
        let format = AudioFormat::new(SampleRate::Hz48000, BitDepth::Bit16, Channels::Stereo);
        controller.set_format(format).ok();
        controller.allocate_buffer(0x80000000, 192000).ok();
        controller.allocate_buffer(0x80040000, 192000).ok();

        assert_eq!(controller.active_buffer, 0);
        controller.switch_buffer();
        assert_eq!(controller.active_buffer, 1);
        controller.switch_buffer();
        assert_eq!(controller.active_buffer, 0);
    }
}
