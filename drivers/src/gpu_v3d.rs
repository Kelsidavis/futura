//! V3D 3D Graphics Driver for Raspberry Pi 4/5
//!
//! This module implements V3D GPU support including:
//! - Job submission and execution tracking
//! - Texture and buffer management
//! - Rendering command lists
//! - Performance monitoring
//!
//! The V3D core is present on RPi4 (v4.1) and RPi5 (v7.1) platforms.
//! RPi3 uses the older VideoCore IV with no 3D acceleration.

use core::fmt;

/// V3D core version information
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3dVersion {
    /// V3D 4.1 (RPi4)
    V41,
    /// V3D 7.1 (RPi5)
    V71,
}

/// GPU job submission status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStatus {
    /// Job is queued and waiting
    Queued,
    /// Job is currently executing
    Running,
    /// Job completed successfully
    Completed,
    /// Job encountered an error
    Error,
    /// Job was cancelled
    Cancelled,
}

/// Texture formats supported by V3D
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextureFormat {
    /// 8-bit grayscale
    R8,
    /// 16-bit RGB (5-6-5)
    Rgb565,
    /// 24-bit RGB (8-8-8)
    Rgb888,
    /// 32-bit RGBA with alpha
    Rgba8888,
    /// Floating-point formats
    Rg16f,
    /// Depth formats
    Depth32f,
    /// Compressed formats (BC)
    Bc1,
}

impl TextureFormat {
    /// Get bits per pixel for this format
    pub fn bits_per_pixel(&self) -> u32 {
        match self {
            TextureFormat::R8 => 8,
            TextureFormat::Rgb565 => 16,
            TextureFormat::Rgb888 => 24,
            TextureFormat::Rgba8888 => 32,
            TextureFormat::Rg16f => 32,
            TextureFormat::Depth32f => 32,
            TextureFormat::Bc1 => 4, // Compressed
        }
    }

    /// Get bytes per pixel for this format
    pub fn bytes_per_pixel(&self) -> u32 {
        (self.bits_per_pixel() + 7) / 8
    }
}

/// Texture descriptor
#[derive(Clone, Copy, Debug)]
pub struct Texture {
    /// GPU memory address
    pub address: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Texture format
    pub format: TextureFormat,
    /// Mipmap levels (0 = no mipmaps)
    pub mipmap_levels: u32,
}

impl Texture {
    /// Create a new texture
    pub fn new(address: u32, width: u32, height: u32, format: TextureFormat) -> Self {
        Texture {
            address,
            width,
            height,
            format,
            mipmap_levels: 0,
        }
    }

    /// Calculate texture size in bytes
    pub fn size(&self) -> u32 {
        self.width * self.height * self.format.bytes_per_pixel()
    }
}

/// Vertex buffer descriptor
#[derive(Clone, Copy, Debug)]
pub struct VertexBuffer {
    /// GPU memory address
    pub address: u32,
    /// Size in bytes
    pub size: u32,
    /// Vertex stride in bytes
    pub stride: u32,
    /// Number of vertices
    pub vertex_count: u32,
}

impl VertexBuffer {
    /// Create a new vertex buffer
    pub fn new(address: u32, size: u32, stride: u32, vertex_count: u32) -> Self {
        VertexBuffer {
            address,
            size,
            stride,
            vertex_count,
        }
    }
}

/// Index buffer descriptor
#[derive(Clone, Copy, Debug)]
pub struct IndexBuffer {
    /// GPU memory address
    pub address: u32,
    /// Size in bytes
    pub size: u32,
    /// Number of indices
    pub index_count: u32,
}

impl IndexBuffer {
    /// Create a new index buffer
    pub fn new(address: u32, size: u32, index_count: u32) -> Self {
        IndexBuffer {
            address,
            size,
            index_count,
        }
    }
}

/// Uniform buffer descriptor
#[derive(Clone, Copy, Debug)]
pub struct UniformBuffer {
    /// GPU memory address
    pub address: u32,
    /// Size in bytes
    pub size: u32,
}

impl UniformBuffer {
    /// Create a new uniform buffer
    pub fn new(address: u32, size: u32) -> Self {
        UniformBuffer { address, size }
    }
}

/// Rendering job command
#[derive(Clone, Copy, Debug)]
pub struct RenderJob {
    /// Job ID for tracking
    pub job_id: u32,
    /// Vertex buffer to render
    pub vertex_buffer: Option<VertexBuffer>,
    /// Index buffer for indexed rendering
    pub index_buffer: Option<IndexBuffer>,
    /// Number of primitives to render
    pub primitive_count: u32,
    /// Current job status
    pub status: JobStatus,
}

impl RenderJob {
    /// Create a new render job
    pub fn new(job_id: u32, primitive_count: u32) -> Self {
        RenderJob {
            job_id,
            vertex_buffer: None,
            index_buffer: None,
            primitive_count,
            status: JobStatus::Queued,
        }
    }

    /// Set vertex buffer for this job
    pub fn with_vertex_buffer(&mut self, buffer: VertexBuffer) {
        self.vertex_buffer = Some(buffer);
    }

    /// Set index buffer for this job
    pub fn with_index_buffer(&mut self, buffer: IndexBuffer) {
        self.index_buffer = Some(buffer);
    }
}

/// Compute shader job
#[derive(Clone, Copy, Debug)]
pub struct ComputeJob {
    /// Job ID for tracking
    pub job_id: u32,
    /// Work group size (X dimension)
    pub work_groups_x: u32,
    /// Work group size (Y dimension)
    pub work_groups_y: u32,
    /// Work group size (Z dimension)
    pub work_groups_z: u32,
    /// Current job status
    pub status: JobStatus,
}

impl ComputeJob {
    /// Create a new compute job
    pub fn new(job_id: u32, work_groups_x: u32, work_groups_y: u32, work_groups_z: u32) -> Self {
        ComputeJob {
            job_id,
            work_groups_x,
            work_groups_y,
            work_groups_z,
            status: JobStatus::Queued,
        }
    }

    /// Calculate total work groups
    pub fn total_work_groups(&self) -> u32 {
        self.work_groups_x * self.work_groups_y * self.work_groups_z
    }
}

/// Performance statistics
#[derive(Clone, Copy, Debug)]
pub struct PerformanceStats {
    /// Total jobs submitted
    pub jobs_submitted: u32,
    /// Total jobs completed
    pub jobs_completed: u32,
    /// Total job errors
    pub jobs_failed: u32,
    /// GPU time accumulated (clock cycles)
    pub gpu_cycles: u64,
    /// Average job duration (cycles)
    pub avg_job_duration: u32,
}

impl PerformanceStats {
    /// Create new statistics structure
    pub fn new() -> Self {
        PerformanceStats {
            jobs_submitted: 0,
            jobs_completed: 0,
            jobs_failed: 0,
            gpu_cycles: 0,
            avg_job_duration: 0,
        }
    }

    /// Update average job duration
    fn update_avg_duration(&mut self, duration: u32) {
        if self.jobs_completed > 0 {
            self.avg_job_duration =
                (self.avg_job_duration + duration) / self.jobs_completed.max(1);
        }
    }
}

impl Default for PerformanceStats {
    fn default() -> Self {
        Self::new()
    }
}

/// V3D GPU controller
pub struct V3dController {
    /// V3D core version
    version: V3dVersion,
    /// Controller enabled flag
    enabled: bool,
    /// Next job ID
    next_job_id: u32,
    /// Maximum jobs in flight
    max_jobs: u32,
    /// Performance statistics
    stats: PerformanceStats,
    /// Textures bound for rendering
    bound_textures: [Option<Texture>; 8],
}

impl V3dController {
    /// Create a new V3D controller
    pub fn new(version: V3dVersion) -> Self {
        V3dController {
            version,
            enabled: false,
            next_job_id: 0,
            max_jobs: 32,
            stats: PerformanceStats::new(),
            bound_textures: [None; 8],
        }
    }

    /// Get V3D core version
    pub fn version(&self) -> V3dVersion {
        self.version
    }

    /// Enable the V3D core
    pub fn enable(&mut self) -> Result<(), &'static str> {
        self.enabled = true;
        Ok(())
    }

    /// Disable the V3D core
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if V3D is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Allocate new job ID
    fn allocate_job_id(&mut self) -> u32 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        id
    }

    /// Submit a render job
    pub fn submit_render_job(&mut self, mut job: RenderJob) -> Result<u32, &'static str> {
        if !self.enabled {
            return Err("V3D controller not enabled");
        }

        if self.stats.jobs_submitted >= self.max_jobs {
            return Err("Job queue full");
        }

        job.job_id = self.allocate_job_id();
        self.stats.jobs_submitted += 1;

        Ok(job.job_id)
    }

    /// Submit a compute job
    pub fn submit_compute_job(&mut self, mut job: ComputeJob) -> Result<u32, &'static str> {
        if !self.enabled {
            return Err("V3D controller not enabled");
        }

        if self.stats.jobs_submitted >= self.max_jobs {
            return Err("Job queue full");
        }

        job.job_id = self.allocate_job_id();
        self.stats.jobs_submitted += 1;

        Ok(job.job_id)
    }

    /// Bind texture to texture unit
    pub fn bind_texture(&mut self, unit: usize, texture: Texture) -> Result<(), &'static str> {
        if unit >= 8 {
            return Err("Texture unit out of bounds (0-7)");
        }

        self.bound_textures[unit] = Some(texture);
        Ok(())
    }

    /// Unbind texture from texture unit
    pub fn unbind_texture(&mut self, unit: usize) -> Result<(), &'static str> {
        if unit >= 8 {
            return Err("Texture unit out of bounds (0-7)");
        }

        self.bound_textures[unit] = None;
        Ok(())
    }

    /// Get bound texture at unit
    pub fn get_texture(&self, unit: usize) -> Option<&Texture> {
        if unit < 8 {
            self.bound_textures[unit].as_ref()
        } else {
            None
        }
    }

    /// Get performance statistics
    pub fn stats(&self) -> &PerformanceStats {
        &self.stats
    }

    /// Get mutable performance statistics
    pub fn stats_mut(&mut self) -> &mut PerformanceStats {
        &mut self.stats
    }

    /// Record job completion
    pub fn record_job_complete(&mut self, duration_cycles: u32) {
        self.stats.jobs_completed += 1;
        self.stats.gpu_cycles += duration_cycles as u64;
        self.stats.update_avg_duration(duration_cycles);
    }

    /// Record job failure
    pub fn record_job_error(&mut self) {
        self.stats.jobs_failed += 1;
    }

    /// Reset performance statistics
    pub fn reset_stats(&mut self) {
        self.stats = PerformanceStats::new();
    }
}

impl Default for V3dController {
    fn default() -> Self {
        Self::new(V3dVersion::V71)
    }
}

impl fmt::Debug for V3dController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V3dController")
            .field("version", &self.version)
            .field("enabled", &self.enabled)
            .field("next_job_id", &self.next_job_id)
            .field("max_jobs", &self.max_jobs)
            .field("jobs_submitted", &self.stats.jobs_submitted)
            .field("jobs_completed", &self.stats.jobs_completed)
            .field("jobs_failed", &self.stats.jobs_failed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_texture_format_sizes() {
        assert_eq!(TextureFormat::R8.bits_per_pixel(), 8);
        assert_eq!(TextureFormat::Rgb565.bits_per_pixel(), 16);
        assert_eq!(TextureFormat::Rgb888.bits_per_pixel(), 24);
        assert_eq!(TextureFormat::Rgba8888.bits_per_pixel(), 32);

        assert_eq!(TextureFormat::R8.bytes_per_pixel(), 1);
        assert_eq!(TextureFormat::Rgb565.bytes_per_pixel(), 2);
        assert_eq!(TextureFormat::Rgb888.bytes_per_pixel(), 3);
        assert_eq!(TextureFormat::Rgba8888.bytes_per_pixel(), 4);
    }

    #[test]
    fn test_texture_size_calculation() {
        let tex = Texture::new(0x10000000, 1920, 1080, TextureFormat::Rgba8888);
        assert_eq!(tex.size(), 1920 * 1080 * 4);
    }

    #[test]
    fn test_vertex_buffer_creation() {
        let buffer = VertexBuffer::new(0x10000000, 16384, 24, 682);
        assert_eq!(buffer.vertex_count, 682);
        assert_eq!(buffer.size, 16384);
    }

    #[test]
    fn test_render_job_creation() {
        let mut job = RenderJob::new(0, 1000);
        assert_eq!(job.status, JobStatus::Queued);

        let vb = VertexBuffer::new(0x10000000, 8192, 12, 682);
        job.with_vertex_buffer(vb);
        assert!(job.vertex_buffer.is_some());
    }

    #[test]
    fn test_compute_job_creation() {
        let job = ComputeJob::new(0, 64, 64, 1);
        assert_eq!(job.total_work_groups(), 4096);
    }

    #[test]
    fn test_v3d_controller() {
        let mut v3d = V3dController::new(V3dVersion::V41);
        assert!(!v3d.is_enabled());

        assert!(v3d.enable().is_ok());
        assert!(v3d.is_enabled());

        // Test texture binding
        let tex = Texture::new(0x10000000, 512, 512, TextureFormat::Rgba8888);
        assert!(v3d.bind_texture(0, tex).is_ok());
        assert!(v3d.get_texture(0).is_some());

        // Test job submission
        let job = RenderJob::new(0, 500);
        assert!(v3d.submit_render_job(job).is_ok());
        assert_eq!(v3d.stats().jobs_submitted, 1);
    }

    #[test]
    fn test_texture_binding() {
        let mut v3d = V3dController::new(V3dVersion::V71);
        v3d.enable().ok();

        let tex1 = Texture::new(0x10000000, 256, 256, TextureFormat::Rgb888);
        let tex2 = Texture::new(0x20000000, 512, 512, TextureFormat::Rgba8888);

        // Bind multiple textures
        assert!(v3d.bind_texture(0, tex1).is_ok());
        assert!(v3d.bind_texture(1, tex2).is_ok());

        assert!(v3d.get_texture(0).is_some());
        assert!(v3d.get_texture(1).is_some());

        // Unbind
        assert!(v3d.unbind_texture(0).is_ok());
        assert!(v3d.get_texture(0).is_none());
    }

    #[test]
    fn test_performance_tracking() {
        let mut v3d = V3dController::new(V3dVersion::V41);
        v3d.enable().ok();

        // Submit and track jobs
        for i in 0..10 {
            let job = RenderJob::new(i, 100);
            v3d.submit_render_job(job).ok();
        }

        // Simulate completions
        for _ in 0..5 {
            v3d.record_job_complete(1000);
        }
        for _ in 0..3 {
            v3d.record_job_error();
        }

        let stats = v3d.stats();
        assert_eq!(stats.jobs_submitted, 10);
        assert_eq!(stats.jobs_completed, 5);
        assert_eq!(stats.jobs_failed, 3);
    }

    #[test]
    fn test_job_queue_limit() {
        let mut v3d = V3dController::new(V3dVersion::V71);
        v3d.enable().ok();
        v3d.max_jobs = 2;

        let job1 = RenderJob::new(0, 100);
        let job2 = RenderJob::new(1, 100);
        let job3 = RenderJob::new(2, 100);

        assert!(v3d.submit_render_job(job1).is_ok());
        assert!(v3d.submit_render_job(job2).is_ok());
        assert!(v3d.submit_render_job(job3).is_err()); // Queue full
    }

    #[test]
    fn test_v3d_version_detection() {
        let v3d_v41 = V3dController::new(V3dVersion::V41);
        assert_eq!(v3d_v41.version(), V3dVersion::V41);

        let v3d_v71 = V3dController::new(V3dVersion::V71);
        assert_eq!(v3d_v71.version(), V3dVersion::V71);
    }
}
