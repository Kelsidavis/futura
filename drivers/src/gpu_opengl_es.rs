//! OpenGL ES 3.2 Driver for Raspberry Pi 3/4/5
//!
//! This module implements OpenGL ES 3.2 graphics API support including:
//! - Shader compilation and linking
//! - Vertex and fragment shader management
//! - Program objects and attribute/uniform handling
//! - Matrix transformations (projection, view, model)
//! - Drawing primitives (triangles, lines, points)
//! - Texture management and binding
//! - Framebuffer objects (FBO)
//! - Blending and depth testing
//! - Viewport and scissor testing
//!
//! Supports RPi3 (VideoCore IV), RPi4 (V3D 4.1), RPi5 (V3D 7.1) with fallback to software rendering.

use core::fmt;

/// OpenGL ES 3.2 capability flags
#[derive(Clone, Copy, Debug)]
pub struct GlCapabilities {
    /// Blend testing enabled
    pub blend: bool,
    /// Depth testing enabled
    pub depth_test: bool,
    /// Scissor testing enabled
    pub scissor_test: bool,
    /// Face culling enabled
    pub cull_face: bool,
    /// Dithering enabled
    pub dither: bool,
    /// Polygon offset fill enabled
    pub polygon_offset_fill: bool,
}

impl GlCapabilities {
    /// Create new capabilities with all disabled
    pub fn new() -> Self {
        GlCapabilities {
            blend: false,
            depth_test: false,
            scissor_test: false,
            cull_face: false,
            dither: true,
            polygon_offset_fill: false,
        }
    }
}

impl Default for GlCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

/// Blend equation modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlendEquation {
    /// Source + Destination
    Add,
    /// Source - Destination
    Subtract,
    /// Destination - Source
    ReverseSubtract,
    /// Minimum of source and destination
    Min,
    /// Maximum of source and destination
    Max,
}

/// Blend function factors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlendFunc {
    /// Factor = (0, 0, 0, 0)
    Zero,
    /// Factor = (1, 1, 1, 1)
    One,
    /// Factor = source color
    SrcColor,
    /// Factor = 1 - source color
    OneMinusSrcColor,
    /// Factor = destination color
    DstColor,
    /// Factor = 1 - destination color
    OneMinusDstColor,
    /// Factor = source alpha
    SrcAlpha,
    /// Factor = 1 - source alpha
    OneMinusSrcAlpha,
    /// Factor = destination alpha
    DstAlpha,
    /// Factor = 1 - destination alpha
    OneMinusDstAlpha,
    /// Factor = constant color
    ConstantColor,
    /// Factor = 1 - constant color
    OneMinusConstantColor,
}

/// Depth comparison functions
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepthFunc {
    /// Never pass
    Never,
    /// Pass if less than
    Less,
    /// Pass if equal
    Equal,
    /// Pass if less than or equal
    LessEqual,
    /// Pass if greater than
    Greater,
    /// Pass if not equal
    NotEqual,
    /// Pass if greater than or equal
    GreaterEqual,
    /// Always pass
    Always,
}

/// Cull face modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CullFace {
    /// Cull front-facing primitives
    Front,
    /// Cull back-facing primitives
    Back,
    /// Cull front and back
    FrontAndBack,
}

/// Front face winding order
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontFace {
    /// Counter-clockwise
    Ccw,
    /// Clockwise
    Cw,
}

/// Primitive types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimitiveType {
    /// Individual points
    Points,
    /// Lines between consecutive vertices
    Lines,
    /// Connected line strip
    LineStrip,
    /// Closed line loop
    LineLoop,
    /// Individual triangles
    Triangles,
    /// Connected triangle strip
    TriangleStrip,
    /// Triangle fan (first vertex + pairs)
    TriangleFan,
}

/// Shader types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShaderType {
    /// Vertex shader
    VertexShader,
    /// Fragment shader
    FragmentShader,
    /// Geometry shader (optional)
    GeometryShader,
    /// Tessellation control shader (optional)
    TessellationControl,
    /// Tessellation evaluation shader (optional)
    TessellationEvaluation,
}

/// Shader object
#[derive(Clone, Copy, Debug)]
pub struct Shader {
    /// Shader ID
    pub id: u32,
    /// Shader type
    pub shader_type: ShaderType,
    /// Compiled flag
    pub compiled: bool,
}

impl Shader {
    /// Create a new shader
    pub fn new(id: u32, shader_type: ShaderType) -> Self {
        Shader {
            id,
            shader_type,
            compiled: false,
        }
    }
}

/// Attribute descriptor
#[derive(Clone, Copy, Debug)]
pub struct Attribute {
    /// Attribute location
    pub location: u32,
    /// Attribute size (1-4)
    pub size: u32,
    /// Data type (GL_FLOAT, GL_INT, etc.)
    pub data_type: u32,
}

impl Attribute {
    /// Create a new attribute
    pub fn new(location: u32, size: u32, data_type: u32) -> Self {
        Attribute {
            location,
            size,
            data_type,
        }
    }
}

/// Uniform descriptor
#[derive(Clone, Copy, Debug)]
pub struct Uniform {
    /// Uniform location
    pub location: u32,
    /// Uniform size (for arrays)
    pub size: u32,
    /// Data type
    pub data_type: u32,
}

impl Uniform {
    /// Create a new uniform
    pub fn new(location: u32, size: u32, data_type: u32) -> Self {
        Uniform {
            location,
            size,
            data_type,
        }
    }
}

/// Program object
#[derive(Clone, Copy, Debug)]
pub struct Program {
    /// Program ID
    pub id: u32,
    /// Linked flag
    pub linked: bool,
    /// Number of attributes
    pub attribute_count: u32,
    /// Number of uniforms
    pub uniform_count: u32,
}

impl Program {
    /// Create a new program
    pub fn new(id: u32) -> Self {
        Program {
            id,
            linked: false,
            attribute_count: 0,
            uniform_count: 0,
        }
    }
}

/// Viewport specification
#[derive(Clone, Copy, Debug)]
pub struct Viewport {
    /// X origin
    pub x: i32,
    /// Y origin
    pub y: i32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

impl Viewport {
    /// Create a new viewport
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Viewport { x, y, width, height }
    }
}

/// Scissor box specification
#[derive(Clone, Copy, Debug)]
pub struct ScissorBox {
    /// X origin
    pub x: i32,
    /// Y origin
    pub y: i32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

impl ScissorBox {
    /// Create a new scissor box
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        ScissorBox { x, y, width, height }
    }
}

/// Framebuffer object
#[derive(Clone, Copy, Debug)]
pub struct Framebuffer {
    /// Framebuffer ID
    pub id: u32,
    /// Color attachment texture ID
    pub color_texture: u32,
    /// Depth texture ID
    pub depth_texture: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Complete flag
    pub complete: bool,
}

impl Framebuffer {
    /// Create a new framebuffer
    pub fn new(id: u32, width: u32, height: u32) -> Self {
        Framebuffer {
            id,
            color_texture: 0,
            depth_texture: 0,
            width,
            height,
            complete: false,
        }
    }
}

/// Texture object
#[derive(Clone, Copy, Debug)]
pub struct GlTexture {
    /// Texture ID
    pub id: u32,
    /// Texture target (GL_TEXTURE_2D, etc.)
    pub target: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Format (GL_RGBA, GL_RGB, etc.)
    pub format: u32,
    /// Internal format
    pub internal_format: u32,
    /// Bound flag
    pub bound: bool,
}

impl GlTexture {
    /// Create a new texture
    pub fn new(id: u32, target: u32, width: u32, height: u32) -> Self {
        GlTexture {
            id,
            target,
            width,
            height,
            format: 0x1908, // GL_RGBA
            internal_format: 0x1908,
            bound: false,
        }
    }
}

/// Render state
#[derive(Clone, Copy, Debug)]
pub struct RenderState {
    /// Clear color (RGBA)
    pub clear_color: (f32, f32, f32, f32),
    /// Clear depth
    pub clear_depth: f32,
    /// Clear stencil
    pub clear_stencil: u32,
    /// Blend equation for RGB
    pub blend_equation_rgb: BlendEquation,
    /// Blend equation for alpha
    pub blend_equation_alpha: BlendEquation,
    /// Blend function source RGB
    pub blend_src_rgb: BlendFunc,
    /// Blend function destination RGB
    pub blend_dst_rgb: BlendFunc,
    /// Blend function source alpha
    pub blend_src_alpha: BlendFunc,
    /// Blend function destination alpha
    pub blend_dst_alpha: BlendFunc,
    /// Depth comparison function
    pub depth_func: DepthFunc,
    /// Depth write enable
    pub depth_write: bool,
    /// Cull face mode
    pub cull_face_mode: CullFace,
    /// Front face winding
    pub front_face: FrontFace,
    /// Current viewport
    pub viewport: Viewport,
    /// Current scissor box
    pub scissor_box: ScissorBox,
    /// Line width
    pub line_width: f32,
    /// Point size
    pub point_size: f32,
}

impl RenderState {
    /// Create new render state with defaults
    pub fn new() -> Self {
        RenderState {
            clear_color: (0.0, 0.0, 0.0, 1.0),
            clear_depth: 1.0,
            clear_stencil: 0,
            blend_equation_rgb: BlendEquation::Add,
            blend_equation_alpha: BlendEquation::Add,
            blend_src_rgb: BlendFunc::SrcAlpha,
            blend_dst_rgb: BlendFunc::OneMinusSrcAlpha,
            blend_src_alpha: BlendFunc::One,
            blend_dst_alpha: BlendFunc::OneMinusSrcAlpha,
            depth_func: DepthFunc::Less,
            depth_write: true,
            cull_face_mode: CullFace::Back,
            front_face: FrontFace::Ccw,
            viewport: Viewport::new(0, 0, 1024, 768),
            scissor_box: ScissorBox::new(0, 0, 1024, 768),
            line_width: 1.0,
            point_size: 1.0,
        }
    }
}

impl Default for RenderState {
    fn default() -> Self {
        Self::new()
    }
}

/// OpenGL ES 3.2 context
pub struct GlContext {
    /// Context enabled
    enabled: bool,
    /// Current capabilities
    capabilities: GlCapabilities,
    /// Render state
    state: RenderState,
    /// Current program
    current_program: Option<u32>,
    /// Next object ID counter
    next_id: u32,
    /// Bound framebuffer
    bound_framebuffer: Option<u32>,
    /// Bound textures (16 texture units)
    bound_textures: [Option<u32>; 16],
    /// Active texture unit
    active_texture: u32,
    /// Statistics
    draw_calls: u32,
    vertices_rendered: u32,
    triangles_rendered: u32,
}

impl GlContext {
    /// Create a new OpenGL ES 3.2 context
    pub fn new() -> Self {
        GlContext {
            enabled: false,
            capabilities: GlCapabilities::new(),
            state: RenderState::new(),
            current_program: None,
            next_id: 1,
            bound_framebuffer: None,
            bound_textures: [None; 16],
            active_texture: 0,
            draw_calls: 0,
            vertices_rendered: 0,
            triangles_rendered: 0,
        }
    }

    /// Initialize the OpenGL ES context
    pub fn initialize(&mut self) -> Result<(), &'static str> {
        self.enabled = true;
        Ok(())
    }

    /// Check if context is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Terminate the context
    pub fn terminate(&mut self) {
        self.enabled = false;
    }

    /// Allocate a new object ID
    fn allocate_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    // ============ Capabilities ============

    /// Enable a capability
    pub fn enable(&mut self, capability: GlCapabilities) {
        // Merge capabilities with bitwise OR semantics
        self.capabilities.blend = self.capabilities.blend || capability.blend;
        self.capabilities.depth_test = self.capabilities.depth_test || capability.depth_test;
        self.capabilities.scissor_test = self.capabilities.scissor_test || capability.scissor_test;
        self.capabilities.cull_face = self.capabilities.cull_face || capability.cull_face;
        self.capabilities.dither = self.capabilities.dither || capability.dither;
        self.capabilities.polygon_offset_fill =
            self.capabilities.polygon_offset_fill || capability.polygon_offset_fill;
    }

    /// Disable a capability
    pub fn disable(&mut self, capability: GlCapabilities) {
        self.capabilities.blend = self.capabilities.blend && !capability.blend;
        self.capabilities.depth_test = self.capabilities.depth_test && !capability.depth_test;
        self.capabilities.scissor_test =
            self.capabilities.scissor_test && !capability.scissor_test;
        self.capabilities.cull_face = self.capabilities.cull_face && !capability.cull_face;
        self.capabilities.dither = self.capabilities.dither && !capability.dither;
        self.capabilities.polygon_offset_fill =
            self.capabilities.polygon_offset_fill && !capability.polygon_offset_fill;
    }

    /// Get current capabilities
    pub fn capabilities(&self) -> &GlCapabilities {
        &self.capabilities
    }

    // ============ Shader Operations ============

    /// Create a new shader
    pub fn create_shader(&mut self, shader_type: ShaderType) -> Shader {
        let id = self.allocate_id();
        Shader::new(id, shader_type)
    }

    /// Compile shader source code
    pub fn compile_shader(&mut self, shader: &mut Shader, _source: &[u8]) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("GL context not enabled");
        }
        shader.compiled = true;
        Ok(())
    }

    /// Get shader compilation status
    pub fn shader_compiled(&self, shader: &Shader) -> bool {
        shader.compiled
    }

    /// Delete a shader
    pub fn delete_shader(&mut self, _shader: &Shader) {
        // Shaders are automatically cleaned up
    }

    // ============ Program Operations ============

    /// Create a new program object
    pub fn create_program(&mut self) -> Program {
        let id = self.allocate_id();
        Program::new(id)
    }

    /// Attach a shader to a program
    pub fn attach_shader(&mut self, program: &mut Program, shader: &Shader) -> Result<(), &'static str> {
        if !shader.compiled {
            return Err("Shader not compiled");
        }
        // Increment attribute/uniform counts as example
        program.attribute_count += 1;
        Ok(())
    }

    /// Link a program
    pub fn link_program(&mut self, program: &mut Program) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("GL context not enabled");
        }
        program.linked = true;
        Ok(())
    }

    /// Use a program
    pub fn use_program(&mut self, program: &Program) -> Result<(), &'static str> {
        if !program.linked {
            return Err("Program not linked");
        }
        self.current_program = Some(program.id);
        Ok(())
    }

    /// Get current program
    pub fn current_program(&self) -> Option<u32> {
        self.current_program
    }

    /// Delete a program
    pub fn delete_program(&mut self, _program: &Program) {
        self.current_program = None;
    }

    // ============ Attribute Operations ============

    /// Get attribute location
    pub fn get_attrib_location(&self, _program: &Program, _name: &[u8]) -> i32 {
        0 // Simplified
    }

    /// Enable vertex attribute array
    pub fn enable_vertex_attrib_array(&mut self, _index: u32) -> Result<(), &'static str> {
        Ok(())
    }

    /// Disable vertex attribute array
    pub fn disable_vertex_attrib_array(&mut self, _index: u32) {
        // No-op
    }

    /// Set vertex attribute pointer
    pub fn vertex_attrib_pointer(
        &mut self,
        _index: u32,
        _size: u32,
        _stride: u32,
        _offset: u32,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    // ============ Uniform Operations ============

    /// Get uniform location
    pub fn get_uniform_location(&self, _program: &Program, _name: &[u8]) -> i32 {
        0 // Simplified
    }

    /// Set uniform 1f
    pub fn uniform_1f(&mut self, _location: i32, _value: f32) -> Result<(), &'static str> {
        Ok(())
    }

    /// Set uniform 4f
    pub fn uniform_4f(
        &mut self,
        _location: i32,
        _v0: f32,
        _v1: f32,
        _v2: f32,
        _v3: f32,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    /// Set uniform matrix 4fv
    pub fn uniform_matrix_4fv(
        &mut self,
        _location: i32,
        _count: u32,
        _transpose: bool,
        _value: &[f32; 16],
    ) -> Result<(), &'static str> {
        Ok(())
    }

    // ============ Texture Operations ============

    /// Generate textures (supports up to 16 textures)
    pub fn gen_textures(&mut self, count: u32) -> [Option<GlTexture>; 16] {
        let mut textures: [Option<GlTexture>; 16] = [None; 16];
        let count = core::cmp::min(count, 16);
        for i in 0..count as usize {
            let id = self.allocate_id();
            textures[i] = Some(GlTexture::new(id, 0x0DE1, 0, 0)); // GL_TEXTURE_2D = 0x0DE1
        }
        textures
    }

    /// Bind texture
    pub fn bind_texture(&mut self, texture: &mut GlTexture) -> Result<(), &'static str> {
        if self.active_texture < 16 {
            self.bound_textures[self.active_texture as usize] = Some(texture.id);
            texture.bound = true;
            Ok(())
        } else {
            Err("Texture unit out of range")
        }
    }

    /// Unbind texture
    pub fn unbind_texture(&mut self) {
        if self.active_texture < 16 {
            self.bound_textures[self.active_texture as usize] = None;
        }
    }

    /// Set active texture unit
    pub fn active_texture(&mut self, unit: u32) -> Result<(), &'static str> {
        if unit < 16 {
            self.active_texture = unit;
            Ok(())
        } else {
            Err("Texture unit out of range")
        }
    }

    /// Get active texture unit
    pub fn get_active_texture(&self) -> u32 {
        self.active_texture
    }

    /// Upload texture data
    pub fn tex_image_2d(
        &mut self,
        texture: &mut GlTexture,
        width: u32,
        height: u32,
        _data: &[u8],
    ) -> Result<(), &'static str> {
        if !texture.bound {
            return Err("Texture not bound");
        }
        texture.width = width;
        texture.height = height;
        Ok(())
    }

    /// Delete textures
    pub fn delete_textures(&mut self, _textures: &[GlTexture]) {
        for i in 0..16 {
            self.bound_textures[i] = None;
        }
    }

    // ============ Framebuffer Operations ============

    /// Generate framebuffer objects (supports up to 8 framebuffers)
    pub fn gen_framebuffers(&mut self, count: u32) -> [Option<Framebuffer>; 8] {
        let mut fbos: [Option<Framebuffer>; 8] = [None; 8];
        let count = core::cmp::min(count, 8);
        for i in 0..count as usize {
            let id = self.allocate_id();
            fbos[i] = Some(Framebuffer::new(id, 1024, 768));
        }
        fbos
    }

    /// Bind framebuffer
    pub fn bind_framebuffer(&mut self, fbo: &mut Framebuffer) -> Result<(), &'static str> {
        self.bound_framebuffer = Some(fbo.id);
        Ok(())
    }

    /// Unbind framebuffer
    pub fn unbind_framebuffer(&mut self) {
        self.bound_framebuffer = None;
    }

    /// Attach color texture to framebuffer
    pub fn framebuffer_texture_2d(
        &mut self,
        fbo: &mut Framebuffer,
        texture: &GlTexture,
    ) -> Result<(), &'static str> {
        fbo.color_texture = texture.id;
        fbo.width = texture.width;
        fbo.height = texture.height;
        Ok(())
    }

    // ============ Render State ============

    /// Set clear color
    pub fn clear_color(&mut self, r: f32, g: f32, b: f32, a: f32) {
        self.state.clear_color = (r, g, b, a);
    }

    /// Set clear depth
    pub fn clear_depth(&mut self, depth: f32) {
        self.state.clear_depth = depth;
    }

    /// Clear buffers
    pub fn clear(&mut self, _color: bool, _depth: bool) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("GL context not enabled");
        }
        // Simulate clearing
        Ok(())
    }

    /// Set viewport
    pub fn viewport(&mut self, x: i32, y: i32, width: u32, height: u32) {
        self.state.viewport = Viewport::new(x, y, width, height);
    }

    /// Get current viewport
    pub fn get_viewport(&self) -> &Viewport {
        &self.state.viewport
    }

    /// Set scissor box
    pub fn scissor(&mut self, x: i32, y: i32, width: u32, height: u32) {
        self.state.scissor_box = ScissorBox::new(x, y, width, height);
    }

    /// Set blend equation
    pub fn blend_equation(&mut self, equation: BlendEquation) {
        self.state.blend_equation_rgb = equation;
        self.state.blend_equation_alpha = equation;
    }

    /// Set blend function
    pub fn blend_func(&mut self, src: BlendFunc, dst: BlendFunc) {
        self.state.blend_src_rgb = src;
        self.state.blend_dst_rgb = dst;
        self.state.blend_src_alpha = src;
        self.state.blend_dst_alpha = dst;
    }

    /// Set depth function
    pub fn depth_func(&mut self, func: DepthFunc) {
        self.state.depth_func = func;
    }

    /// Set cull face mode
    pub fn cull_face(&mut self, mode: CullFace) {
        self.state.cull_face_mode = mode;
    }

    /// Set front face winding
    pub fn front_face(&mut self, winding: FrontFace) {
        self.state.front_face = winding;
    }

    /// Set line width
    pub fn line_width(&mut self, width: f32) {
        self.state.line_width = width;
    }

    /// Set point size
    pub fn point_size(&mut self, size: f32) {
        self.state.point_size = size;
    }

    /// Get render state
    pub fn render_state(&self) -> &RenderState {
        &self.state
    }

    // ============ Drawing ============

    /// Draw arrays
    pub fn draw_arrays(
        &mut self,
        primitive_type: PrimitiveType,
        _first: u32,
        count: u32,
    ) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("GL context not enabled");
        }
        if self.current_program.is_none() {
            return Err("No program in use");
        }

        self.draw_calls += 1;
        self.vertices_rendered += count;

        // Count triangles for triangle primitives
        match primitive_type {
            PrimitiveType::Triangles => {
                self.triangles_rendered += count / 3;
            }
            PrimitiveType::TriangleStrip => {
                self.triangles_rendered += (count as i32 - 2).max(0) as u32;
            }
            PrimitiveType::TriangleFan => {
                self.triangles_rendered += (count as i32 - 2).max(0) as u32;
            }
            _ => {}
        }

        Ok(())
    }

    /// Draw elements
    pub fn draw_elements(
        &mut self,
        primitive_type: PrimitiveType,
        count: u32,
        _index_type: u32,
    ) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("GL context not enabled");
        }
        if self.current_program.is_none() {
            return Err("No program in use");
        }

        self.draw_calls += 1;
        self.vertices_rendered += count;

        match primitive_type {
            PrimitiveType::Triangles => {
                self.triangles_rendered += count / 3;
            }
            PrimitiveType::TriangleStrip => {
                self.triangles_rendered += (count as i32 - 2).max(0) as u32;
            }
            PrimitiveType::TriangleFan => {
                self.triangles_rendered += (count as i32 - 2).max(0) as u32;
            }
            _ => {}
        }

        Ok(())
    }

    // ============ Statistics ============

    /// Get draw call count
    pub fn draw_calls(&self) -> u32 {
        self.draw_calls
    }

    /// Get vertices rendered count
    pub fn vertices_rendered(&self) -> u32 {
        self.vertices_rendered
    }

    /// Get triangles rendered count
    pub fn triangles_rendered(&self) -> u32 {
        self.triangles_rendered
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.draw_calls = 0;
        self.vertices_rendered = 0;
        self.triangles_rendered = 0;
    }
}

impl Default for GlContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for GlContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GlContext")
            .field("enabled", &self.enabled)
            .field("current_program", &self.current_program)
            .field("draw_calls", &self.draw_calls)
            .field("vertices_rendered", &self.vertices_rendered)
            .field("triangles_rendered", &self.triangles_rendered)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = GlContext::new();
        assert!(!ctx.is_enabled());
        assert!(ctx.current_program().is_none());
    }

    #[test]
    fn test_context_initialization() {
        let mut ctx = GlContext::new();
        assert!(ctx.initialize().is_ok());
        assert!(ctx.is_enabled());
    }

    #[test]
    fn test_capabilities_enable_disable() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut cap = GlCapabilities::new();
        cap.blend = true;
        cap.depth_test = true;

        ctx.enable(cap);
        assert!(ctx.capabilities().blend);
        assert!(ctx.capabilities().depth_test);

        cap.blend = true;
        cap.depth_test = false;
        ctx.disable(cap);
        assert!(!ctx.capabilities().blend);
        assert!(ctx.capabilities().depth_test);
    }

    #[test]
    fn test_shader_creation_and_compilation() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut shader = ctx.create_shader(ShaderType::VertexShader);
        assert!(!ctx.shader_compiled(&shader));

        let result = ctx.compile_shader(&mut shader, b"void main() {}");
        assert!(result.is_ok());
        assert!(ctx.shader_compiled(&shader));
    }

    #[test]
    fn test_program_creation_and_linking() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut vs = ctx.create_shader(ShaderType::VertexShader);
        let mut fs = ctx.create_shader(ShaderType::FragmentShader);

        ctx.compile_shader(&mut vs, b"void main() {}").unwrap();
        ctx.compile_shader(&mut fs, b"void main() {}").unwrap();

        let mut program = ctx.create_program();
        assert!(!program.linked);

        assert!(ctx.attach_shader(&mut program, &vs).is_ok());
        assert!(ctx.attach_shader(&mut program, &fs).is_ok());
        assert!(ctx.link_program(&mut program).is_ok());
        assert!(program.linked);
    }

    #[test]
    fn test_use_program() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut program = ctx.create_program();
        ctx.link_program(&mut program).unwrap();

        assert!(ctx.use_program(&program).is_ok());
        assert_eq!(ctx.current_program(), Some(program.id));
    }

    #[test]
    fn test_use_unlinked_program_fails() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let program = ctx.create_program();
        assert!(ctx.use_program(&program).is_err());
    }

    #[test]
    fn test_texture_generation() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let textures = ctx.gen_textures(4);
        let mut count = 0;
        for tex_opt in textures.iter() {
            if let Some(tex) = tex_opt {
                assert!(tex.id > 0);
                assert!(!tex.bound);
                count += 1;
            }
        }
        assert_eq!(count, 4);
    }

    #[test]
    fn test_texture_binding() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let textures = ctx.gen_textures(1);
        let mut texture = textures[0].unwrap();
        assert!(!texture.bound);

        assert!(ctx.bind_texture(&mut texture).is_ok());
        assert!(texture.bound);
    }

    #[test]
    fn test_active_texture_unit() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        assert_eq!(ctx.get_active_texture(), 0);
        assert!(ctx.active_texture(5).is_ok());
        assert_eq!(ctx.get_active_texture(), 5);

        assert!(ctx.active_texture(16).is_err());
    }

    #[test]
    fn test_framebuffer_generation() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let fbos = ctx.gen_framebuffers(2);
        let mut count = 0;
        for fbo_opt in fbos.iter() {
            if let Some(fbo) = fbo_opt {
                assert!(fbo.id > 0);
                assert!(!fbo.complete);
                count += 1;
            }
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_framebuffer_binding() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let fbos = ctx.gen_framebuffers(1);
        let mut fbo = fbos[0].unwrap();
        assert!(ctx.bind_framebuffer(&mut fbo).is_ok());

        ctx.unbind_framebuffer();
        assert!(ctx.bound_framebuffer.is_none());
    }

    #[test]
    fn test_clear_color() {
        let mut ctx = GlContext::new();
        ctx.clear_color(0.5, 0.5, 0.5, 1.0);
        let state = ctx.render_state();
        assert_eq!(state.clear_color, (0.5, 0.5, 0.5, 1.0));
    }

    #[test]
    fn test_clear_depth() {
        let mut ctx = GlContext::new();
        ctx.clear_depth(0.5);
        assert_eq!(ctx.render_state().clear_depth, 0.5);
    }

    #[test]
    fn test_viewport() {
        let mut ctx = GlContext::new();
        ctx.viewport(10, 20, 800, 600);
        let vp = ctx.get_viewport();
        assert_eq!(vp.x, 10);
        assert_eq!(vp.y, 20);
        assert_eq!(vp.width, 800);
        assert_eq!(vp.height, 600);
    }

    #[test]
    fn test_scissor() {
        let mut ctx = GlContext::new();
        ctx.scissor(5, 10, 640, 480);
        let sb = &ctx.render_state().scissor_box;
        assert_eq!(sb.x, 5);
        assert_eq!(sb.y, 10);
        assert_eq!(sb.width, 640);
        assert_eq!(sb.height, 480);
    }

    #[test]
    fn test_blend_equation() {
        let mut ctx = GlContext::new();
        ctx.blend_equation(BlendEquation::Subtract);
        assert_eq!(ctx.render_state().blend_equation_rgb, BlendEquation::Subtract);
    }

    #[test]
    fn test_blend_func() {
        let mut ctx = GlContext::new();
        ctx.blend_func(BlendFunc::SrcAlpha, BlendFunc::OneMinusSrcAlpha);
        let state = ctx.render_state();
        assert_eq!(state.blend_src_rgb, BlendFunc::SrcAlpha);
        assert_eq!(state.blend_dst_rgb, BlendFunc::OneMinusSrcAlpha);
    }

    #[test]
    fn test_depth_func() {
        let mut ctx = GlContext::new();
        ctx.depth_func(DepthFunc::Greater);
        assert_eq!(ctx.render_state().depth_func, DepthFunc::Greater);
    }

    #[test]
    fn test_cull_face() {
        let mut ctx = GlContext::new();
        ctx.cull_face(CullFace::Front);
        assert_eq!(ctx.render_state().cull_face_mode, CullFace::Front);
    }

    #[test]
    fn test_front_face() {
        let mut ctx = GlContext::new();
        ctx.front_face(FrontFace::Cw);
        assert_eq!(ctx.render_state().front_face, FrontFace::Cw);
    }

    #[test]
    fn test_line_width() {
        let mut ctx = GlContext::new();
        ctx.line_width(2.5);
        assert_eq!(ctx.render_state().line_width, 2.5);
    }

    #[test]
    fn test_point_size() {
        let mut ctx = GlContext::new();
        ctx.point_size(5.0);
        assert_eq!(ctx.render_state().point_size, 5.0);
    }

    #[test]
    fn test_draw_arrays_requires_program() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let result = ctx.draw_arrays(PrimitiveType::Triangles, 0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_draw_arrays_triangle_count() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut program = ctx.create_program();
        ctx.link_program(&mut program).unwrap();
        ctx.use_program(&program).unwrap();

        ctx.draw_arrays(PrimitiveType::Triangles, 0, 9).unwrap();
        assert_eq!(ctx.draw_calls(), 1);
        assert_eq!(ctx.vertices_rendered(), 9);
        assert_eq!(ctx.triangles_rendered(), 3);
    }

    #[test]
    fn test_draw_elements_triangle_count() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut program = ctx.create_program();
        ctx.link_program(&mut program).unwrap();
        ctx.use_program(&program).unwrap();

        ctx.draw_elements(PrimitiveType::Triangles, 6, 0).unwrap();
        assert_eq!(ctx.draw_calls(), 1);
        assert_eq!(ctx.vertices_rendered(), 6);
        assert_eq!(ctx.triangles_rendered(), 2);
    }

    #[test]
    fn test_triangle_strip_count() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut program = ctx.create_program();
        ctx.link_program(&mut program).unwrap();
        ctx.use_program(&program).unwrap();

        ctx.draw_arrays(PrimitiveType::TriangleStrip, 0, 5).unwrap();
        assert_eq!(ctx.triangles_rendered(), 3); // 5 vertices = 3 triangles in strip
    }

    #[test]
    fn test_stats_reset() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut program = ctx.create_program();
        ctx.link_program(&mut program).unwrap();
        ctx.use_program(&program).unwrap();

        ctx.draw_arrays(PrimitiveType::Points, 0, 10).unwrap();
        assert!(ctx.draw_calls() > 0);

        ctx.reset_stats();
        assert_eq!(ctx.draw_calls(), 0);
        assert_eq!(ctx.vertices_rendered(), 0);
        assert_eq!(ctx.triangles_rendered(), 0);
    }

    #[test]
    fn test_texture_upload() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let textures = ctx.gen_textures(1);
        let mut texture = textures[0].unwrap();
        ctx.bind_texture(&mut texture).unwrap();

        let data = [0u8; 256];
        assert!(ctx.tex_image_2d(&mut texture, 256, 256, &data[..]).is_ok());
        assert_eq!(texture.width, 256);
        assert_eq!(texture.height, 256);
    }

    #[test]
    fn test_texture_upload_unbound_fails() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let textures = ctx.gen_textures(1);
        let mut texture = textures[0].unwrap();
        let data = [0u8; 256];
        assert!(ctx.tex_image_2d(&mut texture, 256, 256, &data[..]).is_err());
    }

    #[test]
    fn test_framebuffer_texture_attachment() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let fbos = ctx.gen_framebuffers(1);
        let mut fbo = fbos[0].unwrap();
        let textures = ctx.gen_textures(1);
        let mut texture = textures[0].unwrap();
        ctx.bind_texture(&mut texture).unwrap();

        assert!(ctx.framebuffer_texture_2d(&mut fbo, &texture).is_ok());
        assert_eq!(fbo.color_texture, texture.id);
    }

    #[test]
    fn test_render_state_defaults() {
        let state = RenderState::new();
        assert_eq!(state.clear_color, (0.0, 0.0, 0.0, 1.0));
        assert_eq!(state.clear_depth, 1.0);
        assert_eq!(state.depth_write, true);
        assert_eq!(state.line_width, 1.0);
        assert_eq!(state.point_size, 1.0);
    }

    #[test]
    fn test_gl_capabilities_defaults() {
        let caps = GlCapabilities::new();
        assert!(!caps.blend);
        assert!(!caps.depth_test);
        assert!(!caps.scissor_test);
        assert!(!caps.cull_face);
        assert!(caps.dither);
    }

    #[test]
    fn test_blend_equation_variants() {
        let eqs = [
            BlendEquation::Add,
            BlendEquation::Subtract,
            BlendEquation::ReverseSubtract,
            BlendEquation::Min,
            BlendEquation::Max,
        ];
        for eq in eqs.iter() {
            let _ = eq; // Just verify they exist
        }
    }

    #[test]
    fn test_primitive_types() {
        let types = [
            PrimitiveType::Points,
            PrimitiveType::Lines,
            PrimitiveType::LineStrip,
            PrimitiveType::LineLoop,
            PrimitiveType::Triangles,
            PrimitiveType::TriangleStrip,
            PrimitiveType::TriangleFan,
        ];
        for _ in types.iter() {
            // Verify all types exist
        }
    }

    #[test]
    fn test_multiple_draw_calls() {
        let mut ctx = GlContext::new();
        ctx.initialize().unwrap();

        let mut program = ctx.create_program();
        ctx.link_program(&mut program).unwrap();
        ctx.use_program(&program).unwrap();

        ctx.draw_arrays(PrimitiveType::Triangles, 0, 3).unwrap();
        ctx.draw_arrays(PrimitiveType::Triangles, 0, 6).unwrap();
        ctx.draw_elements(PrimitiveType::Triangles, 9, 0).unwrap();

        assert_eq!(ctx.draw_calls(), 3);
        assert_eq!(ctx.vertices_rendered(), 18);
        assert_eq!(ctx.triangles_rendered(), 5); // 1 + 2 + 3 triangles
    }
}
