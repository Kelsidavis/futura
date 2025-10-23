# Framebuffer Console Integration Guide

## Quick Start for Developers

### Adding Framebuffer Console Output to Your Code

#### 1. Include the Header
```c
#include <kernel/fb_console.h>
```

#### 2. Initialize in Your Boot/Platform Code
```c
/* In platform initialization, after framebuffer discovery: */
int rc = fb_console_init();
if (rc == 0) {
    fb_console_write("Framebuffer console initialized\n", 33);
} else {
    fut_printf("Framebuffer initialization failed, using serial\n");
}
```

#### 3. Use for Output
```c
/* Basic character output */
fb_console_putc('A');
fb_console_putc('\n');

/* Write strings */
fb_console_write("Hello, display!\n", 16);

/* Position-specific output (for custom layouts) */
fb_console_putc_at(0, 0, '*');      /* Draw * at top-left */
fb_console_putc_at(127, 95, '*');   /* Draw * at bottom-right */
```

## Integration Points for ARM64

### Option 1: Initialize in Platform Code (Recommended)

Edit `/home/k/futura/platform/arm64/platform_init.c`:

```c
void fut_platform_init(void) {
    // ... existing initialization ...

    fut_serial_init();
    fut_printf("[BOOT] Serial console initialized\n");

    // NEW: Initialize framebuffer console
    if (fb_console_init() == 0) {
        fb_console_write("[BOOT] Framebuffer console ready\n", 34);
        // Optional: Now use fb_console for output instead of serial
    }

    // ... rest of initialization ...
}
```

### Option 2: Early Boot Diagnostics

For debugging early boot issues before main `platform_init()`:

```c
void fut_platform_early_init(void) {
    // Very early - only serial is available
    fut_serial_init();
    fut_printf("[EARLY] Serial initialized\n");
}
```

### Option 3: Conditional Compilation

```c
#if defined(CONFIG_FB_CONSOLE)
    if (fb_console_init() == 0) {
        fb_console_write("FB console enabled\n", 19);
    }
#else
    fut_printf("FB console disabled at compile time\n");
#endif
```

## Dual Console Output (Serial + Display)

### Strategy 1: Fallback Console
```c
/* Try framebuffer first, fallback to serial */
static int use_fb_console = 0;

if (fb_console_init() == 0) {
    use_fb_console = 1;
} else {
    fut_printf("No framebuffer, using serial only\n");
}

/* Later when logging */
void log_message(const char *msg) {
    if (use_fb_console) {
        fb_console_write(msg, strlen(msg));
    } else {
        fut_printf("%s", msg);
    }
}
```

### Strategy 2: Redundant Output (Both)
```c
void debug_output(const char *fmt, ...) {
    va_list args;
    char buffer[256];

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    /* Write to both output devices */
    fut_printf("%s", buffer);              /* Serial */
    fb_console_write(buffer, strlen(buffer)); /* Display */
}
```

## Testing Your Integration

### Test 1: Simple Output
```bash
make PLATFORM=arm64 -j4 kernel
bash /tmp/test_arm64_qemu.sh

# Expected: If fb_console_init() was called successfully,
# you should see white text on black background in QEMU window
```

### Test 2: Verify Initialization
```c
void test_fb_console(void) {
    int cols, rows;
    fb_console_get_dimensions(&cols, &rows);

    if (cols == 0) {
        fut_printf("ERROR: FB console not initialized\n");
        return;
    }

    fut_printf("FB Console: %d cols x %d rows\n", cols, rows);
    fb_console_write("Test string on display\n", 23);
}
```

### Test 3: Advanced Features
```c
void test_advanced(void) {
    /* Clear and fill screen */
    fb_console_clear();

    /* Write a pattern */
    for (int i = 0; i < 10; i++) {
        fb_console_putc('A' + (i % 26));
    }
    fb_console_putc('\n');

    /* Test position-specific output */
    fb_console_putc_at(64, 48, '@');  /* Center screen */

    /* Test scrolling */
    for (int i = 0; i < 100; i++) {
        fb_console_write("Line\n", 5);
    }
}
```

## Customization

### Change Text Color

Edit `/home/k/futura/drivers/video/fb_console.c`, in `fb_console_putc()`:

```c
void fb_console_putc(char c) {
    struct fb_console_state *cons = &g_fb_console;

    if (!cons->initialized) {
        return;
    }

    /* CHANGE THESE COLORS */
    uint32_t fg_color = make_color(255, 255, 0, 255);   // Yellow text
    uint32_t bg_color = make_color(0, 0, 128, 255);     // Dark blue background

    /* ... rest of function ... */
}
```

Color format: `make_color(R, G, B, A)` where each is 0-255

### Change Font Size

To use larger characters, modify in `fb_console_init()`:

```c
cons->char_width = 16;   /* Change from 8 */
cons->char_height = 16;  /* Change from 8 */
cons->cols = cons->width / cons->char_width;
cons->rows = cons->height / cons->char_height;
```

**Note**: You'll also need to create or upscale the font glyphs.

### Custom Font

Replace `g_font_8x8` with your own bitmap font:

```c
static const uint8_t g_font_custom[NUM_CHARS][CHAR_HEIGHT] = {
    // Your glyph data here
};

/* Then update fb_console_draw_char() to use it */
const uint8_t *glyph = g_font_custom[c - START_CHAR];
```

## Performance Tuning

### Profile Before/After

```c
/* In platform_init.c */
uint64_t start = get_ticks();

fb_console_init();
for (int i = 0; i < 100; i++) {
    fb_console_write("Performance test\n", 17);
}

uint64_t end = get_ticks();
fut_printf("FB console: %llu ticks for 100 writes\n", end - start);
```

### Optimization Ideas

1. **Back-buffer** - Draw to memory first, update display periodically
2. **Dirty tracking** - Only update changed regions
3. **Character caching** - Pre-render glyphs, store in scratch memory
4. **Async updates** - Schedule redraws instead of immediate writes

## Troubleshooting Integration

### Problem: "Undefined reference to fb_console_init"

**Cause**: fb_console.c not being compiled

**Solution**:
```bash
# Verify it's in Makefile
grep "drivers/video/fb_console.c" Makefile

# Rebuild
make clean PLATFORM=arm64
make PLATFORM=arm64 -j4 kernel
```

### Problem: Framebuffer console doesn't initialize

**Diagnosis**:
```c
int rc = fb_console_init();
fut_printf("fb_console_init() returned: %d\n", rc);
// -1 means no framebuffer discovered
```

**Solutions**:
1. Verify bootloader/QEMU provides framebuffer
2. Check `fb_probe_from_multiboot()` in `kernel/video/fb_mmio.c`
3. Add debug output to framebuffer discovery
4. Fallback to serial console for boot debugging

### Problem: Rendering is very slow

**Causes**:
1. Scroll operation copying full framebuffer
2. Concurrent framebuffer access from multiple CPUs
3. Memory bandwidth issues

**Solutions**:
1. Profile with `rdtsc` / ARM timer
2. Optimize scroll operation (copy only changed lines)
3. Add locking if multi-threaded access
4. Consider DMA acceleration (future)

## Building with FB Console

### Clean Build
```bash
cd /home/k/futura
make clean PLATFORM=arm64
make PLATFORM=arm64 -j4 kernel
```

### Verify Build
```bash
file build/bin/futura_kernel.elf
# Should show: ELF 64-bit LSB executable, ARM aarch64, version 1

# Check for fb_console symbols
aarch64-linux-gnu-objdump -t build/bin/futura_kernel.elf | grep fb_console
```

### Size Impact
```bash
# Compare with/without fb_console in build
ls -lh build/bin/futura_kernel.elf
# Typical: +4KB overhead (mostly font data)
```

## Next Steps

1. **Try the implementation**: Build and run QEMU test
2. **Integrate into platform code**: Add `fb_console_init()` call
3. **Test on hardware**: Deploy to Raspberry Pi 5
4. **Customize colors/font**: Make it your own
5. **Add advanced features**: ANSI codes, scrollback, etc.

## Advanced: Replacing Serial Console

If you want framebuffer as primary console:

```c
/* Wrapper that uses framebuffer instead of serial */
void console_write_wrapper(const char *buf, size_t len) {
    if (g_fb_console.initialized) {
        fb_console_write(buf, len);
    } else {
        /* Fallback to serial */
        for (size_t i = 0; i < len; i++) {
            fut_serial_putc(buf[i]);
        }
    }
}

/* Then redirect all printf output through this wrapper */
```

## References

- **Implementation**: `/home/k/futura/drivers/video/fb_console.c`
- **API**: `/home/k/futura/include/kernel/fb_console.h`
- **Documentation**: `/home/k/futura/FB_CONSOLE_README.md` (this file)
- **Framebuffer**: `/home/k/futura/kernel/video/fb_mmio.c`
- **ARM64 Platform**: `/home/k/futura/platform/arm64/platform_init.c`

---

**Version**: 1.0
**Updated**: October 23, 2025
