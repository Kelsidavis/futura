# Apple Silicon M2 Hardware Testing Guide

**Target Device**: MacBook Pro A2338 (M2)
**Status**: Ready for tethered boot testing (non-destructive)
**Last Updated**: 2025-11-05

---

## Overview

This guide explains how to test Futura OS on Apple Silicon M2 hardware using **tethered boot** - a completely non-destructive testing method that requires no installation, partitioning, or storage modification.

**Key Benefits**:
- ✅ No installation required
- ✅ No storage modification
- ✅ No partitioning or bootloader changes
- ✅ Runs entirely from RAM
- ✅ Completely reversible (just reboot to macOS)
- ✅ Safe for development and testing

---

## Prerequisites

### Hardware Requirements

1. **Target Device**: MacBook Pro A2338 (M2) - The device you want to test Futura on
2. **Host Device**: Any Mac (Intel or Apple Silicon) - Used to load the kernel
3. **USB-C to USB-C Cable**: For connecting the two Macs

### Software Requirements (on Host Mac)

1. **Python 3** (already installed on macOS):
   ```bash
   python3 --version  # Should be 3.8+
   ```

2. **m1n1 Python tools**:
   ```bash
   # Install m1n1 Python package
   pip3 install --user m1n1

   # Or clone from source
   git clone https://github.com/AsahiLinux/m1n1.git
   cd m1n1
   pip3 install --user -e .
   ```

3. **m1n1 bootloader binary**:
   ```bash
   # Download latest release
   curl -L https://github.com/AsahiLinux/m1n1/releases/latest/download/m1n1.macho -o m1n1.macho

   # Or build from source (requires Rust)
   cd m1n1
   make
   ```

4. **Futura kernel payload** (build on host or development machine):
   ```bash
   cd /path/to/futura
   make PLATFORM=arm64 m1n1-payload

   # Output: build/m1n1/Image.gz
   ```

---

## Tethered Boot Process

### Step 1: Prepare Target Mac (M2 MacBook Pro)

1. **Shut down the target Mac completely**:
   ```
   Apple menu → Shut Down
   Wait for complete power off
   ```

2. **Enter DFU (Device Firmware Update) mode**:

   **For M2 MacBook Pro**:
   - Press and hold the **Power button**
   - Keep holding until you see "Loading startup options"
   - **Continue holding** the power button (this is key!)
   - Screen will go black - keep holding
   - After ~10-15 seconds in DFU mode, you can release

   **Visual confirmation**:
   - Screen will be completely black
   - No Apple logo, no progress bar
   - Mac appears off but is in DFU mode

3. **Connect to host Mac**:
   - Use USB-C cable to connect target Mac to host Mac
   - Target Mac remains in DFU mode (black screen)

### Step 2: Load Kernel from Host Mac

On the **host Mac**, run m1n1 with Futura kernel:

```bash
# Method 1: Using m1n1 Python module
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho

# Method 2: Using m1n1.py script (if cloned from source)
./m1n1.py m1n1.macho -b build/m1n1/Image.gz kernel.macho

# With verbose output for debugging
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho -v
```

**What happens**:
1. m1n1 detects target Mac in DFU mode
2. Uploads m1n1 bootloader to target Mac
3. Uploads Futura kernel (Image.gz)
4. Boots Futura on target Mac

### Step 3: Monitor Console Output

**Option A: USB Serial Console** (Recommended)

Apple Silicon Macs expose UART over the same USB-C connection:

```bash
# Find the serial device (on host Mac)
ls /dev/cu.* | grep -i "debug\|serial"

# Common device names:
# /dev/cu.debug-console
# /dev/cu.usbmodemP_01

# Connect with screen
screen /dev/cu.debug-console 115200

# Or use minicom
minicom -D /dev/cu.debug-console -b 115200

# Or use pyserial
python3 -m serial.tools.miniterm /dev/cu.debug-console 115200
```

**Option B: m1n1 Hypervisor Console**

m1n1 can proxy console output:

```bash
# Run with console proxy
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho -s /dev/cu.debug-console
```

### Step 4: Expected Boot Output

You should see Futura boot messages:

```
Futura OS ARM64 Platform Initialization
========================================

[DTB] Device tree at 0x...
[DTB] Platform detected: Apple M2 (t8112)
[DTB] Compatible: apple,j493 (MacBook Pro 13" M2)
[DTB] Parsing hardware addresses...
[DTB]   UART base: 0x235200000
[DTB]   AIC base: 0x23B100000
[DTB]   ANS mailbox: 0x...
[DTB]   ANS NVMe: 0x...

[INIT] Initializing Apple AIC...
[AIC] Apple Interrupt Controller initialized
[AIC] IRQs: 896 max, IPIs enabled

[INIT] Initializing Apple UART...
[UART] Apple s5l-uart initialized (115200 baud)

[ANS2] Initializing Apple ANS2 NVMe controller...
[RTKit] Initializing RTKit co-processor IPC...
[RTKit] Sending HELLO (version 12)...
[RTKit] Received HELLO_REPLY (version 12)
[RTKit] Discovering endpoints (EPMAP)...
[RTKit] Starting system endpoints...
[RTKit] Power state: IOP → ON, AP → ON
[ANS2] RTKit co-processor ready
[ANS2] Registering endpoint 0x20...
[ANS2] NVMe controller capabilities: 0x...
[ANS2] Admin queue initialized (depth: 2)
[ANS2] I/O queue initialized (depth: 62)
[ANS2] Sending IDENTIFY controller command...
[ANS2] Model: APPLE SSD <model>
[ANS2] Serial: <serial>
[ANS2] Firmware: <version>
[ANS2] Namespace 1: <size> sectors

[INIT] Jumping to kernel main...
```

### Step 5: Interacting with Kernel

Once booted, you can interact via serial console:

- Type commands (if shell is loaded)
- Observe kernel messages
- Test drivers
- Trigger syscalls

### Step 6: Shutdown and Return to macOS

To exit Futura and return to macOS:

1. **Halt Futura** (if it has a shutdown command):
   ```
   (Futura shell) > shutdown
   ```

2. **Or force shutdown**:
   - Press and hold Power button on target Mac for 10 seconds
   - Mac will shut down completely

3. **Boot back to macOS**:
   - Press Power button normally
   - Mac boots to macOS as usual
   - **No changes made to storage**

---

## Troubleshooting

### Target Mac doesn't enter DFU mode

**Symptoms**: Screen shows Apple logo or startup options instead of going black

**Solution**:
- Make sure to **continue holding** the power button after "Loading startup options"
- Hold for 10-15 seconds total after screen goes black
- Try again - DFU timing can be tricky the first time

### m1n1 can't find target Mac

**Symptoms**: `No DFU devices found`

**Solution**:
```bash
# Check if target is in DFU mode
system_profiler SPUSBDataType | grep DFU

# Should show something like:
#   Apple Mobile Device (DFU Mode)

# If not found, re-enter DFU mode on target Mac
```

### No serial console output

**Symptoms**: Kernel boots but no console output

**Solution**:
1. **Check USB-C connection**: Must be the same cable used for DFU
2. **Find correct device**:
   ```bash
   ls /dev/cu.* | grep -i debug
   ```
3. **Try different terminal emulator**:
   ```bash
   # screen
   screen /dev/cu.debug-console 115200

   # minicom (may need: brew install minicom)
   minicom -D /dev/cu.debug-console

   # pyserial
   python3 -m serial.tools.miniterm /dev/cu.debug-console 115200
   ```

### Kernel panics or hangs

**Symptoms**: Boot stops or crashes

**Debugging**:
1. **Enable verbose m1n1**:
   ```bash
   python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho -v -v
   ```

2. **Check device tree**:
   ```bash
   # Extract device tree from m1n1
   python3 -m m1n1.run m1n1.macho --dump-fdt m2.dtb

   # Decompile to inspect
   dtc -I dtb -O dts m2.dtb > m2.dts
   less m2.dts
   ```

3. **Add debug output** to kernel:
   - Edit kernel code to add more `fut_printf()` calls
   - Rebuild: `make PLATFORM=arm64 m1n1-payload`
   - Re-test

### Device tree parsing fails

**Symptoms**: `[DTB] Warning: NVMe base address not configured`

**Debugging**:
```bash
# Check if device tree has expected nodes
dtc -I dtb -O dts m2.dtb | grep -A 10 "ans"
dtc -I dtb -O dts m2.dtb | grep -A 10 "mailbox"

# Compare compatible strings
dtc -I dtb -O dts m2.dtb | grep compatible | head -5
```

---

## Advanced Testing

### Custom Device Tree

If you need to modify the device tree:

```bash
# 1. Extract from m1n1
python3 -m m1n1.run m1n1.macho --dump-fdt m2.dtb

# 2. Decompile to source
dtc -I dtb -O dts m2.dtb > m2.dts

# 3. Edit m2.dts (add nodes, modify addresses, etc.)
nano m2.dts

# 4. Recompile
dtc -I dts -O dtb m2.dts > m2-custom.dtb

# 5. Boot with custom DTB
python3 -m m1n1.run m1n1.macho -b 'build/m1n1/Image.gz;m2-custom.dtb' kernel.macho
```

### Kernel Debugging

Enable debug output during build:

```bash
# Build with debug flags
make PLATFORM=arm64 CFLAGS+="-DDEBUG_DTB -DDEBUG_AIC -DDEBUG_ANS2" kernel

# Create payload
make m1n1-payload

# Boot with verbose output
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho -v
```

### Memory Inspection

m1n1 hypervisor mode allows memory inspection:

```bash
# Boot with hypervisor
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho --hv

# This gives you an m1n1 shell where you can:
# - Inspect memory: read64(0xaddress)
# - Set breakpoints
# - Single-step execution
# - Examine registers
```

---

## Testing Checklist

Use this checklist to systematically test Futura components:

### Phase 1: Boot Infrastructure

- [ ] **Device Tree Parsing**
  - [ ] Platform detected as Apple M2
  - [ ] Compatible string matches (apple,t8112 or apple,j493)
  - [ ] UART base address parsed correctly
  - [ ] AIC base address parsed correctly

- [ ] **Apple AIC (Interrupt Controller)**
  - [ ] AIC initializes without errors
  - [ ] Version register readable
  - [ ] WHOAMI returns valid CPU ID
  - [ ] All IRQs masked initially
  - [ ] IPI send/receive functional (if multi-core enabled)

- [ ] **Apple UART (Console)**
  - [ ] UART initializes at 115200 baud
  - [ ] TX/RX status registers accessible
  - [ ] Character output working (see boot messages)
  - [ ] FIFO enabled
  - [ ] Newline conversion (\n → \r\n) working

- [ ] **ARM Generic Timer**
  - [ ] Timer frequency detected (24 MHz)
  - [ ] Timer interrupts firing (if enabled)

### Phase 2: Storage Infrastructure

- [ ] **RTKit IPC**
  - [ ] Mailbox base address parsed from DT
  - [ ] TX/RX FIFO accessible
  - [ ] HELLO handshake successful
  - [ ] Version negotiation (v11 or v12)
  - [ ] EPMAP returns endpoint bitmap
  - [ ] System endpoints started (syslog, crashlog, debug, ioreport)
  - [ ] Power state transitions (IOP → ON, AP → ON)

- [ ] **ANS2 NVMe Driver**
  - [ ] NVMe base address parsed from DT
  - [ ] Controller capabilities readable
  - [ ] Admin queue allocation successful
  - [ ] I/O queue allocation successful
  - [ ] TCB array allocation successful
  - [ ] IDENTIFY controller command completes
  - [ ] IDENTIFY namespace command completes
  - [ ] Controller model/serial/firmware displayed
  - [ ] Namespace size reported

- [ ] **NVMe I/O Operations** (if implemented)
  - [ ] Read single sector
  - [ ] Write single sector
  - [ ] Verify data integrity
  - [ ] Multiple I/O operations

---

## Next Steps After Successful Boot

Once tethered boot is working:

1. **Validate all Phase 1 & 2 components** using checklist above

2. **Test edge cases**:
   - Multiple reboots
   - Different m1n1 versions
   - Various kernel configurations
   - Stress testing (if applicable)

3. **Performance measurements**:
   - Boot time from m1n1 → kernel main
   - RTKit handshake latency
   - NVMe command completion time
   - Interrupt latency

4. **Document findings**:
   - Update `docs/APPLE_SILICON_IMPLEMENTATION.md`
   - Record any hardware quirks discovered
   - Note differences from documentation

5. **Phase 3 preparation** (when ready):
   - Display Coprocessor (DCP) driver
   - Framebuffer setup
   - HID input devices

---

## Safety Notes

**Tethered boot is completely safe**, but keep in mind:

- ✅ **No risk to macOS**: macOS installation untouched
- ✅ **No storage writes**: Everything runs from RAM
- ✅ **No permanent changes**: Reboot returns to normal macOS
- ⚠️ **USB-C port stress**: Frequent DFU mode entry may wear port slightly
- ⚠️ **Power management**: Tethered boot may prevent sleep/battery optimization
- ⚠️ **Kernel bugs**: Buggy kernel could require hard reset (hold power 10s)

**Never attempt to**:
- Write to internal NVMe without explicit user data backup
- Modify bootloader without understanding consequences
- Install Futura permanently without testing tethered boot first

---

## Resources

- **m1n1 Documentation**: https://github.com/AsahiLinux/m1n1/wiki
- **m1n1 User Guide**: https://asahilinux.org/docs/sw/m1n1-user-guide/
- **Asahi Linux Discord**: https://discord.gg/asahi (for m1n1 support)
- **Futura Docs**: `docs/APPLE_SILICON_ROADMAP.md`, `docs/APPLE_SILICON_IMPLEMENTATION.md`

---

## Contact & Reporting

If you successfully test on hardware:

1. **Record full boot log**:
   ```bash
   python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho 2>&1 | tee futura-m2-boot.log
   ```

2. **Document hardware details**:
   - Exact Mac model (About This Mac)
   - macOS version
   - m1n1 version used
   - Any issues encountered

3. **Share results** in project documentation or issue tracker

---

**Happy Testing!** 🚀

Remember: Tethered boot is safe, non-destructive, and fully reversible. Perfect for development and testing.
