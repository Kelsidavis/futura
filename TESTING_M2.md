# Testing Futura OS on Apple Silicon M2

**Quick Start Guide for Non-Destructive Hardware Testing**

---

## ⚡ TL;DR - Quick Start

```bash
# 1. Download m1n1 bootloader
curl -L https://github.com/AsahiLinux/m1n1/releases/latest/download/m1n1.macho -o m1n1.macho

# 2. Install m1n1 Python tools
pip3 install --user m1n1

# 3. Build Futura kernel
make PLATFORM=arm64 m1n1-payload

# 4. Put MacBook Pro M2 in DFU mode (see below)

# 5. Run automated test script
./scripts/test-on-m2.sh --console
```

**Result**: Futura boots on your M2 Mac with **zero installation** - everything runs from RAM!

---

## 🔒 Safety Guarantees

**Tethered boot is 100% safe and reversible:**

- ✅ **No installation** - Nothing written to disk
- ✅ **No partitioning** - Storage untouched
- ✅ **No bootloader changes** - macOS boot unaffected
- ✅ **Runs from RAM** - Temporary execution only
- ✅ **Fully reversible** - Simple reboot returns to macOS
- ✅ **Non-destructive** - Zero risk to existing data

**To return to macOS**: Just press Power button for 10 seconds, then boot normally.

---

## 📋 Prerequisites

### Hardware
- MacBook Pro A2338 (M2) - Target device
- Any Mac (host) - To load the kernel
- USB-C to USB-C cable

### Software (on host Mac)
```bash
# Check Python version (should be 3.8+)
python3 --version

# Install m1n1 tools
pip3 install --user m1n1

# Download m1n1 bootloader
curl -L https://github.com/AsahiLinux/m1n1/releases/latest/download/m1n1.macho -o m1n1.macho
```

---

## 🚀 Entering DFU Mode

**DFU Mode** (Device Firmware Update) allows loading code over USB without booting macOS.

### Steps for MacBook Pro M2:

1. **Shut down** the MacBook Pro completely
2. **Press and hold** the Power button
3. Keep holding until you see **"Loading startup options"**
4. **⚠️ KEEP HOLDING** - Don't release yet!
5. Screen will go **black** - still keep holding
6. After **10-15 seconds**, release the button
7. **Connect USB-C cable** to host Mac

**Visual confirmation**: Screen is completely black, no Apple logo, Mac appears off.

**Verification** (on host Mac):
```bash
system_profiler SPUSBDataType | grep DFU
# Should show: "Apple Mobile Device (DFU Mode)"
```

---

## 🧪 Testing Methods

### Method 1: Automated Script (Recommended)

```bash
# Quick test with auto-build
./scripts/test-on-m2.sh --build --console

# Test existing build
./scripts/test-on-m2.sh --console

# Verbose output for debugging
./scripts/test-on-m2.sh --verbose --console
```

### Method 2: Manual Testing

```bash
# Build kernel
make PLATFORM=arm64 m1n1-payload

# Boot on M2 (target in DFU mode)
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho

# Connect to console (separate terminal)
screen /dev/cu.debug-console 115200
```

---

## 📊 Expected Output

When successful, you'll see:

```
Futura OS ARM64 Platform Initialization
========================================

[DTB] Device tree at 0x...
[DTB] Platform detected: Apple M2 (t8112)
[DTB] Compatible: apple,j493 (MacBook Pro 13" M2)

[INIT] Initializing Apple AIC...
[AIC] Apple Interrupt Controller initialized

[INIT] Initializing Apple UART...
[UART] Apple s5l-uart initialized (115200 baud)

[ANS2] Initializing Apple ANS2 NVMe controller...
[RTKit] Initializing RTKit co-processor IPC...
[RTKit] HELLO handshake successful (version 12)
[RTKit] Co-processor ready
[ANS2] NVMe controller initialized
[ANS2] Model: APPLE SSD <model>

[INIT] Jumping to kernel main...
```

---

## 🔍 Troubleshooting

### Can't enter DFU mode
- Make sure to **keep holding** Power button after "Loading startup options"
- Hold for full 10-15 seconds after screen goes black
- Timing can be tricky - try again

### m1n1 can't find target
```bash
# Verify DFU mode
system_profiler SPUSBDataType | grep DFU

# If not found, re-enter DFU mode
```

### No console output
```bash
# Find console device
ls /dev/cu.* | grep -i debug

# Try different terminal
screen /dev/cu.debug-console 115200
# OR
minicom -D /dev/cu.debug-console -b 115200
# OR
python3 -m serial.tools.miniterm /dev/cu.debug-console 115200
```

### Kernel hangs or crashes
```bash
# Enable verbose output
./scripts/test-on-m2.sh --build --verbose

# Extract device tree for inspection
python3 -m m1n1.run m1n1.macho --dump-fdt m2.dtb
dtc -I dtb -O dts m2.dtb > m2.dts
less m2.dts
```

---

## 📖 Detailed Documentation

For comprehensive information, see:

- **`docs/APPLE_SILICON_TESTING.md`** - Complete testing guide
- **`docs/APPLE_SILICON_ROADMAP.md`** - Implementation roadmap
- **`docs/APPLE_SILICON_IMPLEMENTATION.md`** - Technical details
- **`build/m1n1/README.txt`** - m1n1 payload usage

---

## ✅ Testing Checklist

Quick validation after successful boot:

- [ ] Platform detected as Apple M2
- [ ] UART console shows boot messages
- [ ] AIC interrupt controller initialized
- [ ] RTKit handshake successful
- [ ] NVMe controller detected
- [ ] Device model/serial displayed

See `docs/APPLE_SILICON_TESTING.md` for full checklist.

---

## 🛑 Returning to macOS

When done testing:

1. **Shutdown Futura** (if shutdown command available)
2. **Or force power off**: Hold Power button for 10 seconds
3. **Boot macOS normally**: Press Power button

**No changes made to your Mac** - everything was in RAM!

---

## 🤝 Reporting Results

If you test on real hardware:

```bash
# Capture full boot log
./scripts/test-on-m2.sh --verbose 2>&1 | tee m2-test-$(date +%Y%m%d).log

# Document in logs:
# - Mac model (About This Mac)
# - macOS version
# - m1n1 version
# - Any issues encountered
```

Share results in project documentation or issue tracker!

---

## 🎯 What Works (Phases 1 & 2 Complete)

✅ Boot infrastructure:
- Device tree platform detection (M1/M2/M3)
- Apple AIC interrupt controller
- Apple UART console (115200 baud)
- m1n1 payload format (ARM64 Linux image)

✅ Storage infrastructure:
- RTKit IPC mailbox protocol
- ANS2 NVMe driver with TCB programming
- Device tree hardware address parsing
- Co-processor communication

🚧 Coming next (Phase 3):
- Display Coprocessor (DCP) driver
- HID input devices (keyboard/trackpad)

---

**Ready to test? Get started with:**

```bash
./scripts/test-on-m2.sh --help
```

**Questions?** See `docs/APPLE_SILICON_TESTING.md` for the complete guide.

---

**Happy testing!** 🚀 Remember: Tethered boot is safe and reversible.
