# Wayland Compositor - Quick Test Reference

**TL;DR Version of WAYLAND_TESTING_GUIDE.md**

---

## 🚀 Run Test (30 seconds)

```bash
cd /home/k/futura
./build/bin/user/futura-wayland
```

---

## 👁️ What to Look For (60 seconds)

| Item | What You're Looking For | Meaning |
|------|------------------------|---------|
| **Display** | 4 colored quadrants | ✅ Demo mode working |
| **Display** | Just green | ❌ Scheduler still interfering |
| **Display** | Nothing | ❌ Framebuffer issue |
| **Console** | `[WRAP_SOCKET]` messages | ✅ Wrappers invoked |
| **Console** | `[WAYLAND-DEBUG]` messages | ✅ Diagnostics working |
| **Console** | `FAILED: <ERROR>` | ✅ Found the root cause |
| **Console** | `errno=13` or `errno=48` etc. | ✅ Exact error identified |

---

## 📊 Quick Analysis (2 minutes)

### Look for this line:
```
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
```

### What the errno means:

| errno | Name | Problem |
|-------|------|---------|
| 13 | EACCES | Permission denied (/tmp not writable) |
| 48 | EADDRINUSE | Socket file already exists |
| 22 | EINVAL | Wrong parameters to syscall |
| 2 | ENOENT | /tmp directory doesn't exist |
| 1 | EPERM | No permission for operation |

---

## ✅ Good Signs

```
[WAYLAND-DEBUG] Test file created successfully
  → /tmp is writable ✓

[WRAP_SOCKET] socket(1, 1, 0)
  → Wrapper is being called ✓

[WRAP_BIND] bind(fd=3, ...)
  → Socket creation got past socket() ✓

[WAYLAND] Demo mode: socket creation failed
  → Demo mode activated properly ✓

Display shows 4 colors (red, green, blue, yellow)
  → Rendering works perfectly ✓
```

---

## 🚨 Bad Signs

```
[WRAP_SOCKET] FAILED: EACCES (errno=13)
  → Permission issue - check /tmp permissions

No [WRAP_SOCKET] messages at all
  → Wrappers not being invoked - linker wrapping issue

[WAYLAND-DEBUG] WARNING: Could not create test file
  → /tmp not writable - permission problem

Display still shows just green
  → Scheduler not stopping - still interfering

No console output at all
  → Stdio initialization problem
```

---

## 💾 Capture Output

```bash
# Save output to file for analysis
./build/bin/user/futura-wayland | tee test_output.log

# Then search it:
grep "FAILED:" test_output.log
grep "errno=" test_output.log
grep "WRAP_SOCKET" test_output.log
```

---

## 🎯 Most Important Info

When socket creation fails, you'll see:
```
[WRAP_SOCKET] FAILED: <ERROR_NAME> (errno=<NUMBER>)
```

This one line tells you everything:
- **errno=13** → Fix /tmp permissions
- **errno=48** → Clean up old socket files
- **errno=22** → Fix syscall parameters
- **errno=2** → Create /tmp directory
- **errno=1** → Check privileges

---

## 📋 Quick Checklist

- [ ] System boots
- [ ] Compositor starts
- [ ] Display shows something
- [ ] Can see console output
- [ ] Found errno value
- [ ] Know what error means
- [ ] Ready to implement fix

---

## 🔗 Full Guides

- Want details? → Read **WAYLAND_TESTING_GUIDE.md**
- Want context? → Read **WAYLAND_SESSION_MASTER_SUMMARY.md**
- Want technical? → Read **WAYLAND_SESSION_2_SUMMARY.md**
- Quick answers? → This document or **WAYLAND_QUICK_REFERENCE.txt**

---

## ⏭️ If Socket Works

If you see:
```
[WRAP_SOCKET] SUCCESS: fd=3
[WRAP_BIND] SUCCESS
[WRAP_LISTEN] SUCCESS
[WAYLAND] SUCCESS: auto socket created: wayland-0
```

Then socket creation succeeded! Display will show compositor (not demo pattern).

Next: Try connecting clients.

---

## ⏭️ Once You Know the Error

1. Note the errno number
2. Look up meaning in table above
3. Create targeted fix
4. Test again
5. Update documentation

---

**That's it! Go run it and find the errno.**
