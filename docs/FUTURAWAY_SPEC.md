# FuturaWay Specification — Display & Compositor System
**Project:** Futura OS  
**Component:** FuturaWay (Wayland-Compatible Compositor)  
**Author:** Kelsi Davis  
**Date:** October 2025  
**License:** MPL 2.0  

---

> **Status (Jan 22 2026)**: Legacy design spec. The active Wayland compositor is `src/user/compositor/futura-wayland/`. `src/user/futurawayd/` is the legacy display server.

## 🪟 Overview
**FuturaWay** is the graphical subsystem and window compositor for Futura OS.  
It operates as a **user-space daemon (`futura-wayland`)** built on the FIPC protocol.  
FuturaWay is *Wayland-compatible* yet streamlined for Futura’s zero-copy, async event model.

---

## 🎯 Objectives
- Replace traditional X11/Quartz-style servers with an FIPC-based compositor.  
- Use shared memory surfaces instead of kernel framebuffers per window.  
- Support both software and GPU compositing via drivers.  
- Provide clean, futuristic UI dynamics inspired by macOS 14—without skeuomorphic clutter.

---

## ⚙️ Architecture
```
┌──────────────────────────────┐
│ Application / Client Process │
│ (FuturaUI Toolkit)           │
└───────────┬──────────────────┘
            │  FIPC Channel
┌──────────────────────────────┐
│ futurawayd (Compositor)      │
│  • Manages surfaces          │
│  • Handles input events      │
│  • Composites framebuffers   │
└───────────┬──────────────────┘
            │  FIPC Channel
┌──────────────────────────────┐
│ Kernel / FIPC Core           │
│  • Memory mgmt & signaling   │
└──────────────────────────────┘
```

---

## 🧩 Message Model
```c
typedef struct {
    uint16_t opcode;     // e.g., SURFACE_CREATE, SURFACE_UPDATE, INPUT_EVENT
    uint16_t object_id;  // Surface/window ID
    uint32_t length;     // Payload length
    uint8_t  payload[];  // Variable data
} fway_msg_t;
```

All messages are transmitted via FIPC channels.

---

## 🧱 Rendering Pipeline
1. Client allocates shared surface buffer via `FIPC_ALLOC_SURFACE`.  
2. Client renders pixel data directly into the mapped region.  
3. Sends `SURFACE_COMMIT` message to `futurawayd`.  
4. Compositor composites updated surfaces into final framebuffer.  
5. Input events flow back to clients via `INPUT_EVENT` messages.  

---

## 🖥️ Surface Management
| Action | Description |
|---------|-------------|
| **Create** | Allocate new surface with geometry + pixel format. |
| **Update** | Notify compositor that buffer changed. |
| **Destroy** | Release shared memory and detach surface. |
| **Focus** | Set active surface for input redirection. |

---

## 🪄 Visual Design Language
- **Clean Geometry:** flat layers, no skeuomorphism.  
- **Dynamic Depth:** shadows and translucency simulate hierarchy.  
- **Contrast-Driven Hierarchy:** UI elements defined by luminance separation.  
- **Scalable Metrics:** all dimensions are DPI-independent.  
- **Color-Agnostic Mode:** pure black-and-white schematic available for low-power displays.  

---

## 🧰 Components
| Component | Role |
|------------|------|
| `futura-wayland` | Main compositor daemon; controls display and input. |
| `futuraui` | Toolkit providing widgets, layout, and event dispatch (planned). |
| `fipc` | Underlying IPC channel layer for all communication. |
| `kernel/video` + `drivers/video` | Backend for framebuffer + GPU integration. |

---

## ⚡ Performance Model
- Asynchronous event dispatch through FIPC.  
- No kernel blocking or polling loops.  
- Shared-memory surfaces minimize context switches.  
- Render thread parallelized for multi-core compositing.  

---

## 🧭 Roadmap
| Milestone | Target |
|------------|--------|
| **M1** | Basic compositor (`futurawayd`) with one surface and keyboard input |
| **M2** | Multi-surface layering, window dragging, redraw scheduling |
| **M3** | GPU-accelerated compositing (Vulkan/OpenGL) |
| **M4** | Full FuturaUI toolkit integration |
| **M5** | Remote display via networked FIPC transport |

---

## 🧩 Relationship to Kernel
FuturaWay lives entirely in userland.  
The kernel only manages:
- Framebuffer or GPU memory mapping  
- FIPC shared memory and event signaling  

This separation enforces modularity and crash isolation.

---

## 🪶 Summary
FuturaWay defines the future of graphical compositors:
- Event-driven, zero-copy, cross-architecture  
- Minimal kernel coupling  
- Modern, futuristic UI principles  
- Wayland-compatible transport  

Together with FIPC, it establishes a **next-generation, message-oriented OS display model**.
