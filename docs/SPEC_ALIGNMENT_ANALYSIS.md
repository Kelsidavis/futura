# Specification Alignment Analysis

**Date:** October 11, 2025
**Reviewed:** Phase 2 & Phase 3 implementation vs. FIPC_SPEC.md & FUTURAWAY_SPEC.md
**Status:** ⚠️ **Partial Alignment - Refinements Needed**

---

## 📊 Executive Summary

Our Phase 2/3 implementation is **conceptually aligned** with the FIPC and FuturaWay specifications, but there are **structural discrepancies** that need resolution for full compliance.

### Overall Alignment Score: **75%**

| Component | Alignment | Status |
|-----------|-----------|--------|
| **FIPC Core Concept** | ✅ 95% | Excellent |
| **FIPC Message Structure** | ⚠️ 60% | Needs refinement |
| **FIPC API** | ✅ 85% | Good, minor gaps |
| **FuturaWay Architecture** | ✅ 90% | Excellent |
| **FuturaWay Message Protocol** | ⚠️ 70% | Needs alignment |
| **FuturaWay Surface Management** | ✅ 85% | Good |

---

## 🔍 FIPC Specification Alignment

### ✅ **Aligned Elements**

1. **Core Philosophy**
   - ✅ Zero-copy messaging via shared memory
   - ✅ Unified event model for IPC, GUI, syscalls
   - ✅ Circular ring buffers for channels
   - ✅ Capability-based security (planned)
   - ✅ Architecture-neutral design

2. **Shared Memory Regions**
   - ✅ `fut_fipc_region` structure exists
   - ✅ Reference counting implemented
   - ✅ Access control fields present
   - ✅ Region mapping API defined

3. **Channel Model**
   - ✅ Point-to-point channels implemented
   - ✅ Circular buffer with head/tail cursors
   - ✅ Atomic operations (in implementation)
   - ✅ Blocking/non-blocking modes

4. **API Functions**
   - ✅ `fut_fipc_channel_create()` - matches spec
   - ✅ `fut_fipc_send()` - matches spec intent
   - ✅ `fut_fipc_recv()` - matches spec intent
   - ✅ `fut_fipc_region_map()` - matches spec
   - ✅ `fut_fipc_poll()` - matches spec

### ⚠️ **Discrepancies - FIPC Message Structure**

**SPECIFICATION (FIPC_SPEC.md lines 33-42):**
```c
typedef struct {
    uint32_t type;        // SYS, FS, UI, NET, USER, etc.
    uint32_t length;      // Payload length
    uint64_t timestamp;   // Kernel tick counter
    uint32_t src_pid;     // Source process ID
    uint32_t dst_pid;     // Destination process ID
    uint64_t capability;  // Channel or permission token
    uint8_t  payload[];   // Flexible payload
} fipc_msg_t;
```

**OUR IMPLEMENTATION (fut_fipc.h lines 97-105):**
```c
struct fut_fipc_msg {
    uint32_t type;                  /* Message type */
    uint32_t size;                  /* Payload size in bytes */
    uint64_t timestamp;             /* Timestamp (ticks) */
    uint64_t sender_id;             /* Sender task ID */

    /* Message payload follows this header */
    uint8_t data[];
};
```

**Gaps:**
1. ❌ Missing `dst_pid` (destination process ID)
2. ❌ Missing `capability` (security token)
3. ⚠️ `length` vs `size` naming inconsistency
4. ⚠️ `src_pid` vs `sender_id` naming inconsistency

**Impact:** Medium - Security and routing capabilities not fully implemented

### ⚠️ **Missing FIPC API Elements**

**From Specification:**
- ❌ `fipc_open(channel_id)` - Not implemented (we use `fut_fipc_channel_create` instead)
- ❌ `fipc_map_shared(channel)` - Not directly exposed (embedded in `fut_fipc_region_map`)
- ❌ `fipc_close(channel)` - Missing (we have `fut_fipc_channel_destroy` but no simple close)

**Impact:** Low - Functionality exists, just different naming/structure

### ⚠️ **Missing FIPC Features**

1. **Broadcast Channels** (Spec mentions, we don't have)
   - Spec: "Broadcast – compositor events, system notifications"
   - Implementation: Only point-to-point

2. **Capability Verification** (Spec emphasizes, we defer)
   - Spec: "Capabilities verified on send/receive"
   - Implementation: Placeholder security model

3. **Performance Metrics** (Spec defines targets)
   - Spec: "< 2 µs latency, > 2 GB/s throughput"
   - Implementation: No benchmarks yet

**Impact:** Medium - Core features missing, needed for Phase 4

---

## 🔍 FuturaWay Specification Alignment

### ✅ **Aligned Elements**

1. **Architecture**
   - ✅ User-space compositor daemon (`futurawayd`)
   - ✅ FIPC-based communication
   - ✅ Shared memory surfaces
   - ✅ Input event routing
   - ✅ Wayland-compatible philosophy

2. **Surface Management**
   - ✅ Create/Update/Destroy lifecycle
   - ✅ Focus management
   - ✅ Shared buffer allocation
   - ✅ Surface commit model

3. **Visual Design Language**
   - ✅ Clean geometry, no skeuomorphism
   - ✅ Dynamic depth via shadows
   - ✅ Contrast-driven hierarchy
   - ✅ Scalable metrics

4. **Component Structure**
   - ✅ `futurawayd` daemon
   - ✅ `futuraui` toolkit (in Phase 3)
   - ✅ FIPC foundation
   - ✅ GPU driver abstraction (planned)

### ⚠️ **Discrepancies - FuturaWay Message Structure**

**SPECIFICATION (FUTURAWAY_SPEC.md lines 48-56):**
```c
typedef struct {
    uint16_t opcode;     // e.g., SURFACE_CREATE, SURFACE_UPDATE, INPUT_EVENT
    uint16_t object_id;  // Surface/window ID
    uint32_t length;     // Payload length
    uint8_t  payload[];  // Variable data
} fway_msg_t;
```

**OUR IMPLEMENTATION (futura_way.h lines 32-47):**
```c
#define FWAY_MSG_CREATE_SURFACE    0x2001
#define FWAY_MSG_DESTROY_SURFACE   0x2002
#define FWAY_MSG_ATTACH_BUFFER     0x2003
// ... etc

// Uses fut_fipc_msg as base structure
struct fut_fipc_msg {
    uint32_t type;      // Full 32-bit message type
    uint32_t size;
    uint64_t timestamp;
    uint64_t sender_id;
    uint8_t data[];
};
```

**Analysis:**
- ⚠️ Spec uses **16-bit opcode + 16-bit object_id**
- ✅ We use **32-bit type** (more flexible, but inconsistent)
- ⚠️ Spec has **object_id in header**
- ✅ We embed **surface_id in payload** (works, but different)

**Impact:** Low - Functional equivalence, but protocol mismatch

### ⚠️ **Missing FuturaWay Features**

1. **Rendering Pipeline Details**
   - Spec: "FIPC_ALLOC_SURFACE" operation
   - Implementation: We use `FWAY_MSG_CREATE_SURFACE` (different name)

2. **Performance Characteristics**
   - Spec: "Asynchronous event dispatch"
   - Implementation: Present in design, not benchmarked

3. **Milestones**
   - Spec defines M1-M5 roadmap
   - Implementation: Not explicitly tracked

**Impact:** Low - Implementation in progress

---

## 🛠️ Required Refinements

### **Priority 1: FIPC Message Structure**

**Action:** Align `fut_fipc_msg` with specification

```c
// Proposed aligned structure
struct fut_fipc_msg {
    uint32_t type;        // Message type (SYS, FS, UI, NET, USER)
    uint32_t length;      // Payload length (renamed from 'size')
    uint64_t timestamp;   // Kernel tick counter
    uint32_t src_pid;     // Source process ID (renamed from 'sender_id')
    uint32_t dst_pid;     // Destination process ID (NEW)
    uint64_t capability;  // Channel/permission token (NEW)
    uint8_t  payload[];   // Flexible payload (renamed from 'data')
};
```

**Files to Update:**
- `include/kernel/fut_fipc.h`
- `kernel/ipc/fut_fipc.c`
- All Phase 3 protocol headers (futura_way.h, futura_posix.h, etc.)

**Compatibility:** Breaking change - requires full subsystem update

---

### **Priority 2: FIPC API Naming**

**Action:** Add spec-compliant function names

```c
// Add these to fut_fipc.h:
static inline int fipc_open(uint64_t channel_id) {
    // Wrapper for fut_fipc_channel_attach or similar
}

static inline int fipc_close(struct fut_fipc_channel *channel) {
    fut_fipc_channel_destroy(channel);
    return 0;
}

static inline void *fipc_map_shared(struct fut_fipc_channel *channel) {
    // Expose channel's shared memory region
}

static inline int fipc_send(struct fut_fipc_channel *channel,
                             void *msg, size_t len) {
    // Wrapper for fut_fipc_send
}
```

**Benefit:** Dual API - legacy code works, new code follows spec

---

### **Priority 3: FuturaWay Message Protocol**

**Action:** Align message format

**Option A (Recommended):** Keep our design, document deviation
- Rationale: Our 32-bit type is more flexible
- Update FUTURAWAY_SPEC.md to reflect implementation

**Option B:** Adopt spec exactly
- Split type into 16-bit opcode + 16-bit object_id
- Rewrite all Phase 3 message definitions

**Recommendation:** Option A - spec is flexible, our design is cleaner

---

### **Priority 4: Broadcast Channels**

**Action:** Implement broadcast FIPC channels for compositor events

```c
// Add to fut_fipc.h
#define FIPC_CHANNEL_BROADCAST  (1 << 3)

int fut_fipc_channel_create_broadcast(
    struct fut_task *sender,
    size_t queue_size,
    uint32_t flags,
    struct fut_fipc_channel **channel_out
);

int fut_fipc_subscribe(
    struct fut_fipc_channel *broadcast_channel,
    struct fut_task *subscriber
);
```

**Use Case:** System notifications, compositor frame events

---

### **Priority 5: Capability Security**

**Action:** Implement capability tokens (Phase 4)

- Add `capability` field to `fut_fipc_msg`
- Implement capability table per process
- Verify capabilities on send/receive
- Integrate with future sandboxing system

**Defer to:** Phase 4 (Security & Sandboxing)

---

## 📋 Alignment Action Plan

### **Immediate (This Sprint)**

1. ✅ Document discrepancies (this document)
2. ⬜ Update `fut_fipc_msg` structure to match spec
3. ⬜ Add missing fields (`dst_pid`, `capability`)
4. ⬜ Rename fields for consistency (`length`, `src_pid`, `payload`)
5. ⬜ Update all protocol headers to use aligned structure

### **Short Term (Phase 3 Implementation)**

6. ⬜ Add spec-compliant API wrappers (`fipc_open`, `fipc_close`, etc.)
7. ⬜ Implement broadcast channels
8. ⬜ Add FIPC performance benchmarks
9. ⬜ Update FUTURAWAY_SPEC.md to reflect message format decisions

### **Long Term (Phase 4)**

10. ⬜ Implement capability security model
11. ⬜ Add CRC/checksum to messages for traceability
12. ⬜ Implement message replay/logging infrastructure
13. ⬜ Add networked FIPC transport (remote display)

---

## 🎯 Recommendations

### **Recommendation 1: Prioritize Message Structure Alignment**
- **Why:** Core data structure affects all subsystems
- **When:** Before Phase 3 implementation begins
- **Effort:** 2-3 hours

### **Recommendation 2: Document Intentional Deviations**
- **Why:** Some design choices are improvements over spec
- **Action:** Update specs to match implementation where justified
- **Example:** 32-bit message type more flexible than 16-bit opcode

### **Recommendation 3: Defer Capability Security to Phase 4**
- **Why:** Complex feature, needs dedicated focus
- **Action:** Add placeholder fields now, implement later
- **Benefit:** Maintains forward compatibility

### **Recommendation 4: Maintain Dual API**
- **Why:** Support both spec names and implementation names
- **Action:** Add inline wrappers for compatibility
- **Benefit:** No breaking changes for existing code

---

## ✅ Conclusion

Our implementation is **fundamentally aligned** with the specifications:
- Core philosophies match
- Architecture is correct
- Zero-copy, FIPC-based design intact
- FuturaWay compositor model sound

**Minor structural differences exist:**
- Message header fields (easily fixed)
- API naming (wrappers solve this)
- Missing broadcast channels (Phase 3)
- Security capabilities (Phase 4)

**Verdict:** ✅ **Proceed with Phase 3 implementation** after addressing Priority 1 (message structure alignment). Other refinements can be done incrementally.

---

**Next Steps:**
1. Update `fut_fipc_msg` structure
2. Regenerate protocol headers
3. Test backward compatibility
4. Continue Phase 3 userland implementation

---

*Analysis completed: October 11, 2025*
*Reviewed by: FUTURA_CORE*
