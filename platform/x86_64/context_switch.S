/*
 * Futura OS - x86_64 Context Switching
 * Preserves full kernel thread state including SIMD context.
 */

.section .text

/* struct fut_cpu_context layout (see include/arch/x86_64/regs.h)
 *
 *  uint64_t r15, r14, r13, r12, rbx, rbp;
 *  uint64_t rip, rsp, rflags, cs, ss;
 *  uint64_t ds, es, fs, gs;
 *  uint64_t rdi, rsi, rdx, rcx, rax;
 *  uint8_t  fx_area[512];
 */
.equ CTX_R15,     0
.equ CTX_R14,     8
.equ CTX_R13,     16
.equ CTX_R12,     24
.equ CTX_RBX,     32
.equ CTX_RBP,     40
.equ CTX_RIP,     48
.equ CTX_RSP,     56
.equ CTX_RFLAGS,  64
.equ CTX_CS,      72
.equ CTX_SS,      80
.equ CTX_DS,      88
.equ CTX_ES,      96
.equ CTX_FS,      104
.equ CTX_GS,      112
.equ CTX_RDI,     120
.equ CTX_RSI,     128
.equ CTX_RDX,     136
.equ CTX_RCX,     144
.equ CTX_RAX,     152
.equ CTX_FX,      160

/*
 * fut_switch_context
 *   RDI = previous context pointer (nullable)
 *   RSI = next context pointer (non-null)
 */
.global fut_switch_context
.type fut_switch_context, @function
fut_switch_context:
    /* Stash next context pointer in %r11 (scratch) */
    movq %rsi, %r11

    /* Save current context if present */
    testq %rdi, %rdi
    jz 1f

    movq %r15, CTX_R15(%rdi)
    movq %r14, CTX_R14(%rdi)
    movq %r13, CTX_R13(%rdi)
    movq %r12, CTX_R12(%rdi)
    movq %rbx, CTX_RBX(%rdi)
    movq %rbp, CTX_RBP(%rdi)

    movq (%rsp), %rax
    movq %rax, CTX_RIP(%rdi)
    leaq 8(%rsp), %rax
    movq %rax, CTX_RSP(%rdi)

    pushfq
    popq %rax
    movq %rax, CTX_RFLAGS(%rdi)

    movq $0x08, %rax
    movq %rax, CTX_CS(%rdi)
    movq $0x10, %rax
    movq %rax, CTX_SS(%rdi)

    /* Note: We don't save segment registers from kernel context
     * They're always kernel segments (0x10) for kernel code, and we
     * restore them explicitly below rather than from saved context
     */

    leaq CTX_FX(%rdi), %rax
    fxsave64 (%rax)

1:
    /* Restore next context (pointer in %r11) */
    leaq CTX_FX(%r11), %rax
    fxrstor64 (%rax)

    movq CTX_RFLAGS(%r11), %rax
    pushq %rax
    popfq

    movq CTX_RSP(%r11), %rsp

    movq CTX_R15(%r11), %r15
    movq CTX_R14(%r11), %r14
    movq CTX_R13(%r11), %r13
    movq CTX_R12(%r11), %r12

    /* For kernel threads, segment registers are always kernel data segment (0x10).
     * In 64-bit mode, these don't affect addressing, but we set them for consistency.
     * Skip explicit restore - they're already set correctly from boot/previous switch.
     */

    /* Restore rbx and rbp */
    movq CTX_RBX(%r11), %rbx
    movq CTX_RBP(%r11), %rbp

    movq CTX_RDI(%r11), %rdi
    movq CTX_RSI(%r11), %rsi
    movq CTX_RDX(%r11), %rdx
    movq CTX_RCX(%r11), %rcx
    movq CTX_RAX(%r11), %rax

    /* Jump to saved RIP using ret for proper stack alignment */
    movq CTX_RIP(%r11), %r10
    pushq %r10
    ret

.size fut_switch_context, . - fut_switch_context

/*
 * fut_switch_context_irq - IRQ-safe context switch using IRET
 *
 * System V AMD64 ABI:
 * RDI = pointer to previous thread (fut_thread_t *prev)
 * RSI = pointer to next thread (fut_thread_t *next)
 * RDX = pointer to interrupt frame (fut_interrupt_frame_t *frame)
 *
 * CRITICAL: This function does NOT return normally to its caller!
 *
 * Architecture:
 * 1. Timer IRQ handler pushes all registers, creating interrupt frame on stack
 * 2. Calls this function: fut_switch_context_irq(prev, next, frame_ptr)
 * 3. We save PREV thread's state to prev->irq_frame (allocating if needed)
 * 4. We copy NEXT thread's saved state to the stack (or construct if first time)
 * 5. We restore ALL of next thread's registers from the stack
 * 6. We execute IRETQ to jump directly to next thread
 *
 * The IRQ handler's register restoration code is NEVER reached - we bypass it
 * entirely by doing IRETQ ourselves. This is necessary because if we returned
 * normally, the IRQ handler would pop the OLD thread's registers back, undoing
 * the context switch!
 *
 * Stack layout on entry:
 *   [5 callee-saved: rbx, r12-r15]  <- we push these (40 bytes)
 *   [return address]                 <- points to IRQ handler (8 bytes)
 *   [alignment padding]              <- 0-8 bytes for 16-byte align
 *   [interrupt frame (208 bytes)]    <- RDX points here
 *     - gs, fs, es, ds               (32 bytes)
 *     - 15 GPRs                      (120 bytes)
 *     - vector, error                (16 bytes)
 *     - rip, cs, rflags, rsp, ss     (40 bytes) <- hardware-pushed for IRET
 *
 * Thread structure offsets (see include/kernel/fut_thread.h):
 *   +0:   tid (8 bytes)
 *   +8:   task (8 bytes)
 *   +16:  stack_base (8 bytes)
 *   +24:  stack_size (8 bytes)
 *   +32:  alloc_base (8 bytes)
 *   +40:  _padding (8 bytes)
 *   +48:  context (672 bytes)
 *   +720: irq_frame (8 bytes pointer to saved interrupt frame)
 */
.global fut_switch_context_irq
.type fut_switch_context_irq, @function
fut_switch_context_irq:
    /* Save callee-saved registers */
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    /* Save arguments */
    movq %rdi, %r12         /* r12 = prev */
    movq %rsi, %r13         /* r13 = next */
    movq %rdx, %r14         /* r14 = frame */

    /* Step 1: Save/allocate interrupt frame for prev thread */
    testq %r12, %r12
    jz 1f                   /* Skip if prev is NULL */

    /* Check if prev->irq_frame is NULL (needs allocation) */
    movq 720(%r12), %r15
    testq %r15, %r15
    jnz .save_frame         /* Already allocated, just save */

    /* Allocate frame storage (208 bytes) - call fut_malloc */
    /* Save frame pointer first */
    pushq %r14
    movq $208, %rdi
    call fut_malloc
    popq %r14
    movq %rax, %r15         /* r15 = allocated frame */

    /* Check allocation success */
    testq %r15, %r15
    jz 1f                   /* Skip if allocation failed */

    /* Save pointer */
    movq %r15, 720(%r12)    /* prev->irq_frame = allocated_frame */

.save_frame:
    /* Copy current frame to prev->irq_frame */
    movq %r15, %rdi         /* dest = prev->irq_frame */
    movq %r14, %rsi         /* src = current frame on stack */
    movq $26, %rcx          /* 208 bytes / 8 = 26 qwords */
    cld
    rep movsq

    /* CRITICAL FIX: For kernel-mode interrupts, the CPU does NOT push RSP/SS.
     * Offsets 192/200 in the frame contain garbage. We must fix them up with
     * the actual current values so when we restore this frame later, we have
     * valid SS to load.
     *
     * ALSO: Fix up CS to ensure it matches current privilege level. If we're in
     * kernel mode (CPL=0), ensure CS is 0x08, not some garbage value. */
    pushq %rax
    pushq %rdx

    /* Debug: Check what CS and RIP values were saved */
    movw $0x3F8, %dx
    movb $'[', %al          /* [ = start frame save debug */
    outb %al, %dx

    /* Check RIP first - if it's ZERO, don't save this frame! */
    movq 168(%r15), %rax    /* Get saved RIP from frame */
    testq %rax, %rax
    jnz .save_rip_nonzero

    /* RIP is ZERO - thread hasn't started yet, skip saving frame */
    movb $'0', %al          /* 0 = RIP is zero, skipping frame save! */
    outb %al, %dx
    movb $']', %al
    outb %al, %dx

    /* IMPORTANT: Clear prev->irq_frame to prevent restoring stale zero-RIP frame */
    testq %r12, %r12        /* Check if we have a prev thread */
    jz 1f                   /* No prev thread, skip to restore next */
    movq $0, 720(%r12)      /* prev->irq_frame = NULL (offset 720) */

    jmp 1f                  /* Skip to step 2: restore next thread */

.save_rip_nonzero:
    movb $'r', %al          /* r = RIP is non-zero */
    outb %al, %dx
.save_rip_done:

    /* Check CS */
    movq 176(%r15), %rax    /* Get saved CS from frame */
    cmpq $0x08, %rax
    je .save_cs_kernel
    movb $'u', %al          /* u = user CS in saved frame */
    outb %al, %dx
    jmp .save_cs_done
.save_cs_kernel:
    movb $'k', %al          /* k = kernel CS in saved frame */
    outb %al, %dx
.save_cs_done:

    /* CRITICAL: Trust hardware-pushed frames. If we see unexpected values,
     * the frame is corrupted and should be REJECTED, not fixed! */

    /* Validate frame consistency: CS must match RIP address space */
    movq 176(%r15), %rax    /* Get CS from saved frame */
    cmpq $0x08, %rax        /* Is it kernel CS? */
    je .validate_kernel_frame

    /* User CS - validate RIP is in user space (< 0x800000000000) */
    movq 168(%r15), %rax    /* Get RIP */
    movq %rax, %rcx
    shrq $47, %rcx          /* Get top 17 bits */
    testq %rcx, %rcx        /* Should be 0 for user addresses */
    jz .skip_all_fixups     /* Valid user frame */

    /* User CS but kernel RIP - corrupted! Skip save */
    movb $'!', %al          /* ! = frame validation failed */
    outb %al, %dx
    jmp .skip_save_corrupted

.validate_kernel_frame:
    /* Kernel CS - validate RIP is in kernel space (>= 0xFFFF800000000000) */
    movq 168(%r15), %rax    /* Get RIP */
    movq %rax, %rcx
    shrq $47, %rcx          /* Get top 17 bits */
    cmpq $0x1FFFF, %rcx     /* Should be 0x1FFFF for kernel addresses */
    jne .kernel_rip_invalid /* Invalid - skip save */

    /* CRITICAL FIX: In 64-bit mode, CPU pushes SS unconditionally, but kernel
     * may run with SS=0. Fix SS to kernel data segment for IRETQ.
     * Note: CPU-pushed RSP at offset 192 is already correct - don't modify it! */
    movq $0x10, 200(%r15)   /* SS = kernel data segment selector */
    jmp .skip_all_fixups    /* Valid kernel frame, SS now fixed up */

.kernel_rip_invalid:

    /* Kernel CS but non-kernel RIP - corrupted! Skip save */
    movb $'!', %al          /* ! = frame validation failed */
    outb %al, %dx
    jmp .skip_save_corrupted

.skip_save_corrupted:
    /* Frame is corrupted - don't save it */
    movb $'Y', %al          /* Y = skipping corrupted frame */
    outb %al, %dx
    movb $']', %al
    outb %al, %dx

    /* Clear prev->irq_frame to prevent using stale frame */
    testq %r12, %r12
    jz 1f
    movq $0, 720(%r12)      /* prev->irq_frame = NULL */

    jmp 1f                  /* Skip to restore next thread */

.skip_all_fixups:
    /* Frame is valid - save it as-is without any modifications */
    movb $']', %al          /* ] = end frame save debug */
    outb %al, %dx

    popq %rdx
    popq %rax

1:
    /* CRITICAL: Never allow idle thread (tid=1) to have saved interrupt frames.
     * Idle thread should always construct frames from context to avoid corruption.
     * If prev is idle thread, ensure its irq_frame is NULL. */
    testq %r12, %r12        /* Check if we have a prev thread */
    jz .check_next_idle
    movq 0(%r12), %rax      /* Get prev->tid (first field in struct) */
    cmpq $1, %rax           /* Is it tid=1 (idle thread)? */
    jne .check_next_idle
    /* prev is idle thread - ensure irq_frame is NULL */
    movq $0, 720(%r12)      /* prev->irq_frame = NULL */

.check_next_idle:
    /* Similarly, if next is idle thread, ensure its irq_frame is NULL */
    testq %r13, %r13        /* Check if we have a next thread */
    jz .get_next_frame
    movq 0(%r13), %rax      /* Get next->tid */
    cmpq $1, %rax           /* Is it tid=1 (idle thread)? */
    jne .get_next_frame
    /* next is idle thread - clear irq_frame to force construction from context */
    movq $0, 720(%r13)      /* next->irq_frame = NULL */

.get_next_frame:
    /* Step 2: Get next thread's saved frame pointer */
    movq 720(%r13), %r11

    /* Debug: Check if we have a saved frame */
    testq %r11, %r11
    jz .no_saved_frame
    /* We have a saved frame! Print 'S' */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'S', %al
    outb %al, %dx
    popq %rdx
    jmp .restore_saved_frame
.no_saved_frame:
    /* No saved frame, will construct from context. Print 'C' */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'C', %al
    outb %al, %dx
    popq %rdx

    /* IMPORTANT: Clear next->irq_frame to prevent reusing stale frames */
    /* This handles both the case where irq_frame was NULL and where
     * we jumped here from validation failure (line 468) */
    testq %r13, %r13        /* Check if we have a next thread */
    jz .skip_clear_next
    movq $0, 720(%r13)      /* next->irq_frame = NULL */
.skip_clear_next:

    /* If next->irq_frame is NULL, construct frame from context */

    /* Construct interrupt frame from thread context */
    /* Thread structure: context starts at offset 48 */
    /* Context layout: r15(0), r14(8), r13(16), r12(24), rbx(32), rbp(40),
     *                 rip(48), rsp(56), rflags(64), cs(72), ss(80),
     *                 ds(88), es(96), fs(104), gs(112),
     *                 rdi(120), rsi(128), rdx(136), rcx(144), rax(152) */

    leaq 48(%r13), %rsi     /* rsi = &next->context */
    movq %r14, %rdi         /* rdi = interrupt frame on stack */

    /* Copy segment registers (gs, fs, es, ds) */
    movq 112(%rsi), %rax    /* context.gs */
    movq %rax, 0(%rdi)      /* frame->gs */
    movq 104(%rsi), %rax    /* context.fs */
    movq %rax, 8(%rdi)      /* frame->fs */
    movq 96(%rsi), %rax     /* context.es */
    movq %rax, 16(%rdi)     /* frame->es */
    movq 88(%rsi), %rax     /* context.ds */
    movq %rax, 24(%rdi)     /* frame->ds */

    /* Copy general purpose registers */
    movq 152(%rsi), %rax    /* context.rax */
    movq %rax, 32(%rdi)     /* frame->rax */
    movq 32(%rsi), %rax     /* context.rbx */
    movq %rax, 40(%rdi)     /* frame->rbx */
    movq 144(%rsi), %rax    /* context.rcx */
    movq %rax, 48(%rdi)     /* frame->rcx */
    movq 136(%rsi), %rax    /* context.rdx */
    movq %rax, 56(%rdi)     /* frame->rdx */
    movq 128(%rsi), %rax    /* context.rsi */
    movq %rax, 64(%rdi)     /* frame->rsi */
    movq 120(%rsi), %rax    /* context.rdi */
    movq %rax, 72(%rdi)     /* frame->rdi */
    movq 40(%rsi), %rax     /* context.rbp */
    movq %rax, 80(%rdi)     /* frame->rbp */

    /* Copy r8-r15 (set to context values) */
    movq $0, 88(%rdi)       /* frame->r8 = 0 */
    movq $0, 96(%rdi)       /* frame->r9 = 0 */
    movq $0, 104(%rdi)      /* frame->r10 = 0 */
    movq $0, 112(%rdi)      /* frame->r11 = 0 */
    movq 24(%rsi), %rax     /* context.r12 */
    movq %rax, 120(%rdi)    /* frame->r12 */
    movq 16(%rsi), %rax     /* context.r13 */
    movq %rax, 128(%rdi)    /* frame->r13 */
    movq 8(%rsi), %rax      /* context.r14 */
    movq %rax, 136(%rdi)    /* frame->r14 */
    movq 0(%rsi), %rax      /* context.r15 */
    movq %rax, 144(%rdi)    /* frame->r15 */

    /* Set vector and error_code */
    movq $32, 152(%rdi)     /* frame->vector = 32 (IRQ0) */
    movq $0, 160(%rdi)      /* frame->error_code = 0 */

    /* Copy control registers (CPU-pushed values) */
    movq 48(%rsi), %rax     /* context.rip */

    /* Debug: Check if RIP is NULL */
    testq %rax, %rax
    jnz .rip_ok
    /* RIP is NULL! Print '!' and halt */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'!', %al
    outb %al, %dx
    popq %rdx
    hlt
.rip_ok:

    movq %rax, 168(%rdi)    /* frame->rip */
    movq 72(%rsi), %rax     /* context.cs */
    movq %rax, 176(%rdi)    /* frame->cs */
    movq 64(%rsi), %rax     /* context.rflags */
    movq %rax, 184(%rdi)    /* frame->rflags */

    /* ALWAYS initialize RSP/SS in frame, even for kernel mode.
     * While IRETQ won't read these for same-privilege returns (kernel->kernel),
     * initializing them prevents issues with garbage values and ensures
     * the frame is always in a valid state. */
    movq 56(%rsi), %rax     /* context.rsp */
    movq %rax, 192(%rdi)    /* frame->rsp */

    /* Set SS from context (or default to kernel SS if zero) */
    movq 80(%rsi), %rax     /* context.ss */
    testq %rax, %rax        /* Is it zero (uninitialized)? */
    jnz .ss_valid
    /* context.ss is 0 - default to kernel SS for safety */
    movq $0x10, %rax
.ss_valid:
    movq %rax, 200(%rdi)    /* frame->ss */
    jmp 2f

.restore_saved_frame:
    /* CRITICAL: Validate saved frame before restoring! */
    /* First check: RIP must NOT be zero (invalid for any mode) */
    movq 168(%r11), %rax    /* Get RIP from saved frame */
    testq %rax, %rax        /* Is RIP zero? */
    jz .restore_frame_invalid  /* Zero RIP is always invalid! */

    /* Check if kernel or user mode */
    movq 176(%r11), %rax    /* Get CS from saved frame */
    cmpq $0x08, %rax        /* Is it kernel CS? */
    jne .validate_user_frame  /* User thread - validate user constraints */

    /* Kernel thread - validate RIP is in kernel space (>= 0xFFFF800000000000) */
    movq 168(%r11), %rax    /* Get RIP from saved frame */
    movq %rax, %rcx         /* Copy for test */
    shrq $47, %rcx          /* Get top 17 bits */
    cmpq $0x1FFFF, %rcx     /* Should be 0x1FFFF for kernel addresses */
    je .restore_frame_ok    /* Valid kernel RIP */
    jmp .restore_frame_invalid  /* Invalid kernel RIP */

.validate_user_frame:
    /* User thread - validate RIP is in user space (< 0x800000000000) */
    movq 168(%r11), %rax    /* Get RIP from saved frame */
    movq %rax, %rcx         /* Copy for test */
    shrq $47, %rcx          /* Get top 17 bits */
    testq %rcx, %rcx        /* Should be 0 for user addresses */
    jz .restore_frame_ok    /* Valid user RIP */
    /* Fall through to .restore_frame_invalid */

.restore_frame_invalid:
    /* Invalid RIP in saved frame! Clear irq_frame and construct from context */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'X', %al          /* X = frame validation failed! */
    outb %al, %dx
    popq %rdx

    /* Clear next->irq_frame so we don't use this corrupted frame again */
    movq $0, 720(%r13)      /* next->irq_frame = NULL */
    jmp .no_saved_frame     /* Construct from context instead */

.restore_frame_ok:
    /* Debug: Check what CS value is in saved frame we're about to restore */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'{', %al          /* { = start restore frame debug */
    outb %al, %dx

    movq 176(%r11), %rax    /* Get CS from saved frame */
    cmpq $0x08, %rax
    je .restore_cs_kernel
    movb $'U', %al          /* U = user CS in saved frame to restore */
    outb %al, %dx
    jmp .restore_cs_done
.restore_cs_kernel:
    movb $'K', %al          /* K = kernel CS in saved frame to restore */
    outb %al, %dx
.restore_cs_done:

    /* Debug: Print RIP from saved frame (first 2 hex digits) */
    movq 168(%r11), %rax    /* Get RIP from saved frame */
    pushq %rax              /* Save full RIP */
    shrq $56, %rax          /* Get top byte */
    andb $0xF, %al          /* Get low nibble */
    addb $'0', %al
    cmpb $'9', %al
    jle .rip_nibble1_ok
    addb $7, %al
.rip_nibble1_ok:
    outb %al, %dx

    popq %rax               /* Restore full RIP */
    pushq %rax              /* Save again */
    shrq $52, %rax          /* Get next nibble */
    andb $0xF, %al
    addb $'0', %al
    cmpb $'9', %al
    jle .rip_nibble2_ok
    addb $7, %al
.rip_nibble2_ok:
    outb %al, %dx

    popq %rax               /* Restore RIP value */

    movb $'}', %al          /* } = end restore frame debug */
    outb %al, %dx

    popq %rdx
    popq %rax

    /* Step 3: Copy saved frame to current interrupt frame location */
    movq %r14, %rdi         /* dest = current frame on stack */
    movq %r11, %rsi         /* src = next->irq_frame */
    movq $26, %rcx          /* 208 bytes / 8 = 26 qwords */
    cld
    rep movsq

2:
    /* Step 4: Restore FPU state from next thread's context */
    /* context is at offset 48, fx_area is at offset 160 within context */
    /* So fx_area is at 48 + 160 = 208 */

    /* Debug: Check if R13 (next thread pointer) is valid */
    testq %r13, %r13
    jnz .r13_ok
    /* R13 is NULL! Print '?' and halt */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'?', %al
    outb %al, %dx
    popq %rdx
    hlt
.r13_ok:

    leaq 208(%r13), %rax    /* rax = &next->context.fx_area */

    /* Debug: Check if RAX is valid after calculation */
    testq %rax, %rax
    jnz .rax_ok
    /* RAX is NULL after leaq! Print '@' and halt */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'@', %al
    outb %al, %dx
    popq %rdx
    hlt
.rax_ok:

    fxrstor64 (%rax)

    /* Debug: FPU restore successful, print '#' */
    pushq %rdx
    movw $0x3F8, %dx
    movb $'#', %al
    outb %al, %dx
    popq %rdx

    /* Step 5: Set stack pointer directly to the interrupt frame */
    /* R14 still contains the pointer to the frame (passed as RDX parameter) */
    /* We can't just add to RSP because of stack alignment - use R14 directly */
    movq %r14, %rsp         /* RSP now points to start of interrupt frame */

    /* Step 6: Restore all registers from the interrupt frame on stack */
    /* The interrupt frame layout (see fut_interrupt_frame in regs.h):
     *   +0:   gs (8)       +32:  rax (8)      +152: r15 (8)
     *   +8:   fs (8)       +40:  rbx (8)      +160: vector (8)
     *   +16:  es (8)       +48:  rcx (8)      +168: error_code (8)
     *   +24:  ds (8)       +56:  rdx (8)      +176: rip (8)        <- for IRET
     *   ...               +64:  rsi (8)      +184: cs (8)         <- for IRET
     *                      +72:  rdi (8)      +192: rflags (8)     <- for IRET
     *                      +80:  rbp (8)      +200: rsp (8)        <- for IRET (if CPL change)
     *                      +88-144: r8-r14    +208: ss (8)         <- for IRET (if CPL change)
     */

    /* Restore segment registers */

    /* CRITICAL: NEVER load GS! The kernel uses GS_BASE MSR for per-CPU data.
     * Loading any GS selector would read the base from the GDT descriptor
     * (which is 0 for user data segment), corrupting the per-CPU pointer.
     * Just skip the saved GS value entirely. */
    addq $8, %rsp           /* Skip the GS value - never load it */

    /* Validate and load FS */
    movq 0(%rsp), %rax      /* Peek at FS value without popping */
    testw %ax, %ax          /* Check if NULL selector (0) */
    jz .fs_skip             /* NULL is valid, skip loading */
    cmpw $0x10, %ax         /* Check if valid kernel segment */
    je .fs_ok
    cmpw $0x23, %ax         /* Check if valid user segment */
    je .fs_ok
    /* FS value is invalid! Skip loading it, use current FS */
.fs_skip:
    addq $8, %rsp           /* Skip the FS value */
    jmp .fs_done
.fs_ok:
    popq %rax               /* Pop fs */
    movw %ax, %fs
.fs_done:

    /* Validate and load ES */
    movq 0(%rsp), %rax      /* Peek at ES value without popping */
    testw %ax, %ax          /* Check if NULL selector (0) */
    jz .es_skip             /* NULL is valid, skip loading */
    cmpw $0x10, %ax         /* Check if valid kernel segment */
    je .es_ok
    cmpw $0x23, %ax         /* Check if valid user segment */
    je .es_ok
    /* ES value is invalid! Skip loading it, use current ES */
.es_skip:
    addq $8, %rsp           /* Skip the ES value */
    jmp .es_done
.es_ok:
    popq %rax               /* Pop es */
    movw %ax, %es
.es_done:

    /* Validate and load DS */
    movq 0(%rsp), %rax      /* Peek at DS value without popping */
    testw %ax, %ax          /* Check if NULL selector (0) */
    jz .ds_skip             /* NULL is valid, skip loading */
    cmpw $0x10, %ax         /* Check if valid kernel segment */
    je .ds_ok
    cmpw $0x23, %ax         /* Check if valid user segment */
    je .ds_ok
    /* DS value is invalid! Skip loading it and use current DS */
.ds_skip:
    addq $8, %rsp           /* Skip the DS value */
    jmp .segments_done
.ds_ok:
    popq %rax               /* Pop ds */
    movw %ax, %ds

.segments_done:

    /* Restore general purpose registers */
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Skip vector number and error code (16 bytes) */
    addq $16, %rsp

    /* Step 7: Execute IRETQ to jump to the next thread */
    /* Stack now has: rip, cs, rflags, rsp, ss (pushed by hardware during IRQ) */
    /* IRETQ will pop these and jump to the new thread's saved RIP */

    /* Debug: About to IRETQ, print '$' */
    pushq %rdx
    pushq %rax
    movw $0x3F8, %dx
    movb $'$', %al
    outb %al, %dx

    /* Debug: Print all IRETQ frame values */
    /* Stack layout after pushing RAX and RDX:
     * [RSP+0]  = RAX (temp)
     * [RSP+8]  = RDX (temp)
     * [RSP+16] = RIP (IRETQ frame)
     * [RSP+24] = CS  (IRETQ frame)
     * [RSP+32] = RFLAGS (IRETQ frame)
     * [RSP+40] = RSP (only if CPL change)
     * [RSP+48] = SS  (only if CPL change)
     */

    /* Print 'R' and RIP value */
    movq 16(%rsp), %rax        /* Get RIP from stack */
    pushq %rax
    movb $'R', %al
    outb %al, %dx
    popq %rax

    /* Print RFLAGS value (before printing RIP nibbles) */
    movq 32(%rsp), %r8          /* Get RFLAGS from stack */

    /* Check if RFLAGS has IF (interrupt enable) bit set */
    testq $0x200, %r8           /* IF is bit 9 */
    jnz .if_set
    movb $'i', %al              /* i = interrupts disabled */
    outb %al, %dx
    jmp .if_done
.if_set:
    movb $'I', %al              /* I = interrupts enabled */
    outb %al, %dx
.if_done:

    /* Check if RFLAGS has reserved bit 1 set (must always be 1) */
    testq $0x2, %r8             /* Bit 1 */
    jnz .res_ok
    movb $'!', %al              /* ! = RFLAGS invalid (bit 1 not set) */
    outb %al, %dx
    jmp .res_done
.res_ok:
    movb $'V', %al              /* V = RFLAGS valid */
    outb %al, %dx
.res_done:

    /* Restore RAX with RIP value for further processing */
    movq 16(%rsp), %rax

    /* Check if RIP is in kernel space (high bit set) */
    testq %rax, %rax
    js .rip_kernel
    movb $'U', %al              /* U = user space RIP */
    outb %al, %dx
    jmp .rip_checked
.rip_kernel:
    movb $'K', %al              /* K = kernel space RIP */
    outb %al, %dx
.rip_checked:

    /* Print high nibble of byte 7 (most significant byte) */
    movq %rax, %rcx
    shrq $60, %rcx
    andb $0xF, %cl
    cmpb $10, %cl
    jl .rip_digit1
    addb $('A' - 10), %cl
    jmp .rip_print1
.rip_digit1:
    addb $'0', %cl
.rip_print1:
    pushq %rax
    movb %cl, %al
    outb %al, %dx
    popq %rax

    /* Print low nibble of byte 7 */
    movq %rax, %rcx
    shrq $56, %rcx
    andb $0xF, %cl
    cmpb $10, %cl
    jl .rip_digit2
    addb $('A' - 10), %cl
    jmp .rip_print2
.rip_digit2:
    addb $'0', %cl
.rip_print2:
    pushq %rax
    movb %cl, %al
    outb %al, %dx
    popq %rax

    /* Check if RIP is NULL */
    testq %rax, %rax
    jnz .rip_not_null
    /* RIP IS NULL! Print 'Z' and halt */
    movb $'Z', %al
    outb %al, %dx
    hlt
.rip_not_null:

    /* CRITICAL: Validate and fix CS value in IRETQ frame */
    /* Valid CS values: 0x08 (kernel), 0x1B (user with RPL=3) */
    movq 24(%rsp), %rax        /* Get CS from stack */
    cmpq $0x08, %rax          /* Is it kernel CS? */
    je .cs_iretq_ok
    cmpq $0x1B, %rax          /* Is it user CS (0x18 | 3)? */
    je .cs_iretq_ok

    /* CS is INVALID! Fix it based on RIP address space */
    movb $'C', %al            /* C = Invalid CS detected */
    outb %al, %dx
    movb $'!', %al
    outb %al, %dx

    /* Check if RIP is kernel or user space to determine correct CS */
    movq 16(%rsp), %rax       /* Get RIP from frame */
    testq %rax, %rax
    js .fix_kernel_cs         /* High bit set = kernel address */
    /* User space RIP - set user CS */
    movq $0x1B, 24(%rsp)      /* CS = user code (0x18 | 3) */
    jmp .cs_iretq_ok
.fix_kernel_cs:
    movq $0x08, 24(%rsp)      /* CS = kernel code */
.cs_iretq_ok:
    /* Print current CS for debug */
    movq 24(%rsp), %rax
    cmpq $0x08, %rax
    je .cs_print_k
    movb $'u', %al            /* u = user CS */
    outb %al, %dx
    jmp .cs_print_done
.cs_print_k:
    movb $'K', %al            /* K = kernel CS */
    outb %al, %dx
.cs_print_done:

    popq %rax
    popq %rdx

    /* Debug: Print '>' immediately before IRETQ */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'>', %al
    outb %al, %dx

    /* CRITICAL FIX: Validate SS in IRETQ frame.
     * In x86-64 mode, IRETQ always pops SS from RSP+32.
     * Invalid SS values cause #GP. Valid values: 0, 0x10 (kernel), 0x23 (user).
     * Stack layout after our push: [RSP+0]=RAX, [RSP+8]=RDX
     * IRETQ frame starts at RSP+16: RIP(+16), CS(+24), RFLAGS(+32), RSP(+40), SS(+48) */
    movq 48(%rsp), %rax     /* Get SS from IRETQ frame */

    /* Check if SS is a valid selector: 0, 0x10, or 0x23 */
    testw %ax, %ax          /* Is SS zero? */
    jz .ss_iretq_ok         /* Zero is valid (kernel can use NULL SS in 64-bit mode) */
    cmpw $0x10, %ax         /* Is SS kernel data segment? */
    je .ss_iretq_ok
    cmpw $0x23, %ax         /* Is SS user data segment? */
    je .ss_iretq_ok

    /* SS is INVALID - fix it! */
    movb $'!', %al          /* ! = Invalid SS detected, fixing! */
    outb %al, %dx

    /* Determine correct SS value based on CS (kernel vs user) */
    movq 24(%rsp), %rax     /* Get CS from frame */
    cmpq $0x08, %rax        /* Is it kernel CS? */
    je .fix_kernel_ss
    /* User CS - set SS to user data segment 0x23 */
    movq $0x23, %rax
    jmp .write_fixed_ss
.fix_kernel_ss:
    /* Kernel CS - set SS to kernel data segment 0x10 */
    movq $0x10, %rax
.write_fixed_ss:
    movq %rax, 48(%rsp)     /* Write fixed SS back to frame */

.ss_iretq_ok:
    popq %rdx
    popq %rax

    iretq

.size fut_switch_context_irq, . - fut_switch_context_irq

/*
 * fut_get_rsp - Get current stack pointer
 *
 * Returns: Current RSP value in RAX
 */
.global fut_get_rsp
.type fut_get_rsp, @function
fut_get_rsp:
    movq %rsp, %rax
    ret

.size fut_get_rsp, . - fut_get_rsp

/*
 * fut_get_rbp - Get current base pointer
 *
 * Returns: Current RBP value in RAX
 */
.global fut_get_rbp
.type fut_get_rbp, @function
fut_get_rbp:
    movq %rbp, %rax
    ret

.size fut_get_rbp, . - fut_get_rbp

/*
 * fut_set_kernel_stack - Set kernel stack for interrupt handling
 *
 * System V AMD64 ABI:
 * RDI = new kernel stack pointer
 */
.global fut_set_kernel_stack
.type fut_set_kernel_stack, @function
fut_set_kernel_stack:
    /* This would update TSS RSP0 in a full implementation */
    /* For now, just update RSP directly */
    movq %rdi, %rsp
    ret

.size fut_set_kernel_stack, . - fut_set_kernel_stack

/*
 * fut_idle - Halt CPU until next interrupt
 */
.global fut_idle
.type fut_idle, @function
fut_idle:
    hlt
    ret

.size fut_idle, . - fut_idle

/*
 * fut_enter_usermode - Enter user mode (ring 3)
 *
 * System V AMD64 ABI:
 * RDI = user entry point
 * RSI = user stack pointer
 */
.global fut_enter_usermode
.type fut_enter_usermode, @function
fut_enter_usermode:
    /* Disable interrupts during transition */
    cli

    /* Set up IRET frame for user mode */
    pushq $0x20 | 3                     /* User data segment (SS) with RPL=3 */
    pushq %rsi                          /* User stack pointer (RSP) */
    pushq $0x200                        /* RFLAGS (IF=1) */
    pushq $0x18 | 3                     /* User code segment (CS) with RPL=3 */
    pushq %rdi                          /* User entry point (RIP) */

    /* Clear all registers for security */
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %rsi, %rsi
    xorq %rdi, %rdi
    xorq %rbp, %rbp
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    /* Set user data segments */
    movw $(0x20 | 3), %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    /* Zero XMM registers before entering userspace to prevent leaking kernel values.
     * GCC -O2 uses XMM registers to store pointers, and garbage values cause crashes. */
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
    pxor %xmm6, %xmm6
    pxor %xmm7, %xmm7
    pxor %xmm8, %xmm8
    pxor %xmm9, %xmm9
    pxor %xmm10, %xmm10
    pxor %xmm11, %xmm11
    pxor %xmm12, %xmm12
    pxor %xmm13, %xmm13
    pxor %xmm14, %xmm14
    pxor %xmm15, %xmm15

    /* Execute IRET to enter user mode */
    iretq

.size fut_enter_usermode, . - fut_enter_usermode

/*
 * fut_context_size - Return size of context structure
 *
 * Returns: Size in RAX
 */
.global fut_context_size
.type fut_context_size, @function
fut_context_size:
    movq $672, %rax                     /* sizeof(fut_cpu_context_t) */
    ret

.size fut_context_size, . - fut_context_size

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
