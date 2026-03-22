/*
 * Futura OS - x86_64 Context Switching
 * Preserves full kernel thread state including SIMD context.
 */

/* Debug serial output - set to 1 to enable verbose context switch tracing */
.equ DEBUG_SERIAL, 0

/* Serial port: 0x3F8 for COM1 output, 0x80 for silent (POST debug port) */
.if DEBUG_SERIAL
.equ SERIAL_PORT, 0x3F8
.else
.equ SERIAL_PORT, 0x80
.endif

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
    andq $~0x200, %rax          /* Clear IF - prevent preemption during restore */
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
    testq %r10, %r10
    jnz .coop_rip_ok

    /* NULL RIP in cooperative context! Print diagnostic and halt.
     * This catches corruption where a thread's context.rip was zeroed
     * after being saved, preventing a jump to address 0. */
    movw $0x3F8, %dx
    movb $'Z', %al          /* Z = zero RIP in cooperative switch */
    outb %al, %dx
    cli
    hlt
    jmp .                   /* Infinite loop if NMI wakes hlt */

.coop_rip_ok:
    pushq %r10
    sti                         /* Re-enable interrupts - shadow covers ret */
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
.extern fut_in_interrupt
.extern fut_current_frame
.extern lapic_base

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

    /* Step 1: Save interrupt frame for prev thread.
     * irq_frame is pre-allocated in fut_thread_create() — never call
     * fut_malloc from interrupt context (corrupts heap if interrupted
     * thread was mid-allocation). */
    testq %r12, %r12
    jz 1f                   /* Skip if prev is NULL */

    movq 720(%r12), %r15    /* r15 = prev->irq_frame (pre-allocated) */
    testq %r15, %r15
    jz 1f                   /* Skip if NULL (should never happen) */
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
    movw $SERIAL_PORT, %dx
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
    jz .skip_rip_zero_clear /* No prev thread, skip to restore next */
    movq $0, 720(%r12)      /* prev->irq_frame = NULL (offset 720) */

.skip_rip_zero_clear:
    /* CRITICAL: Must pop rdx/rax before jumping - they were pushed at line 227-228 */
    popq %rdx
    popq %rax
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
    jz .skip_corrupted_clear
    movq $0, 720(%r12)      /* prev->irq_frame = NULL */

.skip_corrupted_clear:
    /* CRITICAL: Must pop rdx/rax before jumping - they were pushed at line 227-228 */
    popq %rdx
    popq %rax
    jmp 1f                  /* Skip to restore next thread */

.skip_all_fixups:
    /* Frame is valid - save it as-is without any modifications */
    movb $']', %al          /* ] = end frame save debug */
    outb %al, %dx

    popq %rdx
    popq %rax

1:
    /* CRITICAL: Also save prev's cooperative context (kernel-mode register
     * state at this point in fut_schedule). This ensures that prev can be
     * cooperatively restored by fut_switch_context if the scheduler later
     * uses the cooperative path.
     *
     * Without this, threads that have ONLY been IRETQ-saved (like the idle
     * thread) have stale initial cooperative context values (trampoline RIP,
     * RFLAGS=0x2 with IF=0), causing system hangs when cooperatively restored.
     *
     * The saved context represents the "return from fut_switch_context_irq"
     * point. On cooperative restore, the thread returns from this function
     * as if it returned normally, then unwinds through the timer ISR call
     * chain: fut_schedule() -> fut_timer_tick() -> fut_timer_irq() -> ISR
     * stub -> IRETQ back to the original preemption point. */
    testq %r12, %r12
    jz .get_next_frame          /* Skip if no prev thread */

    /* prev->context starts at offset 48 from thread pointer (%r12).
     * Stack layout: [R15]+0 [R14]+8 [R13]+16 [R12]+24 [RBX]+32 [retaddr]+40 */
    movq 0(%rsp), %rax
    movq %rax, (48 + 0)(%r12)     /* context.r15 */
    movq 8(%rsp), %rax
    movq %rax, (48 + 8)(%r12)     /* context.r14 */
    movq 16(%rsp), %rax
    movq %rax, (48 + 16)(%r12)    /* context.r13 */
    movq 24(%rsp), %rax
    movq %rax, (48 + 24)(%r12)    /* context.r12 */
    movq 32(%rsp), %rax
    movq %rax, (48 + 32)(%r12)    /* context.rbx */
    movq %rbp, (48 + 40)(%r12)    /* context.rbp (not pushed, still original) */

    movq 40(%rsp), %rax
    movq %rax, (48 + 48)(%r12)    /* context.rip = return addr in fut_schedule */

    leaq 48(%rsp), %rax
    movq %rax, (48 + 56)(%r12)    /* context.rsp = caller's RSP before call */

    pushfq
    popq %rax
    orq $0x200, %rax              /* CRITICAL FIX: Set IF=1 in saved RFLAGS.
                                    * We're inside an ISR so IF=0 (CPU clears IF on
                                    * interrupt entry). But the thread was running with
                                    * IF=1 when it was preempted. If this cooperative
                                    * context is later used to construct an IRETQ frame
                                    * (via .no_saved_frame path), IF=0 would cause the
                                    * thread to resume with interrupts disabled, leading
                                    * to hangs and deadlocks. */
    movq %rax, (48 + 64)(%r12)    /* context.rflags (IF=1 for resumed threads) */

    movq $0x08, (48 + 72)(%r12)   /* context.cs = kernel CS */
    movq $0x10, (48 + 80)(%r12)   /* context.ss = kernel SS */

    /* Save FX state so FPU registers are preserved on cooperative restore */
    leaq (48 + 160)(%r12), %rax
    fxsave64 (%rax)

.get_next_frame:
    /* Step 2: Get next thread's saved frame pointer */
    movq 720(%r13), %r11

    /* Debug: Check if we have a saved frame */
    testq %r11, %r11
    jz .no_saved_frame
    /* We have a saved irq_frame.
     *
     * IMPORTANT: For kernel threads (CS=0x08 in the saved irq_frame), same-privilege
     * IRETQ does NOT restore RSP — only RIP, CS, and RFLAGS are popped.  The restore
     * path always places the frame at stack_top-208 and IRETQ from there, so RSP after
     * IRETQ = stack_top-16 regardless of where the thread's call stack actually was.
     * This clobbers the thread's RSP and corrupts its call stack, causing a crash.
     *
     * Instead, use the cooperative context that was saved alongside irq_frame (lines
     * 346-394): switch to next's kernel stack at context.rsp (inside the ISR call
     * chain) and "return" from fut_switch_context_irq back up through fut_schedule →
     * fut_timer_tick → fut_timer_irq → ISR stub → ISR IRETQ.  That final IRETQ
     * correctly restores the thread's user- or kernel-mode registers. */
    cmpq $0x08, 176(%r11)   /* irq_frame->cs: 0x08=kernel, 0x23=user */
    je .kernel_coop_restore  /* Kernel-mode frame: cooperative restore */
    /* User thread: IRETQ restores RSP/SS on privilege change. Print 'S'. */
    pushq %rdx
    movw $SERIAL_PORT, %dx
    movb $'S', %al
    outb %al, %dx
    popq %rdx
    jmp .restore_saved_frame
.no_saved_frame:
    /* No saved irq_frame.
     *
     * context.cs is always 0x08 (set by thread_create and both cooperative-save
     * paths), so this branch always goes to .kernel_coop_restore for the kernel
     * threads that make up all tests.  The IRETQ-frame construction code below is
     * only reached by threads whose context.cs has been set to user CS (0x23),
     * which does not currently happen. */
    cmpq $0x08, 120(%r13)   /* next->context.cs (context at +48, cs at +72 => +120) */
    je .kernel_coop_restore

    /* User thread with no saved frame: construct IRETQ frame from context. Print 'C' */
    pushq %rdx
    movw $SERIAL_PORT, %dx
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

    /* CRITICAL: Place the constructed IRETQ frame on NEXT's kernel stack,
     * NOT on prev's stack (where the original interrupt frame is).
     * If we overwrite prev's interrupt frame, the ISR return path (used
     * when prev is cooperatively restored) finds corrupted data and crashes
     * with a GPF loading invalid segment registers.
     *
     * Place the frame BELOW next's saved RSP (context.rsp). This avoids
     * corrupting the thread's initial stack setup (return address at the top).
     * After IRETQ restores RSP to context.rsp, this frame is dead stack space. */
    movq 56(%rsi), %rdi     /* next's context.rsp (CTX_RSP offset within context) */
    subq $208, %rdi         /* room for 208-byte interrupt frame below RSP */
    movq %rdi, %r14         /* update R14 (used by movq %r14, %rsp later) */

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

    /* Debug: Print '<' and first few nibbles of context RIP for C path */
    pushq %rdx
    pushq %rax
    movw $SERIAL_PORT, %dx
    movb $'<', %al          /* < = context RIP about to be loaded */
    outb %al, %dx

    /* Print nibbles 7-12 of context RIP (bits 31-8) */
    popq %rax
    pushq %rax

    /* nibble 8 (bits 31-28) */
    movq %rax, %rcx
    shrq $28, %rcx
    andb $0xF, %cl
    cmpb $10, %cl
    jl .ctx_rip_nib8_digit
    addb $('A' - 10), %cl
    jmp .ctx_rip_nib8_print
.ctx_rip_nib8_digit:
    addb $'0', %cl
.ctx_rip_nib8_print:
    movb %cl, %al
    outb %al, %dx

    popq %rax
    pushq %rax

    /* nibble 9 (bits 27-24) */
    movq %rax, %rcx
    shrq $24, %rcx
    andb $0xF, %cl
    cmpb $10, %cl
    jl .ctx_rip_nib9_digit
    addb $('A' - 10), %cl
    jmp .ctx_rip_nib9_print
.ctx_rip_nib9_digit:
    addb $'0', %cl
.ctx_rip_nib9_print:
    movb %cl, %al
    outb %al, %dx

    popq %rax
    pushq %rax

    /* nibble 10 (bits 23-20) */
    movq %rax, %rcx
    shrq $20, %rcx
    andb $0xF, %cl
    cmpb $10, %cl
    jl .ctx_rip_nib10_digit
    addb $('A' - 10), %cl
    jmp .ctx_rip_nib10_print
.ctx_rip_nib10_digit:
    addb $'0', %cl
.ctx_rip_nib10_print:
    movb %cl, %al
    outb %al, %dx

    popq %rax
    pushq %rax

    /* nibble 11 (bits 19-16) */
    movq %rax, %rcx
    shrq $16, %rcx
    andb $0xF, %cl
    cmpb $10, %cl
    jl .ctx_rip_nib11_digit
    addb $('A' - 10), %cl
    jmp .ctx_rip_nib11_print
.ctx_rip_nib11_digit:
    addb $'0', %cl
.ctx_rip_nib11_print:
    movb %cl, %al
    outb %al, %dx

    movb $'>', %al          /* > = end of context RIP */
    outb %al, %dx

    popq %rax
    popq %rdx

    /* Debug: Check if RIP is NULL */
    testq %rax, %rax
    jnz .rip_ok
    /* RIP is NULL! Print '!' and halt */
    pushq %rdx
    movw $SERIAL_PORT, %dx
    movb $'!', %al
    outb %al, %dx
    popq %rdx
    hlt
.rip_ok:

    movq %rax, 168(%rdi)    /* frame->rip */
    movq 72(%rsi), %rax     /* context.cs */
    movq %rax, 176(%rdi)    /* frame->cs */
    movq 64(%rsi), %rax     /* context.rflags */

    /* Ensure reserved bit 1 is always set (required by x86-64) AND force
     * IF=1 so the thread starts with interrupts enabled.
     *
     * Threads initialize context.rflags = RFLAGS_KERNEL_INIT = 0x2 (IF=0),
     * but when a thread is first scheduled via the IRQ path it takes this
     * path and resumes with IF=0.  Since fut_malloc/fut_free preserve the
     * current IF state rather than unconditionally re-enabling interrupts,
     * the thread runs indefinitely with IF=0 — the timer can never preempt
     * it, causing the whole system to hang if the thread blocks.
     *
     * The cooperative path always resumes with sti (IF=1), so we match that
     * behaviour here by forcing IF=1 in the IRETQ frame. */
    orq $0x202, %rax        /* Ensure bit 1 (reserved) + bit 9 (IF) are set */
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
    movw $SERIAL_PORT, %dx
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
    movw $SERIAL_PORT, %dx
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

    popq %rax               /* Restore full RIP for more nibbles */
    pushq %rax

    /* Print nibble 3 (bits 51-48) */
    shrq $48, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib3_digit
    addb $('A' - 10), %al
    jmp .rip_nib3_print
.rip_nib3_digit:
    addb $'0', %al
.rip_nib3_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 4 (bits 47-44) */
    shrq $44, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib4_digit
    addb $('A' - 10), %al
    jmp .rip_nib4_print
.rip_nib4_digit:
    addb $'0', %al
.rip_nib4_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 5 (bits 43-40) */
    shrq $40, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib5_digit
    addb $('A' - 10), %al
    jmp .rip_nib5_print
.rip_nib5_digit:
    addb $'0', %al
.rip_nib5_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 6 (bits 39-36) */
    shrq $36, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib6_digit
    addb $('A' - 10), %al
    jmp .rip_nib6_print
.rip_nib6_digit:
    addb $'0', %al
.rip_nib6_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 7 (bits 35-32) */
    shrq $32, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib7_digit
    addb $('A' - 10), %al
    jmp .rip_nib7_print
.rip_nib7_digit:
    addb $'0', %al
.rip_nib7_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 8 (bits 31-28) */
    shrq $28, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib8_digit
    addb $('A' - 10), %al
    jmp .rip_nib8_print
.rip_nib8_digit:
    addb $'0', %al
.rip_nib8_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 9 (bits 27-24) */
    shrq $24, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib9_digit
    addb $('A' - 10), %al
    jmp .rip_nib9_print
.rip_nib9_digit:
    addb $'0', %al
.rip_nib9_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 10 (bits 23-20) */
    shrq $20, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib10_digit
    addb $('A' - 10), %al
    jmp .rip_nib10_print
.rip_nib10_digit:
    addb $'0', %al
.rip_nib10_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 11 (bits 19-16) */
    shrq $16, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib11_digit
    addb $('A' - 10), %al
    jmp .rip_nib11_print
.rip_nib11_digit:
    addb $'0', %al
.rip_nib11_print:
    outb %al, %dx

    popq %rax
    pushq %rax

    /* Print nibble 12 (bits 15-12) */
    shrq $12, %rax
    andb $0xF, %al
    cmpb $10, %al
    jl .rip_nib12_digit
    addb $('A' - 10), %al
    jmp .rip_nib12_print
.rip_nib12_digit:
    addb $'0', %al
.rip_nib12_print:
    outb %al, %dx

    popq %rax               /* Final restore of RIP value */

    movb $'}', %al          /* } = end restore frame debug */
    outb %al, %dx

    popq %rdx
    popq %rax

    /* Step 3: Copy saved frame to next thread's kernel stack.
     * CRITICAL: Do NOT overwrite prev's interrupt frame on the stack!
     * If prev is later cooperatively restored, it returns through the ISR
     * stub which pops the interrupt frame. Overwriting it causes GPF. */
    movq 16(%r13), %rdi     /* next->stack_base */
    addq 24(%r13), %rdi     /* + stack_size -> top of stack */
    subq $208, %rdi         /* room for 208-byte interrupt frame */
    movq %rdi, %r14         /* update R14 (used by movq %r14, %rsp later) */
    movq %r11, %rsi         /* src = next->irq_frame */
    movq $26, %rcx          /* 208 bytes / 8 = 26 qwords */
    cld
    rep movsq

    /* IMPORTANT: Do NOT clear IF in RFLAGS!
     *
     * Previously, we cleared IF to "give the thread time to execute before
     * getting immediately re-interrupted". However, this breaks preemption:
     * - If IF=0, timer interrupts don't fire
     * - The thread runs without being preempted
     * - Other threads starve, including sleeping threads that should wake up
     *
     * The saved frame already has IF=1 (set by the CPU when the interrupt fired).
     * We preserve that so the thread can be preempted again. */

    /* CRITICAL FIX: Clear next->irq_frame after copying to prevent reusing stale frames.
     * When this thread gets preempted next time, we want to save the ACTUAL interrupt
     * state, not reuse this old frame. The frame we just copied represents where the
     * thread WAS, not where it will be when next interrupted.
     *
     * Without this fix, threads can get "stuck" with old RIP values because the saved
     * frame never gets updated when they make progress. */
    movq $0, 720(%r13)      /* next->irq_frame = NULL */

2:
    /* Step 4: Restore FPU state from next thread's context */
    /* context is at offset 48, fx_area is at offset 160 within context */
    /* So fx_area is at 48 + 160 = 208 */

    /* Debug: Check if R13 (next thread pointer) is valid */
    testq %r13, %r13
    jnz .r13_ok
    /* R13 is NULL! Print '?' and halt */
    pushq %rdx
    movw $SERIAL_PORT, %dx
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
    movw $SERIAL_PORT, %dx
    movb $'@', %al
    outb %al, %dx
    popq %rdx
    hlt
.rax_ok:

    fxrstor64 (%rax)

    /* Debug: FPU restore successful, print '#' */
    pushq %rdx
    movw $SERIAL_PORT, %dx
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

    /* CRITICAL: Skip FS segment loading entirely!
     * In 64-bit mode, loading a segment selector (mov fs, ax) clears MSR_FS_BASE
     * to the GDT descriptor base (which is 0 for standard data segments).
     * We manage FS_BASE via MSR in the scheduler (wrmsr MSR_FS_BASE), so loading
     * the selector would corrupt our TLS base.
     * Just pop and discard the FS value from the interrupt frame. */
    addq $8, %rsp           /* Skip the FS value - don't load it */

    /* Validate and load ES */
    movq 0(%rsp), %rax      /* Peek at ES value without popping */
    testw %ax, %ax          /* Check if NULL selector (0) */
    jz .es_skip             /* NULL is valid, skip loading */
    cmpw $0x10, %ax         /* Check if valid kernel segment */
    je .es_ok
    cmpw $0x1b, %ax         /* Check if valid user data segment (0x18|RPL=3) */
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
    cmpw $0x1b, %ax         /* Check if valid user data segment (0x18|RPL=3) */
    je .ds_ok
    /* DS value is invalid! Skip loading it and use current DS */
.ds_skip:
    addq $8, %rsp           /* Skip the DS value */
    jmp .segments_done
.ds_ok:
    popq %rax               /* Pop ds */
    movw %ax, %ds

.segments_done:

    /* CRITICAL: Write MSR_FS_BASE for TLS support.
     * This must be done in assembly because the C code writes the MSR
     * BEFORE the context switch, but loading segment registers can
     * clear the MSR value. By writing it here (after segment restore,
     * before GPR restore), we ensure it's correct when the thread runs.
     * r13 still contains the next thread pointer at this point.
     * Thread struct layout: fs_base at offset 728.
     * Note: GS_BASE is NOT restored here — GS is used for per-CPU data
     * (no SWAPGS), so only the kernel's GS_BASE must persist. */
    pushq %rax
    pushq %rcx
    pushq %rdx
    movq 728(%r13), %rax    /* Load fs_base from thread struct (offset 728) */
    movl $0xC0000100, %ecx  /* MSR_FS_BASE */
    movq %rax, %rdx
    shrq $32, %rdx          /* EDX = high 32 bits */
    /* EAX already has low 32 bits */
    wrmsr
    popq %rdx
    popq %rcx
    popq %rax

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
    movw $SERIAL_PORT, %dx
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
    /* Valid CS values: 0x08 (kernel), 0x23 (user code with RPL=3) */
    movq 24(%rsp), %rax        /* Get CS from stack */
    cmpq $0x08, %rax          /* Is it kernel CS? */
    je .cs_iretq_ok
    cmpq $0x23, %rax          /* Is it user CS (0x20 | 3)? */
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
    movq $0x23, 24(%rsp)      /* CS = user code (0x20 | 3) */
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
    movw $SERIAL_PORT, %dx
    movb $'>', %al
    outb %al, %dx

    /* CRITICAL FIX: Validate SS in IRETQ frame.
     * In x86-64 mode, IRETQ always pops SS from RSP+32.
     * Invalid SS values cause #GP. Valid values: 0, 0x10 (kernel), 0x1b (user).
     * Stack layout after our push: [RSP+0]=RAX, [RSP+8]=RDX
     * IRETQ frame starts at RSP+16: RIP(+16), CS(+24), RFLAGS(+32), RSP(+40), SS(+48) */
    movq 48(%rsp), %rax     /* Get SS from IRETQ frame */

    /* Check if SS is a valid selector: 0, 0x10, or 0x1b */
    testw %ax, %ax          /* Is SS zero? */
    jz .ss_iretq_ok         /* Zero is valid (kernel can use NULL SS in 64-bit mode) */
    cmpw $0x10, %ax         /* Is SS kernel data segment? */
    je .ss_iretq_ok
    cmpw $0x1b, %ax         /* Is SS user data segment (0x18|RPL=3)? */
    je .ss_iretq_ok

    /* SS is INVALID - fix it! */
    movb $'!', %al          /* ! = Invalid SS detected, fixing! */
    outb %al, %dx

    /* Determine correct SS value based on CS (kernel vs user) */
    movq 24(%rsp), %rax     /* Get CS from frame */
    cmpq $0x08, %rax        /* Is it kernel CS? */
    je .fix_kernel_ss
    /* User CS - set SS to user data segment 0x1b */
    movq $0x1b, %rax
    jmp .write_fixed_ss
.fix_kernel_ss:
    /* Kernel CS - set SS to kernel data segment 0x10 */
    movq $0x10, %rax
.write_fixed_ss:
    movq %rax, 48(%rsp)     /* Write fixed SS back to frame */

.ss_iretq_ok:
    popq %rdx
    popq %rax

    /* CRITICAL: Send EOI to LAPIC before IRETQ.
     *
     * This function was called from fut_timer_irq() which was called from irq0_timer.
     * If we do IRETQ without sending EOI, the LAPIC will have the timer interrupt
     * stuck in "in-service" state, preventing any future timer interrupts.
     *
     * We write 0 directly to LAPIC_REG_EOI (base + 0xB0).
     * The LAPIC base is mapped at a fixed virtual address. We use the
     * lapic_base symbol which contains the mapped virtual address.
     *
     * NOTE: This is safe because we're still in kernel mode with kernel page tables.
     * The LAPIC is mapped at its physical address 0xFEE00000 to a kernel VA.
     */
    pushq %rax
    pushq %rcx
    /* Get LAPIC base from the global variable */
    movq lapic_base(%rip), %rcx
    testq %rcx, %rcx        /* Check if LAPIC is initialized */
    jz .skip_eoi            /* Skip if NULL */
    /* Write 0 to EOI register (offset 0xB0 / 4 = index 0x2C) */
    movl $0, 0xB0(%rcx)
.skip_eoi:
    popq %rcx
    popq %rax

    /* CRITICAL: Clear fut_in_interrupt and fut_current_frame before IRETQ.
     *
     * fut_switch_context_irq is called from fut_schedule() inside the timer
     * ISR. Since we IRETQ directly to the next thread (never returning to
     * the timer ISR), the timer ISR's cleanup code (which normally clears
     * these globals) is never reached. If left stale:
     *
     * - fut_in_interrupt = 1 causes the scheduler to incorrectly use the
     *   IRETQ path for threads that were saved cooperatively (e.g., INT 0x80
     *   syscalls that sleep). This saves the INT 0x80 frame (RAX=syscall
     *   number) as irq_frame, and when restored via IRETQ, the syscall
     *   number is returned to userspace instead of the actual result.
     *
     * - fut_current_frame pointing to the old timer frame (on the previous
     *   thread's stack) would be used by the next fut_schedule() call as
     *   the frame to save, even though it belongs to a different thread. */
    movb $0, fut_in_interrupt(%rip)
    movq $0, fut_current_frame(%rip)

    iretq

/* ----------------------------------------------------------------
 * .kernel_coop_restore — cooperative restore for kernel threads
 *
 * Called when the next thread runs in kernel mode (irq_frame->cs == 0x08
 * or context.cs == 0x08, which is always the case for kernel threads).
 *
 * Why: same-privilege IRETQ does NOT restore RSP.  Placing the IRETQ frame
 * at stack_top-208 and executing IRETQ always yields RSP=stack_top-16,
 * completely discarding the thread's actual call-stack depth and corrupting
 * its stack frame.
 *
 * Instead we do what fut_switch_context does: load next's cooperative
 * context (rsp, rip, and callee-saved registers), push context.rip as a
 * return address, and `sti; ret`.  This "returns" from fut_switch_context_irq
 * back into fut_schedule → fut_timer_tick → fut_timer_irq → ISR stub, which
 * then executes its own IRETQ to bring the thread back to the point at which
 * it was originally interrupted — with the fully correct RSP.
 *
 * For freshly-started threads (no prior preemption), context.rip points to
 * fut_thread_trampoline and context.rsp = aligned_top-8.  After `ret` the
 * trampoline runs from scratch on a clean stack.
 *
 * Registers on entry (from fut_switch_context_irq):
 *   r12 = prev thread pointer
 *   r13 = next thread pointer
 *   r14 = original interrupt frame pointer (prev's frame)
 *   r11 = next->irq_frame (may be NULL)
 * ---------------------------------------------------------------- */
.kernel_coop_restore:
    /* Debug: print 'G' (Grounded restore, avoiding broken IRETQ path) */
    pushq %rdx
    movw $SERIAL_PORT, %dx
    movb $'G', %al
    outb %al, %dx
    popq %rdx

    /* Clear next->irq_frame so the stale saved frame is not reused. */
    movq $0, 720(%r13)      /* next->irq_frame = NULL */

    /* Restore next thread's FPU/SSE state from context.fx_area (thread+208). */
    leaq 208(%r13), %rax
    fxrstor64 (%rax)

    /* Write FS_BASE MSR for next thread's TLS (thread.fs_base at offset 728). */
    pushq %rax
    pushq %rcx
    pushq %rdx
    movq 728(%r13), %rax
    movl $0xC0000100, %ecx  /* MSR_FS_BASE */
    movq %rax, %rdx
    shrq $32, %rdx
    wrmsr
    popq %rdx
    popq %rcx
    popq %rax

    /* Clear fut_current_frame so a nested timer interrupt during the cooperative
     * unwind does not incorrectly reuse prev's stale ISR frame pointer. */
    movq $0, fut_current_frame(%rip)

    /* Send EOI to LAPIC and clear fut_in_interrupt — mirrors the IRETQ path
     * (lines immediately before `iretq`).
     *
     * Why EOI here: for FRESH kernel threads (context.rip == trampoline) there
     * is no ISR-unwind chain, so nobody else will call lapic_send_eoi().  The
     * LAPIC keeps the timer vector set in its ISR register, which suppresses
     * all future timer interrupts — the system hangs with 0/N tests.
     *
     * For NON-FRESH kernel threads the ISR unwind (fut_timer_irq → lapic_send_eoi)
     * will write to EOI a second time; that write is a safe no-op if the ISR
     * bit is already clear, or it correctly acknowledges the next timer tick
     * that arrived in the window between the two writes. */
    pushq %rax
    pushq %rcx
    movq lapic_base(%rip), %rcx
    testq %rcx, %rcx
    jz .kernel_coop_skip_eoi
    movl $0, 0xB0(%rcx)             /* Write 0 to LAPIC EOI register (offset 0xB0) */
.kernel_coop_skip_eoi:
    popq %rcx
    popq %rax

    /* Clear fut_in_interrupt — same reason as IRETQ path.  The stale 1 would
     * cause fut_schedule to use the IRETQ branch on the next voluntary switch,
     * then find fut_current_frame==NULL and fall through to the cooperative
     * path where it sends a spurious LAPIC EOI.  Clearing it here is simpler
     * and matches what the IRETQ path does at lines 1314-1315. */
    movb $0, fut_in_interrupt(%rip)

    /* Load next's cooperative context.
     * Context layout (all offsets relative to thread base, context at +48):
     *   r15(+48) r14(+56) r13(+64) r12(+72) rbx(+80) rbp(+88)
     *   rip(+96) rsp(+104) rflags(+112) cs(+120) ss(+128)
     *   ds(+136) es(+144) fs(+152) gs(+160)
     *   rdi(+168) rsi(+176) rdx(+184) rcx(+192) rax(+200)
     *
     * We keep r13 (thread ptr) alive until after we've read everything, then
     * overwrite it last. r10/r11 are used as temporaries. */
    leaq 48(%r13), %r11     /* r11 = &next->context */

    /* Stash rip and rsp before we overwrite r13/r14. */
    movq 48(%r11), %r10     /* r10 = context.rip */
    movq 56(%r11), %r14     /* r14 = context.rsp (caller's RSP as after a ret) */

    /* Load RFLAGS with IF cleared; sti just before ret re-enables interrupts. */
    movq 64(%r11), %rax
    andq $~0x200, %rax      /* Clear IF */
    pushq %rax
    popfq

    /* Restore callee-saved and argument registers. */
    movq  0(%r11), %r15
    movq 24(%r11), %r12
    movq 32(%r11), %rbx
    movq 40(%r11), %rbp
    movq 120(%r11), %rdi
    movq 128(%r11), %rsi
    movq 136(%r11), %rdx
    movq 144(%r11), %rcx
    movq 152(%r11), %rax

    /* Switch to next thread's kernel stack. */
    movq %r14, %rsp

    /* Push context.rip so that `ret` jumps to it (the return point from
     * fut_switch_context_irq inside next's fut_schedule call). */
    pushq %r10

    /* Load r14 and r13 now that we no longer need them as temporaries. */
    movq  8(%r11), %r14     /* context.r14 */
    movq 16(%r11), %r13     /* context.r13 — destroys thread ptr, no longer needed */

    /* Zero caller-saved scratch registers. */
    xorq %r10, %r10
    xorq %r11, %r11

    /* Re-enable interrupts and return to context.rip.
     * The sti-shadow guarantees the ret instruction executes before any
     * pending interrupt is delivered, ensuring clean stack state. */
    sti
    ret

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

    /* Set up IRET frame for user mode
     * GDT layout: user data at 0x18 (selector 0x1B), user code at 0x20 (selector 0x23) */
    pushq $0x18 | 3                     /* User data segment (SS) with RPL=3 = 0x1B */
    pushq %rsi                          /* User stack pointer (RSP) */
    pushq $0x200                        /* RFLAGS (IF=1) */
    pushq $0x20 | 3                     /* User code segment (CS) with RPL=3 = 0x23 */
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

    /* Set user data segments (but DON'T touch FS or GS - they use MSRs!) */
    movw $(0x18 | 3), %ax               /* User data selector = 0x1B */
    movw %ax, %ds
    movw %ax, %es
    /* FS intentionally NOT loaded - must preserve MSR_FS_BASE for TLS support */
    /* GS intentionally NOT loaded - must preserve GS_BASE MSR for per-CPU data */

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
