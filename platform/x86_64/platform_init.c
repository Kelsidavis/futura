/*
 * Futura OS - x86_64 Platform Initialization
 * Copyright (C) 2025 Futura OS Project
 *
 * Platform-specific initialization for x86_64 architecture
 */

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/regs.h>
#include <platform/x86_64/gdt.h>
#include <platform/x86_64/memory/pat.h>
#include <platform/x86_64/msr.h>
#include <platform/x86_64/cpu.h>
#include <kernel/fut_mm.h>
#include <kernel/fb.h>
#include <kernel/trap.h>
#include <kernel/boot_args.h>
#include <kernel/fut_percpu.h>
#include <kernel/platform_hooks.h>
#include <kernel/fut_sched.h>

/* Serial port definitions for debugging */
#define SERIAL_PORT_COM1 0x3F8
#define SERIAL_DATA(port) (port)
#define SERIAL_INTR(port) (port + 1)
#define SERIAL_FIFO_CTRL(port) (port + 2)
#define SERIAL_LINE_CTRL(port) (port + 3)
#define SERIAL_MODEM_CTRL(port) (port + 4)
#define SERIAL_LINE_STATUS(port) (port + 5)

/* PIC (Programmable Interrupt Controller) definitions */
#define PIC1_COMMAND 0x20
#define PIC1_DATA 0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA 0xA1

#define ICW1_ICW4 0x01      /* ICW4 needed */
#define ICW1_INIT 0x10      /* Initialization */
#define ICW4_8086 0x01      /* 8086 mode */

#define PIC_EOI 0x20        /* End of Interrupt */

#define INT_SYSCALL 128

struct multiboot_tag {
    uint32_t type;
    uint32_t size;
} __attribute__((packed));

#define MULTIBOOT_TAG_TYPE_CMDLINE 1

/* PIT (Programmable Interval Timer) definitions */
#define PIT_CHANNEL0 0x40
#define PIT_COMMAND 0x43
#define PIT_FREQUENCY 1193182
#define TIMER_HZ 100        /* 100 Hz timer */

/* I/O port operations */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void io_wait(void) {
    outb(0x80, 0);
}

/* HAL wrappers for use by other subsystems */
void hal_outb(uint16_t port, uint8_t value) {
    outb(port, value);
}

uint8_t hal_inb(uint16_t port) {
    return inb(port);
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

void hal_outw(uint16_t port, uint16_t value) {
    outw(port, value);
}

uint16_t hal_inw(uint16_t port) {
    return inw(port);
}

static _Atomic bool serial_ready = false;

bool fut_serial_ready(void) {
    return atomic_load_explicit(&serial_ready, memory_order_acquire);
}

/* External declarations */
extern void fut_gdt_load(void);
extern void fut_idt_load(void);
extern void fut_idt_set_entry(uint8_t vector, uint64_t handler,
                               uint16_t selector, uint8_t flags);
extern void fut_enable_interrupts(void);
extern void fut_disable_interrupts(void);

/* External ISR/IRQ handlers */
extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);

extern void irq0(void);
extern void irq1(void);
extern void irq2(void);
extern void irq3(void);
extern void irq4(void);
extern void irq5(void);
extern void irq6(void);
extern void irq7(void);
extern void irq8(void);
extern void irq9(void);
extern void irq10(void);
extern void irq11(void);
extern void irq12(void);
extern void irq13(void);
extern void irq14(void);
extern void irq15(void);

extern void irq0_timer(void);
extern void isr_syscall_int80_stub(void);

/* Kernel main function */
extern void fut_kernel_main(void);

/* Forward declarations for init functions */
static void fut_serial_init(void);
static void fut_pic_init(void);
static void fut_pit_init(void);
static void fut_idt_init(void);

/* Serial debugging functions */
static void fut_serial_init(void) {
    /* Disable all interrupts */
    outb(SERIAL_INTR(SERIAL_PORT_COM1), 0x00);

    /* Enable DLAB (set baud rate divisor) */
    outb(SERIAL_LINE_CTRL(SERIAL_PORT_COM1), 0x80);

    /* Set divisor to 3 (38400 baud) */
    outb(SERIAL_DATA(SERIAL_PORT_COM1), 0x03);
    outb(SERIAL_INTR(SERIAL_PORT_COM1), 0x00);

    /* 8 bits, no parity, one stop bit */
    outb(SERIAL_LINE_CTRL(SERIAL_PORT_COM1), 0x03);

    /* Enable FIFO, clear, 14-byte threshold */
    outb(SERIAL_FIFO_CTRL(SERIAL_PORT_COM1), 0xC7);

    /* Enable IRQs, RTS/DSR set */
    outb(SERIAL_MODEM_CTRL(SERIAL_PORT_COM1), 0x0B);

    atomic_store_explicit(&serial_ready, true, memory_order_release);
}

void fut_serial_putc(char c) {
    /* Wait for transmit buffer to be empty */
    while ((inb(SERIAL_LINE_STATUS(SERIAL_PORT_COM1)) & 0x20) == 0)
        ;
    outb(SERIAL_DATA(SERIAL_PORT_COM1), c);

    /* Also write to framebuffer console if available */
    extern void fb_console_putc(char c);
    fb_console_putc(c);
}

int fut_serial_getc(void) {
    /* Check if data is available (bit 0 of line status register) */
    if ((inb(SERIAL_LINE_STATUS(SERIAL_PORT_COM1)) & 0x01) == 0) {
        return -1;  /* No data available */
    }
    /* Read and return the character */
    return (int)inb(SERIAL_DATA(SERIAL_PORT_COM1));
}

int fut_serial_getc_blocking(void) {
    /* Wait for data to be available, yielding to scheduler when idle */
    while ((inb(SERIAL_LINE_STATUS(SERIAL_PORT_COM1)) & 0x01) == 0) {
        /* Yield to let other threads run instead of spinning.
         * Only yield if scheduler is started (avoids issues during early boot). */
        if (fut_sched_is_started()) {
            fut_schedule();
        } else {
            /* During early boot, use pause hint for CPU efficiency */
            __asm__ volatile("pause" ::: "memory");
        }
    }
    /* Read and return the character */
    return (int)inb(SERIAL_DATA(SERIAL_PORT_COM1));
}

void fut_serial_flush_input(void) {
    /* Read and discard all pending characters from the serial input buffer */
    while ((inb(SERIAL_LINE_STATUS(SERIAL_PORT_COM1)) & 0x01) != 0) {
        (void)inb(SERIAL_DATA(SERIAL_PORT_COM1));  /* Discard the character */
    }
}

void fut_serial_puts(const char *str) {
    while (*str) {
        if (*str == '\n')
            fut_serial_putc('\r');
        fut_serial_putc(*str++);
    }
}

/* Alias for serial_puts used by kernel code */
void serial_puts(const char *str) {
    fut_serial_puts(str);
}

/* Printf implementation with format string support */
static void print_num(uint64_t num, int base, int uppercase, int sign, int width) {
    char buf[32];
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;
    int negative = 0;

    /* Handle signed numbers */
    if (sign && (int64_t)num < 0) {
        negative = 1;
        num = -(int64_t)num;
    }

    /* Convert to string (reverse order) */
    if (num == 0) {
        buf[i++] = '0';
    } else {
        while (num > 0) {
            buf[i++] = digits[num % base];
            num /= base;
        }
    }

    /* Add sign */
    if (negative) {
        buf[i++] = '-';
    }

    /* Pad with spaces if needed */
    while (i < width) {
        buf[i++] = ' ';
    }

    /* Print in correct order */
    while (i > 0) {
        fut_serial_putc(buf[--i]);
    }
}

void fut_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    while (*fmt) {
        if (*fmt == '%') {
            fmt++;

            /* Parse flags (currently only '+' supported for signed integers) */
            int show_plus = 0;
            while (*fmt == '+' || *fmt == ' ') {
                if (*fmt == '+') {
                    show_plus = 1;
                }
                fmt++;
            }

            /* Parse width */
            int width = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }

            /* Parse length modifiers */
            int is_long = 0;
            int is_longlong = 0;
            int is_size_t = 0;
            if (*fmt == 'l') {
                fmt++;
                is_long = 1;
                if (*fmt == 'l') {
                    fmt++;
                    is_longlong = 1;
                }
            } else if (*fmt == 'z') {
                /* size_t / ssize_t */
                fmt++;
                is_size_t = 1;
            }

            /* Process format specifier */
            switch (*fmt) {
                case 'd':
                case 'i': {
                    int64_t val;
                    if (is_longlong) {
                        val = va_arg(args, int64_t);
                    } else if (is_long || is_size_t) {
                        val = va_arg(args, long);
                    } else {
                        val = va_arg(args, int);
                    }
                    if (show_plus && val >= 0) {
                        fut_serial_putc('+');
                        if (width > 0) {
                            width--;
                        }
                    }
                    print_num((uint64_t)val, 10, 0, 1, width);
                    break;
                }
                case 'u': {
                    uint64_t val;
                    if (is_longlong) {
                        val = va_arg(args, uint64_t);
                    } else if (is_long || is_size_t) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    print_num(val, 10, 0, 0, width);
                    break;
                }
                case 'x': {
                    uint64_t val;
                    if (is_longlong) {
                        val = va_arg(args, uint64_t);
                    } else if (is_long || is_size_t) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    print_num(val, 16, 0, 0, width);
                    break;
                }
                case 'X': {
                    uint64_t val;
                    if (is_longlong) {
                        val = va_arg(args, uint64_t);
                    } else if (is_long || is_size_t) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    print_num(val, 16, 1, 0, width);
                    break;
                }
                case 'p': {
                    void *ptr = va_arg(args, void *);
                    fut_serial_puts("0x");
                    print_num((uint64_t)ptr, 16, 0, 0, 16);
                    break;
                }
                case 's': {
                    const char *str = va_arg(args, const char *);
                    if (str) {
                        fut_serial_puts(str);
                    } else {
                        fut_serial_puts("(null)");
                    }
                    break;
                }
                case 'c': {
                    char c = (char)va_arg(args, int);
                    fut_serial_putc(c);
                    break;
                }
                case '%': {
                    fut_serial_putc('%');
                    break;
                }
                default: {
                    fut_serial_putc('%');
                    fut_serial_putc(*fmt);
                    break;
                }
            }
            fmt++;
        } else {
            fut_serial_putc(*fmt);
            fmt++;
        }
    }

    va_end(args);
}

/* ============================================================
 *   Deferred Reschedule Tracking (for IRQ context)
 * ============================================================ */

static _Bool reschedule_pending = 0;

_Bool fut_reschedule_pending(void) {
    return reschedule_pending;
}

void fut_clear_reschedule(void) {
    reschedule_pending = 0;
}

void fut_request_reschedule(void) {
    reschedule_pending = 1;
}

/* PIC initialization */
static void fut_pic_init(void) {
    /* Start initialization sequence */
    outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();

    /* ICW2: Remap IRQs */
    outb(PIC1_DATA, 32);    /* IRQ0-7 -> INT 32-39 */
    io_wait();
    outb(PIC2_DATA, 40);    /* IRQ8-15 -> INT 40-47 */
    io_wait();

    /* ICW3: Cascade identity */
    outb(PIC1_DATA, 0x04);  /* Slave on IRQ2 */
    io_wait();
    outb(PIC2_DATA, 0x02);  /* Cascade identity */
    io_wait();

    /* ICW4: 8086 mode */
    outb(PIC1_DATA, ICW4_8086);
    io_wait();
    outb(PIC2_DATA, ICW4_8086);
    io_wait();

    /* Mask all IRQs initially - they will be unmasked individually when ready */
    /* Don't restore firmware masks as they may have interrupts enabled too early */
    outb(PIC1_DATA, 0xFF);  /* Mask all IRQs on master PIC */
    outb(PIC2_DATA, 0xFF);  /* Mask all IRQs on slave PIC */
}

/**
 * Disable the legacy 8259 PIC.
 * Must be called when switching to APIC mode to prevent conflicts.
 */
void fut_pic_disable(void) {
    /* Mask all interrupts on both PICs */
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
}

void fut_pic_send_eoi(uint8_t irq) {
    if (irq >= 8)
        outb(PIC2_COMMAND, PIC_EOI);
    outb(PIC1_COMMAND, PIC_EOI);
}

void fut_irq_send_eoi(uint8_t irq) {
    fut_pic_send_eoi(irq);
}

void fut_irq_enable(uint8_t irq) {
    uint16_t port;
    uint8_t value;

    if (irq < 8) {
        port = PIC1_DATA;
    } else {
        port = PIC2_DATA;
        irq -= 8;
    }

    value = inb(port) & ~(1 << irq);
    outb(port, value);
}

void fut_irq_disable(uint8_t irq) {
    uint16_t port;
    uint8_t value;

    if (irq < 8) {
        port = PIC1_DATA;
    } else {
        port = PIC2_DATA;
        irq -= 8;
    }

    value = inb(port) | (1 << irq);
    outb(port, value);
}

/* PIT initialization */
static void fut_pit_init(void) {
    uint32_t divisor = PIT_FREQUENCY / TIMER_HZ;

    /* Set command byte: channel 0, rate generator mode */
    outb(PIT_COMMAND, 0x36);

    /* Set frequency divisor */
    outb(PIT_CHANNEL0, divisor & 0xFF);
    outb(PIT_CHANNEL0, (divisor >> 8) & 0xFF);
}

/* IDT initialization */
static void fut_idt_init(void) {
    /* IDT flags: Present, DPL=0, Type=0xE (64-bit interrupt gate) */
    uint8_t flags = 0x8E;

    /* Install CPU exception handlers (ISR 0-31) */
    fut_idt_set_entry(0, (uint64_t)isr0, 0x08, flags);
    fut_idt_set_entry(1, (uint64_t)isr1, 0x08, flags);
    fut_idt_set_entry(2, (uint64_t)isr2, 0x08, flags);
    fut_idt_set_entry(3, (uint64_t)isr3, 0x08, flags);
    fut_idt_set_entry(4, (uint64_t)isr4, 0x08, flags);
    fut_idt_set_entry(5, (uint64_t)isr5, 0x08, flags);
    fut_idt_set_entry(6, (uint64_t)isr6, 0x08, flags);
    fut_idt_set_entry(7, (uint64_t)isr7, 0x08, flags);
    fut_idt_set_entry(8, (uint64_t)isr8, 0x08, flags);
    fut_idt_set_entry(9, (uint64_t)isr9, 0x08, flags);
    fut_idt_set_entry(10, (uint64_t)isr10, 0x08, flags);
    fut_idt_set_entry(11, (uint64_t)isr11, 0x08, flags);
    fut_idt_set_entry(12, (uint64_t)isr12, 0x08, flags);
    fut_idt_set_entry(13, (uint64_t)isr13, 0x08, flags);
    fut_idt_set_entry(14, (uint64_t)isr14, 0x08, flags);
    fut_idt_set_entry(15, (uint64_t)isr15, 0x08, flags);
    fut_idt_set_entry(16, (uint64_t)isr16, 0x08, flags);
    fut_idt_set_entry(17, (uint64_t)isr17, 0x08, flags);
    fut_idt_set_entry(18, (uint64_t)isr18, 0x08, flags);
    fut_idt_set_entry(19, (uint64_t)isr19, 0x08, flags);
    fut_idt_set_entry(20, (uint64_t)isr20, 0x08, flags);
    fut_idt_set_entry(21, (uint64_t)isr21, 0x08, flags);
    fut_idt_set_entry(22, (uint64_t)isr22, 0x08, flags);
    fut_idt_set_entry(23, (uint64_t)isr23, 0x08, flags);
    fut_idt_set_entry(24, (uint64_t)isr24, 0x08, flags);
    fut_idt_set_entry(25, (uint64_t)isr25, 0x08, flags);
    fut_idt_set_entry(26, (uint64_t)isr26, 0x08, flags);
    fut_idt_set_entry(27, (uint64_t)isr27, 0x08, flags);
    fut_idt_set_entry(28, (uint64_t)isr28, 0x08, flags);
    fut_idt_set_entry(29, (uint64_t)isr29, 0x08, flags);
    fut_idt_set_entry(30, (uint64_t)isr30, 0x08, flags);
    fut_idt_set_entry(31, (uint64_t)isr31, 0x08, flags);

    /* Install IRQ handlers (32-47) */
    fut_idt_set_entry(32, (uint64_t)irq0_timer, 0x08, flags);  /* Timer uses special handler */
    fut_idt_set_entry(33, (uint64_t)irq1, 0x08, flags);
    fut_idt_set_entry(34, (uint64_t)irq2, 0x08, flags);
    fut_idt_set_entry(35, (uint64_t)irq3, 0x08, flags);
    fut_idt_set_entry(36, (uint64_t)irq4, 0x08, flags);
    fut_idt_set_entry(37, (uint64_t)irq5, 0x08, flags);
    fut_idt_set_entry(38, (uint64_t)irq6, 0x08, flags);
    fut_idt_set_entry(39, (uint64_t)irq7, 0x08, flags);
    fut_idt_set_entry(40, (uint64_t)irq8, 0x08, flags);
    fut_idt_set_entry(41, (uint64_t)irq9, 0x08, flags);
    fut_idt_set_entry(42, (uint64_t)irq10, 0x08, flags);
    fut_idt_set_entry(43, (uint64_t)irq11, 0x08, flags);
    fut_idt_set_entry(44, (uint64_t)irq12, 0x08, flags);
    fut_idt_set_entry(45, (uint64_t)irq13, 0x08, flags);
    fut_idt_set_entry(46, (uint64_t)irq14, 0x08, flags);
    fut_idt_set_entry(47, (uint64_t)irq15, 0x08, flags);

    /* Install system call handler (128) with DPL=3 for user mode */
    fut_idt_set_entry(INT_SYSCALL, (uint64_t)isr_syscall_int80_stub, 0x08, 0xEE);

    /* Load IDT */
    fut_idt_load();

    /* Set up SYSCALL instruction support (x86_64 fast path) */
    extern void isr_syscall_fastpath(void);

    #define MSR_EFER          0xC0000080
    #define MSR_STAR          0xC0000081
    #define MSR_LSTAR         0xC0000082
    #define MSR_FMASK         0xC0000084
    /* EFER_SCE is defined in regs.h */

    /* IA32_LSTAR: Entry point for SYSCALL instruction */
    uint64_t lstar_address = (uint64_t)isr_syscall_fastpath;
    wrmsr(MSR_LSTAR, lstar_address);

    /* IA32_STAR: Segment selectors for SYSCALL/SYSRET
     * [31:16] = kernel CS (we use 0x08 for kernel code segment)
     * [47:32] = user CS for SYSRET (CS-16 is DS for 64-bit, so if CS=0x23, then 0x23-16=0x1b is unused but still works)
     */
    uint64_t star = ((0x08ULL) << 32) | ((0x23ULL) << 48);
    wrmsr(MSR_STAR, star);

    /* IA32_FMASK: Flags to clear on SYSCALL entry
     * Clear IF (0x200) to disable interrupts during syscall handling
     */
    uint64_t fmask = 0x200;  /* IF flag - interrupts disabled on entry */
    wrmsr(MSR_FMASK, fmask);

    /* Enable SYSCALL instruction in EFER MSR */
    uint64_t efer = rdmsr(MSR_EFER);
    efer |= EFER_SCE;  /* Enable SYSCALL/SYSRET */
    wrmsr(MSR_EFER, efer);
}

/* Main platform initialization entry point */
__attribute__((unused))
static void serial_put_hex32(uint32_t value) {
    char buf[9];
    for (int i = 7; i >= 0; --i) {
        uint32_t nibble = (value >> (i * 4)) & 0xF;
        buf[7 - i] = (char)(nibble < 10 ? ('0' + nibble) : ('A' + nibble - 10));
    }
    buf[8] = '\0';
    fut_serial_puts(buf);
}

/* ============================================================
 *   Platform Hook Implementations (for kernel/kernel_main.c)
 * ============================================================ */

#include <kernel/platform_hooks.h>

/**
 * arch_early_init - x86_64 early platform initialization
 * Called before any kernel subsystems are initialized.
 * Note: fut_platform_init already does this, so this is a no-op.
 */
void arch_early_init(void) {
    /* fut_platform_init handles early init before calling kernel_main */
}

/**
 * arch_memory_config - Provide x86_64 memory layout
 */
void arch_memory_config(uintptr_t *ram_start, uintptr_t *ram_end, size_t *heap_size) {
    extern char _kernel_end[];
    extern char boot_ptables_start[];
    extern char boot_ptables_end[];

    /* x86_64 memory layout (higher-half kernel) */
    uintptr_t kernel_virt_end = (uintptr_t)_kernel_end;
    uintptr_t mem_base = (kernel_virt_end + 0xFFF) & ~0xFFFULL;  /* Page-align */

    /* Skip legacy VGA/BIOS hole below 1 MiB */
    uintptr_t min_phys = KERNEL_VIRTUAL_BASE + 0x100000ULL;
    if (mem_base < min_phys) {
        mem_base = min_phys;
    }

    /* Convert to physical addresses */
    extern phys_addr_t pmap_virt_to_phys(uintptr_t vaddr);
    phys_addr_t mem_base_phys = pmap_virt_to_phys(mem_base);
    phys_addr_t boot_ptables_start_phys = pmap_virt_to_phys((uintptr_t)boot_ptables_start);
    phys_addr_t boot_ptables_end_phys = pmap_virt_to_phys((uintptr_t)boot_ptables_end);
    boot_ptables_start_phys &= ~(PAGE_SIZE - 1ULL);
    boot_ptables_end_phys = PAGE_ALIGN_UP(boot_ptables_end_phys);
    if (mem_base_phys < boot_ptables_end_phys) {
        mem_base_phys = boot_ptables_end_phys;
    }

    *ram_start = mem_base_phys;
    *ram_end = mem_base_phys + (1024 * 1024 * 1024);  /* 1 GiB */
    *heap_size = 96 * 1024 * 1024;  /* 96 MiB kernel heap */
}

/**
 * fut_save_and_disable_interrupts - Save interrupt state and disable interrupts
 * Returns: Current RFLAGS IF flag value for later restoration with fut_restore_interrupts
 */
uint64_t fut_save_and_disable_interrupts(void) {
    uint64_t rflags;
    __asm__ volatile(
        "pushfq\n"
        "popq %0\n"
        "cli\n"
        : "=r"(rflags)
        :
        : "memory"
    );
    return rflags & RFLAGS_IF;  /* Return only the IF flag for fut_restore_interrupts */
}

void fut_platform_init(uint32_t multiboot_magic __attribute__((unused)),
                       uint32_t multiboot_addr __attribute__((unused))) {
    /* Early debug marker: Write 'I' to show we entered the function */
    /* Use minimal assembly that doesn't depend on stack setup */
    __asm__ volatile(
        "movw $0x3F8, %%dx\n"
        "movb $'I', %%al\n"
        "outb %%al, %%dx\n"
        :
        :
        : "%dx", "%al", "memory"
    );

    /* Initialize serial port for early debugging */
    fut_serial_init();
    fut_printf("[INIT] Multiboot magic: 0x%x\n", multiboot_magic);
    cpu_features_init();

    /* Debug marker after serial init: Write 'N' */
    __asm__ volatile(
        "movw $0x3F8, %%dx\n"
        "movb $'N', %%al\n"
        "outb %%al, %%dx\n"
        ::: "%dx", "%al"
    );

    fut_serial_puts("Futura OS x86_64 Platform Initialization\n");

    /* Load GDT */
    fut_serial_puts("[INIT] Loading GDT...\n");
    fut_gdt_load();
    fut_tss_init();

    /* Initialize paging structures */
    fut_serial_puts("[INIT] Initializing paging...\n");
    fut_paging_init();
    pat_init();
    fut_mm_system_init();

    /* Initialize and load IDT */
    fut_serial_puts("[INIT] Initializing IDT...\n");
    fut_idt_init();

    /* Initialize PIC */
    fut_serial_puts("[INIT] Initializing PIC...\n");
    fut_pic_init();

    /* Initialize PIT */
    fut_serial_puts("[INIT] Initializing PIT...\n");
    fut_pit_init();

    /* Enable timer IRQ */
    /* DISABLED: Timer IRQ will be unmasked later after scheduler initialization */
    /* fut_irq_enable(0); */

    /* Enable interrupts
     * Note: Per-CPU data will be initialized later in kernel_main after ACPI/LAPIC init.
     * The guard flag in fut_thread_current() prevents access until initialization is complete. */
    fut_serial_puts("[INIT] Enabling interrupts...\n");
    fut_enable_interrupts();

    fut_boot_args_init(NULL);
    if (multiboot_addr) {
        const uint8_t *mb_base = (const uint8_t *)(uintptr_t)multiboot_addr;
        uint32_t total_size = *(const uint32_t *)mb_base;
        fut_printf("[INIT-MB2] multiboot_addr=0x%llx total_size=%u\n",
                   (unsigned long long)multiboot_addr, total_size);
        const uint8_t *tag_ptr = mb_base + 8;
        const uint8_t *end = mb_base + total_size;
        int tag_count = 0;
        while (tag_ptr < end) {
            const struct multiboot_tag *tag =
                (const struct multiboot_tag *)tag_ptr;
            tag_count++;
            fut_printf("[INIT-MB2] tag #%d: type=%u size=%u\n",
                       tag_count, tag->type, tag->size);
            if (tag->type == 0 || tag->size == 0) {
                break;
            }
            if (tag->type == MULTIBOOT_TAG_TYPE_CMDLINE) {
                const char *cmdline = (const char *)(tag + 1);
                fut_printf("[INIT-MB2] CMDLINE tag found: %s\n", cmdline);
                fut_boot_args_init(cmdline);
                break;
            }
            tag_ptr += (tag->size + 7u) & ~7u;
        }
        fut_printf("[INIT-MB2] Total tags parsed: %d\n", tag_count);
    }

    /* Probe Multiboot framebuffer if present */
    (void)fb_probe_from_multiboot((const void *)(uintptr_t)multiboot_addr);

    /* Print Multiboot info */
    fut_serial_puts("[INIT] Multiboot2 magic: 0x");
    /* Simple hex output would go here in full implementation */
    fut_serial_puts("\n");

    /* Call kernel main */
    fut_serial_puts("[INIT] Jumping to kernel main...\n\n");
    fut_kernel_main();

    /* Should never reach here */
    fut_serial_puts("[PANIC] Kernel main returned!\n");
    while (1) {
        __asm__ volatile("cli; hlt");
    }
}

/* Stub handlers that can be overridden by kernel */
void __attribute__((weak)) fut_kernel_main(void) {
    fut_serial_puts("[KERNEL] Kernel main not implemented!\n");
    while (1) {
        __asm__ volatile("hlt");
    }
}

void __attribute__((weak)) fut_timer_irq(void) {
    /* Timer tick - send EOI */
    fut_pic_send_eoi(0);
}

/* IPI handlers - can be overridden by kernel SMP code */
void __attribute__((weak)) ipi_reschedule_handler(void) {
    /* Reschedule request - send EOI and continue */
}

void __attribute__((weak)) ipi_tlb_flush_handler(void) {
    /* TLB flush request - send EOI and continue */
}

void __attribute__((weak)) ipi_halt_handler(void) {
    /* CPU halt request - halt without sending EOI */
    while (1) {
        __asm__ volatile("cli; hlt");
    }
}

/* Helper function to print hex value */
static void print_hex64(uint64_t val) {
    const char *hex = "0123456789ABCDEF";
    char buf[17];
    buf[16] = '\0';

    for (int i = 15; i >= 0; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }

    fut_serial_puts(buf);
}

static void print_hex8(uint8_t val) {
    const char *hex = "0123456789ABCDEF";
    char buf[3];
    buf[0] = hex[(val >> 4) & 0xF];
    buf[1] = hex[val & 0xF];
    buf[2] = '\0';
    fut_serial_puts(buf);
}

/* Exception names for debugging output */
static const char *exception_names[32] = {
    "Divide Error", "Debug", "NMI", "Breakpoint",
    "Overflow", "Bound Range Exceeded", "Invalid Opcode", "Device Not Available",
    "Double Fault", "Coprocessor Segment Overrun", "Invalid TSS", "Segment Not Present",
    "Stack-Segment Fault", "General Protection Fault", "Page Fault", "Reserved",
    "x87 FPU Error", "Alignment Check", "Machine Check", "SIMD Exception",
    "Virtualization Exception", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Security Exception", "Reserved"
};

void __attribute__((weak)) fut_isr_handler(void *regs_ptr) {
    fut_interrupt_frame_t *regs = (fut_interrupt_frame_t *)regs_ptr;

    if (regs->vector == 14) {
        if (fut_trap_handle_page_fault(regs)) {
            return;
        }
    }

    fut_disable_interrupts();
    fut_serial_puts("\n\n");
    fut_serial_puts("========================================\n");
    fut_serial_puts("  KERNEL EXCEPTION\n");
    fut_serial_puts("========================================\n");

    /* Read CR2 register (fault address for page faults) */
    uint64_t cr2 = 0;
    __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));

    /* Display exception type based on vector number */
    fut_serial_puts("Exception #");
    print_hex64(regs->vector);
    fut_serial_puts(": ");

    if (regs->vector < 32) {
        fut_serial_puts(exception_names[regs->vector]);
    } else {
        fut_serial_puts("Unknown");
    }
    fut_serial_puts("\n");

    /* For page faults (#14), display additional information */
    if (regs->vector == 14) {
        fut_serial_puts("Fault Address (CR2): 0x");
        print_hex64(cr2);
        fut_serial_puts("\n");

        fut_serial_puts("Error Code: ");
        if (regs->error_code & 0x1) fut_serial_puts("PRESENT ");
        else fut_serial_puts("NOT-PRESENT ");
        if (regs->error_code & 0x2) fut_serial_puts("WRITE ");
        else fut_serial_puts("READ ");
        if (regs->error_code & 0x4) fut_serial_puts("USER ");
        else fut_serial_puts("SUPERVISOR ");
        if (regs->error_code & 0x10) fut_serial_puts("INSTRUCTION-FETCH ");
        fut_serial_puts("(0x");
        print_hex64(regs->error_code);
        fut_serial_puts(")\n");
    } else {
    fut_serial_puts("Error Code: 0x");
    print_hex64(regs->error_code);
    fut_serial_puts("\n");

    if (regs->vector == 6) {
        fut_serial_puts("[#UD] Opcode bytes @0x");
        print_hex64(regs->rip);
        fut_serial_puts(": ");
        if ((uintptr_t)regs->rip >= KERNEL_VIRTUAL_BASE) {
            const uint8_t *p = (const uint8_t *)regs->rip;
            for (int i = 0; i < 8; i++) {
                print_hex8(p[i]);
                if (i != 7) {
                    fut_serial_puts(" ");
                }
            }
        } else {
            fut_serial_puts("<unmapped>");
        }
        fut_serial_puts("\n");
    }
    }

    fut_serial_puts("\nRegisters:\n");
    fut_serial_puts("  RIP: 0x"); print_hex64(regs->rip); fut_serial_puts("\n");
    fut_serial_puts("  RSP: 0x"); print_hex64(regs->rsp); fut_serial_puts("\n");
    fut_serial_puts("  RBP: 0x"); print_hex64(regs->rbp); fut_serial_puts("\n");
    fut_serial_puts("  RAX: 0x"); print_hex64(regs->rax); fut_serial_puts("\n");
    fut_serial_puts("  RBX: 0x"); print_hex64(regs->rbx); fut_serial_puts("\n");
    fut_serial_puts("  RCX: 0x"); print_hex64(regs->rcx); fut_serial_puts("\n");
    fut_serial_puts("  RDX: 0x"); print_hex64(regs->rdx); fut_serial_puts("\n");
    fut_serial_puts("  RSI: 0x"); print_hex64(regs->rsi); fut_serial_puts("\n");
    fut_serial_puts("  RDI: 0x"); print_hex64(regs->rdi); fut_serial_puts("\n");
    fut_serial_puts("  RFL: 0x"); print_hex64(regs->rflags); fut_serial_puts("\n");
    fut_serial_puts("  CR2: 0x"); print_hex64(cr2); fut_serial_puts("\n");

    fut_serial_puts("\nSegments:\n");
    fut_serial_puts("  CS: 0x"); print_hex64(regs->cs); fut_serial_puts("\n");
    fut_serial_puts("  DS: 0x"); print_hex64(regs->ds); fut_serial_puts("\n");

    /* SS/RSP are only in the frame if there was a privilege level change (CS & 3).
     * For ring 0 exceptions, read SS directly from the register instead. */
    if ((regs->cs & 3) == 0) {
        /* Ring 0 exception - SS not in frame, read from register */
        uint16_t current_ss;
        __asm__ volatile("mov %%ss, %0" : "=r"(current_ss));
        fut_serial_puts("  SS: 0x"); print_hex64(current_ss); fut_serial_puts(" (from register)\n");
    } else {
        /* Ring 3 exception - SS is in frame */
        fut_serial_puts("  SS: 0x"); print_hex64(regs->ss); fut_serial_puts(" (from frame)\n");
    }

    fut_serial_puts("\nSystem halted.\n");
    fut_serial_puts("========================================\n");

    while (1) {
        __asm__ volatile("cli; hlt");
    }
}

void __attribute__((weak)) fut_irq_handler(void *regs __attribute__((unused))) {
    /* Generic IRQ handler - send EOI */
    fut_pic_send_eoi(0);
}

/* Platform panic - halt system with error message */
void fut_platform_panic(const char *message) {
    fut_disable_interrupts();
    fut_serial_puts("\n\n");
    fut_serial_puts("========================================\n");
    fut_serial_puts("  KERNEL PANIC\n");
    fut_serial_puts("========================================\n");
    fut_serial_puts(message);
    fut_serial_puts("\n");
    fut_serial_puts("System halted.\n");
    fut_serial_puts("========================================\n");

    /* Halt forever */
    while (1) {
        __asm__ volatile("cli; hlt");
    }
}

/* CPU halt function */
void fut_platform_cpu_halt(void) {
    __asm__ volatile("hlt");
}

/* ========================================
 *   Platform Hooks for Multi-Arch Support
 * ======================================== */

/**
 * arch_late_init - Platform-specific late initialization
 * Called after all core kernel subsystems are ready.
 * For x86_64, init spawning is handled differently via execve_blob,
 * so this is empty.
 */
void arch_late_init(void) {
    /* x86_64 spawns init via execve_blob in kernel_main, not here */
}

/**
 * arch_idle_loop - Platform-specific idle loop
 * Called when kernel has nothing to do.
 */
void arch_idle_loop(void) {
    fut_printf("[x86_64] Entering idle loop...\n");
    while (1) {
        __asm__ volatile("hlt");
    }
}
