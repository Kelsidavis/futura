/* kernel/security/bpf.c - Classic BPF bytecode interpreter for seccomp
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the classic BPF (cBPF) virtual machine used by seccomp-bpf
 * to filter syscalls. Programs are guaranteed to terminate (no backward
 * jumps), have max 4096 instructions, and use a simple register machine.
 *
 * Registers: A (accumulator), X (index)
 * Memory: M[0..15] scratch slots
 * Input: seccomp_data { nr, arch, instruction_pointer, args[6] }
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/* BPF instruction classes */
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_RET   0x06
#define BPF_MISC  0x07

/* BPF addressing modes */
#define BPF_IMM   0x00
#define BPF_ABS   0x20
#define BPF_IND   0x40
#define BPF_MEM   0x60
#define BPF_LEN   0x80
#define BPF_MSH   0xa0

/* BPF ALU operations */
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60
#define BPF_RSH   0x70
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0

/* BPF jump operations */
#define BPF_JA    0x00
#define BPF_JEQ   0x10
#define BPF_JGT   0x20
#define BPF_JGE   0x30
#define BPF_JSET  0x40

/* BPF source */
#define BPF_K     0x00
#define BPF_X     0x08

/* BPF sizes */
#define BPF_W     0x00  /* 32-bit */
#define BPF_H     0x08  /* 16-bit */
#define BPF_B     0x10  /* 8-bit */

/* Seccomp return values */
#define SECCOMP_RET_KILL_PROCESS  0x80000000U
#define SECCOMP_RET_KILL_THREAD   0x00000000U
#define SECCOMP_RET_TRAP          0x00030000U
#define SECCOMP_RET_ERRNO         0x00050000U
#define SECCOMP_RET_LOG           0x7ffc0000U
#define SECCOMP_RET_ALLOW         0x7fff0000U
#define SECCOMP_RET_ACTION_FULL   0xffff0000U
#define SECCOMP_RET_DATA          0x0000ffffU

/* BPF instruction */
struct sock_filter {
    uint16_t code;
    uint8_t  jt;    /* Jump true offset */
    uint8_t  jf;    /* Jump false offset */
    uint32_t k;     /* Immediate value */
};

/* Seccomp input data (what the BPF program reads) */
struct seccomp_data {
    int      nr;           /* Syscall number */
    uint32_t arch;         /* Architecture (AUDIT_ARCH_X86_64 = 0xC000003E) */
    uint64_t instruction_pointer;
    uint64_t args[6];
};

#define BPF_MEMWORDS 16
#define BPF_MAXINSNS 4096

/**
 * Execute a classic BPF program on seccomp_data.
 * Returns the seccomp action (SECCOMP_RET_*).
 */
uint32_t bpf_run(const struct sock_filter *insns, uint32_t n_insns,
                 const struct seccomp_data *sd) {
    if (!insns || n_insns == 0 || n_insns > BPF_MAXINSNS || !sd)
        return SECCOMP_RET_KILL_PROCESS;

    uint32_t A = 0, X = 0;
    uint32_t mem[BPF_MEMWORDS] = {0};
    const uint8_t *data = (const uint8_t *)sd;
    uint32_t data_len = sizeof(struct seccomp_data);

    for (uint32_t pc = 0; pc < n_insns; pc++) {
        const struct sock_filter *f = &insns[pc];
        uint16_t cls = f->code & 0x07;

        switch (cls) {
        case BPF_LD: {
            uint16_t size = f->code & 0x18;
            uint16_t mode = f->code & 0xe0;
            uint32_t off;
            if (mode == BPF_IMM) { A = f->k; break; }
            if (mode == BPF_ABS) off = f->k;
            else if (mode == BPF_IND) off = X + f->k;
            else if (mode == BPF_MEM) { A = (f->k < BPF_MEMWORDS) ? mem[f->k] : 0; break; }
            else if (mode == BPF_LEN) { A = data_len; break; }
            else break;
            if (size == BPF_W && off + 4 <= data_len)
                A = *(uint32_t *)(data + off);
            else if (size == BPF_H && off + 2 <= data_len)
                A = *(uint16_t *)(data + off);
            else if (size == BPF_B && off + 1 <= data_len)
                A = data[off];
            else return SECCOMP_RET_KILL_PROCESS;
            break;
        }
        case BPF_LDX: {
            uint16_t mode = f->code & 0xe0;
            if (mode == BPF_IMM) X = f->k;
            else if (mode == BPF_MEM) X = (f->k < BPF_MEMWORDS) ? mem[f->k] : 0;
            else if (mode == BPF_LEN) X = data_len;
            break;
        }
        case BPF_ST:
            if (f->k < BPF_MEMWORDS) mem[f->k] = A;
            break;
        case BPF_STX:
            if (f->k < BPF_MEMWORDS) mem[f->k] = X;
            break;
        case BPF_ALU: {
            uint32_t src = (f->code & BPF_X) ? X : f->k;
            switch (f->code & 0xf0) {
                case BPF_ADD: A += src; break;
                case BPF_SUB: A -= src; break;
                case BPF_MUL: A *= src; break;
                case BPF_DIV: A = src ? A / src : 0; break;
                case BPF_MOD: A = src ? A % src : 0; break;
                case BPF_OR:  A |= src; break;
                case BPF_AND: A &= src; break;
                case BPF_XOR: A ^= src; break;
                case BPF_LSH: A <<= src; break;
                case BPF_RSH: A >>= src; break;
                case BPF_NEG: A = -A; break;
            }
            break;
        }
        case BPF_JMP: {
            uint32_t src = (f->code & BPF_X) ? X : f->k;
            bool cond = false;
            switch (f->code & 0xf0) {
                case BPF_JA:   pc += f->k; continue;
                case BPF_JEQ:  cond = (A == src); break;
                case BPF_JGT:  cond = (A > src); break;
                case BPF_JGE:  cond = (A >= src); break;
                case BPF_JSET: cond = (A & src) != 0; break;
            }
            pc += cond ? f->jt : f->jf;
            break;
        }
        case BPF_RET:
            return (f->code & BPF_X) ? X : f->k;
        case BPF_MISC:
            if (f->code == (BPF_MISC | 0x00)) X = A;      /* TAX */
            else if (f->code == (BPF_MISC | 0x80)) A = X;  /* TXA */
            break;
        }
    }

    return SECCOMP_RET_KILL_PROCESS;  /* Fell off end → kill */
}
