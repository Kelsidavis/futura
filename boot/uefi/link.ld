OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(efi_main)

SECTIONS
{
    . = 0;
    ImageBase = .;

    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .rel.dyn : { *(.rel.*) }
    .rela.dyn : { *(.rela.*) }

    . = ALIGN(4096);
    .text : {
        _text = .;
        *(.text.efi_main)
        *(.text .text.*)
        *(.gnu.linkonce.t.*)
        . = ALIGN(16);
    }

    . = ALIGN(4096);
    .reloc : {
        *(.reloc)
    }

    . = ALIGN(4096);
    .data : {
        _data = .;
        *(.rodata*)
        *(.got.plt)
        *(.got)
        *(.data*)
        *(.sdata)
        *(.sbss)
        *(.scommon)
    }

    . = ALIGN(4096);
    .dynamic : { *(.dynamic) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }

    . = ALIGN(4096);
    .bss : {
        _bss = .;
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.gnu_debuglink)
        *(.gnu.lto_*)
    }
}
