/* UEFI PE32+ Linker Script */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(efi_main)

SECTIONS
{
    . = 0;
    ImageBase = .;

    .text : {
        *(.text.efi_main)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.note.*)
        *(.comment)
    }
}
