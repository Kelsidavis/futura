#!/usr/bin/env python3
"""
Fix Multiboot2 Header Offset in ELF File

Copyright (c) 2025 Kelsi Davis
Licensed under the MPL v2.0 — see LICENSE for details.

This script reorganizes ELF segments to ensure the boot segment (containing
the multiboot header) is placed within the first 32KB of the file.

Strategy: Move boot segment to low file offset, shift other segments after it.
"""

import struct
import sys

def fix_elf_offset(input_file, output_file):
    # Read the entire ELF file
    with open(input_file, 'rb') as f:
        elf_data = bytearray(f.read())

    # Parse ELF header
    if elf_data[:4] != b'\x7fELF':
        print("Error: Not a valid ELF file")
        return False

    ei_class = elf_data[4]  # 1=32-bit, 2=64-bit
    if ei_class != 2:
        print("Error: Only ELF64 supported")
        return False

    # ELF64 header offsets
    e_phoff = struct.unpack('<Q', elf_data[32:40])[0]  # Program header offset
    e_shoff = struct.unpack('<Q', elf_data[40:48])[0]  # Section header offset
    e_phentsize = struct.unpack('<H', elf_data[54:56])[0]  # Program header entry size
    e_phnum = struct.unpack('<H', elf_data[56:58])[0]  # Number of program headers

    print(f"ELF64 file: {e_phnum} program headers at 0x{e_phoff:x}")

    # First, find the multiboot header in the file by searching for the magic number
    multiboot_magic = 0xE85250D6
    multiboot_offset = None
    for i in range(0, len(elf_data) - 4, 4):
        magic = struct.unpack('<I', elf_data[i:i+4])[0]
        if magic == multiboot_magic:
            multiboot_offset = i
            print(f"\nFound multiboot header at file offset: 0x{i:x}")
            break

    if multiboot_offset is None:
        print("Error: Multiboot header not found in file!")
        return False

    # Find all boot-related sections (.boot and .boot_bss)
    e_shentsize = struct.unpack('<H', elf_data[58:60])[0]
    e_shnum = struct.unpack('<H', elf_data[60:62])[0]
    e_shstrndx = struct.unpack('<H', elf_data[62:64])[0]

    # Read section header string table
    shstrtab_offset_pos = e_shoff + e_shstrndx * e_shentsize + 24
    shstrtab_offset = struct.unpack('<Q', elf_data[shstrtab_offset_pos:shstrtab_offset_pos+8])[0]
    shstrtab_size_pos = e_shoff + e_shstrndx * e_shentsize + 32
    shstrtab_size = struct.unpack('<Q', elf_data[shstrtab_size_pos:shstrtab_size_pos+8])[0]
    shstrtab = elf_data[shstrtab_offset:shstrtab_offset+shstrtab_size]

    boot_sections = []
    for i in range(e_shnum):
        sh_name_pos = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack('<I', elf_data[sh_name_pos:sh_name_pos+4])[0]
        sh_offset_pos = e_shoff + i * e_shentsize + 24
        sh_size_pos = e_shoff + i * e_shentsize + 32
        sh_offset = struct.unpack('<Q', elf_data[sh_offset_pos:sh_offset_pos+8])[0]
        sh_size = struct.unpack('<Q', elf_data[sh_size_pos:sh_size_pos+8])[0]

        # Get section name
        name_end = shstrtab.find(b'\x00', sh_name_idx)
        section_name = shstrtab[sh_name_idx:name_end].decode('ascii')

        if section_name.startswith('.boot') and not section_name.startswith('.boot_bss'):
            boot_sections.append({
                'name': section_name,
                'offset': sh_offset,
                'size': sh_size
            })
            print(f"  Found section {section_name} at offset 0x{sh_offset:x}, size 0x{sh_size:x}")

    if not boot_sections:
        print("Error: No boot sections found")
        return False

    # Sort by offset to get contiguous data
    boot_sections.sort(key=lambda x: x['offset'])

    # Extract all boot data (from first boot section to end of last)
    boot_data_start = boot_sections[0]['offset']
    boot_data_end = boot_sections[-1]['offset'] + boot_sections[-1]['size']
    boot_data_size = boot_data_end - boot_data_start
    boot_data = bytes(elf_data[boot_data_start:boot_data_end])

    # Parse all segments for reorganization
    segments = []
    boot_phdr_idx = None
    PT_LOAD = 1

    boot_data_segment_idx = None

    for i in range(e_phnum):
        phdr_offset = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', elf_data[phdr_offset:phdr_offset+4])[0]
        p_offset = struct.unpack('<Q', elf_data[phdr_offset+8:phdr_offset+16])[0]
        p_vaddr = struct.unpack('<Q', elf_data[phdr_offset+16:phdr_offset+24])[0]
        p_paddr = struct.unpack('<Q', elf_data[phdr_offset+24:phdr_offset+32])[0]
        p_filesz = struct.unpack('<Q', elf_data[phdr_offset+32:phdr_offset+40])[0]

        # Identify empty boot PT_LOAD segment (first PT_LOAD with filesz==0)
        if p_type == PT_LOAD and p_filesz == 0 and boot_phdr_idx is None:
            boot_phdr_idx = i
            print(f"  Found empty boot PT_LOAD segment at index {i}")
        elif p_filesz > 0:
            if p_type == PT_LOAD and p_vaddr == 0x100000 and boot_data_segment_idx is None:
                boot_data_segment_idx = i
            segments.append({
                'idx': i,
                'phdr_offset': phdr_offset,
                'type': p_type,
                'offset': p_offset,
                'filesz': p_filesz,
                'data': bytes(elf_data[p_offset:p_offset+p_filesz]) if p_offset + p_filesz <= len(elf_data) else b''
            })

    # If no empty boot PT_LOAD found, we need to create one
    create_new_boot_phdr = (boot_phdr_idx is None)
    if create_new_boot_phdr:
        print(f"  No empty boot PT_LOAD found, will create new one")
        boot_phdr_idx = 0  # Insert at beginning

        if boot_data_segment_idx is not None:
            segments = [seg for seg in segments if seg['idx'] != boot_data_segment_idx]

    print(f"\nBoot data: offset 0x{boot_data_start:x}, size 0x{boot_data_size:x}")

    if boot_data_size >= 0x8000:
        print(f"Error: Boot data too large ({boot_data_size} bytes) for 32KB limit")
        return False

    # Calculate new layout: boot data after headers (accounting for potential new phdr)
    new_phnum = e_phnum + 1 if create_new_boot_phdr else e_phnum
    new_headers_end = e_phoff + e_phentsize * new_phnum
    new_boot_offset = ((new_headers_end + 0x1ff) // 0x200) * 0x200  # Align to 512 bytes

    if new_boot_offset + boot_data_size >= 0x8000:
        print(f"Error: Boot data won't fit in first 32KB!")
        print(f"  Headers end at 0x{new_headers_end:x}")
        print(f"  Boot data needs 0x{boot_data_size:x} bytes")
        return False

    print(f"\nReorganizing ELF file:")
    print(f"  Boot data: 0x{boot_data_start:x} -> 0x{new_boot_offset:x}")

    # Build new file layout
    # Start with ELF header and program headers (with space for new boot phdr if needed)
    if create_new_boot_phdr:
        # Copy ELF header (64 bytes)
        new_elf_data = bytearray(elf_data[:e_phoff])

        # Create new boot PT_LOAD program header as first entry
        boot_phdr_data = bytearray(e_phentsize)
        # ELF64 program header structure:
        struct.pack_into('<I', boot_phdr_data, 0, PT_LOAD)  # p_type
        struct.pack_into('<I', boot_phdr_data, 4, 7)  # p_flags = RWE
        struct.pack_into('<Q', boot_phdr_data, 8, new_boot_offset)  # p_offset (temporary)
        struct.pack_into('<Q', boot_phdr_data, 16, 0x100000)  # p_vaddr
        struct.pack_into('<Q', boot_phdr_data, 24, 0x100000)  # p_paddr
        struct.pack_into('<Q', boot_phdr_data, 32, boot_data_size)  # p_filesz
        struct.pack_into('<Q', boot_phdr_data, 40, boot_data_size)  # p_memsz
        struct.pack_into('<Q', boot_phdr_data, 48, 0x1000)  # p_align
        new_elf_data.extend(boot_phdr_data)

        # Copy existing program headers
        new_elf_data.extend(elf_data[e_phoff:e_phoff + e_phentsize * e_phnum])

        # Update e_phnum in ELF header
        struct.pack_into('<H', new_elf_data, 56, new_phnum)

        if boot_data_segment_idx is not None:
            old_boot_phdr_offset = e_phoff + (boot_data_segment_idx + 1) * e_phentsize
            struct.pack_into('<I', new_elf_data, old_boot_phdr_offset + 0, 0)    # PT_NULL
            struct.pack_into('<I', new_elf_data, old_boot_phdr_offset + 4, 0)    # flags
            struct.pack_into('<Q', new_elf_data, old_boot_phdr_offset + 8, 0)    # offset
            struct.pack_into('<Q', new_elf_data, old_boot_phdr_offset + 16, 0)   # vaddr
            struct.pack_into('<Q', new_elf_data, old_boot_phdr_offset + 24, 0)   # paddr
            struct.pack_into('<Q', new_elf_data, old_boot_phdr_offset + 32, 0)   # filesz
            struct.pack_into('<Q', new_elf_data, old_boot_phdr_offset + 40, 0)   # memsz
            struct.pack_into('<Q', new_elf_data, old_boot_phdr_offset + 48, 0x1000)  # align
    else:
        # Just copy up to old headers_end
        headers_end = e_phoff + e_phentsize * e_phnum
        new_elf_data = bytearray(elf_data[:headers_end])

    # Pad to boot data start
    new_elf_data.extend(b'\x00' * (new_boot_offset - len(new_elf_data)))

    # Write boot data
    new_elf_data.extend(boot_data)

    # Calculate offset for next segment (align to 4KB for safety)
    current_offset = ((len(new_elf_data) + 0xfff) // 0x1000) * 0x1000

    # Write other segments
    segment_relocations = {}
    section_relocations = {}

    # Track boot section relocations
    for boot_sec in boot_sections:
        offset_within_boot_data = boot_sec['offset'] - boot_data_start
        section_relocations[boot_sec['offset']] = new_boot_offset + offset_within_boot_data

    for seg in segments:
        # Pad to current offset
        if current_offset > len(new_elf_data):
            new_elf_data.extend(b'\x00' * (current_offset - len(new_elf_data)))

        segment_relocations[seg['idx']] = current_offset
        new_elf_data.extend(seg['data'])

        print(f"  Segment {seg['idx']}: 0x{seg['offset']:x} -> 0x{current_offset:x}")

        # Track section relocations for segments
        section_relocations[seg['offset']] = current_offset

        current_offset = ((len(new_elf_data) + 0xfff) // 0x1000) * 0x1000

    # Update program headers with new offsets
    # If we created a new boot phdr, all existing indices shift by 1
    phdr_index_offset = 1 if create_new_boot_phdr else 0
    for idx, new_offset in segment_relocations.items():
        phdr_offset = e_phoff + (idx + phdr_index_offset) * e_phentsize
        struct.pack_into('<Q', new_elf_data, phdr_offset + 8, new_offset)

    # Boot PT_LOAD segment was already set up when creating new phdrs, or update existing
    if not create_new_boot_phdr and boot_phdr_idx is not None:
        boot_phdr_offset = e_phoff + boot_phdr_idx * e_phentsize
        # ELF64 program header structure:
        # Offset 0: p_type (4 bytes) - already PT_LOAD
        # Offset 4: p_flags (4 bytes) - set to 7 (RWE)
        # Offset 8: p_offset (8 bytes) - file offset
        # Offset 16: p_vaddr (8 bytes) - virtual address
        # Offset 24: p_paddr (8 bytes) - physical address
        # Offset 32: p_filesz (8 bytes) - size in file
        # Offset 40: p_memsz (8 bytes) - size in memory
        # Offset 48: p_align (8 bytes) - alignment
        struct.pack_into('<I', new_elf_data, boot_phdr_offset + 4, 7)  # p_flags = RWE
        struct.pack_into('<Q', new_elf_data, boot_phdr_offset + 8, new_boot_offset)  # p_offset
        struct.pack_into('<Q', new_elf_data, boot_phdr_offset + 16, 0x100000)  # p_vaddr
        struct.pack_into('<Q', new_elf_data, boot_phdr_offset + 24, 0x100000)  # p_paddr
        struct.pack_into('<Q', new_elf_data, boot_phdr_offset + 32, boot_data_size)  # p_filesz
        struct.pack_into('<Q', new_elf_data, boot_phdr_offset + 40, boot_data_size)  # p_memsz
        struct.pack_into('<Q', new_elf_data, boot_phdr_offset + 48, 0x1000)  # p_align

    print(f"  Boot PT_LOAD: offset=0x{new_boot_offset:x}, vaddr=0x100000, paddr=0x100000, size=0x{boot_data_size:x}")

    # CRITICAL: Preserve ALL data from the original file
    # We need to ensure no embedded binaries or metadata is lost

    # Find the actual extent of all data in the original file
    # This includes all PT_LOAD segment data plus section headers
    max_original_offset = 0

    # Check all PT_LOAD segments
    for i in range(e_phnum):
        phdr_offset = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', elf_data[phdr_offset:phdr_offset+4])[0]
        p_offset = struct.unpack('<Q', elf_data[phdr_offset+8:phdr_offset+16])[0]
        p_filesz = struct.unpack('<Q', elf_data[phdr_offset+32:phdr_offset+40])[0]

        if p_type == PT_LOAD and p_filesz > 0:
            segment_end = p_offset + p_filesz
            if segment_end > max_original_offset:
                max_original_offset = segment_end
                print(f"  Segment {i}: ends at 0x{segment_end:x}")

    # Also consider section headers and any data beyond
    if e_shoff > 0:
        section_table_end = e_shoff + (e_shentsize * e_shnum)
        if section_table_end > max_original_offset:
            max_original_offset = section_table_end
            print(f"  Section table ends at 0x{section_table_end:x}")

    # Finally, use the actual file size if it's larger
    if len(elf_data) > max_original_offset:
        max_original_offset = len(elf_data)

    print(f"\n[DATA PRESERVATION] Original file ends at: 0x{max_original_offset:x} ({max_original_offset} bytes)")
    print(f"[DATA PRESERVATION] New ELF currently at:  0x{len(new_elf_data):x} ({len(new_elf_data)} bytes)")

    # Ensure we preserve all data up to max_original_offset
    # by padding and copying remaining data from original file
    if max_original_offset > len(new_elf_data):
        # Calculate padding alignment for sections
        new_shoff = ((len(new_elf_data) + 0xfff) // 0x1000) * 0x1000

        if new_shoff > len(new_elf_data):
            new_elf_data.extend(b'\x00' * (new_shoff - len(new_elf_data)))

        # Copy remaining original file data
        if new_shoff < len(elf_data):
            remaining = elf_data[new_shoff:max_original_offset]
            new_elf_data.extend(remaining)
            print(f"[DATA PRESERVATION] Preserved data from 0x{new_shoff:x} to 0x{max_original_offset:x}")

        print(f"[DATA PRESERVATION] Final file size:     0x{len(new_elf_data):x} ({len(new_elf_data)} bytes)")
    else:
        # Already have all data, just add minimal section headers if needed
        if e_shoff == 0:
            null_shdr = bytearray(64)
            new_elf_data.extend(null_shdr)
            print(f"[DATA PRESERVATION] Added minimal section header table")

    struct.pack_into('<Q', new_elf_data, 40, new_shoff)  # Set e_shoff
    struct.pack_into('<H', new_elf_data, 60, e_shnum)  # Preserve original e_shnum
    struct.pack_into('<H', new_elf_data, 62, e_shstrndx)  # Preserve original e_shstrndx

    # Write output file
    with open(output_file, 'wb') as f:
        f.write(new_elf_data)

    print(f"\n✓ Multiboot header now at file offset: 0x{new_boot_offset:x}")
    print(f"✓ New ELF file size: {len(new_elf_data)} bytes")
    print(f"✓ Fixed ELF written to: {output_file}")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.elf> <output.elf>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if fix_elf_offset(input_file, output_file):
        sys.exit(0)
    else:
        sys.exit(1)
