#!/usr/bin/env python3
"""
Fix Multiboot2 Header Offset in ELF File

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
    for i in range(e_phnum):
        phdr_offset = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', elf_data[phdr_offset:phdr_offset+4])[0]
        p_offset = struct.unpack('<Q', elf_data[phdr_offset+8:phdr_offset+16])[0]
        p_filesz = struct.unpack('<Q', elf_data[phdr_offset+32:phdr_offset+40])[0]

        if p_filesz > 0:
            segments.append({
                'idx': i,
                'phdr_offset': phdr_offset,
                'type': p_type,
                'offset': p_offset,
                'filesz': p_filesz,
                'data': bytes(elf_data[p_offset:p_offset+p_filesz]) if p_offset + p_filesz <= len(elf_data) else b''
            })

    print(f"\nBoot data: offset 0x{boot_data_start:x}, size 0x{boot_data_size:x}")

    if boot_data_size >= 0x8000:
        print(f"Error: Boot data too large ({boot_data_size} bytes) for 32KB limit")
        return False

    # Calculate new layout: boot data after headers, others follow
    headers_end = e_phoff + e_phentsize * e_phnum
    new_boot_offset = ((headers_end + 0x1ff) // 0x200) * 0x200  # Align to 512 bytes

    if new_boot_offset + boot_data_size >= 0x8000:
        print(f"Error: Boot data won't fit in first 32KB!")
        print(f"  Headers end at 0x{headers_end:x}")
        print(f"  Boot data needs 0x{boot_data_size:x} bytes")
        return False

    print(f"\nReorganizing ELF file:")
    print(f"  Boot data: 0x{boot_data_start:x} -> 0x{new_boot_offset:x}")

    # Build new file layout
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
    for idx, new_offset in segment_relocations.items():
        phdr_offset = e_phoff + idx * e_phentsize
        struct.pack_into('<Q', new_elf_data, phdr_offset + 8, new_offset)

    # Update section headers and their offsets
    if e_shoff > 0:
        # Place section headers at end of file
        new_shoff = len(new_elf_data)
        old_shoff_end = e_shoff + e_shentsize * e_shnum
        section_headers = bytearray(elf_data[e_shoff:old_shoff_end])

        # Update ALL section header file offsets
        for i in range(e_shnum):
            sh_offset_pos = i * e_shentsize + 24  # sh_offset
            sh_type_pos = i * e_shentsize + 4     # sh_type
            sh_offset = struct.unpack('<Q', section_headers[sh_offset_pos:sh_offset_pos+8])[0]
            sh_type = struct.unpack('<I', section_headers[sh_type_pos:sh_type_pos+4])[0]

            if sh_offset > 0 and sh_type != 8:  # Not NOBITS
                # Check if this is one of the boot sections we relocated
                if sh_offset in section_relocations:
                    struct.pack_into('<Q', section_headers, sh_offset_pos, section_relocations[sh_offset])
                    continue

                # Find which segment contains this section
                section_relocated = False
                for seg in segments:
                    seg_start = seg['offset']
                    seg_end = seg['offset'] + seg['filesz']

                    if seg_start <= sh_offset < seg_end:
                        # Section is in this segment
                        new_seg_offset = segment_relocations[seg['idx']]
                        offset_within_seg = sh_offset - seg_start
                        new_sh_offset = new_seg_offset + offset_within_seg
                        struct.pack_into('<Q', section_headers, sh_offset_pos, new_sh_offset)
                        section_relocated = True
                        break

                # If section wasn't in any segment, leave it as is (might be debug section)

        new_elf_data.extend(section_headers)
        struct.pack_into('<Q', new_elf_data, 40, new_shoff)
        print(f"  Section headers: 0x{e_shoff:x} -> 0x{new_shoff:x}")

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
