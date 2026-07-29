package parse_elf

import "core:os"
import "core:fmt"
import "base:runtime"

// ============================================
//  Read Unisgned Little-Endian 64-Bit Integer
// ============================================

read_ul_64 :: proc(data: []u8, offset: int) -> u64 {
	v := u64(data[offset]) |
		(u64(data[offset + 1]) <<  8) |
		(u64(data[offset + 2]) << 16) |
		(u64(data[offset + 3]) << 24) |
		(u64(data[offset + 4]) << 32) |
		(u64(data[offset + 5]) << 40) |
		(u64(data[offset + 6]) << 48) |
		(u64(data[offset + 7]) << 56)
	return v
}

// ============================================
//  Read Unisgned Little-Endian 32-Bit Integer
// ============================================

read_ul_32 :: proc(data: []u8, offset: int) -> u32 {
	v := u32(data[offset]) |
		(u32(data[offset + 1]) <<  8) |
		(u32(data[offset + 2]) << 16) |
		(u32(data[offset + 3]) << 24)
	return v
}

// ============================================
//  Read Unisgned Little-Endian 16-Bit Integer
// ============================================

read_ul_16 :: proc(data: []u8, offset: int) -> u16 {    
	v := u16(data[offset]) | 
		(u16(data[offset + 1]) << 8)
    return v
}

// ===============================
//  Get Number of Section Headers
// ===============================

get_e_shnum :: proc(data: []u8) -> u16 {
	assert(len(data) >= 62, "Data too short to extract e_shnum")
	return read_ul_16(data, 60)
}

// =================================
//  Get Section Header Table Offset
// =================================

get_e_shoff :: proc(data: []u8) -> u64 {
	assert(len(data) >= 48, "Data too short to extract e_shoff")
    return read_ul_64(data, 40)
}

// =================================
//  Get Size of Each Section Header
// =================================

get_shentsize :: proc(data: []u8) -> u16 {
	assert(len(data) >= 60, "Data too short to extract e_shentsize")
	return read_ul_16(data, 58)
}

// ==============
//  Get SHSTRNDX
// ==============

get_e_shstrndx :: proc(data: []u8) -> u16 {
    assert(len(data) >= 64, "Data too short to extract e_shstrndx")
    return read_ul_16(data, 62)
}

// =========================
//  Get SHSTR Header Offset
// =========================

get_shstr_hdr_off :: proc(data: []u8) -> u64 {
	return get_e_shoff(data) + u64(get_e_shstrndx(data)) * u64(get_shentsize(data))
}

// ==================
//  Get SHSTR Offset
// ==================

get_shstr_off ::proc(data: []u8) -> u64 {
    shstr_hdr: = get_shstr_hdr_off(data)
    assert(len(data) >= int(shstr_hdr) + 32, 
    	   "Data too short to extract Section Header String Table")
    return read_ul_64(data, int(shstr_hdr) + 24)
}

// ================
//  Get SHSTR Size
// ================

get_shstr_size :: proc(data: []u8) -> u64 {
    shstr_hdr := get_shstr_hdr(data)
    return read_ul_64(data, int(shstr_hdr) + 32)
}

// ==================
//  Get SHSTR Header
// ==================

get_shstr_hdr :: proc(data: []u8) -> u32 {
    return u32(get_e_shoff(data)) + u32(get_e_shstrndx(data)) * u32(get_shentsize(data))
}

// =================
//  Get SHSTR Table
// =================

get_shstrtab :: proc(data: []u8) -> []u8 {
    shstr_off  := get_shstr_off(data)
    shstr_size := get_shstr_size(data)
    return data[shstr_off : shstr_off + shstr_size]
}

// =============
//  Elf Section 
// =============

elf_section :: struct {
    name        : string,
    addr        : u64,
    file_offset : u64,
    data        : []u8
}

// =====================
//  Get Section By Name 
// =====================

get_section_by_name :: proc(data: []u8, section_name: string) -> elf_section {
    e_shnum   := get_e_shnum(data)
    e_shoff   := get_e_shoff(data)
    e_shentsz := get_shentsize(data)
    shstrtab  := get_shstrtab(data)
    for i := 0; i < int(e_shnum); i += 1 {
        shdr:     int = int(e_shoff) + i * int(e_shentsz)
        name_off: u32   = read_ul_32(data, shdr)
        end:      int = int(name_off)
        for end < len(shstrtab) && shstrtab[end] != 0 {
    		end += 1
		}
		name: string
		if int(name_off) < len(shstrtab) {
		    name = cast(string) shstrtab[int(name_off) : end]
		} else {
		    name = "<invalid>"
		}
        if name == section_name {
            sec_addr: u64 = read_ul_64(data, shdr + 16)
            sec_off:  u64 = read_ul_64(data, shdr + 24)
            sec_size: u64 = read_ul_64(data, shdr + 32)
            return elf_section{ name = name, addr = sec_addr, 
            					file_offset = sec_off, 
            					data = data[sec_off : sec_off + sec_size]}
        }
    }
    return elf_section{ name = "", addr = 0, file_offset = 0, data = []u8{}}
}

// ==============
//  Load Segment
// ==============

load_segment :: struct {
    file_offset: 	u64,
    file_size:  	u64,
    vaddr: 			u64
}

// ===================
//  VA to File Offset
// ===================

va_to_file_offset :: proc(segs: [dynamic]load_segment, va: u64) -> (int, bool) {
    for s in segs {
        if va >= s.vaddr && va < s.vaddr + s.file_size {
            return int(s.file_offset + (va - s.vaddr)), true
        }
    }
    return 0, false
}

// =========
//  ST Type
// =========

st_type :: enum u8 { 
    stt_notype                      = 0,
    stt_object                      = 1,
    stt_func                        = 2,
    stt_section                     = 3, 
    stt_file                        = 4,
    all                             = 0xff
}

// ==============
//  Elf Function
// ==============

elf_func :: struct {
    offset 		: u64,
    data 		: []u8
}

// ============
//  Elf 32 Sym
// ============

elf_64_sym :: struct {
    st_name 	: u32,
    st_value 	: u64,
    st_size 	: u64,
    st_info		: u8,
    st_other	: u8,
    st_shndx    : u16
}

// ===================
//  Get Load Segments
// ===================

get_load_segments :: proc(elf_file: []u8) -> [dynamic]load_segment {
    e_phoff   := read_ul_32(elf_file, 32)
    e_phentsz := read_ul_16(elf_file, 54)
    e_phnum   := read_ul_16(elf_file, 56)

    segs := make([dynamic]load_segment)

    for i := 0; i < int(e_phnum); i += 1 {
        ph: int = int(e_phoff) + int(i) * int(e_phentsz)

        p_type := read_ul_32(elf_file, ph + 0)
        if p_type != 1 {
            continue
        }

        p_offset := read_ul_64(elf_file, ph +  8)
        p_paddr  := read_ul_64(elf_file, ph + 16)
        p_filesz := read_ul_64(elf_file, ph + 32)

        append_elem(&segs, load_segment{ file_offset = p_offset, file_size = p_filesz, vaddr = p_paddr })
    }
    return segs;
}

// =================================
//  Get Functions From Text Section
// =================================

get_funcs_from_text_sec :: proc(elf_file: []u8) -> [dynamic]elf_func {
	symtab_sec := get_section_by_name(elf_file, ".symtab")
    strtab_sec := get_section_by_name(elf_file, ".strtab")
    text_sec   := get_section_by_name(elf_file, "text")

    symdata    := symtab_sec.data
    strdata    := strtab_sec.data
    text_start := text_sec.addr
    segs 	   := get_load_segments(elf_file)

    funcs: [dynamic]elf_func

    for pos := 0; pos + 16 <= len(symdata); pos += 24 {
        sym: elf_64_sym
        sym.st_name  = read_ul_32(symdata, pos + 0)
        sym.st_value = read_ul_64(symdata, pos + 8)
        sym.st_size  = read_ul_64(symdata, pos + 16)
        sym.st_info  = symdata[pos + 4]
        sym.st_other = symdata[pos + 5]
        sym.st_shndx = read_ul_16(symdata, pos + 6)

        sym_type := sym.st_info & 0xF
        if st_type(sym_type) != st_type.stt_func {
        	continue
        }
 
        name_off := sym.st_name
        if int(name_off) >= len(strdata) { 
        	continue
        }
        end: int = int(name_off)
        for end < len(strdata) && strdata[end] != 0 {
    		end += 1
		}

        name :string = cast(string) strdata[name_off : end]
        func_va := sym.st_value
        file_offset, ok := va_to_file_offset(segs, func_va)
		if !ok {
    		continue
		}

        data := elf_file[file_offset : file_offset + int(sym.st_size)]
        assert(len(data) == int(sym.st_size))
        append_elem(&funcs, elf_func{ offset = func_va, data = data })
    }
    return funcs
}

main :: proc() {
    filename := "../../test/z_arch64.elf" // replace with your ELF file path

    // Read the entire ELF file
    data, ok := os.read_entire_file(filename)
    if !ok {
        fmt.println("Failed to read file:", filename)
        return
    }

    // Get all functions from .text section
    funcs := get_funcs_from_text_sec(data)
    if len(funcs) == 0 {
        fmt.println("No functions found in ELF")
        return
    }

    fmt.println("Decoding instructions in", len(funcs), "functions")

    vm : cortex_a_vm

    // Iterate through each function
    for f_idx := 0; f_idx < len(funcs); f_idx += 1 {
        f := funcs[f_idx]
        fmt.printf("Function at VA 0x%016x size: %d\n", f.offset, len(f.data))
        // Feed 4 bytes at a time to get_opcode
        for i := 0; i + 4 <= len(f.data); i += 4 {
            instr_bytes := f.data[i : i + 4]
            instr := read_ul_32(instr_bytes, 0) // 32-bit little-endian

            op := get_opcode(instr)

            if op == a64_opcode.invalid {
			    fmt.printf("Invalid instruction at func VA 0x%016x offset 0x%08x: 0x%08x\n",
			        f.offset, i, instr)
			    panic("Execution halted due to invalid instruction")
			} else {
			    fmt.printf("Decoded instruction at func VA 0x%016x offset 0x%08x: %s\n",
			        f.offset, i, opcode_to_string(op))
			}

            parsed_instr := parse_instr(instr)

            exec_instr(&parsed_instr, &vm)
        }
    }

    fmt.println("Finished decoding all functions")
}