import std.stdio;
import std.exception;
import core.exception : ArraySliceError;
import std.conv;
import std.file;
import std.array;
import std.format;
import std.typecons;
import std.algorithm;

import vm;
import cortex_m_core;
import memory_sections;
import thumb_2_opcodes;
import thumb_2_instrs;
import thumb_2_decode_instr;

import elf_table_names;

import log;
// --------------------------------------------------------------------------------------
// ===================
//  GET LOAD SEGMENTS
// ===================

load_segment[] get_load_segments(const string elf_file) {
    ubyte[] elf = cast(ubyte[]) read(elf_file);
    uint   e_phoff   = read_ul_32(elf, 28);
    ushort e_phentsz = read_ul_16(elf, 42);
    ushort e_phnum   = read_ul_16(elf, 44);

    load_segment[] segs;

    foreach (i; 0 .. e_phnum) {
        size_t ph = e_phoff + i * e_phentsz;

        uint p_type   = read_ul_32(elf, ph + 0);
        if (p_type != 1)
            continue;

        uint p_offset = read_ul_32(elf, ph +  4);
        uint p_paddr  = read_ul_32(elf, ph + 12);
        uint p_filesz = read_ul_32(elf, ph + 16);

        segs ~= load_segment(p_offset, p_filesz, p_paddr);
    }

    return segs;
}
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// ==========
//  ELF FILE
// ==========

class elf_file {
    this (string elf_file_name) {
        _file_data = cast(ubyte[])read(elf_file_name);
        _elf_file_name = elf_file_name;
    }
    uint get_e_shoff() {
        if (_e_shoff != 0) 
            return _e_shoff;
        size_t offset = 32;
        return read_ul_32(_file_data, offset);
    }
    uint get_elf_entry_point() {
        if (_entry_point != 0) 
            return _entry_point;
        size_t offset = 24;
        return read_ul_32(_file_data, offset);
    }
    ushort get_e_shentsz() {
        if (_e_shentsz != 0) 
            return _e_shentsz;
        size_t offset = 46;
        return read_ul_16(_file_data, offset);
    }
    ushort get_e_shnum() {
        if (_e_shnum != 0) 
            return _e_shnum;
        size_t offset = 48;
        return read_ul_16(_file_data, offset);
    }
    uint get_e_shstrndx() {; 
        return cast(ushort)(_file_data[50] | (_file_data[51] << 8));
    }
    uint get_shstr_size() {
        return read_ul_32(_file_data, get_shstr_hdr() + 20);
    }
    uint get_shstr_off() {
        size_t offset = get_shstr_hdr() + 16;
        return read_ul_32(_file_data, offset);
    }
    uint get_shstr_hdr() {
        return get_e_shoff() + get_e_shstrndx() * get_e_shentsz();
    }
    ref const(elf_section) get_symtab() {
        if (_symtab.data.length != 0)
            return _symtab;
        _symtab = get_section_by_name(this, ".symtab");
        return _symtab;
    }
    ref const(elf_section) get_strtab() {
        if (_strtab.data.length != 0)
            return _strtab;
        _strtab = get_section_by_name(this, ".strtab");
        return _strtab;
    }
    ref const(ubyte[]) get_symdata() {
        if (_symtab.data.length != 0)
            return _symtab.data;
        _symtab = get_section_by_name(this, ".symtab");
        return _symtab.data;
    }
    ref const(ubyte[]) get_strdata() {
        if (_strtab.data.length != 0)
            return _strtab.data;
        _strtab = get_section_by_name(this, ".strtab");
        return _strtab.data;
    }
    ref const(load_segment[]) get_load_segments() {
        if (_segs.length != 0)
            return _segs;
        _segs = .get_load_segments(_elf_file_name);
        return _segs;
    }
    ref const(ubyte[]) get_shstrtab() {
        if (_shstrtab.length != 0) 
            return _shstrtab;
        _shstrtab = _file_data[get_shstr_off() .. get_shstr_off() + get_shstr_size()];
        return _shstrtab;
    }
    ref const(ubyte[]) get_file_data() {
        return _file_data;
    }
    string get_file_name() {
        return _elf_file_name;
    }
    ref const(ubyte[]) get_text() {
        return get_text_section().data;
    }
    ref const(elf_section) get_text_section() {
        if (_text.data.length == 0) {
                _text = get_section_by_name(this, "text");
                if (_text.name == "")
                    _text = get_section_by_name(this, ".text");
        }
        return _text;
    }
    uint get_text_start_addr() {
        return get_text_section().addr;
    }
    uint get_text_end_addr() {
        return get_text_start_addr() + cast(uint)get_text().length;
    }
private:
    string _elf_file_name;
    uint _e_shoff;
    ushort _e_shnum;
    ushort _e_shentsz;
    uint _entry_point;
    ubyte[] _file_data;
    elf_section _symtab;
    elf_section _strtab;
    elf_section _text;
    ubyte[] _shstrtab;
    load_segment[] _segs;
}
// -------------------------------------------------------------------------------------- 

// --------------------------------------------------------------------------------------
alias read_fn(T) = T function(const(ubyte)[] data, size_t offset);
// --------------------------------------------------------------------------------------
// ===========================
//  GET UNSIGNED LITTE ENDIAN
// ===========================
ushort read_ul_16(const(ubyte)[] data, size_t offset) {
    auto v = data[offset] | (data[offset + 1] << 8);
    return cast(ushort)v;
}
// --------------------------------------------------------------------------------------
// ==========================
//  READ UNSIGNED BIG ENDIAN
// ==========================
ushort read_ub_16(const(ubyte)[] data, size_t offset) {
    auto v = data[offset + 1] | (data[offset] << 8);
    return cast(ushort)v;
}
// --------------------------------------------------------------------------------------
// ============================
//  READ UNSIGNED LITTE ENDIAN
// ============================
uint read_ul_32(const(ubyte)[] data, size_t offset) {
    uint v =   data[offset]
            | (data[offset + 1] <<  8)
            | (data[offset + 2] << 16)
            | (data[offset + 3] << 24);
    return v;
}
// --------------------------------------------------------------------------------------
// ==========================
//  READ UNSIGNED BIG ENDIAN
// ==========================

uint read_ub_32(const(ubyte)[] data, size_t offset) {
    ushort hw1 = cast(ushort)(data[offset]   | (data[offset+1] << 8));
    ushort hw2 = cast(ushort)(data[offset+2] | (data[offset+3] << 8));
    return (cast(uint)hw1 << 16) | hw2;
}

uint read_ub_32_(const(ubyte)[] data, size_t offset) {
    ushort hw1 = cast(ushort)(data[offset]   | (data[offset+1] << 8));
    ushort hw2 = cast(ushort)(data[offset+2] | (data[offset+3] << 8));
    return (cast(uint)hw2 << 16) | hw1;
}
// --------------------------------------------------------------------------------------
// =====================
//  GET ELF ENTRY POINT
// =====================
uint get_elf_entry_point(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 28);
    size_t offset = 24;
    return read_ul_32(data, offset);
}
// --------------------------------------------------------------------------------------
// =============
//  GET E SHOFF
// =============
uint get_e_shoff(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 36);
    size_t offset = 32;
    return read_ul_32(data, offset);
}
// --------------------------------------------------------------------------------------
// ===============
//  GET E SHENTSZ
// ===============
ushort get_e_shentsz(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 48);
    size_t offset = 46;
    return read_ul_16(data, offset);
}
// --------------------------------------------------------------------------------------
// =============
//  GET E SHNUM
// =============
ushort get_e_shnum(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 50);
    size_t offset = 48;
    return read_ul_16(data, offset);
}
// --------------------------------------------------------------------------------------
// ==============
//  GET SHSTRNDX
// ==============
uint get_e_shstrndx(const string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 52); 
    return cast(ushort)(data[50] | (data[51] << 8));
}
// --------------------------------------------------------------------------------------
// ===============
//  GET SHSTR HDR
// ===============
uint get_shstr_hdr(const ref string filename) {
    auto e_shoff = get_e_shoff(filename);
    auto e_shstrndx = get_e_shstrndx(filename);
    auto e_shentsz = get_e_shentsz(filename);
    return e_shoff + e_shstrndx * e_shentsz;
}
// --------------------------------------------------------------------------------------
// ==================
//  GET SHSTR OFFSET
// ==================
uint get_shstr_off(const ref string filename) {
    auto shstr_hdr = get_shstr_hdr(filename);
    ubyte[] data = cast(ubyte[]) read(filename, shstr_hdr + 20);
    size_t offset = shstr_hdr + 16;
    return read_ul_32(data, offset);
}
// --------------------------------------------------------------------------------------
// ================
//  GET SHSTR SIZE
// ================
uint get_shstr_size(const ref string filename) {
    auto shstr_hdr = get_shstr_hdr(filename);
    ubyte[] data = cast(ubyte[]) read(filename, shstr_hdr + 24);
    size_t offset = shstr_hdr + 20;
    return read_ul_32(data, offset);
}
// --------------------------------------------------------------------------------------
// ==============
//  GET SHSTRTAB
// ==============
ubyte[] get_shstrtab(const ref string filename) {
    auto shstr_off = get_shstr_off(filename);
    auto shstr_size = get_shstr_size(filename);
    ubyte[] data = cast(ubyte[]) read(filename, shstr_off + shstr_size);
    return data[shstr_off .. shstr_off + shstr_size];
}
// --------------------------------------------------------------------------------------
// ===================
//  GET SECTION NAMES
// ===================

string[] get_section_names(const ref string filename) {
    auto e_shnum   = get_e_shnum(filename);
    auto e_shoff   = get_e_shoff(filename);
    auto e_shentsz = get_e_shentsz(filename);
    auto shstrtab  = get_shstrtab(filename);
    ubyte[] data = cast(ubyte[]) read(filename);
    string[] names;
    foreach (i; 0 .. e_shnum) {
        size_t shdr = e_shoff + i * e_shentsz;
        uint name_off = read_ul_32(data, shdr);
        if (name_off >= shstrtab.length) 
            names ~= "<invalid>";
        else {
            size_t end = name_off;
            while (end < shstrtab.length && shstrtab[end] != 0) 
                end++; 
            names ~= cast(string) shstrtab[name_off .. end]; 
        } 
    }
    return names;
}
// --------------------------------------------------------------------------------------
// =============
//  ELF SECTION
// =============

struct elf_section {
    this (string _name, uint _addr, uint _off, const(ubyte)[] _data) {
        name = _name;
        addr = _addr;
        file_offset = _off;
        data = _data.dup;
    }
    string         name;
    uint           addr;
    uint    file_offset;
    ubyte[]        data;
}
// --------------------------------------------------------------------------------------
// =====================
//  GET SECTION BY NAME
// =====================

elf_section get_section_by_name(const string filename, const string section_name) {
    ubyte[] data   = cast(ubyte[]) read(filename);
    auto e_shnum   = get_e_shnum(filename);
    auto e_shoff   = get_e_shoff(filename);
    auto e_shentsz = get_e_shentsz(filename);
    auto shstrtab  = get_shstrtab(filename);
    foreach (i; 0 .. e_shnum) {
        size_t shdr   = e_shoff + i * e_shentsz;
        uint name_off = read_ul_32(data, shdr);
        size_t end    = name_off;
        while (end < shstrtab.length && shstrtab[end] != 0) 
            end++;
        string name   = (name_off < shstrtab.length) ? cast(string) shstrtab[name_off .. end] : "<invalid>";
        if (name == section_name) {
            uint sec_addr = read_ul_32(data, shdr + 12);
            uint sec_off  = read_ul_32(data, shdr + 16);
            uint sec_size = read_ul_32(data, shdr + 20);
            return elf_section(name, sec_addr, sec_off, data[sec_off .. sec_off + sec_size]);
        }
    }
    return elf_section("", 0, 0, []);
}

// --------------------------------------------------------------------------------------
elf_section get_section_by_name(elf_file elf, const string section_name) {
    const ubyte[] shstrtab = elf.get_shstrtab();
    const ubyte[] data     = elf.get_file_data();
    foreach (i; 0 .. elf.get_e_shnum()) {
        size_t shdr   = elf.get_e_shoff() + i * elf.get_e_shentsz();
        uint name_off = read_ul_32(elf.get_file_data(), shdr);
        size_t end    = name_off;
        while (end < shstrtab.length && shstrtab[end] != 0) 
            end++;
        string name   = (name_off < shstrtab.length) ? cast(string) shstrtab[name_off .. end] : "<invalid>";
        if (name == section_name) {
            uint sec_addr = read_ul_32(data, shdr + 12);
            uint sec_off  = read_ul_32(data, shdr + 16);
            uint sec_size = read_ul_32(data, shdr + 20);
            return elf_section(name, sec_addr, sec_off, data[sec_off .. sec_off + sec_size]);
        }
    }
    return elf_section("", 0, 0, []);
}
// --------------------------------------------------------------------------------------
// ==============
//  LOAD SEGMENT
// ==============
struct load_segment {
    uint file_offset;
    uint file_size;
    uint vaddr;
}
// --------------------------------------------------------------------------------------
// =====================
//  FILE OFFSET TO ADDR
// =====================

uint file_offset_to_addr(uint file_offset, load_segment[] segs) {
    foreach (s; segs) {
        if (file_offset >= s.file_offset &&
            file_offset <  s.file_offset + s.file_size) {
            return s.vaddr + (file_offset - s.file_offset);
        }
    }
    throw new Exception("file offset not mapped by any PT_LOAD");
}
// --------------------------------------------------------------------------------------
// ==========================
//  LOAD SECTION INTO MEMORY
// ==========================

void 
load_section_into_memory
(vm_t)
(const ref string filename, const string section_name, ref vm_t vm) {
    auto section = get_section_by_name(filename, section_name);
    if (section.data.length == 0)
        return;
    auto segments = get_load_segments(filename);
    uint addr = file_offset_to_addr(section.file_offset, segments);
    foreach (b; section.data)
        vm.load_byte(addr++, b);
}
// --------------------------------------------------------------------------------------
// ============
//  ELF 32 SYM
// ============

struct elf_32_sym {
    uint                st_name;   
    uint                st_value; 
    uint                st_size;   
    ubyte               st_info;   
    ubyte               st_other;
    ushort              st_shndx; 
}
// --------------------------------------------------------------------------------------
// ====================
//  GET ELF 32 ST TYPE
// ====================

ubyte get_elf_32_st_type(ubyte info) {
    return info & 0x0F;
}
// --------------------------------------------------------------------------------------
// =========
//  ST TYPE
// =========

enum st_type { 
    stt_notype                      = 0,
    stt_object                      = 1,
    stt_func                        = 2,
    stt_section                     = 3, 
    stt_file                        = 4,
    stt_common                      = 5,
    stt_loos                        = 10,
    stt_hios                        = 12,
    stt_loproc                      = 13,
    stt_hiproc                      = 14,
    all                             = 0xff
}
// --------------------------------------------------------------------------------------
// =============
//  ST NAME VAL
// =============

struct st_name_val {
    string      name;
    uint        addr;
    uint        size;
}

// --------------------------------------------------------------------------------------
// ================
//  STM32 START UP
// ================

string[] stm32_start_up = [
    "_init",
    "LoopFillZerobss",
    "frame_dummy",
    "CopyDataInit",
    "LoopCopyDataInit",
    "CopyDataInit",
    "FillZerobss",
    "register_tm_clones"
];
// --------------------------------------------------------------------------------------
// =====
//  SOC 
// =====

enum soc {
    stm32,
    nrf,
    nxp,
    s32k16,
    all
}
// --------------------------------------------------------------------------------------
// ============
//  FUNC SIZES
// ============

size_t[string] func_sizes = [
    //"__start"           :52,
    "__aeabi_uldivmod"  :48,
    "__aeabi_read_tp"   :12,
    "LoopFillZerobss"   :38,
    "LoopCopyDataInit"  :14,
    "_init"             :12,
    "frame_dummy"       :28,
    "Reset_Handler"     :18,
    "CopyDataInit"      : 6,
    "FillZerobss"       : 4,
    "register_tm_clones":36,
    "z_arm_bus_fault"   :20,
    "z_arm_svc"         :36
];
// --------------------------------------------------------------------------------------

enum SHN_UNDEF = 0;
enum SHN_ABS   = 0xFFF1;

// =================
//  GET ST NAME VAL
// =================

st_name_val[] get_st_name_val(const string elf_file, 
                              const st_type type = st_type.all, 
                              soc mcu, 
                              bool get_all = false, 
                              bool get_size = false) {
    auto symtab_sec = get_section_by_name(elf_file, ".symtab");
    auto strtab_sec = get_section_by_name(elf_file, ".strtab");
    auto text_sec   = get_section_by_name(elf_file, "text");

    if (text_sec.name == "")
        text_sec   = get_section_by_name(elf_file, ".text");

    ubyte[] symdata = symtab_sec.data;
    ubyte[] strdata = strtab_sec.data;
    uint text_start = text_sec.addr;
    uint text_end   = text_sec.addr + cast(uint)text_sec.data.length;

    st_name_val[] items;

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        auto sym = get_sym(symdata, pos);

        if (sym.st_shndx == SHN_ABS ||
            sym.st_shndx == SHN_UNDEF) {
            continue;
        }

        auto _st_type = get_elf_32_st_type(sym.st_info);
        
        uint name_off = sym.st_name;
        if(name_off >= strdata.length)
            continue;

        size_t end = name_off;
        while(end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if (name == "$d" || name == "$t") {
            continue;
        }

        if (type != st_type.all) {
            if (_st_type != type) {
                if (stm32_start_up.canFind(name)) {
                    // do nothing
                }
                else 
                    continue;
            }
        }

        if (!get_size) {
            if (!get_all) {
                uint lower_bound;
                if (mcu == soc.stm32) {
                    lower_bound = 0x08000000;
                } 
                if ((sym.st_value >= lower_bound) && (sym.st_value <= 0x20020000)) {
                    bool found = false;
                    if (_st_type != st_type.stt_func)
                        found = add_zephyr_syms(name, sym, items);
                    if (!found)
                        items ~= st_name_val(name, sym.st_value);
                }
            } else {
                items ~= st_name_val(name, sym.st_value);
            }
        } else {
            uint size = sym.st_size;
            if (size == 0 && name in func_sizes) 
                size = cast(uint)func_sizes[name];
            if (size == 0)
                size = get_func_size(elf_file, name); 
            items ~= st_name_val(name, sym.st_value, size);
        }
    }
    return items;
}
// --------------------------------------------------------------------------------------
// =================
//  GET ST NAME VAL
// =================

st_name_val get_st_name_val(const string elf_file, const string sym_name) {
    auto symtab_sec = get_section_by_name(elf_file, ".symtab");
    auto strtab_sec = get_section_by_name(elf_file, ".strtab");

    ubyte[] symdata = symtab_sec.data;
    ubyte[] strdata = strtab_sec.data;

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        auto sym = get_sym(symdata, pos);
        
        uint name_off = sym.st_name;
        if(name_off >= strdata.length)
            continue;

        size_t end = name_off;
        while(end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if (name == sym_name)
            return st_name_val(name, sym.st_value);
    }
    return st_name_val();
}

st_name_val get_st_name_val(ref elf_file elf, const string sym_name) {
    auto symdata = elf.get_symdata();
    auto strdata = elf.get_strdata();

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        auto sym = get_sym(symdata, pos);
        
        uint name_off = sym.st_name;
        if(name_off >= strdata.length)
            continue;

        size_t end = name_off;
        while(end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if (name == sym_name)
            return st_name_val(name, sym.st_value);
    }
    return st_name_val();
}
// --------------------------------------------------------------------------------------
// =================
//  GET ST NAME VAL
// =================

st_name_val[] get_st_name_val(ref elf_file elf, 
                              const st_type type = st_type.all, 
                              soc mcu, 
                              bool get_all = false, 
                              bool get_size = false) {
    auto symdata    = elf.get_symdata();
    auto strdata    = elf.get_strdata();
    auto text       = elf.get_text();
    uint text_start = elf.get_text_start_addr();
    uint text_end   = elf.get_text_end_addr();

    st_name_val[] items;

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        auto sym = get_sym(symdata, pos);

        if (sym.st_shndx == SHN_ABS ||
            sym.st_shndx == SHN_UNDEF) {
            continue;
        }

        auto _st_type = get_elf_32_st_type(sym.st_info);
        
        uint name_off = sym.st_name;
        if(name_off >= strdata.length)
            continue;

        size_t end = name_off;
        while(end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if (name == "$d" || name == "$t") {
            continue;
        }

        if (type != st_type.all) {
            if (_st_type != type) {
                if (stm32_start_up.canFind(name)) {
                    // do nothing
                }
                else 
                    continue;
            }
        }

        if (!get_size) {
            if (!get_all) {
                uint lower_bound;
                if (mcu == soc.stm32) {
                    lower_bound = 0x08000000;
                } 
                if ((sym.st_value >= lower_bound) && (sym.st_value <= 0x20020000)) {
                    bool found = false;
                    if (_st_type != st_type.stt_func)
                        found = add_zephyr_syms(name, sym, items);
                    if (!found)
                        items ~= st_name_val(name, sym.st_value);
                }
            } else {
                items ~= st_name_val(name, sym.st_value);
            }
        } else {
            uint size = sym.st_size;
            if (size == 0 && name in func_sizes) 
                size = cast(uint)func_sizes[name];
            if (size == 0)
                size = get_func_size(elf.get_file_name(), name); 
            items ~= st_name_val(name, sym.st_value, size);
        }
    }
    return items;
}
// --------------------------------------------------------------------------------------
// ==========
//  ELF FUNC
// ==========

struct elf_func {
    this (uint _off, const(ubyte)[] _data) {
        offset = _off;
        data = _data.dup;
    }
    uint    offset;
    ubyte[] data;
    uint[]  skipped_addrs;
}
// --------------------------------------------------------------------------------------
// ===================
//  VA TO FILE OFFSET
// ===================

size_t va_to_file_offset(const ref load_segment[] segs, uint va) {
    foreach (s; segs) {
        if (va >= s.vaddr && va < s.vaddr + s.file_size) {
            return s.file_offset + (va - s.vaddr);
        }
    }
    throw new Exception(format("VA %08X not in any PT_LOAD segment", va));
}
// --------------------------------------------------------------------------------------
size_t va_to_file_offset(ref elf_file elf, uint va) {
    const load_segment[] segs = elf.get_load_segments();
    return va_to_file_offset(segs, va);
}
// --------------------------------------------------------------------------------------

elf_section find_section_containing_va(const string elf_file, uint va) {
    auto e_shnum   = get_e_shnum(elf_file);
    auto e_shoff   = get_e_shoff(elf_file);
    auto e_shentsz = get_e_shentsz(elf_file);

    ubyte[] data = cast(ubyte[]) read(elf_file);

    foreach (i; 0 .. e_shnum) {
        size_t shdr = e_shoff + i * e_shentsz;

        uint sec_addr = read_ul_32(data, shdr + 12);
        uint sec_off  = read_ul_32(data, shdr + 16);
        uint sec_size = read_ul_32(data, shdr + 20);

        if (va >= sec_addr && va < sec_addr + sec_size) {
            return elf_section("", sec_addr, sec_off,
                data[sec_off .. sec_off + sec_size]);
        }
    }

    throw new Exception("VA not found in any section");
}

elf_section find_section_containing_va(ref elf_file elf, uint va) {
    auto data = elf.get_file_data();
    foreach (i; 0 .. elf.get_e_shnum()) {
        size_t shdr = elf.get_e_shoff() + i * elf.get_e_shentsz();

        uint sec_addr = read_ul_32(data, shdr + 12);
        uint sec_off  = read_ul_32(data, shdr + 16);
        uint sec_size = read_ul_32(data, shdr + 20);

        if (va >= sec_addr && va < sec_addr + sec_size) {
            return elf_section("", sec_addr, sec_off,
                data[sec_off .. sec_off + sec_size]);
        }
    }
    throw new Exception("VA not found in any section");
}
// --------------------------------------------------------------------------------------
// ==============
//  GET ELF FUNC
// ==============
ubyte[] file_data;

elf_func get_elf_func(const string elf_file, const string func_name, const uint addr) {
    auto symtab_sec = get_section_by_name(elf_file, ".symtab");
    auto strtab_sec = get_section_by_name(elf_file, ".strtab");
    auto text_sec   = get_section_by_name(elf_file, "text");

    if (text_sec.name == "")
        text_sec   = get_section_by_name(elf_file, ".text");

    ubyte[] symdata    = symtab_sec.data;
    ubyte[] strdata    = strtab_sec.data;
    uint    text_start = text_sec.addr;
    if (file_data.length == 0) 
        file_data = cast(ubyte[])read(elf_file);
    auto segs = get_load_segments(elf_file);

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        auto sym = get_sym(symdata, pos);

        uint name_off = sym.st_name;
        if (name_off >= strdata.length) continue;
        size_t end = name_off;
        while (end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if(name != func_name || sym.st_value != addr)
            continue;

        uint func_va = sym.st_value;
        func_va &= ~1u;

        size_t file_offset;
        try {
            file_offset = va_to_file_offset(segs, func_va);
        } catch (Exception) {
            auto section = find_section_containing_va(elf_file, func_va);
            file_offset = section.file_offset + (func_va - section.addr);
        }

        size_t size = cast(size_t)sym.st_size;

        if (size == 0 && name in func_sizes) 
            size = func_sizes[name]; 
        if (size == 0)
            size = get_func_size(elf_file, name); 

        auto data = file_data[file_offset .. file_offset + size];
        assert(data.length == size, format("%s: sizes are not equal, %d != %d", name, data.length, size));
        return elf_func(func_va, data);
    }
    return elf_func(0, []);
}

// --------------------------------------------------------------------------------------
elf_func get_elf_func(ref elf_file elf, const string func_name, const uint addr) {
    auto strdata = elf.get_strdata();
    auto symdata = elf.get_symdata();
    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        immutable sym      = get_sym(elf, pos);
        immutable name_off = sym.st_name;
        
        if (name_off >= strdata.length) 
            continue;
        
        size_t end = name_off;
        
        while (end < strdata.length && strdata[end] != 0) 
            end++;

        string name = cast(string) strdata[name_off .. end];

        if(name != func_name || sym.st_value != addr)
            continue;

        uint func_va = sym.st_value;
        func_va &= ~1u;

        size_t file_offset;
        try {
            file_offset = va_to_file_offset(elf, func_va);
        } catch (Exception) {
            auto section = find_section_containing_va(elf, func_va);
            file_offset = section.file_offset + (func_va - section.addr);
        }

        size_t size = cast(size_t)sym.st_size;

        if (size == 0 && name in func_sizes) 
            size = func_sizes[name]; 
        if (size == 0)
            size = get_func_size(elf.get_file_name(), name); 

        auto data = elf.get_file_data()[file_offset .. file_offset + size];
        assert(data.length == size, format("%s: sizes are not equal, %d != %d", name, data.length, size));
        return elf_func(func_va, data);
    }
    return elf_func(0, []);
}
// --------------------------------------------------------------------------------------
// =============
//  GET SYMDATA
// =============

elf_32_sym get_sym(const ubyte[] symdata, const size_t symstart) {
    elf_32_sym sym;
    sym.st_name  = read_ul_32(symdata, symstart + 0);
    sym.st_value = read_ul_32(symdata, symstart + 4);
    sym.st_size  = read_ul_32(symdata, symstart + 8);
    sym.st_info  = symdata[symstart + 12];
    sym.st_other = symdata[symstart + 13];
    sym.st_shndx = read_ul_16(symdata, symstart + 14);
    return sym;
}

elf_32_sym get_sym(ref elf_file elf, const size_t symstart) {
    return get_sym(elf.get_symdata(), symstart);
}
// --------------------------------------------------------------------------------------
// ======================
//  GET FUNCTION BY NAME
// ======================

ubyte[] get_function_by_name(const string elf_file, const string func_name) {
    auto symtab_sec   = get_section_by_name(elf_file, ".symtab");
    auto strtab_sec   = get_section_by_name(elf_file, ".strtab");
    auto text_sec     = get_section_by_name(elf_file, "text");

    if (text_sec.name == "")
        text_sec = get_section_by_name(elf_file, ".text");

    ubyte[] symdata    = symtab_sec.data;
    ubyte[] strdata    = strtab_sec.data;
    uint    text_start = text_sec.addr;
    ubyte[] text_data  = text_sec.data;

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        auto sym = get_sym(symdata, pos);

        if(get_elf_32_st_type(sym.st_info) != st_type.stt_func)
            continue;

        uint name_off = sym.st_name;
        if (name_off >= strdata.length) continue;
        size_t end = name_off;
        while (end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if(name != func_name)
            continue;

        if(sym.st_value < text_start || sym.st_value >= text_start + text_data.length)
            throw new Exception(format("Function %s is outside .text section", func_name));

        size_t offset_in_text = cast(size_t)(sym.st_value - text_start);
        size_t size = cast(size_t)sym.st_size;

        if(offset_in_text + size > text_data.length)
            size = text_data.length - offset_in_text;

        return text_data[offset_in_text - 1 .. offset_in_text + size - 1];
    }
    return [];
}
// --------------------------------------------------------------------------------------
// =======================
//  IS 32-BIT INSTRUCTION
// =======================

bool is_32_bit_instr(uint instr) {
    ushort first_hw = cast(ushort)(instr & 0xFFFF);
    return (first_hw & 0xF800) >= 0xE800;
}

bool is_32_bit_instr(ushort first_hw) {
    return ((first_hw & 0xE000) == 0xE000) &&
           ((first_hw & 0x1800) != 0x0000);
}
// --------------------------------------------------------------------------------------
// =============
//  FETCH INSTR
// =============

string fetch_instr(ubyte[] b) {
    if (b.length == 2) return format("%02x%02x", b[1], b[0]);
    if (b.length == 4) return format("%02x%02x%02x%02x", b[1], b[0], b[3], b[2]);
    assert(0, "Invalid instruction length");
}
// --------------------------------------------------------------------------------------
// =======================
//  GET FUNCTION FROM ELF
// =======================

func get_function_from_elf(const string elf_file, 
                           const string func_name, 
                           const uint addr, 
                           ref bool[uint] pending_literals) {
    func res;
    res.name             = func_name;
    auto e_func          = get_elf_func(elf_file, func_name, addr);
    auto literal_offsets = extract_literal_pool(elf_file, e_func, res, pending_literals);
    uint offset          = 0;
    uint addr_offset     = 0;
    while (offset + 2 <= e_func.data.length) {
        if ((offset + 2 == e_func.data.length) && (read_ul_16(e_func.data, offset) == 0))
            break;
        ushort first_hw  = read_ul_16(e_func.data, offset);
        uint len         = (first_hw & 0xF800) >= 0xE800 ? 4 : 2;
        ubyte[] bytes;
        assert(e_func.data.length != 0);
        try {
            bytes = e_func.data[offset .. offset + len];
        }
        catch (ArraySliceError e) {
            writeln("Slice failed: " ~ func_name);
        }
        while (addr_offset in literal_offsets) 
            addr_offset += 4;
        while (e_func.skipped_addrs.canFind(addr_offset))
            addr_offset += 2;
        if (len == 2) {
            auto op = decode_mnemonic(read_ul_16(bytes, 0));
            if (op == opcode.invalid) {
                addr_offset += len;
                offset      += len;     
                continue;
            }
        } else { // len == 4
            auto op = decode_mnemonic(read_ub_32(bytes, 0));
            if (op == opcode.invalid) {
                addr_offset += len;
                offset      += len;
                continue;
            } 
        }
        res.instrs  ~= addr_instr(e_func.offset + addr_offset, fetch_instr(bytes));
        offset      += len;
        addr_offset += len;
    }
    return res; 
}

func get_function_from_elf(ref elf_file elf, 
                           const string func_name, 
                           const uint addr, 
                           ref bool[uint] pending_literals) {
    func res;
    res.name             = func_name;
    auto e_func          = get_elf_func(elf, func_name, addr);
    auto literal_offsets = extract_literal_pool(elf, e_func, res, pending_literals);
    uint offset          = 0;
    uint addr_offset     = 0;
    while (offset + 2 <= e_func.data.length) {
        if ((offset + 2 == e_func.data.length) && (read_ul_16(e_func.data, offset) == 0))
            break;
        ushort first_hw  = read_ul_16(e_func.data, offset);
        uint len         = (first_hw & 0xF800) >= 0xE800 ? 4 : 2;
        ubyte[] bytes;
        try {
            bytes = e_func.data[offset .. offset + len];
        }
        catch (ArraySliceError e) {
            writeln("Slice failed: " ~ func_name);
        }
        while (addr_offset in literal_offsets) 
            addr_offset += 4;
        while (e_func.skipped_addrs.canFind(addr_offset))
            addr_offset += 2;
        if (len == 2) {
            auto op = decode_mnemonic(read_ul_16(bytes, 0));
            if (op == opcode.invalid) {
                addr_offset += len;
                offset      += len;     
                continue;
            }
        } else { // len == 4
            auto op = decode_mnemonic(read_ub_32(bytes, 0));
            if (op == opcode.invalid) {
                addr_offset += len;
                offset      += len;
                continue;
            } 
        }
        res.instrs  ~= addr_instr(e_func.offset + addr_offset, fetch_instr(bytes));
        offset      += len;
        addr_offset += len;
    }
    return res; 
}
// --------------------------------------------------------------------------------------
// ======================
//  EXTRACT LITERAL POOL
// ======================

bool[uint] extract_literal_pool(const string elf_file, ref elf_func e_func, 
                                ref func f, 
                                ref bool[uint] pending_literals) {
    auto text_sec     = get_section_by_name(elf_file, "text");
    if (text_sec.name == "")
        text_sec = get_section_by_name(elf_file, ".text");
    uint text_sec_start = text_sec.addr;
    uint text_sec_end   = cast(uint)(text_sec.addr + text_sec.data.length);
    uint[]     to_remove;
    bool[uint] words_to_remove;
    bool[uint] literal_offsets;
    auto data   = e_func.data;
    uint offset = 0;
    foreach (l, _; pending_literals) {
        if (l >= e_func.offset && l < e_func.offset + data.length) {
            to_remove ~= l;
            const uint rel_offset = l - e_func.offset;
            words_to_remove[rel_offset] = true;
            literal_offsets[rel_offset] = true;
            f.literal_pool[l] = read_ub_32_(data, rel_offset);        
        }
    }
    foreach (l; to_remove) {
        pending_literals.remove(l);
    }
    uint cmp_instr_size;
    uint branch_instr_size;
    while (offset + 2 <= data.length) {
        if (offset in words_to_remove) {
            offset += 4;
            continue;
        }
        ushort first_hw = read_ul_16(data, offset);
        uint len = is_32_bit_instr(first_hw) ? 4 : 2;
        if (len == 4) {
            if (offset + len >= data.length) {
                offset += 4;
                continue;
            }
            uint instr = read_ub_32(data, offset);
            if (decode_mnemonic(instr) == opcode.ldr_lit_t2) {
                auto parsed_instr = decode_instr!(instr_32,uint)(instr);
                uint base = e_func.offset + offset + 4;
                base &= ~0x3;   
                uint lit_offset = base + parsed_instr.imm;
                uint rel_offset = lit_offset - e_func.offset; 
                words_to_remove[rel_offset] = true;
                literal_offsets[rel_offset] = true;
                if (rel_offset < data.length) 
                    f.literal_pool[lit_offset] = read_ub_32_(data, rel_offset);
                else 
                    pending_literals[lit_offset] = true;
            }
            if (decode_mnemonic(instr) == opcode.ldr_reg_t2) {
                auto parsed_instr = decode_instr!(instr_32,uint)(instr);
                if (parsed_instr.rt == reg.pc) { 
                    int  base     = offset + 4;
                    uint abs_base = e_func.offset;
                    abs_base &= ~0x3; 
                    auto next_instr = read_ul_16(data, base);
                    if (decode_mnemonic(next_instr) == opcode.nop_t1)
                        base += 2;
                    int table_pos = base;
                    while (read_ul_32(data, table_pos) > text_sec_start && 
                           read_ul_32(data, table_pos) < text_sec_end) {
                        words_to_remove[table_pos] = true;
                        literal_offsets[table_pos] = true; 
                        f.literal_pool[abs_base + table_pos] = read_ub_32_(data, table_pos);
                        table_pos += 4;
                    }
                }
            }
            if (decode_mnemonic(instr) == opcode.tbb_tbh_t1) {
                auto parsed_instr = decode_instr!(instr_32,uint)(instr);
                bool is_tbh = parsed_instr.is_tbh;
                uint cmp_offset = offset - branch_instr_size - cmp_instr_size;
                uint cmp_imm;
                if (cmp_instr_size == 2) {
                    auto cmp_instr = read_ul_16(data, cmp_offset);
                    cmp_imm = decode_instr!(instr_16,ushort)(cmp_instr).imm;  
                } else { 
                    auto cmp_instr = read_ul_32(data, cmp_offset);
                    cmp_imm = decode_instr!(instr_32,uint)(cmp_instr).imm; 
                }
                uint entries     = cmp_imm + 1;
                uint raw_size    = is_tbh ? entries * 2 : entries;
                uint padded_size = (raw_size & 1) ? raw_size + 1 : raw_size;
                f.byte_tables ~= byte_table(
                    offset + 4,
                    e_func.offset + offset + 4,
                    data[(offset + 4) .. (offset + 4 + padded_size)]
                );
                for (int i = offset + 4; i < offset + 4 + padded_size; i += 2) 
                    e_func.skipped_addrs ~= i;
                offset += padded_size;
            }
        } else if (len == 2) {
            if (decode_mnemonic(first_hw) == opcode.ldr_lit_t1) {
                auto parsed_instr = decode_instr!(instr_16,ushort)(first_hw);
                uint base = e_func.offset + offset + 4;
                base &= ~0x3;   
                uint lit_offset = base + parsed_instr.imm;
                uint rel_offset = lit_offset - e_func.offset; 
                words_to_remove[rel_offset] = true;
                literal_offsets[rel_offset] = true;          
                if (rel_offset < data.length) 
                    f.literal_pool[lit_offset] = read_ub_32_(data, rel_offset);
                else 
                    pending_literals[lit_offset] = true;
            }
            if (decode_mnemonic(first_hw) == opcode.adr_t1) {
                auto parsed_instr = decode_instr!(instr_16,ushort)(first_hw);
                auto next_instr = read_ul_32(data, offset + 2);
                if (decode_mnemonic(next_instr) != opcode.ldr_reg_t2) {
                    uint lit_offset = word_align(offset) + 4 + parsed_instr.imm;
                    words_to_remove[lit_offset] = true;
                    literal_offsets[lit_offset] = true;
                    if (lit_offset + 4 < data.length) 
                         f.literal_pool[e_func.offset + lit_offset] = read_ub_32_(data, lit_offset);
                    else 
                        pending_literals[lit_offset] = true;
                }
            }
        }
        offset += len;
        cmp_instr_size = branch_instr_size;
        branch_instr_size = len;
    }
    uint[uint] widths;
    foreach (w; words_to_remove.keys) {
        widths[w] = 4;  
    }
    foreach (table; f.byte_tables) {;
        widths[table.offset] = cast(uint)table.data.length;
    }
    auto keys = widths.keys;
    keys.sort;      
    keys.reverse;
    foreach (w; keys) {
        uint width = widths[w];
        if (w + width <= data.length) 
            data = data[0 .. w] ~ data[w + width .. $];
    }
    e_func.data = data;
    return literal_offsets;
}

bool[uint] extract_literal_pool(ref elf_file elf, ref elf_func e_func, 
                                ref func f, 
                                ref bool[uint] pending_literals) {
    auto text_sec       = elf.get_text_section();
    uint text_sec_start = elf.get_text_start_addr();
    uint text_sec_end   = elf.get_text_end_addr();
    uint[]     to_remove;
    bool[uint] words_to_remove;
    bool[uint] literal_offsets;
    auto data   = e_func.data;
    uint offset = 0;
    foreach (l, _; pending_literals) {
        if (l >= e_func.offset && l < e_func.offset + data.length) {
            to_remove ~= l;
            const uint rel_offset = l - e_func.offset;
            words_to_remove[rel_offset] = true;
            literal_offsets[rel_offset] = true;
            f.literal_pool[l] = read_ub_32_(data, rel_offset);        
        }
    }
    foreach (l; to_remove) {
        pending_literals.remove(l);
    }
    uint cmp_instr_size;
    uint branch_instr_size;
    while (offset + 2 <= data.length) {
        if (offset in words_to_remove) {
            offset += 4;
            continue;
        }
        ushort first_hw = read_ul_16(data, offset);
        uint len = is_32_bit_instr(first_hw) ? 4 : 2;
        if (len == 4) {
            if (offset + len >= data.length) {
                offset += 4;
                continue;
            }
            uint instr = read_ub_32(data, offset);
            if (decode_mnemonic(instr) == opcode.ldr_lit_t2) {
                auto parsed_instr = decode_instr!(instr_32,uint)(instr);
                uint base = e_func.offset + offset + 4;
                base &= ~0x3;   
                uint lit_offset = base + parsed_instr.imm;
                uint rel_offset = lit_offset - e_func.offset; 
                words_to_remove[rel_offset] = true;
                literal_offsets[rel_offset] = true;
                if (rel_offset < data.length) 
                    f.literal_pool[lit_offset] = read_ub_32_(data, rel_offset);
                else 
                    pending_literals[lit_offset] = true;
            }
            if (decode_mnemonic(instr) == opcode.ldr_reg_t2) {
                auto parsed_instr = decode_instr!(instr_32,uint)(instr);
                if (parsed_instr.rt == reg.pc) { 
                    int  base     = offset + 4;
                    uint abs_base = e_func.offset;
                    abs_base &= ~0x3; 
                    auto next_instr = read_ul_16(data, base);
                    if (decode_mnemonic(next_instr) == opcode.nop_t1)
                        base += 2;
                    int table_pos = base;
                    while (read_ul_32(data, table_pos) > text_sec_start && 
                           read_ul_32(data, table_pos) < text_sec_end) {
                        words_to_remove[table_pos] = true;
                        literal_offsets[table_pos] = true; 
                        f.literal_pool[abs_base + table_pos] = read_ub_32_(data, table_pos);
                        table_pos += 4;
                    }
                }
            }
            if (decode_mnemonic(instr) == opcode.tbb_tbh_t1) {
                auto parsed_instr = decode_instr!(instr_32,uint)(instr);
                bool is_tbh = parsed_instr.is_tbh;
                uint cmp_offset = offset - branch_instr_size - cmp_instr_size;
                uint cmp_imm;
                if (cmp_instr_size == 2) {
                    auto cmp_instr = read_ul_16(data, cmp_offset);
                    cmp_imm = decode_instr!(instr_16,ushort)(cmp_instr).imm;  
                } else { 
                    auto cmp_instr = read_ul_32(data, cmp_offset);
                    cmp_imm = decode_instr!(instr_32,uint)(cmp_instr).imm; 
                }
                uint entries     = cmp_imm + 1;
                uint raw_size    = is_tbh ? entries * 2 : entries;
                uint padded_size = (raw_size & 1) ? raw_size + 1 : raw_size;
                f.byte_tables ~= byte_table(
                    offset + 4,
                    e_func.offset + offset + 4,
                    data[(offset + 4) .. (offset + 4 + padded_size)]
                );
                for (int i = offset + 4; i < offset + 4 + padded_size; i += 2) 
                    e_func.skipped_addrs ~= i;
                offset += padded_size;
            }
        } else if (len == 2) {
            if (decode_mnemonic(first_hw) == opcode.ldr_lit_t1) {
                auto parsed_instr = decode_instr!(instr_16,ushort)(first_hw);
                uint base = e_func.offset + offset + 4;
                base &= ~0x3;   
                uint lit_offset = base + parsed_instr.imm;
                uint rel_offset = lit_offset - e_func.offset; 
                words_to_remove[rel_offset] = true;
                literal_offsets[rel_offset] = true;          
                if (rel_offset < data.length) 
                    f.literal_pool[lit_offset] = read_ub_32_(data, rel_offset);
                else 
                    pending_literals[lit_offset] = true;
            }
            if (decode_mnemonic(first_hw) == opcode.adr_t1) {
                auto parsed_instr = decode_instr!(instr_16,ushort)(first_hw);
                auto next_instr = read_ul_32(data, offset + 2);
                if (decode_mnemonic(next_instr) != opcode.ldr_reg_t2) {
                    uint lit_offset = word_align(offset) + 4 + parsed_instr.imm;
                    words_to_remove[lit_offset] = true;
                    literal_offsets[lit_offset] = true;
                    if (lit_offset + 4 < data.length) 
                         f.literal_pool[e_func.offset + lit_offset] = read_ub_32_(data, lit_offset);
                    else 
                        pending_literals[lit_offset] = true;
                }
            }
        }
        offset += len;
        cmp_instr_size = branch_instr_size;
        branch_instr_size = len;
    }
    uint[uint] widths;
    foreach (w; words_to_remove.keys) {
        widths[w] = 4;  
    }
    foreach (table; f.byte_tables) {;
        widths[table.offset] = cast(uint)table.data.length;
    }
    auto keys = widths.keys;
    keys.sort;      
    keys.reverse;
    foreach (w; keys) {
        uint width = widths[w];
        if (w + width <= data.length) 
            data = data[0 .. w] ~ data[w + width .. $];
    }
    e_func.data = data;
    return literal_offsets;
}
// --------------------------------------------------------------------------------------
// ===========================
//  LOAD FUNCTION INTO MEMORY
// ===========================

void 
load_function_into_memory
(vm_t)
(func f, ref vm_t vm) {
    foreach (i; f.instrs) {
        if (i._instr_bytes.length == 4) {
            vm.load_half_word(i._addr, i._in_16);
        }
        if (i._instr_bytes.length == 8) {
            vm.load_word(i._addr, i._in_32);
        }
    }
    foreach (addr, value; f.literal_pool) {
        vm.load_word(addr, value);
    }
    foreach (t; f.byte_tables) {
        uint offset = 0;
        auto data   = t.data;
        uint addr   = t.addr;
        while (offset + 4 <= data.length) {
            immutable val = read_ul_32(data, offset);
            vm.load_word(addr, val);
            offset += 4;
            addr   += 4;
        }
        if (offset + 2 <= data.length) {
            immutable val = read_ul_16(data, offset);
            vm.load_half_word(addr, val);
            offset += 2;
            addr   += 2;
        }
        enforce(offset == data.length, "Table size not aligned to 2 bytes");
    }
}
// --------------------------------------------------------------------------------------
// ======================
//  GET PROGRAM FROM ELF
// ======================

func[] get_program_from_elf(const string elf_file) {
    bool[uint] pending_literals;
    func[] res;
    auto f_s = get_st_name_val(elf_file, st_type.stt_func, soc.all);
    auto s   = get_st_name_val(elf_file, "delay_machine_code.0");
    if (s.name != "") 
        f_s ~= s;
    foreach (fn; f_s) {
        auto f = get_function_from_elf(elf_file, fn.name, fn.addr, pending_literals);
        res ~= f; 
    }
    return res;
}

func[] get_program_from_elf(ref elf_file elf) {
    bool[uint] pending_literals;
    func[] res;
    auto f_s = get_st_name_val(elf, st_type.stt_func, soc.all);
    auto s   = get_st_name_val(elf, "delay_machine_code.0");
    if (s.name != "") 
        f_s ~= s;
    foreach (fn; f_s) {
        auto f = get_function_from_elf(elf, fn.name, fn.addr, pending_literals);
        res ~= f; 
    }
    return res;
}
// --------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------
unittest {
    auto filename = "../test/blinky.elf";
    // --------------------------------------------------------------------------------------
    // ==========================
    //  TEST GET ELF ENTRY POINT
    // ==========================
    {
        uint entry_point = get_elf_entry_point(filename);
        assert(entry_point == 0x8000A91);
    }
    // --------------------------------------------------------------------------------------
    // ==================
    //  TEST GET E SHOFF
    // ==================
    {
        uint actual_e_shoff = get_e_shoff(filename);
        assert(actual_e_shoff == 0x86860, 
               format("e_shoff is [%08X], not the expected 0x86860", 
               actual_e_shoff));
    }
    // --------------------------------------------------------------------------------------
    // ====================
    //  TEST GET E SHENTSZ
    // ====================
    {
        ushort actual_e_shentsz = get_e_shentsz(filename);
        assert(actual_e_shentsz == 0x28, 
               format("e_shentsz is [%08X], not the expected 0x28", 
               actual_e_shentsz));
    }
    // --------------------------------------------------------------------------------------
    // ==================
    //  TEST GET E SHNUM
    // ==================
    {
        ushort actual_e_shnum = get_e_shnum(filename);
        assert(actual_e_shnum == 0x22, 
               format("e_shnum is [%08X], not the expected 0x22", 
               actual_e_shnum));
    }
    // --------------------------------------------------------------------------------------
    // =======================
    //  TEST GET SHSTR HEADER
    // =======================
    {
        uint actual_shstr_hdr = get_shstr_hdr(filename);
        assert(actual_shstr_hdr == 0x86860 + 33 * 0x28, 
               format("shstr_hdr is [%08X], not the expected value", 
               actual_shstr_hdr));
    }
    // --------------------------------------------------------------------------------------
    // =======================
    //  TEST GET SHSTR OFFSET
    // =======================
    {
        uint actual_shstr_off = get_shstr_off(filename);
        assert(actual_shstr_off == 0x866BE, 
               format("shstr_off is [%08X], not the expected 0x866BE", 
               actual_shstr_off));
    }
    // --------------------------------------------------------------------------------------
    // =====================
    //  TEST GET SHSTR SIZE
    // =====================
    {
        uint actual_shstr_size = get_shstr_size(filename);
        assert(actual_shstr_size == 0x1A2, 
               format("shstr_size is [%08X], not the expected 0x1A2", 
               actual_shstr_size));
    }
    // --------------------------------------------------------------------------------------
    // ============================
    //  TEST GET FUNCTION FROM ELF
    // ============================
    bool[uint] l;
    auto __start = get_function_from_elf(filename, "__start", 0x8000A91, l);
    auto start_addr = __start.instrs[0]._addr;
    assert(start_addr == 0x8000A90, 
           format("Actual instr_bytes is [%08X], not the expected 0x8000A90", 
           start_addr));
    // --------------------------------------------------------------------------------------
    // ===================
    //  TEST GET ELF FUNC
    // ===================
    {
        auto e_func = get_elf_func("../test/z_prod_con.elf", "__l_vfprintf", 
                                   0x800A085);
        assert(e_func.data.length == 1208, 
               format("Func is %d and not 1268", 
               e_func.data.length));
    }
    {
        auto e_func = get_elf_func(filename, "__start", 0x8000A91);
        assert(e_func.offset == 0x8000a90, 
               format("Actual char_out offset is [%08X], not the expected 0x8000A90", 
               e_func.offset));
    }
    // ===============================
    //  TEST LOAD SECTION INTO MEMORY
    // ===============================
    {
        auto section_name = "device_area";
        cortex_m_vm!(stm32f4_mem) mem;
        load_section_into_memory(filename, section_name, mem);
        auto actual_data = mem.read_word(0x80039D4);
        assert(actual_data == 0x08004446, 
               format("Actual device area length is %d, not the expected 0x08004446", 
               actual_data));
    }
    // --------------------------------------------------------------------------------------
    // ==========================
    //  TEST GET SECTION BY NAME
    // ==========================
    {
        auto section_name = "device_area";
        auto device_area_section = get_section_by_name(filename, section_name);
        assert(device_area_section.data.length == 364, 
               format("Actual device area length is %d, not the expected 364", 
               device_area_section.data.length));
        assert(device_area_section.addr == 0x80039D4, 
               format("Actual device area offset is [%X08], not the expected 0x80039d4", 
               device_area_section.addr));
    }
    // --------------------------------------------------------------------------------------
}
// --------------------------------------------------------------------------------------
// ==============
//  MEMBER NAMES
// ==============
Tuple!(string, int)[][string] member_names = [
    "uart_cfg":       [tuple("parity",      0), 
                       tuple("stop_bits",   1), 
                       tuple("data_bits",   2), 
                       tuple("flow_ctrl",   3)],
    "mpu_config":     [tuple("num_regions", 0), 
                       tuple("mpu_regions", 4)],
    "gpio_stm32_cfg": [tuple("common.port_pin_mask", 0),
                       tuple("base", 4),
                       tuple("port", 8),
                       tuple("pclken.bus", 12),
                       tuple("pclken.div", 16),
                       tuple("pclken.enr", 20)]
];
// --------------------------------------------------------------------------------------
// =================
//  ADD ZEPHYR SYMS
// =================

bool add_zephyr_syms(string name, const ref elf_32_sym sym, st_name_val[] items) {
    bool found = false;
    foreach (k, v; member_names) {
        if (name.canFind(k)) {
            found = true;
            foreach (i; v) {
                items ~= st_name_val(name ~ "." ~ i[0], sym.st_value + i[1]);
            }
        }
    }
    return found;
}
// --------------------------------------------------------------------------------------
// =============
//  GET CONFIGS
// =============

st_name_val[] get_configs(const string elf_filename) {
    auto vals = get_st_name_val(elf_filename, st_type.all, soc.stm32, true);
    st_name_val[] configs;
    foreach (val; vals) {
        if (val.name.canFind("CONFIG")) {
            configs ~= val;
        }
    } 
    return configs;
}
// --------------------------------------------------------------------------------------
// ===============
//  GET FUNC SIZE
// ===============

int get_func_size(const string elf_filename, const string func_name) {
    auto f_s  = get_st_name_val(elf_filename, st_type.stt_func, soc.all);
    auto func = get_st_name_val(elf_filename, func_name);
    uint next_f_addr = 0xffffffff;
    foreach (f; f_s) {
        if ((f.addr & 0xFFFF0000) != (func.addr & 0xFFFF0000))
            continue;
        if (f.addr > func.addr && f.addr < next_f_addr)
            next_f_addr = f.addr;
    }
    if (next_f_addr == 0xffffffff)
        return 0;
    return next_f_addr - func.addr;
} 
// ------------------------------------------------------------------------------------------
unittest {
    // ====================
    //  TEST GET FUNC SIZE
    // ====================
    auto filename = "../test/blinky.elf";
    auto size     = get_func_size(filename, "z_arm_pendsv");
    assert(size == 84, format("pendsv size is %d, not 84", size));
    // --------------------------------------------------------------------------------------
}

// =============
//  ZEPHYR VARS
// =============

string[] z_vars = [
//    "announce_remaining",
    //announced_cycles",
//    "curr_tick",
//    "cycle_count",
//    "last_load",
//    "overflow_cyc",
//    "pending_current",
//    "slice_max_prio",
//    "slice_ticks",
//    "z_sys_post_kernel",
//    "z_arm_tls_ptr"
];

string[] z_configs = [
//    "CONFIG_IDLE_STACK_SIZE",
//    "CONFIG_ISR_STACK_SIZE",
//    "CONFIG_NUM_COOP_PRIORITIES",
//    "CONFIG_MP_MAX_NUM_CPUS",
//    "CONFIG_NUM_PREEMPT_PRIORITIES",
//    "CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC",
//    "CONFIG_SYS_CLOCK_MAX_TIMEOUT_DAYS",
//    "CONFIG_SYS_CLOCK_TICKS_PER_SEC",
//    "CONFIG_TIMEOUT_64BIT",
//    "CONFIG_TIMESLICE_SIZE"
];

st_name_val[] get_z_vars(const string elf_file) {
    st_name_val[] res;
    foreach (v; z_vars) {
       auto s = get_st_name_val(elf_file, v);
       res ~= s;
    }
    return res;
}

st_name_val[] get_z_configs(const string elf_file) {
    st_name_val[] res;
    foreach (v; z_configs) {
       auto s = get_st_name_val(elf_file, v);
       res ~= s;
    }
    return res;
}