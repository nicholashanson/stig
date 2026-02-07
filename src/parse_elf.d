import std.stdio;
import std.exception;
import std.conv;
import std.file;
import std.array;
import std.format;

import memory_sections;
import thumb_2_opcodes;
import cortex_m;

enum elf_class {
    elf_32 = 1,
    elf_64 = 2
}

enum elf_endian {
    little = 1,
    big = 2
}

struct elf_file_info {
    elf_class e_class;
    elf_endian endian;
}

enum elf_tpye {
    none,
    rel,
    exec,
    dyn, 
    core,
    lo_proc = 0xff00,
    hi_proc = 0xffff
}

enum elf_machine {
    arm = 40
}

enum elf_osabi {
    sysv,
    hpux,
    netbsd,
    linux,
    hurd,
    solaris,
    aix,
    irix,
    freebsd,
    tru64,
    modesto,
    openbsd,
    openvms,
    nsk,
    aros,
    fenixos,
    cloud,
    sortix,
    arm_aeabi,
    arm,
    cell_lv2,
    standalone,
}

alias read_fn(T) = T function(const(ubyte)[] data, size_t offset);

ushort read_ul_16(const(ubyte)[] data, size_t offset) {
    auto v = data[offset] | (data[offset + 1] << 8);
    return cast(ushort)v;
}

uint read_ul_32(const(ubyte)[] data, size_t offset) {
    uint v =   data[offset]
            | (data[offset + 1] <<  8)
            | (data[offset + 2] << 16)
            | (data[offset + 3] << 24);
    return v;
}

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

uint get_elf_entry_point(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 28);
    size_t offset = 24;
    return read_ul_32(data, offset);
}

unittest {
    auto filename = "../test/blinky.elf";
    uint entry_point = get_elf_entry_point(filename);
    assert(entry_point == 0x8000a91);
}

uint get_e_shoff(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 36);
    size_t offset = 32;
    return read_ul_32(data, offset);
}

unittest {
    auto filename = "../test/blinky.elf";
    uint actual_e_shoff = get_e_shoff(filename);
    assert(actual_e_shoff == 0x86860, format("Actual e_shoff is [%08X], not the expected 0x86860", actual_e_shoff));
}

ushort get_e_shentsz(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 48);
    size_t offset = 46;
    return read_ul_16(data, offset);
}

unittest {
    auto filename = "../test/blinky.elf";
    ushort actual_e_shentsz = get_e_shentsz(filename);
    assert(actual_e_shentsz == 0x28, format("Actual e_shentsz is [%08X], not the expected 0x28", actual_e_shentsz));
}

ushort get_e_shnum(const ref string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 50);
    size_t offset = 48;
    return read_ul_16(data, offset);
}

unittest {
    auto filename = "../test/blinky.elf";
    ushort actual_e_shnum = get_e_shnum(filename);
    assert(actual_e_shnum == 0x22, format("Actual e_shnum is [%08X], not the expected 0x22", actual_e_shnum));
}

uint get_e_shstrndx(const string filename) {
    ubyte[] data = cast(ubyte[]) read(filename, 52); 
    return cast(ushort)(data[50] | (data[51] << 8));
}

uint get_shstr_hdr(const ref string filename) {
    auto e_shoff = get_e_shoff(filename);
    auto e_shstrndx = get_e_shstrndx(filename);
    auto e_shentsz = get_e_shentsz(filename);
    return e_shoff + e_shstrndx * e_shentsz;
}

unittest {
    auto filename = "../test/blinky.elf";
    uint actual_shstr_hdr = get_shstr_hdr(filename);
    assert(actual_shstr_hdr == 0x86860 + 33 * 0x28, format("Actual e_shnum is [%08X], not the expected value", actual_shstr_hdr));
}

uint get_shstr_off(const ref string filename) {
    auto shstr_hdr = get_shstr_hdr(filename);
    ubyte[] data = cast(ubyte[]) read(filename, shstr_hdr + 20);
    size_t offset = shstr_hdr + 16;
    return read_ul_32(data, offset);
}

unittest {
    auto filename = "../test/blinky.elf";
    uint actual_shstr_off = get_shstr_off(filename);
    assert(actual_shstr_off == 0x866be, format("Actual shstr_off is [%08X], not the expected 0x866be", actual_shstr_off));
}

uint get_shstr_size(const ref string filename) {
    auto shstr_hdr = get_shstr_hdr(filename);
    ubyte[] data = cast(ubyte[]) read(filename, shstr_hdr + 24);
    size_t offset = shstr_hdr + 20;
    return read_ul_32(data, offset);
}

unittest {
    auto filename = "../test/blinky.elf";
    uint actual_shstr_size = get_shstr_size(filename);
    assert(actual_shstr_size == 0x1a2, format("Actual shstr_off is [%08X], not the expected 0x1a2", actual_shstr_size));
}

ubyte[] get_shstrtab(const ref string filename) {
    auto shstr_off = get_shstr_off(filename);
    auto shstr_size = get_shstr_size(filename);
    ubyte[] data = cast(ubyte[]) read(filename, shstr_off + shstr_size);
    return data[shstr_off .. shstr_off + shstr_size];
}

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

unittest {
    auto filename = "../test/blinky.elf";
    auto section_names = get_section_names(filename);
    foreach (name; section_names) {
        writeln(name);
    }
}

struct elf_section {
    string  name;
    uint    addr;
    uint    file_offset;
    ubyte[] data;
}

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

unittest {
    auto filename = "../test/blinky.elf";
    auto section_name = "device_area";
    auto device_area_section = get_section_by_name(filename, section_name);
    assert(device_area_section.data.length == 364, 
           format("Actual device area length is %d, not the expected 364", device_area_section.data.length));
    assert(device_area_section.addr == 0x80039d4, 
           format("Actual device area offset is [%X08], not the expected 0x80039d4", device_area_section.addr));
}

struct load_segment {
    uint file_offset;
    uint file_size;
    uint vaddr;
}

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

uint file_offset_to_addr(uint file_offset, load_segment[] segs) {
    foreach (s; segs) {
        if (file_offset >= s.file_offset &&
            file_offset <  s.file_offset + s.file_size) {
            return s.vaddr + (file_offset - s.file_offset);
        }
    }
    throw new Exception("file offset not mapped by any PT_LOAD");
}

void load_section_into_memory(const ref string filename, const string section_name, ref memory mem) {
    auto section = get_section_by_name(filename, section_name);
    if (section.data.length == 0)
        return;
    auto segments = get_load_segments(filename);
    uint addr = file_offset_to_addr(section.file_offset, segments);
    foreach (b; section.data) {
        mem.write_byte(addr++, b, 0);
    }
}

unittest {
    auto filename = "../test/blinky.elf";
    auto section_name = "device_area";
    memory mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data = mem.read_word(0x80039d4, 0);
    assert(actual_data == 0x08004446, 
           format("Actual device area length is %d, not the expected 0x08004446", actual_data));
}

unittest {
    auto filename = "../test/blinky.elf";
    auto section_name = "text";
    memory mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data_start = mem.read_half_word(0x8000188);
    assert(actual_data_start == 0xb953, 
           format("Actual value at 0x8000188 is %08X, not the expected 0xb953", actual_data_start));
    auto actual_data_end = mem.read_half_word(0x8003938);
    assert(actual_data_end == 0xe7cb, 
           format("Actual value at 0x8003938 is %08X, not the expected 0xe7cb", actual_data_end));
}

unittest {
    auto filename = "../test/button.elf";
    auto section_name = "text";
    memory mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data_start = mem.read_half_word(0x8000194);
    assert(actual_data_start == 0xb953, 
           format("Actual value at 0x8000194 is %08X, not the expected 0xb953", actual_data_start));
    auto actual_data_end = mem.read_half_word(0x80039fa);
    assert(actual_data_end == 0xe7cb, 
           format("Actual value at 0x80039fa is %08X, not the expected 0xe7cb", actual_data_end));
}   

unittest {
    auto filename = "../test/sys_heap.elf";
    auto section_name = "text";
    memory mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data_start = mem.read_half_word(0x8003e68);
    assert(actual_data_start == 0x2e09, 
           format("Actual value at 0x8000194 is %08X, not the expected 0xb953", actual_data_start));
    auto actual_data_end = mem.read_half_word(0x8003ece);
    assert(actual_data_end == 0xe7cb, 
           format("Actual value at 0x8003ece is %08X, not the expected 0xe7cb", actual_data_end));
} 

unittest {
    auto filename = "../test/blinky.elf";
    auto section_name = "rodata";
    memory mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data = mem.read_word(0x8003e34, 0);
    assert(actual_data == 0x00000044, 
           format("Actual value at 0x8003e34 is %08X, not the expected 0x00000044", actual_data));
}

struct elf_32_sym {
    uint                st_name;   
    uint                st_value; 
    uint                st_size;   
    ubyte               st_info;   
    ubyte               st_other;
    ushort              st_shndx; 
}

ubyte get_elf_32_st_type(ubyte info) {
    return info & 0x0F;
}

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
    //stt_sparc_regioster           = 13,
    stt_hiproc                      = 14,
    all                             = 0xff
}

struct st_name_val {
    string      name;
    uint        addr;
}

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

st_name_val[] get_st_name_val(const string elf_file, const st_type type = st_type.all, bool get_all = false) {
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
        elf_32_sym sym;
        sym.st_name  = read_ul_32(symdata, pos + 0);
        sym.st_value = read_ul_32(symdata, pos + 4);
        sym.st_size  = read_ul_32(symdata, pos + 8);
        sym.st_info  = symdata[pos + 12];
        sym.st_other = symdata[pos + 13];
        sym.st_shndx = cast(ushort)(symdata[pos + 14] | (symdata[pos + 15] << 8));

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

            if (_st_type == st_type.stt_func) {
                if (sym.st_value < text_start || sym.st_value >= text_end)
                    continue;
            }
        }

        if (name == "LoopFillZerobss") 
            writeln(name, ": ", _st_type.to!string);

        if (!get_all) { 
            if ((sym.st_value >= 0x08000000) && (sym.st_value <= 0x20020000)) {
                if (name.canFind("uart_cfg")) {
                    items ~= st_name_val(name ~ ".parity",               sym.st_value    );
                    items ~= st_name_val(name ~ ".stop_bits",            sym.st_value + 1);
                    items ~= st_name_val(name ~ ".data_bits",            sym.st_value + 2);
                    items ~= st_name_val(name ~ ".flow_ctrl",            sym.st_value + 3);
                } else if (name.canFind("mpu_config") && _st_type != st_type.stt_func) {
                    items ~= st_name_val(name ~ ".num_regions",          sym.st_value    );
                    items ~= st_name_val(name ~ ".mpu_regions",          sym.st_value + 4);
                } else if (name.canFind("gpio_stm32_cfg")) {
                    items ~= st_name_val(name ~ ".common.port_pin_mask", sym.st_value     );
                    items ~= st_name_val(name ~ ".base",                 sym.st_value +  4);
                    items ~= st_name_val(name ~ ".port",                 sym.st_value +  8);
                    items ~= st_name_val(name ~ ".pclken.bus",           sym.st_value + 12);
                    items ~= st_name_val(name ~ ".pclken.div",           sym.st_value + 16); 
                    items ~= st_name_val(name ~ ".pclken.enr",           sym.st_value + 20);
                } else {
                    items ~= st_name_val(name, sym.st_value);
                }
            }
        } else {
            items ~= st_name_val(name, sym.st_value);
        }
    }
    return items;
}

unittest {
    auto filename = "../test/blinky.elf";
    auto f_s = get_st_name_val(filename, st_type.stt_func);
    foreach (f; f_s) {
        writeln(f.name);
    }
}

unittest {
    auto filename = "../test/stm32_dsp.elf";
    auto f_s = get_st_name_val(filename, st_type.stt_func);
    foreach (f; f_s) {
        writeln(f.name, format(": %08X", f.addr));
    }
}

struct elf_func {
    uint    offset;
    ubyte[] data;
}

size_t va_to_file_offset(const ref load_segment[] segs, uint va) {
    foreach (s; segs) {
        if (va >= s.vaddr && va < s.vaddr + s.file_size) {
            return s.file_offset + (va - s.vaddr);
        }
    }
    throw new Exception(format("VA %08X not in any PT_LOAD segment", va));
}

elf_func get_elf_func(const string elf_file, const string func_name) {
    auto symtab_sec = get_section_by_name(elf_file, ".symtab");
    auto strtab_sec = get_section_by_name(elf_file, ".strtab");
    auto text_sec   = get_section_by_name(elf_file, "text");

    if (text_sec.name == "")
        text_sec   = get_section_by_name(elf_file, ".text");

    ubyte[] symdata = symtab_sec.data;
    ubyte[] strdata = strtab_sec.data;
    uint    text_start = text_sec.addr;
    //ubyte[] text_data = text_sec.data;
    ubyte[] file_data = cast(ubyte[])read(elf_file);
    auto segs = get_load_segments(elf_file);

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        elf_32_sym sym;
        sym.st_name  = read_ul_32(symdata, pos + 0);
        sym.st_value = read_ul_32(symdata, pos + 4);
        sym.st_size  = read_ul_32(symdata, pos + 8);
        sym.st_info  = symdata[pos + 12];
        sym.st_other = symdata[pos + 13];
        sym.st_shndx = cast(ushort)(symdata[pos + 14] | (symdata[pos + 15] << 8));

        //if(get_elf_32_st_type(sym.st_info) != st_type.stt_func)
        //   continue;

        uint name_off = sym.st_name;
        if (name_off >= strdata.length) continue;
        size_t end = name_off;
        while (end < strdata.length && strdata[end] != 0) end++;
        string name = cast(string) strdata[name_off .. end];

        if(name != func_name)
            continue;

        uint func_va = sym.st_value;
        bool thumb = (func_va & 1) != 0;
        func_va &= ~1u;

        size_t file_offset = va_to_file_offset(segs, func_va);

        //if(sym.st_value < text_start || sym.st_value >= text_start + text_data.length)
        //    throw new Exception(format("Function %s is outside .text section", func_name));

        //size_t offset_in_text = cast(size_t)(sym.st_value - text_start);
        size_t size = cast(size_t)sym.st_size;

        if (name == "__start")              size = 52;
        if (name == "__aeabi_uldivmod")     size = 48;
        if (name == "__aeabi_read_tp")      size = 12;
        if (name == "LoopFillZerobss")      size = 38;
        if (name == "LoopCopyDataInit")     size = 14;
        if (name == "_init")                size = 12;
        if (name == "frame_dummy")          size = 28;
        if (name == "Reset_Handler")        size = 18;
        if (name == "CopyDataInit")         size =  6;
        if (name == "FillZerobss")          size =  4;
        if (name == "register_tm_clones")   size = 36;

        //if(offset_in_text + size > text_data.length)
        //    size = text_data.length - offset_in_text;

        //auto data = text_data[offset_in_text - 1 .. offset_in_text + size - 1];
        //file_offset &= ~0x3;
        auto data = file_data[file_offset .. file_offset + size];
        assert(data.length == size, format("%s: sizes are not equal, %d != %d", name, data.length, size));
        return elf_func(func_va, data);
    }
    return elf_func(0, []);
}

unittest {
    auto filename = "../test/blinky.elf";
    auto f = get_elf_func(filename, "char_out");
    assert(f.offset == 0x80004ec, 
           format("Actual char_out offset is [%08X], not the expected 0x80004ec", f.offset));
    assert(f.data.length == 12, 
           format("Actual char_out data length is %d, not the expected 12", f.data.length));
    write("Elf func bytes: ");
    foreach (b; f.data) {
        writef("%02X ", b);  
    }
    writeln();
}

unittest {
    auto filename = "../test/blinky.elf";
    auto f = get_elf_func(filename, "__start");
    assert(f.offset == 0x8000a90, 
           format("Actual char_out offset is [%08X], not the expected 0x8000a90", f.offset));
    //assert(f.data.length == 12, 
    //       format("Actual char_out data length is %d, not the expected 12", f.data.length));
    write("__start func bytes: ");
    foreach (b; f.data) {
        writef("%02X ", b);  
    }
    writeln();
}

ubyte[] get_function_by_name(const string elf_file, const string func_name) {
    auto symtab_sec = get_section_by_name(elf_file, ".symtab");
    auto strtab_sec = get_section_by_name(elf_file, ".strtab");
    auto text_sec   = get_section_by_name(elf_file, "text");

    ubyte[] symdata = symtab_sec.data;
    ubyte[] strdata = strtab_sec.data;
    uint text_start = text_sec.addr;
    ubyte[] text_data = text_sec.data;

    for (size_t pos = 0; pos + 16 <= symdata.length; pos += 16) {
        elf_32_sym sym;
        sym.st_name  = read_ul_32(symdata, pos + 0);
        sym.st_value = read_ul_32(symdata, pos + 4);
        sym.st_size  = read_ul_32(symdata, pos + 8);
        sym.st_info  = symdata[pos + 12];
        sym.st_other = symdata[pos + 13];
        sym.st_shndx = cast(ushort)(symdata[pos + 14] | (symdata[pos + 15] << 8));

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

unittest {
    auto filename = "../test/blinky.elf";
    auto char_out = get_function_by_name(filename, "char_out");
    foreach (b; char_out) {
        writef("%02X ", b);  
    }
    writeln(); 
    auto st_stm32_common_config = get_function_by_name(filename, "st_stm32_common_config");
    foreach (b; st_stm32_common_config) {
        writef("%02X ", b);  
    }
    writeln(); 
}

bool is_32_bit_instr(uint instr) {
    ushort first_hw = cast(ushort)(instr & 0xFFFF);
    return (first_hw & 0xF800) >= 0xE800;
}

import std.algorithm;

string fetch_instr(ubyte[] b)
{
    if (b.length == 2) return format("%02x%02x", b[1], b[0]);
    if (b.length == 4) return format("%02x%02x%02x%02x", b[1], b[0], b[3], b[2]);
    return b.map!(x => format("%02x", x)).join;
}

func get_function_from_elf(const string elf_file, const string func_name, ref bool[uint] pending_literals) {
    func res;
    res.name = func_name;
    auto e_func = get_elf_func(elf_file, func_name);
    auto literal_offsets = extract_literal_pool(e_func, res, pending_literals);
    uint offset = 0;
    uint addr_offset = 0;
    while (offset + 2 <= e_func.data.length) {
        ushort first_hw = cast(ushort)(e_func.data[offset] | (e_func.data[offset + 1] << 8));
        uint len        = (first_hw & 0xF800) >= 0xE800 ? 4 : 2;
        auto bytes      = e_func.data[offset .. offset + len];
        while (addr_offset in literal_offsets) {
            addr_offset += 4;
        }
        res.instrs  ~= addr_instr(e_func.offset + addr_offset, fetch_instr(bytes));
        offset      += len;
        addr_offset += len;
    }
    return res; 
}

bool[uint] extract_literal_pool(ref elf_func e_func, ref func f, ref bool[uint] pending_literals) {
    uint[] toRemove;
    bool[uint] words_to_remove;
    bool[uint] literal_offsets;
    auto data = e_func.data;
    uint offset = 0;
    foreach (l, _; pending_literals) {
        if (l >= e_func.offset && l < e_func.offset + data.length) {
            toRemove ~= l;
            const uint rel_offset = l - e_func.offset;
            words_to_remove[rel_offset] = true;
            literal_offsets[rel_offset] = true;
            writeln("removing: ", format("%08X", l));
            writeln("removing: ", format("%08X", rel_offset)); 
            f.literal_pool[l] = read_ub_32_(data, rel_offset);        
        }
    }
    foreach (l; toRemove) {
        pending_literals.remove(l);
    }
    while (offset + 2 <= data.length) {
        if (offset in words_to_remove) {
            offset += 4;
            continue;
        }
        ushort first_hw = cast(ushort)(data[offset] | (data[offset + 1] << 8));
        bool is32 = ((first_hw & 0xE000) == 0xE000) &&
                    ((first_hw & 0x1800) != 0x0000);
        uint len = is32 ? 4 : 2;
        if (len == 4) {
            if (offset + len >= data.length) {
                offset += 4;
                continue;
            }
            uint instr = read_ub_32(data, offset);
            if (decode_mnemonic_32(instr) == opcode.ldr_lit_32) {
                auto parsed_instr = decode_instr(instr);
                uint base = e_func.offset + offset + 4;
                base &= ~0x3;   
                uint lit_offset = base + parsed_instr.imm;
                uint rel_offset = lit_offset - e_func.offset; 
                words_to_remove[rel_offset] = true;
                literal_offsets[rel_offset] = true;
                writeln(format("%s: %08X %08X", f.name, e_func.offset + offset, lit_offset));
                if (rel_offset < data.length) 
                    f.literal_pool[lit_offset] = read_ub_32_(data, rel_offset);
                else {
                    pending_literals[lit_offset] = true;
                    writeln("Added %08X to pending literals", lit_offset);
                }
            }
        } else if (len == 2) {
            if (decode_mnemonic(first_hw) == opcode.ldr_pool) {
                auto parsed_instr = decode_instr(first_hw);
                uint base = e_func.offset + offset + 4;
                base &= ~0x3;   
                uint lit_offset = base + parsed_instr.imm;
                uint rel_offset = lit_offset - e_func.offset; 
                words_to_remove[rel_offset] = true;
                literal_offsets[rel_offset] = true;
                writeln(format("%s: %08X %08X", f.name, e_func.offset + offset, lit_offset));
                if (rel_offset < data.length) 
                    f.literal_pool[lit_offset] = read_ub_32_(data, rel_offset);
                else {
                    pending_literals[lit_offset] = true;
                    writeln("Added %08X to pending literals", lit_offset);
                }
            }
        }
        offset += len;
    }
    auto keys = words_to_remove.keys;
    keys.sort;
    keys.reverse;
    foreach (w; keys) {
        if (w + 4 <= data.length) {
            data = data[0 .. w] ~ data[w + 4 .. $];
        }
    }
    e_func.data = data;
    return literal_offsets;
}

unittest {
    ubyte[] original = [
        0x08, 0xb5, 0xff, 0xf7, 0xef, 0xff,
        0x0b, 0x4a, 0xd2, 0xf8, 0x88, 0x30,
        0x23, 0xf4, 0x70, 0x03, 0xc2, 0xf8, 0x88, 0x30,
        0xef, 0xf3, 0x14, 0x83, 0x23, 0xf0, 0x04, 0x03,
        0x83, 0xf3, 0x14, 0x88, 0xbf, 0xf3, 0x6f, 0x8f,
        0xff, 0xf7, 0xc6, 0xfc, 0xff, 0xf7, 0xda, 0xfc,
        0x00, 0xf0, 0x56, 0xf8, 0x01, 0xf0, 0xe6, 0xf8,
        0x00, 0xed, 0x00, 0xe0
    ];
    ubyte[] expected = [
        0x08, 0xb5, 0xff, 0xf7, 0xef, 0xff,
        0x0b, 0x4a, 0xd2, 0xf8, 0x88, 0x30,
        0x23, 0xf4, 0x70, 0x03, 0xc2, 0xf8, 0x88, 0x30,
        0xef, 0xf3, 0x14, 0x83, 0x23, 0xf0, 0x04, 0x03,
        0x83, 0xf3, 0x14, 0x88, 0xbf, 0xf3, 0x6f, 0x8f,
        0xff, 0xf7, 0xc6, 0xfc, 0xff, 0xf7, 0xda, 0xfc,
        0x00, 0xf0, 0x56, 0xf8, 0x01, 0xf0, 0xe6, 0xf8
    ];
    elf_func e_func;
    e_func.data = original;
    func f;
    bool[uint] l;
    extract_literal_pool(e_func, f, l);
    assert(e_func.data == expected, "Byte array is not correct after removing literals");
}

void extract_literal_pool(ref func f) {
    for (int i = cast(int)f.instrs.length - 1; i >= 0; --i) {
        auto elem = f.instrs[i];
        
        bool is_ldr_lit_16;
        bool is_ldr_lit_32;
        if (elem._instr_bytes.length == 8 && decode_mnemonic_32(elem._in_32) == opcode.ldr_lit_32) {
            is_ldr_lit_32 = true;
        }
        if (elem._instr_bytes.length == 4 && decode_mnemonic(elem._in_16) == opcode.ldr_pool) {
            is_ldr_lit_16 = true;
        }
        if (!(is_ldr_lit_16 || is_ldr_lit_32)) {
            continue;
        }
        if (is_ldr_lit_16) {
            auto parsed = decode_instr(elem._in_16);
            uint pc = (elem._addr + 4) & ~3u;
            uint lit_addr = pc + parsed.imm;        
            for (int j = cast(int)f.instrs.length - 1; j >= 0; --j) {
                auto cand = f.instrs[j];
                if (cand._addr == lit_addr) {
                    uint value;
                    if (cand._instr_bytes.length == 8) {
                        value = parse!uint(cand._instr_bytes, 16);
                    } else if (cand._instr_bytes.length == 4) {
                        if (j + 1 < cast(int)f.instrs.length) {
                            auto high = parse!uint(f.instrs[j+1]._instr_bytes, 16);
                            value = (high << 16) | parse!uint(cand._instr_bytes, 16);
                            f.instrs = f.instrs[0 .. j] ~ f.instrs[j+2 .. $];
                        } else {
                            value = parse!uint(cand._instr_bytes, 16);
                            f.instrs = f.instrs[0 .. j] ~ f.instrs[j+1 .. $];
                        }
                    }
                    f.literal_pool[lit_addr] = value;
                    break;
                }
            }
        }
        if (is_ldr_lit_32) {
            auto parsed = decode_instr(elem._in_32);
            uint pc = (elem._addr + 4) & ~3u;
            uint lit_addr = pc + parsed.imm;        
            for (int j = cast(int)f.instrs.length - 1; j >= 0; --j) {
                auto cand = f.instrs[j];
                if (cand._addr == lit_addr) {
                    // check if the literal spans multiple instr entries
                    uint value;
                    if (cand._instr_bytes.length == 8) {
                        // already 32-bit entry
                        value = parse!uint(cand._instr_bytes, 16);
                    } else if (cand._instr_bytes.length == 4) {
                        // two consecutive 16-bit entries
                        if (j + 1 < cast(int)f.instrs.length) {
                            auto high = parse!uint(f.instrs[j+1]._instr_bytes, 16);
                            value = (high << 16) | parse!uint(cand._instr_bytes, 16);
                            // remove both entries from instrs
                            f.instrs = f.instrs[0 .. j] ~ f.instrs[j+2 .. $];
                        } else {
                            value = parse!uint(cand._instr_bytes, 16);
                            f.instrs = f.instrs[0 .. j] ~ f.instrs[j+1 .. $];
                        }
                    }
                    f.literal_pool[lit_addr] = value;
                    break;
                }
            }
        }
    }
}

unittest {
    auto filename = "../test/blinky.elf";
    //auto f = get_function_from_elf(filename, "char_out");
    //assert(f.instrs.length == 4, format("Actual instrs length is %d, not the expected 4", f.instrs.length));
    //auto res = f.instrs[0]._instr_bytes;
    //assert(res == "4b01", 
    //       format("Actual instr_bytes is %s, not the expected 4b01", res));
    bool[uint] l;
    auto __start = get_function_from_elf(filename, "__start", l);
    auto start_addr = __start.instrs[0]._addr;
    assert(start_addr == 0x8000a90, 
           format("Actual instr_bytes is [%08X], not the expected 0x8000a90", start_addr));
}

void load_function_into_memory(const string elf_file, const string func_name, ref memory mem) {
    func f = get_function(elf_file, func_name);
    foreach (i; f.instrs) {
        if (i._instr_bytes.length == 4) {
            mem.write_half_word(i._addr, i._in_16, 0);
        }
        if (i._instr_bytes.length == 8) {
            mem.write_word(i._addr, i._in_32);
        }
    }
    foreach (addr, value; f.literal_pool) {
        mem.write_word(addr, value);
    }
}

void load_function_into_memory(func f, ref memory mem) {
    foreach (i; f.instrs) {
        if (i._instr_bytes.length == 4) {
            mem.write_half_word(i._addr, i._in_16, 0);
        }
        if (i._instr_bytes.length == 8) {
            mem.write_word(i._addr, i._in_32);
        }
    }
    foreach (addr, value; f.literal_pool) {
        mem.write_word(addr, value);
    }
}

unittest {
    auto filename = "../test/blinky.elf";
    memory mem;
    //load_function_into_memory(filename, "char_out", mem);
    auto lit = mem.read_word(0x80004f4, 0);
    //assert(lit == 0x20000000, format("Actual instrs length is %08X, not the expected 0x20000000", lit));
}

func[] get_program_from_elf(const string elf_file) {
    bool[uint] pending_literals;
    func[] res;
    auto f_s = get_st_name_val(elf_file, st_type.stt_func);
    foreach (fn; f_s) {
        auto f = get_function_from_elf(elf_file, fn.name, pending_literals);
        res ~= f; 
    }
    return res;
}

unittest {
    auto filename = "../test/stm32_dsp.elf";
    auto prog = get_program_from_elf(filename);
}

string[] blinky_funcs = [
    "char_out",
    "st_stm32_common_config",
    "mem_manage_fault",
    "usage_fault.isra.0",
    "bus_fault.isra.0",
    "region_init",
    "size_to_mpu_rasr_size",
    "mpu_configure_regions",
    "picolibc_put",
    "malloc_prepare",
    "stm32_exti_init",
    "stm32_fill_irq_table",
    "stm32_exti_gpio_intc_init",
    "stm32_intc_gpio_isr",
    "stm32_clock_control_on",
    "stm32_clock_control_off",
    "stm32_clock_control_get_subsys_rate",
    "stm32_clock_control_configure",
    "stm32_clock_control_get_status",
    "uart_console_init",
    "console_out",
    "gpio_stm32_port_get_raw",
    "gpio_stm32_port_set_masked_raw",
    "gpio_stm32_port_set_bits_raw",
    "gpio_stm32_port_clear_bits_raw",
    "gpio_stm32_port_toggle_bits",
    "gpio_stm32_manage_callback",
    "gpio_stm32_pin_interrupt_configure",
    "gpio_stm32_isr",
    "gpio_stm32_configure_raw.isra.0",
    "gpio_stm32_config",
    "gpio_stm32_init",
    "LL_USART_ClearFlag_PE",
    "LL_USART_ClearFlag_ORE",
    "LL_USART_ClearFlag_NE",
    "LL_USART_ClearFlag_FE",
    "uart_stm32_err_check",
    "uart_stm32_set_baudrate",
    "uart_stm32_poll_out",
    "uart_stm32_poll_in",
    "uart_stm32_parameters_set",
    "uart_stm32_configure",
    "uart_stm32_init",
    "uart_stm32_config_get",
    "elapsed",
    "sys_clock_driver_init",
    "z_sys_init_run_level",
    "bg_thread_main",
    "sys_dlist_remove",
    "unpend_thread_no_timeout",
    "z_swap_irqlock",
    "ready_thread",
    "unready_thread",
    "z_tick_sleep",
    "slice_timeout",
    "first",
    "next_timeout",
    "elapsed",
    "remove_timeout",
    "__ultoa_invert",
    "skip_to_arg",
    "chunk_size",
    "free_list_add",
    "reset_stm32_status",
    "reset_stm32_line_assert",
    "reset_stm32_line_deassert",
    "reset_stm32_line_toggle",
    "z_abort_timeout",
    "z_arm_mpu_init",
    "z_arm_bus_fault",
    "z_arm_pendsv",
    "stm32_gpio_intc_select_line_trigger",
    "z_arm_reset",
    "sys_clock_announce",
    "z_impl_zephyr_fputc",
    "sys_clock_tick_get_32",
    "move_current_to_end_of_prio_q",
    "printf",
    "sys_clock_tick_get",
    "z_arm_usage_fault",
    "arch_early_memset",
    "stm32_gpio_intc_set_irq_callback",
    "z_arm_mpu_fault",
    "HAL_RCC_GetSysClockFreq",
    "z_thread_entry",
    "z_impl_k_yield",
    "soc_early_init_hook",
    "z_dummy_thread_init",
    "k_sys_fatal_error_handler",
    "memcpy",
    "arch_coprocessors_disable",
    "z_do_kernel_oops",
    "z_sched_wake_thread",
    "z_cstart",
    "__aeabi_uldivmod",
    "__l_vfprintf",
    "stm32_gpio_intc_disable_line",
    "z_check_thread_stack_fail",
    "z_arm_configure_dynamic_mpu_regions",
    "sys_clock_isr",
    "mem_attr_get_regions",
    "arm_core_mpu_configure_dynamic_mpu_regions",
    "__aeabi_memcpy",
    "z_sched_init",
    "_OffsetAbsSyms",
    "__printk_hook_install",
    "k_sched_lock",
    "config_pll_sysclock",
    "__udivmoddi4",
    "sys_clock_set_timeout",
    "stm32_exti_is_pending",
    "__aeabi_memcpy4",
    "config_enable_default_clocks",
    "arch_cpu_idle",
    "stm32_clock_control_init",
    "strnlen",
    "z_arm_configure_static_mpu_regions",
    "z_arm_exc_exit",
    "get_pllsrc_frequency",
    "__aeabi_memcpy8",
    "stm32_exti_clear_pending",
    "arch_switch_to_main_thread",
    "arm_core_mpu_enable",
    "__start",
    "z_impl_k_thread_abort",
    "arch_printk_char_out",
    "arch_data_copy",
    "idle",
    "thread_is_sliceable",
    "z_impl_k_sleep",
    "vprintk",
    "z_thread_timeout",
    "z_impl_device_is_ready",
    "z_thread_abort",
    "_isr_wrapper",
    "config_plli2s",
    "z_arm_fault",
    "do_device_init",
    "z_reschedule",
    "_ConfigAbsSyms",
    "stm32_gpio_intc_get_pin_irq_line",
    "arm_irq_enable",
    "z_arm_exc_spurious",
    "printk",
    "arch_system_halt",
    "__aeabi_ldiv0",
    "k_sched_unlock",
    "z_arm_interrupt_init",
    "LL_SetFlashLatency",
    "memset",
    "sys_heap_init",
    "main",
    "stm32_exti_get_line_src_port",
    "z_SysNmiOnReset",
    "z_irq_spurious",
    "arm_irq_priority_set",
    "enabled_clock",
    "stm32_gpio_intc_remove_irq_callback",
    "arm_core_mpu_disable",
    "z_arm_int_exit",
    "__stdout_hook_install",
    "stm32_gpio_intc_enable_line",
    "stm32_exti_set_line_src_port",
    "pinctrl_lookup_state",
    "z_arm_debug_monitor",
    "config_regulator_voltage",
    "z_add_timeout",
    "relocate_vector_table",
    "arm_core_mpu_configure_static_mpu_regions",
    "gpio_stm32_configure",
    "z_init_cpu",
    "sys_clock_elapsed",
    "z_ready_thread",
    "z_prep_c",
    "arch_new_thread",
    "pinctrl_configure_pins",
    "z_reschedule_irqlock",
    "z_setup_new_thread",
    "z_arm_fault_init",
    "__aeabi_idiv0",
    "z_arm_fatal_error",
    "z_arm_svc",
    "z_arm_cpu_idle_init",
    "arch_early_memcpy",
    "z_impl_k_wakeup",
    "z_reset_time_slice",
    "arch_bss_zero",
    "z_arm_nmi",
    "z_time_slice",
    "z_impl_k_sched_current_thread_query",
    "z_fatal_error",
    "boot_banner",
    "vfprintf",
    "arch_irq_unlock_outlined",
    "z_arm_hard_fault"
];

unittest {
    auto filename = "../test/blinky.elf";
    bool[uint] l;
    foreach (f_n; blinky_funcs) {
        writeln(format("%s", f_n));
        auto f = get_function_from_elf(filename, f_n, l);
    }
}

struct elf_basic_structs {
    read_fn!ushort half;
    read_fn!uint   word;
    read_fn!ulong  xword;
    read_fn!long   sxword;
}

elf_basic_structs get_basic_structs(const ref elf_file_info info) {
    elf_basic_structs basic;
    basic.half = &read_ul_16;
    basic.word = &read_ul_32;
    return basic;
}

elf_file_info identify_elf(const ref string filename) {
    auto info = elf_file_info();
    auto data = cast(ubyte[]) read(filename, 16);
    enforce(data.length >= 16, "File too small for ELF");
    enforce(data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F',
            "Magic number does not match ELF");

    auto e_class = cast(elf_class)(data[4]);
    final switch (e_class) {
        case elf_class.elf_32: info.e_class = elf_class.elf_32; break;
        case elf_class.elf_64: info.e_class = elf_class.elf_64; 
    } 
    auto endian = cast(elf_endian)(data[5]);
    final switch (endian) {
        case elf_endian.little: info.endian = elf_endian.little; break;
        case elf_endian.big   : info.endian = elf_endian.big;
    }
    return info;
}

unittest {
    auto filename = "../test/blinky.elf";
    auto res = identify_elf(filename);
    assert(res.e_class == elf_class.elf_32 && res.endian == elf_endian.little,
           "blinky.elf is not Elf 32 Little Endian");
    auto b_structs = get_basic_structs(res);
    assert(b_structs.half == &read_ul_16 && b_structs.word == &read_ul_32, "Basic Structs test failed");
}