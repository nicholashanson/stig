import std.stdio;
import std.exception;
import std.conv;
import std.file;
import std.array;
import std.format;

import memory_sections;
import thumb_2_opcodes;
import thumb_2_instrs;
import thumb_2_decode_instr;

import log;

string[] table_names = [
    "rodata",
    "_static_thread_data_area",
    "k_heap_area",
    "device_area",
    "initlevel",
    "uart_driver_api_area",
    "clock_control_driver_api_area",
    "reset_driver_api_area",
    "sw_isr_table",
    "datas",
    "text",
    "log_msg_ptr_area",
    "k_sem_area",
    "log_backend_area",
    "log_const_area",
    "log_mpsc_pbuf",
    "gpio_driver_api_area",
    "rom_start",
    "k_msgq_area",
    "adc_driver_api_area",
    "i2c_driver_api_area",
    "sensor_driver_api_area",
    "k_mutex_area",
    "k_condvar_area",
    "net_buf_pool_area",
    ".init_array",
    "entropy_driver_api_area",
    "bt_hci_driver_api_area"
];

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

ushort read_ub_16(const(ubyte)[] data, size_t offset) {
    auto v = data[offset + 1] | (data[offset] << 8);
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

void load_section_into_memory(mem_t)(const ref string filename, const string section_name, ref mem_t mem) {
    auto section = get_section_by_name(filename, section_name);
    if (section.data.length == 0)
        return;
    // log load
    auto segments = get_load_segments(filename);
    uint addr = file_offset_to_addr(section.file_offset, segments);
    foreach (b; section.data) {
        mem.write_byte(addr++, b);
    }
}

unittest {
    auto filename = "../test/blinky.elf";
    auto section_name = "device_area";
    stm32f4_mem mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data = mem.read_word(0x80039d4);
    assert(actual_data == 0x08004446, 
           format("Actual device area length is %d, not the expected 0x08004446", actual_data));
}

unittest {
    auto filename = "../test/blinky.elf";
    auto section_name = "text";
    stm32f4_mem mem;
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
    stm32f4_mem mem;
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
    stm32f4_mem mem;
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
    stm32f4_mem mem;
    load_section_into_memory(filename, section_name, mem);
    auto actual_data = mem.read_word(0x8003e34);
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
    uint        size;
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

enum soc {
    stm32,
    nrf,
    all
}

st_name_val[] get_st_name_val(const string elf_file, const st_type type = st_type.all, soc mcu, bool get_all = false, bool get_size = false) {
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

        if (!get_size) {
            if (!get_all) {
                uint lower_bound;
                if (mcu == soc.stm32) {
                    lower_bound = 0x08000000;
                } 
                if ((sym.st_value >= lower_bound) && (sym.st_value <= 0x20020000)) {
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
        } else {
            items ~= st_name_val(name, sym.st_value, sym.st_size);
        }
    }
    return items;
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

elf_func get_elf_func(const string elf_file, const string func_name, const uint addr) {
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

        if(name != func_name || sym.st_value != addr)
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
        if (name == "z_arm_bus_fault")      size = 20;

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
    auto f = get_elf_func(filename, "char_out", 0x80004ed);
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
    auto f = get_elf_func(filename, "__start", 0x8000a91);
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
    assert(0, "Invalid instruction length");
}

func get_function_from_elf(const string elf_file, const string func_name, const uint addr, ref bool[uint] pending_literals) {
    func res;
    res.name = func_name;
    auto e_func = get_elf_func(elf_file, func_name, addr);
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
            f.literal_pool[l] = read_ub_32_(data, rel_offset);        
        }
    }
    foreach (l; toRemove) {
        pending_literals.remove(l);
    }
    uint cmp_instr_size;
    uint branch_instr_size;
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
                else {
                    pending_literals[lit_offset] = true;
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
                else {
                    pending_literals[lit_offset] = true;
                    writeln("Added %08X to pending literals", lit_offset);
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
        if (w + width <= data.length) {
            data = data[0 .. w] ~ data[w + width .. $];
        }
    }
    e_func.data = data;
    return literal_offsets;
}

unittest {
    auto e_func = get_elf_func("../test/blinky.elf", "__l_vfprintf", 0x80028ED);
    assert(e_func.data.length == 1268, format("Func is %d and not 1268", e_func.data.length));
    func f;
    bool[uint] l;
    extract_literal_pool(e_func, f, l);
    assert(l.length == 0, "Literal pool for __l_vfprintf is not empty");
    assert(f.byte_tables.length == 2, format("Number of byte tables found is %d and not 2", f.byte_tables.length));
    writeln(format("%08X", f.byte_tables[0].addr));
    writeln(format("first size: %d", f.byte_tables[0].data.length));
    writeln(format("%08X", f.byte_tables[1].addr));
    writeln(format("second size: %d", f.byte_tables[1].data.length));
    assert(f.byte_tables[0].data.length == 18, format("First bytes table length is %d and not 18", f.byte_tables[0].data.length));
}

/*
unittest {
    auto e_func = get_elf_func("../test/z_prod_con.elf", "__l_vfprintf", 0x800A085);
    assert(e_func.data.length == 1208, format("Func is %d and not 1268", e_func.data.length));
    func f;
    bool[uint] l;
    extract_literal_pool(e_func, f, l);
    assert(l.length == 0, "Literal pool for __l_vfprintf is not empty");
    assert(f.byte_tables.length == 2, format("Number of byte tables found is %d and not 2", f.byte_tables.length));
    writeln(format("%08X", f.byte_tables[0].addr));
    writeln(format("first size: %d", f.byte_tables[0].data.length));
    writeln(format("%08X", f.byte_tables[1].addr));
    writeln(format("second size: %d", f.byte_tables[1].data.length));
    assert(f.byte_tables[0].data.length == 18, format("First bytes table length is %d and not 18", f.byte_tables[0].data.length));
    assert(f.byte_tables[1].data.length == 38, format("Second bytes table length is %d and not 38", f.byte_tables[1].data.length));
    assert(e_func.data.length == 1208 - 18 - 38 - 4 - 4, format("Function is not the right length: %d, not %d", e_func.data.length, 1208 - 18 - 38 - 4 - 4));
}
*/

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

unittest {
    auto filename = "../test/blinky.elf";
    //auto f = get_function_from_elf(filename, "char_out");
    //assert(f.instrs.length == 4, format("Actual instrs length is %d, not the expected 4", f.instrs.length));
    //auto res = f.instrs[0]._instr_bytes;
    //assert(res == "4b01", 
    //       format("Actual instr_bytes is %s, not the expected 4b01", res));
    bool[uint] l;
    auto __start = get_function_from_elf(filename, "__start", 0x8000a91, l);
    auto start_addr = __start.instrs[0]._addr;
    assert(start_addr == 0x8000a90, 
           format("Actual instr_bytes is [%08X], not the expected 0x8000a90", start_addr));
}

void 
load_function_into_memory
(mem_t)
(const string elf_file, const string func_name, ref mem_t mem) {
    func f = get_function(elf_file, func_name);
    foreach (i; f.instrs) {
        if (i._instr_bytes.length == 4) {
            mem.write_half_word(i._addr, i._in_16);
        }
        if (i._instr_bytes.length == 8) {
            mem.write_word(i._addr, i._in_32);
        }
    }
    foreach (addr, value; f.literal_pool) {
        mem.write_word(addr, value);
    }
}

void 
load_function_into_memory
(mem_t)
(func f, ref mem_t mem) {
    foreach (i; f.instrs) {
        if (i._instr_bytes.length == 4) {
            mem.write_half_word(i._addr, i._in_16);
        }
        if (i._instr_bytes.length == 8) {
            mem.write_word(i._addr, i._in_32);
        }
    }
    foreach (addr, value; f.literal_pool) {
        mem.write_word(addr, value);
    }
    foreach (t; f.byte_tables) {
        uint offset = 0;
        auto data   = t.data;
        uint addr   = t.addr;

    
        while (offset + 4 <= data.length) {
            uint val = cast(uint)(
                 data[offset]            |
                (data[offset + 1] <<  8) |
                (data[offset + 2] << 16) |
                (data[offset + 3] << 24)
            );
            mem.write_word(addr, val);
            offset += 4;
            addr   += 4;
        }

        if (offset + 2 <= data.length) {
            ushort val = cast(ushort)(data[offset] | (data[offset + 1] << 8));
            mem.write_half_word(addr, val);
            offset += 2;
            addr   += 2;
        }
        enforce(offset == data.length, "Table size not aligned to 2 bytes!");
    }
}

unittest {
    auto filename = "../test/blinky.elf";
    stm32f4_mem mem;
    //load_function_into_memory(filename, "char_out", mem);
    auto lit = mem.read_word(0x80004f4);
    //assert(lit == 0x20000000, format("Actual instrs length is %08X, not the expected 0x20000000", lit));
}

func[] get_program_from_elf(const string elf_file) {
    bool[uint] pending_literals;
    func[] res;
    auto f_s = get_st_name_val(elf_file, st_type.stt_func, soc.all);
    foreach (fn; f_s) {
        auto f = get_function_from_elf(elf_file, fn.name, fn.addr, pending_literals);
        res ~= f; 
    }
    return res;
}
