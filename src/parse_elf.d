import std.stdio;
import std.exception;
import std.conv;
import std.file;
import std.array;

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
}