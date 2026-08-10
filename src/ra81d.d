import std.string : format;
//              ________________________
// 0xFFFF_FFFF |                        |
//             |     Arm Cortex-M85     |
// 0xE010_0000 |________________________|
//             |                        |
//             | Private peripheral bus |
// 0xE000_0000 |________________________|
//             |                        |
//             |     Reserved area      | (22)
// 0xA000_0000 |________________________|
//             |                        |
//             | External address space | (OSPI area)
// 0x8000_0000 |________________________|
//             |                        |
//             |     Reserved area      | (21)
// 0x7000_0000 |________________________|
//             |                        |
//             | External address space | (SDRAM area)
// 0x6800_0000 |________________________|
//             |                        |
//             | External address space | (CS area)
// 0x6000_0000 |________________________|
//             |                        |
//             |     Reserved area      | (20)
// 0x5050_0000 |________________________|
//             |                        |
//             |Peripheral I/O registers| 
// 0x5020_0000 |________________________|
//             |                        |
//             |     Reserved area      | (19)
// 0x5012_0000 |________________________|
//             |                        |
//             |   Flash I/O registers  | 
// 0x5010_0000 |________________________|
//             |                        |
//             |Peripheral I/O registers| 
// 0x5000_0000 |________________________|                             __ 
//             |                        |                               |
//             |     Reserved area      | (18)                          |
// 0x4050_0000 |________________________|                               |
//             |                        |                               |
//             |Peripheral I/O registers|                               |
// 0x4020_0000 |________________________|                               |
//             |                        |                               |______ Secure
//             |     Reserved area      | (17)                          |
// 0x4012_0000 |________________________|                               |
//             |                        |                               |
//             |   Flash I/O registers  |                               |
// 0x4010_0000 |________________________|                               |
//             |                        |                               |
//             |Peripheral I/O registers|                               |
// 0x4000_0000 |________________________|                             __|
//             |                        |
//             |     Reserved area      | (16)
// 0x3703_0400 |________________________|
//             |                        |
//             |     On-chip flash      | (option-setting memory) 
// 0x3703_0050 |________________________|
//             |                        |
//             |     Reserved area      | (15)
// 0x3700_3000 |________________________|
//             |                        |
//             |     On-chip flash      | (data flash) 
// 0x3700_0000 |________________________|
//             |                        |
//             |     Reserved area      | (14)
// 0x3600_0400 |________________________|
//             |                        |
//             |     Standby SRAM       | 
// 0x3600_0000 |________________________|
//             |                        |
//             |     Reserved area      | (13)
// 0x320E_0000 |________________________|                                   
//             |                        |
//             |      On-chip SRAM      | 
// 0x3200_0000 |________________________|
//             |                        |
//             |     Reserved area      | (12)
// 0x3001_0000 |________________________|
//             |                        |
//             |          DTCM          | 
// 0x3000_0000 |________________________|
//             |                        |
//             |     Reserved area      | (11)
// 0x2703_0400 |________________________|
//             |                        |
//             |     On-chip flash      | (option-setting memory) 
// 0x2703_0050 |________________________|
//             |                        |
//             |     Reserved area      | 
// 0x2700_3000 |________________________|
//             |                        |
//             |     On-chip flash      | (data flash) 
// 0x2700_0000 |________________________|
//             |                        |
//             |     Reserved area      | (10)
// 0x2600_0400 |________________________|
//             |                        |
//             |     Standby SRAM       | 
// 0x2600_0000 |________________________|
//             |                        |
//             |     Reserved area      | (9)
// 0x220E_0000 |________________________|
//             |                        |
//             |      On-chip SRAM      | 
// 0x2200_0000 |________________________|
//             |                        |
//             |     Reserved area      | (8)
// 0x2001_0000 |________________________|
//             |                        |
//             |          DTCM          | 
// 0x2000_0000 |________________________|
//             |                        |
//             |     Reserved area      | (7)
// 0x1300_A300 |________________________|
//             |                        |
//             |     On-chip flash      | (option-setting memory) 
// 0x1300_A100 |________________________|
//             |                        |
//             |     Reserved area      | (6)
// 0x1300_81B4 |________________________|
//             |                        |
//             |     On-chip flash      | (factory flash) 
// 0x1300_80F0 |________________________|
//             |                        |
//             |     Reserved area      | (5)
// 0x122F_8000 |________________________|
//             |                        |
//             |     On-chip flash      | (code flash)(read only) 
// 0x1200_0000 |________________________|
//             |                        |
//             |     Reserved area      | (4)
// 0x1001_0000 |________________________|
//             |                        |
//             |          ITCM          | (D)
// 0x1000_0000 |________________________|
//             |                        |
//             |     Reserved area      | (3) 
// 0x0300_A300 |________________________|
//             |                        |
//             |     On-chip flash      | (factory flash) (C)
// 0x0300_A100 |________________________|
//             |                        |
//             |     Reserved area      | (1)
// 0x022F_8000 |________________________|
//             |                        |
//             |     On-chip flash      | (code flash)(read only) (B)
// 0x0200_0000 |________________________|
//             |                        |
//             |     Reserved area      | (0) 
// 0x0001_0000 |________________________|
//             |                        |
//             |          ITCM          | (A)
// 0x0000_0000 |________________________|

struct address_range {
    uint lower_bound;
    uint upper_bound;
}

address_range[23] reserved_ranges = [
    address_range(0xA000_0000, 0xE000_0000),    // (22)
    address_range(0x7000_0000, 0x8000_0000),    // (21)
    address_range(0x5050_0000, 0x6000_0000),    // (20)
    address_range(0x5012_0000, 0x5020_0000),    // (19)
    address_range(0x4050_0000, 0x5000_0000),    // (18)
    address_range(0x4012_0000, 0x4020_0000),    // (17)
    address_range(0x3703_0400, 0x4000_0000),    // (16)
    address_range(0x3700_3000, 0x3703_0050),    // (15)
    address_range(0x3600_0400, 0x3700_0000),    // (14)
    address_range(0x320E_0000, 0x3600_0000),    // (13)
    address_range(0x3001_0000, 0x3200_0000),    // (12)
    address_range(0x2703_0400, 0x3000_0000),    // (11)
    address_range(0x2600_0400, 0x2700_0000),    // (10)
    address_range(0x220E_0000, 0x2600_0000),    // (9)
    address_range(0x2001_0000, 0x2200_0000),    // (8)
    address_range(0x1300_A300, 0x2000_0000),    // (7)
    address_range(0x1300_81B4, 0x1300_A100),    // (6)
    address_range(0x122F_8000, 0x1300_80F0),    // (5)
    address_range(0x1001_0000, 0x1200_0000),    // (4)
    address_range(0x0001_0000, 0x0200_0000),    // (3)
    address_range(0x0300_A300, 0x1000_0000),    // (2)
    address_range(0x022F_8000, 0x0300_A100),    // (1)
    address_range(0x0001_0000, 0x0200_0000)     // (0)
];

void check_for_reserve_access(const uint addr) {
    foreach (addr_range; reserved_ranges) {
        if ((addr >= addr_range.lower_bound) && (addr < addr_range.upper_bound)) 
            assert(0, "Accessing reserved memory space");
    }
}

struct mem_region(uint base_addr, uint total_size, size_t N) {
    enum uint m_base_addr  = base_addr;
    enum uint m_chunk_size = total_size / N;
    enum uint m_total_size = total_size;
    private ubyte[][N] m_chunks;

    static assert((total_size % N) == 0, 
        "Memory space is not divisible by chunk size");

    void write(T)(const uint addr, const T val) {
        size_t chunk_idx = (addr - m_base_addr) / m_chunk_size;
        uint offset = (addr - m_base_addr) % m_chunk_size;
        if (m_chunks[chunk_idx] is null) {
            m_chunks[chunk_idx] = new ubyte[](m_chunk_size);
            //m_chunks[chunk_idx][] = 0xFF; // Default erase value for flash
        }

        static foreach (i; 0 .. T.sizeof) {
            m_chunks[chunk_idx][offset + i] = cast(ubyte)(val >> (i * 8));
        }
    }
}

struct mem_region_meta {
    uint base_addr;
    uint total_size;
    size_t n_chunks;
}

enum mem_region_meta[] ra8d1_map = [
    /* base_addr , total_size, N */
    mem_region_meta(0x0000_0000, 0x0001_0000, 16), // (A) ITCMI
    mem_region_meta(0x1200_0000, 0x002F_8000, 16), // (B) Code Flash
    mem_region_meta(0x0300_A100, 0x0000_0200,  1), // (C) Factory Flash
    mem_region_meta(0x1000_0000, 0x0001_0000, 16)  // (D) ITCMD
];

struct ra8d1_mem {
    static foreach (i, meta; ra8d1_map) {
        mixin(format("mem_region!(ra8d1_map[%d].base_addr, ra8d1_map[%d].total_size, ra8d1_map[%d].n_chunks) region_%d;", i, i, i, i));
    }

    void write_byte(const uint addr, const ubyte val) {
        static foreach (i, meta; ra8d1_map) {
            if ((addr >= meta.base_addr) && (addr < (meta.base_addr + meta.total_size))) {
                mixin(format("return region_%d.write(addr, val);", i));
            }
        }

        check_for_reserve_access(addr);
        assert(0, "Valid memory access unhandled");
    }

    void write_half_word(const uint addr, const ushort val) {
        static foreach (i, meta; ra8d1_map) {
            if ((addr >= meta.base_addr) && (addr < (meta.base_addr + meta.total_size))) {
                mixin(format("return region_%d.write(addr, val);", i));
            }
        }

        check_for_reserve_access(addr);
        assert(0, "Valid memory access unhandled");
    }

    void write_word(const uint addr, const uint val) {
        static foreach (i, meta; ra8d1_map) {
            if ((addr >= meta.base_addr) && (addr < (meta.base_addr + meta.total_size))) {
                mixin(format("return region_%d.write(addr, val);", i));
            }
        }

        check_for_reserve_access(addr);
        assert(0, "Valid memory access unhandled");
    }
}