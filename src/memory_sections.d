import std.algorithm;
import std.stdio;
import std.format;
import std.traits : EnumMembers;
import std.conv;
import core.exception : RangeError;

import log;
import cortex_m_core;
import cortex_m_scb;
import scb_defs;
import stm32f4_defs;
import stm32f4_peripherals;
import nrf52_defs;
import nrf52_peripherals;
import thumb_2_instrs;
import rw612_peripherals;
import rw612_defs;

// --------------------------------------------------------------------------------------
// ====================
//  WRITE BYTE TO WORD
// ====================
void 
write_byte_to_word
(T1,T2)
(ref uint[T1] mem_block, const T2 addr, const ubyte b) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr &  3) * 8;
    uint   old;
    try {
        old       =  mem_block[cast(T1)word_addr];
    } catch (RangeError e) { 
        throw new Exception(format("Invalid access: %08X", addr));
    }
    const uint   masked    = (old & ~(0xff << shift)) | (b << shift);
    try {
        mem_block[cast(T1)word_addr] = masked;
    } catch (RangeError e) { 
        throw new Exception(format("Invalid access: %08X", addr));
    }
}

// =====================
//  READ BYTE FROM WORD
// =====================
ubyte 
read_byte_from_word
(T1,T2)
(ref uint[T1] mem_block, T2 addr) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr & 3) * 8;
    uint   val;
    try {
        val       = mem_block[cast(T1)word_addr];
    } catch (RangeError e) { 
        throw new Exception(format("Invalid access: %08X", addr));
    }
    return cast(ubyte)((val >> shift) & 0xff);
}
// --------------------------------------------------------------------------------------

// =========================
//  WRITE HALF WORD TO WORD
// =========================

void 
write_half_word_to_word
(T1,T2)
(ref uint[T1] mem_block, const T2 addr, const ushort hw) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr &  2) * 16;
    const uint   old       =  mem_block[cast(T1)word_addr];
    const uint   masked    = (old & ~(0xffff << shift)) | (hw << shift);
    mem_block[cast(T1)word_addr] = masked;
}
// --------------------------------------------------------------------------------------

// ==========================
//  READ HALF WORD FROM WORD
// ==========================
ushort 
read_half_word_from_word
(T1,T2)
(ref uint[T1] mem_block, T2 addr) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr & 2) * 16;
    const uint   val       = mem_block[cast(T1)word_addr];
    return cast(ushort)((val >> shift) & 0xffff);
}
// --------------------------------------------------------------------------------------

// ==========
//  TINY MEM
// ==========

struct tiny_mem {
    enum flash_origin = 0;
    enum flash_length = 0;
    enum ram_origin = 0;
    enum ram_length = 0;
    enum stack_base = 0x400;
    mem_section!(1,0) mem; 

    void write_word(size_t addr, uint val) {
        mem.write_word(addr, val);  
    }
    uint read_word(size_t addr) const { 
        return mem.read_word(addr);
    }
    void write_byte(size_t addr, ubyte val) {
        mem.write_byte(addr, val);
    }
    ubyte read_byte(size_t addr) const { 
        return mem.read_byte(addr);
    }
    void write_half_word(size_t addr, ushort val) {
        mem.write_half_word(addr, val);
    }
    ushort read_half_word(size_t addr) const { 
        return mem.read_half_word(addr);
    }
    void flip_bit(const uint addr, const uint bit){}
    string get_reg_name(const uint addr) { return ""; }
    void set_vtor() {};
    uint peek_word(size_t addr) {
        uint res;
        return res;
    }
}
// --------------------------------------------------------------------------------------
// ========================================
//  GET SYSTEM CONTROL BLOCK REGISTER NAME
// ========================================

string get_scb_reg_name(const uint reg_addr) { 
    foreach(k; scb.keys)  
    {
        if (cast(uint) k == reg_addr)  
            return k.to!string;        
    }
    return "";
}
// --------------------------------------------------------------------------------------  
// ================================
//  READ UNSIGNED LITTLE ENDIAN 16
// ================================
ushort read_ul_16(const ubyte[] cells, size_t index) {
    return (cells[index + 1] << 8) | cells[index];
}

// ================================
//  READ UNSIGNED LITTLE ENDIAN 32
// ================================
uint read_ul_32(const ubyte[] cells, size_t index) {
    uint res = (cells[index + 3] << 24) | 
               (cells[index + 2] << 16) | 
               (cells[index + 1] <<  8) | 
                cells[index    ];
    return res;
}

// =================================
//  WRITE UNSIGNED LITTLE ENDIAN 32
// =================================
void write_ul_32(ubyte[] cells, size_t index, const uint val) {
    cells[index + 3] = (val >> 24) & 0xff;
    cells[index + 2] = (val >> 16) & 0xff;
    cells[index + 1] = (val >>  8) & 0xff;
    cells[index] =      val        & 0xff;
}

// =================================
//  WRITE UNSIGNED LITTLE ENDIAN 16
// =================================
void write_ul_16(ubyte[] cells, size_t index, const ushort val) {
    cells[index + 1] = (val >> 8) & 0xff;
    cells[index] =      val       & 0xff;
}
// -------------------------------------------------------------------------------------- 

// =============
//  MEM SECTION
// =============

struct mem_section(size_t kb, size_t origin) {
	ubyte[kb * 1024] cells;
    // -------------------------------------------------------------------------------------- 
    // ===========
    //  READ BYTE
    // ===========
    const(ubyte) read_byte(size_t index) const {
    	index -= origin;
        return cells[index];
    }

    // ============
    //  WRITE BYTE
    // ============
    void write_byte(size_t index, const ubyte val) {
        index -= origin;
        cells[index] = val;
    }
    // -------------------------------------------------------------------------------------- 
    // ================
    //  READ HALF WORD
    // ================
    const(ushort) read_half_word(size_t index) const {
    	index -= origin;
    	return read_ul_16(cells, index);
    }

    // =================
    //  WRITE HALF WORD
    // =================
    void write_half_word(size_t index, const ushort val) {
        index -= origin;
        write_ul_16(cells, index, val);
    }
    // -------------------------------------------------------------------------------------- 
    // ===========
    //  READ WORD
    // ===========
    const(uint) read_word(size_t index) const {
    	index -= origin;
    	return read_ul_32(cells, index);
    }

    // ============
    //  WRITE WORD
    // ============
    void write_word(size_t index, const uint val) {
    	index -= origin;
        write_ul_32(cells, index, val);
    }
}
// --------------------------------------------------------------------------------------

__gshared ubyte[1024 * 1024] g_big_mem;

// =================
//  BIG MEM SECTION
// =================

struct big_mem_section(size_t origin) {
    // ===========
    //  READ BYTE
    // ===========
    const(ubyte) read_byte(size_t index) const {
    	index -= origin;
        return g_big_mem[index];
    }

    // ============
    //  WRITE BYTE
    // ============
    void write_byte(size_t index, const ubyte val) {
        index -= origin;
        g_big_mem[index] = val;
    }
    // --------------------------------------------------------------------------------------
    // ================
    //  READ HALF WORD
    // ================
    const(ushort) read_half_word(size_t index) const {
    	index -= origin;
    	return read_ul_16(g_big_mem, index);
    }

    // =================
    //  WRITE HALF WORD
    // =================
    void write_half_word(size_t index, const ushort val) {
        index -= origin;
        write_ul_16(g_big_mem, index, val);
    }
    // --------------------------------------------------------------------------------------
    // ===========
    //  READ WORD
    // ===========

    const(uint) read_word(size_t index) const {
    	index -= origin;
    	return read_ul_32(g_big_mem, index);
    }

    // ============
    //  WRITE WORD
    // ============
    static void write_word(size_t index, const uint val) {
       	index -= origin;
    	write_ul_32(g_big_mem, index, val);
    }

    enum origin_ = origin; 
}
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
unittest {
    big_mem_section!(0x08000000) flash;
    flash.write_word(flash.origin_, 32);
    uint read_value = flash.read_word(flash.origin_);
    assert(read_value == 32, "Failed to read word from flash");
}

enum scb_base = 0xE0000000;

// ==========
//  USART DR
// ==========

size_t[] usart_dr = [
    USART1_DR,
    USART2_DR,
    USART3_DR,
    USART6_DR
];

// =============
//  STM32F4 MEM
// =============

struct stm32f4_mem {
    enum flash_origin  =  0x08000000;
    enum ram_origin    =  0x20000000;
    enum sram_1_origin =  0x20020000;
    enum flash_length  = 1024 * 1024;
    enum ram_length    =  128 * 1024;
    enum sram_1_length =  368 * 1024;
    mem_section!(368, sram_1_origin) sram_1;            
    mem_section!(128,    ram_origin)    ram;
    big_mem_section!(flash_origin)    flash;
    static uint stack_base = ram_origin + ram_length;

    void set_vtor() {
        scb[VTOR] = 0x8000000;
    }

    string get_reg_name(const uint reg_addr) {
        foreach(k; stm32f4_peripheral_regs.keys)  
        {
            if (cast(uint) k == reg_addr)  
                return k.to!string;        
        }
        return "";
    }

    uint peek_word(size_t addr) {
        uint res;
        if (addr >= scb_base) {
            if (cast(scb_reg)addr in scb) {
                res = scb_ctrl.read_word(addr);
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= sram_1_origin + sram_1_length) {
            if (cast(stm32f4_peripheral_reg)addr in stm32f4_peripheral_regs) {
                res = stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr];                           
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= sram_1_origin) {
            res = sram_1.read_word(addr);
        } else if (addr >= ram_origin) {
            res = ram.read_word(addr);
        } else {
            res = flash.read_word(addr);
        }
        return res;
    }

    uint read_word(size_t addr) {
        if (addr == CAN1_MSR) {
            if (stm32f4_peripheral_regs[CAN1_MSR] == 0x00000C02) {
                stm32f4_peripheral_regs[CAN1_MSR] = 0x00000C03;
                return stm32f4_peripheral_regs[CAN1_MSR];
            }
            if (stm32f4_peripheral_regs[CAN1_MSR] == 0x00000C03) {
                stm32f4_peripheral_regs[CAN1_MSR] = 0x00000C01;
                return stm32f4_peripheral_regs[CAN1_MSR];
            }
            if (stm32f4_peripheral_regs[CAN1_MSR] == 0x00000C01) {
                stm32f4_peripheral_regs[CAN1_MSR] = 0x00000C00;
                return stm32f4_peripheral_regs[CAN1_MSR];
            }
        }
        if (addr == 0x40023800) {
            flip_bit(0x40023800, 25);
            flip_bit(0x40023800, 27);
        }
        if (addr == 0x40023874)
            flip_bit(0x40023874, 1);
        uint res;
        if (addr >= scb_base) {
            res = scb_ctrl.read_word(addr);
        } else if (addr >= sram_1_origin + sram_1_length) {
            if (cast(stm32f4_peripheral_reg)addr in stm32f4_peripheral_regs) {
                res = stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr];       
                if (addr == OTG_FS_GRSTCTL) {
                    if (res == 0x80000001) {
                        res = 0x80000000;
                    }
                }                    
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= sram_1_origin) {
            res = sram_1.read_word(addr);
        } else if (addr >= ram_origin) {
            res = ram.read_word(addr);
        } else {
            res = flash.read_word(addr);
        }
        return res;
    }

    void flip_bit(size_t addr, int bit_pos) {
        if (addr >= scb_base) {
            uint val = scb[cast(scb_reg)addr];
            val ^= (1u << bit_pos);
            scb[cast(scb_reg)addr] = val;
        } else if (addr > ram_origin + ram_length) {
            uint val = stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr];
            val ^= (1u << bit_pos);
            stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr] = val;
        }
    }

    const(ushort) read_half_word(size_t addr) {
        if (addr >= sram_1_origin) {
            return sram_1.read_half_word(addr);
        } else if (addr >= ram_origin) {
            return ram.read_half_word(addr);
        } else {
            return flash.read_half_word(addr);
        }
    }

    void write_half_word(size_t addr, ushort val) {
        if (addr >= sram_1_origin) {
            sram_1.write_half_word(addr, val);
        } else if (addr >= ram_origin) {
            ram.write_half_word(addr, val);
        } else {
            flash.write_half_word(addr, val);
        }
    }

    const(ubyte) read_byte(size_t addr) {
        if (addr > scb_base) {
            if (addr == 0xE000E400) {
                return 0xf0;
            }
            return read_byte_from_word(scb, addr);
        } else if (addr >= ram_origin + ram_length) {
            return read_byte_from_word(stm32f4_peripheral_regs, addr);
        } 
        if (addr >= ram_origin) {
            return ram.read_byte(addr);
        } else {
            return flash.read_byte(addr);
        }
    }

    void write_word(size_t addr, uint val) {
        if (addr >= scb_base) {
            return scb_ctrl.write_word(addr, val);
        } else if (addr >= sram_1_origin + sram_1_length) {
            if (addr == 0x40023808) {
                uint cfgr = stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr];
                cfgr = val;
                uint sw = val & 0x3;
                cfgr &= ~(0x3 << 2);
                cfgr |= (sw << 2);
                stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr] = cfgr;
            } else if (addr == 0x40023874 && val == 0x1) {
                stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr] = 0x3;
            } else if (usart_dr.canFind(addr)) {
                auto f = uart_log();
                f.write(cast(char)(val & 0xff));
                f.flush();
            } else if (addr == 0x40020018) { 
                auto f = gpio_log();
                if (val & (1 << 5)) {
                    f.write("GPIOA5 toggled on\n");
                }
                if (val & (1 << (5 + 16))) {
                    f.write("GPIOA5 toggled off\n");
                }
                f.flush();
            } else {
                stm32f4_peripheral_regs[cast(stm32f4_peripheral_reg)addr] = val;
            }
            return;
        }
        if (addr >= sram_1_origin) {
            return sram_1.write_word(addr, val);
        }
        if (addr >= ram_origin) {
            return ram.write_word(addr, val);
        } else {
            return flash.write_word(addr, val);
        }
    }

    void write_byte(const size_t addr, const uint val) {
        const ubyte b = cast(ubyte)slice(val, 0, 8);
        if (addr >= scb_base) {
            write_byte_to_word(scb, addr, b);
        } else if (addr >= ram_origin + ram_length) {
            write_byte_to_word(stm32f4_peripheral_regs, addr, b);
        } else if (addr >= ram_origin) {
            ram.write_byte(addr, b);
        } else {
            flash.write_byte(addr, b);
        }
    }
}

size_t[] nrf52840_always_set = [
    CLOCK_LFCLKSRC,
    UART0_EVENTS_TXDRDY,
    QPSI_EVENTS_READY,
    UARTE0_EVENTS_TXSTOPPED,
    UARTE0_EVENTS_ENDTX,        
    ECB_EVENTS_ENDECB
];

struct nrf52840_mem {
    enum flash_origin  =  0x00000000;
    enum ram_origin    =  0x20000000;
    enum flash_length  =  1024* 1024;
    enum ram_length    =  256 * 1024;
    enum ficr_length   =   16 * 1024;
    enum ficr_origin   =  0x10000000;
    mem_section!(256, ram_origin)     ram;
    big_mem_section!(flash_origin)  flash;
    mem_section!(16, ficr_origin)    ficr;
    static uint stack_base = ram_origin + ram_length;

    string get_reg_name(const uint reg_addr) {
        foreach(k; nrf52_peripheral_regs.keys)  
        {
            if (cast(uint) k == reg_addr)  
                return k.to!string;        
        }
        return "";
    }

    void set_vtor() {}

    uint read_word(size_t addr) {
        uint res;
        if (nrf52840_always_set.canFind(addr)) 
            return 0x1;
        if (addr >= scb_base) {
            res = scb_ctrl.read_word(addr);
        } else if (addr > ram_origin + ram_length) {
            if (cast(nrf52_peripheral_reg)addr in nrf52_peripheral_regs) {
                res = nrf52_peripheral_regs[cast(nrf52_peripheral_reg)addr]; 
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= ram_origin) {
            res = ram.read_word(addr);
        } else if (addr >= ficr_origin) {
            res = ficr.read_word(addr);
        } else {
            res = flash.read_word(addr);
        }
        return res;
    }

    uint peek_word(size_t addr) {
        uint res;
        return res;
    }

    void flip_bit(size_t addr, int bit_pos) {
        if (addr >= scb_base) {
            uint val = scb[cast(scb_reg)addr];
            val ^= (1u << bit_pos);
            scb[cast(scb_reg)addr] = val;
        } else if (addr > ram_origin + ram_length) {
            uint val = nrf52_peripheral_regs[cast(nrf52_peripheral_reg)addr];
            val ^= (1u << bit_pos);
            nrf52_peripheral_regs[cast(nrf52_peripheral_reg)addr] = val;
        }
    }

    const(ushort) read_half_word(size_t addr) {
        if (addr > ram_origin + ram_length) {
            return read_half_word_from_word(nrf52_peripheral_regs, addr);
        } else if (addr >= ram_origin) {
            return ram.read_half_word(addr);
        } else if (addr >= ficr_origin) {
            return ficr.read_half_word(addr);
        } else if (addr < flash_origin + flash_length) {
            return flash.read_half_word(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }

    void write_half_word(size_t addr, ushort val) {
        if (addr >= ram_origin) {
            ram.write_half_word(addr, val);
        } else {
            flash.write_half_word(addr, val);
        }
    }

    const(ubyte) read_byte(size_t addr) {
        if (addr >= scb_base) {
            if (addr == 0xE000E400) {
                return 0xf0;
            }
            return read_byte_from_word(scb, addr);
        }
        if (addr >= ram_origin + ram_length) {
            return read_byte_from_word(nrf52_peripheral_regs, addr);
        } 
        if (addr >= ram_origin) {
            return ram.read_byte(addr);
        } else {
            return flash.read_byte(addr);
        }
    }

    void handle_uart() {
        auto f       = uart_log();
        uint tx_ptr  = read_word(UARTE0_TXD_PTR);          
        uint max_cnt = read_word(UARTE0_TXD_MAXCNT);
        assert((tx_ptr >= ram_origin) && tx_ptr < ram_origin + ram_length);
        if (max_cnt == 0) return;
        for (uint i = 0; i < max_cnt; ++i ) 
            f.write(cast(char)read_byte(tx_ptr + i));
        f.flush();
    }

    void write_word(size_t addr, uint val) {
        if (addr >= scb_base) {
            return scb_ctrl.write_word(addr, val);
        } else if (addr >= ram_origin + ram_length) {
            nrf52_peripheral_regs[cast(nrf52_peripheral_reg)addr] = val;
            if (addr == UART0_TASKS_STARTTX)
                handle_uart();
        }
        else if (addr >= ram_origin) {
            ram.write_word(addr, val);
        } else if (addr >= ficr_origin) {
            ficr.write_word(addr, val);
        } else {
            flash.write_word(addr, val);
        }
    }

    void write_byte(const size_t addr, const uint val) {
        immutable b = cast(ubyte)slice(val, 0, 8);
        if (addr >= scb_base)
            write_byte_to_word(scb, addr, b);
        else if (addr >= ram_origin + ram_length)
            write_byte_to_word(nrf52_peripheral_regs, addr, b);
        else if (addr >= ram_origin) 
            ram.write_byte(addr, b);
        else
            flash.write_byte(addr, b);
    }
}


rw612_peripheral_reg[] rw612_reset_ctl_set = [
    RSTCTL0_PRSTCTL0_SET,
    RSTCTL0_PRSTCTL1_SET,
    RSTCTL0_PRSTCTL2_SET,
    RSTCTL1_PRSTCTL0_SET,
    RSTCTL1_PRSTCTL1_SET,
    RSTCTL1_PRSTCTL2_SET,
];

rw612_peripheral_reg[] rw612_reset_ctl_clr = [
    RSTCTL0_PRSTCTL0_CLR,
    RSTCTL0_PRSTCTL1_CLR,
    RSTCTL0_PRSTCTL2_CLR,
    RSTCTL1_PRSTCTL0_CLR,
    RSTCTL1_PRSTCTL1_CLR,
    RSTCTL1_PRSTCTL2_CLR,
];

void handle_reset_ctl_set(const size_t addr, uint val) {
    switch (cast(rw612_peripheral_reg)addr) {
        case RSTCTL0_PRSTCTL0_SET:
            rw612_peripheral_regs[RSTCTL0_PRSTCTL0] |= val;
            break;
        case RSTCTL0_PRSTCTL1_SET:
            rw612_peripheral_regs[RSTCTL0_PRSTCTL1] |= val;
            break;
        case RSTCTL0_PRSTCTL2_SET:
            rw612_peripheral_regs[RSTCTL0_PRSTCTL2] |= val;
            break;
        case RSTCTL1_PRSTCTL0_SET:
            rw612_peripheral_regs[RSTCTL1_PRSTCTL0] |= val;
            break;
        case RSTCTL1_PRSTCTL1_SET:
            rw612_peripheral_regs[RSTCTL1_PRSTCTL1] |= val;
            break;
        case RSTCTL1_PRSTCTL2_SET:
            rw612_peripheral_regs[RSTCTL1_PRSTCTL2] |= val;
            break;
        default:
            break;
    }
}

void handle_reset_ctl_clr(const size_t addr, uint val) {
    uint res;
    switch (cast(rw612_peripheral_reg)addr) {
        case RSTCTL0_PRSTCTL0_CLR:
            res = rw612_peripheral_regs[RSTCTL0_PRSTCTL0] & val;
            res = ~res;
            rw612_peripheral_regs[RSTCTL0_PRSTCTL0] = res; 
            break;
        case RSTCTL0_PRSTCTL1_CLR:
            res = rw612_peripheral_regs[RSTCTL0_PRSTCTL1] & val;
            res = ~res;
            rw612_peripheral_regs[RSTCTL0_PRSTCTL1] = res;
            break;
        case RSTCTL0_PRSTCTL2_CLR:
            res = rw612_peripheral_regs[RSTCTL0_PRSTCTL2] & val;
            res = ~res;
            rw612_peripheral_regs[RSTCTL0_PRSTCTL2] = res;
            break;
        case RSTCTL1_PRSTCTL0_CLR:
            res = rw612_peripheral_regs[RSTCTL1_PRSTCTL0] & val;
            res = ~res;
            rw612_peripheral_regs[RSTCTL1_PRSTCTL0] = res; 
            break;
        case RSTCTL1_PRSTCTL1_CLR:
            res = rw612_peripheral_regs[RSTCTL1_PRSTCTL1] & val;
            res = ~res;
            rw612_peripheral_regs[RSTCTL1_PRSTCTL1] = res;
            break;
        case RSTCTL1_PRSTCTL2_CLR:
            res = rw612_peripheral_regs[RSTCTL1_PRSTCTL2] & val;
            res = ~res;
            rw612_peripheral_regs[RSTCTL1_PRSTCTL2] = res;
            break;
        default:
            break;
    }
}

struct rw612_mem {
    enum ram_origin   =  0x1000_0000;   
    enum ram_length   =  0x0013_0000;
    enum flash_origin  = 0x1800_0000;   
    enum flash_length  = 1024 * 1024; 
    mem_section!(1_216, ram_origin)  sram;
    big_mem_section!(flash_origin)  flash;
    void write_word(size_t addr, uint val) {
        if (addr >= scb_base) {
            addr &= ~0x0002_0000;
            scb_ctrl.write_word(addr, val);
        } else if (addr >= flash_origin + flash_length) {    
            addr = remove_alias(addr);
            if (addr == USART3_FIFOWR) {
                auto f = uart_log();
                f.write(cast(char)(val & 0xff));
                f.flush();
                return;
            }
            if (rw612_reset_ctl_set.canFind(addr)) {
                return handle_reset_ctl_set(addr, val);
            }
            if (rw612_reset_ctl_clr.canFind(addr)) {
                return handle_reset_ctl_clr(addr, val);
            }
            //APB_GRP1_MEM_RULE2
            if (addr >= 0x40030000 && addr < 0x40037FFF) {
                if (addr >= 0x40031000 && addr < 0x40031128) {
                    set_periph_reg(addr, val);
                    return;
                } else
                    return;
            }
            // CLKCTL0_RULE1
            // 0x4000 1000--0x4000 1FFF
            if (addr >= 0x40001000 && addr < 0x40001FFF)
                return;
            // 0x4000 0000--0x4000 0FFF
            // RSTCTL0_RULE0
            if (addr >= 0x40000000 && addr < 0x40000FFF) {
                if (addr >= 0x4000_0000 && addr <= 0x4000_0078) {
                    set_periph_reg(addr, val);
                    return;
                } else
                    return;
            }
            // 0x45000000-0x4500FFFF parta (SOC_TOP_MEM_RULE0 - SOC_TOP_MEM_RULE3)
            if (addr >= 0x45000000 && addr < 0x4500FFFF)
                return;
            // ITRC_RULE4
            // 0x4002 4000--0x4002 4FFF
            if (addr >= 0x40024000 && addr < 0x40024FFF)
                return;
            // SYSCTL2_RULE3
            // 0x4000 3000--0x4000 3FFF
            if (addr >= 0x4000_3000 && addr < 0x4000_3FFF) {
                if (addr >= 0x4000_3000 && addr <= 0x4000_3294) {
                    set_periph_reg(addr, val);
                    if (addr == PLL_CTRL) {
                        if (val == 0x00029D01)
                            set_periph_reg(addr, 0x00029D03);
                        if (val == 0x0002A323)
                            set_periph_reg(addr, 0x0002A363);
                    } 
                    return;
                } else
                    return;
            }
            set_periph_reg(addr, val);
        } else if (addr_in_flash(addr)) {    
            flash.write_word(addr, val);
        } else if (addr_in_ram(addr)) {    
            sram.write_word(addr, val);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }

    uint get_periph_reg(const size_t addr) { 
        return rw612_peripheral_regs[cast(rw612_peripheral_reg)addr];
    }

    void set_periph_reg(const size_t addr, const uint val) {
        rw612_peripheral_regs[cast(rw612_peripheral_reg)addr] = val;
    }

    uint read_word(size_t addr) {
        if (addr >= scb_base) {
            size_t addrc = addr;
            addrc &= ~0x0002_0000;
            return scb_ctrl.read_word(addrc); 
        } else if (addr >= flash_origin + flash_length) {    
            addr = remove_alias(addr);
            //APB_GRP1_MEM_RULE2
            if (addr == USB_PLL_Control_0) {
                return get_periph_reg(addr) | 0x8000_0000;
            } 
            if (addr == USB_Calibration_Control) {
                if (get_periph_reg(addr) == 0x4833_0788) {
                    uint res = get_periph_reg(addr) | 0x8000_0000;
                    set_periph_reg(addr, res);
                    return res;
                }
                if (get_periph_reg(addr) == 0xC833_2788) {
                    uint res = get_periph_reg(addr) | 0x0080_0000;
                    set_periph_reg(addr, res);
                    return res;
                }
            } 
            if (addr == USB_USBCMD) {
                if (get_periph_reg(addr) == 0x0008_0002) {
                    return get_periph_reg(addr) ^ 0x2;
                } 
            }
            if (addr >= 0x40030000 && addr < 0x40037FFF) {
                if (addr >= 0x40031000 && addr < 0x40031128) {
                    try {
                        return get_periph_reg(addr);
                    } catch (RangeError e) { 
                        throw new Exception(format("Invalid access: %08X", addr));
                    }
                } else
                    return 0x0;
            } 
            // CLKCTL0_RULE1
            // 0x4000 1000--0x4000 1FFF
            if (addr >= 0x40001000 && addr < 0x40001FFF)
                return 0x0;
            // 0x4000 0000--0x4000 0FFF
            // RSTCTL0_RULE0
            if (addr >= 0x40000000 && addr < 0x40000FFF) {
                if (addr >= 0x4000_0000 && addr <= 0x4000_0078) {
                    uint val;
                    try {
                        val = rw612_peripheral_regs[cast(rw612_peripheral_reg)addr];
                    } catch (RangeError e) { 
                        throw new Exception(format("Invalid access: %08X", addr));
                    }
                    if (addr == PRSTCTL2) {
                        val = get_periph_reg(addr);
                        set_periph_reg(addr, 0x04000005);
                    }
                    return val;
                } else
                    return 0x0;
            }
            // ELS_RULE7
            // 0x4000 7000--0x4000 7FFF
            if (addr >= 0x40007000 && addr < 0x40007FFF)
                return 0x0;
            // 0x45000000-0x4500FFFF parta (SOC_TOP_MEM_RULE0 - SOC_TOP_MEM_RULE3)
            if (addr >= 0x45000000 && addr < 0x4500FFFF)
                return 0x0;
            // ITRC_RULE4
            // 0x4002 4000--0x4002 4FFF
            if (addr >= 0x40024000 && addr < 0x40024FFF)
                return 0x0;
            // SYSCTL2_RULE3
            // 0x4000 3000--0x4000 3FFF
            if (addr >= 0x4000_3000 && addr < 0x4000_3FFF) {
                if (addr >= 0x4000_3000 && addr <= 0x4000_3294) {
                    uint val;
                    try {
                         val = get_periph_reg(addr);
                    } catch (RangeError e) { 
                        throw new Exception(format("Invalid access: %08X", addr));
                    }
                    return val;
                } else
                    return 0x0;
            }
            uint val;
            try {
                val = get_periph_reg(addr);
                static int reset_state = 0;
                if (addr == RSTCTL1_PRSTCTL1) {
                    switch (reset_state) {
                        case 0: 
                            reset_state = 1;
                            set_periph_reg(addr, 0x80010002);
                            return 0x80010002;
                            break;
                        case 1: // clear phase
                            reset_state = 2;
                            set_periph_reg(addr, 0x80010002);
                            return 0x80010002;
                            break;
                        case 2: // re-arm phase
                            reset_state = 3;
                            set_periph_reg(addr, 0x80010001);
                            return 0x80010001;
                            break;
                        case 3: // re-arm phase         
                            reset_state = 4;
                            set_periph_reg(addr, 0x80010002);
                            return 0x80010002;
                            break;
                        case 4: // re-arm phase
                            reset_state = 5;
                            set_periph_reg(addr, 0x80010001);
                            return 0x80010002;
                            break;
                        case 5: // re-arm phase
                            reset_state = 6;
                            set_periph_reg(addr, 0x80010000);
                            return 0x80010000;
                            break;
                        case 6: // re-arm phase
                            reset_state = 7;
                            set_periph_reg(addr, 0x80010020);
                            return 0x80010002;
                            break;
                        case 7:
                        default:
                            assert(0);
                    }
                }
                if (addr == RSTCTL1_PRSTCTL2) {
                    if (val == 0xC000_011F) {
                        set_periph_reg(addr, 0x8000_011F);
                        return 0x8000_011F;
                    }
                }
            } catch (RangeError e) { 
                throw new Exception(format("Invalid access: %08X", addr));
            }
            return val;              
            throw new Exception(format("Invalid memory access: %08X", addr));
        } else if (addr_in_flash(addr)) {    
            return flash.read_word(addr);
        } else if (addr_in_ram(addr)) {    
            return sram.read_word(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }

    bool addr_in_flash(const size_t addr) {
        return addr >= flash_origin && addr < flash_origin + flash_length;
    }
    bool addr_in_ram(const size_t addr) {
        return addr >= ram_origin   && addr < ram_origin + ram_length;
    }
    void write_byte(size_t addr, ubyte val) {
        immutable b = cast(ubyte)slice(val, 0, 8);
        if (addr >= scb_base) {
            write_byte_to_word(scb, addr, b);
        } else if (addr >= flash_origin + flash_length) {    
            addr = remove_alias(addr);
            write_byte_to_word(rw612_peripheral_regs, addr, b);
        } else if (addr_in_flash(addr)) {    
            flash.write_byte(addr, val);
        } else if (addr_in_ram(addr)) {    
            sram.write_byte(addr, val);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    size_t remove_alias(const size_t addr) {
        if (slice(cast(uint)addr, 28, 4) == 0x5) 
            return addr & ~0x1000_0000;
        return addr;
    }

    ubyte read_byte(size_t addr) {
        if (addr >= scb_base) {
            return read_byte_from_word(scb, addr);
        } else if (addr >= flash_origin + flash_length) {    
            addr = remove_alias(addr);
            return read_byte_from_word(rw612_peripheral_regs, addr);
        } else if (addr_in_flash(addr)) {    
            return flash.read_byte(addr);
        } else if (addr_in_ram(addr)) {    
            return sram.read_byte(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    void write_half_word(const size_t addr, ushort val) {
        if (addr_in_ram(addr)) {
            sram.write_half_word(addr, val);
        } else {
            flash.write_half_word(addr, val);
        }
    }
    ushort read_half_word(size_t addr) { 
        if (addr >= scb_base) {
            return read_half_word_from_word(scb, addr);
        } else if (addr >= flash_origin + flash_length) {    
            addr = remove_alias(addr);
            return read_half_word_from_word(rw612_peripheral_regs, addr);
        } else if (addr_in_flash(addr)) {    
            return flash.read_half_word(addr);
        } else if (addr_in_ram(addr)) {    
            return sram.read_half_word(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    void flip_bit(const uint addr, const uint bit) {}
    string get_reg_name(const uint addr) { return ""; }
    void set_vtor() {}
    uint peek_word(size_t addr) {
        uint res;
        return res;
    }
}

struct s32k146_mem {
    enum ram_origin   =  0x1000_0000;   
    enum ram_length   =  0x0013_0000;
    enum flash_origin  = 0x0;   
    enum flash_length  = 128 * 1024; 
    mem_section!(1_216, ram_origin)  sram;
    mem_section!(128, flash_origin)  flash;
        void write_word(const size_t addr, uint val) {
        if (addr >= scb_base) {
            size_t addrc = addr;
            scb_ctrl.write_word(addrc, val);
        } else if (addr >= flash_origin + flash_length) {    
            size_t addrc = addr;
            throw new Exception(format("Invalid memory access: %08X", addr));
        } else if (addr >= flash_origin && addr < flash_origin + flash_length) {    
            flash.write_word(addr, val);
        } else if (addr >= ram_origin   && addr < ram_origin   + ram_length) {    
            sram.write_word(addr, val);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    uint read_word(const size_t addr) {
        if (addr >= scb_base) {
            size_t addrc = addr;
            return scb_ctrl.read_word(addrc); 
        } else if (addr >= flash_origin + flash_length) {    
            size_t addrc = addr;            
            throw new Exception(format("Invalid memory access: %08X", addrc));
        } else if (addr >= flash_origin && addr < flash_origin + flash_length) {    
            return flash.read_word(addr);
        } else if (addr >= ram_origin   && addr < ram_origin   + ram_length) {    
            return sram.read_word(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    void write_byte(const size_t addr, ubyte val) {
        immutable b = cast(ubyte)slice(val, 0, 8);
        if (addr >= scb_base) {
            write_byte_to_word(scb, addr, b);
        } else if (addr >= flash_origin + flash_length) {    
            size_t addrc = addr;
            throw new Exception(format("Invalid memory access: %08X", addrc));
        } else if (addr >= flash_origin && addr < flash_origin + flash_length) {    
            flash.write_word(addr, val);
        } else if (addr >= ram_origin   && addr < ram_origin   + ram_length) {    
            sram.write_word(addr, val);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    ubyte read_byte(const size_t addr) {
        if (addr >= scb_base) {
            return read_byte_from_word(scb, addr);
        } else if (addr >= flash_origin + flash_length) {    
            size_t addrc = addr;
            throw new Exception(format("Invalid memory access: %08X", addrc));
        } else if (addr >= flash_origin && addr < flash_origin + flash_length) {    
            return flash.read_byte(addr);
        } else if (addr >= ram_origin   && addr < ram_origin   + ram_length) {    
            return sram.read_byte(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    void write_half_word(const size_t addr, ushort val) {
        if (addr >= ram_origin   && addr < ram_origin   + ram_length) {
            sram.write_half_word(addr, val);
        } else {
            flash.write_half_word(addr, val);
        }
    }
    ushort read_half_word(const size_t addr) { 
        if (addr >= scb_base) {
            return read_half_word_from_word(scb, addr);
        } else if (addr >= flash_origin + flash_length) {    
            size_t addrc = addr;
            throw new Exception(format("Invalid memory access: %08X", addrc));
        } else if (addr >= flash_origin && addr < flash_origin + flash_length) {    
            return flash.read_half_word(addr);
        } else if (addr >= ram_origin   && addr < ram_origin   + ram_length) {    
            return sram.read_half_word(addr);
        } else {
            throw new Exception(format("Invalid memory access: %08X", addr));
        }
    }
    void flip_bit(const uint addr, const uint bit) {}
    string get_reg_name(const uint addr) { return ""; }
    void set_vtor() {}
    uint peek_word(size_t addr) {
        uint res;
        return res;
    }
}