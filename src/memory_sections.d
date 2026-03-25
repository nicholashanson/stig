import std.algorithm;
import std.stdio;
import std.format;
import std.traits : EnumMembers;
import std.conv;

import log;
import cortex_m_core;
import cortex_m_scb;
import scb_defs;
import stm32f4_defs;
import nrf52_defs;
import nrf52_peripherals;

// --------------------------------------------------------------------------------------
// ====================
//  WRITE BYTE TO WORD
// ====================
void write_byte_to_word(T1,T2)(ref uint[T1] mem_block, const T2 addr, const ubyte b) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr &  3) * 8;
    const uint   old       =  mem_block[cast(T1)word_addr];
    const uint   masked    = (old & ~(0xff << shift)) | (b << shift);
    mem_block[cast(T1)word_addr] = masked;
}

// =====================
//  READ BYTE FROM WORD
// =====================
ubyte read_byte_from_word(T1,T2)(ref uint[T1] mem_block, T2 addr) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr & 3) * 8;
    const uint   val       = mem_block[cast(T1)word_addr];
    return cast(ubyte)((val >> shift) & 0xff);
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
     return (cells[index + 3] << 24) | 
            (cells[index + 2] << 16) | 
            (cells[index + 1] <<  8) | 
             cells[index    ];
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
// System Handler Priority Register 1
// --------------------------------------------------------------------------------------

immutable string[size_t] stm32f4_peripheral_names = [
    0x40000000: "TIM2_CR1",
    0x40000004: "TIM2_CR2",
    0x40000008: "TIM2_SMCR",
    0x40001000: "TIM6_CR1",   
    0x40001004: "TIM6_CR2",
    0x4000100C: "TIM6_DIER",
    0x40001010: "TIM6_SR",
    0x40001014: "TIM6_EGR", 
    0x40001024: "TIM6_CNT",
    0x40001028: "TIM6_PSC",
    0x4000102C: "TIM6_ARR",
    0x40020000: "GPIOA_MODER",
    0x40020004: "GPIOA_OTYPER",
    0x40020008: "GPIOA_OSPEEDR",
    0x4002000C: "GPIOA_PUPDR",
    0x40020010: "GPIOA_IDR",
    0x40020014: "GPIOA_ODR",
    0x40020020: "GPIOA_AFRL",
    0x40020024: "GPIOA_AFRH",
    0x40020400: "GPIOB_MODER",
    0x40020404: "GPIOB_OTYPER",
    0x40020408: "GPIOB_OSPEEDR",
    0x4002040C: "GPIOB_PUPDR",
    0x40020410: "GPIOB_IDR",
    0x40020414: "GPIOB_ODR",
    0x40020420: "GPIOB_AFRL",
    0x40020424: "GPIOB_AFRH",
    0x40020800: "GPIOC_MODER",
    0x40020804: "GPIOC_OTYPER",
    0x40020808: "GPIOC_OSPEEDR",
    0x4002080C: "GPIOC_PUPDR",
    0x40020810: "GPIOC_IDR",
    0x40020814: "GPIOC_ODR",
    0x40020820: "GPIOC_AFRL",
    0x40020824: "GPIOC_AFRH",
    0x40020C00: "GPIOD_MODER",
    0x40020C04: "GPIOD_OTYPER",
    0x40020C08: "GPIOD_OSPEEDR",
    0x40020C0C: "GPIOD_PUPDR",
    0x40020C10: "GPIOD_IDR",
    0x40020C14: "GPIOD_ODR",
    0x40020C20: "GPIOD_AFRL",
    0x40020C24: "GPIOD_AFRH",
    0x40021000: "GPIOE_MODER",
    0x40021004: "GPIOE_OTYPER",
    0x40021008: "GPIOE_OSPEEDR",
    0x4002100C: "GPIOE_PUPDR",
    0x40021010: "GPIOE_IDR",
    0x40021014: "GPIOE_ODR",
    0x40021020: "GPIOE_AFRL",
    0x40021024: "GPIOE_AFRH",
    0x40021400: "GPIOF_MODER",
    0x40021404: "GPIOF_OTYPER",
    0x40021408: "GPIOF_OSPEEDR",
    0x4002140C: "GPIOF_PUPDR",
    0x40021410: "GPIOF_IDR",
    0x40021414: "GPIOF_ODR",
    0x40021420: "GPIOF_AFRL",
    0x40021424: "GPIOF_AFRH",
    0x40021800: "GPIOG_MODER",
    0x40021804: "GPIOG_OTYPER",
    0x40021808: "GPIOG_OSPEEDR",
    0x4002180C: "GPIOG_PUPDR",
    0x40021810: "GPIOG_IDR",
    0x40021814: "GPIOG_ODR",
    0x40021820: "GPIOG_AFRL",
    0x40021824: "GPIOG_AFRH",
    0x40021C00: "GPIOH_MODER",
    0x40021C04: "GPIOH_OTYPER",
    0x40021C08: "GPIOH_OSPEEDR",
    0x40021C0C: "GPIOH_PUPDR",
    0x40021C10: "GPIOH_IDR",
    0x40021C14: "GPIOH_ODR",
    0x40021C20: "GPIOH_AFRL",
    0x40021C24: "GPIOH_AFRH",
    0x40023830: "RCC_AHB1ENR",
    0x40023840: "RCC_APB1ENR",
    0x40023844: "RCC_APB2ENR",
    0xE000ED90: "MPU_TYPE",
    0xE000ED94: "MPU_CTRL", 
    0xE000ED98: "MPU_RNR",
    0xE000ED9C: "MPU_RBAR",
    0xE000EDA0: "MPU_RASR",
    0x4002388C: "RCC_DCKCFGR",
    0x40011400: "USART6_SR",
    0x40011404: "USART6_DR",
    0x40011408: "USART6_BRR",
    0x4001140C: "USART6_CR1",
    0x40011410: "USART6_CR2",
    0x40011414: "USART6_CR3",
    0x40011418: "USART6_GTPR",
    0x40004400: "USART2_SR",
    0x40023C00: "FLASH_ACR", 
    0x40013C00: "EXTI_IMR",
    0x40013C04: "EXTI_EMR",
    0x40013C08: "EXTI_RTSR",
    0x40013C0C: "EXIT_FTSR",
    0x40013C10: "EXTI_SWIER",
    0x40013C14: "EXTI_PR",
    0x40023800: "RCC_CR",
    0x40023804: "RCC_PLLCFGR", 
    0x40023808: "RCC_CFGR",
    0x4002380C: "RCC_CIR",
    0x40023874: "RCC_CSR",
    0x40013800: "SYSCFG_MEMRMP",
    0x40026400: "DMA2_LISR",
    0x40026404: "DMA2_HISR"    
]; 

enum USART1_DR = 0x40011004;
enum USART2_DR = 0x40004404;
enum USART3_DR = 0x40004804;    
enum USART6_DR = 0x40011404;
enum FMC_BCR1  = 0xA0000000;
enum FMC_BCR2  = 0xA0000008;
enum FMC_BCR3  = 0xA0000010;
enum FMC_BCR4  = 0xA0000018;
enum FMC_BTR1  = 0xA0000004;
enum FMC_BTR2  = 0xA000000C;
enum FMC_BTR3  = 0xA0000014;
enum FMC_BTR4  = 0xA000001C;
enum FMC_BWTR1 = 0xA0000104;
enum FMC_BWTR2 = 0xA000010C;
enum FMC_BWTR3 = 0xA0000104;
enum FMC_BWTR4 = 0xA000010C;
enum FMC_PCR2  = 0xA0000060;
enum FMC_PCR3  = 0xA0000080;
enum FMC_PCR4  = 0xA00000A0;
enum FMC_SR2   = 0xA0000064;
enum FMC_SR3   = 0xA0000084;
enum FMC_SR4   = 0xA00000A4;
enum FMC_PMEM2 = 0xA0000068;
enum FMC_PMEM3 = 0xA0000088;
enum FMC_PMEM4 = 0xA00000A8;
enum FMC_PATT2 = 0xA000006C;
enum FMC_PATT3 = 0xA000008C;
enum FMC_PATT4 = 0xA00000AC;
enum FMC_PIO4  = 0xA00000B0;
enum FMC_ECCR2 = 0xA0000074;
enum FMC_ECCR3 = 0xA0000094;
enum FMC_SDCR_1= 0xA0000140;
enum FMC_SDCR_2= 0xA0000144;
enum FMC_SDTR1 = 0xA0000148;
enum FMC_SDTR2 = 0xA000014C;
enum FMC_SDCMR = 0xA0000150;
enum FMC_SDRTR = 0xA0000154;
enum FMC_SDSR  = 0xA0000158;

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
    uint[size_t] peripherals = [
        0x40012000: 0,          // ADC1_SR
                                // Bit 5 OVR: Overrun
                                // This bit is set by hardware when data are lost (either 
                                // in single mode or in dual/triple mode). It
                                // is cleared by software. Overrun detection is enabled only 
                                // when DMA = 1 or EOCS = 1.
                                //      0: No overrun occurred
                                //      1: Overrun has occurred
                                // Bit 4 STRT: Regular channel start flag
                                // This bit is set by hardware when regular channel conversion 
                                // starts. It is cleared by software.
                                //      0: No regular channel conversion started
                                //      1: Regular channel conversion has started
                                // Bit 3 JSTRT: Injected channel start flag
                                // This bit is set by hardware when injected group conversion 
                                // starts. It is cleared by software.
                                //      0: No injected group conversion started
                                //      1: Injected group conversion has started
                                // Bit 2 JEOC: Injected channel end of conversion
                                // This bit is set by hardware at the end of the conversion 
                                // of all injected channels in the group.
                                // It is cleared by software.
                                //      0: Conversion is not complete
                                //      1: Conversion complete
                                // Bit 1 EOC: Regular channel end of conversion
                                // This bit is set by hardware at the end of the conversion 
                                // of a regular group of channels. It is
                                // cleared by software or by reading the ADC_DR register.
                                //      0: Conversion not complete (EOCS = 1), or sequence 
                                //         of conversions not complete
                                //         (EOCS = 0)
                                //      1: Conversion complete (EOCS = 1), or sequence of 
                                //         conversions complete (EOCS = 0)
        0x40012008: 0,          // ADC1 control register 2 (ADC1_CR2)
                                // Bit 30 SWSTART: Start conversion of regular channels
                                // This bit is set by software to start conversion and cleared 
                                // by hardware as soon as the conversion starts.
                                //      0: Reset state
                                //      1: Starts conversion of regular channels
                                // Note: This bit can be set only when ADON = 1 otherwise no 
                                // conversion is launched.
                                // Bit 1 CONT: Continuous conversion
                                // This bit is set and cleared by software. If it is set, 
                                // conversion takes place continuously until it is cleared.
                                //      0: Single conversion mode
                                //      1: Continuous conversion mode
        0x400120DC: 0,          // ADC1 regular data register (ADC1_DR)
                                // Bits 15:0 DATA[15:0]: Regular data
                                // These bits are read-only. They contain the conversion result 
                                // from the regular channels.
        0x40005400: 0,          // I2C1 control register 1 (I2C1_CR1)   
                                // Bit 19 GCEN: General call enable
                                //      0: General call disabled. 
                                //         Address 0b00000000 is NACKed.
                                //      1: General call enabled. 
                                //         Address 0b00000000 is ACKed.                     
                                // Bit 17 NOSTRETCH: Clock stretching disable
                                // This bit is used to disable clock stretching in slave mode. 
                                // It must be kept cleared in master mode.
                                //      0: Clock stretching enabled
                                //      1: Clock stretching disabled
                                // Note: This bit can be programmed only when the I2C peripheral 
                                // is disabled (PE = 0)
                                // Bit 12 ANFOFF: Analog noise filter OFF
                                //      0: Analog noise filter enabled
                                //      1: Analog noise filter disabled
                                // Note: This bit can be programmed only when the I2C peripheral 
                                // is disabled (PE = 0).
        0x40005404: 0,          // I2C control register 2 (I2C_CR2)
                                // Bit 26 PECBYTE: Packet error checking byte
                                // This bit is set by software, and cleared by hardware when 
                                // the PEC is transferred, or when a STOP condition or an 
                                // Address matched is received, also when PE = 0.
                                //      0: No PEC transfer
                                //      1: PEC transmission/reception is requested
                                // Note: Writing 0 to this bit has no effect.
                                // This bit has no effect when RELOAD is set, and in slave mode 
                                // when SBC = 0.
        0x40007000: 0x0000C000, // PWR_CR
        

        0x4000780C: 0,          // reserved
        0x40007810: 0,          // reserved
        0x40007814: 0,          // reserved
        0x40013818: 0,
        // -------------------------------------- TIM2 ------------------------------------------
        0x40000000: 0,          // TIM2_CR1 TIM2 Control Register 1
        0x40000004: 0,          // TIM2_CR2 TIM2 Control Register 2
        0x40000008: 0,          // TIM2_SMCR TIM2 Slave Mode Control Register
        // -------------------------------------- EXTI ------------------------------------------
        0x40013C00: 0,          // EXTI_IMR
        0x40013C04: 0,          // EXTI_EMR
        0x40013C08: 0,          // EXTI_RTSR
        0x40013C0C: 0,          // EXIT_FTSR
        0x40013C10: 0,          // EXTI_SWIER
        0x40013C14: 0,          // EXTI_PR
        // -------------------------------------- FLASH -----------------------------------------
        0x40023C00: 0,          // FLASH_ACR 
                                // The Flash access control register is used to enable/disable 
                                // the acceleration features and control the flash memory access 
                                // time according to CPU frequency.
                                // Bit 11 ARTRST: ART Accelerator reset
                                //  0: ART Accelerator is not reset
                                //  1: ART Accelerator is reset
                                // Bit 9 ARTEN: ART Accelerator Enable
                                //  0: ART Accelerator is disabled
                                //  1: ART Accelerator is enabled
                                // Bit 8 PRFTEN: Prefetch enable
                                //  0: Prefetch is disabled
                                //  1: Prefetch is enabled
                                // Bits 3:0 LATENCY[3:0]: Latency
                                // These bits represent the ratio of the CPU clock period to the 
                                // flash memory access time.
                                //      0000: Zero wait state
                                //      0001: One wait state
                                //      0010: Two wait states
                                //      -
                                //      -
                                //      -
                                //      1110: Fourteen wait states
                                //      1111: Fifteen wait states
        // -------------------------------------- USART6 ----------------------------------------
        0x40011400: 0xC0,       // USART6_SR
        USART6_DR: 0,
        0x40011408: 0,          // USART6_BRR
        0x4001140C: 0,          // USART6_CR1
        0x40011410: 0,          // USART6_CR2
        0x40011414: 0,          // USART6_CR3
        0x40011418: 0,          // USART6_GTPR
        // --------------------------------------------------------------------------------------
        0x40013814: 0,
        0x40013C08: 0,          // SYSCFG_EXTICR1
        0x40013C0C: 0,          // SYSCFG_EXTICR2
        0x40013C10: 0,          // SYSCFG_EXTICR3
        0x40013C14: 0,          // SYSCFG_EXTICR4
        // --------------------------------------- RCC ------------------------------------------
        // There are three types of reset, defined as system Reset, power Reset and backup 
        // domain Reset.
        RCC_CR:         0x23333083,  RCC_PLLCFGR:    0x24003010,   RCC_AHB1LPENR: 0x7EF7B7FF, 
        RCC_AHB1LPENR:  0x7EF7B7FF,  RCC_CSR:        0x0E000000, 
        RCC_PLLI2SCFGR: 0x20003000,  RCC_PLLSAICFGR: 0x24003000, 
        RCC_CFGR:                0,  RCC_CIR:                 0,        
        RCC_AHB1RSTR:            0,  RCC_AHB2RSTR:            0,   RCC_AHB3RSTR:           0,         
        RCC_APB2RSTR:            0,  
        RCC_AHB1ENR:             0,  RCC_AHB2ENR:             0,   RCC_AHB3ENR:            0,
        RCC_APB1ENR:             0,  RCC_APB2ENR:             0,
        RCC_AHB1LPENR:           0,  RCC_AHB2LPENR:           0,   RCC_AHB3LPENR:          0, 
        RCC_APB1LPENR:           0,  RCC_APB2LPENR:           0,  
        RCC_BDCR:                0,  RCC_CSR:                 0,   RCC_SSCGR:              0, 
        RCC_DCKCFGR:             0, 
        // --------------------------------------------------------------------------------------
        0x40011000: 0xC0,       // USART1_SR
        USART1_DR: 0,         
        0x40011008: 0,          // USART1_BRR
        0x4001100C: 0,          // USART1_CR1
        0x40011010: 0,          // USART1_CR2
        0x40011014: 0,          // USART1_CR3
        0x40011018: 0,          // USART1_GPTR
        // -------------------------------------- USART3 ----------------------------------------
        0x40004800: 0xC0,       // USART3_SR
        USART3_DR: 0,         
        0x40004808: 0,          // USART3_BRR
        0x4000480C: 0,          // USART3_CR1
        0x40004810: 0,          // USART3_CR2
        0x40004814: 0,          // USART3_CR3
        0x40004818: 0,          // USART3_GPTR
        // -------------------------------------- GPIOA -----------------------------------------
        0x40020000: 0,          // GPIOA_MODER
        0x40020004: 0,          // GPIOA_OTYPER
        0x40020008: 0,          // GPIOA_OSPEEDR
        0x4002000C: 0,          // GPIOA_PUPDR
        0x40020010: 0,          // GPIOA_IDR
        0x40020014: 0,          // GPIOA_ODR
        0x40020020: 0,          // GPIOA_AFRL
        0x40020024: 0,          // GPIOA_AFRH
        // -------------------------------------- GPIOB -----------------------------------------
        0x40020400: 0,          // GPIOB_MODER
        0x40020404: 0,          // GPIOB_OTYPER
        0x40020408: 0,          // GPIOB_OSPEEDR
        0x4002040C: 0,          // GPIOB_PUPDR
        0x40020410: 0,          // GPIOB_IDR
        0x40020414: 0,          // GPIOB_ODR
        0x40020420: 0,          // GPIOB_AFRL
        0x40020424: 0,          // GPIOB_AFRH
        // -------------------------------------- GPIOC -----------------------------------------
        0x40020800: 0,          // GPIOC_MODER
        0x40020804: 0,          // GPIOC_OTYPER
        0x40020808: 0,          // GPIOC_OSPEEDR
        0x4002080C: 0,          // GPIOC_PUPDR
        0x40020810: 0,          // GPIOC_IDR
        0x40020814: 0,          // GPIOC_ODR
        0x40020820: 0,          // GPIOC_AFRL
        0x40020824: 0,          // GPIOC_AFRH
        // -------------------------------------- GPIOD -----------------------------------------
        0x40020C00: 0,          // GPIOD_MODER
        0x40020C04: 0,          // GPIOD_OTYPER
        0x40020C08: 0,          // GPIOD_OSPEEDR
        0x40020C0C: 0,          // GPIOD_PUPDR
        0x40020C10: 0,          // GPIOD_IDR
        0x40020C14: 0,          // GPIOD_ODR
        0x40020C20: 0,          // GPIOD_AFRL
        0x40020C24: 0,          // GPIOD_AFRH
        // -------------------------------------- GPIOE -----------------------------------------
        0x40021000: 0,          // GPIOE_MODER
        0x40021004: 0,          // GPIOE_OTYPER
        0x40021008: 0,          // GPIOE_OSPEEDR
        0x4002100C: 0,          // GPIOE_PUPDR
        0x40021010: 0,          // GPIOE_IDR
        0x40021014: 0,          // GPIOE_ODR
        0x40021020: 0,          // GPIOE_AFRL
        0x40021024: 0,          // GPIOE_AFRH
        // -------------------------------------- GPIOF -----------------------------------------
        0x40021400: 0,          // GPIOF_MODER
        0x40021404: 0,          // GPIOF_OTYPER
        0x40021408: 0,          // GPIOF_OSPEEDR
        0x4002140C: 0,          // GPIOF_PUPDR
        0x40021410: 0,          // GPIOF_IDR
        0x40021414: 0,          // GPIOF_ODR
        0x40021420: 0,          // GPIOF_AFRL
        0x40021424: 0,          // GPIOF_AFRH
        // -------------------------------------- GPIOG -----------------------------------------
        0x40021800: 0,          // GPIOG_MODER
        0x40021804: 0,          // GPIOG_OTYPER
        0x40021808: 0,          // GPIOG_OSPEEDR
        0x4002180C: 0,          // GPIOG_PUPDR
        0x40021810: 0,          // GPIOG_IDR
        0x40021814: 0,          // GPIOG_ODR
        0x40021820: 0,          // GPIOG_AFRL
        0x40021824: 0,          // GPIOG_AFRH
        // -------------------------------------- GPIOH -----------------------------------------
        0x40021C00: 0,          // GPIOH_MODER
        0x40021C04: 0,          // GPIOH_OTYPER
        0x40021C08: 0,          // GPIOH_OSPEEDR
        0x40021C0C: 0,          // GPIOH_PUPDR
        0x40021C10: 0,          // GPIOH_IDR
        0x40021C14: 0,          // GPIOH_ODR
        0x40021C20: 0,          // GPIOH_AFRL
        0x40021C24: 0,          // GPIOH_AFRH
        // -------------------------------------- GPIOI -----------------------------------------
        0x40022000: 0,          // GPIOI_MODER
        0x40022004: 0,          // GPIOI_OTYPER
        0x40022008: 0,          // GPIOI_OSPEEDR
        0x4002200C: 0,          // GPIOI_PUPDR
        0x40022010: 0,          // GPIOI_IDR
        0x40022014: 0,          // GPIOI_ODR
        0x40022020: 0,          // GPIOI_AFRL
        0x40022024: 0,          // GPIOI_AFRH
        // -------------------------------------- GPIOJ -----------------------------------------
        0x40022400: 0,          // GPIOJ_MODER
        0x40022404: 0,          // GPIOJ_OTYPER
        0x40022408: 0,          // GPIOJ_OSPEEDR
        0x4002240C: 0,          // GPIOJ_PUPDR
        0x40022410: 0,          // GPIOJ_IDR
        0x40022414: 0,          // GPIOJ_ODR
        0x40022420: 0,          // GPIOJ_AFRL
        0x40022424: 0,          // GPIOJ_AFRH
        // -------------------------------------- GPIOK -----------------------------------------
        0x40022800: 0,          // GPIOK_MODER
        0x40022804: 0,          // GPIOK_OTYPER
        0x40022808: 0,          // GPIOK_OSPEEDR
        0x4002280C: 0,          // GPIOK_PUPDR
        0x40022810: 0,          // GPIOK_IDR
        0x40022814: 0,          // GPIOK_ODR
        0x40022820: 0,          // GPIOK_AFRL
        0x40022824: 0,          // GPIOK_AFRH
        // --------------------------------------------------------------------------------------
        // TIM6
        0x40001000: 0,          // TIM6_CR1   
        0x40001004: 0,          // TIM6_CR2
        0x40001008: 0,          
        0x4000100C: 0,          // TIM6_DIER
        0x40001010: 0,          // TIM6_SR
        0x40001014: 0,          // TIM6_EGR
        0x40001018: 0,          
        0x4000101C: 0,
        0x40001020: 0, 
        0x40001024: 0,          // TIM6_CNT
        0x40001028: 0,          // TIM6_PSC
        0x4000102C: 0,          // TIM6_ARR
        0x40001030: 0, 
        0x40001034: 0, 
        0x40001038: 0, 
        0x4000103C: 0,
        0x40001040: 0, 
        0x40001044: 0,
        0x4000440C: 0,
        0x40023820: 0,
        0x40004410: 0,
        0x40004414: 0,

        0x40000C00: 0,
        0x40000C00: 0,
        0x40000C04: 0,
        0x40000C08: 0,
        0x40000C0C: 0,
        0x40000C10: 0,
        0x40000C14: 0,
        0x40000C18: 0,
        0x40000C1C: 0,
        0x40000C20: 0,
        0x40000C24: 0,
        0x40000C28: 0,
        0x40000C2C: 0,
        0x40000C30: 0,
        0x40000C34: 0,
        0x40000C38: 0,
        0x40000C3C: 0,
        0x40000C40: 0,
        0x40000C44: 0,
        0x40000C48: 0,
        0x40000C4C: 0,
        0x40000C50: 0,
        // --------------------------------------------------------------------------------------
        0x40004400: 0xC0, // USART2_SR
        // Reset value: 0x000C000C0
        // Bit 7 TXE: Transmit data register empty
        // This bit is set by hardware when the content of the TDR register has been transferred 
        // into the shift register. An interrupt is generated if the TXEIE bit =1 in the 
        // USART_CR1 register. It is cleared by a write to the USART_DR register.
        //  0: Data is not transferred to the shift register
        //  1: Data is transferred to the shift register)
        // Note: This bit is used during single buffer transmission.
        // Bit 6 TC: Transmission complete
        // This bit is set by hardware if the transmission of a frame containing data is 
        // complete and if TXE is set. An interrupt is generated if TCIE=1 in the USART_CR1 
        // register. It is cleared by a software sequence (a read from the USART_SR register 
        // followed by a write to the USART_DR register). The TC bit can also be cleared by 
        // writing a '0' to it. This clearing sequence is recommended only for multibuffer 
        // communication.
        //  0: Transmission is not complete
        //  1: Transmission is complete
        USART2_DR: 0,  // USART2_DR
        0x40004408: 0,  // USART2_BRR
        // Bits 15:4 DIV_Mantissa[11:0]: mantissa of USARTDIV
        //  These 12 bits define the mantissa of the USART Divider (USARTDIV)
        0x40004414: 0,  // USART2_CR3
        // Bit 11 ONEBIT: One sample bit method enable
        // This bit allows the user to select the sample method. When the one sample bit 
        // method is selected the noise detection flag (NF) is disabled.
        //  0: Three sample bit method
        //  1: One sample bit method
        // Note: The ONEBIT feature applies only to data bits. It does not apply to 
        // START bit.
        0x40026410: 0,
        0x40026424: 0,
        0x40012300: 0,
        0x40012304: 0,
        0x40012004: 0,
        0x40012008: 0,
        0x4001202C: 0,
        0x40012010: 0,
        0x40012034: 0,
        0x40026088: 0,
        0x4002609C: 0,
        0x40007400: 0,
        0x40026400: 0,      // DMA2_LISR
                            // Bits 27, 21, 11, 5 TCIF[3:0]: 
                            // Stream x transfer complete interrupt flag (x = 3 to 0)
                            // This bit is set by hardware. It is cleared by software writing 1 
                            // to the corresponding bit in DMA_LIFCR register.
                            //      0: No transfer complete event on stream x
                            //      1: A transfer complete event occurred on stream x.
        OTG_GOTGCTL: 0x10000, 
        FMC_BCR1:   0,  FMC_BCR2:   0,  FMC_BCR3:  0,  FMC_BCR4:  0,    
        FMC_BTR1:   0,  FMC_BTR2:   0,  FMC_BTR3:  0,  FMC_BTR4:  0,    
        FMC_BWTR1:  0,  FMC_BWTR2:  0,  FMC_BWTR3: 0,  FMC_BWTR4: 0,  
        FMC_PCR2:   0,  FMC_PCR3:   0,  FMC_PCR4:  0,   
        FMC_SR2:    0,  FMC_SR3:    0,  FMC_SR4:   0,   
        FMC_PMEM2:  0,  FMC_PMEM3:  0,  FMC_PMEM4: 0,   
        FMC_PATT2:  0,  FMC_PATT3:  0,  FMC_PATT4: 0,   
        FMC_PIO4 :  0,   
        FMC_ECCR2:  0,  FMC_ECCR3:  0,   
        FMC_SDCR_1: 0,  FMC_SDCR_2: 0,  
        FMC_SDTR1:  0,  FMC_SDTR2:  0,   
        FMC_SDCMR:  0,   
        FMC_SDRTR:  0,   
        FMC_SDSR:   0,    
    ];

    void set_vtor() {
        scb[VTOR] = 0x8000000;
    }

    string get_reg_name(const uint reg_addr) {
        auto s = get_scb_reg_name(reg_addr);
        if (s != "") return s;
        return stm32f4_peripheral_names.get(reg_addr, "");
    }

    uint read_word(size_t addr) {
        if (addr == 0x40023800) {
            flip_bit(0x40023800, 25);
            flip_bit(0x40023800, 27);
        }
        if (addr == 0x40023874)
            flip_bit(0x40023874, 1);
        uint res;
        if (addr >= scb_base) {
            if (cast(scb_reg)addr in scb) {
                res = scb[cast(scb_reg)addr];              
            } else {
                throw new Exception("Invalid access");            
            }
            if (addr == SYST_CSR) {
                scb[SYST_CSR] &= ~0x00010000;
            }
        } else if (addr >= sram_1_origin + sram_1_length) {
            if (auto p = addr in peripherals) {
                res = *p;              
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
            uint val = peripherals[addr];
            val ^= (1u << bit_pos);
            peripherals[addr] = val;
        }
    }

    const(ushort) read_half_word(size_t addr) {
        if (addr >= ram_origin) {
            return ram.read_half_word(addr);
        } else {
            return flash.read_half_word(addr);
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
        if (addr > scb_base) {
            if (addr == 0xE000E400) {
                return 0xf0;
            }
            return read_byte_from_word(scb, addr);
        } else if (addr >= ram_origin + ram_length) {
            return read_byte_from_word(peripherals, addr);
        } 
        if (addr >= ram_origin) {
            return ram.read_byte(addr);
        } else {
            return flash.read_byte(addr);
        }
    }

    void write_word(size_t addr, uint val) {
        if (addr >= scb_base) {
            if (cast(scb_reg)addr in scb) {
                scb[cast(scb_reg)addr] = val;   
                if (addr == SYST_CVR) {
                    scb[SYST_CSR] &= ~0x00010000;
                }
                return;           
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= sram_1_origin + sram_1_length) {
            if (addr == 0x40023808) {
                uint cfgr = peripherals[addr];
                cfgr = val;
                uint sw = val & 0x3;
                cfgr &= ~(0x3 << 2);
                cfgr |= (sw << 2);
                peripherals[addr] = cfgr;
            } else if (addr == 0x40023874 && val == 0x1) {
                peripherals[addr] = 0x3;
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
                peripherals[addr] = val;
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
        const ubyte b = cast(ubyte)(val & 0xff);
        if (addr >= scb_base) {
            write_byte_to_word(scb, addr, b);
        } else if (addr >= ram_origin + ram_length) {
            write_byte_to_word(peripherals, addr, b);
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
        auto s = get_scb_reg_name(reg_addr);
        if (s != "") return s;
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
            if (cast(scb_reg)addr in scb) {
                res = scb[cast(scb_reg)addr];              
            } else {
                throw new Exception("Invalid access");            
            }
            if (addr == SYST_CSR) {
                scb[SYST_CSR] &= ~0x00010000;
            }
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
        if (addr >= ram_origin) {
            return ram.read_half_word(addr);
        } else {
            return flash.read_half_word(addr);
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

    void write_word(size_t addr, uint val) {
        if (addr >= scb_base) {
            if (cast(scb_reg)addr in scb) {
                scb[cast(scb_reg)addr] = val;  
                if (addr == SYST_CVR) {
                    scb[SYST_CSR] &= ~0x00010000;
                }
                return;            
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= ram_origin + ram_length) {
            nrf52_peripheral_regs[cast(nrf52_peripheral_reg)addr] = val;
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
        const ubyte b = cast(ubyte)(val & 0xff);
        if (addr >= scb_base) {
            write_byte_to_word(scb, addr, b);
        } else if (addr >= ram_origin + ram_length) {
            write_byte_to_word(nrf52_peripheral_regs, addr, b);
        } else if (addr >= ram_origin) {
            ram.write_byte(addr, b);
        } else {
            flash.write_byte(addr, b);
        }
    }
}

struct FRDM_RW612 {
    enum flash_origin = 0x18000000;
    mem_section!(256, flash_origin) flash;
}