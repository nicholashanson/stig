import std.algorithm;
import std.stdio;
import std.format;

import log;
import cortex_m_core;

// --------------------------------------------------------------------------------------
// ====================
//  WRITE BYTE TO WORD
// ====================
void write_byte_to_word(ref uint[size_t] mem_block, const size_t addr, const ubyte b) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr &  3) * 8;
    const uint   old       =  mem_block[word_addr];
    const uint   masked    = (old & ~(0xff << shift)) | (b << shift);
    mem_block[word_addr] = masked;
}

// =====================
//  READ BYTE FROM WORD
// =====================
ubyte read_byte_from_word(ref uint[size_t] mem_block, size_t addr) {
    const size_t word_addr =  addr & ~3;
    const uint   shift     = (addr & 3) * 8;
    const uint   val       = mem_block[word_addr];
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
enum ise_base     = 0xE000E100;
enum ise_top      = 0xE000E13C;
enum ice_base     = 0xE000E180;
enum ice_top      = 0xE000E1BC;
enum isp_base     = 0xE000E200;
enum isp_top      = 0xE000E23C;
enum icpr_base    = 0xE000E280;
enum icpr_top     = 0xE000E2BC;
enum iab_base     = 0xE000E300;
enum iab_top      = 0xE000E33C;
enum ipr_base     = 0xE000E400;
enum ipr_top      = 0xE000E5EC;
// --------------------------------------------------------------------------------------
// =====================================
//  SYSTEM CONTROL BLOCK REGISTER NAMES
// =====================================

immutable string[size_t] scb_reg_names = [
    0xE000E010:   "SYST_CSR",
    0xE000E014:   "SYST_RVR",       
    0xE000E018:   "SYST_CVR",       
    0xE000E01C: "SYST_CALIB",
    0xE000ED04:       "ICSR", 
    0xE000ED08:       "VTOR",
    0xE000ED10:        "SCR",
    0xE000ED14:        "CCR",
    0xE000ED18:      "SHPR1",
    0xE000ED1C:      "SHPR2", 
    0xE000ED20:      "SHPR3",
    0xE000ED24:      "SHCSR",
    0xE000ED28:       "CFSR",
    0xE000ED2C:       "HFSR",
    0xE000ED88:      "CPACR",
    0xE000ED90:   "MPU_TYPE"
];
// --------------------------------------------------------------------------------------
// ========================================
//  GET SYSTEM CONTROL BLOCK REGISTER NAME
// ========================================

string get_scb_reg_name(const uint reg_addr) { 
    if (reg_addr >= ipr_base && reg_addr <= ipr_top) {
        return format("NVIC_IPR%d", (reg_addr - ipr_base)  / 4);
    } 
    if (reg_addr >= ise_base && reg_addr <= ise_top) {
        return format("NVIC_ISER%d", (reg_addr - ise_base) / 4);
    }
    if (reg_addr >= ice_base && reg_addr <= ice_top) {
        return format("NVIC_ICER%d", (reg_addr - ice_base) / 4);
    }  
    if (reg_addr >= isp_base && reg_addr <= isp_top) {
        return format("NVIC_ISPR%d", (reg_addr - isp_base) / 4);
    }
    return scb_reg_names.get(reg_addr, "");;
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
uint[size_t] scb = [
    // NVIC
    0xE000E3FC: 0,
    0xE000ED00: 0,
    0xE000ED04: 0,          // Interrupt Control and State Register, ICSR
                            // Provides software control of the NMI, PendSV, and SysTick 
                            // exceptions, and provides interrupt status information.
                            // [28] RW PENDSVSET On writes, sets the PendSV exception as 
                            // pending. 
                            // On reads, indicates thecurrent state of the exception:
                            //      0 = On writes, has no effect. On reads, PendSV is not 
                            //          pending.
                            //      1 = On writes, make PendSV exception pending. On reads, 
                            //          PendSV is pending.
                            // Normally, software writes 1 to this bit to request a context 
                            // switch.
    0xE000ED14: 0,          // CCR(RW) 0x00000000
                            // Configuration and Control Register
                            // [9] STKALIGN Determines whether the exception entry sequence 
                            // guarantees 8-byte stack frame alignment, adjusting the SP if 
                            // necessary before saving state:
                            //      0 = Guaranteed SP alignment is 4-byte, no SP adjustment 
                            //          is performed.
                            //      1 = 8-byte alignment guaranteed, SP adjusted if 
                            //          necessary
                            // [4] DIV_0_TRP Controls the trap on divide by 0:
                            //      0 = Trapping disabled.
                            //      1 = Trapping enabled.
    0xE000ED20: 0,          // System Handler Priority Register 3, SHPR3
                            // [31:24] PRI_15 Priority of system handler 15, SysTick
                            // [23:16] PRI_14 Priority of system handler 14, PendSV
                            // [15:8] PRI_13 Reserved for priority of system handler 13
                            // [7:0] PRI_12 Priority of system handler 12, DebugMonitor
    0xE000ED18: 0,          // System Handler Priority Register 1
    0xE000ED1C: 0,
    0xE000ED24: 0,          // System Handler Control and State Register
                            // Controls and provides the active and pending status of system 
                            // exceptions.
                            // [18] USGFAULTENA 0 = Disable UsageFault.
                            //                  1 = Enable UsageFault.
                            // [17] BUSFAULTENA 0 = Disable BusFault.
                            //                  1 = Enable BusFault.
                            // [16] MEMFAULTENA 0 = Disable MemManage fault.
                            //                  1 = Enable MemManage fault.
    // --------------------------------------- MPU ------------------------------------------
    0xE000ED90: 0x00000800, // MPU_TYPE(RO): reset value for Cortex M-4
    0xE000ED94: 0,          // MPU_CTRL(RW)
                            // Enables the MPU, and when the MPU is enabled, controls whether the 
                            // default memory map is enabled as a background region for privileged 
                            // accesses, and whether the MPU is enabled for HardFaults, NMIs, and 
                            // exception handlers when FAULTMASK is set to 1.
                            // [2] PRIVDEFENA, [1] HFNMIENA, [0] ENABLE
                            // PRIVDEFENA: 0 disables the default mewidthmory map. Any instruction
                            //             or data access that does not access a defined region
                            //             faults
                            //             1 enables the default memory map as a background region
                            //             for privileged access
                            // HFNMIENA: when the ENABLE bit is set to 1, controls whether handlers 
                            //           executing with priority less than 0 access memory with the 
                            //           MPU enabled or with the MPU disabled
    0xE000ED98: 0,          // MPU_RNR(RW) MPU Region Number Register
                            // selects the region currently accessed by MPU_RBAR and MPU_RASR
                            // [7:0] REGION
    0xE000ED9C: 0,          // MPU_RBAR(RW) MPU Region Base Address Register
                            // [31:5] ADDR, [4] VALID, [3:0] REGION
                            // ADDR:   Base address of the region
                            // VALID:  On writes, indicates whether the region to update is 
                            //         specified by  MPU_RNR.REGION, or by the REGION value 
                            //         specified in this write. 
                            //         When using the REGION value specified by this write, 
                            //         MPU_RNR.REGION is updated to this value
                            // REGION: on writes, can specify the number of the region to 
                            //         update
    0xE000EDA0: 0,          // MPU_RASR(RW) MPU Region Attribute and Size Register
    // --------------------------------------------------------------------------------------  
    
    // ------------------------------------- NVIC ABR ---------------------------------------  
    0xE000E300: 0,
    0xE000E304: 0,
    0xE000E308: 0,
    0xE000E30C: 0,
    0xE000E310: 0,
    0xE000E314: 0,
    0xE000E318: 0,
    0xE000E31C: 0,
    0xE000E320: 0,
    0xE000E324: 0,
    0xE000E328: 0,
    0xE000E32C: 0,
    0xE000E330: 0,
    0xE000E334: 0,
    0xE000E338: 0,
    0xE000E33C: 0,
    // ------------------------------------- NVIC ISR ---------------------------------------                        
    0xE000E400: 0,
    0xE000E100: 0,
    0xE000E104: 0,
    0xE000E108: 0,
    0xE000E10C: 0,
    0xE000E110: 0,
    0xE000E114: 0,
    0xE000E118: 0,
    0xE000E11C: 0,
    0xE000E120: 0,
    0xE000E124: 0,
    0xE000E128: 0,
    0xE000E12C: 0,
    0xE000E130: 0,
    0xE000E134: 0,
    0xE000E138: 0,
    0xE000E13C: 0,
    // ------------------------------------- NVIC ISP ---------------------------------------
    0xE000E200: 0,
    0xE000E204: 0,
    0xE000E208: 0,
    0xE000E20C: 0,
    0xE000E210: 0,
    0xE000E214: 0,
    0xE000E218: 0,
    0xE000E21C: 0,
    0xE000E220: 0,
    0xE000E224: 0,
    0xE000E228: 0,
    0xE000E22C: 0,
    0xE000E230: 0,
    0xE000E234: 0,
    0xE000E238: 0,
    0xE000E23C: 0,
    // ------------------------------------- NVIC ICPR --------------------------------------   
    0xE000E280: 0,
    0xE000E284: 0,
    0xE000E288: 0,
    0xE000E28C: 0,
    0xE000E290: 0,
    0xE000E294: 0,
    0xE000E298: 0,
    0xE000E29C: 0,
    0xE000E2A0: 0,
    0xE000E2A4: 0,
    0xE000E2A8: 0,
    0xE000E2AC: 0,
    0xE000E2B0: 0,
    0xE000E2B4: 0,
    0xE000E2B8: 0,
    0xE000E2BC: 0,
    // ------------------------------------- NVIC IPR ---------------------------------------                        
    0xE000E400: 0,
    0xE000E404: 0,
    0xE000E408: 0,
    0xE000E40C: 0,
    0xE000E410: 0,
    0xE000E414: 0,
    0xE000E418: 0,
    0xE000E41C: 0,
    0xE000E420: 0,
    0xE000E424: 0,
    0xE000E428: 0,
    0xE000E42C: 0,
    0xE000E430: 0,
    0xE000E434: 0,
    0xE000E438: 0,
    0xE000E43C: 0,
    0xE000E440: 0,
    0xE000E444: 0,
    0xE000E448: 0,
    0xE000E44C: 0,
    0xE000E450: 0,
    0xE000E454: 0,
    0xE000E458: 0,
    0xE000E45C: 0,
    0xE000E460: 0,
    0xE000E464: 0,
    // --------------------------------------------------------------------------------------
    0xE000E3F8: 0,
    0xE000EF34: 0,
    // --------------------------------------- SCB ------------------------------------------
    0xE000ED08: 0,          // VTOR(RW) Vector Table Offset Register
    0xE000ED0C: 0xFA050000, // AIRCR(RW) Application Interrupt and Reset Control Register 
    0xE000ED10: 0,          // SCR(RW) 0x00000000 
                            // [4] SEVONPEND Determines whether an interrupt transition from 
                            // inactive state to pending state is a wakeup event:
                            //  0 = Transitions from inactive to pending are not wakeup 
                            //      events.
                            //  1 = Transitions from inactive to pending are wakeup events.
                            // [2] SLEEPDEEP Provides a qualifying hint indicating that 
                            // waking from sleep might take longer. An implementation can use 
                            // this bit to select between two alternative sleep states:
                            //  0 = Selected sleep state is not deep sleep.
                            //  1 = Selected sleep state is deep sleep
                            // [1] SLEEPONEXIT Determines whether, on an exit from an ISR 
                            // that returns to the base level of execution the processor 
                            // enters a sleep state:
                            //  0 = Do not enter sleep state.
                            //  1 = Enter sleep state.
    0xE000ED28: 0,          // CFSR(RW) 0x00000000
                            // Write a one to a register bit to clear the corresponding fault.
                            // [31:16] UsageFault Provides information on UsageFault exceptions
                            // [15:8] BusFault Provides information on BusFault exceptions
                            // [7:0] MemManage Provides information on MemManage exceptions
    0xE000ED2C: 0,          // HFSR(RW) 0x00000000
                            // Write a one to a register bit to clear the corresponding fault.
    // --------------------------------------------------------------------------------------
    // ------------------------------------- SysTick ----------------------------------------
    0xE000E010: 0,          // SYST_CSR(RW) SysTick Control and Status Register
    0xE000E014: 0,          // SYST_RVR(RW) SysTick Reload Value Register
    0xE000E018: 0,          // SYST_CVR(RW) SysTick Current Value Register
    0xE000E01C: 0,          // SYST_CALIB(RW) SysTick Calibration Value Register
    // --------------------------------------------------------------------------------------
    0xE000ED88: 0,          // SCB_CPACR/CPACR(RW)
                            // Coprocessor Access Control Register
                            // Specifies the access privileges for coprocessors.
    0xE000E018: 0,
    0xE0042004: 0           // DBGMCU_CR Debug MCU Configuration Register
];
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
        // --------------------------------------------------------------------------------------
        // -------------------------------------- EXTI ------------------------------------------
        0x40013C00: 0,          // EXTI_IMR
        0x40013C04: 0,          // EXTI_EMR
        0x40013C08: 0,          // EXTI_RTSR
        0x40013C0C: 0,          // EXIT_FTSR
        0x40013C10: 0,          // EXTI_SWIER
        0x40013C14: 0,          // EXTI_PR
        // --------------------------------------------------------------------------------------
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
        // --------------------------------------------------------------------------------------
        // -------------------------------------- USART6 ----------------------------------------
        0x40011400: 0xC0,       // USART_SR
        0x40011404: 0,          // USART_DR
        0x40011408: 0,          // USART_BRR
        0x4001140C: 0,          // USART_CR1
        0x40011410: 0,          // USART_CR2
        0x40011414: 0,          // USART_CR3
        0x40011418: 0,          // USART_GTPR
        // --------------------------------------------------------------------------------------
        0x40013814: 0,
        0x40013C08: 0,          // SYSCFG_EXTICR1
        0x40013C0C: 0,          // SYSCFG_EXTICR2
        0x40013C10: 0,          // SYSCFG_EXTICR3
        0x40013C14: 0,          // SYSCFG_EXTICR4
        0x40023808: 0,          // RCC_CFGR
                                // Bits 15:13 PPRE2: APB high-speed prescaler (APB2)
                                // Set and cleared by software to control APB high-speed clock 
                                // division factor.
                                // Caution: The software has to set these bits correctly not 
                                // to exceed 90 MHz on this domain.
                                // The clocks are divided with the new prescaler factor from 1 
                                // to 16 AHB cycles after PPRE2 write.
                                //      0xx: AHB clock not divided
                                //      100: AHB clock divided by 2
                                //      101: AHB clock divided by 4
                                //      110: AHB clock divided by 8
                                //      111: AHB clock divided by 16
                                // Bits 12:10 PPRE1: APB Low-speed prescaler (APB1)
                                // Set and cleared by software to control APB low-speed clock 
                                // division factor.
                                // Caution: The software has to set these bits correctly not 
                                // to exceed 45 MHz on this domain.
                                // The clocks are divided with the new prescaler factor from 
                                // 1 to 16 AHB cycles after PPRE1 write.
                                //      0xx: AHB clock not divided
                                //      100: AHB clock divided by 2
                                //      101: AHB clock divided by 4
                                //      110: AHB clock divided by 8
                                //      111: AHB clock divided by 16
                                // Bits 3:2 SWS: System clock switch status
                                // Set and cleared by hardware to indicate which clock source is 
                                // used as the system clock.
                                //      00: HSI oscillator used as the system clock
                                //      01: HSE oscillator used as the system clock
                                //      10: PLL used as the system clock
                                //      11: not applicable
                                // Bits 1:0 SW: System clock switch
                                // Set and cleared by software to select the system clock source.
                                // Set by hardware to force the HSI selection when leaving the 
                                // Stop or Standby mode or in case of failure of the HSE 
                                // oscillator used directly or  indirectly as the system clock.
                                //      00: HSI oscillator selected as system clock
                                //      01: HSE oscillator selected as system clock
                                //      10: PLL selected as system clock
                                //      11: not allowed
        // --------------------------------------- RCC ------------------------------------------
        // There are three types of reset, defined as system Reset, power Reset and backup 
        // domain Reset.
        0x40023800: 0x03333083, // RCC_CR, Reset value: 0x0000XX83 where X is undefined.
                                // Bit 27 PLLI2SRDY: PLLI2S clock ready flag
                                // Set by hardware to indicate that the PLLI2S is locked.
                                //      0: PLLI2S unlocked
                                //      1: PLLI2S locked
                                // Bit 25 PLLRDY: Main PLL (PLL) clock ready flag
                                // Set by hardware to indicate that PLL is locked.
                                //      0: PLL unlocked
                                //      1: PLL locked
                                // Bit 1 HSIRDY: Internal high-speed clock ready flag
                                // Set by hardware to indicate that the HSI oscillator is stable. 
                                // After the HSION bit is cleared, HSIRDY goes low after 6 HSI 
                                // clock cycles.
                                //      0: HSI oscillator not ready
                                //      1: HSI oscillator ready
                                // Bit 0 HSION: Internal high-speed clock enable
                                // Set and cleared by software.
                                // Set by hardware to force the HSI oscillator ON when leaving 
                                // the Stop or Standby mode or in case of a failure of the HSE 
                                // oscillator used directly or indirectly as the system clock. 
                                // This bit cannot be cleared if the HSI is used directly or 
                                // indirectly as the system clock.
                                //      0: HSI oscillator OFF
                                //      1: HSI oscillator ON
        0x40023804: 0x24003010, // RCC_PLLCFGR
                                // Reset value: 0x2400 3010
        0x40023824: 0,          // RCC_APB2RSTR
        0x40023830: 0,          // RCC_AHB1ENR Peripheral Clock Enable Register
        0x40023840: 0,          // RCC_APB1ENR Peripheral Clock Enable Register
                                // Bit 28 PWREN: Power interface clock enable
                                // This bit is set and cleared by software.
                                //      0: Power interface clock disabled
                                //      1: Power interface clock enable
        0x40023844: 0,          // RCC_APB2ENR Peripheral Clock Enable Register
        0x40023850: 0x7EF7B7FF, // RCC_AHB1LPENR
                                // RCC AHB1 peripheral clock enable in low-power mode register
        0x40023874: 0x0E000000, // RCC_CSR
                                // RCC clock control & status register (RCC_CSR)
                                // Reset value: 0x0E00 0000, reset by system reset, except reset 
                                // Bit 1 LSIRDY: Internal low-speed oscillator ready
                                // This bit is set and cleared by hardware to indicate when the 
                                // internal RC 40 kHz oscillator is stable. After the LSION bit 
                                // is cleared, LSIRDY goes low after 3 LSI clock cycles.
                                //      0: LSI RC oscillator not ready
                                //      1: LSI RC oscillator ready
                                // flags by power reset only
                                // Bit 0 LSION: Internal low-speed oscillator enable
                                // This bit is set and cleared by software.
                                //      0: LSI RC oscillator OFF
                                //      1: LSI RC oscillator ON
        0x40023884: 0x20003000, // RCC_PLLI2SCFGR
        0x4002388C: 0,          // RCC_DCKCFGR Dedicated Clock Configuration Register
        // --------------------------------------------------------------------------------------
        // -------------------------------------- USART1 ----------------------------------------
        0x40011000: 0xC0,       // USART1_SR
        0x40011004: 0,          // USART1_DR
        0x40011008: 0,          // USART1_BRR
        0x4001100C: 0,          // USART1_CR1
        0x40011010: 0,          // USART1_CR2
        0x40011014: 0,          // USART1_CR3
        0x40011024: 0,          // USART1_GPTR
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOA -----------------------------------------
        0x40020000: 0,          // GPIOA_MODER
        0x40020004: 0,          // GPIOA_OTYPER
        0x40020008: 0,          // GPIOA_OSPEEDR
        0x4002000C: 0,          // GPIOA_PUPDR
        0x40020010: 0,          // GPIOA_IDR
        0x40020014: 0,          // GPIOA_ODR
        0x40020020: 0,          // GPIOA_AFRL
        0x40020024: 0,          // GPIOA_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOB -----------------------------------------
        0x40020400: 0,          // GPIOB_MODER
        0x40020404: 0,          // GPIOB_OTYPER
        0x40020408: 0,          // GPIOB_OSPEEDR
        0x4002040C: 0,          // GPIOB_PUPDR
        0x40020410: 0,          // GPIOB_IDR
        0x40020414: 0,          // GPIOB_ODR
        0x40020420: 0,          // GPIOB_AFRL
        0x40020424: 0,          // GPIOB_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOC -----------------------------------------
        0x40020800: 0,          // GPIOC_MODER
        0x40020804: 0,          // GPIOC_OTYPER
        0x40020808: 0,          // GPIOC_OSPEEDR
        0x4002080C: 0,          // GPIOC_PUPDR
        0x40020810: 0,          // GPIOC_IDR
        0x40020814: 0,          // GPIOC_ODR
        0x40020820: 0,          // GPIOC_AFRL
        0x40020824: 0,          // GPIOC_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOD -----------------------------------------
        0x40020C00: 0,          // GPIOD_MODER
        0x40020C04: 0,          // GPIOD_OTYPER
        0x40020C08: 0,          // GPIOD_OSPEEDR
        0x40020C0C: 0,          // GPIOD_PUPDR
        0x40020C10: 0,          // GPIOD_IDR
        0x40020C14: 0,          // GPIOD_ODR
        0x40020C20: 0,          // GPIOD_AFRL
        0x40020C24: 0,          // GPIOD_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOE -----------------------------------------
        0x40021000: 0,          // GPIOE_MODER
        0x40021004: 0,          // GPIOE_OTYPER
        0x40021008: 0,          // GPIOE_OSPEEDR
        0x4002100C: 0,          // GPIOE_PUPDR
        0x40021010: 0,          // GPIOE_IDR
        0x40021014: 0,          // GPIOE_ODR
        0x40021020: 0,          // GPIOE_AFRL
        0x40021024: 0,          // GPIOE_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOF -----------------------------------------
        0x40021400: 0,          // GPIOF_MODER
        0x40021404: 0,          // GPIOF_OTYPER
        0x40021408: 0,          // GPIOF_OSPEEDR
        0x4002140C: 0,          // GPIOF_PUPDR
        0x40021410: 0,          // GPIOF_IDR
        0x40021414: 0,          // GPIOF_ODR
        0x40021420: 0,          // GPIOF_AFRL
        0x40021424: 0,          // GPIOF_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOG -----------------------------------------
        0x40021800: 0,          // GPIOG_MODER
        0x40021804: 0,          // GPIOG_OTYPER
        0x40021808: 0,          // GPIOG_OSPEEDR
        0x4002180C: 0,          // GPIOG_PUPDR
        0x40021810: 0,          // GPIOG_IDR
        0x40021814: 0,          // GPIOG_ODR
        0x40021820: 0,          // GPIOG_AFRL
        0x40021824: 0,          // GPIOG_AFRH
        // --------------------------------------------------------------------------------------
        // -------------------------------------- GPIOH -----------------------------------------
        0x40021C00: 0,          // GPIOH_MODER
        0x40021C04: 0,          // GPIOH_OTYPER
        0x40021C08: 0,          // GPIOH_OSPEEDR
        0x40021C0C: 0,          // GPIOH_PUPDR
        0x40021C10: 0,          // GPIOH_IDR
        0x40021C14: 0,          // GPIOH_ODR
        0x40021C20: 0,          // GPIOH_AFRL
        0x40021C24: 0,          // GPIOH_AFRH
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
        0x40004404: 0,  // USART2_DR
        0x40004404: 0,  // USART2_BRR
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
        0x5000000: 0x10000, // OTG_GOTGCTL
                            // Reset value: 0x00010000
                            // Bit 21 CURMOD: Current mode of operation
                            // Indicates the current mode (host or device).
                            //      0: Device mode
                            //      1: Host mode
                            // Bit 20 OTGVER: OTG version
                            // Selects the OTG revision.
                            //      0:OTG Version 1.3. OTG1.3 is obsolete for new product development.
                            //      1:OTG Version 2.0. In this version the core supports only data 
                            //        line pulsing for SRP.
                            // Bit 17 DBCT: Long/short debounce time
                            // Indicates the debounce time of a detected connection.
                            //      0: Long debounce time, used for physical connections 
                            //         (100 ms + 2.5 μs)
                            //      1: Short debounce time, used for soft connections 
                            //         (2.5 μs)
                            //      Note: Only accessible in host mode.
    ];

    void set_vtor() {
        scb[0xE000ED08] = 0x8000000;
    }

    string get_reg_name(const uint reg_addr) {
        auto s = get_scb_reg_name(reg_addr);
        if (s != "") return s;
        return stm32f4_peripheral_names.get(reg_addr, "");
    }

    uint read_word(size_t addr) {
        uint res;
        if (addr >= scb_base) {
            if (auto s = addr in scb) {
                res = *s;              
            } else {
                throw new Exception("Invalid access");            
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
            uint val = scb[addr];
            val ^= (1u << bit_pos);
            scb[addr] = val;
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
            if (addr in scb) {
                scb[addr] = val;   
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
            } else if (addr == 0x40011004 || addr == 0x40004404 || addr == 0x40011404) {
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

// =======
//  UART0
// =======

enum UART0 { 
    EVENTS_TXDRDY = 0x4000211C
}

// ========
//  UARTE0
// ========

enum UARTE0 {
    EVENTS_TXSTOPPED = 0x40002158
}

// =======
//  CLOCK
// =======

enum CLOCK {
    LFCLKSRC = 0x40000518
}

// ======
//  QPSI
// ======

enum QPSI {
    EVENTS_READY = 0x40029100
}

size_t[] nrf52840_always_set = [
    CLOCK.LFCLKSRC,
    UART0.EVENTS_TXDRDY,
    QPSI.EVENTS_READY,
    UARTE0.EVENTS_TXSTOPPED
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
    uint[size_t]   peripherals      = [
        0x40011504: 0,          // RTC1: COUNTER, Reset 0x00000000 
        // CLOCK---------------------------------------------------------------------------------
        0x40000000: 0,          // TASKS_HFCLKSTART; Start HFXO crystal oscillator
        0x40000004: 0,          // TASKS_HFCLKSTOP; Stop HFXO crystal oscillator
        0x40000008: 0,          // TASKS_LFCLKSTART; Start LFCLK
        0x4000000C: 0,          // TASKS_LFCLKSTOP; Stop LFCLK
        0x40000010: 0,          // TASKS_CAL; Start calibration of LFRC
        0x40000014: 0,          // TASKS_CTSTART; Start calibration timer
        0x40000018: 0,          // TASKS_CTSTOP; Stop calibration timer
        0x40000100: 0,          // EVENTS_HFCLKSTARTED; HFXO crystal oscillator started
        0x40000104: 0,          // EVENTS_LFCLKSTARTED; LFCLK started
        0x4000010C: 0,          // EVENTS_DONE; Calibration of LFRC completed
        0x40000110: 0,          // EVENTS_CTTO; Calibration timer timeout
        0x40000128: 0,          // EVENTS_CTSTARTED; Calibration timer has been started and is ready to process new tasks
        0x4000012C: 0,          // EVENTS_CTSTOPPED; Calibration timer has been stopped and is ready to process new tasks
        0x40000304: 0,          // INTENSET; Enable interrupt
        0x40000308: 0,          // INTENCLR; Disable interrupt
        0x40000408: 0,          // HFCLKRUN; Status indicating that HFCLKSTART task has been triggered
        0x4000040C: 0,          // HFCLKSTAT; HFCLK status
        0x40000414: 0,          // LFCLKRUN; Status indicating that LFCLKSTART task has been triggered
        0x40000418: 0x00010001, // LFCLKSTAT; LFCLK status
        0x4000041C: 0,          // LFCLKSRCCOPY; Copy of LFCLKSRC register, set when LFCLKSTART task was triggered
        0x40000518: 0,          // LFCLKSRC; Clock source for the LFCLK
        0x40000528: 0,          // HFXODEBOUNCE; HFXO debounce time. The HFXO is started by triggering the TASKS_HFCLKSTART task.
        0x40000538: 0,          // CTIV; Calibration timer interval
                                // This register is retained.
        0x4000055C: 0,          // TRACECONFIG; Clocking options for the trace port debug interface
        0x400005B4: 0,          // LFRCMODE; LFRC mode configuration
        // RNG-----------------------------------------------------------------------------------
        0x4000D000: 0,          // TASKS_START: Task starting the random number generator
        0x4000D004: 0,          // TASKS_STOP:  Task stopping the random number generator
        0x4000D100: 0,          // EVENTS_VALRDY: Event being generated for every new random 
                                // number written to the VALUE register
        0x4000D200: 0,          // SHORTS: Shortcuts between local events and tasks
        0x4000D304: 0,          // INTENSET: Enable interrupt
        0x4000D308: 0,          // INTENCLR: Disable interrupt
        0x4000D504: 0,          // CONFIG: Configuration register
        0x4000D508: 0,          // VALUE: Output random number
        // UART0---------------------------------------------------------------------------------
        0x40002000: 0,          // TASKS_STARTRX: Start UART receiver
        0x40002004: 0,          // TASKS_STOPRX: Stop UART receiver
        0x40002008: 0,          // TASKS_STARTTX: Start UART transmitter
        0x4000200C: 0,          // TASKS_STOPTX: Stop UART transmitter
        0x4000201C: 0,          // TASKS_SUSPEND: Suspend UART
        0x40002100: 0,          // EVENTS_CTS: CTS is activated (set low). Clear To Send.
        0x40002104: 0,          // EVENTS_NCTS: CTS is deactivated (set high). Not Clear To Send.
        0x40002108: 0,          // EVENTS_RXDRDY: Data received in RXD
        0x4000211C: 0,          // EVENTS_TXDRDY: Data sent from TXD
        0x40002124: 0,          // EVENTS_ERROR: Error detected
        0x40002144: 0,          // EVENTS_RXTO: Receiver timeout
        0x40002200: 0,          // SHORTS: Shortcuts between local events and tasks
        0x40002304: 0,          // INTENSET: Enable interrupt
        0x40002308: 0,          // INTENCLR: Disable interrupt
        0x40002480: 0,          // ERRORSRC: Error source
        0x40002500: 0,          // ENABLE: Enable UART
        0x40002508: 0,          // PSEL.RTS: Pin select for RTS
        0x4000250C: 0,          // PSEL.TXD: Pin select for TXD
        0x40002510: 0,          // PSEL.CTS: Pin select for CTS
        0x40002514: 0,          // PSEL.RXD: Pin select for RXD
        0x40002518: 0,          // RXD: RXD register. Register is cleared on read and the double 
                                // buffered byte will be moved to RXD if it exists.
        0x4000251C: 0,          // TXD: TXD register
        0x40002524: 0,          // BAUDRATE: Baud rate. Accuracy depends on the HFCLK source 
                                // selected.
        0x4000256C: 0,          // CONFIG: Configuration of parity and hardware flow control
        // UARTE0--------------------------------------------------------------------------------
        // Universal asynchronous receiver/transmitter with EasyDMA, unit 0
        0x4000202C: 0,          // TASKS_FLUSHRX: Flush RX FIFO into RX buffer
        0x40002110: 0,          // EVENTS_ENDRX: Receive buffer is filled up
        0x40002120: 0,          // EVENTS_ENDTX: Last TX byte transmitted
        0x4000214C: 0,          // EVENTS_RXSTARTED: UART receiver has started
        0x40002150: 0,          // EVENTS_TXSTARTED: UART transmitter has started
        0x40002158: 0,          // EVENTS_TXSTOPPED: Transmitter stopped
        0x40002300: 0,          // INTEN: Enable or disable interrupt
        // RTC-----------------------------------------------------------------------------------
        0x4000B000: 0,          // TASKS_START 0x000 Start RTC COUNTER
        0x4000B004: 0,          // TASKS_STOP 0x004 Stop RTC COUNTER
        0x4000B008: 0,          // TASKS_CLEAR 0x008 Clear RTC COUNTER
        0x4000B00C: 0,          // TASKS_TRIGOVRFLW 0x00C Set COUNTER to 0xFFFFF0
        0x4000B100: 0,          // EVENTS_TICK 0x100 Event on COUNTER increment
        0x4000B104: 0,          // EVENTS_OVRFLW 0x104 Event on COUNTER overflow
        0x4000B140: 0,          // EVENTS_COMPARE[0] 0x140 Compare event on CC[0] match
        0x4000B144: 0,          // EVENTS_COMPARE[1] 0x144 Compare event on CC[1] match
        0x4000B148: 0,          // EVENTS_COMPARE[2] 0x148 Compare event on CC[2] match
        0x4000B14C: 0,          // EVENTS_COMPARE[3] 0x14C Compare event on CC[3] match
        0x4000B304: 0,          // INTENSET 0x304 Enable interrupt
        0x4000B308: 0,          // INTENCLR 0x308 Disable interrupt
        0x4000B340: 0,          // EVTEN 0x340 Enable or disable event routing
        0x4000B344: 0,          // EVTENSET 0x344 Enable event routing
        0x4000B348: 0,          // EVTENCLR 0x348 Disable event routing
        0x4000B504: 0,          // COUNTER 0x504 Current COUNTER value
        0x4000B508: 0,          // PRESCALER 0x508 12 bit prescaler for COUNTER frequency (32768/(PRESCALER+1)). Must be written when RTC is
                                // stopped.
        0x4000B540: 0,          // CC[0] 0x540 Compare register 0
        0x4000B544: 0,          // CC[1] 0x544 Compare register 1
        0x4000B548: 0,          // CC[2] 0x548 Compare register 2
        0x4000B54C: 0,          // CC[3] 0x54C Compare register 3
        // GPIO----------------------------------------------------------------------------------
        0x50000504: 0,          // OUT: Write GPIO port
        0x50000508: 0,          // OUTSET: Set individual bits in GPIO port
        0x5000050C: 0,          // OUTCLR: Clear individual bits in GPIO port
        0x50000510: 0,          // IN: Read GPIO port
        0x50000514: 0,          // DIR: Direction of GPIO pins
        0x50000518: 0,          // DIRSET: DIR set register
        0x5000051C: 0,          // DIRCLR: DIR clear register
        0x50000520: 0,          // LATCH: Latch register indicating what GPIO pins that have met the criteria set in the PIN_CNF[n].SENSE
                                // registers
        0x50000524: 0,          // DETECTMODE: Select between default DETECT signal behavior and LDETECT mode
        0x50000700: 0,          // PIN_CNF[0]: Configuration of GPIO pins
        0x50000704: 0,          // PIN_CNF[1]: Configuration of GPIO pins
        0x50000708: 0,          // PIN_CNF[2]: Configuration of GPIO pins
        0x5000070C: 0,          // PIN_CNF[3]: Configuration of GPIO pins
        0x50000710: 0,          // PIN_CNF[4]: Configuration of GPIO pins
        0x50000714: 0,          // PIN_CNF[5]: Configuration of GPIO pins
        0x50000718: 0,          // PIN_CNF[6]: Configuration of GPIO pins
        0x5000071C: 0,          // PIN_CNF[7]: Configuration of GPIO pins
        0x50000720: 0,          // PIN_CNF[8]: Configuration of GPIO pins
        0x50000724: 0,          // PIN_CNF[9]: Configuration of GPIO pins
        0x50000728: 0,          // PIN_CNF[10]: Configuration of GPIO pins
        0x5000072C: 0,          // PIN_CNF[11]: Configuration of GPIO pins
        0x50000730: 0,          // PIN_CNF[12]: Configuration of GPIO pins
        0x50000734: 0,          // PIN_CNF[13]: Configuration of GPIO pins
        0x50000738: 0,          // PIN_CNF[14]: Configuration of GPIO pins
        0x5000073C: 0,          // PIN_CNF[15]: Configuration of GPIO pins
        0x50000740: 0,          // PIN_CNF[16]: Configuration of GPIO pins
        0x50000744: 0,          // PIN_CNF[17]: Configuration of GPIO pins
        0x50000748: 0,          // PIN_CNF[18]: Configuration of GPIO pins
        0x5000074C: 0,          // PIN_CNF[19]: Configuration of GPIO pins
        0x50000750: 0,          // PIN_CNF[20]: Configuration of GPIO pins
        0x50000754: 0,          // PIN_CNF[21]: Configuration of GPIO pins
        0x50000758: 0,          // PIN_CNF[22]: Configuration of GPIO pins
        0x5000075C: 0,          // PIN_CNF[23]: Configuration of GPIO pins
        0x50000760: 0,          // PIN_CNF[24]: Configuration of GPIO pins
        0x50000764: 0,          // PIN_CNF[25]: Configuration of GPIO pins
        0x50000768: 0,          // PIN_CNF[26]: Configuration of GPIO pins
        0x5000076C: 0,          // PIN_CNF[27]: Configuration of GPIO pins
        0x50000770: 0,          // PIN_CNF[28]: Configuration of GPIO pins
        0x50000774: 0,          // PIN_CNF[29]: Configuration of GPIO pins
        0x50000778: 0,          // PIN_CNF[30]: Configuration of GPIO pins
        0x5000077C: 0,          // PIN_CNF[31]: Configuration of GPIO pins
        // QPSI----------------------------------------------------------------------------------
        0x40029000: 0,          // TASKS_ACTIVATE 0x000 Activate QSPI interface
        0x40029004: 0,          // TASKS_READSTART 0x004 Start transfer from external flash memory to internal RAM
        0x40029008: 0,          // TASKS_WRITESTART 0x008 Start transfer from internal RAM to external flash memory
        0x4002900C: 0,          // TASKS_ERASESTART 0x00C Start external flash memory erase operation
        0x40029010: 0,          // TASKS_DEACTIVATE 0x010 Deactivate QSPI interface
        0x40029100: 0,          // EVENTS_READY 0x100 QSPI peripheral is ready. This event will be generated as a response to any QSPI task.
        0x40029300: 0,          // INTEN 0x300 Enable or disable interrupt
        0x40029304: 0,          // INTENSET 0x304 Enable interrupt
        0x40029308: 0,          // INTENCLR 0x308 Disable interrupt
        0x40029500: 0,          // ENABLE 0x500 Enable QSPI peripheral and acquire the pins selected in PSELn registers
        0x40029504: 0,          // READ.SRC 0x504 Flash memory source address
        0x40029508: 0,          // READ.DST 0x508 RAM destination address
        0x4002950C: 0,          // READ.CNT 0x50C Read transfer length
        0x40029510: 0,          // WRITE.DST 0x510 Flash destination address
        0x40029514: 0,          // WRITE.SRC 0x514 RAM source address
        0x40029518: 0,          // WRITE.CNT 0x518 Write transfer length
        0x4002951C: 0,          // ERASE.PTR 0x51C Start address of flash block to be erased
        0x40029520: 0,          // ERASE.LEN 0x520 Size of block to be erased.
        0x40029524: 0,          // PSEL.SCK 0x524 Pin select for serial clock SCK
        0x40029528: 0,          // PSEL.CSN 0x528 Pin select for chip select signal CSN.
        0x40029530: 0,          // PSEL.IO0 0x530 Pin select for serial data MOSI/IO0.
        0x40029534: 0,          // PSEL.IO1 0x534 Pin select for serial data MISO/IO1.
        0x40029538: 0,          // PSEL.IO2 0x538 Pin select for serial data IO2.
        0x4002953C: 0,          // PSEL.IO3 0x53C Pin select for serial data IO3.
        0x40029540: 0,          // XIPOFFSET 0x540 Address offset into the external memory for Execute in Place operation.
        0x40029544: 0,          // IFCONFIG0 0x544 Interface configuration.
        0x40029600: 0,          // IFCONFIG1 0x600 Interface configuration.
        0x40029604: 0,          // STATUS 0x604 Status register.
        0x40029614: 0,          // DPMDUR 0x614 Set the duration required to enter/exit deep power-down mode (DPM).
        0x40029624: 0,          // ADDRCONF 0x624 Extended address configuration.
        0x40029634: 0,          // CINSTRCONF 0x634 Custom instruction configuration register.
        0x40029638: 0,          // CINSTRDAT0 0x638 Custom instruction data register 0.
        0x4002963C: 0,          // CINSTRDAT1 0x63C Custom instruction data register 1.
        0x40029640: 0,          // IFTIMING 0x640 SPI interface timing
    ];
    string[size_t] peripheral_names = [
        0x40011504: "RTC1_COUNTER"
    ]; 

    string get_reg_name(const uint reg_addr) {
        auto s = get_scb_reg_name(reg_addr);
        if (s != "") return s;
        return peripheral_names.get(reg_addr, "");
    }

    void set_vtor() {}

    uint read_word(size_t addr) {
        uint res;
        if (nrf52840_always_set.canFind(addr)) 
            return 0x1;
        if (addr >= scb_base) {
            if (auto s = addr in scb) {
                res = *s;              
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr > ram_origin + ram_length) {
            if (auto p = addr in peripherals) {
                res = *p;              
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
            uint val = scb[addr];
            val ^= (1u << bit_pos);
            scb[addr] = val;
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
        if (addr >= scb_base) {
            if (addr == 0xE000E400) {
                return 0xf0;
            }
            return read_byte_from_word(scb, addr);
        }
        if (addr >= ram_origin + ram_length) {
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
            if (addr in scb) {
                scb[addr] = val;  
                return;            
            } else {
                throw new Exception("Invalid access");            
            }
        } else if (addr >= ram_origin + ram_length) {
            peripherals[addr] = val;
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
            write_byte_to_word(peripherals, addr, b);
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