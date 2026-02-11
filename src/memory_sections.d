import std.stdio;
import std.format;

import cortex_m_core;
import load_store_log_;

File* access_log_ptr = null;

File* access_log() {
    if (access_log_ptr is null) {
        access_log_ptr = new File("access_log.txt", "w");
    }
    return access_log_ptr;
}

File* stack_log_ptr = null;

File* stack_log() {
    if (stack_log_ptr is null) {
        stack_log_ptr = new File("stack_log.txt", "w");
    }
    return stack_log_ptr;
}

File* uart_log_ptr = null;

File* uart_log() {
    if (uart_log_ptr is null) {
        uart_log_ptr = new File("uart_log.txt", "w");
    }
    return uart_log_ptr;
}

File* gpio_log_ptr = null;

File* gpio_log() {
    if (gpio_log_ptr is null) {
        gpio_log_ptr = new File("gpio_log.txt", "w");
    }
    return gpio_log_ptr;
}

// =============
//  MEM SECTION
// =============

struct mem_section(size_t kb, size_t origin) {
	ubyte[kb * 1024] cells;

    const(ubyte) read_byte(size_t index) const {
    	index -= origin;
        return cells[index];
    }

    const(ushort) read_half_word(size_t index) {
    	index -= origin;
    	ushort res = (cells[index + 1] << 8) | cells[index];
    	return res;
    }

    const(uint) read_word(size_t index) {
    	index -= origin;
    	uint res = (cells[index + 3] << 24) | 
    	           (cells[index + 2] << 16) | 
    	           (cells[index + 1] <<  8) | 
    	            cells[index    ];
    	return res;
    }

    void write_byte(size_t index, const ubyte val) {
    	index -= origin;
    	cells[index] = val;
    }

    void write_half_word(size_t index, const ushort val) {
    	index -= origin;
    	cells[index + 1] = (val >> 8) & 0xff;
    	cells[index] =      val       & 0xff;
    }

    void write_word(size_t index, const uint val) {
    	index -= origin;
    	cells[index + 3] = (val >> 24) & 0xff;
    	cells[index + 2] = (val >> 16) & 0xff;
    	cells[index + 1] = (val >>  8) & 0xff;
    	cells[index] =      val        & 0xff;
    }
}

__gshared ubyte[1024 * 1024] g_big_mem;

// =================
//  Big Mem Section
// =================

struct big_mem_section(size_t origin) {
    const(ubyte) read_byte(size_t index) const {
    	index -= origin;
        return g_big_mem[index];
    }

    const(ushort) read_half_word(size_t index) const {
    	index -= origin;
    	ushort res = (g_big_mem[index + 1] << 8) | g_big_mem[index];
    	return res;
    }

    void write_byte(size_t index, const ubyte val) {
        index -= origin;
        g_big_mem[index] = val;
    }

    void write_half_word(size_t index, const ushort val) {
        index -= origin;
        g_big_mem[index + 1] = (val >> 8) & 0xff;
        g_big_mem[index] =      val       & 0xff;
    }

    const(uint) read_word(size_t index) const {
    	index -= origin;
    	uint res = (g_big_mem[index + 3] << 24) | 
    	           (g_big_mem[index + 2] << 16) | 
    	           (g_big_mem[index + 1] <<  8) |  
    	            g_big_mem[index];
    	return res;
    }

    static void write_word(size_t index, const uint val) {
       	index -= origin;
    	g_big_mem[index + 3] = (val >> 24) & 0xff;
    	g_big_mem[index + 2] = (val >> 16) & 0xff;
    	g_big_mem[index + 1] = (val >>  8) & 0xff;
    	g_big_mem[index    ] =  val        & 0xff;
    }

    enum origin_ = origin; 
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    big_mem_section!(0x08000000) flash;
    flash.write_word(flash.origin_, 32);
    uint read_value = flash.read_word(flash.origin_);
    assert(read_value == 32, "Failed to read word from flash");
}

enum scb_base = 0xE0000000;

uint[size_t] scb = [
    // NVIC
    0xE000E3FC: 0,
    0xE000ED00: 0,
    0xe000ed04: 0,
    0xe000ed14: 0,
    0xe000ed20: 0,
    0xe000ed18: 0,
    0xe000ed1c: 0,
    0xe000ed24: 0,

    // --------------------------------------- MPU ------------------------------------------
    0xE000ED90: 0x00000800, // MPU_TYPE(RO): reset value for Cortex M-4
    0xE000ED94: 0,          // MPU_CTRL(RW)
                            // enables the MPU
                            // [2] PRIVDEFENA, [1] HFNMIENA, [0] ENABLE
                            // PRIVDEFENA: 0 disables the default memory map. Any instruction
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
                            // VALID:  On writes, indicates whether the region to update is specified by 
                            //         MPU_RNR.REGION, or by the REGION value specified in this write. 
                            //         When using the REGION value specified by this write, MPU_RNR.REGION 
                            //         is updated to this value
                            // REGION: on writes, can specify the number of the region to update
    0xE000EDA0: 0,          // MPU_RASR(RW) MPU Region Attribute and Size Register
    // --------------------------------------------------------------------------------------  
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
    0xE000ED08: 0, //0x08000000, // VTOR(RW) Vector Table Offset Register
    0xE000ED0C: 0xFA050000, // AIRCR(RW) Application Interrupt and Reset Control Register 
    0xE000ED10: 0,          // SCR(RW) 0x00000000 
    0xE000ED28: 0,          // CFSR(RW) 0x00000000
    0xE000ED2C: 0,          // HFSR(RW) 0x00000000
    // --------------------------------------------------------------------------------------
    // ------------------------------------- SysTick ----------------------------------------
    0xE000E010: 0,          // SYST_CSR(RW) SysTick Control and Status Register
    0xE000E014: 0,          // SYST_RVR(RW) SysTick Reload Value Register
    0xE000E018: 0,          // SYST_CVR(RW) SysTick Current Value Register
    0xE000E01C: 0,          // SYST_CALIB(RW) SysTick Calibration Value Register
    // --------------------------------------------------------------------------------------
    0xE000ED88: 0,          // SCB_CPACR

    0xE000E018: 0,
    0xE0042004: 0           // DBGMCU_CR Debug MCU Configuration Register

];

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
        0x40007000: 0x0000C000, // PWR_CR
        0x40023800: 0x03333083, // RCC_CR, reset val: 0x00000083
        0x40023804: 0x24003010, // RCC_PLLCFGR
        0x40023884: 0x20003000, // RCC_PLLI2SCFGR

        0x4000780C: 0,          // reserved
        0x40007810: 0,          // reserved
        0x40007814: 0,          // reserved
        0x40013818: 0,
        // -------------------------------------- TIM2 ------------------------------------------
        0x40000000: 0,          // TIM2_CR1 TIM2 Control Register 1
        0x40000004: 0,          // TIM2_CR2 TIM2 Control Register 2
        0x40000008: 0,          // TIM2_SMCR TIM2 Slave Mode Control Register
        // --------------------------------------------------------------------------------------
        // -------------------------------------- FLASH -----------------------------------------
        0x40023C00: 0x000083,   // FLASH_ACR 
        // --------------------------------------------------------------------------------------
        // -------------------------------------- USART6 ----------------------------------------
        0x40011400: 0xc0,       // USART_SR
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
        // --------------------------------------- RCC ------------------------------------------
        0x40023824: 0,          // RCC_APB2RSTR
        0x40023830: 0,          // RCC_AHB1ENR Peripheral Clock Enable Register
        0x40023840: 0,          // RCC_APB1ENR Peripheral Clock Enable Register
        0x40023844: 0,          // RCC_APB2ENR Peripheral Clock Enable Register
        0x4002388C: 0,          // RCC_DCKCFGR Dedicated Clock Configuration Register
        // --------------------------------------------------------------------------------------
        // -------------------------------------- USART1 ----------------------------------------
        0x4001100c: 0,          // CR1
        0x40011010: 0,          // CR2
        0x40011014: 0,          // CR3
        0x40011024: 0,          // GPTR
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
        0x40001000: 0,      
        0x40001004: 0, 
        0x40001008: 0, 
        0x4000100C: 0,
        0x40001010: 0, 
        0x40001014: 0, 
        0x40001018: 0, 
        0x4000101C: 0,
        0x40001020: 0, 
        0x40001024: 0, 
        0x40001028: 0, 
        0x4000102C: 0,
        0x40001030: 0, 
        0x40001034: 0, 
        0x40001038: 0, 
        0x4000103C: 0,
        0x40001040: 0, 
        0x40001044: 0,
        0x40023874: 0,
        0x4000440C: 0,
        0x40023820: 0,
        0x40004410: 0,
        0x40004414: 0,
        0x40004400: 0xc0,
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
        0x40011000: 0xc0
    ];

    string[size_t] peripheral_names = [
        0x40000000: "TIM2_CR1",
        0x40000004: "TIM2_CR2",
        0x40000008: "TIM2_SMCR",
        0xE000E010: "SYST_CSR",
        0xE000E014: "SYST_RVR",       
        0xE000E018: "SYST_CVR",       
        0xE000E01C: "SYST_CALIB",
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
        0x40011400: "USART_SR",
        0x40011404: "USART_DR",
        0x40011408: "USART_BRR",
        0x4001140C: "USART_CR1",
        0x40011410: "USART_CR2",
        0x40011414: "USART_CR3",
        0x40011418: "USART_GTPR" 
    ]; 

    string get_reg_name(const uint reg_addr) {
        const uint ise_base     = 0xE000E100;
        const uint ise_top      = 0xE000E13C;
        const uint ice_base     = 0xE000E180;
        const uint ice_top      = 0xE000E1BC;
        const uint isp_base     = 0xE000E200;
        const uint isp_top      = 0xE000E23C;
        const uint iab_base     = 0xE000E300;
        const uint iab_top      = 0xE000E33C;
        const uint ipr_base     = 0xE000E400;
        const uint ipr_top      = 0xE000E5EC;
        if (reg_addr >= ipr_base && reg_addr <= ipr_top) {
            return format("NVIC_IPR%d", (reg_addr - ipr_base) / 4);
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
        return peripheral_names.get(reg_addr, "");
    }

    unittest {
        stm32f4_mem mem;
        auto reg_name = mem.get_reg_name(0xE000E100);
        assert(reg_name == "NVIC_ISER0", format("reg_name of 0xE000E100 is %s, instead of the expected NVIC_ISER0", reg_name));
        auto zero_case = mem.get_reg_name(0x0);
        assert(zero_case == "", format("reg_name of 0xE000E100 is %s, instead of the expected empty string", zero_case));
    }

    uint read_word(size_t addr, uint pc) {
        auto f = load_store_log();
        f.writeln(format("Attempting to access [%08X]", addr));
        f.flush();
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
        f.writeln(format("%08X: %08X loaded from [%08X]", pc, res, addr));
        f.flush();
        return res;
    }

    void flip_bit(size_t addr, int bit_pos) {
        if (addr > ram_origin + ram_length) {
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

    void write_half_word(size_t addr, ushort val, uint pc) {
        auto f = load_store_log();
        if (addr >= ram_origin) {
            ram.write_half_word(addr, val);
        } else {
            flash.write_half_word(addr, val);
        }
        f.writeln(format("%08X: %08X stored to [%08X]", pc, addr, addr));
        f.flush();
    }

    const(ubyte) read_byte(size_t addr) {
        if (addr > scb_base) {
            if (addr == 0xE000E400) {
                return 0xf0;
            }
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;
            uint val = scb[word_addr];
            return cast(ubyte)((val >> shift) & 0xff);
        } else if (addr >= ram_origin + ram_length) {
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;
            uint val = peripherals[word_addr];
            return cast(ubyte)((val >> shift) & 0xff);
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

    void write_byte(const size_t addr, const uint val, const uint pc) {
        auto f = load_store_log();
        f.writeln(format("Attempting to access [%08X]", addr));
        const ubyte b = cast(ubyte)(val & 0xff);
        if (addr >= scb_base) {
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;

            uint old = scb[word_addr];
            uint masked = (old & ~(0xff << shift)) | (b << shift);
            scb[word_addr] = masked;
        } else if (addr >= ram_origin + ram_length) {
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;

            uint old = peripherals[word_addr];
            uint masked = (old & ~(0xff << shift)) | (b << shift);
            peripherals[word_addr] = masked;
        } else if (addr >= ram_origin) {
            ram.write_byte(addr, b);
        } else {
            flash.write_byte(addr, b);
        }
        f.writeln(format("%08X: %08X stored to [%08X]", pc, val, addr));
        f.flush();
    }

    void inc_sp_word_width(ref cortex_m_cpu cpu) {
        uint current_sp = cpu.get_sp();
        current_sp += 4;
        cpu.set_sp(current_sp);
    }

    void dec_sp_word_width(ref cortex_m_cpu cpu) {
        uint current_sp = cpu.get_sp();
        current_sp -= 4;
        cpu.set_sp(current_sp);
    }

    void push(ref cortex_m_cpu cpu, uint val) {
        dec_sp_word_width(cpu);
        ram.write_word(cpu.get_sp(), val);
    }

    uint pop(ref cortex_m_cpu cpu) {
        uint res = ram.read_word(cpu.get_sp());
        inc_sp_word_width(cpu);
        return res;
    }
}

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
    ];
    string[size_t] peripheral_names = [
        0x40011504: "RTC1_COUNTER"
    ]; 

    string get_reg_name(const uint reg_addr) {
        const uint ise_base     = 0xE000E100;
        const uint ise_top      = 0xE000E13C;
        const uint ice_base     = 0xE000E180;
        const uint ice_top      = 0xE000E1BC;
        const uint isp_base     = 0xE000E200;
        const uint isp_top      = 0xE000E23C;
        const uint iab_base     = 0xE000E300;
        const uint iab_top      = 0xE000E33C;
        const uint ipr_base     = 0xE000E400;
        const uint ipr_top      = 0xE000E5EC;
        if (reg_addr >= ipr_base && reg_addr <= ipr_top) {
            return format("NVIC_IPR%d", (reg_addr - ipr_base) / 4);
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
        return peripheral_names.get(reg_addr, "");
    }

    unittest {
        stm32f4_mem mem;
        auto reg_name = mem.get_reg_name(0xE000E100);
        assert(reg_name == "NVIC_ISER0", format("reg_name of 0xE000E100 is %s, instead of the expected NVIC_ISER0", reg_name));
        auto zero_case = mem.get_reg_name(0x0);
        assert(zero_case == "", format("reg_name of 0xE000E100 is %s, instead of the expected empty string", zero_case));
    }

    uint read_word(size_t addr, uint pc) {
        auto f = load_store_log();
        f.writeln(format("[%08X]Attempting to access [%08X]", pc, addr));
        f.flush();
        uint res;
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
        f.writeln(format("%08X: %08X loaded from [%08X]", pc, res, addr));
        f.flush();
        return res;
    }

    void flip_bit(size_t addr, int bit_pos) {
        if (addr > ram_origin + ram_length) {
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

    void write_half_word(size_t addr, ushort val, uint pc) {
        auto f = load_store_log();
        f.writeln(format("[%08X]Attempting to access [%08X]", pc, addr));
        f.flush();
        if (addr >= ram_origin) {
            ram.write_half_word(addr, val);
        } else {
            flash.write_half_word(addr, val);
        }
        f.writeln(format("%08X: %08X stored to [%08X]", pc, addr, addr));
        f.flush();
    }

    const(ubyte) read_byte(size_t addr) {
        if (addr >= scb_base) {
            if (addr == 0xE000E400) {
                return 0xf0;
            }
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;
            uint val = scb[word_addr];
            return cast(ubyte)((val >> shift) & 0xff);
        }
        if (addr >= ram_origin + ram_length) {
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;
            uint val = peripherals[word_addr];
            return cast(ubyte)((val >> shift) & 0xff);
        } 
        if (addr >= ram_origin) {
            return ram.read_byte(addr);
        } else {
            return flash.read_byte(addr);
        }
    }

    void write_word(size_t addr, uint val) {
        auto f = load_store_log();
        f.writeln(format("Attempting to access [%08X]", addr));
        f.flush();
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
        f.writeln(format("%08X stored to [%08X]", val, addr));
        f.flush();
    }

    void write_byte(const size_t addr, const uint val, const uint pc) {
        auto f = load_store_log();
        f.writeln(format("[%08X]Attempting to access [%08X]", pc, addr));
        const ubyte b = cast(ubyte)(val & 0xff);
        if (addr >= scb_base) {
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;

            uint old = scb[word_addr];
            uint masked = (old & ~(0xff << shift)) | (b << shift);
            scb[word_addr] = masked;
        } else if (addr >= ram_origin + ram_length) {
            size_t word_addr = addr & ~3;
            uint shift = (addr & 3) * 8;

            uint old = peripherals[word_addr];
            uint masked = (old & ~(0xff << shift)) | (b << shift);
            peripherals[word_addr] = masked;
        } else if (addr >= ram_origin) {
            ram.write_byte(addr, b);
        } else {
            flash.write_byte(addr, b);
        }
        f.writeln(format("%08X: %08X stored to [%08X]", pc, val, addr));
        f.flush();
    }

    void inc_sp_word_width(ref cortex_m_cpu cpu) {
        uint current_sp = cpu.get_sp();
        current_sp += 4;
        cpu.set_sp(current_sp);
    }

    void dec_sp_word_width(ref cortex_m_cpu cpu) {
        uint current_sp = cpu.get_sp();
        current_sp -= 4;
        cpu.set_sp(current_sp);
    }

    void push(ref cortex_m_cpu cpu, uint val) {
        dec_sp_word_width(cpu);
        ram.write_word(cpu.get_sp(), val);
    }

    uint pop(ref cortex_m_cpu cpu) {
        uint res = ram.read_word(cpu.get_sp());
        inc_sp_word_width(cpu);
        return res;
    }
}