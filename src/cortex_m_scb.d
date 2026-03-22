import scb_defs;

uint[size_t] scb = [
    // NVIC
    0xE000E3FC: 0,
    0xE000ED00: 0,
    ICSR:  0,          
    CCR:   0,
    SHPR3: 0,
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
    MPU_TYPE: 0x00000800, MPU_CTRL: 0, MPU_RNR: 0, MPU_RBAR: 0, MPU_RASR: 0, 
    // ------------------------------------- NVIC ABR ---------------------------------------  
    NVIC_IABR0:  0, NVIC_IABR1:  0, NVIC_IABR2:  0, NVIC_IABR3:  0, NVIC_IABR4:  0, NVIC_IABR5:  0, 
    NVIC_IABR6:  0, NVIC_IABR7:  0, NVIC_IABR8:  0, NVIC_IABR9:  0, NVIC_IABR10: 0, NVIC_IABR11: 0,
    NVIC_IABR12: 0, NVIC_IABR13: 0, NVIC_IABR14: 0, NVIC_IABR15: 0,
    // ------------------------------------- NVIC ISR ---------------------------------------                        
    NVIC_ISER0:  0, NVIC_ISER1:  0, NVIC_ISER2:  0, NVIC_ISER3:  0, NVIC_ISER4:  0, NVIC_ISER5:  0, 
    NVIC_ISER6:  0, NVIC_ISER7:  0, NVIC_ISER8:  0, NVIC_ISER9:  0, NVIC_ISER10: 0, NVIC_ISER11: 0,
    NVIC_ISER12: 0, NVIC_ISER13: 0, NVIC_ISER14: 0, NVIC_ISER15: 0,
    // ------------------------------------- NVIC ISPR --------------------------------------
    NVIC_ISPR0:  0, NVIC_ISPR1:  0, NVIC_ISPR2:  0, NVIC_ISPR3:  0, NVIC_ISPR4:  0, NVIC_ISPR5:  0, 
    NVIC_ISPR6:  0, NVIC_ISPR7:  0, NVIC_ISPR8:  0, NVIC_ISPR9:  0, NVIC_ISPR10: 0, NVIC_ISPR11: 0,
    NVIC_ISPR12: 0, NVIC_ISPR13: 0, NVIC_ISPR14: 0, NVIC_ISPR15: 0, 
    // ------------------------------------- NVIC ICPR --------------------------------------   
    NVIC_ICPR0:  0, NVIC_ICPR1:  0, NVIC_ICPR2:  0, NVIC_ICPR3:  0, NVIC_ICPR4:  0, NVIC_ICPR5:  0, 
    NVIC_ICPR6:  0, NVIC_ICPR7:  0, NVIC_ICPR8:  0, NVIC_ICPR9:  0, NVIC_ICPR10: 0, NVIC_ICPR11: 0,
    NVIC_ICPR12: 0, NVIC_ICPR13: 0, NVIC_ICPR14: 0, NVIC_ICPR15: 0, 
    // ------------------------------------- NVIC IPR ---------------------------------------                        
    NVIC_ISR0:  0, NVIC_ISR1:  0, NVIC_ISR2:  0, NVIC_ISR3:  0, NVIC_ISR4:  0, NVIC_ISR5:  0, 
    NVIC_ISR6:  0, NVIC_ISR7:  0, NVIC_ISR8:  0, NVIC_ISR9:  0, NVIC_ISR10: 0, NVIC_ISR11: 0,
    NVIC_ISR12: 0, NVIC_ISR13: 0, NVIC_ISR14: 0, NVIC_ISR15: 0, NVIC_ISR16: 0, NVIC_ISR17: 0,
    NVIC_ISR18: 0, NVIC_ISR19: 0, NVIC_ISR20: 0, NVIC_ISR21: 0, NVIC_ISR22: 0, NVIC_ISR23: 0, 
    NVIC_ISR24: 0, NVIC_ISR25: 0,
    // --------------------------------------------------------------------------------------
    0xE000E3F8: 0,
    0xE000EF34: 0,
    VTOR: 0, AIRCR: 0xFA050000, SCR: 0,
    0xE000ED28: 0,          // CFSR(RW) 0x00000000
                            // Write a one to a register bit to clear the corresponding fault.
                            // [31:16] UsageFault Provides information on UsageFault exceptions
                            // [15:8] BusFault Provides information on BusFault exceptions
                            // [7:0] MemManage Provides information on MemManage exceptions
    HFSR: 0,   
    // ------------------------------------- SysTick ----------------------------------------
    SYST_CSR: 0, SYST_RVR: 0, SYST_CVR: 0, SYST_CALIB: 0,
    // --------------------------------------------------------------------------------------
    CPACR: 0,
    0xE000E018: 0,
    0xE0042004: 0           // DBGMCU_CR Debug MCU Configuration Register
];