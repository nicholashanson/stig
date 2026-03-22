// Interrupt Control and State Register
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
enum ICSR = 0xE000ED04;

// Configuration and Control Register(RW) 0x00000000           
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
enum CCR = 0xE000ED14;

// System Handler Priority Register 3
// [31:24] PRI_15 Priority of system handler 15, SysTick
// [23:16] PRI_14 Priority of system handler 14, PendSV
// [15:8] PRI_13 Reserved for priority of system handler 13
// [7:0] PRI_12 Priority of system handler 12, DebugMonitor  
enum SHPR3 = 0xE000ED20;
// MPU_TYPE(RO): reset value for Cortex M-4: 0x00000800
enum MPU_TYPE = 0xE000ED90;
// MPU_CTRL(RW)
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
enum MPU_CTRL = 0xE000ED94;
// MPU Region Number Register(RW)
// selects the region currently accessed by MPU_RBAR and MPU_RASR
// [7:0] REGION
enum MPU_RNR = 0xE000ED98;          
// MPU Region Base Address Register(RW)
// [31:5] ADDR, [4] VALID, [3:0] REGION
// ADDR:   Base address of the region
// VALID:  On writes, indicates whether the region to update is 
//         specified by  MPU_RNR.REGION, or by the REGION value 
//         specified in this write. 
//         When using the REGION value specified by this write, 
//         MPU_RNR.REGION is updated to this value
// REGION: on writes, can specify the number of the region to 
//         update

enum MPU_RBAR = 0xE000ED9C;          
// MPU Region Attribute and Size Register(RW)                 
enum MPU_RASR = 0xE000EDA0;   

// SYST_CSR SysTick Control and Status Register(RW)
enum SYST_CSR = 0xE000E010;
// SysTick Reload Value Register(RW)
enum SYST_RVR = 0xE000E014;
// SysTick Current Value Register(RW)
enum SYST_CVR = 0xE000E018;
// SysTick Calibration Value Register(RW)
enum SYST_CALIB = 0xE000E01C;

// Coprocessor Access Control Register
// Specifies the access privileges for coprocessors.
enum CPACR = 0xE000ED88;

// HFSR(RW) 0x00000000
// Write a one to a register bit to clear the corresponding fault.      
enum HFSR = 0xE000ED2C;

enum NVIC_IABR0  = 0xE000E300;
enum NVIC_IABR1  = 0xE000E304;
enum NVIC_IABR2  = 0xE000E308;
enum NVIC_IABR3  = 0xE000E30C;
enum NVIC_IABR4  = 0xE000E310;
enum NVIC_IABR5  = 0xE000E314;
enum NVIC_IABR6  = 0xE000E318;
enum NVIC_IABR7  = 0xE000E31C;
enum NVIC_IABR8  = 0xE000E320;
enum NVIC_IABR9  = 0xE000E324;
enum NVIC_IABR10 = 0xE000E328;
enum NVIC_IABR11 = 0xE000E32C;
enum NVIC_IABR12 = 0xE000E330;
enum NVIC_IABR13 = 0xE000E334;
enum NVIC_IABR14 = 0xE000E338;
enum NVIC_IABR15 = 0xE000E33C;

enum NVIC_ISER0  = 0xE000E100;
enum NVIC_ISER1  = 0xE000E104;
enum NVIC_ISER2  = 0xE000E108;
enum NVIC_ISER3  = 0xE000E10C;
enum NVIC_ISER4  = 0xE000E110;
enum NVIC_ISER5  = 0xE000E114;
enum NVIC_ISER6  = 0xE000E118;
enum NVIC_ISER7  = 0xE000E11C;
enum NVIC_ISER8  = 0xE000E120;
enum NVIC_ISER9  = 0xE000E124;
enum NVIC_ISER10 = 0xE000E128;
enum NVIC_ISER11 = 0xE000E12C;
enum NVIC_ISER12 = 0xE000E130;
enum NVIC_ISER13 = 0xE000E134;
enum NVIC_ISER14 = 0xE000E138;
enum NVIC_ISER15 = 0xE000E13C;  

enum NVIC_ISPR0  = 0xE000E200;
enum NVIC_ISPR1  = 0xE000E204;
enum NVIC_ISPR2  = 0xE000E208;
enum NVIC_ISPR3  = 0xE000E20C;
enum NVIC_ISPR4  = 0xE000E210;
enum NVIC_ISPR5  = 0xE000E214;
enum NVIC_ISPR6  = 0xE000E218;
enum NVIC_ISPR7  = 0xE000E21C;
enum NVIC_ISPR8  = 0xE000E220;
enum NVIC_ISPR9  = 0xE000E224;
enum NVIC_ISPR10 = 0xE000E228;
enum NVIC_ISPR11 = 0xE000E22C;
enum NVIC_ISPR12 = 0xE000E230;
enum NVIC_ISPR13 = 0xE000E234;
enum NVIC_ISPR14 = 0xE000E238;
enum NVIC_ISPR15 = 0xE000E23C;

enum NVIC_ICPR0  = 0xE000E280; 
enum NVIC_ICPR1  = 0xE000E284; 
enum NVIC_ICPR2  = 0xE000E288; 
enum NVIC_ICPR3  = 0xE000E28C; 
enum NVIC_ICPR4  = 0xE000E290; 
enum NVIC_ICPR5  = 0xE000E294; 
enum NVIC_ICPR6  = 0xE000E298; 
enum NVIC_ICPR7  = 0xE000E29C; 
enum NVIC_ICPR8  = 0xE000E2A0; 
enum NVIC_ICPR9  = 0xE000E2A4; 
enum NVIC_ICPR10 = 0xE000E2A8; 
enum NVIC_ICPR11 = 0xE000E2AC; 
enum NVIC_ICPR12 = 0xE000E2B0; 
enum NVIC_ICPR13 = 0xE000E2B4; 
enum NVIC_ICPR14 = 0xE000E2B8; 
enum NVIC_ICPR15 = 0xE000E2BC; 

enum NVIC_ISR0  = 0xE000E400;
enum NVIC_ISR1  = 0xE000E404;
enum NVIC_ISR2  = 0xE000E408;
enum NVIC_ISR3  = 0xE000E40C;
enum NVIC_ISR4  = 0xE000E410;
enum NVIC_ISR5  = 0xE000E414;
enum NVIC_ISR6  = 0xE000E418;
enum NVIC_ISR7  = 0xE000E41C;
enum NVIC_ISR8  = 0xE000E420;
enum NVIC_ISR9  = 0xE000E424;
enum NVIC_ISR10 = 0xE000E428;
enum NVIC_ISR11 = 0xE000E42C;
enum NVIC_ISR12 = 0xE000E430;
enum NVIC_ISR13 = 0xE000E434;
enum NVIC_ISR14 = 0xE000E438;
enum NVIC_ISR15 = 0xE000E43C;
enum NVIC_ISR16 = 0xE000E440;
enum NVIC_ISR17 = 0xE000E444;
enum NVIC_ISR18 = 0xE000E448;
enum NVIC_ISR19 = 0xE000E44C;
enum NVIC_ISR20 = 0xE000E450;
enum NVIC_ISR21 = 0xE000E454;
enum NVIC_ISR22 = 0xE000E458;
enum NVIC_ISR23 = 0xE000E45C;
enum NVIC_ISR24 = 0xE000E460;
enum NVIC_ISR25 = 0xE000E464;

// Vector Table Offset Register(RW)
enum VTOR = 0xE000ED08;          
// Application Interrupt and Reset Control Register(RW)
enum AIRCR = 0xE000ED0C; 
// SCR(RW) 0x00000000 
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
enum SCR = 0xE000ED10;     

                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
                            
