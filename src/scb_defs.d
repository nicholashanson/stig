import std.traits;
import std.array;
import std.format;

bool get_bit(const uint val, const ubyte bit_pos) {
    return true;
}

template generateAliases(alias E)
{
    enum string aliases = generate();

    // Compile-time function that returns the code as a string
    private enum string generate()
    {
        string result;
        static foreach(member; __traits(allMembers, E))
        {
            // Append each alias line
            result ~= "enum " ~ member ~ " = " ~ E.stringof ~ "." ~ member ~ ";\n";
        }
        return result;
    }
}

enum string SCB_REGS = q{
// Interrupt Control and State Register
// Provides software control of the NMI, PendSV, and SysTick 
// exceptions, and provides interrupt status information.
// [26] RW PENDSTSET On writes, sets the SysTick exception as pending. On reads, indicates the
// current state of the exception:
//      0 = On writes, has no effect. On reads, SysTick is not pending.
//      1 = On writes, make SysTick exception pending. On reads, SysTick is
//      pending.
// [25] WO PENDSTCLR Removes the pending status of the SysTick exception:
//      0 = No effect.
//      1 = Remove pending status.
// [28] RW PENDSVSET On writes, sets the PendSV exception as 
// pending. 
// On reads, indicates thecurrent state of the exception:
//      0 = On writes, has no effect. On reads, PendSV is not 
//          pending.
//      1 = On writes, make PendSV exception pending. On reads, 
//          PendSV is pending.
// Normally, software writes 1 to this bit to request a context 
// switch.
ICSR = 0xE000ED04,

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
CCR = 0xE000ED14,

BFAR = 0xE000ED38,

// MPU Memory Attribute Indirection Register 0
MPU_MAIR0 = 0xE000EDC0, 

// System Handler Priority Register 3
// [31:24] PRI_15 Priority of system handler 15, SysTick
// [23:16] PRI_14 Priority of system handler 14, PendSV
// [15:8] PRI_13 Reserved for priority of system handler 13
// [7:0] PRI_12 Priority of system handler 12, DebugMonitor  
SHPR3 = 0xE000ED20,
// MPU_TYPE(RO): reset value for Cortex M-4: 0x00000800
MPU_TYPE = 0xE000ED90,
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
MPU_CTRL = 0xE000ED94,
// MPU Region Number Register(RW)
// selects the region currently accessed by MPU_RBAR and MPU_RASR
// [7:0] REGION
MPU_RNR = 0xE000ED98,     
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

MPU_RBAR = 0xE000ED9C,        
// MPU Region Attribute and Size Register(RW)                 
MPU_RASR = 0xE000EDA0,  

// SYST_CSR SysTick Control and Status Register(RW)
SYST_CSR = 0xE000E010,
// SysTick Reload Value Register(RW)
SYST_RVR = 0xE000E014,
// SysTick Current Value Register(RW)
SYST_CVR = 0xE000E018,
// SysTick Calibration Value Register(RW)
SYST_CALIB = 0xE000E01C,

// HFSR(RW) 0x00000000
// Write a one to a register bit to clear the corresponding fault.      
HFSR = 0xE000ED2C,

NVIC_ICER1  = 0xE000E184,  

NVIC_ISR0  = 0xE000E400,
NVIC_ISR1  = 0xE000E404,
NVIC_ISR2  = 0xE000E408,
NVIC_ISR3  = 0xE000E40C,
NVIC_ISR4  = 0xE000E410,
NVIC_ISR5  = 0xE000E414,
NVIC_ISR6  = 0xE000E418,
NVIC_ISR7  = 0xE000E41C,
NVIC_ISR8  = 0xE000E420,
NVIC_ISR9  = 0xE000E424,
NVIC_ISR10 = 0xE000E428,
NVIC_ISR11 = 0xE000E42C,
NVIC_ISR12 = 0xE000E430,
NVIC_ISR13 = 0xE000E434,
NVIC_ISR14 = 0xE000E438,
NVIC_ISR15 = 0xE000E43C,
NVIC_ISR16 = 0xE000E440,
NVIC_ISR17 = 0xE000E444,
NVIC_ISR18 = 0xE000E448,
NVIC_ISR19 = 0xE000E44C,
NVIC_ISR20 = 0xE000E450,
NVIC_ISR21 = 0xE000E454,
NVIC_ISR22 = 0xE000E458,
NVIC_ISR23 = 0xE000E45C,
NVIC_ISR24 = 0xE000E460,
NVIC_ISR25 = 0xE000E464,
NVIC_ISR26 = 0xE000E468,
NVIC_ISR27 = 0xE000E46C,
NVIC_ISR28 = 0xE000E470,
NVIC_ISR29 = 0xE000E474,
NVIC_ISR30 = 0xE000E478,
NVIC_ISR31 = 0xE000E47C,
NVIC_ISR32 = 0xE000E480,

// Software Triggered Interrupt Register
// Writing to this register has the same effect as setting the NVIC 
// ISPR bit corresponding to the interrupt to 1
// This register applies to implemented external interrupts only.
STIR = 0xE000EF00,

// Vector Table Offset Register(RW)
VTOR = 0xE000ED08,          
// Application Interrupt and Reset Control Register(RW)
AIRCR = 0xE000ED0C, 
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
SCR = 0xE000ED10,    

// System Handler Control and State Register
// Controls and provides the active and pending status of system 
// exceptions.
// [18] USGFAULTENA 0 = Disable UsageFault.
//                  1 = Enable UsageFault.
// [17] BUSFAULTENA 0 = Disable BusFault.
//                  1 = Enable BusFault.
// [16] MEMFAULTENA 0 = Disable MemManage fault.
//                  1 = Enable MemManage fault.   
SHCSR = 0xE000ED24,           
                            
// CFSR(RW) 0x00000000
// Write a one to a register bit to clear the corresponding fault.
// [31:16] UsageFault Provides information on UsageFault exceptions
// [15:8] BusFault Provides information on BusFault exceptions
// [7:0] MemManage Provides information on MemManage exceptions 
CFSR = 0xE000ED28,       

CPUID = 0xE000ED00,

SHPR1 = 0xE000ED18, 
SHPR2 = 0xE000ED1C,  

DBGMCU_CR = 0xE0042004,

// The Data Watchpoint and Trace Unit
DWT = 0xE0001000,

// Cortex M33
// Non-secure Access Control Register
NSACR = 0xE000ED8C, 

FP_CTRL = 0xE0002000,
DFSR = 0xE000ED30,
DHCSR = 0xE000EDF0,
DEMCR = 0xE000EDFC,
UFSR = 0xE002ED2A,
DWT_CTL = 0xE0001000,
SFSR = 0xE000EDE4,
};

enum string ARMv8_M_SCB_REGS = q{
CPACR = 0xE000ED88,
CPACR_S = CPACR,
CPACR_NS = 0xE002ED88, 

FPCCR = 0xE000EF34, 
FPCCR_S = FPCCR,
FPCCR_NS = 0xE002EF34,

CPPWR = 0xE000E00C,
CPPWR_S = CPPWR,
CPPWR_NS = 0xE002E00C,
};     

enum string ARMv7_M_SCB_REGS = q{
// Coprocessor Access Control Register
// Specifies the access privileges for coprocessors.
CPACR = 0xE000ED88,
FPCCR = 0xE000EF34,
CPPWR = 0xE000E00C,
};         

mixin(() {
    string code = "enum scb_reg : uint {\n";

    code ~= SCB_REGS;

version (ARMv7_M) {
    code ~= ARMv7_M_SCB_REGS;
}

version (ARMv8_M) {
    code ~= ARMv8_M_SCB_REGS;
}

    static foreach (n; 0 .. 126)
    {
        code ~= format(
            "FP_COMP%d = 0x%X,\n",
            n,
            0xE0002008 + 4 * n
        );
    }

    static foreach (n; 0 .. 14)
    {
        code ~= format(
            "DWT_FUNCTION%d = 0x%X,\n",
            n,
            0xE0001028 + 16 * n
        );
    }

    static foreach (n; 0 .. 14)
    {
        code ~= format(
            "DWT_COMP%d = 0x%X,\n",
            n,
            0xE0001020 + 16 * n
        );
    }

    static foreach (n; 0 .. 16)
    {
        code ~= format(
            "NVIC_IABR%d = 0x%X,\n",
            n,
            0xE000E300 + 4 * n
        );
    }

    static foreach (n; 0 .. 16)
    {
        code ~= format(
            "NVIC_ISER%d = 0x%X,\n",
            n,
            0xE000E100 + 4 * n
        );
    }

    static foreach (n; 0 .. 16)
    {
        code ~= format(
            "NVIC_ISPR%d = 0x%X,\n",
            n,
            0xE000E200 + 4 * n
        );
    }

    static foreach (n; 0 .. 16)
    {
        code ~= format(
            "NVIC_ICPR%d = 0x%X,\n",
            n,
            0xE000E280 + 4 * n
        );
    }

    code ~= "}\n";

    return code;
}());                 
                            
mixin(generateAliases!scb_reg.aliases);                       
                            
                            
                            
                            
