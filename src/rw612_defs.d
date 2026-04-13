import std.traits;
import std.array;

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

mixin(generateAliases!rw612_peripheral_reg.aliases);

enum rw612_peripheral_reg : uint {

// Power management unit
// 4003_1000h
// Power mode control register 32 RW 0000_0000h
PWR_MODE = 0x4003_1000,
// Power mode status register 32 R 0000_0000h
PWR_MODE_STATUS = 0x4003_1004,
// sys reset enable resister 32 RW 0000_0000h
SYS_RST_EN = 0x4003_1008,
// Reset status Register 32 R 0000_0000h
SYS_RST_STATUS = 0x4003_100C,
// sys reset clear resister 32 RW 0000_0000h
SYS_RST_CLR = 0x4003_1010,
// Wakeup Level Register 32 RW 0000_0003h
WAKEUP_LEVEL = 0x4003_1014,
// Wakeup Mask Interrupt Register 32 RW 0000_0000h
WAKEUP_MASK = 0x4003_1018,
// Wakeup status register 32 R 0000_0000h
WAKEUP_STATUS = 0x4003_101C,
// 20h Wake up source clear register (WAKE_SRC_CLR) 32 RW 0000_0000h
// 24h Wake up done register (WL_BLE_WAKEUP_DONE) 32 RW 0000_0000h
// CAU sleep clock control register 32 RW 0000_0002h
CAU_SLP_CTRL = 0x4003_1028,
// 2Ch soc_ciu_rdy register (SOC_CIU_RDY) 32 R 0000_0004h
// 30h pulse in register (CAPT_PULSE) 32 RW 0000_0000h
// 34h capt_pulse_base_val (CAPT_PULSE_BASE_VAL) 32 RW 0000_0000h
// 38h capt_pulse_val (CAPT_PULSE_VAL) 32 R 0000_0000h
// 3Ch XTAL32k Control Register (XTAL32K_CTRL) 32 RW 0000_3300h
// 44h PMIP BUCK LEVEL (PMIP_BUCK_LVL) 32 RW 6060_6060h
// 48h PMIP BUCK ctrl (PMIP_BUCK_CTRL) 32 RW 0000_0000h
// 4Ch PMIP LDO level ctrl (PMIP_LDO_LVL) 32 RW 0000_0044h
// 50h PMIP reset request register (PMIP_RST) 32 RW 0000_0000h
// 5Ch BOD register (BOD) 32 RW 0000_0000h
// 60h mem configuration register (MEM_CFG) 32 RW 0000_0000h
// 64h reset disable register (RESET_DISABLE) 32 RW 0000_0001h
// 68h WLAN Control Register (WLAN_CTRL) 32 RW 0000_000Ch
// 6Ch BLEControl Register (BLE_CTRL) 32 RW 0000_000Ch
// Wakeup PM2 state Mask Interrupt Register 32 RW 0000_0000h
WAKEUP_PM2_MASK1 = 0x4003_1088,
// soc mem pdwn register 32 RW 0000_0003h
SOC_MEM_PDWN = 0x4003_1074,
// Wakeup PM2 state Mask Interrupt Register 32 RW 0000_0000h
WAKEUP_PM2_MASK0 = 0x4003_1084,


// 88h PLL control register 32 RW 0002_9D00h
PLL_CTRL = 0x4000_3088,
// 90h source clock gate control 32 RW 0000_00FFh
SOURCE_CLK_GATE = 0x4000_3090,

CLKTREE_CTRL_SIX_REG = 0x450020D8,
X = 0x450020E8,
Y = 0x45002048,
Z = 0x45002068,

// FRG PLL clock divider 32 RW 4000_0000h
FRGPLLCLKDIV = 0x400216FC,

// Peripheral reset control 2 32 RW 0C00_0005h
PRSTCTL2 = 0x4000_0018,

// Peripheral reset control 2 32 RW C000_011Fh
RSTCTL1_PRSTCTL2 = 0x40020018,

// Peripheral reset control 0 32 RW F351_0F00h
PRSTCTL0 = 0x4000_0010,

// Peripheral reset control 1 32 RW 0F03_0007h
RSTCTL0_PRSTCTL1 = 0x4000_0014,

// Peripheral reset control 1 32 RW 8001_0003h
RSTCTL1_PRSTCTL1 = 0x4002_0014,
// Peripheral reset control 0 32 RW 0140_0F00h
RSTCTL1_PRSTCTL0 = 0x4002_0010,

// MCI_IO_MUX base address: 4000_4000h
// flexcomm1 function sel 32 RW 0000_0000h
FC1 = 0x4000_4008,
// function sel 32 RW 0000_0000h
FSEL = 0x4000_4020,
// ctimer input function sel 32 RW 0000_0000h
C_TIMER_IN = 0x4000_4024,
// ctimer output function sel 32 RW 0000_0000h
C_TIMER_OUT = 0x4000_4028,
// sctimer function sel 32 RW 0000_0000h
SC_TIMER = 0x4000_402C,
// security GPIO sel 32 RW 0000_0000h
S_GPIO = 0x4000_4000,
// GPIO[31:0] sel 32 RW 0000_0000h
GPIO_GRP0 = 0x4000_4030,
// flexcomm2 function sel 32 RW 0000_0000h
FC2 = 0x4000_400C,
// flexcomm0 function sel 32 RW 0000_0000h
FC0 = 0x4000_4004,
FC3 = 0x4000_4010,
// GPIO[63:32] sel (GPIO_GRP1) 32 RW 0000_0000h
GPIO_GRP1 = 0x4000_4034,
FC_14 = 0x4000401C,

// OSTIMER base address: 4013_B000h
// EVTIMER Low Register 32 R 0000_0000h
EVTIMERL = 0x4013_B000,
// EVTIMER High Register 32 R 0000_0000h
EVTIMERH = 0x4013_B004,
// OS Event Timer Control Register for CPU 32 RW 0000_0000h
OSEVENT_CTRL = 0x4013_B01C,

// MRT0 base address: 4002_D000h
// Module Configuration 32 RW See section
MRT0_MODCFG = 0x4002D0F0,
MRT1_MODCFG = 0x4003F0F0,

// GPIO base address: 4010_0000h
PIN0 = 0x4010_2100,
PIN1 = 0x4010_2104,
DIR0 = 0x4010_2000,
DIR1 = 0x4010_2004,
// LCDIC base address: 4012_8000h
// Baseline Control Register 0 (TO_CTRL) 32 RW 0000_0101h
LCDIC_TO_CTRL = 0x40128028,
}