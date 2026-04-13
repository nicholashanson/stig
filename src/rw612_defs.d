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



// 88h PLL control register 32 RW 0002_9D00h
PLL_CTRL = 0x4000_3088,
// 90h source clock gate control 32 RW 0000_00FFh
SOURCE_CLK_GATE = 0x4000_3090,

CLKTREE_CTRL_SIX_REG = 0x450020D8,
}