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

mixin(generateAliases!stm32f4_peripheral_reg.aliases);

enum stm32f4_peripheral_reg : uint {
// RCC_CR, Reset value: 0x0000XX83 where X is undefined.
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
RCC_CR = 0x40023800,                    
// Reset value: 0x24003010
RCC_PLLCFGR = 0x40023804,  
// RCC_CFGR
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
RCC_CFGR = 0x40023808,          
// RCC clock interrupt register (RCC_CIR)
RCC_CIR = 0x4002380C,        
// RCC_AHB1RSTR  
RCC_AHB1RSTR = 0x40023810,         
// RCC_AhB2RSTR 
RCC_AHB2RSTR = 0x40023814,         
// RCC_AHB3RSTR 
RCC_AHB3RSTR = 0x40023818,         
// RCC_APB1RSTR
RCC_APB2RSTR = 0x40023824,          
// RCC_AHB1ENR Peripheral Clock Enable Register
RCC_AHB1ENR = 0x40023830,         
RCC_AHB2ENR = 0x40023834,          
RCC_AHB3ENR = 0x40023838,
// RCC_APB1ENR Peripheral Clock Enable Register
// Bit 28 PWREN: Power interface clock enable
// This bit is set and cleared by software.
//      0: Power interface clock disabled
//      1: Power interface clock enable
RCC_APB1ENR = 0x40023840,          
// RCC_APB2ENR Peripheral Clock Enable Register
RCC_APB2ENR = 0x40023844,
// RCC AHB1 peripheral clock enable in low-power mode register          
RCC_AHB1LPENR = 0x40023850,
                        
RCC_AHB2LPENR = 0x40023854,
RCC_AHB3LPENR = 0x40023858, 
RCC_APB1LPENR = 0x40023860,
RCC_APB2LPENR = 0x40023864,  
RCC_BDCR = 0x40023870, 
// RCC_CSR
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
RCC_CSR   = 0x40023874, 
RCC_SSCGR = 0x40023888,          
RCC_PLLI2SCFGR = 0x40023884,
// Reset value: 0x2400 3000
RCC_PLLSAICFGR = 0x40023888, 
// RCC_DCKCFGR Dedicated Clock Configuration Register
RCC_DCKCFGR = 0x4002388C,    

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
OTG_GOTGCTL = 0x50000000,              
}