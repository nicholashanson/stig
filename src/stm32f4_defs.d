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
RCC_APB1RSTR = 0x40023820,         
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
OTG_FS_GOTGCTL = 0x50000000, 
OTG_FS_GOTGINT = 0x50000004,
OTG_FS_GAHBCFG = 0x50000008,  
OTG_FS_GUSBCFG = 0x5000000C,
// Bit 0 CSRST: Core soft reset
// Resets the HCLK and PCLK domains as follows:
// Clears the interrupts and all the CSR register bits except for the following bits:
// – RSTPDMODL bit in OTG_FS_PCGCCTL
// – GAYEHCLK bit in OTG_FS_PCGCCTL
// – PWRCLMP bit in OTG_FS_PCGCCTL
// – STPPCLK bit in OTG_FS_PCGCCTL
// – FSLSPCS bit in OTG_FS_HCFG
// – DSPD bit in OTG_FS_DCFG
// All module state machines (except for the AHB slave unit) are reset to the Idle state, and all
// the transmit FIFOs and the receive FIFO are flushed.
// Any transactions on the AHB Master are terminated as soon as possible, after completing the
// last data phase of an AHB transfer. Any transactions on the USB are terminated immediately.
// The application can write to this bit any time it wants to reset the core. This is a self-clearing
// bit and the core clears this bit after all the necessary logic is reset in the core, which can take
// several clocks, depending on the current state of the core. Once this bit has been cleared,
// the software must wait at least 3 PHY clocks before accessing the PHY domain
// (synchronization delay). The software must also check that bit 31 in this register is set to 1
// (AHB Master is Idle) before starting any operation.
// Typically, the software reset is used during software development and also when you
// dynamically change the PHY selection bits in the above listed USB configuration registers.
// When you change the PHY, the corresponding clock for the PHY is selected and used in the
// PHY domain. Once a new clock is selected, the PHY domain has to be reset for proper
// operation.
OTG_FS_GRSTCTL = 0x50000010,
OTG_FS_GCCFG = 0x50000038, 

// OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXFx)
// (x = 1..3, where x is the FIFO_number)
OTG_FS_DIEPTXF1 = 0x50000104,
OTG_FS_DIEPTXF2 = 0x50000108,
OTG_FS_DIEPTXF3 = 0x5000010C,

// OTG_FS device endpoint-x transfer size register (OTG_FS_DIEPTSIZx)
// (x = 1..3, where x = Endpoint_number)
// Address offset: 0x910 + 0x20 * x
// Reset value: 0x0000 0000
OTG_FS_DIEPTSIZ1 = 0x50000910,
OTG_FS_DIEPTSIZ2 = 0x50000930,
OTG_FS_DIEPTSIZ3 = 0x50000950,

// OTG device endpoint x control register (OTG_FS_DIEPCTLx) (x = 1..3, where
// x = Endpoint_number)
// Address offset: 0x900 + 0x20 * x
// Reset value: 0x0000 0000
OTG_FS_DIEPCTL1 = 0x50000900,
OTG_FS_DIEPCTL2 = 0x50000920,
OTG_FS_DIEPCTL3 = 0x50000930,


GPIOA_MODER = 0x40020000, 
GPIOA_OTYPER = 0x40020004,
GPIOA_OSPEEDR = 0x40020008,
GPIOA_PUPDR = 0x4002000C,
GPIOA_IDR = 0x40020010,
GPIOA_ODR = 0x40020014,
GPIOA_AFRL = 0x40020020,
GPIOA_AFRH = 0x40020024,

GPIOB_MODER = 0x40020400, 
GPIOB_OTYPER = 0x40020404,
GPIOB_OSPEEDR = 0x40020408,
GPIOB_PUPDR = 0x4002040C,
GPIOB_IDR = 0x40020410,
GPIOB_ODR = 0x40020414,
GPIOB_AFRL = 0x40020420,
GPIOB_AFRH = 0x40020424,

GPIOC_MODER = 0x40020800, 
GPIOC_OTYPER = 0x40020804,
GPIOC_OSPEEDR = 0x40020808,
GPIOC_PUPDR = 0x4002080C,
GPIOC_IDR = 0x40020810,
GPIOC_ODR = 0x40020814,
GPIOC_AFRL = 0x40020820,
GPIOC_AFRH = 0x40020824,

GPIOD_MODER = 0x40020C00, 
GPIOD_OTYPER = 0x40020C04,
GPIOD_OSPEEDR = 0x40020C08,
GPIOD_PUPDR = 0x40020C0C,
GPIOD_IDR = 0x40020C10,
GPIOD_ODR = 0x40020C14,
GPIOD_AFRL = 0x40020C20,
GPIOD_AFRH = 0x40020C24,

GPIOE_MODER = 0x40021000, 
GPIOE_OTYPER = 0x40021004,
GPIOE_OSPEEDR = 0x40021008,
GPIOE_PUPDR = 0x4002100C,
GPIOE_IDR = 0x40021010,
GPIOE_ODR = 0x40021014,
GPIOE_AFRL = 0x40021020,
GPIOE_AFRH = 0x40021024,

GPIOF_MODER = 0x40021400, 
GPIOF_OTYPER = 0x40021404,
GPIOF_OSPEEDR = 0x40021408,
GPIOF_PUPDR = 0x4002140C,
GPIOF_IDR = 0x40021410,
GPIOF_ODR = 0x40021414,
GPIOF_AFRL = 0x40021420,
GPIOF_AFRH = 0x40021424,

GPIOG_MODER = 0x40021800, 
GPIOG_OTYPER = 0x40021804,
GPIOG_OSPEEDR = 0x40021808,
GPIOG_PUPDR = 0x4002180C,
GPIOG_IDR = 0x40021810,
GPIOG_ODR = 0x40021814,
GPIOG_AFRL = 0x40021820,
GPIOG_AFRH = 0x40021824,

GPIOH_MODER = 0x40021C00, 
GPIOH_OTYPER = 0x40021C04,
GPIOH_OSPEEDR = 0x40021C08,
GPIOH_PUPDR = 0x40021C0C,
GPIOH_IDR = 0x40021C10,
GPIOH_ODR = 0x40021C14,
GPIOH_AFRL = 0x40021C20,
GPIOH_AFRH = 0x40021C24,

GPIOI_MODER = 0x40022000, 
GPIOI_OTYPER = 0x40022004,
GPIOI_OSPEEDR = 0x40022008,
GPIOI_PUPDR = 0x4002200C,
GPIOI_IDR = 0x40022010,
GPIOI_ODR = 0x40022014,
GPIOI_AFRL = 0x40022020,
GPIOI_AFRH = 0x40022024,

GPIOJ_MODER = 0x40022400, 
GPIOJ_OTYPER = 0x40022404,
GPIOJ_OSPEEDR = 0x40022408,
GPIOJ_PUPDR = 0x4002240C,
GPIOJ_IDR = 0x40022410,
GPIOJ_ODR = 0x40022414,
GPIOJ_AFRL = 0x40022420,
GPIOJ_AFRH = 0x40022424,

GPIOK_MODER = 0x40022800, 
GPIOK_OTYPER = 0x40022804,
GPIOK_OSPEEDR = 0x40022808,
GPIOK_PUPDR = 0x4002280C,
GPIOK_IDR = 0x40022810,
GPIOK_ODR = 0x40022814,
GPIOK_AFRL = 0x40022820,
GPIOK_AFRH = 0x40022824,

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
FLASH_ACR = 0x40023C00,  

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
USART2_SR = 0x40004400,  
USART2_DR = 0x40004404, 
// Bits 15:4 DIV_Mantissa[11:0]: mantissa of USARTDIV
//  These 12 bits define the mantissa of the USART Divider (USARTDIV) 
USART2_BRR = 0x40004408,  
// Bit 11 ONEBIT: One sample bit method enable
// This bit allows the user to select the sample method. When the one sample bit 
// method is selected the noise detection flag (NF) is disabled.
//  0: Three sample bit method
//  1: One sample bit method
// Note: The ONEBIT feature applies only to data bits. It does not apply to 
// START bit. 
USART2_CR3 = 0x40004414,
USART2_CR1 = 0x4000440C, 
USART2_CR2 = 0x40004410, 
USART2_GPTR = 0x40004418,

PWR_CR = 0x40007000,

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
ADC1_SR = 0x40012000,
// ADC1 control register 2 (ADC1_CR2)
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
ADC1_CR2 = 0x40012008,
// ADC1 regular data register 
// Bits 15:0 DATA[15:0]: Regular data
// These bits are read-only. They contain the conversion result 
// from the regular channels.
ADC1_DR = 0x400120DC, 
// I2C1 control register 1    
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
I2C1_CR1 = 0x40005400,        
// I2C control register 2 
// Bit 26 PECBYTE: Packet error checking byte
// This bit is set by software, and cleared by hardware when 
// the PEC is transferred, or when a STOP condition or an 
// Address matched is received, also when PE = 0.
//      0: No PEC transfer
//      1: PEC transmission/reception is requested
// Note: Writing 0 to this bit has no effect.
// This bit has no effect when RELOAD is set, and in slave mode 
// when SBC = 0.        
I2C_CR2 = 0x40005404,          

TIM2_CR1 = 0x40000000,          
TIM2_CR2 = 0x40000004,          
TIM2_SMCR = 0x40000008, 

EXTI_IMR = 0x40013C00,
EXTI_EMR = 0x40013C04,
EXTI_RTSR = 0x40013C08,
EXIT_FTSR = 0x40013C0C,
EXTI_SWIER = 0x40013C10,
EXTI_PR = 0x40013C14,

TIM6_CR1 = 0x40001000,            
TIM6_CR2 = 0x40001004,           
TIM6_DIER = 0x4000100C,           
TIM6_SR = 0x40001010,           
TIM6_EGR = 0x40001014,           
TIM6_CNT = 0x40001024,           
TIM6_PSC = 0x40001028,           
TIM6_ARR = 0x4000102C,           

TIM5_CR1 = 0x40000C00,
TIM5_CR2 = 0x40000C04,
TIM5_SMCR = 0x40000C08,
TIM5_DIER = 0x40000C0C,
TIM5_SR = 0x40000C10,
TIM5_EGR = 0x40000C14,
TIM5_CCMR1 = 0x40000C18,
TIM5_CCMR2 = 0x40000C1C,
TIM5_CCER = 0x40000C20,
TIM5_CNT = 0x40000C24,
TIM5_PSC = 0x40000C28,
TIM5_ARR = 0x40000C2C,
TIM5_CCR1 = 0x40000C34,
TIM5_CCR2 = 0x40000C38,
TIM5_CCR3 = 0x40000C3C,
TIM5_CCR4 = 0x40000C40,
TIM5_DCR = 0x40000C48,
TIM5_DMAR = 0x40000C4C,
TIM5_OR = 0x40000C50,

// Bits 27, 21, 11, 5 TCIF[3:0]: 
// Stream x transfer complete interrupt flag (x = 3 to 0)
// This bit is set by hardware. It is cleared by software writing 1 
// to the corresponding bit in DMA_LIFCR register.
//      0: No transfer complete event on stream x
//      1: A transfer complete event occurred on stream x.
DMA2_LISR = 0x40026400,      
DMA2_S0CR = 0x40026410,
DMA2_S0FCR = 0x40026424,

ADC_CSR = 0x40012300,
ADC_CCR = 0x40012304,
ADC1_CR1 = 0x40012004,
ADC1_SQR1 = 0x4001202C,
ADC1_SMPR2 = 0x40012010,
ADC1_SQR3 = 0x40012034,
DMA2_S5CR = 0x40026088,
DMA2_S5FCR = 0x4002609C,
DAC_CR = 0x40007400,

USART1_SR = 0x40011000,
USART1_DR = 0x40011004,         
USART1_BRR = 0x40011008, 
USART1_CR1 = 0x4001100C, 
USART1_CR2 = 0x40011010, 
USART1_CR3 = 0x40011014, 
USART1_GPTR = 0x40011018,

USART3_SR = 0x40004800,      
USART3_DR = 0x40004804,         
USART3_BRR = 0x40004808,          
USART3_CR1 = 0x4000480C,          
USART3_CR2 = 0x40004810,          
USART3_CR3 = 0x40004814,          
USART3_GPTR = 0x40004818,    

USART6_SR = 0x40011400,
USART6_DR = 0x40011404,
USART6_BRR = 0x40011408,          
USART6_CR1 = 0x4001140C,          
USART6_CR2 = 0x40011410,          
USART6_CR3 = 0x40011414,          
USART6_GTPR = 0x40011418, 

UART7_SR = 0x40007800,
UART7_DR = 0x40007804,
UART7_BRR = 0x40007808,          
UART7_CR1 = 0x4000780C,          
UART7_CR2 = 0x40007810,          
UART7_CR3 = 0x40007814,          
UART7_GTPR = 0x40007818,   

SYSCFG_EXTICR1 = 0x40013808,          
SYSCFG_EXTICR2 = 0x4001380C,          
SYSCFG_EXTICR3 = 0x40013810,
SYSCFG_EXTICR4 = 0x40013814,

FMC_BCR1  = 0xA0000000,
FMC_BCR2  = 0xA0000008,
FMC_BCR3  = 0xA0000010,
FMC_BCR4  = 0xA0000018,
FMC_BTR1  = 0xA0000004,
FMC_BTR2  = 0xA000000C,
FMC_BTR3  = 0xA0000014,
FMC_BTR4  = 0xA000001C,
FMC_BWTR1 = 0xA0000104,
FMC_BWTR2 = 0xA000010C,
FMC_BWTR3 = 0xA0000104,
FMC_BWTR4 = 0xA000010C,
FMC_PCR2  = 0xA0000060,
FMC_PCR3  = 0xA0000080,
FMC_PCR4  = 0xA00000A0,
FMC_SR2   = 0xA0000064,
FMC_SR3   = 0xA0000084,
FMC_SR4   = 0xA00000A4,
FMC_PMEM2 = 0xA0000068,
FMC_PMEM3 = 0xA0000088,
FMC_PMEM4 = 0xA00000A8,
FMC_PATT2 = 0xA000006C,
FMC_PATT3 = 0xA000008C,
FMC_PATT4 = 0xA00000AC,
FMC_PIO4  = 0xA00000B0,
FMC_ECCR2 = 0xA0000074,
FMC_ECCR3 = 0xA0000094,
FMC_SDCR_1= 0xA0000140,
FMC_SDCR_2= 0xA0000144,
FMC_SDTR1 = 0xA0000148,
FMC_SDTR2 = 0xA000014C,
FMC_SDCMR = 0xA0000150,
FMC_SDRTR = 0xA0000154,
FMC_SDSR  = 0xA0000158,

}