import std.traits;
import std.array;

template generateAliases(alias E)
{
    enum string aliases = generate();

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

mixin(generateAliases!nrf52_peripheral_reg.aliases);

enum nrf52_peripheral_reg : uint {
// Start RTC COUNTER
RTC1_TASKS_START = 0x40011000,          
// Stop RTC COUNTER
RTC1_TASKS_STOP = 0x40011004,       
// Clear RTC COUNTER
RTC1_TASKS_CLEAR = 0x40011008,       
// Set COUNTER to 0xFFFFF0
RTC1_TASKS_TRIGOVRFLW = 0x4001100C,     
// Event on COUNTER increment
RTC1_EVENTS_TICK = 0x40011100,       
// Event on COUNTER overflow
RTC1_EVENTS_OVRFLW = 0x40011104,      
// Compare event on CC[0] match
RTC1_EVENTS_COMPARE_0 = 0x40011140,       
// Compare event on CC[1] match
RTC1_EVENTS_COMPARE_1 = 0x40011144,      
// Compare event on CC[2] match
RTC1_EVENTS_COMPARE_2 = 0x40011148,      
// Compare event on CC[3] match
RTC1_EVENTS_COMPARE_3 = 0x4001114C,         
// Enable interrupt
RTC1_INTENSET = 0x40011304,       
// Disable interrupt
RTC1_INTENCLR = 0x40011308,     
// Enable or disable event routing
RTC1_EVTEN = 0x40011340,     
// Enable event routing
RTC1_EVTENSET = 0x40011344,       
// Disable event routing
RTC1_EVTENCLR = 0x40011348,       
// Current COUNTER value
// Reset 0x00000000 
RTC1_COUNTER = 0x40011504,         
// 12 bit prescaler for COUNTER frequency (32768/(PRESCALER+1)). Must be written when RTC is
// stopped.
RTC1_PRESCALER = 0x40011508,         
// Compare register 0
RTC1_CC_0 = 0x40011540,        
// Compare register 1
RTC1_CC_1 = 0x40011544,        
// Compare register 2
RTC1_CC_2 = 0x40011548,        
// Compare register 3
RTC1_CC_3 = 0x4001154C,    

// Start HFXO crystal oscillator
CLOCK_TASKS_HFCLKSTART = 0x40000000,         
// Stop HFXO crystal oscillator 
CLOCK_TASKS_HFCLKSTOP = 0x40000004,          
// Start LFCLK
CLOCK_TASKS_LFCLKSTART = 0x40000008,         
// Stop LFCLK 
CLOCK_TASKS_LFCLKSTOP = 0x4000000C,   
// Start calibration of LFRC       
CLOCK_TASKS_CAL = 0x40000010,         
// Start calibration timer
CLOCK_TASKS_CTSTART = 0x40000014,     
// Stop calibration timer     
CLOCK_TASKS_CTSTOP = 0x40000018,      
// HFXO crystal oscillator started
CLOCK_EVENTS_HFCLKSTARTED = 0x40000100,         
// LFCLK started
CLOCK_EVENTS_LFCLKSTARTED = 0x40000104,  
// Calibration of LFRC completed        
CLOCK_EVENTS_DONE = 0x4000010C,          
// Calibration timer timeout
CLOCK_EVENTS_CTTO = 0x40000110,          
// Calibration timer has been started and is ready to process new tasks
CLOCK_EVENTS_CTSTARTED = 0x40000128,         
// Calibration timer has been stopped and is ready to process new tasks 
CLOCK_EVENTS_CTSTOPPED = 0x4000012C,  
// Enable interrupt       
CLOCK_INTENSET = 0x40000304,         
// Disable interrupt 
CLOCK_INTENCLR = 0x40000308,         
// Status indicating that HFCLKSTART task has been triggered
CLOCK_HFCLKRUN = 0x40000408,          
// HFCLK status
CLOCK_HFCLKSTAT = 0x4000040C,         
// Status indicating that LFCLKSTART task has been triggered
CLOCK_LFCLKRUN = 0x40000414,          
// LFCLK status
CLOCK_LFCLKSTAT = 0x40000418, 
// Copy of LFCLKSRC register, set when LFCLKSTART task was triggered
CLOCK_LFCLKSRCCOPY = 0x4000041C,    
// Clock source for the LFCLK     
CLOCK_LFCLKSRC = 0x40000518,        
// HFXO debounce time. The HFXO is started by triggering the TASKS_HFCLKSTART task.
CLOCK_HFXODEBOUNCE = 0x40000528,       
// Calibration timer interval
// This register is retained.
CLOCK_CTIV = 0x40000538,        
// Clocking options for the trace port debug interface
CLOCK_TRACECONFIG = 0x4000055C,      
// LFRC mode configuration   
CLOCK_LFRCMODE = 0x400005B4,    

// Software force enable APPROTECT mechanism until next reset.
APPROTECT_FORCEPROTECT = 0x40000550,
// Software disable APPROTECT mechanism   
APPROTECT_DISABLE = 0x40000558, 

// Enable DC/DC converter for REG1 stage
POWER_DCDCEN = 0x40000578,
// Enable DC/DC converter for REG0 stage 
POWER_DCDCEN0 = 0x40000580, 

// Event generated from multiple input GPIO pins with SENSE mechanism enabled
GPIOTE_EVENTS_PORT = 0x4000617C, 

// Channel 19 event endpoint
PPI_CH_19_EEP = 0x4001F5A8,
// Channel 19 task endpoint 
PPI_CH_19_TEP = 0x4001F5AC, 

// Task starting the random number generator
RNG_TASKS_START = 0x4000D000,        
// Task stopping the random number generator
RNG_TASKS_STOP = 0x4000D004,       
// Event being generated for every new random 
// number written to the VALUE register
RNG_EVENTS_VALRDY = 0x4000D100, 
// Shortcuts between local events and tasks         
RNG_SHORTS = 0x4000D200,
// Enable interrupt
RNG_INTENSET = 0x4000D304,
// Disable interrupt
RNG_INTENCLR = 0x4000D308,
// Configuration register
RNG_CONFIG = 0x4000D504,
// Output random number
RNG_VALUE = 0x4000D508,

// Start UART receiver
UART0_TASKS_STARTRX = 0x40002000, 
// Stop UART receiver       
UART0_TASKS_STOPRX = 0x40002004,
// Start UART transmitter
UART0_TASKS_STARTTX = 0x40002008,       
// Stop UART transmitter
UART0_TASKS_STOPTX = 0x4000200C,        
// Suspend UART
UART0_TASKS_SUSPEND = 0x4000201C,         
// CTS is activated (set low). Clear To Send.
UART0_EVENTS_CTS = 0x40002100,      
// CTS is deactivated (set high). Not Clear To Send.
UART0_EVENTS_NCTS = 0x40002104,       
// Data received in RXD
UART0_EVENTS_RXDRDY = 0x40002108,        
// Data sent from TXD
UART0_EVENTS_TXDRDY = 0x4000211C,        
// Error detected
UART0_EVENTS_ERROR = 0x40002124,       
// Receiver timeout
UART0_EVENTS_RXTO = 0x40002144,     
// Shortcuts between local events and tasks
UART0_SHORTS = 0x40002200,      
// Enable interrupt
UART0_INTENSET = 0x40002304,        
// Disable interrupt
UART0_INTENCLR = 0x40002308,        
// Error source
UART0_ERRORSRC = 0x40002480,        
// Enable UART
UART0_ENABLE = 0x40002500,       
// Pin select for RTS
UART0_PSEL_RTS = 0x40002508,        
// Pin select for TXD
UART0_PSEL_TXD = 0x4000250C,        
// Pin select for CTS
UART0_PSEL_CTS = 0x40002510,        
// Pin select for RXD
UART0_PSEL_RXD = 0x40002514,        
// RXD: RXD register. Register is cleared on read and the double 
// buffered byte will be moved to RXD if it exists.
UART0_RXD = 0x40002518,        
// TXD register
UART0_TXD = 0x4000251C,        
// Baud rate. Accuracy depends on the HFCLK source selected.
UART0_BAUDRATE = 0x40002524,        
// Configuration of parity and hardware flow control
UART0_CONFIG = 0x4000256C,   
// Write GPIO port
GPIO_OUT = 0x50000504,
// Set individual bits in GPIO port
GPIO_OUTSET = 0x50000508,          
// Clear individual bits in GPIO port
GPIO_OUTCLR = 0x5000050C,
// Read GPIO port
GPIO_IN = 0x50000510,
// Direction of GPIO pins
GPIO_DIR = 0x50000514,
// DIR set register
GPIO_DIRSET = 0x50000518,        
// DIR clear register
GPIO_DIRCLR = 0x5000051C,         
// Latch register indicating what GPIO pins that have met the criteria set in the PIN_CNF[n].SENSE
// registers 
GPIO_LATCH = 0x50000520,     
// Select between default DETECT signal behavior and LDETECT mode     
GPIO_DETECTMODE = 0x50000524,
// Configuration of GPIO pins
GPIO_PIN_CNF_0  = 0x50000700,       
GPIO_PIN_CNF_1  = 0x50000704,       
GPIO_PIN_CNF_2  = 0x50000708,       
GPIO_PIN_CNF_3  = 0x5000070C,       
GPIO_PIN_CNF_4  = 0x50000710,       
GPIO_PIN_CNF_5  = 0x50000714,       
GPIO_PIN_CNF_6  = 0x50000718,       
GPIO_PIN_CNF_7  = 0x5000071C,       
GPIO_PIN_CNF_8  = 0x50000720,       
GPIO_PIN_CNF_9  = 0x50000724,       
GPIO_PIN_CNF_10 = 0x50000728,        
GPIO_PIN_CNF_11 = 0x5000072C,        
GPIO_PIN_CNF_12 = 0x50000730,        
GPIO_PIN_CNF_13 = 0x50000734,        
GPIO_PIN_CNF_14 = 0x50000738,        
GPIO_PIN_CNF_15 = 0x5000073C,        
GPIO_PIN_CNF_16 = 0x50000740,        
GPIO_PIN_CNF_17 = 0x50000744,        
GPIO_PIN_CNF_18 = 0x50000748,        
GPIO_PIN_CNF_19 = 0x5000074C,        
GPIO_PIN_CNF_20 = 0x50000750,        
GPIO_PIN_CNF_21 = 0x50000754,        
GPIO_PIN_CNF_22 = 0x50000758,        
GPIO_PIN_CNF_23 = 0x5000075C,        
GPIO_PIN_CNF_24 = 0x50000760,        
GPIO_PIN_CNF_25 = 0x50000764,        
GPIO_PIN_CNF_26 = 0x50000768,        
GPIO_PIN_CNF_27 = 0x5000076C,        
GPIO_PIN_CNF_28 = 0x50000770,        
GPIO_PIN_CNF_29 = 0x50000774,        
GPIO_PIN_CNF_30 = 0x50000778,        
GPIO_PIN_CNF_31 = 0x5000077C,   

// Flush RX FIFO into RX buffer
UARTE0_TASKS_FLUSHRX = 0x4000202C,         
// Receive buffer is filled up 
UARTE0_EVENTS_ENDRX = 0x40002110,          
// Last TX byte transmitted
UARTE0_EVENTS_ENDTX  = 0x40002120,         
// UART receiver has started
UARTE0_EVENTS_RXSTARTED = 0x4000214C,          
// UART transmitter has started
UARTE0_EVENTS_TXSTARTED = 0x40002150,          
// Transmitter stopped
UARTE0_EVENTS_TXSTOPPED = 0x40002158,
// Enable or disable interrupt          
UARTE0_INTEN = 0x40002300,          
// Disable interrupt
UARTE0_INTENCLR = 0x40002308,          
// Error source
// This register is read/write one to clear.
UARTE0_ERRORSRC = 0x40002480,                           
// Data pointer                                
UARTE0_RXD_PTR  = 0x40002534,         
// Maximum number of bytes in receive buffer
UARTE0_RXD_MAXCNT = 0x40002538,          
// Number of bytes transferred in the last transaction
UARTE0_RXD_AMOUNT = 0x4000253C,        
// Data pointer  
UARTE0_TXD_PTR  = 0x40002544,          
// Maximum number of bytes in transmit buffer
UARTE0_TXD_MAXCNT = 0x40002548,        
// Number of bytes transferred in the last transaction
UARTE0_TXD_AMOUNT = 0x4000254C,          

// Activate QSPI interface
QPSI_TASKS_ACTIVATE = 0x40029000,         
// Start transfer from external flash memory to internal RAM
QPSI_TASKS_READSTART = 0x40029004,          
// Start transfer from internal RAM to external flash memory
QPSI_TASKS_WRITESTART = 0x40029008,          
// Start external flash memory erase operation
QPSI_TASKS_ERASESTART = 0x4002900C,         
// Deactivate QSPI interface 
QPSI_TASKS_DEACTIVATE = 0x40029010,         
// QSPI peripheral is ready. This event will be generated as a response to any QSPI task.
QPSI_EVENTS_READY = 0x40029100,
// Enable or disable interrupt          
QPSI_INTEN = 0x40029300,       
// Enable interrupt
QPSI_INTENSET = 0x40029304,          
// Disable interrupt
QPSI_INTENCLR = 0x40029308,        
// Enable QSPI peripheral and acquire the pins selected in PSELn registers 
QPSI_ENABLE = 0x40029500,          
// Flash memory source address
QPSI_READ_SRC = 0x40029504,        
// RAM destination address
QPSI_READ_DST = 0x40029508,          
// Read transfer length
QPSI_READ_CNT = 0x4002950C,          
// Flash destination address
QPSI_WRITE_DST = 0x40029510,          
// RAM source address
QPSI_WRITE_SRC = 0x40029514,        
// Write transfer length  
QPSI_WRITE_CNT = 0x40029518,        
// Start address of flash block to be erased
QPSI_ERASE_PTR = 0x4002951C,         
// Size of block to be erased.
QPSI_ERASE_LEN = 0x40029520,        
// Pin select for serial clock SCK 
QPSI_PSEL_SCK = 0x40029524,         
// Pin select for chip select signal CSN.
QPSI_PSEL_CSN = 0x40029528,          
// Pin select for serial data MOSI/IO0.
QPSI_PSEL_IO0 = 0x40029530,        
// Pin select for serial data MISO/IO1.  
QPSI_PSEL_IO1 = 0x40029534,        
// Pin select for serial data IO2.
QPSI_PSEL_IO2 = 0x40029538,       
// Pin select for serial data IO3.   
QPSI_PSEL_IO3 = 0x4002953C,       
// Address offset into the external memory for Execute in Place operation.
QPSI_XIPOFFSET = 0x40029540,       
// Interface configuration. 
QPSI_IFCONFIG0 = 0x40029544,       
// Interface configuration.
QPSI_IFCONFIG1 = 0x40029600,     
// Status register.    
QPSI_STATUS = 0x40029604,       
// Set the duration required to enter/exit deep power-down mode (DPM). 
QPSI_DPMDUR = 0x40029614,       
// Extended address configuration.
QPSI_ADDRCONF = 0x40029624,         
// Custom instruction configuration register.
QPSI_CINSTRCONF = 0x40029634,       
// Custom instruction data register 0.
QPSI_CINSTRDAT0 = 0x40029638,       
// Custom instruction data register 1. 
QPSI_CINSTRDAT1 = 0x4002963C,      
// SPI interface timing           
QPSI_IFTIMING = 0x40029640,

// Start RTC COUNTER
RTC0_TASKS_START = 0x4000B000,          
// Stop RTC COUNTER
RTC0_TASKS_STOP = 0x4000B004,       
// Clear RTC COUNTER
RTC0_TASKS_CLEAR = 0x4000B008,       
// Set COUNTER to 0xFFFFF0
RTC0_TASKS_TRIGOVRFLW = 0x4000B00C,     
// Event on COUNTER increment
RTC0_EVENTS_TICK = 0x4000B100,       
// Event on COUNTER overflow
RTC0_EVENTS_OVRFLW = 0x4000B104,      
// Compare event on CC[0] match
RTC0_EVENTS_COMPARE_0 = 0x4000B140,       
// Compare event on CC[1] match
RTC0_EVENTS_COMPARE_1 = 0x4000B144,      
// Compare event on CC[2] match
RTC0_EVENTS_COMPARE_2 = 0x4000B148,      
// Compare event on CC[3] match
RTC0_EVENTS_COMPARE_3 = 0x4000B14C,         
// Enable interrupt
RTC0_INTENSET = 0x4000B304,       
// Disable interrupt
RTC0_INTENCLR = 0x4000B308,     
// Enable or disable event routing
RTC0_EVTEN = 0x4000B340,     
// Enable event routing
RTC0_EVTENSET = 0x4000B344,       
// Disable event routing
RTC0_EVTENCLR = 0x4000B348,       
// Current COUNTER value
RTC0_COUNTER = 0x4000B504,         
// 12 bit prescaler for COUNTER frequency (32768/(PRESCALER+1)). Must be written when RTC is
// stopped.
RTC0_PRESCALER = 0x4000B508,         
// Compare register 0
RTC0_CC_0 = 0x4000B540,        
// Compare register 1
RTC0_CC_1 = 0x4000B544,        
// Compare register 2
RTC0_CC_2 = 0x4000B548,        
// Compare register 3
RTC0_CC_3 = 0x4000B54C,        

// Start ECB block encrypt
ECB_TASKS_STARTECB = 0x4000E000,         
// Abort a possible executing ECB operation 
ECB_TASKS_STOPECB = 0x4000E004,          
// ECB block encrypt complete
ECB_EVENTS_ENDECB = 0x4000E100,          
// ECB block encrypt aborted because of a STOPECB task or due to an error
ECB_EVENTS_ERROREC = 0x4000E104,    
// Enable interrupt      
ECB_INTENSET = 0x4000E304,          
// Disable interrupt
ECB_INTENCLR = 0x4000E308,          
// ECB block encrypt memory pointers 
ECB_ECBDATAPTR = 0x4000E504,   

ACL_0_ADDR = 0x4001E800,  // Start address of region to protect. The start address must be word-aligned.
ACL_0_SIZE = 0x4001E804,  // Size of region to protect counting from address ACL[0].ADDR. Writing a '0' has no effect.
ACL_0_PERM = 0x4001E808,  // Access permissions for region 0 as defined by start address ACL[0].ADDR and size ACL[0].SIZE
ACL_1_ADDR = 0x4001E810,  // Start address of region to protect. The start address must be word-aligned.
ACL_1_SIZE = 0x4001E814,  // Size of region to protect counting from address ACL[1].ADDR. Writing a '0' has no effect.
ACL_1_PERM = 0x4001E818,  // Access permissions for region 1 as defined by start address ACL[1].ADDR and size ACL[1].SIZE
ACL_2_ADDR = 0x4001E820,  // Start address of region to protect. The start address must be word-aligned.
ACL_2_SIZE = 0x4001E824,  // Size of region to protect counting from address ACL[2].ADDR. Writing a '0' has no effect.
ACL_2_PERM = 0x4001E828,  // Access permissions for region 2 as defined by start address ACL[2].ADDR and size ACL[2].SIZE
ACL_3_ADDR = 0x4001E830,  // Start address of region to protect. The start address must be word-aligned.
ACL_3_SIZE = 0x4001E834,  // Size of region to protect counting from address ACL[3].ADDR. Writing a '0' has no effect.
ACL_3_PERM = 0x4001E838,  // Access permissions for region 3 as defined by start address ACL[3].ADDR and size ACL[3].SIZE
ACL_4_ADDR = 0x4001E840,  // Start address of region to protect. The start address must be word-aligned.
ACL_4_SIZE = 0x4001E844,  // Size of region to protect counting from address ACL[4].ADDR. Writing a '0' has no effect.
ACL_4_PERM = 0x4001E848,  // Access permissions for region 4 as defined by start address ACL[4].ADDR and size ACL[4].SIZE
ACL_5_ADDR = 0x4001E850,  // Start address of region to protect. The start address must be word-aligned.
ACL_5_SIZE = 0x4001E854,  // Size of region to protect counting from address ACL[5].ADDR. Writing a '0' has no effect.
ACL_5_PERM = 0x4001E858,  // Access permissions for region 5 as defined by start address ACL[5].ADDR and size ACL[5].SIZE
ACL_6_ADDR = 0x4001E860,  // Start address of region to protect. The start address must be word-aligned.
ACL_6_SIZE = 0x4001E864,  // Size of region to protect counting from address ACL[6].ADDR. Writing a '0' has no effect.
ACL_6_PERM = 0x4001E868,  // Access permissions for region 6 as defined by start address ACL[6].ADDR and size ACL[6].SIZE
ACL_7_ADDR = 0x4001E870,  // Start address of region to protect. The start address must be word-aligned.
ACL_7_SIZE = 0x4001E874,  // Size of region to protect counting from address ACL[7].ADDR. Writing a '0' has no effect.
ACL_7_PERM = 0x4001E878,  // Access permissions for region 7 as defined by start address ACL[7].ADDR and size ACL[7].SIZE              

NVMC_READY = 0x4001E400, // Ready flag
NVMC_READYNEXT = 0x4001E408, // Ready flag
NVMC_CONFIG = 0x4001E504, // Configuration register
NVMC_ERASEPAGE = 0x4001E508, // Register for erasing a page in code area
NVMC_ERASEALL = 0x4001E50C, // Register for erasing all non-volatile user memory
NVMC_ERASEUICR = 0x4001E514, // Register for erasing user information configuration registers
NVMC_ERASEPAGEPARTIAL = 0x4001E518, // Register for partial erase of a page in code area
NVMC_ERASEPAGEPARTIALCFG = 0x4001E51C, // Register for partial erase configuration
NVMC_ICACHECNF = 0x4001E540, // I-code cache configuration register
NVMC_IHIT = 0x4001E538, // I-code cache hit counter
NVMC_IMISS = 0x4001E54C, // I-code cache miss counter
}