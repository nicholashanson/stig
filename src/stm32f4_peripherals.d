import stm32f4_defs;

uint[stm32f4_peripheral_reg] stm32f4_peripheral_regs = [
    ADC1_SR:  0, ADC1_CR1: 0, ADC1_CR2: 0, ADC1_SQR1: 0, ADC1_SMPR2: 0, ADC1_SQR3: 0,         
    I2C1_CR1: 0, I2C_CR2:  0,          
    PWR_CR:   0x0000C000,        
    // -------------------------------------- TIM2 ------------------------------------------
    TIM2_CR1:  0, TIM2_CR2:  0, TIM2_SMCR: 0,         
    // -------------------------------------- EXTI ------------------------------------------
    EXTI_IMR: 0,  EXTI_EMR:  0, EXTI_RTSR: 0, EXIT_FTSR: 0, EXTI_SWIER: 0, EXTI_PR: 0,          
    // -------------------------------------- FLASH -----------------------------------------
    FLASH_ACR: 0,
    // --------------------------------------------------------------------------------------
    SYSCFG_EXTICR1: 0, SYSCFG_EXTICR2: 0, SYSCFG_EXTICR3: 0, SYSCFG_EXTICR4: 0,       
    // --------------------------------------- RCC ------------------------------------------
    // There are three types of reset, defined as system Reset, power Reset and backup 
    // domain Reset.
    RCC_CR:         0x23333083,  RCC_PLLCFGR:    0x24003010,   RCC_AHB1LPENR: 0x7EF7B7FF, 
    RCC_AHB1LPENR:  0x7EF7B7FF,  RCC_CSR:        0x0E000000, 
    RCC_PLLI2SCFGR: 0x20003000,  RCC_PLLSAICFGR: 0x24003000, 
    RCC_CFGR:                0,  RCC_CIR:                 0,        
    RCC_AHB1RSTR:            0,  RCC_AHB2RSTR:            0,   RCC_AHB3RSTR:           0,         
    RCC_APB2RSTR:            0,  
    RCC_AHB1ENR:             0,  RCC_AHB2ENR:             0,   RCC_AHB3ENR:            0,
    RCC_APB1ENR:             0,  RCC_APB2ENR:             0,
    RCC_AHB1LPENR:           0,  RCC_AHB2LPENR:           0,   RCC_AHB3LPENR:          0, 
    RCC_APB1LPENR:           0,  RCC_APB2LPENR:           0,  
    RCC_BDCR:                0,  RCC_CSR:                 0,   RCC_SSCGR:              0, 
    RCC_DCKCFGR:             0,  RCC_APB1RSTR:            0,
    // --------------------------------------------------------------------------------------
    USART1_SR: 0xC0, USART1_DR: 0, USART1_BRR: 0, USART1_CR1: 0, USART1_CR2: 0, USART1_CR3: 0,          
    USART1_GPTR:  0,          
    // -------------------------------------- USART3 ----------------------------------------
    USART3_SR: 0xC0, USART3_DR: 0, USART3_BRR: 0, USART3_CR1: 0, USART3_CR2: 0, USART3_CR3: 0,          
    USART3_GPTR:  0,          
    // -------------------------------------- USART6 ----------------------------------------
    USART6_SR: 0xC0, USART6_DR: 0, USART6_BRR: 0, USART6_CR1: 0, USART6_CR2: 0, USART6_CR3: 0,          
    USART6_GTPR:  0,      
    // --------------------------------------- UART7 ----------------------------------------
    UART7_SR: 0xC0, UART7_DR: 0, UART7_BRR: 0, UART7_CR1: 0, UART7_CR2: 0, UART7_CR3: 0,          
    UART7_GTPR:  0,    

    USART2_SR: 0xC0, USART2_DR: 0, USART2_BRR: 0, USART2_CR1: 0, USART2_CR2: 0, USART2_CR3: 0,          
    USART2_GTPR:  0, 
    // -------------------------------------- GPIOA -----------------------------------------
    GPIOA_MODER: 0, GPIOA_OTYPER: 0, GPIOA_OSPEEDR: 0, GPIOA_PUPDR: 0, GPIOA_IDR: 0,
    GPIOA_ODR:   0, GPIOA_AFRL:   0, GPIOA_AFRH:    0,
    // -------------------------------------- GPIOB -----------------------------------------
    GPIOB_MODER: 0, GPIOB_OTYPER: 0, GPIOB_OSPEEDR: 0, GPIOB_PUPDR: 0, GPIOB_IDR: 0,
    GPIOB_ODR:   0, GPIOB_AFRL:   0, GPIOB_AFRH:    0,
    // -------------------------------------- GPIOC -----------------------------------------
    GPIOC_MODER: 0, GPIOC_OTYPER: 0, GPIOC_OSPEEDR: 0, GPIOC_PUPDR: 0, GPIOC_IDR: 0,
    GPIOC_ODR:   0, GPIOC_AFRL:   0, GPIOC_AFRH:    0,
    // -------------------------------------- GPIOD -----------------------------------------
    GPIOD_MODER: 0, GPIOD_OTYPER: 0, GPIOD_OSPEEDR: 0, GPIOD_PUPDR: 0, GPIOD_IDR: 0,
    GPIOD_ODR:   0, GPIOD_AFRL:   0, GPIOD_AFRH:    0,
    // -------------------------------------- GPIOE -----------------------------------------
    GPIOE_MODER: 0, GPIOE_OTYPER: 0, GPIOE_OSPEEDR: 0, GPIOE_PUPDR: 0, GPIOE_IDR: 0,
    GPIOE_ODR:   0, GPIOE_AFRL:   0, GPIOE_AFRH:    0,
    // -------------------------------------- GPIOF -----------------------------------------
    GPIOF_MODER: 0, GPIOF_OTYPER: 0, GPIOF_OSPEEDR: 0, GPIOF_PUPDR: 0, GPIOF_IDR: 0,
    GPIOF_ODR:   0, GPIOF_AFRL:   0, GPIOF_AFRH:    0,
    // -------------------------------------- GPIOG -----------------------------------------
    GPIOG_MODER: 0, GPIOG_OTYPER: 0, GPIOG_OSPEEDR: 0, GPIOG_PUPDR: 0, GPIOG_IDR: 0,
    GPIOG_ODR:   0, GPIOG_AFRL:   0, GPIOG_AFRH:    0,
    // -------------------------------------- GPIOH -----------------------------------------
    GPIOH_MODER: 0, GPIOH_OTYPER: 0, GPIOH_OSPEEDR: 0, GPIOH_PUPDR: 0, GPIOH_IDR: 0,
    GPIOH_ODR:   0, GPIOH_AFRL:   0, GPIOH_AFRH:    0,
    // -------------------------------------- GPIOI -----------------------------------------
    GPIOI_MODER: 0, GPIOI_OTYPER: 0, GPIOI_OSPEEDR: 0, GPIOI_PUPDR: 0, GPIOI_IDR: 0,
    GPIOI_ODR:   0, GPIOI_AFRL:   0, GPIOI_AFRH:    0,
    // -------------------------------------- GPIOJ -----------------------------------------
    GPIOJ_MODER: 0, GPIOJ_OTYPER: 0, GPIOJ_OSPEEDR: 0, GPIOJ_PUPDR: 0, GPIOJ_IDR: 0,
    GPIOJ_ODR:   0, GPIOJ_AFRL:   0, GPIOJ_AFRH:    0,
    // -------------------------------------- GPIOK -----------------------------------------
    GPIOH_MODER: 0, GPIOH_OTYPER: 0, GPIOH_OSPEEDR: 0, GPIOH_PUPDR: 0, GPIOH_IDR: 0,
    GPIOH_ODR:   0, GPIOH_AFRL:   0, GPIOH_AFRH:    0,
    // --------------------------------------------------------------------------------------
    TIM6_CR1:   0, TIM6_CR2:   0, TIM6_DIER: 0, TIM6_SR: 0, TIM6_EGR: 0,          
    TIM6_CNT:   0, TIM6_PSC:   0, TIM6_ARR:  0,         
    TIM5_CR1:   0, TIM5_CR2:   0, TIM5_SMCR: 0, TIM5_DIER: 0, TIM5_SR:  0, TIM5_EGR: 0,
    TIM5_CCMR1: 0, TIM5_CCMR2: 0, TIM5_CCER: 0, TIM5_CNT:  0, TIM5_PSC: 0, TIM5_ARR: 0,
    TIM5_CCR1:  0, TIM5_CCR2:  0, TIM5_CCR3: 0, TIM5_CCR4: 0,
    TIM5_DCR:   0, TIM5_DMAR:  0, TIM5_OR:   0,
    DMA2_S5CR: 0, 
    DMA2_S5FCR: 0, 
    DAC_CR: 0, 
    DMA2_LISR:   0,       DMA2_S0CR:      0, DMA2_S0FCR:     0,
    OTG_GOTGCTL: 0x10000, OTG_FS_GAHBCFG: 0, OTG_FS_GUSBCFG: 0xA00, OTG_FS_GCCFG: 0,
    OTG_FS_GRSTCTL: 0x80000000,
    FMC_BCR1:   0,  FMC_BCR2:   0,  FMC_BCR3:  0,  FMC_BCR4:  0,    
    FMC_BTR1:   0,  FMC_BTR2:   0,  FMC_BTR3:  0,  FMC_BTR4:  0,    
    FMC_BWTR1:  0,  FMC_BWTR2:  0,  FMC_BWTR3: 0,  FMC_BWTR4: 0,  
    FMC_PCR2:   0,  FMC_PCR3:   0,  FMC_PCR4:  0,  
    FMC_SR2:    0,  FMC_SR3:    0,  FMC_SR4:   0,   
    FMC_PMEM2:  0,  FMC_PMEM3:  0,  FMC_PMEM4: 0,   
    FMC_PATT2:  0,  FMC_PATT3:  0,  FMC_PATT4: 0,   
    FMC_PIO4 :  0,  FMC_ECCR2:  0,  FMC_ECCR3: 0,  FMC_SDCR_1: 0,  FMC_SDCR_2: 0,  
    FMC_SDTR1:  0,  FMC_SDTR2:  0,  FMC_SDCMR: 0,  FMC_SDRTR:  0,  FMC_SDSR:   0, 
    // -------------------------------------- CAN1 ------------------------------------------
    CAN1_MCR:   0x00010002, CAN1_MSR: 0x00000C02, CAN1_FMR: 0x2A1C0E01, CAN1_FS1R: 0,
    CAN1_BTR:   0x01230000, CAN1_IER: 0,          CAN1_FA1R:         0,
];