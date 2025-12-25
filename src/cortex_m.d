import std.algorithm : all, canFind, find, map, reverse, startsWith;
import std.conv : to, ConvException, parse;
import std.exception;
import std.string : indexOf, replace, split, splitLines, strip, stripLeft;
import std.traits;
import std.variant : Algebraic;
import std.format : format;
import std.stdio;
import std.regex;
import std.array;
import std.typecons : Tuple;
import core.exception;
import std.container;

enum special_reg : ubyte {
	APSR = 			0b00000000,
	IAPSR =         0b00000001,
	EAPSR =			0b00000010,
	XPSR = 			0b00000011,
	IPSR = 			0b00000101,
	EPSR = 			0b00000110,
	IEPSR =			0b00000111,
	MSP =			0b00001000,
	PSP =   		0b00001001,
	PRIMASK = 	    0b00010000,
	BASEPRI = 		0b00010001,
	BASEPRI_MAX =	0b00010010,
	FAULTMASK =	    0b00010011,
	CONTROL =		0b00010100
}

File* load_store_log_ptr = null;

File* load_store_log() {
    if (load_store_log_ptr is null) {
        load_store_log_ptr = new File("load_store_log.txt", "w");
    }
    return load_store_log_ptr;
}

string[] bare_metal_func_names = [
    "SystemInit",
    "Reset_Handler",
    "CopyDataInit",
    "LoopCopyDataInit",
    "FillZerobss",
    "LoopFillZerobss",
    "__libc_init_array",
    "_init",
    "register_fini",
    "atexit",
    "__register_exitproc",
    "frame_dummy",
    "register_tm_clones",
    "main",
    "HAL_Init",
    "HAL_NVIC_SetPriorityGrouping",
    "__NVIC_SetPriorityGrouping",
    "HAL_InitTick",
    "HAL_SYSTICK_Config",
    "SysTick_Config",
    "HAL_MspInit",
    "SystemClock_Config",
    "memset",
    "MX_GPIO_Init",
    "MX_USART1_UART_Init",
    "HAL_UART_Init",
    "HAL_UART_MspInit",
    "HAL_GPIO_Init",
    "UART_SetConfig",
    "HAL_RCC_GetPCLK2Freq",
    "HAL_RCC_GetHCLKFreq",
    "__aeabi_uldivmod",
    "__udivmoddi4",
    "__aeabi_idiv0",
    "strlen"
];

string[] freertos_func_names = [
	"SystemInit",
    "Reset_Handler",
    "CopyDataInit",
    "LoopCopyDataInit",
    "FillZerobss",
    "LoopFillZerobss",
    "__libc_init_array",
    "_init",
    "register_fini",
    "atexit",
    "__register_exitproc",
    "frame_dummy",
    "register_tm_clones",
    "main",
    "HAL_Init",
    "HAL_NVIC_SetPriorityGrouping",
    "__NVIC_SetPriorityGrouping",
    "HAL_InitTick",
    "HAL_SYSTICK_Config",
    "SysTick_Config",
    "HAL_MspInit",
    "SystemClock_Config",
    "memset",
    "MX_GPIO_Init",
    "HAL_RCC_GetClockConfig",
    "HAL_RCC_GetPCLK1Freq",
    "HAL_RCC_GetHCLKFreq",
    "HAL_TIM_Base_Init",
    "HAL_TIM_Base_MspInit",
    "TIM_Base_SetConfig",
    "HAL_TIM_Base_Start_IT",
    "HAL_NVIC_SetPriority",
    "__NVIC_GetPriorityGrouping",
    "NVIC_EncodePriority",
    "__NVIC_SetPriority",
    "HAL_NVIC_GetPriorityGrouping",
    "HAL_RCC_OscConfig",
    "HAL_RCC_ClockConfig",
    "HAL_GetTick",
    "HAL_RCC_GetSysClockFreq",
    "HAL_GPIO_WritePin",
    "HAL_GPIO_Init",
    "osKernelInitialize",
    "osThreadNew",
    "xTaskCreate",
    "pvPortMalloc",
    "vTaskSuspendAll",
    "prvHeapInit",
    "xTaskResumeAll",
    "vPortEnterCritical",
    "vPortExitCritical"
];

string[] zephyr_func_names = [
	"__start",
	"z_prep_c",
	"relocate_vector_table",
	"arch_bss_zero",
	"arch_early_memset",
	"memset",
	"arch_data_copy",
	"arch_early_memcpy",
	"memcpy",
	"z_arm_interrupt_init",
	"z_cstart",
	"z_sys_init_run_level",
	"z_arm_fault_init",
	"z_arm_cpu_idle_init",
	"z_arm_mpu_init",
	"arm_core_mpu_disable",
	"mem_attr_get_regions",
	"arm_core_mpu_enable",
	"z_arm_configure_static_mpu_regions",
	"arm_core_mpu_configure_static_mpu_regions",
	"mpu_configure_regions",
	"z_dummy_thread_init",
	"soc_early_init_hook",
	"z_sched_init",
	"z_setup_new_thread",
	"arch_tls_stack_setup",
	"arch_new_thread",
	"z_ready_thread",
	"ready_thread",
	"z_reset_time_slice",
	"z_abort_timeout",
	"first",
	"remove_timeout",
	"thread_is_sliceable",
	"z_init_cpu"
];
 
enum reg : ubyte {
	r0,
	r1,
	r2,
	r3,
	r4,
	r5,
	r6,
	r7,
	r8,
	r9,
	r10,
	r11,
	r12,
	sp,   	// stack pointer
	lr,		// link register
	pc,		// program counter
	none
}

struct imm {
	int value;
}

struct mem {
	reg base;
	imm offset;
}

enum mnemonic : ubyte {
	add,
	bx,
	cmp,			
	ldr_w,
	wfe,			// wait for event
	invalid
}

// ============
//  Parse Enum
// ============

private T parse_enum(T, string file = __FILE__, size_t line = __LINE__)(string s)
    if (is(T == enum))
{
    static const string[] validNames = [ __traits(allMembers, T) ];

    string norm = s.replace('.', '_');
    
    try return norm.to!T;
    catch (ConvException e)
        throw new ConvException(format!"Invalid %s '%s' (valid: %(%s, %))"(
            T.stringof, s, validNames), file, line);
}

// ================
//  Parse Mnemonic
// ================

alias parse_mnemonic = parse_enum!mnemonic;

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "ldr.w";
    auto result = parse_mnemonic(s);
    assert(result == mnemonic.ldr_w);
}

alias operand = Algebraic!(reg, imm, mem);

struct instr {
	uint addr;
	mnemonic opcode;
	operand[] operands;
}

struct stm32f4_rcc {
	enum cr         = 0x40023800;	// clock control
	enum pll_cfgr   = 0x40023804;	// pll config
	enum cfgr       = 0x40023808;	// clock config
	enum cir		= 0x4002380c;	// clock interrupt
	enum ahb1_enr	= 0x40023830;	// advanced high performance bus
}

struct stm32f4_rcc_cr {
	enum hsion		= 0;
	enum hsirdy		= 1;
	enum hsitrim	= 2;
	enum hseon		= 8;
	enum hserdy		= 9;
	enum hsebyp		= 16;
	enum csson		= 18;	// clock security system enable
	enum pllon		= 19;
	enum pllrdy		= 20;
	enum plli2son	= 24;
	enum plli2srdy  = 25;
}

struct stm32f4_rcc_pllcfgr {
	enum pllm 		= 0;	// division factor
	enum plln       = 6;	// multiplication factor
	enum pllp		= 16;	// pll output division
	enum pplsrc		= 19;
	enum pplq		= 24;
}

struct stm32f4_rcc_apb1enr {
	enum tim2 		= 0;
	enum tim3 		= 1;
	enum tim5		= 4;
	enum spi2		= 17;
	enum i2c1		= 21;
	enum i2c2		= 22;
	enum i2c3		= 23;
	enum uart4		= 28;
	enum uart5		= 29;
	enum usart2		= 31;
}

struct stm32f4_dac_cr {
	enum em1		= 0;	// enable DAC channel 1
	enum boff1		= 1;	// output buffer disable
	enum ten1		= 2;	// trigger enable
	enum tsel1		= 3;	// trigger source select
	enum wave1		= 6;	// noise/triangle enable
	enum mamp1		= 8;	// wave amplitude
	enum dmaen1		= 12;	// DMA enable
}

struct stm32f4_swtrigr {
	enum swtrig1 	= 0;
	enum swtrig2	= 1;
}

enum instr_grp : ubyte {
	alu_imm			= 0b00,
	data_proc		= 0b010000,
	misc			= 0b1011,
	single_str_1    = 0b0101,
	single_str_2	= 0b011,
	single_str_3    = 0b100,
	ldr_pool 		= 0b01001,
	special         = 0b010001,
	b_imm_11 		= 0b11100,
	add_sp          = 0b10101,
	adr             = 0b10100
}

enum alu_imm : ubyte {
	add_8           = 0b110,
	add_3 			= 0b01110,
	asr             = 0b010,
	cmp				= 0b101,
	lsl             = 0b000,
	lsr 			= 0b001,
	movs            = 0b100,
	subs_8			= 0b111,
	sub_reg			= 0b01101,
	add_reg         = 0b01100,
	sub_imm_3  		= 0b01111
}

enum data_proc : ubyte {
	and 			= 0b0000,
	cmp             = 0b1010,
	lor 			= 0b1100,
	mvn             = 0b1111,
	lsl_reg		    = 0b0010,
	lsr_reg 		= 0b0011,
	adc_reg         = 0b0101, 
	negs            = 0b1001,
	tst 			= 0b1000
}

enum single_str : ubyte {
	str 			= 0b000,
	str_sp      	= 0b1001,
	strh  			= 0b001,
	ldr_reg         = 0b100,
	ldrb_reg        = 0b110
}

enum misc : ubyte {
	cmp_br 		    = 0b0001,
	sub_sp          = 0b00001,
	push_mult_reg   = 0b010,
	pop_mult_reg  	= 0b110,
	if_then			= 0b1111,
	blx				= 0b111,
	uxtb 			= 0b001011
}

enum cmp_br : ubyte {
	cmp_br_z  = 0,
	cmp_br_nz = 1
}

enum special : ubyte {
	add_lo_reg  	= 0b0000,
	add_high_reg_1  = 0b0001,
	bx  	  		= 0b110,
	blx				= 0b111,
	mov_high_1 		= 0b101,
	mov_high_2	    = 0b1001,
	add_high_reg_2  = 0b001,
	mov_lo			= 0b1000,
	cmp_high_1      = 0b011,
	cmp_high_2      = 0b0101
}

enum opcode : ubyte {
	adc_32,
	adc_reg,
	add_32,
	add_high_reg_1,
	add_high_reg_2,
	add_imm_3,
	add_imm_8,
	add_imm_32,
	add_lo_reg,
	add_32_reg,
	add_reg,
	add_sp,	
	add_sp_t1,
	add_sp_t2,
	adr,
	adr_32,
	and_reg,
	and_reg_32,
	and_imm_32,
	asr_imm,
	b_32,
	b_cond_32,
	b_imm_11,
	b_uncond_32,
	bfc_32,
	bfi_32,
	bic_reg_32,
	bic_imm_32,
	bit_not_32,
	bit_or_not_32,
	bl_32,
	blx,
	b_cond,
	bx,
	cmp_br_z,
	cmp_br_nz,
	cmp_high_1,
	cmp_high_2,
	cmp_imm,
	cmp_imm_32,
	cmp_reg,
	cps,
	dmb_32,
	dsb_32,
	isb_32,
	if_then,
	ld_rex,
	ldh_32,
	ldmia,
	ldr_imm,
	ldr_imm_32,
	ldr_imm_32_t3,
	ldr_imm_32_t4,
	ldr_lit_32,
	ldr_reg_32,
	ldrt_32,
	ldr_pool,
	ldr_sp,
	ldr_reg,
	ldr_sh_32,
	ldrb_imm,
	ldrb_reg,
	ldrd_imm_32,
	ldrh_imm,
	ldrb_32,
	ldrb_imm_32_t2,
    ldrb_imm_32_t3,
    ldrbt_32,
    ldrb_reg_32,
    ldrsb_32,
    ldrsb_imm_32_t1,
    ldrsb_imm_32_t2,
    ldrsbt_32,
    ldrsb_reg_32,
	lor_reg,
	lsl_imm,
	lsl_reg,
	lsr_reg,
	lsr_imm,
	mls_32,
	mov_16_imm_32,
	mov_32,
	mov_high_1,
	mov_high_2,
	mov_high_reg,
	mov_imm,
	mov_imm_32_t2,
	mov_lo,
	movt_32,
	mul_32,
	mvn_reg,
	mvn_reg_32,
	mrs_32,
	msr_32,
	negs,
	nop,
	nop_32,
	or_not_32,
	orr_32,
	orr_reg_32,
	pld_32,
	pld_imm_32,
	pld_reg_32,
	pop_mult_reg,
	pop_mult_reg_32,
	push_mult_reg,
	push_mult_reg_32,
	rev,
	rsb_32,
	sbc_32,
	sbfx_32,
	stmb_32,
	str_imm,
	str_imm_32_t3,
	str_imm_32_t4,
	str_sp,
	str_reg,
	str_rex,
	strb_reg,
	str_reg_32,
	strb_imm,
	strb_imm_32_t2,
	strb_imm_32_t3,
	strb_reg_32,
	strd_32,
	strh_imm,
	strh_imm_32_t2,
	strh_imm_32_t3,
	strh_reg_32,
	strh_reg,
	sub_imm_3,
	sub_imm_8,
	sub_imm_32,
	sub_reg,
	subs_32,
	sub_sp,
	tst,
	tst_32,
	ubfx_32,	
	udiv_32,
	umull_32,
	uxtb,
	asr_reg_32,
	ror_32,
	lsl_reg_32,
	lsr_reg_32,	
	sxtah_32,
	sxth_32,
	uxtah_32,
	uxth_32,
	sxtab_16_32,
	sxtb16_32,
	uxtab_16_32,
	uxtb16_32,
	sxtab_32,
	sxtb_32,
	uxtab_32,
	uxtb_32,
	qadd_32,
	qdadd_32,
	qsub_32,
	qdsub_32,
	rev_32,
	rev_16_32,
	rbit_32,
	revsh_32,
	sel_32,
	clz_32,
	uadd8_32,
	uxth,
	invalid
}

enum all_field_tuples = 
	  field_tuples_adc_reg
	~ field_tuples_adc_32
	~ field_tuples_add_32
	~ field_tuples_add_32_reg
	~ field_tuples_add_high_reg_1
	~ field_tuples_add_high_reg_2
	~ field_tuples_add_imm_3
	~ field_tuples_add_imm_8
	~ field_tuples_add_lo_reg
	~ field_tuples_add_reg
	~ field_tuples_add_sp_t1
	~ field_tuples_add_sp_t2
	~ field_tuples_adr
	~ field_tuples_and_imm_32
	~ field_tuples_and_reg
	~ field_tuples_asr_imm
	~ field_tuples_b_32
	~ field_tuples_b_cond
	~ field_tuples_b_imm_11
	~ field_tuples_b_uncond_32
	~ field_tuples_bic_reg_32
	~ field_tuples_bic_imm_32
	~ field_tuples_bit_not_32
	~ field_tuples_bl_32
	~ field_tuples_blx
	~ field_tuples_bx
	~ field_tuples_cmp_br_nz
	~ field_tuples_cmp_br_z
	~ field_tuples_cmp_high_1
	~ field_tuples_cmp_high_2
	~ field_tuples_cmp_imm
	~ field_tuples_cmp_imm_32
	~ field_tuples_cmp_reg
	~ field_tuples_dsb_32
	~ field_tuples_if_then
	~ field_tuples_isb_32
	~ field_tuples_ldr_imm
	~ field_tuples_ldr_imm_32_t3
	~ field_tuples_ldr_lit_32
	~ field_tuples_ldr_pool
	~ field_tuples_ldr_imm_32_t4
	~ field_tuples_ldr_reg
	~ field_tuples_ldr_reg_32
	~ field_tuples_ldr_sp
	~ field_tuples_ldrb_imm
	~ field_tuples_ldrb_imm_32_t2
	~ field_tuples_ldrb_imm_32_t3
	~ field_tuples_ldrb_reg
	~ field_tuples_ldrd_imm_32
	~ field_tuples_ldrh_imm
	~ field_tuples_ldrsb_imm_32_t1
	~ field_tuples_ldrsb_imm_32_t2
	~ field_tuples_lor_reg
	~ field_tuples_lsl_reg_32
	~ field_tuples_lsl_imm
	~ field_tuples_lsl_reg
	~ field_tuples_lsr_imm
	~ field_tuples_lsr_reg_32
	~ field_tuples_lsr_reg
	~ field_tuples_mls_32
	~ field_tuples_mov_16_imm_32
	~ field_tuples_mov_32
	~ field_tuples_mov_imm_32_t2
	~ field_tuples_mov_high_1
	~ field_tuples_mov_high_2
	~ field_tuples_mov_imm
	~ field_tuples_mov_lo
	~ field_tuples_mrs_32
	~ field_tuples_msr_32
	~ field_tuples_subs_32
	~ field_tuples_mul_32
	~ field_tuples_mvn_reg
	~ field_tuples_negs
	~ field_tuples_nop
	~ field_tuples_nop_32
	~ field_tuples_orr_32
	~ field_tuples_orr_reg_32
	~ field_tuples_pop_mult_reg
	~ field_tuples_pop_mult_reg_32
	~ field_tuples_push_mult_reg
	~ field_tuples_push_mult_reg_32
	~ field_tuples_rsb_32
	~ field_tuples_sbc_32
	~ field_tuples_str_imm
	~ field_tuples_str_imm_32_t3
	~ field_tuples_str_imm_32_t4
	~ field_tuples_str_reg
	~ field_tuples_str_reg_32
	~ field_tuples_str_sp
	~ field_tuples_strb_imm
	~ field_tuples_strb_reg
	~ field_tuples_strb_imm_32_t2
	~ field_tuples_strb_imm_32_t3
	~ field_tuples_strd_32
	~ field_tuples_strh_imm
	~ field_tuples_sub_imm_3
	~ field_tuples_sub_imm_8
	~ field_tuples_sub_imm_32
	~ field_tuples_sub_sp
	~ field_tuples_sub_reg
	~ field_tuples_subs_32
	~ field_tuples_tst
	//~ field_tuples_tst
	~ field_tuples_udiv_32
	~ field_tuples_umull_32
	~ field_tuples_ubfx_32
	~ field_tuples_uxtb;

immutable string[][opcode] field_map = (() {
    string[][opcode] m;
    foreach(t; all_field_tuples)
        m[t[0]] = t[1];
    return m;
})();

// =================
//  Decode Mnemonic
// =================

opcode decode_mnemonic(ushort instr) { 
    if (cast(ubyte)((instr >> 14) & 0b11) == instr_grp.alu_imm) {
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.cmp) {
    		return opcode.cmp_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.movs) {
    		return opcode.mov_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.subs_8) {
    		return opcode.sub_imm_8;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b11111) == alu_imm.add_3) {
    		return opcode.add_imm_3;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.add_8) {
    		return opcode.add_imm_8;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.asr) {
    		return opcode.asr_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.lsl) {
    		return opcode.lsl_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.lsr) {
    		return opcode.lsr_imm;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b11111) == alu_imm.sub_reg) {
    		return opcode.sub_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b11111) == alu_imm.add_reg) {
    		return opcode.add_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b11111) == alu_imm.sub_imm_3) {
    		return opcode.sub_imm_3;
    	}
    }
    if (cast(ubyte)((instr >> 10) & 0b111111) == instr_grp.data_proc) {
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.and) {
    		return opcode.and_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.lor) {
    		return opcode.lor_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.mvn) {
    		return opcode.mvn_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.cmp) {
    		return opcode.cmp_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.lsl_reg) {
    		return opcode.lsl_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.lsr_reg) {
    		return opcode.lsr_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.adc_reg) {
    		return opcode.adc_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.negs) {
    		return opcode.negs;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.tst) {
    		return opcode.tst;
    	}
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == instr_grp.single_str_1) {
    	ubyte opb = cast(ubyte)((instr >>  9) & 0b111);
    	ubyte opa = cast(ubyte)((instr >> 12) & 0b1111);
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.str) {
    		return opcode.str_reg;
    	}
    	// 0x559a
    	// 0101 0101 1001 1010
    	if ((opa == 0b0101) && (opb == 0b010)) {
    		return opcode.strb_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.strh) {
    		return opcode.strh_reg;
    	}
    	if ((opa == 0b0101) && (opb == 0b110)) {
    		return opcode.ldrb_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.ldr_reg) {
    		return opcode.ldr_reg;
    	}
    }
    if (cast(ubyte)((instr >> 13) & 0b111)  == instr_grp.single_str_2) {
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.str_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldr_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.strb_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldrb_imm;
    		}
    	}
    }
    if (cast(ubyte)((instr >> 13) & 0b111)  == instr_grp.single_str_3) {
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.strh_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldrh_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldr_sp;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.str_sp;
    		}
    	}
    }
    if (cast(ubyte)((instr >> 11) & 0b11111) == instr_grp.ldr_pool) {
    	return opcode.ldr_pool;
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == 0b1101) {
    	return opcode.b_cond;
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == instr_grp.misc) {
    	ubyte _opcode_ = cast(ubyte)((instr >> 5) & 0b1111111);
    	if ((_opcode_ & 0b1111100) == 0b0000000) {
    		return opcode.add_sp;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b111111) == misc.uxtb) {
    		return opcode.uxtb;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == misc.push_mult_reg) {
    		return opcode.push_mult_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == misc.pop_mult_reg) {
    		return opcode.pop_mult_reg;
    	}
    	if (cast(ubyte)((instr >> 8) & 0b1111) == misc.if_then) {
    		if (cast(ubyte)(instr & 0xff) == 0) {
    			return opcode.nop;
    		}
    		return opcode.if_then;
    	}
    	if (cast(ubyte)((instr >> 7) & 0b11111) == misc.sub_sp) {
    		return opcode.sub_sp;
    	}
    	if ((_opcode_ & 0b1111000) == 0b0001000 ||
    		(_opcode_ & 0b1111000) == 0b0011000 ||
    		(_opcode_ & 0b1111000) == 0b1001000 ||
    		(_opcode_ & 0b1111000) == 0b1011000) {
	    	// b383: 1011 0011 1000 0011
	    	// b943: 1011 1001 0100 0011
	    	if (cast(ubyte)((instr >> 11) & 0b1) == 0b0) {
	    		return opcode.cmp_br_z;
			}
			if (cast(ubyte)((instr >> 11) & 0b1) == 0b1) {
				return opcode.cmp_br_nz;
			}
		}
		if ((_opcode_ & 0b1111110) == 0b0010100) {
			return opcode.uxth;
		}
		if (_opcode_ == 0b0110011) {
			return opcode.cps;
		}
		if ((_opcode_ & 0b1111110) == 0b1010000) {
			return opcode.rev;
		}
    }
    if (cast(ubyte)((instr >> 10) & 0b111111) == instr_grp.special) {
    	if (cast(ubyte)((instr >> 7) & 0b111) == special.bx) {
    		return opcode.bx;
    	}
    	if (cast(ubyte)((instr >> 7) & 0b111) == special.mov_high_1) {
    		return opcode.mov_high_1;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == special.mov_high_2) {
    		return opcode.mov_high_2;
    	}
    	if (cast(ubyte)((instr >> 7) & 0b111) == special.blx) {
    		return opcode.blx;
    	}
    	if (cast(ubyte)((instr >> 7) & 0b111) == special.cmp_high_1) {
    		return opcode.cmp_high_1;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == special.mov_lo) {
    		return opcode.mov_lo;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == special.cmp_high_2) {
    		return opcode.cmp_high_2;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == special.add_lo_reg) {
    		return opcode.add_lo_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == special.add_high_reg_1) {
    		return opcode.add_high_reg_1;
    	}
    	if (cast(ubyte)((instr >> 7) & 0b111) == special.add_high_reg_2) {
    		return opcode.add_high_reg_2;
    	}

    }
    if (cast(ubyte)((instr >> 11) & 0b11111) == instr_grp.b_imm_11) {
    	return opcode.b_imm_11;
    }
    if (cast(ubyte)((instr >> 11) & 0b11111) == instr_grp.add_sp) {
    	return opcode.add_sp;
    }
    if (cast(ubyte)((instr >> 11) & 0b11111) == instr_grp.adr) {
    	return opcode.adr;
    }
    return opcode.invalid;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		opcode expected;
	}

	test_case[] tests = [
		test_case(0x10b6, opcode.asr_imm),
		test_case(0x3730, opcode.add_imm_8),
		test_case(0x4013, opcode.and_reg),
		test_case(0x2b00, opcode.cmp_imm),
		test_case(0x2300, opcode.mov_imm),
		test_case(0x3902, opcode.sub_imm_8),
		test_case(0x00d9, opcode.lsl_imm),
		test_case(0x099b, opcode.lsr_imm),
		test_case(0x4313, opcode.lor_reg),
		test_case(0x43db, opcode.mvn_reg),
		test_case(0x608b, opcode.str_imm),
		test_case(0x80fb, opcode.strh_imm),
		test_case(0x88fb, opcode.ldrh_imm),
		test_case(0x781a, opcode.ldrb_imm),
		test_case(0x701a, opcode.strb_imm),
		test_case(0x68fb, opcode.ldr_imm),
		test_case(0x4283, opcode.cmp_reg),
		test_case(0x4803, opcode.ldr_pool),
		test_case(0xd002, opcode.b_cond),
		test_case(0xb103, opcode.cmp_br_z),
		test_case(0x4718, opcode.bx),
		test_case(0x1a1b, opcode.sub_reg),
		test_case(0xb510, opcode.push_mult_reg),
		test_case(0xb943, opcode.cmp_br_nz),
		test_case(0xbd10, opcode.pop_mult_reg),
		test_case(0xe7cf, opcode.b_imm_11),
		test_case(0xbf00, opcode.nop),
		test_case(0x469d, opcode.mov_high_1),
		test_case(0x460f, opcode.mov_lo),
		test_case(0x4798, opcode.blx),
		test_case(0xaf00, opcode.add_sp),
		test_case(0x5cd3, opcode.ldrb_reg),
		test_case(0xb092, opcode.sub_sp),
		test_case(0x1d3b, opcode.add_imm_3),
		test_case(0x4413, opcode.add_lo_reg),
		test_case(0x409a, opcode.lsl_reg),
		test_case(0x40da, opcode.lsr_reg),
		test_case(0xa201, opcode.adr),
		test_case(0x4652, opcode.mov_high_2),
		test_case(0x9300, opcode.str_sp),
		test_case(0x1891, opcode.add_reg),
		test_case(0x458c, opcode.cmp_high_1),
		test_case(0x4463, opcode.add_high_reg_1),
		test_case(0x1e54, opcode.sub_imm_3),
		test_case(0x44e6, opcode.add_high_reg_2),
		test_case(0x4572, opcode.cmp_high_2),
		test_case(0x4241, opcode.negs),
		test_case(0x58fb, opcode.ldr_reg),
		test_case(0xb480, opcode.push_mult_reg),
		test_case(0x50c4, opcode.str_reg),
		test_case(0x6013, opcode.str_imm),
		test_case(0x4a0a, opcode.ldr_pool),
		test_case(0x681b, opcode.ldr_imm),
		test_case(0xb2db, opcode.uxtb),
		test_case(0x415b, opcode.adc_reg),
		test_case(0xbf08, opcode.if_then),
		test_case(0x9d08, opcode.ldr_sp),
		test_case(0x682b, opcode.ldr_imm),
		test_case(0x58d4, opcode.ldr_reg),
		test_case(0xb580, opcode.push_mult_reg),
		test_case(0x9301, opcode.str_sp),
		test_case(0xb005, opcode.add_sp),
		test_case(0x4208, opcode.tst),
		test_case(0xaf00, opcode.add_sp),
		test_case(0x2300, opcode.mov_imm),
		test_case(0x559a, opcode.strb_reg)
		// 1010 1111 0000 0000
		//test_case(0x58d4, opcode.ldr_imm)
	];

	foreach (t; tests) {
		opcode actual = decode_mnemonic(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%04X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}

enum op1_32 : ubyte {
	grp1				 	= 0b01,
	grp2					= 0b10,
	grp3					= 0b11
}

enum op2_32 : ubyte {
	data_proc_shift_reg 	= 0b0100000,
	data_proc_bin_imm 		= 0b0100000,
	load_store_mult 		= 0b1100100,
	data_proc_imm           = 0b0100000,
	long_mult               = 0b1111000,
	mult					= 0b1111000,
	data_proc_reg           = 0b1110000,
	ld_bytes_mem_hints      = 0b1100111,
	str_single              = 0b1110001,
	ld_str_dual             = 0b1100100,
	ldh  					= 0b1100111,
	load_word 				= 0b1100111,
	store_single_data_item  = 0b1110001,
	load_byte 				= 0b1100111
}

opcode decode_mnemonic_32(uint instr) {
	ubyte op1 = cast(ubyte)((instr >> 27) & 0b11);
	ubyte op2 = cast(ubyte)((instr >> 20) & 0b1111111);
	if (op1 == op1_32.grp1) { 
		if ((op2 & op2_32.data_proc_shift_reg) == op2_32.data_proc_shift_reg) {
			ubyte op = cast(ubyte)((instr >> 21) & 0b1111);
			auto rn = cast(ubyte)((instr >> 16) & 0b1111);
			auto rd = cast(ubyte)((instr >>  8) & 0b1111);
			if (op == 0b1000) {
				if (rd != 0b1111) {
					return opcode.add_32_reg;
				}
			}
			if (op == 0b0010) {
				if (rn != 0b1111) {
					return opcode.orr_reg_32;
				}
				if (rn == 0b1111) {
					return opcode.mov_32;
				}
			}
			if (op == 0b1101) {
				if (rd != 0b1111) {
					return opcode.subs_32;
				}
			}
			if (op == 0b1011) {
				return opcode.sbc_32;
			}
			if (op == 0b1010) {
				return opcode.adc_32;
			}
			if (op == 0b0011) {
				if (rn == 0b1111) {
					return opcode.or_not_32;
				}
				if (rn != 0b1111) {
					return opcode.mvn_reg_32;
				}
			}
			ubyte s = cast(ubyte)((instr >> 20) & 0b1);
			if (op == 0b0000) {
				if ((rd == 0b1111) && (s == 0b1)) {
					return opcode.tst_32;
				}
				if (rd != 0b1111) {
					return opcode.and_reg_32;
				}
			}
			if (op == 0b0001) {
				return opcode.bic_reg_32;
			}

		}
		if ((op2 & op2_32.load_store_mult) == 0b0000000)  {
			ubyte op = cast(ubyte)((instr >> 23) & 0b11);
			ubyte rn = cast(ubyte)((instr >> 16) & 0b1111);
			ubyte W = cast(ubyte)((instr >> 21) & 0b1);
			ubyte Wrn = cast(ubyte)((W << 4) | rn);
			ubyte L = cast(ubyte)((instr >> 20) & 0b1);
			if (op == 0b01) {
				if (L == 0b1) {
					if (Wrn == 0b11101) {
						return opcode.pop_mult_reg_32;
					} else {
						return opcode.ldmia;
					}
				}
			}
			if (op == 0b10) {
				if (L == 0b0) {
					if (rn == 0b1101) {
						return opcode.push_mult_reg_32;
					}
				}
			}
		}
		if ((op2 & op2_32.ld_str_dual) == 0b0000100) {
			ubyte _op1 = cast(ubyte)((instr >> 23) & 0b11);
			ubyte _op2 = cast(ubyte)((instr >> 20) & 0b11);
			if (((_op1 & 0b10) == 0b00) && (_op2 == 0b10)) {
				return opcode.strd_32;
			}
			if (((_op1 & 0b10) == 0b10) && ((_op2 & 0b01) == 0b00)) {
				return opcode.strd_32;
			}
			if (((_op1 & 0b10) == 0b00) && (_op2 == 0b11)) {
				return opcode.ldrd_imm_32;
			}
			if (((_op1 & 0b10) == 0b10) && ((_op2 & 0b01) == 0b01)) {
				return opcode.ldrd_imm_32;
			}
			if ((_op1 == 0b00) && (_op2 == 0b01)) {
				return opcode.ld_rex;
			}
			if ((_op2 == 0b00) && (_op1 == 0b00)) {
				return opcode.str_rex;
			}
		}
	}
	if (op1 == op1_32.grp2) {
		ubyte op = cast(ubyte)((instr >> 15) & 0b1); 
		ubyte rd = cast(ubyte)((instr >> 20) & 0b1111); 
		if (op) {
			ubyte _op1 = cast(ubyte)((instr >> 12) & 0b111);
			ubyte _op = cast(ubyte)((instr >> 20) & 0b1111111);
			if (((_op1 & 0b101) == 0b000) & (_op == 0b0111011)) {
				ubyte option = cast(ubyte)(instr & 0xf);
				ubyte _opc_ = cast(ubyte)((instr >> 4) & 0xf);
				if ((_opc_ == 0b100) & ((option & 1011) != 0b0000)) {
					return opcode.dsb_32;
				}
				if (_opc_ == 0b110) {
					return opcode.isb_32;
				}
				if (_opc_ == 0b0101) {
					return opcode.dmb_32;
				}
			}
			if ((_op1 & 0b101) == 0b101) {
				return opcode.bl_32;
			}
			if (((_op1 & 0b101) == 0b000) & ((_op & 0b1111110) == 0b0111110)) {
				return opcode.mrs_32;
			}
			if (((_op1 & 0b101) == 0b000) & ((_op & 0b1111110) == 0b0111000)) {
				return opcode.msr_32;
			}
			if (_op == 0b0111010) {
				ubyte __op1 = cast(ubyte)((instr >> 8) & 0b111);
				ubyte __op2 = cast(ubyte)(instr & 0b11111111);
				if (__op1 == 0b000) {
					if (__op2 == 0b00000000) {
						return opcode.nop_32;
					}
				}
			}
			/*
			if (_op == 0b0111011) {
				ubyte __op = cast(ubyte)((instr >> 4) & 0b1111);
				return opcode.dsb; 
			}
			*/
			if (((_op1 & 0b101) == 0b000) && ((_op & 0b0111000) != 0b0111000)) {
				if (cast(ubyte)((instr >> 12) & 0b1) == 0b1) {
					return opcode.b_uncond_32;
				}
				return opcode.b_32;
			}
			if ((_op1 & 0b101) == 0b001) {
				if (cast(ubyte)((instr >> 12) & 0b1) == 0b1) {
					return opcode.b_uncond_32;
				}
				return opcode.b_32;
			}
		}
		if (((op2 & op2_32.data_proc_imm) == 0b0000000) && !op) {
			ubyte _op = cast(ubyte)((instr >> 20) & 0b11111);
			ubyte rd_ = cast(ubyte)((instr >> 8) & 0xf);
			ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
			if (((_op & 0b11110) == 0b00100) & (rn == 0b1111)) {
				return opcode.mov_imm_32_t2;
			}      
			if (((_op & 0b11110) == 0b11010)) {
				// 0xF1B37F80
				// 1111 0001 1011 0011 0111 1111 1000 0000
				if (rd_ != 0b1111) {
					return opcode.sub_imm_32;
				}
				if (rd_ == 0b1111) {
					return opcode.cmp_imm_32;
				}
			} 
			if ((_op & 0b11110) == 0b00000) {
				if (rd_ != 0b1111) {
					return opcode.and_imm_32;
				}
				if (rd_ == 0b1111) {
					return opcode.tst_32;
				}
			}
			if (((_op & 0b11110) == 0b00100) && (rn != 0b1111)) {
				return opcode.orr_32;
			}
			if (((_op & 0b11110) == 0b00100) && (rn == 0b1111)) {	
				return opcode.mov_32;
			}
			if ((_op & 0b11110) == 0b00110) {
				if (rn != 0b1111) {
					return opcode.bit_or_not_32;
				}
				if (rn == 0b1111) {
					return opcode.bit_not_32;
				}
			}
			if (((_op & 0b11110) == 0b10000) && (rd != 0b1111)) {	
				return opcode.add_32;
			}
			if ((_op & 0b11110) == 0b00010) {
				return opcode.bic_imm_32;
			}
			if ((_op & 0b11110) == 0b11100) {
				return opcode.rsb_32;
			}
		}
		if (((op2 & op2_32.data_proc_bin_imm) == op2_32.data_proc_bin_imm) && !op) {
			ubyte _op = cast(ubyte)((instr >> 20) & 0b11111);
			ubyte _rn = cast(ubyte)((instr >> 16) & 0b11111);
			if (_op == 0b11100) {
				return opcode.ubfx_32;
			}
			if (_op == 0b00100) {
				return opcode.mov_16_imm_32;
			}
			if (_op == 0b01100) {
				return opcode.movt_32;
			}
			if (_op == 0b10100) {
				return opcode.sbfx_32;
			}
			if ((_op == 0b10110) && (_rn != 0b1111)) {
				return opcode.bfi_32;
			}
			if ((_op == 0b10110) && (_rn != 0b1111)) {
				return opcode.bfc_32;
			}
			if ((_op == 0b01010) && (_rn != 0b1111)) {
				return opcode.sub_imm_32;
			}
			if ((_op == 0b01010) && (_rn == 0b1111)) {
				return opcode.adr_32;
			}
			if ((_op == 0b00000) && (_rn == 0b1111)) {
				return opcode.adr_32;
			}
			if ((_op == 0b00000) && (_rn == 0b1111)) {
				return opcode.add_imm_32;
			}
		}
	}
	if (op1 == op1_32.grp3) {
		ubyte _op = cast(ubyte)((instr >> 20) & 0b111);
		if ((op2 & op2_32.ldh) == 0b0000011) {
			return opcode.ldh_32;
		}
		if ((op2 & op2_32.long_mult) == 0b0111000) {
			if (_op == 0b011) { 
				return opcode.udiv_32;
			}
			if (_op == 0b010) {
				return opcode.umull_32;
			}
		}
		if ((op2 & op2_32.mult) == 0b0110000) {
			ubyte ra = cast(ubyte)((instr >> 12) & 0b1111);
			ubyte _op2 = cast(ubyte)((instr >> 4) & 0b11);
			if (_op == 0b000) { 
				if (_op2 == 0b00) {
					if (ra == 0b1111) {
						return opcode.mul_32;
					}
				}
				if (_op2 == 0b01) {
					return opcode.mls_32;
				}
			}
		}
		if ((op2 & op2_32.data_proc_reg) == 0b0100000) {
			ubyte _rn = cast(ubyte)((instr >>  16) & 0b1111);
			ubyte _op1 = cast(ubyte)((instr >> 20) & 0b1111);
			ubyte _op2 = cast(ubyte)((instr >>  4) & 0b1111);
			if (((_op1 & 0b1110) == 0b0000) && _op2 == 0b0) {
				return opcode.lsl_reg_32;
			}
			if (((_op1 & 0b1110) == 0b0010) && _op2 == 0b0) {
				return opcode.lsr_reg_32;
			}
			if (((_op1 & 0b1110) == 0b0100) && _op2 == 0b0) {
				return opcode.asr_reg_32;
			}
			if (((_op1 & 0b1110) == 0b0110) && _op2 == 0b0) {
				return opcode.ror_32;
			}
			if ((_op1 == 0b0000) && ((_op2 & 0b1000) == 0b1000) && (_rn != 0b1111)) {
				return opcode.sxtah_32;
			}
			if ((_op1 == 0b0000) && ((_op2 & 0b1000) == 0b1000) && (_rn == 0b1111)) {
				return opcode.sxth_32;
			}
			if ((_op1 == 0b0001) && ((_op2 & 0b1000) == 0b1000) && (_rn != 0b1111)) {
				return opcode.uxtah_32;
			}
			if ((_op1 == 0b0001) && ((_op2 & 0b1000) == 0b1000) && (_rn == 0b1111)) {
				return opcode.uxth_32;
			}
			if ((_op1 == 0b0010) && ((_op2 & 0b1000) == 0b1000) && (_rn != 0b1111)) {
				return opcode.sxtab_16_32;
			}
			if ((_op1 == 0b0010) && ((_op2 & 0b1000) == 0b1000) && (_rn == 0b1111)) {
				return opcode.sxtb16_32;
			}
			if ((_op1 == 0b0011) && ((_op2 & 0b1000) == 0b1000) && (_rn != 0b1111)) {
				return opcode.uxtab_16_32;
			}
			if ((_op1 == 0b0011) && ((_op2 & 0b1000) == 0b1000) && (_rn == 0b1111)) {
				return opcode.uxtb16_32;
			}
			if ((_op1 == 0b0100) && ((_op2 & 0b1000) == 0b1000) && (_rn != 0b1111)) {
				return opcode.sxtab_32;
			}
			if ((_op1 == 0b0100) && ((_op2 & 0b1000) == 0b1000) && (_rn == 0b1111)) {
				return opcode.sxtb_32;
			}
			if ((_op1 == 0b0101) && ((_op2 & 0b1000) == 0b1000) && (_rn != 0b1111)) {
				return opcode.uxtab_32;
			}
			if ((_op1 == 0b0101) && ((_op2 & 0b1000) == 0b1000) && (_rn == 0b1111)) {
				return opcode.uxtb_32;
			}
			if (((_op1 & 0b1000) == 0b1000) && ((_op2 & 0b1100) == 0b0000)) {
				return opcode.uadd8_32;
			}
			if (((_op1 & 0b1000) == 0b1000) && ((_op2 & 0b1100) == 0b0100)) {
				return opcode.uadd8_32;
			}
			if (((_op1 & 0b1100) == 0b1000) && ((_op2 & 0b1100) == 0b1000)) {
				ubyte __op1 = cast(ubyte)((instr >> 20) & 0b11);
				ubyte __op2 = cast(ubyte)((instr >>  4) & 0b11);
				if ((__op1 == 0b00) && (__op2 == 0b00)) {
					return opcode.qadd_32;
				}
				if ((__op1 == 0b00) && (__op2 == 0b01)) {
					return opcode.qdadd_32;
				}
				if ((__op1 == 0b00) && (__op2 == 0b10)) {
					return opcode.qsub_32;
				}
				if ((__op1 == 0b00) && (__op2 == 0b11)) {
					return opcode.qdsub_32;
				}
				if ((__op1 == 0b01) && (__op2 == 0b00)) {
					return opcode.rev_32;
				}
				if ((__op1 == 0b01) && (__op2 == 0b01)) {
					return opcode.rev_16_32;
				}
				if ((__op1 == 0b01) && (__op2 == 0b10)) {
					return opcode.rbit_32;
				}
				if ((__op1 == 0b01) && (__op2 == 0b11)) {
					return opcode.revsh_32;
				}
				if ((__op1 == 0b10) && (__op2 == 0b00)) {
					return opcode.sel_32;
				}
				if ((__op1 == 0b11) && (__op2 == 0b00)) {
					return opcode.clz_32;
				}
			}
		}
		if ((op2 & op2_32.load_word) == 0b0000101) {
			ubyte _op2 = cast(ubyte)((instr >>  6) & 0b111111);
			ubyte _op1 = cast(ubyte)((instr >> 23) & 0b11);
			ubyte _rn = cast(ubyte)((instr >>  16) & 0xf);
			if ((_op1 == 0b01) && (_rn != 0b1111)) {
				return opcode.ldr_imm_32_t3;
			}
			if ((_op1 == 0b00) && ((_op2 & 0b100100) == 0b100100) && (_rn != 0b1111)) {
				return opcode.ldr_imm_32_t4;	
			}
			if ((_op1 == 0b00) && ((_op2 & 0b111100) == 0b110000) && (_rn != 0b1111)) {
				return opcode.ldr_imm_32_t4;
			}
			if ((_op1 == 0b00) && ((_op2 & 0b111100) == 0b111000) && (_rn != 0b1111)) {
				return opcode.ldrt_32;
			}
			if ((_op1 == 0b00) && (_op2 == 0b0) && (_rn != 0b1111)) {
				return opcode.ldr_reg_32;
			}
			if (((_op1 & 0b10) == 0b00) && (_rn == 0b1111)) {
				return opcode.ldr_lit_32;
			}
		}
		if ((op2 & op2_32.store_single_data_item) == 0b0000000) {
			ubyte _op2 = cast(ubyte)((instr >>  6) & 0b111111);
			ubyte _op1 = cast(ubyte)((instr >> 21) & 0b111);
			if (_op1 == 0b100) {
				return opcode.strb_imm_32_t2;
			}
			if ((_op1 == 0b000) && ((_op2 & 0b100000) == 0b100000)) {
				return opcode.strb_imm_32_t3;
			}
			if ((_op1 == 0b000) && ((_op2 & 0b100000) == 0b000000)) {
				return opcode.strb_reg_32;
			}
			// half
			if (_op1 == 0b101) {
				return opcode.strh_imm_32_t2;
			}
			if ((_op1 == 0b001) && ((_op2 & 0b100000) == 0b100000)) {
				return opcode.strh_imm_32_t3;
			}
			if ((_op1 == 0b001) && ((_op2 & 0b100000) == 0b000000)) {
				return opcode.strh_reg_32;
			}
			// reg
			if (_op1 == 0b110) {
				return opcode.str_imm_32_t3;
			}
			if ((_op1 == 0b010) && ((_op2 & 0b100000) == 0b100000)) {
				return opcode.str_imm_32_t4;
			}
			if ((_op1 == 0b010) && ((_op2 & 0b100000) == 0b000000)) {
				return opcode.str_reg_32;
			}
		}
		if ((op2 & op2_32.load_byte) == 0b0000001) {
			ubyte _op2 = cast(ubyte)((instr >>  6) & 0b111111);
			ubyte _op1 = cast(ubyte)((instr >> 23) & 0b11);
			ubyte rt = cast(ubyte)((instr >> 12) & 0b1111);
			ubyte rn = cast(ubyte)((instr >> 16) & 0b1111);
			if (((_op1 & 0b10) == 0b00) && (rn == 0b1111) && (rt != 0b1111)) {
				return opcode.ldrb_32;
			}
			if ((_op1 == 0b01) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrb_imm_32_t2;
			}
			if ((_op1 == 0b00) && ((_op2 & 0b100100) == 0b100100) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrb_imm_32_t3;
			}
			if ((_op1 == 0b00) && ((_op2 & 0b111100) == 0b110000) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrb_imm_32_t3;
			}
			// ldrbt
			if ((_op1 == 0b00) && ((_op2 & 0b111100) == 0b111000) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrbt_32;
			}
			// ldrb
			if ((_op1 == 0b00) && ((_op2 & 0b000000) == 0b110000) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrb_reg_32;
			}
			// ldrsb
			if (((_op1 & 0b10) == 0b10) && (rn == 0b1111) && (rt != 0b1111)) {
				return opcode.ldrsb_32;
			}
			// ldrsb_imm
			if ((_op1 == 0b11) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrsb_imm_32_t1;
			}
			if ((_op1 == 0b10) && ((_op2 & 0b100100) == 0b100100) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrsb_imm_32_t2;
			}
			if ((_op1 == 0b10) && ((_op2 & 0b111100) == 0b110000) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrsb_imm_32_t2;
			}
			// ldrsbt
			if ((_op1 == 0b10) && ((_op2 & 0b111100) == 0b111000) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrsbt_32;
			}
			// ldrsb
			if ((_op1 == 0b10) && (_op2 == 0b000000) && (rn != 0b1111) && (rt != 0b1111)) {
				return opcode.ldrsb_reg_32;
			}
			// 
			if ((_op1 == 0b00) && (_op2 == 0b000000) && (rn != 0b1111) && (rt == 0b1111)) {
				return opcode.pld_reg_32;
			}
			// pld literal
			if (((_op1 & 0b10) == 0b00) && (rn == 0b1111) && (rt == 0b1111)) {
				return opcode.pld_32;
			}
			// pld immediate
			if ((_op1 == 0b00) && ((_op2 & 0b111100) == 0b110000) && (rn != 0b1111) && (rt == 0b1111)) {
				return opcode.pld_imm_32;
			}
			if ((_op1 == 0b01) && (rn != 0b1111) && (rt == 0b1111)) {
				return opcode.pld_imm_32;
			}
		}
	}
	return opcode.invalid;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		uint instr;
		opcode expected;
	}

	test_case[] tests = [
		test_case(0xeb0101a3, opcode.add_32_reg),
		test_case(0xf7ffffda, opcode.bl_32),
		test_case(0xf3af8000, opcode.nop_32),
		test_case(0xe8bd4008, opcode.pop_mult_reg_32),
		test_case(0xf5a33a80, opcode.sub_imm_32),
		test_case(0xf008ff15, opcode.bl_32),
		test_case(0xf009f8a6, opcode.bl_32),
		test_case(0xf003030c, opcode.and_imm_32),
		test_case(0xfbb2f3f3, opcode.udiv_32),
		test_case(0xf3c20208, opcode.ubfx_32),
		test_case(0xfb02f303, opcode.mul_32),
		test_case(0xfa22f303, opcode.lsr_reg_32),
		test_case(0xf4434380, opcode.orr_32),
		test_case(0xf1070314, opcode.add_32),
		test_case(0xf0230310, opcode.bic_imm_32),
		test_case(0xf64f03ff, opcode.mov_16_imm_32),
		test_case(0xf9973007, opcode.ldrsb_imm_32_t1),
		test_case(0xf8412023, opcode.str_reg_32),
		test_case(0xf8dfd034, opcode.ldr_lit_32),
		test_case(0xf3bf8f4f, opcode.dsb_32),
		test_case(0xf1c30307, opcode.rsb_32),
		test_case(0xfba22303, opcode.umull_32),
		test_case(0xe9c72300, opcode.strd_32),
		test_case(0xf67fae90, opcode.b_32),
		test_case(0xe92d4fb0, opcode.push_mult_reg_32),
		test_case(0xea4161d2, opcode.orr_reg_32),
		test_case(0xebb2080a, opcode.subs_32),
		test_case(0xeb63090b, opcode.sbc_32),
		test_case(0xeb45030b, opcode.adc_32),
		test_case(0xf06f0240, opcode.bit_not_32),
		test_case(0xe8533f00, opcode.ld_rex),
		test_case(0xe8412300, opcode.str_rex),
		test_case(0xfb0e7711, opcode.mls_32),
		test_case(0xf9b4500c, opcode.ldh_32),
		test_case(0xea1c0f0e, opcode.tst_32),
		test_case(0xea010808, opcode.and_reg_32),
		test_case(0xea23030c, opcode.bic_reg_32),
		test_case(0xf7ffbfbb, opcode.b_uncond_32),
		test_case(0xeba30605, opcode.subs_32),
		test_case(0xea4f06a6, opcode.mov_32),
		// 1110 1010 0100 1111 0000 0110 1010 0110
		test_case(0xf8553b04, opcode.ldr_imm_32_t4), // f8553b04
		test_case(0xf7ffb8f7, opcode.b_uncond_32),
		test_case(0xf8441023, opcode.str_reg_32),
		test_case(0xf8c46188, opcode.str_imm_32_t3),
		// 1111 1000 1100 0100 0110 0001 1000 1000
		test_case(0xe8bd4008, opcode.pop_mult_reg_32),
		// 1110 1000 1011 1101 0100 0000 0000 1000
		test_case(0xeb0101a3, opcode.add_32_reg),
		test_case(0xf1b37f80, opcode.cmp_imm_32),
		test_case(0xf1070318, opcode.add_32),
		test_case(0xfa02f303, opcode.lsl_reg_32),
		test_case(0xe92d4fb0, opcode.push_mult_reg_32),
		test_case(0xea400301, opcode.orr_reg_32),
		test_case(0xe9d7453a, opcode.ldrd_imm_32),
		test_case(0xe9d78928, opcode.ldrd_imm_32),
		test_case(0xf04f31ff, opcode.mov_imm_32_t2),
		test_case(0xf04f30ff, opcode.mov_imm_32_t2),
		test_case(0xe8bd4010, opcode.pop_mult_reg_32),
		test_case(0xf883203c, opcode.strb_imm_32_t2),
		test_case(0xf9973007, opcode.ldrsb_imm_32_t1),
		test_case(0xf890f000, opcode.pld_imm_32),
		test_case(0xf893303d, opcode.ldrb_imm_32_t2),
		test_case(0xf997300f, opcode.ldrsb_imm_32_t1),
		test_case(0xf8832300, opcode.strb_imm_32_t2),
		test_case(0xf8032b01, opcode.strb_imm_32_t3),
		test_case(0xf8522023, opcode.ldr_reg_32),
		test_case(0xf8dfd034, opcode.ldr_lit_32),
		test_case(0xf8d33088, opcode.ldr_imm_32_t3),
		test_case(0xf8533022, opcode.ldr_reg_32),
		test_case(0xf3ef8305, opcode.mrs_32),
	 	test_case(0xf3808808, opcode.msr_32),
	 	test_case(0xf3bf8f6f, opcode.isb_32),
	 	test_case(0xf3bf8f4f, opcode.dsb_32),
	 	test_case(0xf8114b01, opcode.ldrb_imm_32_t3),
	 	test_case(0xf3c20208, opcode.ubfx_32),
	 	test_case(0xf8423c20, opcode.str_imm_32_t4),
	 	test_case(0xf003030f, opcode.and_imm_32),
	 	test_case(0xf0230301, opcode.bic_imm_32) 
	];

	foreach (t; tests) {
		auto actual = decode_mnemonic_32(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%08X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}

enum condition : ubyte {
	cs = 0b0010,
	eq = 0b0000,
	ge = 0b1010,
	le = 0b1101,
	mi = 0b0100,
	ne = 0b0001,
	pl = 0b0101,
	hi = 0b1000,
	ls = 0b1001,
	vs = 0b0110,
	vc = 0b0111,
	cc = 0b0011, 	// carry clear
	invalid = 0xff
}

struct instr_16 {
	uint addr;
	opcode op;
	reg rd;
	reg rm;
	reg rn;
	reg rt;
	uint imm;
	int offset;
	int imm_long;
	condition cond;
	reg[] reg_list = null;
	bool set_flags;
	ubyte first_cond;
	ubyte mask;
}

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_reg = [Tuple!(opcode, string[])(opcode.add_reg, ["rd","rn","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move, and Compare
	ADD <Rd>,<Rn>,<Rm>
	[15:9] 0001100
	[8:6] Rm
	[5:3] Rn
	[2:0] Rd
*/
instr_16 parse_add_reg(short instr) {
	instr_16 res;
	res.op = opcode.add_reg;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_high_reg_1 = [Tuple!(opcode, string[])(opcode.add_high_reg_1, ["rd","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ADD <Rdn>,<Rm>
	[15:8] 01000100
	[7] DN
	[6:3] Rm
	[2:0] Rdn
*/
instr_16 parse_add_high_reg_1(short instr) {
	instr_16 res;
	res.op = opcode.add_high_reg_1;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte dn = cast(ubyte)((instr >> 7) & 0b1);
	if (dn) {
		rdn |= 0b1000;
	}
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_high_reg_2 = [Tuple!(opcode, string[])(opcode.add_high_reg_2, ["rd","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ADD <Rdn>,<Rm>
	[15:8] 01000100
	[7] DN
	[6:3] Rm
	[2:0] Rdn
*/
instr_16 parse_add_high_reg_2(short instr) {
	instr_16 res;
	res.op = opcode.add_high_reg_2;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte dn = cast(ubyte)((instr >> 7) & 0b1);
	if (dn) {
		rdn |= 0b1000;
	}
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// ======================
//  Parse ADD(Immediate)
// ======================

enum field_tuples_add_imm_3 = [Tuple!(opcode, string[])(opcode.add_imm_3, ["rd","rn","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move, and Compare
	ADD <Rd>,<Rn>,#<imm3>
	[15:9] 0001110
	[8:6] imm3 
	[5:3] Rn
	[2:0] Rd
*/
instr_16 parse_add_imm_3(short instr) {
	instr_16 res;
	res.op = opcode.add_imm_3;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_3 = cast(ubyte)((instr >> 6) & 0b111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.imm = imm_3;
	return res;
}

// ======================
//  Parse ADD(Immediate)
// ======================

enum field_tuples_add_imm_8 = [Tuple!(opcode, string[])(opcode.add_imm_8, ["rn","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ADD <Rd>,<Rn>,#<imm3>
	[15:11] 00110
	[10:8] Rdn
	[7:0] imm8
*/
instr_16 parse_add_imm_8(short instr) {
	instr_16 res;
	res.op = opcode.add_imm_8;
	ubyte rdn = cast(ubyte)((instr >> 8) & 0b111);
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	return res;
}

// ==================
//  Parse ADD LO REG
// ==================

enum field_tuples_add_lo_reg = [Tuple!(opcode, string[])(opcode.add_lo_reg, ["rd","rm","imm"])];
/*
	Special Data Instructions and Branch and Exchange
	ADD <Rdn>,<Rm>
	[15:8] 01000100
	[7] DN
	[6:3] Rm
	[2:0] Rdn  
*/
instr_16 parse_add_lo_reg(short instr) {
	instr_16 res;
	res.op = opcode.add_lo_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// ==============================
//  Parse ADD(SP Plus Immediate)
// ==============================

enum field_tuples_add_sp_t2 = [Tuple!(opcode, string[])(opcode.add_sp_t2, ["sp","imm"])];
enum field_tuples_add_sp_t1 = [Tuple!(opcode, string[])(opcode.add_sp_t1, ["rd","sp","imm"])];
/*
	General SP-Relative Address
	ADD <Rd>,SP,#<imm8>
	[15:11] 10101
	[10:8] Rd
	[7:0] imm8
*/
instr_16 parse_add_sp(short instr) {
	instr_16 res;
	ubyte first_four = cast(ubyte)((instr >> 12) & 0xf);
	if (first_four == 0b1011) {
		res.op = opcode.add_sp_t2;
		res.rd = reg.sp;
		ubyte imm_7 = cast(ubyte)(instr & 0x3f);
		res.imm = (imm_7 << 2);
	} else {
		res.op = opcode.add_sp_t1;
		ubyte imm_8 = cast(ubyte)(instr & 0xff);
	  	ubyte rd = cast(ubyte)((instr >> 8) & 0b111);
		res.imm = (imm_8 << 2);
		res.rd = cast(reg)(rd);
	}
	return res;
}

// ===========
//  Parse ADR
// ===========

enum field_tuples_adr = [Tuple!(opcode, string[])(opcode.adr, ["rd","pc","imm"])];
/*
	Generate PC-Relative Address
	ADR <Rd>,<Label>
	[15:11] 10100
	[10:8] Rd
	[7:0] imm8  
*/
instr_16 parse_adr(short instr) {
	instr_16 res;
	res.op = opcode.adr;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0b111);
	res.imm = cast(ubyte)(imm_8 * 4);
	res.rd = cast(reg)(rd);
	return res;
}

// =====================
//  Parse AND(Register)
// =====================

enum field_tuples_and_reg = [Tuple!(opcode, string[])(opcode.and_reg, ["rd","rm"])];
/*
	Data Processing
	AND <Rdn>,<Rm>
	[15:6] 0100000000
	[5:3] Rm
	[2:0] Rdn
*/
instr_16 parse_and_reg(short instr) {
	instr_16 res;
	res.op = opcode.and_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// ======================
//  Parse ASR(Immediate)
// ======================

enum field_tuples_asr_imm = [Tuple!(opcode, string[])(opcode.asr_imm, ["rm","rd","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ASR <Rd>,<Rm>,#<imm5>
	[15:11] 00010
	[10:6] imm5
	[5:3] Rm
	[2:0] Rd  
*/
instr_16 parse_asr_imm(short instr) {
	instr_16 res;
	res.op = opcode.asr_imm;
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = imm;
	res.rm = cast(reg)(rm);
	res.rd = cast(reg)(rd);
	return res;
}

// =========
//  Parse B
// =========

enum field_tuples_b_cond = [Tuple!(opcode, string[])(opcode.b_cond, [])];
/*
	Condtional Branch, and Supervisor Call
	B <label>
	[15:12] 1101
	[11:8] cond
	[7:0] imm8
*/
instr_16 parse_b_cond(short instr) {
	instr_16 res;
	res.op = opcode.b_cond;
	ubyte cond = cast(ubyte)((instr >> 8 ) & 0xf);
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	byte s = cast(byte) imm_8; 
	int imm_32 = cast(int)s << 1;
	res.cond = cast(condition)(cond);
	res.offset = imm_32;
	return res;
}

// =========
//  Parse B
// =========

enum field_tuples_b_imm_11 = [Tuple!(opcode, string[])(opcode.b_imm_11, [])];
/*
	Uncondtional Branch
	B <label>
	[15:11] 11100
	[10:0] imm11
*/
// e001      	b.n	800a1b6 <LoopFillZerobss>
// 1110 0000 0000 0001
instr_16 parse_b_imm_11(short instr) {
	//  800023a:	e7cf      	b.n	80001dc
	instr_16 res;
	res.op = opcode.b_imm_11;
	int imm_11 = cast(int)(instr & 0x7ff); 
	imm_11 <<= 1;              
    if ((imm_11 & 0x800) != 0) { 
        imm_11 |= ~0xfff; 
    }
	res.offset = imm_11;
	return res; 
}

// =====================
//  Parse BLX(Register)
// =====================

enum field_tuples_blx = [Tuple!(opcode, string[])(opcode.blx, ["rm"])];
/*
	Special Data Instructions and Branch and Exchange
	BLX <Rm>
	[15:8] 010001111
	[6:3] Rm
	[2:0] 000
*/
instr_16 parse_blx(short instr) {
	instr_16 res;
	res.op = opcode.blx;
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	res.rm = cast(reg)(rm);
	return res;
} 

// ==========
//  Parse BX
// ==========

enum field_tuples_bx = [Tuple!(opcode, string[])(opcode.bx, ["rm"])];
/*
	Special Data Instructions and Branch and Exchange
	BX <Rm>
	[15:7] 010001110
	[6:3] Rm
	[2:0] 000
*/
instr_16 parse_bx(short instr) {
	instr_16 res;
	res.op = opcode.bx;
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	res.rm = cast(reg)(rm);
	return res;
}

// ============
//  Parse CBNZ
// ============

enum field_tuples_cmp_br_nz = [Tuple!(opcode, string[])(opcode.cmp_br_nz, ["rn"])];
/*
	Miscellaneous 16-Bit Instructions
	CBNZ <Rn>,<label>
	[15:12] 1011
	[11] op
	[10] 0
	[9] i
	[8] 1
	[7:3] imm5
	[2:0] Rn  
*/
instr_16 parse_cmp_br_nz(short instr) {
	instr_16 res;
	res.op = opcode.cmp_br_nz;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte i = cast(ubyte)((instr >> 9) & 0b1);
	ushort imm_5 = cast(ushort)((instr >> 3) & 0b11111);
	uint imm = (i << 6) | (imm_5 << 1);
	res.rn = cast(reg)(rn);
	res.offset = imm;
	return res;
}

// ===========
//  Parse CBZ
// ===========

enum field_tuples_cmp_br_z = [Tuple!(opcode, string[])(opcode.cmp_br_z, ["rn"])];
/*
	Miscellaneous 16-Bit Instructions
	CBZ <Rn>,<label>
	[15:12] 1011
	[11] op
	[10] 0
	[9] i
	[8] 1
	[7:3] imm5
	[2:0] Rn  
*/
// b113: 1011 0001 0001 0011
instr_16 parse_cmp_br_z(short instr) {
	instr_16 res;
	res.op = opcode.cmp_br_z;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte i = cast(ubyte)((instr >> 9) & 0b1);
	short imm_5 = cast(short)((instr >> 3) & 0b11111);
	uint imm = (i << 6) | (imm_5 << 1);
	res.rn = cast(reg)(rn);
	res.offset = imm;
	return res;
}

// ======================
//  Parse CMP(Immediate)
// ======================

enum field_tuples_cmp_imm = [Tuple!(opcode, string[])(opcode.cmp_imm, ["rn","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	CMP <Rn>,#<imm8>
	[15:11] 00101
	[10:8] Rn 
	[7:0] imm8  
*/
instr_16 parse_cmp_imm(short instr) {
	instr_16 res;
	res.op = opcode.cmp_imm;
	ubyte rn = cast(ubyte)((instr >> 8) & 0b111);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	res.rn = cast(reg)(rn);
	return res;
}

// =====================
//  Parse CMP(Register)
// =====================

enum field_tuples_cmp_reg = [Tuple!(opcode, string[])(opcode.cmp_reg, ["rn","rm"])];
/*
	Special Data Instructions and Branch and Exchange
	CMP <Rn>,<Rm>
	[15:6] 0100001010
	[5:3] Rm
	[2:0] Rn
*/
instr_16 parse_cmp_reg(short instr) {
	instr_16 res;
	res.op = opcode.cmp_reg;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse CMP(Register)
// =====================

enum field_tuples_cmp_high_1 = [Tuple!(opcode, string[])(opcode.cmp_high_1, ["rn","rm"])];
/*
	Special Data Instructions and Compare and Exchange
	CMP <Rn>,<Rm>
	[15:8] 01000101
	[7] N
	[6:3] Rm
	[2:0] Rn
*/
instr_16 parse_cmp_high_1(short instr) {
	instr_16 res;
	res.op = opcode.cmp_high_1;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte n = cast(ubyte)((instr >> 7) & 0b1);
	if (n) {
		rn |= 0b1000; 
	}
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse CMP(Register)
// =====================

enum field_tuples_cmp_high_2 = [Tuple!(opcode, string[])(opcode.cmp_high_2, ["rn","rm"])];
/*
	Special Data Instructions and Compare and Exchange
	CMP <Rn>,<Rm>
	[15:8] 01000101
	[7] N
	[6:3] Rm
	[2:0] Rn
*/
instr_16 parse_cmp_high_2(short instr) {
	instr_16 res;
	res.op = opcode.cmp_high_2;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte N = cast(ubyte)((instr >> 7) & 0b1);
	if (N) {
		rn |= 0b1000;
	}
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldr_imm = [Tuple!(opcode, string[])(opcode.ldr_imm, ["rt","rn","imm"])];
/*
	Load/Store Single Data Item
	LDRB <Rt>,[<Rn>{,#<imm5>}]
	[15:11] 01101
	[10:6] imm5
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_ldr_imm(ushort instr) {
	instr_16 res;
	res.op = opcode.ldr_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_5 = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = (imm_5 << 2);
	return res;
}

// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldr_sp = [Tuple!(opcode, string[])(opcode.ldr_sp, ["rt","sp","imm"])];
/*
	Load/Store Single Data Item
	LDR <Rt>,[SP{,#<imm8>}]
	[15:11] 10011
	[10:8] Rt
	[7:0] imm8
*/
instr_16 parse_ldr_sp(ushort instr) {
	instr_16 res;
	res.op = opcode.ldr_sp;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 8) & 0b111);
	res.rt = cast(reg)(rt);
	res.imm = (imm_8 << 2);
	return res;
}


// ====================
//  Parse LDR(Literal)
// ====================

enum field_tuples_ldr_pool = [Tuple!(opcode, string[])(opcode.ldr_pool, ["rt","pc","imm"])];
/*
	Load from Literal Pool
	LDR <Rt>,<label>
	[15:11] 01001
	[10:8] Rm
	[7:0] imm8
*/
instr_16 parse_ldr_pool(short instr) {
	instr_16 res;
	res.op = opcode.ldr_pool;
	ubyte rt = cast(ubyte)((instr >> 8) & 0b111);
	int imm_8 = instr & 0xff;
	imm_8 <<= 2;
	res.rt = cast(reg)(rt);
	res.imm = imm_8;
	return res;
}

// =====================
//  Parse LDR(Register)
// =====================

enum field_tuples_ldr_reg = [Tuple!(opcode, string[])(opcode.ldr_reg, ["rt","rn","rm"])];
/*
	Load/Store Single Data Item
	LDR <Rt>,[<Rn>,<Rm>]
	[15:9] 0101100
	[8:6] Rm
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_ldr_reg(short instr) {
	instr_16 res;
	res.op = opcode.ldr_reg;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Parse LDRB(Immediate)
// =======================

enum field_tuples_ldrb_imm = [Tuple!(opcode, string[])(opcode.ldrb_imm, ["rt","rn","imm"])];
/*
	Load/Store Single Data Item
	LDRB <Rt>,[<Rn>{,#<imm5>}]
	[15:11] 01111
	[10:6] imm5
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_ldrb_imm(short instr) {
	instr_16 res;
	res.op = opcode.ldrb_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_5 = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_5;
	return res;
}

// =======================
//  Parse LDRH(Immediate)
// =======================

enum field_tuples_ldrh_imm = [Tuple!(opcode, string[])(opcode.ldrh_imm, ["rt","rn","imm"])];
/*
	Load/Store Single Data Item
	LDRH <Rt>,[<Rn>{,#<imm5>}]
	[15:11] 10001
	[10:6] imm5
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_ldrh_imm(short instr) {
	instr_16 res;
	res.op = opcode.ldrh_imm;
	ubyte rt = cast(ubyte)( instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_5 = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = cast(ubyte)(imm_5 * 2);
	return res;
}

// ======================
//  Parse LSL(Immediate)
// ======================

enum field_tuples_lsl_imm = [Tuple!(opcode, string[])(opcode.lsl_imm, ["rd","rm","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	LSL <Rd>,<Rm>,#<imm5>
	[15:11] 00000
	[10:6] imm5
	[5:3] Rm
	[2:0] Rd
*/
instr_16 parse_lsl_imm(short instr) {
	instr_16 res;
	res.op = opcode.lsl_imm;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = imm;
	return res;
}

// =====================
//  Parse LSL(Register)
// =====================

enum field_tuples_lsl_reg = [Tuple!(opcode, string[])(opcode.lsl_reg, ["rd","rm"])];
/*
	Data Processing
	LSL <Rdn>,<Rm>
	[15:6] 0100000010
	[5:3] Rm
	[2:0] Rdn  
*/
instr_16 parse_lsl_reg(short instr) {
	instr_16 res;
	res.op = opcode.lsl_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// ======================
//  Parse LSR(Immediate)
// ======================

enum field_tuples_lsr_imm = [Tuple!(opcode, string[])(opcode.lsr_imm, ["rd","rm","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	LSR <Rd>,<Rm>,#<imm5>
	[15:11] 00001
	[10:6] imm5
	[5:3] Rm
	[2:0] Rd
*/
instr_16 parse_lsr_imm(short instr) {
	instr_16 res;
	res.op = opcode.lsr_imm;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = imm;
	return res;
}

// =====================
//  Parse LSR(Register)
// =====================

enum field_tuples_lsr_reg = [Tuple!(opcode, string[])(opcode.lsr_reg, ["rd","rm"])];
/*                
    Data Processing
	LSR <Rdn>,<Rm>
	[15:6] 0100000011
	[5:3] Rm
	[2:0] Rdn  
*/
instr_16 parse_lsr_reg(short instr) {
	instr_16 res;
	res.op = opcode.lsr_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse MOV(Register)
// =====================

enum field_tuples_mov_high_1 = [Tuple!(opcode, string[])(opcode.mov_high_1, ["rd","rm"])];
/*
	Special Data Instructions and Branch and Exchange
	MOV <Rd>,<Rm>
	[15:8] 01000110
	[7] D
	[6:3] Rm
	[2:0] Rd  
*/
instr_16 parse_mov_high_1(short instr) {
	instr_16 res;
	res.op = opcode.mov_high_1;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte d = cast(ubyte)((instr >> 7) & 0b1);
	if (d) {
		rd |= 0b1000;
	}
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse MOV(Register)
// =====================

enum field_tuples_mov_high_2 = [Tuple!(opcode, string[])(opcode.mov_high_2, ["rd","rm"])];
/*
	Special Data Instructions and Branch and Exchange
	MOV <Rd>,<Rm>
	[15:6] 0000000000
	[7] D
	[5:3] Rm
	[2:0] Rd  
*/
instr_16 parse_mov_high_2(short instr) {
	instr_16 res;
	res.op = opcode.mov_high_2;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

// ======================
//  Parse MOV(Immediate)
// ======================

enum field_tuples_mov_imm = [Tuple!(opcode, string[])(opcode.mov_imm, ["rd","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ADD <Rd>,<Rn>,#<imm3>
	[15:11] 00100
	[10:8] Rd
	[7:0] imm8
*/
instr_16 parse_mov_imm(short instr) {
	instr_16 res;
	res.op = opcode.mov_imm;
	ubyte rd = cast(ubyte)((instr >> 8) & 0b111);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	res.rd = cast(reg)(rd);
	return res;
}

// =====================
//  Parse MOV(Register)
// =====================

enum field_tuples_mov_lo = [Tuple!(opcode, string[])(opcode.mov_lo, ["rd","rm"])];
/*
	Special Data Instructions and Branch and Exchange
	MOV <Rd>,<Rm>
	[15:8] 01000110
	[7] D
	[6:3] Rm
	[2:0] Rd  
*/
instr_16 parse_mov_lo(short instr) {
	instr_16 res;
	res.op = opcode.mov_lo;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte d = cast(ubyte)((instr >> 7) & 0b1);
	if (d) {
		rd |= 0b1000;
	}
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse MVN(Register) 
// =====================

enum field_tuples_mvn_reg = [Tuple!(opcode, string[])(opcode.mvn_reg, ["rd","rm"])];
/*
	Data Processing
	MVN <Rd>,<Rm>
	[15:6] 0100001111`
	[5:3] Rm
	[2:0] Rd
*/
instr_16 parse_mvn_reg(short instr) {
	instr_16 res;
	res.op = opcode.mvn_reg;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

// ============
//  Parse NEGS
// ============

enum field_tuples_negs = [Tuple!(opcode, string[])(opcode.negs, ["rd","rn"])];
/*
	Data Processing
	NEGS <Rd>,<Rn>
	[15:6] 0100001001
	[5:3] Rn
	[2:0] Rd
*/
instr_16 parse_negs(short instr) {
	instr_16 res;
	res.op = opcode.negs;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// =====================
//  Parse ORR(Register)
// =====================

enum field_tuples_lor_reg = [Tuple!(opcode, string[])(opcode.lor_reg, ["rd","rm"])];
/*
	Data Processing
	ORR <Rdn>,<Rm>
	[15:6] 0100001100
	[5:3] Rm
	[2:0] Rdn
*/
instr_16 parse_lor_reg(short instr) {
	instr_16 res;
	res.op = opcode.lor_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// ====================
//  Parse Pop Mult Reg
// ====================

enum field_tuples_pop_mult_reg = [Tuple!(opcode, string[])(opcode.pop_mult_reg, ["reg_list"])];
/*
	Load Multiple Registers
	LDM <Rn>!,<registers>
	[15:9] 11001
	[10:8] Rn
	[7:0] register_list  
*/
instr_16 parse_pop_mult_reg(short instr) {
	instr_16 res;
	res.op = opcode.pop_mult_reg;
	ubyte p = cast(ubyte)((instr >> 8) & 0b1);
	ubyte reg_mask = cast(ubyte)(instr & 0xff);
	if (reg_mask & 0x01) res.reg_list ~= reg.r0;
	if (reg_mask & 0x02) res.reg_list ~= reg.r1;
	if (reg_mask & 0x04) res.reg_list ~= reg.r2;
	if (reg_mask & 0x08) res.reg_list ~= reg.r3;
	if (reg_mask & 0x10) res.reg_list ~= reg.r4;
	if (reg_mask & 0x20) res.reg_list ~= reg.r5;
	if (reg_mask & 0x40) res.reg_list ~= reg.r6;
	if (reg_mask & 0x80) res.reg_list ~= reg.r7;
	if (p) {
		res.reg_list ~= reg.pc;
	}
	return res;
}

// =====================
//  Parse Push Mult Reg
// =====================

enum field_tuples_push_mult_reg = [Tuple!(opcode, string[])(opcode.push_mult_reg, ["reg_list"])];
/*
	Store Multiple Registers
	STM <Rn>!,<registers>
	[15:9] 11000
	[10:8] Rn
	[7:0] register_list  
*/
instr_16 parse_push_mult_reg(short instr) {
	instr_16 res;
	res.op = opcode.push_mult_reg;
	ubyte m = cast(ubyte)((instr >> 8) & 0b1);
	ubyte reg_mask = cast(ubyte)(instr & 0xff);
	if (reg_mask & 0x01) res.reg_list ~= reg.r0;
	if (reg_mask & 0x02) res.reg_list ~= reg.r1;
	if (reg_mask & 0x04) res.reg_list ~= reg.r2;
	if (reg_mask & 0x08) res.reg_list ~= reg.r3;
	if (reg_mask & 0x10) res.reg_list ~= reg.r4;
	if (reg_mask & 0x20) res.reg_list ~= reg.r5;
	if (reg_mask & 0x40) res.reg_list ~= reg.r6;
	if (reg_mask & 0x80) res.reg_list ~= reg.r7;
	if (m) {
		res.reg_list ~= reg.lr;
	}
	return res;
}

// ======================
//  Parse STR(Immediate) 
// ======================

enum field_tuples_str_imm = [Tuple!(opcode, string[])(opcode.str_imm, ["rt","rn","imm"])];
/*
	Load/Store Single Data Item
	STR <Rt>,[<Rn>{,#<imm5>}]
	[15:11] 10000
	[10:6] imm5
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_str_imm(short instr) {
	instr_16 res;
	res.op = opcode.str_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	ubyte imm_5 = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = imm_5 << 2;
	return res;
}

// ===========
//  Parse TST 
// ===========

enum field_tuples_tst = [Tuple!(opcode, string[])(opcode.tst, ["rn","rm"])];
/*
	TST <Rn>,<Rm>
	[15:6] 0100001000
	[5:3] Rm
	[2:0] Rn
*/
instr_16 parse_tst(short instr) {
	instr_16 res;
	res.op = opcode.tst;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rm = cast(reg)(rm);
	res.rn = cast(reg)(rn);
	return res;
}

// ========================
//  Parse STRRB(Immediate)
// ========================

enum field_tuples_strb_imm = [Tuple!(opcode, string[])(opcode.strb_imm, ["rt","rn","imm"])];
/*
	Load/Store Single Data Item
	STRB <Rt>,[<Rn>{,#<imm5>}]
	[15:11] 01110
	[10:6] imm5
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_strb_imm(short instr) {
	instr_16 res;
	res.op = opcode.strb_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_5 = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_5;
	return res;
}

// =======================
//  Parse STRRB(Register)
// =======================

enum field_tuples_strb_reg = [Tuple!(opcode, string[])(opcode.strb_reg, ["rt","rn","rm"])];
/*
	Load/Store Single Data Item
	STRB <Rt>,[<Rn>{,#<imm5>}]
	[15:11] 01110
	[10:6] imm5
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_strb_reg(short instr) {
	instr_16 res;
	res.op = opcode.strb_reg;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Parse STRH(Immediate)
// =======================

enum field_tuples_strh_imm = [Tuple!(opcode, string[])(opcode.strh_imm, ["rt","rn","imm"])];
/*
	Load/Store Single Data Item
	STRH <Rd>,<Rm>
	[15:11] 10000
	[10:6] imm5
	[5:3] Rd
	[2:0] Rt
*/
instr_16 parse_strh_imm(short instr) {
	instr_16 res;
	res.op = opcode.strh_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_5 = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_5 << 1;
	return res; 
}

// ======================
//  Parse LDRB(Register)
// ======================

enum field_tuples_ldrb_reg = [Tuple!(opcode, string[])(opcode.ldrb_reg, ["rt","rn","rm"])];
/*
	Load/Store Single Data Item
	LDRB <Rt>,[<Rn>,<Rm>]
	[15:9] 0101110
	[8:6] Rm
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_ldrb_reg(short instr) {
	instr_16 res;
	res.op = opcode.ldrb_reg;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// ======================
//  Parse STR(Immediate)
// ======================

enum field_tuples_str_sp = [Tuple!(opcode, string[])(opcode.str_sp, ["rt","sp","imm"])];
/*
	Load/Store Single Data Item
	STR <Rt>,[SP,#<imm8>]
	[15:11] 10010
	[10:8] Rt
	[7:0] imm8
*/
instr_16 parse_str_sp(short instr) {
	instr_16 res;
	res.op = opcode.str_sp;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 8) & 0b111);
	res.imm = imm_8 << 2;
	res.rt = cast(reg)(rt);
	return res;
}

// =====================
//  Parse STR(Register)
// =====================

enum field_tuples_str_reg = [Tuple!(opcode, string[])(opcode.str_reg, ["rt","rn","rm"])];
/*
	Load/Store Single Data Item
	STR <Rt>,[<Rn>,<Rm>]
	[15:9] 0101000
	[8:6] Rm
	[5:3] Rn
	[2:0] Rt
*/
instr_16 parse_str_reg(short instr) {
	instr_16 res;
	res.op = opcode.str_reg;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}


// ======================
//  Parse SUB(Immediate)
// ======================

enum field_tuples_sub_imm_3 = [Tuple!(opcode, string[])(opcode.sub_imm_3, ["rd","rn","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move, and Compare
	SUB <Rd>,<Rn>,#<imm3>
	[15:9] 0001111
	[8:6] imm3
	[5:3] Rn
	[2:0] Rd
*/
instr_16 parse_sub_imm_3(short instr) {
	instr_16 res;
	res.op = opcode.sub_imm_3;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm_3 = cast(ubyte)((instr >> 6) & 0b111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.imm = imm_3;
	return res;
}

// ======================
//  Parse SUB(Immediate)
// ======================

enum field_tuples_sub_imm_8 = [Tuple!(opcode, string[])(opcode.sub_imm_8, ["rd","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	SUB <Rd>,<Rn>,#<imm8>
	[15:9] 0001111
	[8:6] imm3
	[5:3] Rn
	[2:0] Rd
*/
instr_16 parse_sub_imm_8(short instr) {
	instr_16 res;
	res.op = opcode.sub_imm_8;
	ubyte rdn = cast(ubyte)((instr >> 8) & 0b111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	return res;
}

// =====================
//  Parse SUB(Register)
// =====================

enum field_tuples_sub_reg = [Tuple!(opcode, string[])(opcode.sub_reg, ["rd","rn","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move, and Compare
	SUB <Rd>,<Rn>,<Rm>
	[15:9] 0001101
	[8:6] Rm
	[5:3] Rn
	[2:0] Rd  
*/
instr_16 parse_sub_reg(short instr) {
	instr_16 res;
	res.op = opcode.sub_reg;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// ===============================
//  Parse SUB(SP Minus Immediate)
// ===============================

enum field_tuples_sub_sp = [Tuple!(opcode, string[])(opcode.sub_sp, ["sp","imm"])];
/*
	Miscellaneous 16-Bit Instructions
	SUB SP,SP,#<imm7>
	[15:7] 101100001
	[6:0] imm7  
*/
instr_16 parse_sub_sp(short instr) {
	instr_16 res;
	res.op = opcode.sub_sp;
	ubyte imm_7 = cast(ubyte)(instr & 0x7f);
	res.imm = (imm_7 << 2);
	return res;
}

// ============
//  Parse UXTB
// ============

enum field_tuples_uxtb = [Tuple!(opcode, string[])(opcode.uxtb, ["rd","rm"])];
/*
	Miscellaneous 16-Bit Instructions
	UXTB <Rd>,<Rm>
	[15:6] 1011001011
	[5:3] Rm
	[2:0] Rd  
*/
instr_16 parse_uxtb(short instr) {
	instr_16 res;
	res.op = opcode.uxtb;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

// ===========
//  Parse NOP
// ===========

enum field_tuples_nop = [Tuple!(opcode, string[])(opcode.nop, [])];

instr_16 parse_nop(short instr) {
	instr_16 res;
	res.op = opcode.nop;
	return res;
}

// =====================
//  Parse ADC(Register)
// =====================

enum field_tuples_adc_reg = [Tuple!(opcode, string[])(opcode.adc_reg, ["rd","rm"])];
/*
	Data Processing
	ADC <Rdn>,<Rm>
	[15:6] 0100000101
	[5:3] Rm
	[2:0] Rd  
*/
instr_16 parse_adc_reg(short instr) {
	instr_16 res;
	res.op = opcode.adc_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// ==========
//  Parse IT
// ==========

enum field_tuples_if_then = [Tuple!(opcode, string[])(opcode.if_then, ["condition"])];
/*
	If-Then, and Hints
	IT{x{y{z}}} <firstcond>
	[15:8] 10111111
	[7:4] firstcond
	[3:0] mask  
*/
instr_16 parse_if_then(short instr) {
	instr_16 res;
	res.op = opcode.if_then;
	ubyte mask = cast(ubyte)(instr & 0xf);
	ubyte first_cond = cast(ubyte)((instr >> 4) & 0xf);
	res.mask = mask;
	res.first_cond = first_cond;
	return res;
}

// ==============
//  Decode Instr
// ==============

instr_16 decode_instr(ushort instr) {
    instr_16 res;
    auto op = decode_mnemonic(instr);

    switch (op) {
    	case opcode.ldr_sp:
    		return parse_ldr_sp(instr);
        case opcode.cmp_imm:
            return parse_cmp_imm(instr);
        case opcode.asr_imm:
            return parse_asr_imm(instr);
        case opcode.add_imm_8:
            return parse_add_imm_8(instr);
        case opcode.and_reg:
            return parse_and_reg(instr);
        case opcode.mov_imm:
            return parse_mov_imm(instr);
        case opcode.sub_imm_8:
            return parse_sub_imm_8(instr);
        case opcode.lsl_imm:
        	return parse_lsl_imm(instr);
        case opcode.lsr_imm:
        	return parse_lsr_imm(instr);
        case opcode.lor_reg:
        	return parse_lor_reg(instr);
        case opcode.mvn_reg:
        	return parse_mvn_reg(instr);
        case opcode.str_imm:
        	return parse_str_imm(instr);
        case opcode.strh_imm:
        	return parse_strh_imm(instr);
       	case opcode.ldrh_imm:
       		return parse_ldrh_imm(instr);
       	case opcode.ldrb_imm:
       		return parse_ldrb_imm(instr);
       	case opcode.strb_imm:
       		return parse_strb_imm(instr);
       	case opcode.strb_reg:
       		return parse_strb_reg(instr);
       	case opcode.ldr_imm:
       		return parse_ldr_imm(instr);
       	case opcode.cmp_reg:
       		return parse_cmp_reg(instr);
       	case opcode.ldr_pool:
       		return parse_ldr_pool(instr); 
       	case opcode.b_cond:
       		return parse_b_cond(instr);
       	case opcode.cmp_br_z:
       		return parse_cmp_br_z(instr);
       	case opcode.bx:
       		return parse_bx(instr);
       	case opcode.sub_reg:
       		return parse_sub_reg(instr);
       	case opcode.push_mult_reg:
       		return parse_push_mult_reg(instr);
       	case opcode.cmp_br_nz:
       		return parse_cmp_br_nz(instr);
       	case opcode.pop_mult_reg: 
       		return parse_pop_mult_reg(instr);
       	case opcode.b_imm_11:
       		return parse_b_imm_11(instr);
       	case opcode.mov_high_1:
       		return parse_mov_high_1(instr);
       	case opcode.mov_lo:
       		return parse_mov_lo(instr);
       	case opcode.blx: 
       		return parse_blx(instr);
       	case opcode.add_sp:
       		return parse_add_sp(instr);
       	case opcode.ldrb_reg:
       		return parse_ldrb_reg(instr);
       	case opcode.sub_sp:
       		return parse_sub_sp(instr);
       	case opcode.add_imm_3:
       		return parse_add_imm_3(instr);
       	case opcode.add_lo_reg:
       		return parse_add_lo_reg(instr);
       	case opcode.lsl_reg:
       		return parse_lsl_reg(instr);
       	case opcode.lsr_reg:
       		return parse_lsr_reg(instr);
       	case opcode.adr:
       		return parse_adr(instr);
       	case opcode.mov_high_2:
       		return parse_mov_high_2(instr);
       	case opcode.str_sp:
       		return parse_str_sp(instr);
       	case opcode.add_reg:
       		return parse_add_reg(instr);
       	case opcode.cmp_high_1:
       		return parse_cmp_high_1(instr);
        case opcode.add_high_reg_1:
        	return parse_add_high_reg_1(instr);
        case opcode.add_high_reg_2:
        	return parse_add_high_reg_2(instr);
        case opcode.sub_imm_3:
        	return parse_sub_imm_3(instr);
        case opcode.cmp_high_2:
        	return parse_cmp_high_2(instr);
        case opcode.negs:
        	return parse_negs(instr);
        case opcode.ldr_reg:
        	return parse_ldr_reg(instr);
        case opcode.nop:
        	return parse_nop(instr);
        case opcode.str_reg:
        	return parse_str_reg(instr);
        case opcode.uxtb:
        	return parse_uxtb(instr);
        case opcode.adc_reg:
        	return parse_adc_reg(instr);
        case opcode.if_then:
        	return parse_if_then(instr);
        case opcode.tst:
        	return parse_tst(instr);
        default:
        	res.op = op;
            return res;
    }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		instr_16 expected;
	}

	test_case[] tests = [
		test_case(0x2b00, instr_16(op: opcode.cmp_imm,       rn: reg.r3,              imm: 0)),
		test_case(0x10b6, instr_16(op: opcode.asr_imm,       rd: reg.r6,  rm: reg.r6, imm: 2)),
		test_case(0x3730, instr_16(op: opcode.add_imm_8,     rd: reg.r7,  rn: reg.r7, imm: 48)),
		test_case(0x4013, instr_16(op: opcode.and_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r2)),
		test_case(0x2300, instr_16(op: opcode.mov_imm,       rd: reg.r3,              imm: 0)),
		test_case(0x3902, instr_16(op: opcode.sub_imm_8,     rd: reg.r1,  rn: reg.r1, imm: 2)),
		test_case(0x00d9, instr_16(op: opcode.lsl_imm,       rd : reg.r1, rm: reg.r3, imm: 3)),
		test_case(0x099b, instr_16(op: opcode.lsr_imm,       rd: reg.r3,  rm: reg.r3, imm: 6)),
		test_case(0x4313, instr_16(op: opcode.lor_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r2)),
		test_case(0x43db, instr_16(op: opcode.mvn_reg,       rd: reg.r3,  rm: reg.r3 )),
		test_case(0x608b, instr_16(op: opcode.str_imm,       rt: reg.r3,  rn: reg.r1, imm: 8)),
		test_case(0x80fb, instr_16(op: opcode.strh_imm,      rt: reg.r3,  rn: reg.r7, imm: 6)),
		test_case(0x88fb, instr_16(op: opcode.ldrh_imm,      rt: reg.r3,  rn: reg.r7, imm: 6)),
		test_case(0x781a, instr_16(op: opcode.ldrb_imm,      rt: reg.r2,  rn: reg.r3, imm: 0)),
		test_case(0x701a, instr_16(op: opcode.strb_imm,      rt: reg.r2,  rn: reg.r3, imm: 0)),
		test_case(0x68fb, instr_16(op: opcode.ldr_imm,       rt: reg.r3,  rn: reg.r7, imm: 12)),
		test_case(0x4283, instr_16(op: opcode.cmp_reg,       rn: reg.r3,  rm: reg.r0)),
		test_case(0x4803, instr_16(op: opcode.ldr_pool,      rt: reg.r0,              imm: 12)),
		//  80091a0:	4803      	ldr	r0, [pc, #12]	@ (80091b0 <stdio_exit_handler+0x14>)
		// 0100 1000 0000 0011
		test_case(0xd002, instr_16(op: opcode.b_cond,        cond: condition.eq,      offset: 4)),
		// 1101 0000 0000 0010
		test_case(0xb103, instr_16(op: opcode.cmp_br_z,      rn: reg.r3,              offset: 0)),
		// 1101 0001 0000 0011
		test_case(0x4718, instr_16(op: opcode.bx,            rm: reg.r3)),
		test_case(0x1a1b, instr_16(op: opcode.sub_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r0)),
		test_case(0xb510, instr_16(op: opcode.push_mult_reg, reg_list: [reg.r4, reg.lr])),
		test_case(0xb943, instr_16(op: opcode.cmp_br_nz,     rn: reg.r3,			  offset: 16)),
		test_case(0xbd10, instr_16(op: opcode.pop_mult_reg,  reg_list: [reg.r4, reg.pc])),
		test_case(0xe7cf, instr_16(op: opcode.b_imm_11,					 		      offset: -98)),
		// 1110 0111 1100 1111
		//test_case(0xbf00, instr_16(op: if_then))
		test_case(0x469d, instr_16(op: opcode.mov_high_1,    rd: reg.sp,  rm: reg.r3)),
		test_case(0x460f, instr_16(op: opcode.mov_lo,        rd: reg.r7,  rm: reg.r1)),
		test_case(0x4798, instr_16(op: opcode.blx,           rm: reg.r3)),
		test_case(0xaf00, instr_16(op: opcode.add_sp_t1,     rd: reg.r7, 			  imm: 0)),
		test_case(0x5cd3, instr_16(op: opcode.ldrb_reg,      rt: reg.r3,  rn: reg.r2, rm: reg.r3)),
		test_case(0xb092, instr_16(op: opcode.sub_sp,		 						  imm: 72)),
		test_case(0x1d3b, instr_16(op: opcode.add_imm_3,     rd: reg.r3,  rn: reg.r7, imm: 4)),
		test_case(0x4413, instr_16(op: opcode.add_lo_reg,    rd: reg.r3,  rn: reg.r3, rm: reg.r2)),
		test_case(0x409a, instr_16(op: opcode.lsl_reg,       rd: reg.r2,  rn: reg.r2, rm: reg.r3)),
		test_case(0x40da, instr_16(op: opcode.lsr_reg,	     rd: reg.r2,  rn: reg.r2, rm: reg.r3)),
		test_case(0xa201, instr_16(op: opcode.adr,			 rd: reg.r2,  			  imm: 4)),
		test_case(0x4652, instr_16(op: opcode.mov_high_2, 	 rd: reg.r2,  rm: reg.r10)),
		test_case(0x9300, instr_16(op: opcode.str_sp,		 rt: reg.r3,			  imm: 0)),
		test_case(0x1891, instr_16(op: opcode.add_reg, 		 rd: reg.r1,  rn: reg.r2, rm: reg.r2)),
		test_case(0x458c, instr_16(op: opcode.cmp_high_1,    rn: reg.r12, rm: reg.r1)),
		test_case(0x4463, instr_16(op: opcode.add_high_reg_1,rd: reg.r3,  rn: reg.r3, rm: reg.r12)),
		test_case(0x1e54, instr_16(op: opcode.sub_imm_3,     rd: reg.r4,  rn: reg.r2, imm: 1)),
		test_case(0x44e6, instr_16(op: opcode.add_high_reg_2,rd: reg.lr,  rn: reg.lr, rm: reg.r12)),
		test_case(0x4572, instr_16(op: opcode.cmp_high_2,	 rn: reg.r2,  rm: reg.lr)),
		test_case(0x4241, instr_16(op: opcode.negs,			 rd: reg.r1,  rn: reg.r0)),
		test_case(0x58fb, instr_16(op: opcode.ldr_reg,	     rt: reg.r3,  rn: reg.r7, rm: reg.r3)),
		test_case(0x50c4, instr_16(op: opcode.str_reg,	     rt: reg.r4,  rn: reg.r0, rm: reg.r3)),
		test_case(0xd3f9,  instr_16(op: opcode.b_cond,		 cond: condition.cc,	  offset: -14))
		//50c4      	str	r4, [r0, r3]
	];

	foreach (t; tests) {
		assert(
		    decode_instr(t.instr) == t.expected,
		    format("Failed for instruction 0x%04X", t.instr)
		);
    }
} 

// ================
//  Remove Comment
// ================

string remove_comment(string line) {
	size_t at_pos = line.indexOf('@');
	if (at_pos != -1) {
		line = line[0 .. at_pos];
	}
	return strip(line, " \t");
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "800a18c: f8df d034  ldr.w sp, [pc, #52]  @ 800a1c4 <LoopFillZerobss+0xe>";
    auto result = remove_comment(s);
    assert(result.length == 39, "remove_comment return value not the correct length");
    assert(result == "800a18c: f8df d034  ldr.w sp, [pc, #52]",
    	   "remove_comment did not trim correctly");
}

// ========
//  Is Hex
// ========

bool is_hex(dchar c) {
    return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}

// ==========
//  Get Addr
// ==========

string get_addr(string instr_str)
in {
    assert(instr_str.length >= 8, "instr_str too short");
    assert(instr_str[7] == ':', "Expected ':' at 8th position");
} 
body {
	return instr_str[0 .. 7];
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "800a18c: f8df d034  ldr.w sp, [pc, #52]";
    auto result = get_addr(s);
    assert(result == "800a18c");
}

// =============
//  Remove Addr
// =============

string remove_addr(string line) {
	size_t colon_pos = line.indexOf(':');
	if (colon_pos != -1) {
		line = line[(colon_pos + 1) .. $];
	} 
	return stripLeft(line, " \t");
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "800a18c: f8df d034  ldr.w sp, [pc, #52]";
    auto result = remove_addr(s);
    assert(result == "f8df d034  ldr.w sp, [pc, #52]");
}

// ===========
//  Get Bytes
// ===========

string get_bytes(string line)
out(result) {
    assert(result.length == 4 || result.length == 8,
           "Return value must be 4 or 8 characters");
}
body {
	string result;
	while (true) {
		auto bytes = line[0 .. 4];
		if (bytes.all!(c => is_hex(c))) {
			result ~= bytes;
			line = line[5 .. $];
		} else {
			break;
		}
		line = stripLeft(line, " \t");
	}
	return result;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "f8df d034  ldr.w sp, [pc, #52]";
    auto result = get_bytes(s);
    assert(result == "f8dfd034");
}

// ==============
//  Remove Bytes
// ==============

string remove_bytes(string line) {
	while (true) {
		auto bytes = line[0 .. 4];
		if (bytes.all!(c => is_hex(c))) {
			line = line[5 .. $];
		} else {
			break;
		}
		line = stripLeft(line, " \t");
	}
	return line;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "f8df d034  ldr.w sp, [pc, #52]";
    auto result = remove_bytes(s);
    assert(result == "ldr.w sp, [pc, #52]");
}

// ==============
//  Get Mnemonic
// ==============

string get_mnemonic(string line) 
out(result) {
    assert(line.length > 0,
           "Return value must not be empty");
}
body {
	string result = line;
	size_t space_pos = line.indexOf(' ');
	if (space_pos != -1) {
		result = line[0 .. space_pos];
	}
	return result;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "ldr.w sp, [pc, #52]";
    auto result = get_mnemonic(s);
    assert(result == "ldr.w");
}

// =================
//  Remove Mnemonic
// =================

string remove_mnemonic(string line) {
	string result = line;
	size_t space_pos = line.indexOf(' ');
	if (space_pos != -1) {
		result = result[(space_pos + 1) .. $];
	}
	return stripLeft(result, " \t");
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "ldr.w sp, [pc, #52]";
    auto result = remove_mnemonic(s);
    assert(result == "sp, [pc, #52]");
}

// ==============
//  Get Operands
// ==============

string get_operands(string line) {
	string result = line;
	return result;
}

// =================
//  RAM Mem Section
// =================

struct ram_mem_section {
	ubyte[128 * 1024] cells;

    const(ubyte) read_byte(size_t index) const {
    	index -= ram_origin;
        return cells[index];
    }

    const(ushort) read_half_word(size_t index) {
    	index -= ram_origin;
    	ushort res = (cells[index] << 8) | cells[index + 1];
    	return res;
    }

    const(uint) read_word(size_t index) {
    	index -= ram_origin;
    	uint res = (cells[index + 3] << 24) | 
    	           (cells[index + 2] << 16) | 
    	           (cells[index + 1] <<  8) | 
    	            cells[index    ];
    	return res;
    }

    void write_byte(size_t index, ubyte val) {
    	index -= ram_origin;
    	cells[index] = val;
    }

    void write_half_word(size_t index, ushort val) {
    	index -= ram_origin;
    	cells[index    ] = (val >> 8) & 0xff;
    	cells[index + 1] =  val       & 0xff;
    }

    void write_word(size_t index, uint val) {
    	index -= ram_origin;
    	cells[index + 3] = (val >> 24) & 0xff;
    	cells[index + 2] = (val >> 16) & 0xff;
    	cells[index + 1] = (val >>  8) & 0xff;
    	cells[index] =      val        & 0xff;
    }

    static enum ram_origin = 0x20000000;
}

__gshared ubyte[1024 * 1024] g_flash;

static this()
{
    //flash_mem_section.write_word(0x800a18c + 52,memory.stack_base);
}

// ===================
//  Flash Mem Section
// ===================

struct flash_mem_section {
    const(ubyte) read_byte(size_t index) const {
    	index -= flash_origin;
        return g_flash[index];
    }

    const(ushort) read_half_word(size_t index) const {
    	index -= flash_origin;
    	ushort res = (g_flash[index + 1] << 8) | g_flash[index];
    	return res;
    }

    const(uint) read_word(size_t index) const {
    	index -= flash_origin;
    	uint res = (g_flash[index + 3] << 24) | 
    	           (g_flash[index + 2] << 16) | 
    	           (g_flash[index + 1] <<  8) |  
    	            g_flash[index];
    	return res;
    }

    static void write_word(size_t index, uint val) {
       	index -= flash_origin;
    	g_flash[index + 3] = (val >> 24) & 0xff;
    	g_flash[index + 2] = (val >> 16) & 0xff;
    	g_flash[index + 1] = (val >>  8) & 0xff;
    	g_flash[index    ] =  val        & 0xff;
    }

    enum flash_origin = 0x8000000;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    flash_mem_section flash;
    flash.write_word(memory.flash_origin, 32);
    uint read_value = flash.read_word(memory.flash_origin);
    assert(read_value == 32, "Failed to read word from flash");
}

struct memory {
	ram_mem_section ram;
	flash_mem_section flash;
	enum flash_origin = 0x8000000;
	enum ram_origin = 0x20000000;
	enum flash_length = 1024 * 1024;
	enum ram_length = 128 * 1024;
	static uint stack_base = ram_origin + ram_length;
	uint[size_t] peripherals = [
		0x40023c00: 0,	
		0xe000ed0c: 0,
		0x40023844: 0, 	// RCC_APB2ENR
		0x40023840: 0, 	// RCC_APB1ENR
		0x40023830: 0,  // RCC_AHB1ENR
		0x4001100c: 0,  // CR1
		0x40011010: 0,  // CR2
		0x40011014: 0,  // CR3
		0x40011024: 0,  // GPTR
		0x40020000: 0,  // GPIOA_MODER
		0x40020004: 0,  // GPIOA_OTYPER
		0x40020008: 0,  // GPIOA_OSPEEDR
		0x4002000C: 0,  // GPIOA_PUPDR
		0x40020010: 0,  // GPIOA_IDR
		0x40020014: 0,  // GPIOA_ODR
		0x40020020: 0,  // GPIOA_AFRL
		0x40020024: 0,  // GPIOA_AFRH
		0x40020400: 0,  // GPIOB_MODER
		0x40020404: 0,  // GPIOB_OTYPER
		0x40020408: 0,  // GPIOB_OSPEEDR
		0x4002040C: 0,  // GPIOB_PUPDR
		0x40020410: 0,  // GPIOB_IDR
		0x40020414: 0,  // GPIOB_ODR
		0x40020420: 0,  // GPIOB_AFRL
		0x40020424: 0,  // GPIOB_AFRH
		0x40020800: 0,  // GPIOC_MODER
		0x40020804: 0,  // GPIOC_OTYPER
		0x40020808: 0,  // GPIOC_OSPEEDR
		0x4002080C: 0,  // GPIOC_PUPDR
		0x40020810: 0,  // GPIOC_IDR
		0x40020814: 0,  // GPIOC_ODR
		0x40020820: 0,  // GPIOC_AFRL
		0x40020824: 0,  // GPIOC_AFRH
		0x40020C00: 0,  // GPIOD_MODER
		0x40020C04: 0,  // GPIOD_OTYPER
		0x40020C08: 0,  // GPIOD_OSPEEDR
		0x40020C0C: 0,  // GPIOD_PUPDR
		0x40020C10: 0,  // GPIOD_IDR
		0x40020C14: 0,  // GPIOD_ODR
		0x40020C20: 0,  // GPIOD_AFRL
		0x40020C24: 0,  // GPIOD_AFRH
		0x40021000: 0,  // GPIOE_MODER
		0x40021004: 0,  // GPIOE_OTYPER
		0x40021008: 0,  // GPIOE_OSPEEDR
		0x4002100C: 0,  // GPIOE_PUPDR
		0x40021010: 0,  // GPIOE_IDR
		0x40021014: 0,  // GPIOE_ODR
		0x40021020: 0,  // GPIOE_AFRL
		0x40021024: 0,  // GPIOE_AFRH
		0x40021400: 0,  // GPIOF_MODER
		0x40021404: 0,  // GPIOF_OTYPER
		0x40021408: 0,  // GPIOF_OSPEEDR
		0x4002140C: 0,  // GPIOF_PUPDR
		0x40021410: 0,  // GPIOF_IDR
		0x40021414: 0,  // GPIOF_ODR
		0x40021420: 0,  // GPIOF_AFRL
		0x40021424: 0,  // GPIOF_AFRH
		0x40021800: 0,  // GPIOG_MODER
		0x40021804: 0,  // GPIOG_OTYPER
		0x40021808: 0,  // GPIOG_OSPEEDR
		0x4002180C: 0,  // GPIOG_PUPDR
		0x40021810: 0,  // GPIOG_IDR
		0x40021814: 0,  // GPIOG_ODR
		0x40021820: 0,  // GPIOG_AFRL
		0x40021824: 0,  // GPIOG_AFRH
		0x40021C00: 0,  // GPIOH_MODER
		0x40021C04: 0,  // GPIOH_OTYPER
		0x40021C08: 0,  // GPIOH_OSPEEDR
		0x40021C0C: 0,  // GPIOH_PUPDR
		0x40021C10: 0,  // GPIOH_IDR
		0x40021C14: 0,  // GPIOH_ODR
		0x40021C20: 0,  // GPIOH_AFRL
		0x40021C24: 0,  // GPIOH_AFRH
		0x40013C08: 0,  // SYSCFG_EXTICR1
		0x40013C0C: 0,  // SYSCFG_EXTICR2
		0x40013C10: 0,  // SYSCFG_EXTICR3
		0x40013C14: 0,  // SYSCFG_EXTICR4
		0x40023808: 0, 	// RCC_CFGR
		0xE000ED88: 0,  // SCB_CPACR
		// TIM6
		0x40001000: 0, 0x40001004: 0, 0x40001008: 0, 0x4000100C: 0,
	    0x40001010: 0, 0x40001014: 0, 0x40001018: 0, 0x4000101C: 0,
	    0x40001020: 0, 0x40001024: 0, 0x40001028: 0, 0x4000102C: 0,
	    0x40001030: 0, 0x40001034: 0, 0x40001038: 0, 0x4000103C: 0,
	    0x40001040: 0, 0x40001044: 0,
	    // NVIC
	    0xE000E3FC: 0,
	    0xE000ED00: 0,
	    0x40007000: 0x0000C000, // PWR_CR
	    0x40023800: 0x00000083, // CR
	    0xe000ed04: 0,
	    0xe000ed14: 0,
	    0xe000ed20: 0,
	    0xe000ed18: 0,
	    0xe000ed1c: 0,
	    0xe000ed24: 0,
	    0xE000ED90: 0
	];

	uint read_word(size_t addr) {
		if (addr > ram_origin + ram_length) {
        	return peripherals[addr];
		}
		if (addr >= ram_origin) {
			return ram.read_word(addr);
		} else {
			return flash.read_word(addr);
		}
	}

	const(ushort) read_half_word(size_t addr) {
		if (addr >= ram_origin) {
			return ram.read_half_word(addr);
		} else {
			return flash.read_half_word(addr);
		}
	}

	const(ubyte) read_byte(size_t addr) {
		if (addr > ram_origin + ram_length) {
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
		if (addr > ram_origin + ram_length) {
        	peripherals[addr] = val;
        	return;
		}
		if (addr >= ram_origin) {
			return ram.write_word(addr, val);
		} else {
			return flash.write_word(addr, val);
		}
	}

	void write_byte(size_t addr, uint val) {
		ubyte b = cast(ubyte)(val & 0xff);
		if (addr > ram_origin + ram_length) {
        	peripherals[addr] = val;
        	
		   	size_t word_addr = addr & ~3;
		   	uint shift = (addr & 3) * 8;

		   	uint old = peripherals[word_addr];
		   	uint masked = (old & ~(0xff << shift)) | (b << shift);
		   	peripherals[word_addr] = masked;
		   	return;
		} 
		if (addr >= ram_origin) {
			return ram.write_byte(addr, b);
		} else {
			//return flash.write_byte(addr, val);
		}
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
		ram.write_word(cpu.get_sp(), 0);
		inc_sp_word_width(cpu);
		return res;
	}
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    cortex_m_vm vm;
    vm.cpu.set_sp(memory.stack_base);
    vm.mem.push(vm.cpu, 32);
    int val = vm.mem.pop(vm.cpu);
    assert(val == 32);
    assert(vm.cpu.get_sp() == memory.stack_base);
}

enum xyz {
	none,
	t,
	e,
	tt,
	et,
	te,
	ee,
	ttt,
	ett,
	tet,
	eet,
	tte,
	ete,
	tee,
	eee
}

// 0xBF1C
// 1011 1111 0001 1100
xyz get_xyz(ubyte first_cond_mask) {
	ubyte first_cond = cast(ubyte)((first_cond_mask >> 4) & 0xf);
	ubyte mask = cast(ubyte)(first_cond_mask & 0xf);
	if (mask == 0b0001) {
		return xyz.none;
	}
	ubyte first_cond_0 = cast(ubyte)(first_cond & 0b1);
	auto bit0 = first_cond_0 ? 1 : 0;
	if (mask == ((bit0 << 3) | 0b100)) {
		return xyz.t;
	}
	if (mask == (((bit0 ^ 1) << 3) | 0b100)) {
		return xyz.e;
	}
	if (mask == ((bit0 << 3) | (bit0 << 2) | 0b10)) {
		return xyz.tt;
	}
	if (mask == (((bit0 ^ 1) << 3) | (bit0 << 2) | 0b10)) {
		return xyz.et;
	}
	if (mask == ((bit0 << 3) | !(bit0 << 2) | 0b10)) {
		return xyz.te;
	}
	if (mask == (((bit0 ^ 1) << 3) | ((bit0 ^ 1) << 2) | 0b10)) {
		return xyz.ee;
	}
	if (mask == ((bit0 << 3) | (bit0 << 2) | (bit0 << 1) | 0b1)) {
		return xyz.ttt;
	}
	if (mask == (((bit0 ^ 1) << 3) | (bit0 << 2) | (bit0 << 1) | 0b1)) {
		return xyz.ett;
	}
	if (mask == ((bit0 << 3) | ((bit0 ^ 1) << 2) | (bit0 << 1) | 0b1)) {
		return xyz.tet;
	}
	if (mask == (((bit0 ^ 1) << 3) | ((bit0 ^ 1) << 2) | (bit0 << 1) | 0b1)) {
		return xyz.eet;
	}
	if (mask == ((bit0 << 3) | (bit0 << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.tte;
	}
	if (mask == (((bit0 ^ 1) << 3) | (bit0 << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.ete;
	}
	if (mask == ((bit0 << 3) | ((bit0 ^ 1) << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.tee;
	}
	if (mask == (((bit0 ^ 1) << 3) | ((bit0 ^ 1) << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.eee;
	}
	return xyz.none;
}

condition get_negation(condition cond) {
	if (cond == condition.eq) {
		return condition.ne;
	}
	return condition.invalid;
}

enum exception {
	thread_mode
}

struct cortex_m_cpu {
	uint r0;
	uint r1;
	uint r2;
	uint r3;
	uint r4;
	uint r5;
	uint r6;
	uint r7;
	uint r8;
	uint r9;
	uint r10;
	uint r11;
	uint r12;
	uint sp;
	uint lr;
	uint pc;

	uint get_sp() {
	    return sp_sel ? psp : msp;
	}

	void set_sp(uint val) {
	    if (sp_sel)
	        psp = val;
	    else
	        msp = val;
	}

	bool sp_sel;
	uint xspr;
	ubyte basepri;
	uint msp;
	uint psp;
	exception current_exception;

	bool n;
	bool z;
	bool c;
	bool v;

	xyz it_block;
	Array!condition it_block_stack;

	bool in_it_block() {
		return !it_block_stack.empty;
	}

	void init_it_block_stack(condition cond) {
		if (it_block == xyz.none) {
			return;
		}
		string s = it_block.to!string;
		it_block_stack.insertBack(cond); 
		foreach (c; s) {
	        if (c == 't') {
	            it_block_stack.insertBack(cond);       
	        } else if (c == 'e') {
	            it_block_stack.insertBack(get_negation(cond)); 
	        }
	    }
	}

	uint get(reg r) {
		switch (r) {
			case reg.r0:
				return r0;
			case reg.r1:
				return r1;
			case reg.r2:
				return r2;
			case reg.r3:
				return r3;
			case reg.r4:
				return r4;
			case reg.r5: 
				return r5;
			case reg.r6:
				return r6;
			case reg.r7:
				return r7;
			case reg.r8: 
				return r8;
			case reg.r9:
				return r9;
			case reg.r10:
				return r10;
			case reg.r11:
				return r11;
			case reg.r12:
				return r12;
			case reg.pc:
				return pc;
			case reg.lr:
				return lr;
			case reg.sp:
				return get_sp();
			default:
				return r3;
		}
	}

	void set(reg r, int val) {
		switch (r) {
			case reg.r0:
				r0 = cast(uint)(val);
				return;
			case reg.r1:
				r1 = cast(uint)(val);
				return;
			case reg.r2:
				r2 = cast(uint)(val);
				return;
			case reg.r3:
				r3 = cast(uint)(val);
				return;
			case reg.r4:
				r4 = cast(uint)(val);
				return;
			case reg.r5: 
				r5 = cast(uint)(val);
				return;
			case reg.r6:
				r6 = cast(uint)(val);
				return;
			case reg.r7:
				r7 = cast(uint)(val);
				return;
			case reg.r8:
				r8 = cast(uint)(val);
				return;
			case reg.r9:
				r9 = cast(uint)(val);
				return;
			case reg.r10:
				r10 = cast(uint)(val);
				return;
			case reg.r11:
				r11 = cast(uint)(val);
				return;
			case reg.r12:
				r12 = cast(uint)(val);
				return;
			case reg.pc:
				pc = cast(uint)(val);
				return;
			case reg.lr:
				lr = cast(uint)(val);
				return;
			case reg.sp:
				set_sp(cast(uint)(val));
				return;
			default:
				return;
		}
	}

	void increment_pc(int val) {
		pc += val;
	}
}

// =================
//  Execute CMP IMM
// =================

void execute_cmp_imm(instr_16 cmp_imm_instr, ref cortex_m_cpu cpu) {
	int rn_val = cast(int)(cpu.get(cmp_imm_instr.rn));
	int res = rn_val - cmp_imm_instr.imm;
	cpu.z = (res == 0);
	cpu.n = (res < 0);
	cpu.c = (rn_val >= cmp_imm_instr.imm);
	cpu.v = (rn_val < 0 && res > 0);
	cpu.increment_pc(2);
}

// =============
//  Execute ASR
// =============

void execute_asr_imm(instr_16 asr_imm_instr, ref cortex_m_cpu cpu) {
	int rm_value = cast(int)(cpu.get(asr_imm_instr.rm));
	rm_value = rm_value >> (asr_imm_instr.imm - 1);
	bool carry = (1 & rm_value);
	rm_value = rm_value >> 1;
	if (asr_imm_instr.set_flags) {
		cpu.z = (rm_value == 0);
		cpu.n = (rm_value < 0);
		cpu.c = carry;
	}
	cpu.set(asr_imm_instr.rd, rm_value);
	cpu.increment_pc(2);
}

// =============
//  Execute ADD
// =============

void execute_add_imm_8(instr_16 add_imm_8_instr, ref cortex_m_cpu cpu) {
	int rn = cast(int)(cpu.get(add_imm_8_instr.rn));
	int res = rn + add_imm_8_instr.imm;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = (res >= add_imm_8_instr.imm);
		cpu.v = (rn < 0 && res > 0);
	}
	cpu.set(add_imm_8_instr.rd, res);
	cpu.increment_pc(2);
}

// =============
//  Execute AND
// =============

void execute_and_reg(instr_16 and_reg_instr, ref cortex_m_cpu cpu) {
	int rn = cast(int)(cpu.get(and_reg_instr.rn));
	int rm = cast(int)(cpu.get(and_reg_instr.rm));
	int res = rn & rm;
	if (and_reg_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
	}
	cpu.set(and_reg_instr.rd, res);
	cpu.increment_pc(2);
}

// =============
//  Execute MOV
// =============

void execute_mov_imm(instr_16  mov_imm_instr, ref cortex_m_cpu cpu) {
	cpu.set(mov_imm_instr.rd, mov_imm_instr.imm);
	cpu.increment_pc(2);
}

// ==================
//  Execute SUB IMM8
// ==================

void execute_sub_imm_8(instr_16 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn - instr.imm;
	if (/*sub_imm_8_instr.set_flags*/ true) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = cast(uint)rn >= cast(uint)instr.imm;
		cpu.v = (rn < 0 && res > 0);
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}

// =============
//  Execute LSL 
// =============

void execute_lsl_imm(instr_16 lsl_imm_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(lsl_imm_instr.rm);
	int res = rm << (lsl_imm_instr.imm - 1);
	bool carry = ((res & 0x80000000) != 0);
	res = res << 1;
	if (lsl_imm_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = carry;
	}
	cpu.set(lsl_imm_instr.rd, res);
	cpu.increment_pc(2);
}

// =============
//  Execute LSR 
// =============

void execute_lsr_imm(instr_16 lsr_imm_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(lsr_imm_instr.rm);
	int res = rm >>> (lsr_imm_instr.imm - 1);
	bool carry = (res & 1);
	res = res >>> 1;
	if (lsr_imm_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = carry;
	}
	cpu.set(lsr_imm_instr.rd, res);
	cpu.increment_pc(2);
}

// =============
//  Execute LOR
// =============

void execute_lor_reg(instr_16 lor_reg_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(lor_reg_instr.rn);
	int rm = cpu.get(lor_reg_instr.rm);
	int res = rn | rm;
	if (lor_reg_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
	}
	cpu.set(lor_reg_instr.rd, res);
	cpu.increment_pc(2);
}

// =============
//  Execute MVN
// =============

void execute_mvn_reg(instr_16 mvn_reg_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(mvn_reg_instr.rm);
	int res = ~rm;
	if (mvn_reg_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
	}
	cpu.set(mvn_reg_instr.rd, res);
	cpu.increment_pc(2);
}

// ========================
//  Execute STR(Immeidate)
// ========================

void execute_str_imm(instr_16 str_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint rt = cpu.get(str_imm_instr.rt);
	uint rn = cpu.get(str_imm_instr.rn);
	size_t addr = rn + str_imm_instr.imm;
	f.writeln(format("Attempting to access [%08X]", addr));
	mem.write_word(addr, rt);
	f.writeln(format("%08X: %08X stored to [%08X]", cpu.pc, rt, addr));
	f.flush();
	cpu.increment_pc(2);
}

void execute_str_sp(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(instr.rt);
	size_t addr = cpu.get_sp() + instr.imm;
	mem.write_word(addr, rt);
	cpu.increment_pc(2);
}

// =============
//  Execute LDR
// =============

void execute_ldr_imm(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	int rn = cpu.get(instr.rn);
	size_t addr = rn + instr.imm;
	f.writeln(format("Attempting to access [%08X]", addr));
	int data = mem.read_word(addr);
	cpu.set(instr.rt, data);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}

void execute_ldr_sp(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint sp = cpu.get_sp();
	size_t addr = sp + instr.imm;
	f.writeln(format("Attempting to access [%08X]", addr));
	int data = mem.read_word(addr);
	cpu.set(instr.rt, data);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}

// ==============
//  Execute STRH
// ==============

void execute_strh_imm(instr_16 strh_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(strh_imm_instr.rt);
	int rn = cpu.get(strh_imm_instr.rn);
	size_t addr = rn + strh_imm_instr.imm;
	int target = mem.read_word(addr);
	target = (target & 0xffff0000) | rt;  
	mem.write_word(addr, target);
	cpu.increment_pc(2);
}

// ==============
//  Execute LDRH
// ==============

void execute_ldrh_imm(instr_16 ldrh_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	int rt = cpu.get(ldrh_imm_instr.rt);
	int rn = cpu.get(ldrh_imm_instr.rn);
	size_t addr = rn + ldrh_imm_instr.imm;
	f.writeln(format("Attempting to access [%08X]", addr));
	short data = mem.read_half_word(addr);
	cpu.set(ldrh_imm_instr.rt, cast(uint)data);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}

// ==============
//  Execute LDRB
// ==============

void execute_ldrb_imm(instr_16 ldrb_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	int rt = cpu.get(ldrb_imm_instr.rt);
	int rn = cpu.get(ldrb_imm_instr.rn);
	size_t addr = rn + ldrb_imm_instr.imm;
	f.writeln(format("Attempting to access [%08X]", addr));
	int data = mem.read_word(addr);
	cpu.set(ldrb_imm_instr.rt, cast(uint)data);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}

// ==============
//  Execute STRB
// ==============

void execute_strb_imm(instr_16 strb_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(strb_imm_instr.rt);
	int rn = cpu.get(strb_imm_instr.rn);
	size_t addr = rn + strb_imm_instr.imm;
	int data = rt & 0xff;
	mem.write_byte(addr, data);
	cpu.increment_pc(2);
}

void execute_strb_reg(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(instr.rt);
	int rn = cpu.get(instr.rn);
	int rm = cpu.get(instr.rm);
	size_t addr = rn + rm;
	int data = rt & 0xff;
	mem.write_byte(addr, data);
	cpu.increment_pc(2);
}

// =================
//  Execute CMP REG
// =================

void execute_cmp_reg(instr_16 cmp_reg_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(cmp_reg_instr.rm);
	int rn = cpu.get(cmp_reg_instr.rn);
	int res = rn - rm;
	cpu.z = (res == 0);
	cpu.n = (res < 0);
	cpu.c = (rn >= rm);
	cpu.v = (rn < 0 && res > 0);
	cpu.increment_pc(2);
}

// ==================
//  Execute LDR POOL
// ==================

void execute_ldr_pool(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	int base = cpu.get(reg.pc) + 4;
	base &= ~0x3;   
	int addr = base + instr.imm;
	f.writeln(format("Attempting to access [%08X]", addr));
	uint data = mem.read_word(addr);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.set(instr.rt, data);
	cpu.increment_pc(2);
}

// ============
//  Execute BX
// ============

void execute_bx(instr_16 bx_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(bx_instr.rm);
	int val = (rm & ~1);
	cpu.set(reg.pc, val);
}

// ==============
//  Execute UXTB
// ==============

void execute_uxtb(instr_16 instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(instr.rm);
	int val = (rm >> 8) & 0xff;
	cpu.set(instr.rd, val);
	cpu.increment_pc(2);
}

bool condition_is_met(condition cond, ref cortex_m_cpu cpu) {
	switch (cond) {
		case condition.eq:
			return (cpu.z == 1);
		case condition.ne:
			return (cpu.z == 0);
		case condition.cc:
			return (cpu.c == 0);
		case condition.cs: 
			return cpu.c == 1;
		case condition.ge:
			return (cpu.n == cpu.v);
		case condition.mi: 
			return cpu.n == 1;
		case condition.pl: 
			return cpu.n == 0;
		case condition.hi:
			return (cpu.c == 1 && cpu.z == 0);
		case condition.ls:
			return ((cpu.c == 0) || (cpu.z == 1));
		case condition.vs: 
			return cpu.v == 1;
        case condition.vc: 
        	return cpu.v == 0;
		default:
			return false;
	}
}

// ============
//  Execute BR
// ============

void execute_b_cond(instr_16 b_cond_instr, ref cortex_m_cpu cpu) {
	if (condition_is_met(b_cond_instr.cond, cpu)) {
		int pc = cpu.get(reg.pc);
		pc += b_cond_instr.offset + 4;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(2);
	}
}

// ==================
//  Execute CMP BR Z
// ==================

void execute_cmp_br_z(instr_16 cmp_br_z_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(cmp_br_z_instr.rn);
	if (rn == 0) {
		int pc = cpu.get(reg.pc);
		pc += cmp_br_z_instr.offset;
		pc += 4;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(2);
	}
}

// =================
//  Execute SUB REG
// =================

void execute_sub_reg(instr_16 sub_reg_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(sub_reg_instr.rm);
	int rn = cpu.get(sub_reg_instr.rn);
	int res = rn - rm;
	cpu.set(sub_reg_instr.rd, res);
	cpu.increment_pc(2);
}

// =======================
//  Execute PUSH MULT REG
// =======================

void execute_push_mult_reg(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	import std.algorithm : sort;
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	f.writeln(format("Pushing to stack at [%08X]", cpu.pc));
	foreach (r; regs) {
		f.writeln(format("%s: [%08X]", r.to!string, cpu.get(r)));
		f.flush();
		mem.push(cpu, cpu.get(r));
	}
	cpu.increment_pc(2);
} 

// ======================
//  Execute POP MULT REG
// ======================

void execute_pop_mult_reg(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	import std.algorithm : sort;
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	foreach (r; regs) {
		int val = mem.pop(cpu);
		cpu.set(r, val);
	}
	if (regs.back == reg.pc) {
		uint pc = cpu.get(reg.pc);
		pc &= ~0b1;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(2);
	}
} 

// ===================
//  Execute CMP BR NZ
// ===================

void execute_cmp_br_nz(instr_16 cmp_br_nz_instr, ref cortex_m_cpu cpu) {
	if (cpu.get(cmp_br_nz_instr.rn) != 0) {
		int pc = cpu.get(reg.pc);
		pc += cmp_br_nz_instr.offset;
		pc += 4;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(2);
	}
}

// ==================
//  Execute MOV HIGH
// ==================

void execute_mov_high_1(instr_16 mov_high_1_instr, ref cortex_m_cpu cpu) {
	cpu.set(mov_high_1_instr.rd, cpu.get(mov_high_1_instr.rm));
	cpu.increment_pc(2);
}

// =============
//  Execute BLX
// =============

void execute_blx(instr_16 blx_instr, ref cortex_m_cpu cpu) {
	int target = (cpu.get(blx_instr.rm) & ~1);
	cpu.set(reg.lr, cpu.get(reg.pc) + 2);
	cpu.set(reg.pc, target);
}

// ================
//  Execute ADD SP
// ================

void execute_add_sp(instr_16 instr, ref cortex_m_cpu cpu) {
	uint sp = cpu.get_sp();
	uint res = sp + instr.imm;
	cpu.set_sp(res);
	if (instr.op == opcode.add_sp_t1) {
		cpu.set(instr.rd, res);
	} 
	cpu.increment_pc(2);
}

// ==================
//  Execute LDRB REG
// ==================

void execute_ldrb_reg(instr_16 ldrb_reg_instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	size_t addr = cpu.get(ldrb_reg_instr.rn) + cpu.get(ldrb_reg_instr.rm);
	f.writeln(format("Attempting to access [%08X]", addr));
	ubyte data = mem.read_byte(addr);
	cpu.set(ldrb_reg_instr.rt, cast(uint)data);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}

// ================
//  Execute SUB SP
// ================

void execute_sub_sp(instr_16 sub_sp_instr, ref cortex_m_cpu cpu) {
	uint sp = cpu.get_sp();
	sp -= sub_sp_instr.imm;
	cpu.set_sp(sp);
	cpu.increment_pc(2);
}

// ==================
//  Execute ADD IMM3
// ==================

void execute_add_imm_3(instr_16 add_imm_3_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(add_imm_3_instr.rn);
	int res = rn + add_imm_3_instr.imm;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = (res >= add_imm_3_instr.imm);
		cpu.v = (rn < 0 && res > 0);
	}
	cpu.set(add_imm_3_instr.rd, res);
	cpu.increment_pc(2);
}

// ====================
//  Execute ADD LO REG
// ====================

void execute_add_lo_reg(instr_16 add_lo_reg_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(add_lo_reg_instr.rn);
	int rm = cpu.get(add_lo_reg_instr.rm);
	int res = rn + rm;
	cpu.set(add_lo_reg_instr.rd, res);
	cpu.increment_pc(2);
}

// =================
//  Execute LSL REG
// =================

void execute_lsl_reg(instr_16 lsl_reg_instr, ref cortex_m_cpu cpu) {
	int shift = cpu.get(lsl_reg_instr.rm);
	int val = cpu.get(lsl_reg_instr.rn);
	val = val << shift;
	cpu.set(lsl_reg_instr.rd, val);
	cpu.increment_pc(2);
}

// =================
//  Execute LSR REG
// =================

void execute_lsr_reg(instr_16 lsr_reg_instr, ref cortex_m_cpu cpu) {
	int shift = cpu.get(lsr_reg_instr.rm);
	int val = cpu.get(lsr_reg_instr.rn);
	val = val >> shift;
	cpu.set(lsr_reg_instr.rd, val);
	cpu.increment_pc(2);
}

// =============
//  Execute ADR
// =============

void execute_adr(instr_16 adr_instr, ref cortex_m_cpu cpu) {
	int pc = cpu.get(reg.pc);
	pc += adr_instr.imm;
	cpu.set(adr_instr.rd, pc);
}

// =============
//  Execute MOV
// =============

void execute_mov_high_2(instr_16 mov_high_2_instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(mov_high_2_instr.rm);
	cpu.set(mov_high_2_instr.rd, rm);
	cpu.increment_pc(2);
}

// =================
//  Execute ADD REG
// =================

void execute_add_reg(instr_16 add_reg_instr, ref cortex_m_cpu cpu) {
	cpu.set(add_reg_instr.rd, cpu.get(add_reg_instr.rn) + cpu.get(add_reg_instr.rm));
	cpu.increment_pc(2);
}

// =============
//  Execute ADC
// =============

void execute_adc_reg(instr_16 instr, ref cortex_m_cpu cpu) {
	cpu.set(instr.rd, cpu.get(instr.rn) + cpu.get(instr.rm) + cast(uint)(cpu.c));
	cpu.increment_pc(2);
}

// =================
//  Execute LDR REG
// =================

void execute_ldr_reg(instr_16 ldr_reg_instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	int rn = cpu.get(ldr_reg_instr.rn);
	int rm = cpu.get(ldr_reg_instr.rm);
	size_t addr = rn + rm;
	f.writeln(format("Attempting to access [%08X]", addr));
	int data = mem.read_word(addr);
	cpu.set(ldr_reg_instr.rt, data);
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}	

// ========================
//  Execute SUB(Immediate)
// ========================

void execute_sub_imm_3(instr_16 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn - instr.imm;
	cpu.set(instr.rd, res);
	cpu.z = (res == 0);
	cpu.n = (res < 0);
	cpu.c = cast(uint)rn >= cast(uint)instr.imm;
	cpu.v = (rn < 0 && res > 0);
	cpu.increment_pc(2);
}

// =============
//  Execute TST
// =============

void execute_tst(instr_16 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int rm = cpu.get(instr.rm);
	int res = rm & rm;
	cpu.z = (res == 0);
	cpu.n = (res < 0);
	cpu.increment_pc(2);
}

// ==============
//  Execute NEGS
// ==============

void execute_negs(instr_16 negs_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(negs_instr.rn);
	rn = -rn;
	cpu.set(negs_instr.rd, rn);
}

// =============
//  Execute NOP
// =============

void execute_nop(instr_16 negs_instr, ref cortex_m_cpu cpu) {
	int pc = cpu.get(reg.pc);
	cpu.set(reg.pc, pc + 2);
}

// ===========
//  Execute B
// ===========

void execute_b_imm_11(instr_16 instr, ref cortex_m_cpu cpu) {
	int pc = cpu.get(reg.pc);
	pc += instr.offset + 4;
	cpu.set(reg.pc, pc);
}

// =======================
//  Execute STR(Register)
// =======================

void execute_str_reg(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	size_t addr = cpu.get(instr.rn) + cpu.get(instr.rm);
	int data = cpu.get(instr.rt);
	f.writeln(format("Attempting to access [%08X]", addr));
	mem.write_word(addr, data);
	f.writeln(format("%08X: %08X stored to [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(2);
}

// =================
//  Execute IF THEN
// =================

void execute_if_then(instr_16 instr, ref cortex_m_cpu cpu) {
	ubyte mask = instr.mask;
	ubyte first_cond = instr.first_cond;
	condition cond = cast(condition)(first_cond);
	ubyte first_cond_mask = cast(ubyte)((first_cond << 4) | mask);
	xyz it_block = get_xyz(first_cond_mask);
	cpu.it_block = it_block;
	cpu.init_it_block_stack(cond);
	cpu.increment_pc(2);
}

// ===============
//  Execute Instr
// ===============

void execute_instr(instr_16 instr, ref cortex_m_cpu cpu) {
	if (!cpu.it_block_stack.empty) {
		condition active_cond = cpu.it_block_stack.back;
		cpu.it_block_stack.removeBack();
		if (!condition_is_met(active_cond, cpu)) {
			cpu.increment_pc(2);
			return;
		}
	}

	switch (instr.op) {
		case opcode.cmp_imm:
			return execute_cmp_imm(instr, cpu);
		case opcode.asr_imm:
			return execute_asr_imm(instr, cpu);
		case opcode.add_imm_8:
			return execute_add_imm_8(instr, cpu);
		case opcode.and_reg:
			return execute_and_reg(instr, cpu);
		case opcode.mov_imm:
			return execute_mov_imm(instr, cpu);
		case opcode.sub_imm_8:
			return execute_sub_imm_8(instr, cpu);
		case opcode.lsl_imm:
			return execute_lsl_imm(instr, cpu);
		case opcode.lsr_imm:
			return execute_lsr_imm(instr, cpu);
		case opcode.lor_reg:
			return execute_lor_reg(instr, cpu);
		case opcode.mvn_reg:
			return execute_mvn_reg(instr, cpu);
		case opcode.cmp_reg:
		case opcode.cmp_high_1:
		case opcode.cmp_high_2:
			return execute_cmp_reg(instr, cpu);
		case opcode.b_cond:
			return execute_b_cond(instr, cpu);
		case opcode.b_imm_11:
			return execute_b_imm_11(instr, cpu);
		case opcode.cmp_br_z:
			return execute_cmp_br_z(instr, cpu);
		case opcode.bx:
			return execute_bx(instr, cpu);
		case opcode.sub_reg:
			return execute_sub_reg(instr, cpu);
		case opcode.cmp_br_nz:
			return execute_cmp_br_nz(instr, cpu);
		case opcode.mov_lo:
		case opcode.mov_high_1:
			return execute_mov_high_1(instr, cpu);
		case opcode.blx:
			return execute_blx(instr, cpu);
		case opcode.add_sp_t1:
		case opcode.add_sp_t2:
			return execute_add_sp(instr, cpu);
		case opcode.sub_sp:
			return execute_sub_sp(instr, cpu);
		case opcode.add_imm_3:
			return execute_add_imm_3(instr, cpu);
		case opcode.add_lo_reg:
			return execute_add_lo_reg(instr, cpu);
		case opcode.lsl_reg:
			return execute_lsl_reg(instr, cpu);
		case opcode.lsr_reg:
			return execute_lsr_reg(instr, cpu);
		case opcode.adr:
			return execute_adr(instr, cpu);
		case opcode.mov_high_2:
			return execute_mov_high_2(instr, cpu);
		case opcode.add_reg:
		case opcode.add_high_reg_1:
		case opcode.add_high_reg_2:
			return execute_add_reg(instr, cpu);
		case opcode.sub_imm_3:
			return execute_sub_imm_3(instr, cpu);
		case opcode.negs:
			return execute_negs(instr, cpu);
		case opcode.nop:
			return execute_nop(instr, cpu);
		case opcode.uxtb:
			return execute_uxtb(instr, cpu);
		case opcode.adc_reg:
			return execute_adc_reg(instr, cpu);
		case opcode.if_then:
			return execute_if_then(instr, cpu);
		case opcode.tst:
			return execute_tst(instr, cpu);
		default:
			return;
	}
}

void execute_load_store(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	switch (instr.op) {
		case opcode.ldr_sp:
			return execute_ldr_sp(instr, cpu, mem);
		case opcode.str_imm:
			return execute_str_imm(instr, cpu, mem);
		case opcode.str_sp:
			return execute_str_sp(instr, cpu, mem);
		case opcode.strh_imm:
			return execute_strh_imm(instr, cpu, mem);
		case opcode.ldrh_imm:
			return execute_ldrh_imm(instr, cpu, mem);
		case opcode.ldrb_imm:
			return execute_ldrb_imm(instr, cpu, mem);
		case opcode.strb_imm:
			return execute_strb_imm(instr, cpu, mem);
		case opcode.strb_reg:
			return execute_strb_reg(instr, cpu, mem);
		case opcode.ldr_imm:
			return execute_ldr_imm(instr, cpu, mem);
		case opcode.ldr_pool:
			return execute_ldr_pool(instr, cpu, mem);
		case opcode.push_mult_reg:
			return execute_push_mult_reg(instr, cpu, mem);
		case opcode.pop_mult_reg:
			return execute_pop_mult_reg(instr, cpu, mem);
		case opcode.ldrb_reg:
			return execute_ldrb_reg(instr, cpu, mem);
		case opcode.ldr_reg:
			return execute_ldr_reg(instr, cpu, mem);
		case opcode.str_reg:
			return execute_str_reg(instr, cpu, mem);
		default:
			return;
	}
}

// =================
//  Get Instr Bytes
// ================= 

string[] get_instr_bytes(string file_name) {
	string[] result;
	File file;
	try {
		file = File(file_name, "r");
	} catch (Exception e) {
		writeln("Error opening file: ", e.msg);
		return [];
	}

	auto re = regex(r"(?<=\s)([0-9a-fA-F]{4}(?:\s[0-9a-fA-F]{4})*)(?=\s)");

	foreach(line; file.byLine()) {
		auto matches = matchAll(line, re);
		foreach (m; matches) {
            result ~= m.hit.idup.replace(" ", "");
        }
	}

	file.close();
	return result;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string file_name = "../test/cortex_m_asm.txt";
    auto instr_bytes = get_instr_bytes(file_name);
    foreach(instr; instr_bytes) {
    	if (instr.length == 4) {
    		auto copy = instr;
    		ushort value = parse!ushort(copy, 16);
    		auto res = decode_mnemonic(value);
    		assert(res != opcode.invalid, "Error decoding instruction opcode: " ~ instr);
    	}
    	if (instr.length == 8) {
    		auto copy = instr;
    		uint value = parse!uint(copy, 16);
    		auto res = decode_mnemonic_32(value);
    		assert(res != opcode.invalid, "Error decoding instruction opcode: " ~ instr);
    	}
    }
}

ram_mem_section make_ram_with(size_t index, uint value)
{
    ram_mem_section r;
    r.write_word(memory.ram_origin + index, value);
    return r;
}

ram_mem_section make_ram_with(size_t[] indices, uint[] values)
{
	ram_mem_section r;
	uint count = 0;
	foreach (i; indices) {
    	r.write_word(i, values[count]);
    	count++;
    }
    return r;
}

flash_mem_section make_flash_with(size_t index, uint value)
{
    flash_mem_section f;
    f.write_word(memory.flash_origin + index, value);
    return f;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr_bytes;
		instr_16 instr;
		cortex_m_cpu before;
		cortex_m_cpu expected;
	}

	struct test_case_mem {
		ushort instr_bytes;
		instr_16 instr;
		cortex_m_cpu before;
		cortex_m_cpu expected;
		memory mem_before;
		memory mem_after;
	}

	test_case[] tests = [
		test_case(0x2b00,
				  instr_16(op: opcode.cmp_imm,       rn: reg.r3,              imm: 0),
			      cortex_m_cpu(r3: 0),
			      cortex_m_cpu(pc: 2, z: true, n: false, c: true, v: false)),
		test_case(0x10b6,
				  instr_16(op: opcode.asr_imm,       rd: reg.r6,  rm: reg.r6, imm: 2),
			      cortex_m_cpu(r6: 0b10),
			      cortex_m_cpu(pc: 2, r6: 0)),
		test_case(0x1076,
				  instr_16(op: opcode.asr_imm,       rd: reg.r6,  rm: reg.r6, imm: 1),
			      cortex_m_cpu(r6: 0b10),
			      cortex_m_cpu(pc: 2, r6: 0b1)),
		test_case(0x3730, 
			      instr_16(op: opcode.add_imm_8,     rd: reg.r7,  rn: reg.r7, imm: 48),
			      cortex_m_cpu(r7: 0),
			      cortex_m_cpu(pc: 2, r7: 48, c: true)),
		test_case(0x4013, 
			      instr_16(op: opcode.and_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r2),
			      cortex_m_cpu(r3: 0b11100, r2: 0b00111),
			      cortex_m_cpu(pc: 2, r3: 0b00100, r2: 0b00111)),
		test_case(0x2300, 
			      instr_16(op: opcode.mov_imm,       rd: reg.r3,              imm: 0),
			      cortex_m_cpu(r3: 0b111),
			      cortex_m_cpu(pc: 2, r3: 0b000)),
		test_case(0x3902, 
			      instr_16(op: opcode.sub_imm_8,     rd: reg.r1,  rn: reg.r1, imm: 2),
			      cortex_m_cpu(r1: 0b0100),
			      cortex_m_cpu(pc: 2, r1: 0b0010, c: true)),
		test_case(0x00d9, 
				  instr_16(op: opcode.lsl_imm,       rd : reg.r1, rm: reg.r3, imm: 3),
				  cortex_m_cpu(r3: 0b00010000000000000000000111000000),
				  cortex_m_cpu(pc: 2, r3: 0b00010000000000000000000111000000,
				  			   r1: 0b10000000000000000000111000000000)),
		test_case(0x099b, 
				  instr_16(op: opcode.lsr_imm,       rd: reg.r3,  rm: reg.r3, imm: 6),
				  cortex_m_cpu(r3: 0b00000000000000000111000000000001),
				  cortex_m_cpu(pc: 2, r3: 0b00000000000000000000000111000000)),
		test_case(0x4313, 
			      instr_16(op: opcode.lor_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r2),
			      cortex_m_cpu(r3: 0b1100, r2: 0b0011),
			      cortex_m_cpu(pc: 2, r3: 0b1111, r2: 0b0011)),
		test_case(0x43db, 
			      instr_16(op: opcode.mvn_reg,       rd: reg.r3,  rm: reg.r3),
			      cortex_m_cpu(r3: 0b00000000000000000111000000000001),
			      cortex_m_cpu(pc: 2, r3: 0b11111111111111111000111111111110)),
		test_case(0x4283, 
				  instr_16(op: opcode.cmp_reg,       rn: reg.r3,  rm: reg.r0),
				  cortex_m_cpu(r3: 0, r0: 0),
			      cortex_m_cpu(pc: 2, z: true, n: false, c: true, v: false)),
		test_case(0xd002, 
				  instr_16(op: opcode.b_cond,        cond: condition.eq,      offset: 4),
				  cortex_m_cpu(pc: 10, z: true),
				  cortex_m_cpu(pc: 18, z: true)),
		test_case(0xb103, 
			      instr_16(op: opcode.cmp_br_z,      rn: reg.r3,              offset: 0),
			      cortex_m_cpu(r3: 0, pc: 10),
				  cortex_m_cpu(r3: 0, pc: 14)),
		test_case(0x4718, 
			      instr_16(op: opcode.bx,            rm: reg.r3),
			      cortex_m_cpu(r3: 0, pc: 10),
				  cortex_m_cpu(r3: 0, pc:  0)),
		test_case(0x1a1b, 
				  instr_16(op: opcode.sub_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r0),
				  cortex_m_cpu(r3: 10, r0: 3),
				  cortex_m_cpu(pc: 2, r3: 7,  r0: 3)),
		test_case(0xb943, 
			      instr_16(op: opcode.cmp_br_nz,     rn: reg.r3,			  offset: 8),
			      cortex_m_cpu(pc: 10, r3: 1),
				  cortex_m_cpu(pc: 22, r3: 1)),
		/*
		test_case(0xe7cf, 
			      instr_16(op: opcode.b_n,					 				  imm_long: 0xffffffcf),
			      cortex_m_cpu(pc: 10, r3: 1),
				  cortex_m_cpu(pc: 18, r3: 1))
		*/
		////test_case(0xbf00, instr_16(op: if_then))
		test_case(0x469d, 
			      instr_16(op: opcode.mov_high_1,    rd: reg.sp,  rm: reg.r3),
			      cortex_m_cpu(msp: 10, r3: 1),
				  cortex_m_cpu(pc: 2, msp: 1,  r3: 1)),
		test_case(0x460f, 
				  instr_16(op: opcode.mov_lo,        rd: reg.r7,  rm: reg.r1),
				  cortex_m_cpu(r7: 10, r1: 1),
				  cortex_m_cpu(pc: 2, r7: 1,  r1: 1)),
		test_case(0x4798, 
				  instr_16(op: opcode.blx,           rm: reg.r3),
				  cortex_m_cpu(pc: 10, r3: 20),
				  cortex_m_cpu(pc: 20, lr: 12, r3: 20)),
		test_case(0xaf00, 
			      instr_16(op: opcode.add_sp_t1,        rd: reg.r7, 			  imm: 0),
			      cortex_m_cpu(msp: 10, r7: 20),
				  cortex_m_cpu(pc: 2, msp: 10, r7: 10)),
		test_case(0xb092, 
			      instr_16(op: opcode.sub_sp,		 						  imm: 72),
			      cortex_m_cpu(msp: 90),
				  cortex_m_cpu(pc: 2, msp: 18)),
		test_case(0x1d3b, 
			      instr_16(op: opcode.add_imm_3,     rd: reg.r3,  rn: reg.r7, imm: 4),
			      cortex_m_cpu(r3: 3, r7: 4),
				  cortex_m_cpu(pc: 2, r3: 8, r7: 4, c: true)),
		test_case(0x4413, 
				  instr_16(op: opcode.add_lo_reg,    rd: reg.r3,  rn: reg.r3, rm: reg.r2),
				  cortex_m_cpu(r3: 3, r2: 2),
				  cortex_m_cpu(pc: 2, r3: 5, r2: 2)),
		test_case(0x409a, 
			      instr_16(op: opcode.lsl_reg,       rd: reg.r2,  rn: reg.r2, rm: reg.r3),
			      cortex_m_cpu(r2: 0b0101, r3: 1),
			      cortex_m_cpu(pc: 2, r2: 0b1010, r3: 1)),
		test_case(0x40da, 
			      instr_16(op: opcode.lsr_reg,	     rd: reg.r2,  rn: reg.r2, rm: reg.r3),
			      cortex_m_cpu(r2: 0b1010, r3: 1),
			      cortex_m_cpu(pc: 2, r2: 0b0101, r3: 1)),
		test_case(0xa201, 
			      instr_16(op: opcode.adr,	         rd: reg.r2,  			  imm: 4),
			      cortex_m_cpu(r2: 10, pc: 10),
			      cortex_m_cpu(r2: 14, pc: 10)),
		test_case(0x4652, 
			      instr_16(op: opcode.mov_high_2, 	 rd: reg.r2,  rm: reg.r10),
			      cortex_m_cpu(r2: 1, r10: 3),
			      cortex_m_cpu(pc: 2, r2: 3, r10: 3)),
		/*
		test_case(0x9300, 
			      instr_16(op: opcode.str_sp,		 rt: reg.r3,			  imm: 0),
			      cortex_m_cpu(r2: 1, r10: 3),
			      cortex_m_cpu(r2: 3, r10: 3))
		*/
		test_case(0x1891, 
			      instr_16(op: opcode.add_reg, 		 rd: reg.r1,  rn: reg.r2, rm: reg.r2),
			      cortex_m_cpu(r1: 10, r2: 10),
			      cortex_m_cpu(pc: 2,r1: 20, r2: 10)),
		test_case(0x458c, 
			      instr_16(op: opcode.cmp_high_1,    rn: reg.r12, rm: reg.r1),
			      cortex_m_cpu(r3: 0, r0: 0),
			      cortex_m_cpu(pc: 2, z: true, n: false, c: true, v: false)),
		test_case(0x4463, 
				  instr_16(op: opcode.add_high_reg_1,rd: reg.r3,  rn: reg.r3, rm: reg.r12),
				  cortex_m_cpu(r3: 3, r12: 4),
				  cortex_m_cpu(pc: 2, r3: 7, r12: 4)),
		test_case(0x1e54, 
			      instr_16(op: opcode.sub_imm_3,     rd: reg.r4,  rn: reg.r2, imm: 1),
			      cortex_m_cpu(r4: 7, r2: 9),
			      cortex_m_cpu(pc: 2, r4: 8, r2: 9, c: true)),
		test_case(0x44e6, 
			      instr_16(op: opcode.add_high_reg_2,rd: reg.lr,  rn: reg.lr, rm: reg.r12),
			      cortex_m_cpu(lr:  7, r12: 9),
			      cortex_m_cpu(pc: 2, lr: 16, r12: 9)),
		test_case(0x4572, 
			      instr_16(op: opcode.cmp_high_2,	 rn: reg.r2,  rm: reg.lr),
			      cortex_m_cpu(r2: 0, lr: 0),
			      cortex_m_cpu(pc: 2, z: true, n: false, c: true, v: false)),
		test_case(0x4241, 
			      instr_16(op: opcode.negs,			 rd: reg.r1,  rn: reg.r0),
				  cortex_m_cpu(r0: 1),
			      cortex_m_cpu(r1: -1, r0: 1)),
		test_case(0xd3f9,
				  instr_16(op: opcode.b_cond, 		 cond: condition.cc, offset: -14),
				  cortex_m_cpu(pc: 0x800a1a8),
				  cortex_m_cpu(pc: 0x800a19e)),
				  //  800a1a8:	d3f9      	bcc.n	800a19e
				  // 1101 0011 1111 1001
		test_case(0xe001,
				  instr_16(op: opcode.b_imm_11,		offset: 2),
				  cortex_m_cpu(pc: 0x800a1b0),
				  cortex_m_cpu(pc: 0x800a1b6))
				  // 1110 0000 0000 00001
				  // 800a1b0:	e001      	b.n	800a1b6 <LoopFillZerobss>
	];

	foreach (t; tests) {
		execute_instr(t.instr, t.before);
		assert(
		    t.before == t.expected,
		    format("Failed for instruction 0x%04X", t.instr_bytes)
		);
		writeln("Test passed");
    }

	test_case_mem[] tests_mem = [
		test_case_mem(0x608b, 
			          instr_16(op: opcode.str_imm,       rt: reg.r3,  rn: reg.r1, imm: 8),
			          cortex_m_cpu(r3: 0b0101, r1: memory.ram_origin + 12),
			          cortex_m_cpu(pc: 2, r3: 0b0101, r1: memory.ram_origin + 12),
			          memory(ram: make_ram_with(20, 0)),
			          memory(ram: make_ram_with(20, 0b0101))),
		test_case_mem(0x50c4, // str	r4, [r0, r3]
				      instr_16(op: opcode.str_reg, 	     rt: reg.r4,  rn: reg.r0, rm: reg.r3),
					  cortex_m_cpu(r4: 0xffffffff, r3: 10, r0: memory.ram_origin),
					  cortex_m_cpu(r4: 0xffffffff, pc: 2, r3: 10, r0: memory.ram_origin),
					  memory(),
					  memory(ram: make_ram_with(10, 0xffffffff))),
		test_case_mem(0x80fb, 
			          instr_16(op: opcode.strh_imm,      rt: reg.r3,  rn: reg.r7, imm: 6),
			          cortex_m_cpu(r3: 0x0000eeee, r7: memory.ram_origin + 10),
			          cortex_m_cpu(pc: 2, r3: 0x0000eeee, r7: memory.ram_origin + 10),
			          memory(ram: make_ram_with(16, 0xffffffff)),
			          memory(ram: make_ram_with(16, 0xffffeeee))),
		test_case_mem(0x88fb, 
			          instr_16(op: opcode.ldrh_imm,      rt: reg.r3,  rn: reg.r7, imm: 6),
			          cortex_m_cpu(r3: 0xffffffff, r7: memory.ram_origin + 10),
			          cortex_m_cpu(pc: 2, r3: 0xffffeeee, r7: memory.ram_origin + 10),
			          memory(ram: make_ram_with(16, 0x0000eeee)),
			          memory(ram: make_ram_with(16, 0x0000eeee))),
		/*
		test_case_mem(0x781a, 
					  instr_16(op: opcode.ldrb_imm,      rt: reg.r2,  rn: reg.r3, imm: 0),
					  cortex_m_cpu(r2: 0xffffffff, r3: memory.ram_origin + 10),
			          cortex_m_cpu(pc: 2, r2: 0xffffffee, r3: memory.ram_origin + 10),
			          memory(ram: make_ram_with(10, 0x000000ee)),
			          memory(ram: make_ram_with(10, 0x000000ee))),
		*/
		test_case_mem(0x701a, 
				      instr_16(op: opcode.strb_imm,      rt: reg.r2,  rn: reg.r3, imm: 0),
				      cortex_m_cpu(r2: 0x000000ee, r3: memory.ram_origin + 10),
			          cortex_m_cpu(pc: 2, r2: 0x000000ee, r3: memory.ram_origin + 10),
			          memory(ram: make_ram_with(10, 0xffffffff)),
			          memory(ram: make_ram_with(10, 0xffffffee))),
		test_case_mem(0x68fb, 
					  instr_16(op: opcode.ldr_imm,       rt: reg.r3,  rn: reg.r7, imm: 12),
					  cortex_m_cpu(r3: 0x000000ff, r7: memory.ram_origin + 10),
			          cortex_m_cpu(pc: 2, r3: 0x000000ee, r7: memory.ram_origin + 10),
			          memory(ram: make_ram_with(22, 0x000000ee)),
			          memory(ram: make_ram_with(22, 0x000000ee))),
		test_case_mem(0x68fb, 
					  instr_16(op: opcode.ldr_imm,       rt: reg.r3,  rn: reg.r7, imm: 0x30),
					  cortex_m_cpu(r7: 0x40023800),
			          cortex_m_cpu(pc: 2, r7: 0x40023800),
			          memory(),
			          memory()),
		test_case_mem(0x4803, 
					  // 80091a0:	4803      	ldr	r0, [pc, #12]	@ (80091b0 <stdio_exit_handler+0x14>)
					  instr_16(op: opcode.ldr_pool,      rt: reg.r0,              imm: 12),
					  cortex_m_cpu(r0: 0x000000ff, pc: 0x80091a0),
			          cortex_m_cpu(r0: 0x000000ee, pc: 0x80091a2),
			          memory(flash: make_flash_with(0x80091b0 - memory.flash_origin, 0x000000ee)),
			          memory(flash: make_flash_with(0x80091b0 - memory.flash_origin, 0x000000ee))),
		test_case_mem(0xb510, 
			      	  instr_16(op: opcode.push_mult_reg, reg_list: [reg.r4, reg.lr]),
			      	  cortex_m_cpu(msp: memory.stack_base, lr: 0x000000ff, r4: 0x000000ee),
			          cortex_m_cpu(pc: 2, msp: memory.stack_base-8, lr: 0x000000ff, r4: 0x000000ee),
			          memory(),
			          memory(ram: make_ram_with([memory.stack_base-4, memory.stack_base-8],
			          							[0x000000ff, 0x000000ee]))),
		test_case_mem(0xbd10, 
				      instr_16(op: opcode.pop_mult_reg,  reg_list: [reg.r4, reg.pc]),
				      cortex_m_cpu(msp: memory.stack_base-8),
			          cortex_m_cpu(msp: memory.stack_base, pc: 0x000000ee, r4: 0x000000ff),
			          memory(ram: make_ram_with([memory.stack_base-4, memory.stack_base-8],
			          							[0x000000ee, 0x000000ff])),
				      memory()),
		test_case_mem(0x5cd3, 
			      	  instr_16(op: opcode.ldrb_reg,      rt: reg.r3,  rn: reg.r2, rm: reg.r3),
			          cortex_m_cpu(r2: memory.ram_origin + 10, r3: 10),
				      cortex_m_cpu(pc: 2, r3: 0x000000ee, r2: memory.ram_origin + 10),
				      memory(ram: make_ram_with(20, 0xffffffee)),
				      memory(ram: make_ram_with(20, 0xffffffee))),
		test_case_mem(0x58fb, 
			          instr_16(op: opcode.ldr_reg,	     rt: reg.r3,  rn: reg.r7, rm: reg.r3),
			          cortex_m_cpu(r3:         10, r7: memory.ram_origin + 10),
			          cortex_m_cpu(pc: 2, r3: 0xffffffee, r7: memory.ram_origin + 10),
			          memory(ram: make_ram_with(20, 0xffffffee)),
				      memory(ram: make_ram_with(20, 0xffffffee))),
		/*
		test_case_mem(0x6013, 
			          instr_16(op: opcode.str_imm,	     rt: reg.r3,  rn: reg.r2, imm: 0),
			          cortex_m_cpu(r3:         10, r2: 0x5600800),
			          cortex_m_cpu(pc: 2, r3: 0xffffffee, r2: 0x5600800),
			          memory(),
				      memory(flash: make_flash_with(0x5600800 - memory.flash_origin, 0xffffffee)))

		 //800a1b2:	6013      	str	r3, [r2, #0]
		 */
	];

    foreach (t; tests_mem) {
    	execute_load_store(t.instr, t.before, t.mem_before);
    	assert(
    		t.before == t.expected && t.mem_before == t.mem_after,
    		format("Failed for instruction 0x%04X", t.instr_bytes)
    	);
    	writeln("Test passed");
    }
} 

struct instr_32 {
	opcode op;
	reg rd;
	reg rn;
	reg rm;
	reg rt;
	shift_type shift_t;
	uint imm;
	ubyte shift_n;
	int offset;
	reg[] reg_list;
	uint ls_bit;
	uint width;
	uint ms_bit;
	reg rd_hi;
	reg rd_lo;
	reg rt_2;
	reg ra;
	condition cond;
	bool wback;
	bool add;
	bool index;
	ubyte mask;
	special_reg spec_reg;
	bool set_flags;
}

enum shift_type : ubyte {
	lsl,
	lsr,
	asr,
	rrx,
	ror,
	none,
	invalid
}

shift_type get_shift_type(ubyte type, ubyte imm) {
	switch (type) {
		case 0b00:
			return shift_type.lsl;
		case 0b01:
			return shift_type.lsr;
		case 0b10:
			return shift_type.asr;
		case 0b11:
			if (imm == 0b0000) {
				return shift_type.rrx;
			} else {
				return shift_type.ror;
			}
		default:
			return shift_type.invalid;
	}
}

uint shift(shift_type t, uint n, uint val) {
	switch (t) {
		case shift_type.lsl:
			return (val << n);
		case shift_type.lsr:
			return (val >>> n);
		case shift_type.asr:
			return (val >> n);
		default:
			return 0;
	}
}

// ======================
//  Parse MOV(Immediate)
// ======================

enum field_tuples_mov_imm_32_t2 = [Tuple!(opcode, string[])(opcode.mov_imm_32_t2, ["rd","imm"])];
/*
	Data Processing (Modified Immediate)
	First Half-Word:
	[15:11] 11110
	[10] i
	[8:5] 00010
	[4] S
	[3:0] 1111
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8 
*/
// f04f 31ff
// 1111 0000 0100 1111 0011 0001 1111 1111
instr_32 parse_mov_imm_32_t2(uint instr) {
	instr_32 res;
	res.op = opcode.mov_imm_32_t2;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	int imm_32 = thumb_expand_imm(imm_12);
	res.rd = cast(reg)(rd);
	res.imm = imm_32;
	return res;
}

// ===========
//  Parse ADD
// ===========

enum field_tuples_add_32_reg = [Tuple!(opcode, string[])(opcode.add_32_reg, ["rd","rn","rm"])];
/*
	Data Processing (Shifted Register)
	First Half-Word:
	[15:5] 1110101000
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_add_32_reg(uint instr) {
	instr_32 res;
	res.op = opcode.add_32_reg;
	ubyte rm = cast(ubyte)(instr & 0b1111);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0b1111);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte imm_5 = cast(ubyte)((imm_3 << 2) | (imm_2));
	res.shift_t = get_shift_type(type, imm_5);
	ubyte rn = cast(ubyte)((instr >> 16) & 0b1111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm_5;
	}
	return res;
}

// ==========
//  Parse BL
// ==========

enum field_tuples_bl_32 = [Tuple!(opcode, string[])(opcode.bl_32, [])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:11] 11110
	[10] S
	[9:0] imm10
	Second Half-Word:
	[15:14] 11
	[13] J1
	[12] 1
	[11] J2
	[10:0] imm11
*/
instr_32 parse_bl_32(uint instr) {
	instr_32 res;
	res.op = opcode.bl_32;
	ushort imm_11 = cast(ushort)(instr & 0x7ff);
	ushort imm_10 = cast(ushort)((instr >> 16) & 0x3ff);
	ubyte j1 = cast(ubyte)((instr >> 13) & 0b1);
	ubyte j2 = cast(ubyte)((instr >> 11) & 0b1);
	ubyte s = cast(ubyte)((instr >> 26) &0b1);
	int imm_32 = (s << 24) | (!(j1 ^ s) << 23) | (!(j2 ^ s) << 22) | (imm_10 << 12) | (imm_11 << 1) | 0b0;
	if (s == 0b1) {
		imm_32 |= 0xfe000000;
	}
	res.offset = imm_32;
	return res;
}

// ===========
//  Parse NOP
// ===========

enum field_tuples_nop_32 = [Tuple!(opcode, string[])(opcode.nop_32, [])];

instr_32 parse_nop_32(uint instr) {
	instr_32 res;
	res.op = opcode.nop_32;
	return res;
}

// ====================
//  Parse Pop Mult Reg
// ====================

enum field_tuples_pop_mult_reg_32 = [Tuple!(opcode, string[])(opcode.pop_mult_reg_32, ["reg_list"])];
/*
	Load Multiple and Store Multiple
	First Half-Word:
	[15:6] 1110100010
	[5] W
	[4] 1
	[3:0] Rn
	Second Half-Word:
	[15] P
	[14] M
	[13] 0
	[12:0] register_list 
*/
instr_32 parse_pop_mult_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.pop_mult_reg_32;
	ushort reg_list = cast(ushort)(instr & 0xffff);
	if (reg_list & 0x0001) res.reg_list ~= reg.r0;
	if (reg_list & 0x0002) res.reg_list ~= reg.r1;
	if (reg_list & 0x0004) res.reg_list ~= reg.r2;
	if (reg_list & 0x0008) res.reg_list ~= reg.r3;
	if (reg_list & 0x0010) res.reg_list ~= reg.r4;
	if (reg_list & 0x0020) res.reg_list ~= reg.r5;
	if (reg_list & 0x0040) res.reg_list ~= reg.r6;
	if (reg_list & 0x0080) res.reg_list ~= reg.r7;
	if (reg_list & 0x0100) res.reg_list ~= reg.r8;
	if (reg_list & 0x0200) res.reg_list ~= reg.r9;
	if (reg_list & 0x0400) res.reg_list ~= reg.r10;
	if (reg_list & 0x0800) res.reg_list ~= reg.r11;
	if (reg_list & 0x1000) res.reg_list ~= reg.r12;
	if (reg_list & 0x2000) res.reg_list ~= reg.sp;
	if (reg_list & 0x4000) res.reg_list ~= reg.lr;
	if (reg_list & 0x8000) res.reg_list ~= reg.pc;
	return res;
}

uint rotr(uint value, uint n) {
    n %= 32;
    return (value >> n) | (value << (32 - n));
}

// ==================
//  Parse SUB IMM 32
// ==================

enum field_tuples_sub_imm_32 = [Tuple!(opcode, string[])(opcode.sub_imm_32, ["rd","rn","imm"])];
/*
	Data Processing (Modified Immediate)
	First Half-Word:
	[15:11] 11110
	[10] i
	[9:5] 01101
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8 
*/
instr_32 parse_sub_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.sub_imm_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	int imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	return res;
}

// ==================
//  Parse AND IMM 32
// ==================

enum field_tuples_and_imm_32 = [Tuple!(opcode, string[])(opcode.and_imm_32, ["rd","rn","imm"])];
/*
	Data Processing (Modified Immediate)
	First Half-Word:
	[15:11] 11110
	[10] i
	[9:5] 00000
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8 
*/
instr_32 parse_and_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.and_imm_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ubyte S = cast(ubyte)((instr >> 26) & 0b1);
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	uint imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	res.set_flags = S == 1 ? true : false;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// ============
//  Parse UDIV
// ============

enum field_tuples_udiv_32 = [Tuple!(opcode, string[])(opcode.udiv_32, ["rd","rn","rm"])];
/*
	Long Multiply, Long Multiply Accumulate, and Divide Operations
	First Half-Word:
	[15:4] 11110111011
	[3:0] Rn
	Second Half-Word:
	[15:12] 1111
	[11:8] Rd
	[7:4] 1111
	[3:0] Rm 
*/
instr_32 parse_udiv_32(uint instr) {
	instr_32 res;
	res.op = opcode.udiv_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rm = cast(reg)(rm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// ============
//  Parse UBFX
// ============

enum field_tuples_ubfx_32 = [Tuple!(opcode, string[])(opcode.ubfx_32, ["rd","rn","lsb","width"])];
/*
	UBFX <Rd>, <Rn>, #<lsb>, #<width>
	Data Processing (Plain Binary Immediate)
	First Half-Word:
	[15:4] 111100111100
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:6] imm3
	[5] 0
	[4:0] widthm1
*/
instr_32 parse_ubfx_32(uint instr) {
	instr_32 res;
	res.op = opcode.ubfx_32;
	ubyte width = cast(ubyte)(instr & 0xf);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0x3);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	uint ls_bit = (imm_3 << 2) | imm_2;
	res.ls_bit = ls_bit;
	res.width = width + 1;
	res.rn = cast(reg)(rn);
	res.rd = cast(reg)(rd);
	return res;
}

// ===========
//  Parse MUL
// ===========

enum field_tuples_mul_32 = [Tuple!(opcode, string[])(opcode.mul_32, ["rd","rn","rm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111110110000
	[3:0] Rn
	Second Half-Word:
	[15:12] 1111
	[11:8] Rd
	[7:4] 0000
	[3:0] Rm
*/
instr_32 parse_mul_32(uint instr) {
	instr_32 res;
	res.op = opcode.mul_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	res.rn = cast(reg)(rn);
	return res;
}

// =====================
//  Parse LSL(Register)
// =====================

enum field_tuples_lsl_reg_32 = [Tuple!(opcode, string[])(opcode.lsl_reg_32, ["rd","rn","rm"])];
/*
	Data Processing(Register)
	First Half-Word:
	[15:5] 11111010000
	[4] S
	[3:0] Rn 
	Second Half-Word:
	[15:12] 1111
	[11:8] Rd
	[7:4] 0000
	[3:0] Rm
*/
instr_32 parse_lsl_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.lsl_reg_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	res.rn = cast(reg)(rn);
	return res;
}


// ===========
//  Parse LSR
// ===========

enum field_tuples_lsr_reg_32 = [Tuple!(opcode, string[])(opcode.lsr_reg_32, ["rd","rn","rm"])];
/*
	Data Processing(Register)
	First Half-Word:
	[15:5] 11111010001
	[4] S
	[3:0] Rn 
	Second Half-Word:
	[15:12] 1111
	[11:8] Rd
	[7:4] 0000
	[3:0] Rm
*/
instr_32 parse_lsr_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.lsr_reg_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte S = cast(ubyte)((instr >> 20) & 0b1);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	res.rn = cast(reg)(rn);
	res.set_flags = S == 1 ? true : false;
	return res;
}

uint thumb_expand_imm(ushort imm_12) {
	if ((cast(ubyte)(imm_12 >> 10) & 0b11) == 0b00) {
		ubyte imm_8 = cast(ubyte)(imm_12 & 0xff);
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b10) {
			return (imm_8 << 24) | (imm_8 << 8);
		}
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b0) {
			return imm_8;
		}
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b11) {
			return (imm_8 << 24) | (imm_8 << 16) | (imm_8 << 8) | imm_8;
		}
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b01) {
			return (imm_8 << 24) | (imm_8 << 8);
		}
	} 
	int rotate_by = ((imm_12) >> 7) & 0x1f;
	uint unrotated = (1 << 7) | (imm_12 & 0x7f);
	uint rotated = rotr(unrotated, rotate_by);
	return rotated;
}

// ===========
//  Parse ORR
// ===========

enum field_tuples_orr_32 = [Tuple!(opcode, string[])(opcode.orr_32, ["rd","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:11] 11110
	[10] i
	[9:5] 00010
	[4] S
	[3:0] Rn 
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8
*/
instr_32 parse_orr_32(uint instr) {
	instr_32 res;
	res.op = opcode.orr_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	uint imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// ===========
//  Parse ADD
// ===========

enum field_tuples_add_32 = [Tuple!(opcode, string[])(opcode.add_32, ["rd","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:11] 11110
	[10] i
	[9:5] 01000
	[4] S
	[3:0] Rn 
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8
*/
instr_32 parse_add_32(uint instr) {
	instr_32 res;
	res.op = opcode.add_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	uint imm_32 = thumb_expand_imm(imm_12);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.imm = imm_32;
	return res;
}

// =======================
//  Parse Bit Field Clear
// =======================

/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:0] 1111001101101111 
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[7:6] imm2
	[5] 0
	[4:0] msb
*/
instr_32 parse_bfc_32(uint instr) {
	instr_32 res;
	res.op = opcode.bfc_32;
	ubyte msb = cast(ubyte)(instr & 0xf);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0x3);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	uint ls_bit = (imm_3 << 2) | imm_2;
	uint ms_bit = msb;
	res.ls_bit = ls_bit;
	res.rd = cast(reg)(rd);
	return res;
}

// =====================
//  Parse BIC(Register)
// =====================

enum field_tuples_bic_reg_32 = [Tuple!(opcode, string[])(opcode.bic_reg_32, ["rd","rn","rm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101010001
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_bic_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.bic_reg_32;
	ubyte rm = cast(ubyte)(instr & 0b1111);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0b1111);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte imm_5 = cast(ubyte)((imm_3 << 2) | (imm_2));
	res.shift_t = get_shift_type(type, imm_5);
	ubyte rn = cast(ubyte)((instr >> 16) & 0b1111);
	ubyte S = cast(ubyte)((instr >> 20) & 0b1);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	res.set_flags = S == 1 ? true : false;
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm_5;
	}
	return res;
}

enum field_tuples_bic_imm_32 = [Tuple!(opcode, string[])(opcode.bic_imm_32, ["rd","rn","imm"])];
instr_32 parse_bic_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.bic_imm_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ubyte S = cast(ubyte)((instr >> 20) & 0b1);
 	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	int imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	res.set_flags = S == 1 ? true : false;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// ===========
//  Parse MOV
// ===========

enum field_tuples_mov_16_imm_32 = [Tuple!(opcode, string[])(opcode.mov_16_imm_32, ["rd","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:11] 11110
	[10] i
	[9:4] 100100
	[3:0] imm4
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8
*/
instr_32 parse_mov_16_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.mov_16_imm_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte imm_4 = cast(ubyte)((instr >> 16) & 0xf);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
 	uint imm_32 = (imm_4 << 12) | (i << 11) | (imm_3 << 9) | imm_8;
	res.imm = imm_32;
	res.rd = cast(reg)(rd);
	return res;
}

// =============
//  Parse LDRSB
// =============

enum field_tuples_ldrsb_imm_32_t1 = [Tuple!(opcode, string[])(opcode.ldrsb_imm_32_t1, ["rt","rn", "imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	LDRSB <Rt>,[<Rn>,#<imm12>]
	First Half-Word:
	[15:4] 111110011001
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:0] imm12
*/
instr_32 parse_ldrsb_imm_32_t1(uint instr) {
	instr_32 res;
	res.op = opcode.ldrsb_imm_32_t1;
	uint imm_12 = cast(ubyte)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.imm = imm_12;
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	return res;
}

// =============
//  Parse LDRSB
// =============

enum field_tuples_ldrsb_imm_32_t2 = [Tuple!(opcode, string[])(opcode.ldrsb_imm_32_t2, ["rt","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111110011001
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:0] imm12
*/
instr_32 parse_ldrsb_imm_32_t2(uint instr) {
	instr_32 res;
	res.op = opcode.ldrsb_imm_32_t2;
	uint imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.imm = imm_8;
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	return res;
}

// ===========
//  Parse MSR
// ===========

enum field_tuples_msr_32 = [Tuple!(opcode, string[])(opcode.msr_32, ["spec_reg", "rn"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111100111000
	[3:0] Rn
	Second Half-Word:
	[15:12] 1000
	[11:10] mask
	[9:8] 00
	[7:0] SYSm
*/
instr_32 parse_msr_32(uint instr) {
	instr_32 res;
	res.op = opcode.msr_32;
	ubyte sys_m = cast(ubyte)(instr & 0xff);
	ubyte mask = cast(ubyte)((instr >> 10) & 0b11);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rn = cast(reg)(rn);
	res.spec_reg = cast(special_reg)sys_m;
	res.mask = mask;
	return res;
}

enum field_tuples_mrs_32 = [Tuple!(opcode, string[])(opcode.mrs_32, ["rd", "spec_reg"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111100111000
	[3:0] Rn
	Second Half-Word:
	[15:12] 1000
	[11:10] mask
	[9:8] 00
	[7:0] SYSm
*/
instr_32 parse_mrs_32(uint instr) {
	instr_32 res;
	res.op = opcode.mrs_32;
	ubyte sys_m = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	res.rd = cast(reg)(rd);
	res.spec_reg = cast(special_reg)sys_m;
	return res;
}

// ===========
//  Parse STR
// ===========

enum field_tuples_str_reg_32 = [Tuple!(opcode, string[])(opcode.str_reg_32, ["rt","rn","rm","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111110000100
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[5:4] imm2
	[3:0] Rm
*/
instr_32 parse_str_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.str_reg_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte imm_2 = cast(ubyte)((instr >> 4) & 0b11);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	res.rm = cast(reg)(rm);
	res.imm = imm_2;
	return res;
}

// ===========
//  Parse STR
// ===========

enum field_tuples_str_imm_32_t3 = [Tuple!(opcode, string[])(opcode.str_imm_32_t3, ["rt","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111110000100
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[5:4] imm2
	[3:0] Rm
*/
instr_32 parse_str_imm_32_t3(uint instr) {
	instr_32 res;
	res.op = opcode.str_imm_32_t3;
	ushort imm_12 = cast(ushort)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	res.index = true; 
	res.add = true; 
	res.imm = imm_12;
	return res;
}

// ===========
//  Parse STR
// ===========

enum field_tuples_str_imm_32_t4 = [Tuple!(opcode, string[])(opcode.str_imm_32_t4, ["rt","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111110000100
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11] 1
	[10] P
	[9] U
	[8] W
	[7:0] imm8
*/
instr_32 parse_str_imm_32_t4(uint instr) {
	instr_32 res;
	res.op = opcode.str_imm_32_t4;
	ubyte W = cast(ubyte)((instr >>  8) & 0b1);
	ubyte U = cast(ubyte)((instr >>  9) & 0b1);
	ubyte P = cast(ubyte)((instr >> 10) & 0b1);
	bool wback = W == 1 ? true: false;
	bool add = U == 1 ? true: false;
	bool index = P == 1 ? true: false;
	ushort imm_8 = cast(ushort)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	res.wback = wback;
	res.add = add;
	res.index = index;
	res.imm = imm_8;
	return res;
}

// ===========
//  Parse DSB
// ===========

instr_32 parse_dsb_32(uint instr) {
	instr_32 res;
	res.op = opcode.dsb_32;
	return res;
}

// ===========
//  Parse RSB
// ===========

enum field_tuples_rsb_32 = [Tuple!(opcode, string[])(opcode.rsb_32, ["rd","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:11] 11110 
	[10] i
	[9:5] 01110
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8
*/
instr_32 parse_rsb_32(uint instr) {
	instr_32 res;
	res.op = opcode.rsb_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte i = cast(ubyte)((instr >> 20) & 0b1);
	res.rn = cast(reg)(rn);
	res.rd = cast(reg)(rd);
	uint rotate_by = (i << 3) | imm_3;
	uint imm = rotr(imm_8, rotate_by * 2);
	res.imm = imm;
	return res;
}

// =============
//  Parse UMULL
// =============

enum field_tuples_umull_32 = [Tuple!(opcode, string[])(opcode.umull_32, ["rd_lo","rd_hi","rn","rm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:11] 11110 
	[10] i
	[9:5] 01110
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8
*/
instr_32 parse_umull(uint instr) {
	instr_32 res;
	res.op = opcode.umull_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd_hi = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rd_lo = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	res.rd_hi = cast(reg)(rd_hi);
	res.rd_lo = cast(reg)(rd_lo);
	return res;
}

// ============
//  Parse STRD
// ============

enum field_tuples_strd_32 = [Tuple!(opcode, string[])(opcode.strd_32, ["rt","rt2","rn","imm"])];
/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:9] 1110100  
	[8] P
	[7] U
	[6] 1
	[5] W
	[4] 0
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:8] Rt2
	[7:0] imm8
*/
instr_32 parse_strd_32(uint instr) {
	instr_32 res;
	res.op = opcode.strd_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt_2 = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte W = cast(ubyte)((instr >> 21) & 0b1);
	ubyte U = cast(ubyte)((instr >> 23) & 0b1);
	bool wback = W == 1 ? true: false;
	bool add = U == 1 ? true: false;
	res.rt = cast(reg)(rt);
	res.rt_2 = cast(reg)(rt_2);
	res.rn = cast(reg)(rn);
	res.wback = wback;
	res.add = add;
	uint imm = imm_8 << 2;
	res.imm = imm;
	return res;
}

// =========
//  Parse B
// =========

enum field_tuples_b_32 = [Tuple!(opcode, string[])(opcode.b_32, [])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:11] 11110
	[10] S
	[9:6] cond
	[5:0] imm6
	Second Half-Word:
	[15:14] 10
	[13] J1
	[12] 1
	[11] J2
	[10:0] imm11
*/
instr_32 parse_b_32(uint instr) {
	instr_32 res;
	res.op = opcode.b_32;
	ushort imm_11 = cast(ushort)(instr & 0x7ff);
	ushort imm_6 = cast(ushort)((instr >> 16) & 0x3f);
	res.cond = cast(condition)((instr >> 22) & 0b1111);
	ubyte j1 = cast(ubyte)((instr >> 13) & 0b1);
	ubyte j2 = cast(ubyte)((instr >> 11) & 0b1);
	ubyte s = cast(ubyte)((instr >> 26) &0b1);
	int i1 = !(j1 ^ s);
	int i2 = !(j2 ^ s);
	assert(i1 == 0 || i1 == 1);
	assert(i2 == 0 || i2 == 1);
	int imm_32 = (s << 20) | (j1 << 19) | (j2 << 18) | (imm_6 << 12) | (imm_11 << 1) | 0b0;
	if (s == 0b1) {
		imm_32 |= 0xffe00000;
	}
	res.offset = imm_32;
	return res;
}

enum field_tuples_b_uncond_32 = [Tuple!(opcode, string[])(opcode.b_uncond_32, [])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:11] 11110
	[10] S
	[9:0] imm10
	Second Half-Word:
	[15:14] 10
	[13] J1
	[12] 1
	[11] J2
	[10:0] imm11
*/
instr_32 parse_b_uncond_32(uint instr) {
	instr_32 res;
	res.op = opcode.b_uncond_32;
	ushort imm_11 = cast(ushort)(instr & 0x7ff);
	ushort imm_10 = cast(ushort)((instr >> 16) & 0x3ff);
	ubyte j1 = cast(ubyte)((instr >> 13) & 0b1);
	ubyte j2 = cast(ubyte)((instr >> 11) & 0b1);
	ubyte s = cast(ubyte)((instr >> 26) &0b1);
	int i1 = !(j1 ^ s);
	int i2 = !(j2 ^ s);
	assert(i1 == 0 || i1 == 1);
	assert(i2 == 0 || i2 == 1);
	int imm_32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm_10 << 12) | (imm_11 << 1) | 0b0;
	if (s == 0b1) {
		imm_32 |= 0xfe000000;
	}
	res.offset = imm_32;
	return res;
}

// =====================
//  Parse PUSH MULT REG
// =====================

enum field_tuples_push_mult_reg_32 = [Tuple!(opcode, string[])(opcode.push_mult_reg_32, ["reg_list"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:0] 1110100100101101
	Second Half-Word:
	[15] 0 
	[14] M
	[13] 0
	[12:0] register_list
*/
instr_32 parse_push_mult_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.push_mult_reg_32;
	ushort reg_list = cast(ushort)(instr & 0xffff);
	if (reg_list & 0x0001) res.reg_list ~= reg.r0;
	if (reg_list & 0x0002) res.reg_list ~= reg.r1;
	if (reg_list & 0x0004) res.reg_list ~= reg.r2;
	if (reg_list & 0x0008) res.reg_list ~= reg.r3;
	if (reg_list & 0x0010) res.reg_list ~= reg.r4;
	if (reg_list & 0x0020) res.reg_list ~= reg.r5;
	if (reg_list & 0x0040) res.reg_list ~= reg.r6;
	if (reg_list & 0x0080) res.reg_list ~= reg.r7;
	if (reg_list & 0x0100) res.reg_list ~= reg.r8;
	if (reg_list & 0x0200) res.reg_list ~= reg.r9;
	if (reg_list & 0x0400) res.reg_list ~= reg.r10;
	if (reg_list & 0x0800) res.reg_list ~= reg.r11;
	if (reg_list & 0x1000) res.reg_list ~= reg.r12;
	if (reg_list & 0x2000) res.reg_list ~= reg.sp;
	if (reg_list & 0x4000) res.reg_list ~= reg.lr;
	if (reg_list & 0x8000) res.reg_list ~= reg.pc;
	return res;
}

// ===============
//  Parse ORR REG
// ===============

enum field_tuples_orr_reg_32 = [Tuple!(opcode, string[])(opcode.orr_reg_32, ["rd","rn","rm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101010010
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_orr_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.orr_reg_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// ===========
//  Parse SUB
// ===========

enum field_tuples_subs_32 = [Tuple!(opcode, string[])(opcode.subs_32, ["rd","rn","rm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101011101
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_subs_32(uint instr) {
	instr_32 res;
	res.op = opcode.subs_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// ===========
//  Parse SBC
// ===========

enum field_tuples_sbc_32 = [Tuple!(opcode, string[])(opcode.sbc_32, ["rd","rn","rm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101011101
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_sbc_32(uint instr) {
	instr_32 res;
	res.op = opcode.sbc_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// ===========
//  Parse ADC
// ===========

enum field_tuples_adc_32 = [Tuple!(opcode, string[])(opcode.adc_32, ["rd","rn","rm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101011010
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_adc_32(uint instr) {
	instr_32 res;
	res.op = opcode.adc_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// ==================
//  Parse BIT OR NOT
// ==================

/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101011010
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_bit_or_not_32(uint instr) {
	instr_32 res;
	res.op = opcode.bit_or_not_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	//ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte S = cast(ubyte)((instr >> 20) & 0b1);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ushort imm_12 = cast(ushort)((i << 3) | (imm_3 << 8) | imm_8);
	int imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	res.set_flags = S == 1 ? true : false;
	res.rd = cast(reg)(rd);
	return res;
}

// ===============
//  Parse BIT NOT
// ===============

enum field_tuples_bit_not_32 = [Tuple!(opcode, string[])(opcode.bit_not_32, ["rd","imm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101011010
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_bit_not_32(uint instr) {
	instr_32 res = parse_bit_or_not_32(instr);
	res.op = opcode.bit_not_32;
	return res;
}

// =============
//  Parse LDREX
// =============

/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:4] 111010000101
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:8] 1111
	[7:0] imm8
*/
instr_32 parse_ldrex_32(uint instr) {
	instr_32 res;
	res.op = opcode.ld_rex;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	uint imm = cast(ubyte)((imm_8 << 2) | 0b00);
	res.imm = imm;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	return res;
}

// =============
//  Parse STREX
// =============

/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:4] 111010000100
	[3:0] Rd
	Second Half-Word:
	[15:12] Rt
	[11:8] Rn
	[7:0] imm8
*/
instr_32 parse_strex_32(uint instr) {
	instr_32 res;
	res.op = opcode.str_rex;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >>  8) & 0xf);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	uint imm = cast(ubyte)((imm_8 << 2) | 0b00);
	res.imm = imm;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.rd = cast(reg)(rd);
	return res;
}

// ===========
//  Parse MLS
// ===========

enum field_tuples_mls_32 = [Tuple!(opcode, string[])(opcode.mls_32, ["rd","rn","rm","ra"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:4] 111110110000
	[3:0] Rn
	Second Half-Word:
	[15:12] Ra
	[11:8] Rd
	[7:4] 0001
	[3:0] Rm
*/
instr_32 parse_mls_32(uint instr) {
	instr_32 res;
	res.op = opcode.mls_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd = cast(ubyte)((instr >>  8) & 0xf);
	ubyte ra = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.ra = cast(reg)(ra);
	res.rm = cast(reg)(rm);
	res.rn = cast(reg)(rn);
	res.rd = cast(reg)(rd);
	return res;
}

// ========================
//  Parse CMP(immediate)
// ========================

enum field_tuples_cmp_imm_32 = [Tuple!(opcode, string[])(opcode.cmp_imm_32, ["rn","imm"])];
/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:11] 11110  
	[10] i
	[9:4] 011011
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:2] imm3
	[11:8] 1111
	[7:0] imm8 
*/
instr_32 parse_cmp_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.cmp_imm_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	res.rn = cast(reg)(rn);
	res.imm = thumb_expand_imm(imm_12);
	return res;
}

// ========================
//  Parse LDRSH(Immediate)
// ========================

/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:4] 111110011011  
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:0] imm12
*/
instr_32 parse_ldh_32(uint instr) {
	instr_32 res;
	res.op = opcode.ldh_32;
	ubyte imm_12 = cast(ubyte)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.imm = imm_12;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	return res;
}

// ===========
//  Parse TST
// ===========

/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:4] 111010100001
	[3:0] Rn
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] 1111
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_tst_32(uint instr) {
	instr_32 res;
	res.op = opcode.tst_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// =====================
//  Parse AND(Register)
// =====================

/*
	Branches and Miscellaneous Control
	First Half-Word:
	[15:5] 11101010000
	[4] S
	[3:0] Rn
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] type
	[3:0] Rm
*/
instr_32 parse_and_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.and_reg_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte type = cast(ubyte)((instr >> 4) & 0b11);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf); 
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte imm = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	res.rd = cast(reg)(rd);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// =====================
//  Parse LDR(Register)
// =====================

enum field_tuples_ldr_reg_32 = [Tuple!(opcode, string[])(opcode.ldr_reg_32, ["rt","rn","rm"])];
/*
	Load Word
	LDR<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
	First Half-Word:	
	[15:4] 111110000101
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:6] 000000
	[5:4] imm2
	[3:0] Rm 
*/
instr_32 parse_ldr_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.ldr_reg_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte imm_2 = cast(ubyte)((instr >> 4) & 0b11);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	res.shift_t = shift_type.lsl;
	res.shift_n = imm_2;
	return res;
}

// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldr_imm_32_t3 = [Tuple!(opcode, string[])(opcode.ldr_imm_32_t3, ["rt","rn","imm"])];
/*
	Load Word
	First Half-Word:
	[15:4] 111110001101
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:0] imm12
*/
instr_32 parse_ldr_imm_32_t3(uint instr) {
	instr_32 res;
	res.op = opcode.ldr_imm_32_t3;
	ushort imm_12 = cast(ushort)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.add = true;
	res.index = true;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_12;
	return res;
}

// ====================
//  Parse LDR(Literal)
// ====================

enum field_tuples_ldr_lit_32 = [Tuple!(opcode, string[])(opcode.ldr_lit_32, ["rt","pc","imm"])];
/*
	Load Word
	LDR<c>.W <Rt>,[PC,#-0]
	First Half-Word:
	[15:8] 11111000
	[7] U
	[6:0] 1011111
	Second Half-Word:
	[15:12] Rt
	[11:0] imm12
*/
instr_32 parse_ldr_lit_32(uint instr) {
	instr_32 res;
	res.op = opcode.ldr_lit_32;
	ushort imm_12 = cast(ushort)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte U = cast(ubyte)((instr >> 23) & 0b1);
	bool add = U == 1 ? true : false;
	res.rt = cast(reg)(rt);
	res.add = add;
	res.imm = imm_12;
	return res;
}

enum field_tuples_isb_32 = [Tuple!(opcode, string[])(opcode.isb_32, [])];
enum field_tuples_dsb_32 = [Tuple!(opcode, string[])(opcode.dsb_32, [])];

// =======================
//  Parse LDRD(Immediate)
// =======================

enum field_tuples_ldrd_imm_32 = [Tuple!(opcode, string[])(opcode.ldrd_imm_32, ["rt","rt2","rn","imm"])];
/*
	Load Word
	First Half-Word:
	[15:9] 1110100
	[8] P
	[7] U
	[6] 1
	[5] W
	[4] 1
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:8] Rt2
	[7:0] imm8
*/
instr_32 parse_ldrd_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.ldrd_imm_32;
	ubyte P = cast(ubyte)((instr >> 21) & 0b1);
	ubyte U = cast(ubyte)((instr >> 23) & 0b1);
	ubyte W = cast(ubyte)((instr >> 24) & 0b1);
	ushort imm_8 = cast(ushort)(instr & 0xff);
	ubyte rt2 = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.index = P == 1 ? true : false;
	res.add = U == 1 ? true : false;
	res.wback = W == 1 ? true : false;
 	res.rt = cast(reg)(rt);
	res.rt_2 = cast(reg)(rt2);
	res.rn = cast(reg)(rn);
	res.imm = imm_8;
	return res;
}


// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldr_imm_32_t4 = [Tuple!(opcode, string[])(opcode.ldr_imm_32_t4, ["rt","rn","imm"])];
/*
	Load Word
	First Half-Word:
	[15:4] 111110000101
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[10] P
	[9] U
	[8] W
	[7:0] imm8
*/
instr_32 parse_ldr_imm_32_t4(uint instr) {
	instr_32 res;
	res.op = opcode.ldr_imm_32_t4;
	ushort imm_8 = cast(ushort)(instr & 0xff);
	ubyte W = cast(ubyte)((instr >>  8) & 0b1);
	ubyte U = cast(ubyte)((instr >>  9) & 0b1);
	ubyte P = cast(ubyte)((instr >> 10) & 0b1);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	bool wback = W == 1 ? true : false;
	bool add = U == 1 ? true : false;
	bool index = P == 1 ? true : false;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_8;
	res.index = index;
	res.add = add;
	res.wback = wback;
	return res;
}

// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldrb_imm_32_t2 = [Tuple!(opcode, string[])(opcode.ldrb_imm_32_t2, ["rt","rn","imm"])];
/*
	Load Word
	First Half-Word:
	[15:4] 111110001001
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[10] P
	[9] U
	[8] W
	[7:0] imm8
*/
instr_32 parse_ldrb_imm_32_t2(uint instr) {
	instr_32 res;
	res.op = opcode.ldrb_imm_32_t2;
	ushort imm_12 = cast(ushort)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.add = true;
	res.wback = true;
	res.imm = imm_12;
	return res;
}

// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldrb_imm_32_t3 = [Tuple!(opcode, string[])(opcode.ldrb_imm_32_t3, ["rt","rn","imm"])];
/*
	Load Word
	First Half-Word:
	[15:4] 111110000001
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11] 1
	[10] P
	[9] U
	[8] W
	[7:0] imm8
*/
instr_32 parse_ldrb_imm_32_t3(uint instr) {
	instr_32 res;
	res.op = opcode.ldrb_imm_32_t3;
	ubyte W = cast(ubyte)((instr >>  8) & 0b1);
	ubyte U = cast(ubyte)((instr >>  9) & 0b1);
	ubyte P = cast(ubyte)((instr >> 10) & 0b1);
	ushort imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_8;
	bool wback = W == 0b1 ? true : false;
	bool add = U == 0b1 ? true : false;
	bool index = P == 0b1 ? true : false;
	res.wback = wback;
	res.add = add;
	res.index = index;
	return res;
}

// =====================
//  Parse MOV(Register)
// =====================

enum field_tuples_mov_32 = [Tuple!(opcode, string[])(opcode.mov_32, ["rd","rm","imm"])];
/*
	Data Processing
	Mov Register and Immeidate Shifts
	First Half-Word:
	[15:0] 11101010010
	[4] S 
	[3:0] 1111 
	Second Half-Word:
	[15] 0 
	[14:12] imm3
	[11:8] Rd
	[7:6] imm2
	[5:4] 10	
	[3:0] Rm
*/
// ea4f 06a6: 1110 1010 0100 1111 0000 0110 1010 0110
instr_32 parse_mov_32(uint instr) {
	instr_32 res;
	res.op = opcode.mov_32;
	ubyte rm = cast(ushort)(instr & 0xf);
	ubyte imm_2 = cast(ubyte)((instr >> 6) & 0b11);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0b111);
	ubyte imm_5 = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = shift_type.asr;
	res.shift_n = imm_5;
	res.imm = res.shift_n;
	res.rm = cast(reg)(rm);
	res.rd = cast(reg)(rd);
	return res;
}

// =======================
//  Parse STRB(Immediate)
// =======================

enum field_tuples_strb_imm_32_t2 = [Tuple!(opcode, string[])(opcode.strb_imm_32_t2, ["rt","rn","imm"])];
/*
	Data Processing
	Mov Register and Immeidate Shifts
	STRB<c>.W <Rt>,[<Rn>,#<imm12>]
	First Half-Word:
	[15:4] 111110001000
	[3:0] Rn 
	Second Half-Word:
	[15:12] Rt 
	[11:0] imm12
*/
// ea4f 06a6: 1110 1010 0100 1111 0000 0110 1010 0110
instr_32 parse_strb_imm_32_t2(uint instr) {
	instr_32 res;
	res.op = opcode.strb_imm_32_t2;
	ushort imm_12 = cast(ushort)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_12;
	res.index = true;
	res.add = true;
	return res;
}

// =======================
//  Parse STRB(Immediate)
// =======================

enum field_tuples_strb_imm_32_t3 = [Tuple!(opcode, string[])(opcode.strb_imm_32_t3, ["rt","rn","imm"])];
/*
	Data Processing
	Mov Register and Immeidate Shifts
	STRB<c>.W <Rt>,[<Rn>,#<imm12>]
	First Half-Word:
	[15:4] 111110001000
	[3:0] Rn 
	Second Half-Word:
	[15:12] Rt 
	[11:0] imm12
*/
// ea4f 06a6: 1110 1010 0100 1111 0000 0110 1010 0110
instr_32 parse_strb_imm_32_t3(uint instr) {
	instr_32 res;
	res.op = opcode.strb_imm_32_t3;
	ubyte imm_8 = cast(ushort)(instr & 0xff);
	ubyte W = cast(ubyte)((instr >>  8) & 0b1);
	ubyte U = cast(ubyte)((instr >>  9) & 0b1);
	ubyte P = cast(ubyte)((instr >> 10) & 0b1);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	bool wback = W == 0b1 ? true : false;
	bool add = U == 0b1 ? true : false;
	bool index = P == 0b1 ? true : false;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm_8;
	res.wback = wback;
	res.add = add;
	res.index = index;
	return res;
}

// ==============
//  Decode Instr
// ==============

instr_32 decode_instr(uint instr) {
	instr_32 res;
	auto op = decode_mnemonic_32(instr);

	switch (op) {
		case opcode.add_32_reg:
			return parse_add_32_reg(instr);
		case opcode.bl_32:
			return parse_bl_32(instr);
		case opcode.nop_32:
			return parse_nop_32(instr);
		case opcode.pop_mult_reg_32:
			return parse_pop_mult_reg_32(instr);
		case opcode.sub_imm_32:
			return parse_sub_imm_32(instr);
		case opcode.and_imm_32:
			return parse_and_imm_32(instr);
		case opcode.udiv_32:
			return parse_udiv_32(instr);
		case opcode.ubfx_32:
			return parse_ubfx_32(instr);
		case opcode.mul_32:
			return parse_mul_32(instr);
		case opcode.lsr_reg_32:
			return parse_lsr_reg_32(instr);
		case opcode.orr_32:
			return parse_orr_32(instr);
		case opcode.add_32:
			return parse_add_32(instr);
		case opcode.bic_reg_32:
			return parse_bic_reg_32(instr);
		case opcode.bic_imm_32:
			return parse_bic_imm_32(instr);
		case opcode.mov_16_imm_32:
			return parse_mov_16_imm_32(instr);
		case opcode.mov_imm_32_t2:
			return parse_mov_imm_32_t2(instr);
		case opcode.ldrsb_imm_32_t1:
			return parse_ldrsb_imm_32_t1(instr);
		case opcode.ldrsb_imm_32_t2:
			return parse_ldrsb_imm_32_t2(instr);
		case opcode.str_reg_32:
			return parse_str_reg_32(instr);
		case opcode.str_imm_32_t3:
			return parse_str_imm_32_t3(instr);
		case opcode.str_imm_32_t4:
			return parse_str_imm_32_t4(instr);
		case opcode.dsb_32:
			return parse_dsb_32(instr);
		case opcode.rsb_32:
			return parse_rsb_32(instr);
		case opcode.umull_32:
			return parse_umull(instr);
		case opcode.strd_32:
			return parse_strd_32(instr);
		case opcode.b_32:
			return parse_b_32(instr);
		case opcode.push_mult_reg_32:
			return parse_push_mult_reg_32(instr);
		case opcode.orr_reg_32:
			return parse_orr_reg_32(instr);
		case opcode.subs_32:
			return parse_subs_32(instr);
		case opcode.sbc_32:
			return parse_sbc_32(instr);
		case opcode.adc_32:
			return parse_adc_32(instr);
		case opcode.bit_or_not_32:
			return parse_bit_or_not_32(instr);
		case opcode.bit_not_32:
			return parse_bit_not_32(instr);
		case opcode.ld_rex:
			return parse_ldrex_32(instr);
		case opcode.str_rex:
			return parse_strex_32(instr);
		case opcode.mls_32:
			return parse_mls_32(instr);
		case opcode.ldh_32: 
			return parse_ldh_32(instr);
		case opcode.tst_32:
			return parse_tst_32(instr);
		case opcode.and_reg_32:
			return parse_and_reg_32(instr);
		case opcode.ldr_imm_32_t3:
			return parse_ldr_imm_32_t3(instr);
		case opcode.mov_32:
			return parse_mov_32(instr);
		case opcode.ldr_imm_32_t4:
			return parse_ldr_imm_32_t4(instr);
		case opcode.cmp_imm_32:
			return parse_cmp_imm_32(instr);
		case opcode.lsl_reg_32:
			return parse_lsl_reg_32(instr);
		case opcode.b_uncond_32:
			return parse_b_uncond_32(instr);
		case opcode.ldrd_imm_32:
			return parse_ldrd_imm_32(instr);
		case opcode.strb_imm_32_t2:
			return parse_strb_imm_32_t2(instr);
		case opcode.strb_imm_32_t3:
			return parse_strb_imm_32_t3(instr);
		case opcode.ldrb_imm_32_t2:
       		return parse_ldrb_imm_32_t2(instr);
       	case opcode.ldrb_imm_32_t3:
       		return parse_ldrb_imm_32_t3(instr);
       	case opcode.ldr_lit_32:
        	return parse_ldr_lit_32(instr);
        case opcode.ldr_reg_32:
        	return parse_ldr_reg_32(instr);
        case opcode.mrs_32:
        	return parse_mrs_32(instr);
        case opcode.msr_32:
        	return parse_msr_32(instr);
		default:
			res.op = op;
			return res;
	}
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		uint instr;
		instr_32 expected;
	}

	test_case[] tests = [
		test_case(0xeb0101a3, 
				  instr_32(op: opcode.add_32_reg, rd: reg.r1, rn: reg.r1, rm: reg.r3, shift_t: shift_type.asr, shift_n: 2)),				// add.w	r1, r1, r3, asr #2
		test_case(0xf7ffffda,
				  instr_32(op: opcode.bl_32, offset: -76)),
		test_case(0xf3af8000, 
				  instr_32(op: opcode.nop_32)),
		test_case(0xe8bd4008, 
				  instr_32(op: opcode.pop_mult_reg_32, reg_list: [reg.r3, reg.lr])),
		test_case(0xf5a33a80, //  sub.w	sl, r3, #65536	@ 0x10000
				  instr_32(op: opcode.sub_imm_32, rd: reg.r10, rn: reg.r3, imm: 65536)),
		test_case(0xf008ff15, 
				  instr_32(op: opcode.bl_32, offset: 36394)),
		test_case(0xf009f8a6, 
				  instr_32(op: opcode.bl_32, offset: 37196)),
		test_case(0xf003030c, // and.w	r3, r3, #12
				  instr_32(op: opcode.and_imm_32, rd: reg.r3, rn: reg.r3, imm: 12)),
		test_case(0xfbb2f3f3, // udiv	r3, r2, r3
				  instr_32(op: opcode.udiv_32, rd: reg.r3, rn: reg.r2, rm: reg.r3)),
		test_case(0xf3c20208, // ubfx	r2, r2, #0, #9
				  instr_32(op: opcode.ubfx_32, rd: reg.r2, rn: reg.r2, ls_bit: 0, width: 9)),
		test_case(0xfb02f303, // mul.w	r3, r2, r3
			      instr_32(op: opcode.mul_32, rd: reg.r3, rn: reg.r2, rm: reg.r3)),
		test_case(0xfa22f303, // lsr.w	r3, r2, r3
				  instr_32(op: opcode.lsr_reg_32, rd: reg.r3, rn: reg.r2, rm: reg.r3)),
		test_case(0xf4434380, // orr.w	r3, r3, #16384	@ 0x4000
				  instr_32(op: opcode.orr_32, rd: reg.r3, rn: reg.r3, imm: 16384)),
		// 1111 0100 0100 0011 0100 0011 1000 0000
		test_case(0xf1070314, // add.w	r3, r7, #20
				  instr_32(op: opcode.add_32, rd: reg.r3, rn: reg.r7, imm: 20)),
		test_case(0xf0230310, // bic.w	r3, r3, #16
				  // 1111 0000 0010 0011 0000 0011 0001 0000
				  instr_32(op: opcode.bic_imm_32, rd: reg.r3, rn: reg.r3, imm: 16)),
		test_case(0xf64f03ff, // movw	r3, #63743	@ 0xf8ff
				  instr_32(op: opcode.mov_16_imm_32, rd: reg.r3, imm: 63743)),
		// 1111 0110 0100 1111 000 0011 1111 1111
		test_case(0xf9973007, // ldrsb.w	r3, [r7, #7]
				  instr_32(op: opcode.ldrsb_imm_32_t1, rt: reg.r3, rn: reg.r7, imm: 7)),
		// 1111 1001 1001 0111 0011 0000 0000 0111
		test_case(0xf8412023, // str.w	r2, [r1, r3, lsl #2]
				  instr_32(op: opcode.str_reg_32, rt: reg.r2, rn: reg.r1, rm: reg.r3, imm: 2)),
		// 1111 1000 0100 0001 0010 0000 0010 0011
		test_case(0xf3bf8f4f, 
				  instr_32(op: opcode.dsb_32)),
		// 1111 0011 1011 1111 1000 1111 0100 1111
		test_case(0xf1c30307, // rsb	r3, r3, #7
				  instr_32(op: opcode.rsb_32, rd: reg.r3, rn: reg.r3, imm: 7)),
		test_case(0xfba22303, // umull	r2, r3, r2, r3
				  instr_32(op: opcode.umull_32, rd_lo: reg.r2, rd_hi: reg.r3, rn: reg.r2, rm: reg.r3)),
		// 1111 1011 1010 0010 0010 0011 0000 0011
		test_case(0xe9c72300, // strd	r2, r3, [r7]
				  instr_32(op: opcode.strd_32, add: true, rt: reg.r2, rt_2: reg.r3, rn: reg.r7, imm: 0)),
		// 1110 1001 1100 0111 0010 0011 0000 0000
		//		  instr_32(op: opcode.strd_32)),
		test_case(0xf67fae90, // bls.w	8004360
				  instr_32(op: opcode.b_32, cond: condition.ls, offset: -736)),
		// 1111 0110 0111 1111 1010 1110 1001 0000
		test_case(0xe92d4fb0, // stmdb	sp!, {r4, r5, r7, r8, r9, sl, fp, lr}
				  instr_32(op: opcode.push_mult_reg_32, reg_list: [reg.r4, reg.r5, reg.r7, reg.r8, reg.r9, reg.r10, reg.r11, reg.lr])),
		// 1110 1001 0010 1101 0100 1111 1011 0000
		test_case(0xea4161d2, // orr.w	r1, r1, r2, lsr #27
				  instr_32(op: opcode.orr_reg_32, rd: reg.r1, rn: reg.r1, rm: reg.r2, shift_t: shift_type.lsr, shift_n: 27)),
		test_case(0xebb2080a, // subs.w	r8, r2, sl
				  instr_32(op: opcode.subs_32, rd: reg.r8, rn: reg.r2, rm: reg.r10, shift_t: shift_type.lsl, shift_n: 0)),
		// 1110 1011 1011 0010 0000 1000 0000 1010
		test_case(0xeb63090b, // sbc.w	r9, r3, fp
			      instr_32(op: opcode.sbc_32, rd: reg.r9, rn: reg.r3, rm: reg.r11, shift_t: shift_type.lsl, shift_n: 0)),
		test_case(0xeb45030b, // adc.w	r3, r5, fp
				  instr_32(op: opcode.adc_32, rd: reg.r3, rn: reg.r5, rm: reg.r11, shift_t: shift_type.lsl, shift_n: 0)),
		test_case(0xf06f0240, // mvn.w	r2, #64	@ 0x40 
				  instr_32(op: opcode.bit_not_32, rd: reg.r2, imm: 64)),
		// 1111 0000 0110 1111 0000 0010 0100 0000
		test_case(0xe8533f00, // ldrex	r3, [r3]
				  instr_32(op: opcode.ld_rex, rt: reg.r3, rn: reg.r3)),
		// 1110 1000 0101 0011 0011 1111 0000 0000
		test_case(0xe8412300, // strex	r3, r2, [r1]
				  instr_32(op: opcode.str_rex, rd: reg.r3, rt: reg.r2, rn: reg.r1)),
		test_case(0xfb0e7711, // mls	r7, lr, r1, r7
				  instr_32(op: opcode.mls_32, rd: reg.r7, rn: reg.lr, rm: reg.r1, ra: reg.r7)),
		test_case(0xf9b4500c, // ldrsh.w	r5, [r4, #12]
				  instr_32(op: opcode.ldh_32, rt: reg.r5, rn: reg.r4, imm: 12)),
		// 1111 1001 1011 0100 0101 0000 0000 1100
		test_case(0xea1c0f0e, // tst.w	ip, lr
				  instr_32(op: opcode.tst_32, rn: reg.r12, rm: reg.lr, shift_t: shift_type.lsl)),
		// 1110 1010 0001 1100 0000 1111 0000 1110
		test_case(0xea010808, // and.w	r8, r1, r8 
				  instr_32(op: opcode.and_reg_32, rd: reg.r8, rn: reg.r1, rm: reg.r8)),
		// 1110 1010 0000 0001 0000 1000 0000 1000
		test_case(0xea23030c, // bic.w	r3, r3, ip
				  instr_32(op: opcode.bic_reg_32, rd: reg.r3, rn: reg.r3, rm: reg.r12)),
		test_case(0xf7ffbfbb, // b.w	8009c5c <_fclose_r>
				  instr_32(op: opcode.b_uncond_32, offset: -138)),
		test_case(0xf8dfd034, // ldr.w	sp, [pc, #52]
				  instr_32(op: opcode.ldr_lit_32, rt: reg.sp, imm: 52, add: true))
	];//

	foreach (t; tests) {
		assert(
		    decode_instr(t.instr) == t.expected,
		    format("Failed for instruction 0x%08X", t.instr)
		);
    }
}

// ==============
//  Executre ADD
// ==============

void execute_add_32_reg(instr_32 instr, ref cortex_m_cpu cpu) {
	// instr_32(op: opcode.add_32_reg, rd: reg.r1, rn: reg.r1, rm: reg.r3, shift_t: shift_type.asr, shift_n: 2),
	int shifted = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	int rn = cpu.get(instr.rn);
	int res = rn + shifted;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// =============
//  Executre BL
// =============

/*
	Branch with Link (immediate) calls a subroutine at a PC-relative address.
*/
void execute_bl_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int pc = cpu.get(reg.pc);
	int res = ((pc + 4) | 0b1);
	cpu.set(reg.lr, res);
	cpu.set(reg.pc, pc + instr.offset + 4);
}

// ============
//  Executre B
// ============

/*
	Branch with Link (immediate) calls a subroutine at a PC-relative address.
*/
void execute_b_32(instr_32 instr, ref cortex_m_cpu cpu) {
	if (condition_is_met(instr.cond, cpu)) {
		int pc = cpu.get(reg.pc);
		pc += instr.offset + 4;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(4);
	}
}

void execute_b_uncond_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int pc = cpu.get(reg.pc);
	pc += instr.offset + 4;
	cpu.set(reg.pc, pc);
}

// ==============
//  Executre NOP
// ==============

void execute_nop_32(instr_32 instr, ref cortex_m_cpu cpu) {
	cpu.increment_pc(4);
}

// =======================
//  Executre POP MULT REG
// =======================

void execute_pop_mult_reg_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	import std.algorithm : sort;
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	foreach (r; regs) {
		int val = mem.pop(cpu);
		cpu.set(r, val);
	}
	if (regs.back == reg.pc) {
		uint pc = cpu.get(reg.pc);
		pc &= ~0b1;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(4);
	}
}

// ==================
//  Executre SUB IMM
// ==================

void execute_sub_imm_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn - instr.imm;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==================
//  Executre AND IMM
// ==================

void execute_and_imm_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn & instr.imm;
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res < 0);
		cpu.z = (res == 0);
	}
	cpu.increment_pc(4);
}

// ===============
//  Executre UDIV
// ===============

void execute_udiv_32(instr_32 instr, ref cortex_m_cpu cpu) {
	if (cpu.get(instr.rm) == 0) {
		cpu.set(instr.rd, 0);
		cpu.increment_pc(4);
		return;
	}
	uint res = cpu.get(instr.rn) / cpu.get(instr.rm);
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ===============
//  Executre UBFX
// ===============

void execute_ubfx_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int ms_bit = instr.ls_bit + (instr.width - 1);
	int rn = cpu.get(instr.rn);
	if (ms_bit < 32) {
		int res = (rn >> instr.ls_bit) & ((1 << instr.width) - 1);
		cpu.set(instr.rd, res);
	}
	cpu.increment_pc(4);
}

// ==============
//  Executre MUL
// ==============

void execute_mul_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int op1 = cpu.get(instr.rn);
	int op2 = cpu.get(instr.rm);
	int res = op1 * op2;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Executre LSL
// ==============

void execute_lsl_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int rm = cpu.get(instr.rm);
	int res = (rn << rm);
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Executre LSR
// ==============

void execute_lsr_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int rm = cpu.get(instr.rm);
	int res = (rn >> rm);
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res > 0);
		cpu.z = (res == 0);
	}
	cpu.increment_pc(4);
}

// =============
//  Execute ORR
// =============

void execute_orr_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn | instr.imm;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Executre ADD
// ==============

void execute_add_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn + instr.imm;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// =======================
//  Execute BIC(Register)
// =======================

void execute_bic_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(instr.rm);
	int rn = cpu.get(instr.rn);
	int shifted = shift(instr.shift_t, instr.shift_n, rm);
	int res = rn & ~shifted;
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res < 0);
		cpu.z = (res == 0);
	}
	cpu.increment_pc(4);
}

// ========================
//  Execute BIC(Immediate)
// ========================

void execute_bic_imm_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn & ~instr.imm;
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res < 0);
		cpu.z = (res == 0);
	}
	cpu.increment_pc(4);
}

// ==============
//  Executre MOV
// ==============

void execute_mov_16_imm_32(instr_32 instr, ref cortex_m_cpu cpu) {
	cpu.set(instr.rd, instr.imm);
	cpu.increment_pc(4);
}

// ================
//  Executre LDRSB
// ================

void execute_ldrsb_imm_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	size_t addr = cpu.get(instr.rn) + instr.imm;
	byte val = cast(byte)mem.read_byte(addr);
	cpu.set(instr.rt, cast(int)val);	
	cpu.increment_pc(4);
}

// =======================
//  Execute STR(Register)
// =======================

void execute_str_reg_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	int offset = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	auto f = load_store_log();
	size_t addr = cpu.get(instr.rn) + offset;
	int data = cpu.get(instr.rt);
	f.writeln(format("Attempting to access [%08X]", addr));
	mem.write_word(addr, data);
	f.writeln(format("%08X: %08X stored to [%08X]", cpu.pc, data, addr));
	f.flush();
	cpu.increment_pc(4);
}

// ========================
//  Execute RSB(Immediate)
// ========================

void execute_rsb_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int res = instr.imm - cpu.get(instr.rn);
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ===============
//  Execute UMULL
// ===============

void execute_umull_32(instr_32 instr, ref cortex_m_cpu cpu) {
	ulong res =
        cast(ulong)(cast(uint)cpu.get(instr.rn)) *
        cast(ulong)(cast(uint)cpu.get(instr.rm));

    cpu.set(instr.rd_lo, cast(uint)res);
    cpu.set(instr.rd_hi, cast(uint)(res >> 32));

    cpu.increment_pc(4);
}

// =========================
//  Execute STRD(Immediate)
// =========================

void execute_strd_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	uint offset;
	if (instr.add) {
		offset = cpu.get(instr.rn) + instr.imm;
	} else {
		offset = cpu.get(instr.rn) - instr.imm;
	}
	mem.write_word(offset, cpu.get(instr.rt));
	mem.write_word(offset + 4, cpu.get(instr.rt_2));
	if (instr.wback) {
		cpu.set(instr.rn, offset);
	}
	cpu.increment_pc(4);
}

// ========================
//  Executre PUSH MULT REG
// ========================

void execute_push_mult_reg_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	import std.algorithm : sort;
	auto regs = instr.reg_list.dup;
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	f.writeln(format("Pushing to stack at [%08X]", cpu.pc));
	foreach (r; regs) {
		f.writeln(format("%s: [%08X]", r.to!string, cpu.get(r)));
		f.flush();
		mem.push(cpu, cpu.get(r));
	}
	cpu.increment_pc(4);
}

// ========================
//  Executre ORR(Register)
// ========================

void execute_orr_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int shifted = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	int res = cpu.get(instr.rn) | shifted;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Executre SUB
// ==============

void execute_subs_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int shifted = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	int res = cpu.get(instr.rn) - shifted;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Executre SBC
// ==============

void execute_sbc_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int shifted = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	int res = cpu.get(instr.rn) - shifted - cast(uint)(cpu.c);
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Executre ADC
// ==============

void execute_adc_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int shifted = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	int res = cpu.get(instr.rn) + shifted + cast(uint)(cpu.c);
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// =====================
//  Executre BIT OR NOT
// =====================

void execute_bit_or_not_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(instr.rn);
	int res = rn | (~instr.imm);
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res == 0);
		cpu.z = (res < 0);
	}
	cpu.increment_pc(4);
}

void execute_bit_not_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int res = ~instr.imm;
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res == 0);
		cpu.z = (res < 0);
	}
	cpu.increment_pc(4);
}

// ===============
//  Execute LDREX
// ===============

void execute_ldrex(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	uint addr = cpu.get(instr.rn);
	addr += instr.imm;
	int val = mem.read_word(addr);
	cpu.set(instr.rt, val);
}

// ===============
//  Execute STREX
// ===============

void execute_strex(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	size_t addr = cpu.get(instr.rn);
	addr += instr.imm;
	mem.write_word(addr, cpu.get(instr.rt));
	cpu.set(instr.rd, 0xffffffff);
	cpu.increment_pc(4);
}

// ========================
//  Execute STR(Immediate)
// ========================

void execute_str_imm_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	size_t offset_addr; 
	uint rn = cpu.get(instr.rn);
	auto f = load_store_log();
	if (instr.add) {
		offset_addr = rn + instr.imm;
	} else {
		offset_addr = rn - instr.imm;
	}
	size_t addr = instr.index ? offset_addr : rn;
	int data = cpu.get(instr.rt);
	f.writeln(format("Attempting to access [%08X]", addr));
	mem.write_word(addr, data);
	f.writeln(format("%08X: %08X stored to [%08X]", cpu.pc, data, addr));
	f.flush();
	if (instr.wback) {
		cpu.set(instr.rn, cast(uint)offset_addr);
	}
	cpu.increment_pc(4);
}

// =========================
//  Execute STRB(Immediate)
// =========================

void execute_strb_imm_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rn = cpu.get(instr.rn);
	size_t offset_addr;
	if (instr.add) {
		offset_addr = rn + instr.imm;
	} else {
		offset_addr = rn - instr.imm;
	}
	size_t addr = instr.index ? offset_addr : rn;
	auto f = load_store_log();
	int data = cpu.get(instr.rt);
	data = (data & 0xff);
	f.writeln(format("Attempting to access [%08X]", addr));
	mem.write_byte(addr, data);
	f.writeln(format("%08X: %08X stored to [%08X]", cpu.pc, data, addr));
	f.flush();
	if (instr.wback) {
		cpu.set(instr.rn, cast(uint)offset_addr);
	}
	cpu.increment_pc(4);
}

// =============
//  Execute MLS
// =============

void execute_mls_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int op1 = cpu.get(instr.rn);
	int op2 = cpu.get(instr.rm);
	int addend = cpu.get(instr.ra);
	int res = addend - op1 * op2;
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ==============
//  Execute LDRH
// ==============

void execute_ldrh_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	size_t addr = cpu.get(instr.rn);
	addr += instr.imm;
	ushort val = mem.read_half_word(addr);
	int target = cpu.get(instr.rt);
	int res = (target << 16) | val;
	cpu.set(instr.rt, res);
	cpu.increment_pc(4);
}

// =============
//  Execute TST
// =============

void execute_tst_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int shifted = shift(instr.shift_t, instr.shift_n, cpu.get(instr.rm));
	int res = cpu.get(instr.rn) & shifted;
	cpu.n = (res < 0);
	cpu.z = (res == 0);
	cpu.increment_pc(4);
}

// =======================
//  Execute AND(Register)
// =======================

void execute_and_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int res = cpu.get(instr.rn) & cpu.get(instr.rm);
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}

// ======================
//  Execute LDR(Literal)
// ======================

void execute_ldr_lit_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	size_t addr;
	uint pc = cpu.get(reg.pc);
	pc = ((pc + 4) & ~3);
	if (instr.add) {
		addr = pc + instr.imm;
	} else {
		addr = pc - instr.imm;
	}
	f.writeln(format("Attempting to access [%08X]", addr));
	uint data = mem.read_word(addr);
	cpu.set(instr.rt, data);
	int pc_val = cpu.get(reg.pc);
	cpu.set(reg.pc, pc_val + 4);
	f.writeln(format("%08X loaded from [%08X]", data, addr));
	f.flush();
}

// =========================
//  Execute LDRD(Immediate)
// =========================

void execute_ldrd_imm_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint rn = cpu.get(instr.rn);
	size_t offset_addr;
	if (instr.add) {
	 	offset_addr = rn + instr.imm;
	} else {
		offset_addr = rn - instr.imm;
	}
	size_t addr = instr.index ? offset_addr : rn;
	f.writeln(format("Attempting to access [%08X]", addr));
	uint data1 = mem.read_word(addr);
	uint data2 = mem.read_word(addr+4);
	f.writeln(format("%08X and %08X loaded from [%08X] and [%08X]", data1, data2, addr, addr + 4));
	f.flush();
	cpu.set(instr.rt, data1);
	cpu.set(instr.rt_2, data2);
	if (instr.wback) {
		cpu.set(instr.rn, cast(uint)offset_addr);
	}
	cpu.increment_pc(4);
}

// =======================
//  Execute LDR(Register)
// =======================

void execute_ldr_reg_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint rn = cpu.get(instr.rn);
	uint rm = cpu.get(instr.rm);
	int shifted = shift(instr.shift_t, instr.shift_n, rm);
	size_t addr = rn + shifted;
	f.writeln(format("Attempting to access [%08X]", addr));
	uint data = mem.read_word(addr);
	f.writeln(format("%08X loaded from [%08X]", data, addr));
	f.flush();
	cpu.set(instr.rt, data);
	cpu.increment_pc(4);
}

void execute_ldrb_imm_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint rn = cpu.get(instr.rn);
	size_t offset_addr;
	if (instr.add) {
		offset_addr = rn + instr.imm;
	} else {
		offset_addr = rn - instr.imm;
	}
	size_t addr = instr.index ? offset_addr : rn;
	f.writeln(format("Attempting to access [%08X]", addr));
	ubyte data = mem.read_byte(addr);
	f.writeln(format("%08X loaded from [%08X]", data, addr));
	f.flush();
	cpu.set(instr.rt, cast(uint)data);
	if (instr.wback) {
		cpu.set(instr.rn, cast(uint)offset_addr);
	}
	cpu.increment_pc(4);
}

// ========================
//  Execute MOV(Immediate)
// ========================

void execute_mov_32(instr_32 instr, ref cortex_m_cpu cpu) {
	int shifted = shift(shift_type.asr, instr.shift_n, cpu.get(instr.rm));
	cpu.set(instr.rd, shifted);
	cpu.increment_pc(4);
}

void execute_mrs_32(instr_32 instr, ref cortex_m_cpu cpu) {
	switch (instr.spec_reg) {
		case special_reg.BASEPRI:
			cpu.set(instr.rd, cast(uint)cpu.basepri);
			break;
		case special_reg.IPSR:
			cpu.set(instr.rd, cast(uint)cpu.current_exception & 0x1ff);
			break;
		case special_reg.CONTROL:
			uint val = 0;
			if (cpu.sp_sel) {
        		val |= 0x2; 
			}
			cpu.set(instr.rd, val);
			break;
		default:
			return;
	}
	cpu.increment_pc(4);
}

void execute_msr_32(instr_32 instr, ref cortex_m_cpu cpu) {
	uint rn = cpu.get(instr.rn);
	switch (instr.spec_reg) {
		case special_reg.BASEPRI:
			cpu.basepri = cast(ubyte)(rn & 0xff);
			break;
		case special_reg.MSP:
			cpu.msp = rn;
			break;
		case special_reg.PSP:
			cpu.psp = rn;
			break;
		case special_reg.CONTROL:
			cpu.sp_sel = (rn & 0x2) != 0;
			break;
		case special_reg.BASEPRI_MAX:
		    ubyte new_val = cast(ubyte)(rn & 0xff);
    		if (new_val < cpu.basepri || cpu.basepri == 0) {
        		cpu.basepri = new_val;
    		}
    		break;
		default:
			return;
	}
	cpu.increment_pc(4);
}

// ========================
//  Execute MOV(Immediate)
// ========================

void execute_mov_imm_32_t2(instr_32 instr, ref cortex_m_cpu cpu) {
	cpu.set(instr.rd, instr.imm);
	cpu.increment_pc(4);
}

// ========================
//  Execute LDR(Immediate)
// ========================

void execute_ldr_imm_32(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint rn = cpu.get(instr.rn);
	size_t offset_addr = rn;
	if (instr.add) {
		offset_addr += instr.imm;
	} else {
		offset_addr -= instr.imm;
	}
	size_t addr = instr.index ? offset_addr : rn;
	f.writeln(format("Attempting to access [%08X]", addr));
	int data = mem.read_word(addr);
	f.writeln(format("%08X loaded from [%08X]", data, addr));
	f.flush();
	if (instr.wback) {
		cpu.set(instr.rn, cast(uint)offset_addr);
	}
	cpu.set(instr.rt, data);
	cpu.increment_pc(4);
}

// ========================
//  Execute CMP(Immediate)
// ========================

void execute_cmp_imm_32(instr_32 instr, ref cortex_m_cpu cpu) {
	uint rn = cpu.get(instr.rn);
	int res = rn - instr.imm;
	cpu.z = (res == 0);
	cpu.n = (res < 0);
	cpu.c = (rn >= instr.imm);
	cpu.v = (rn < 0 && res > 0);
	cpu.increment_pc(4);
}

// ================
//  Executre Instr
// ================

void execute_instr(instr_32 instr, ref cortex_m_cpu cpu) {
	if (!cpu.it_block_stack.empty) {
		condition active_cond = cpu.it_block_stack.back;
		cpu.it_block_stack.removeBack();
		if (!condition_is_met(active_cond, cpu)) {
			cpu.increment_pc(4);
			return;
		}
	}

	switch (instr.op) {
		case opcode.add_32_reg:
			return execute_add_32_reg(instr, cpu);
		case opcode.b_32:
			return execute_b_32(instr, cpu);
		case opcode.b_uncond_32:
			return execute_b_uncond_32(instr, cpu);
		case opcode.bl_32:
			return execute_bl_32(instr, cpu);
		case opcode.nop_32:
		case opcode.dsb_32:
		case opcode.isb_32:
		case opcode.pld_32:
		case opcode.pld_reg_32:
		case opcode.pld_imm_32:
		case opcode.dmb_32:
			return execute_nop_32(instr, cpu);
		case opcode.sub_imm_32:
			return execute_sub_imm_32(instr, cpu);
		case opcode.and_imm_32:
			return execute_and_imm_32(instr, cpu);
		case opcode.udiv_32:
			return execute_udiv_32(instr, cpu);
		case opcode.ubfx_32:
			return execute_ubfx_32(instr, cpu);
		case opcode.mul_32:
			return execute_mul_32(instr, cpu);
		case opcode.lsl_reg_32:
			return execute_lsl_reg_32(instr, cpu);
		case opcode.lsr_reg_32:
			return execute_lsr_reg_32(instr, cpu);
		case opcode.orr_32:
			return execute_orr_32(instr, cpu);
		case opcode.add_32:
			return execute_add_32(instr, cpu);
		case opcode.bic_imm_32:
			return execute_bic_imm_32(instr, cpu);
		case opcode.bic_reg_32:
			return execute_bic_reg_32(instr, cpu);
		case opcode.mov_16_imm_32:
			return execute_mov_16_imm_32(instr, cpu);
		case opcode.rsb_32:
			return execute_rsb_32(instr, cpu);
		case opcode.umull_32:
			return execute_umull_32(instr, cpu);
		case opcode.orr_reg_32:
			return execute_orr_reg_32(instr, cpu);
		case opcode.subs_32:
			return execute_subs_32(instr, cpu);
		case opcode.sbc_32:
			return execute_sbc_32(instr, cpu);
		case opcode.adc_32:
			return execute_adc_32(instr, cpu);
		case opcode.bit_or_not_32:
			return execute_bit_or_not_32(instr, cpu);
		case opcode.bit_not_32:
			return execute_bit_not_32(instr, cpu);
		case opcode.mls_32:
			return execute_mls_32(instr, cpu);
		case opcode.tst_32:
			return execute_tst_32(instr, cpu);
		case opcode.and_reg_32:
			return execute_and_reg_32(instr, cpu);
		case opcode.mov_32:
			return execute_mov_32(instr, cpu);
		case opcode.cmp_imm_32:
			return execute_cmp_imm_32(instr, cpu);
		case opcode.mov_imm_32_t2:
			return execute_mov_imm_32_t2(instr, cpu);
		case opcode.mrs_32:
			return execute_mrs_32(instr, cpu);
		case opcode.msr_32:
			return execute_msr_32(instr, cpu);
		default:
			return;
	}
}

// ====================
//  Execute Load Store
// ====================

void execute_load_store(instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	switch (instr.op) {
		case opcode.pop_mult_reg_32:
			return execute_pop_mult_reg_32(instr, cpu, mem);
		case opcode.str_reg_32:
			return execute_str_reg_32(instr, cpu, mem);
		case opcode.strd_32:
		 	return execute_strd_32(instr, cpu, mem);
		case opcode.push_mult_reg_32:
			return execute_push_mult_reg_32(instr, cpu, mem);
		case opcode.ld_rex:
			return execute_ldrex(instr, cpu, mem);
		case opcode.str_rex:
			return execute_strex(instr, cpu, mem);
		case opcode.ldh_32:
			return execute_ldrh_32(instr, cpu, mem);
		case opcode.ldr_lit_32:
			return execute_ldr_lit_32(instr, cpu, mem);
		case opcode.ldr_imm_32_t3:
		case opcode.ldr_imm_32_t4:
			return execute_ldr_imm_32(instr, cpu, mem);
		case opcode.str_imm_32_t3:
		case opcode.str_imm_32_t4:
			return execute_str_imm_32(instr, cpu, mem);
		case opcode.ldrd_imm_32:
			return execute_ldrd_imm_32(instr, cpu, mem);
		case opcode.strb_imm_32_t2:
		case opcode.strb_imm_32_t3:
			return execute_strb_imm_32(instr, cpu, mem);
		case opcode.ldrb_imm_32_t2:
		case opcode.ldrb_imm_32_t3:
			return execute_ldrb_imm_32(instr, cpu, mem);
		case opcode.ldrsb_imm_32_t1:
			return execute_ldrsb_imm_32(instr, cpu, mem);
		case opcode.ldr_reg_32:
			return execute_ldr_reg_32(instr, cpu, mem);
		default:
			return;
	}
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		uint instr_bytes;
		instr_32 instr;
		cortex_m_cpu before;
		cortex_m_cpu expected;
	}

	struct test_case_mem {
		uint instr_bytes;
		instr_32 instr;
		cortex_m_cpu before;
		cortex_m_cpu expected;
		memory mem_before;
		memory mem_after;
	}

	test_case[] tests = [
		test_case(0xeb0101a3, // add.w	r1, r1, r3, asr #2
				  instr_32(op: opcode.add_32_reg, rd: reg.r1, rn: reg.r1, rm: reg.r3, shift_t: shift_type.asr, shift_n: 2),
				  cortex_m_cpu(r1:  0b11, r3: 0b1100), 
				  cortex_m_cpu(pc: 4, r1: 0b110, r3: 0b1100)),
		test_case(0xf7ffffda,
				  instr_32(op: opcode.bl_32, offset: -76),
				  cortex_m_cpu(pc: 0x4f),       // 10110100 // 0100 1110 0x4f
				  cortex_m_cpu(pc: 0x3 + 4, lr: 0x4f + 4)),
		test_case(0xf3af8000, 
				  instr_32(op: opcode.nop_32),
				  cortex_m_cpu(),
				  cortex_m_cpu(pc: 4)),
		test_case(0xf5a33a80, //  sub.w	sl, r3, #65536	@ 0x10000
				  instr_32(op: opcode.sub_imm_32, rd: reg.r10, rn: reg.r3, imm: 65536),
				  cortex_m_cpu(r3: 65537),
				  cortex_m_cpu(pc: 4, r3: 65537, r10: 1)),
		test_case(0xf008ff15, 
				  instr_32(op: opcode.bl_32, offset: 36394),
				  cortex_m_cpu(pc: 1),
				  cortex_m_cpu(pc: 36395 + 4, lr: 1 + 4)),
		test_case(0xf009f8a6, 
				  instr_32(op: opcode.bl_32, offset: 37196),
				  cortex_m_cpu(pc: 1),
				  cortex_m_cpu(pc: 37197 + 4, lr: 1 + 4)),
		test_case(0xf003030c, // and.w	r3, r3, #12
				  instr_32(op: opcode.and_imm_32, rd: reg.r3, rn: reg.r3, imm: 12),
				  cortex_m_cpu(r3: 0b0101), // 0b1100
				  cortex_m_cpu(pc: 4, r3: 0b0100)),
		test_case(0xfbb2f3f3, // udiv	r3, r2, r3
				  instr_32(op: opcode.udiv_32, rd: reg.r3, rn: reg.r2, rm: reg.r3),
				  cortex_m_cpu(r2: 2, r3: 2),
				  cortex_m_cpu(pc: 4, r3: 1, r2: 2)),
		test_case(0xf3c20208, // ubfx	r2, r2, #0, #9
				  instr_32(op: opcode.ubfx_32, rd: reg.r2, rn: reg.r2, ls_bit: 0, width: 9),
				  cortex_m_cpu(r2: 0xffff),
				  cortex_m_cpu(pc: 4, r2: 0x01ff)),
		test_case(0xfb02f303, // mul.w	r3, r2, r3
			      instr_32(op: opcode.mul_32, rd: reg.r3, rn: reg.r2, rm: reg.r3),
			      cortex_m_cpu(r3: 4, r2: 2),
			      cortex_m_cpu(pc: 4, r3: 8, r2: 2)),
		test_case(0xfa22f303, // lsr.w	r3, r2, r3
				  instr_32(op: opcode.lsr_reg_32, rd: reg.r3, rn: reg.r2, rm: reg.r3),
				  cortex_m_cpu(r2: 0b1100, r3: 1),
				  cortex_m_cpu(pc: 4, r2: 0b1100, r3: 0b0110)),
		test_case(0xf4434380, // orr.w	r3, r3, #16384	@ 0x4000
				  instr_32(op: opcode.orr_32, rd: reg.r3, rn: reg.r3, imm: 16384),
				  cortex_m_cpu(r3: 0x0001),
				  cortex_m_cpu(pc: 4, r3: 0x4001)),
		test_case(0xf1070314, // add.w	r3, r7, #20
				  instr_32(op: opcode.add_32, rd: reg.r3, rn: reg.r7, imm: 20),
				  cortex_m_cpu(r7: 10),
				  cortex_m_cpu(pc: 4, r3: 30, r7: 10)),
		test_case(0xf0230310, // bic.w	r3, r3, #16
				  instr_32(op: opcode.bic_imm_32, rd: reg.r3, rn: reg.r3, imm: 16), // 0001 0000
				  cortex_m_cpu(r3: 17),                    
				  cortex_m_cpu(pc: 4, r3: 1)), 
		// f0230310
		// 1111 0000 0010 0011 0000 0011 0001 0000                    
		test_case(0xf64f03ff, // movw	r3, #63743	@ 0xf8ff
				  instr_32(op: opcode.mov_16_imm_32, rd: reg.r3, imm: 63743),
				  cortex_m_cpu(),
				  cortex_m_cpu(pc: 4, r3: 0xf8ff)),
		//test_case(0xf3bf8f4f, 
		//		  instr_32(op: opcode.dsb)),
		test_case(0xf1c30307, // rsb	r3, r3, #7
				  instr_32(op: opcode.rsb_32, rd: reg.r3, rn: reg.r3, imm: 7),
				  cortex_m_cpu(r3: 2),
				  cortex_m_cpu(pc: 4, r3: 5)),
		test_case(0xfba22303, // umull	r2, r3, r2, r3
				  instr_32(op: opcode.umull_32, rd_lo: reg.r2, rd_hi: reg.r3, rn: reg.r2, rm: reg.r3),
				  cortex_m_cpu(r2: 10, r3: 5),
				  cortex_m_cpu(pc: 4, r2: 50, r3: 0)),
		test_case(0xf67fae90, // bls.w	8004360
				  instr_32(op: opcode.b_32, cond: condition.ls, offset: -736),
				  cortex_m_cpu(pc:   740, z: true, c: false),
				  cortex_m_cpu(pc: 4 + 4, z: true, c: false)),
		test_case(0xea4161d2, // orr.w	r1, r1, r2, lsr #27
				  instr_32(op: opcode.orr_reg_32, rd: reg.r1, rn: reg.r1, rm: reg.r2, shift_t: shift_type.lsr, shift_n: 27),
				  cortex_m_cpu(r2: 0x40000000, r1: 2), // 0100
				  cortex_m_cpu(pc: 4, r2: 0x40000000, r1: 10)),
		test_case(0xebb2080a, // subs.w	r8, r2, sl
				  instr_32(op: opcode.subs_32, rd: reg.r8, rn: reg.r2, rm: reg.r10, shift_t: shift_type.lsl, shift_n: 0),
				  cortex_m_cpu(r2: 10, r10: 5),
				  cortex_m_cpu(pc: 4, r8:  5, r2: 10, r10: 5)),
		test_case(0xeb63090b, // sbc.w	r9, r3, fpr10
			      instr_32(op: opcode.sbc_32, rd: reg.r9, rn: reg.r3, rm: reg.r11, shift_t: shift_type.lsl, shift_n: 0),
			      cortex_m_cpu(r3: 10, r11: 5, c: true),
				  cortex_m_cpu(pc: 4, r9:  4, r3: 10, r11: 5, c: true)),
		test_case(0xeb45030b, // adc.w	r3, r5, fp
				  instr_32(op: opcode.adc_32, rd: reg.r3, rn: reg.r5, rm: reg.r11, shift_t: shift_type.lsl, shift_n: 0),
				  cortex_m_cpu(r5:  5, r11: 5, c: true),
				  cortex_m_cpu(pc: 4, r3: 11,  r5: 5, r11: 5, c: true)),
		test_case(0xf06f0240, // mvn.w	r2, #64	@ 0x40 
				  instr_32(op: opcode.bit_or_not_32, rd: reg.r2, imm: 64), 
				  cortex_m_cpu(),
				  cortex_m_cpu(pc: 4, r2: -65)),
		test_case(0xfb0e7711, // mls	r7, lr, r1, r7
				  instr_32(op: opcode.mls_32, rd: reg.r7, rn: reg.lr, rm: reg.r1, ra: reg.r7),
				  cortex_m_cpu(r7: 20, r1: 2, lr: 3),
				  cortex_m_cpu(pc: 4, r7: 14, r1: 2, lr: 3)),
		test_case(0xea1c0f0e, // tst.w	ip, lr
				  instr_32(op: opcode.tst_32, rn: reg.r12, rm: reg.lr, shift_t: shift_type.lsl),
				  cortex_m_cpu(r12: 0b1111, lr: 0b1111),
				  cortex_m_cpu(pc: 4, r12: 0b1111, lr: 0b1111, z: false, n: false)),
		test_case(0xea010808, // and.w	r8, r1, r8 
	     		  instr_32(op: opcode.and_reg_32, rd: reg.r8, rn: reg.r1, rm: reg.r8),
	     		  cortex_m_cpu(r8: 0b1100, r1: 0b0111),
				  cortex_m_cpu(pc: 4, r8: 0b0100, r1: 0b0111)),
		test_case(0xea23030c, // bic.w	r3, r3, ip
				  instr_32(op: opcode.bic_reg_32, rd: reg.r3, rn: reg.r3, rm: reg.r12),
				  cortex_m_cpu(r3: 0b1100, r12: 0b0100),
				  cortex_m_cpu(pc: 4, r3: 0b1000, r12:  0b0100)),
		test_case(0xf7ffbfbb, // b.w	8009c5c <_fclose_r>
				  instr_32(op: opcode.b_uncond_32, offset: -138),
				  cortex_m_cpu(pc:   140),
				  cortex_m_cpu(pc: 2 + 4))
	];

	test_case_mem[] tests_mem = [
		test_case_mem(0xe8bd4008, 
				      instr_32(op: opcode.pop_mult_reg_32, reg_list: [reg.r3, reg.lr]),
				      cortex_m_cpu(msp: memory.stack_base - 8),
				      cortex_m_cpu(pc: 4, msp: memory.stack_base, r3: 0xffffffee, lr: 0xffffffff),
				      memory(ram: make_ram_with([memory.stack_base-4, memory.stack_base-8],
				      	 						[0xffffffff, 0xffffffee])),
				      memory()),


		/*
		test_case_mem(0xf9973007, // ldrsb.w	r3, [r7, #7]
				      instr_32(op: opcode.ldrsb_32, rt: reg.r3, rn: reg.r7, imm: 7),
				      cortex_m_cpu(r7: 3),
				      cortex_m_cpu(r3: 0xee, r7: 3),
				      memory(ram: make_ram_with(10, 0xffffffee)),
				      memory(ram: make_ram_with(10, 0xffffffee))),
		test_case_mem(0xf8412023, // str.w	r2, [r1, r3, lsl #2]
				      instr_32(op: opcode.str_reg_32, rt: reg.r2, rn: reg.r1, rm: reg.r3, shift_t: shift_type.lsl, shift_n: 2),
					  cortex_m_cpu(r2: 0xffffffee, r1: 10, r3: 4),
				      cortex_m_cpu(r2: 0xffffffee, r1: 10, r3: 4),
				      memory(),
				      memory(ram: make_ram_with(26, 0xffffffee))),
		test_case_mem(0xe9c72300, // strd	r2, r3, [r7]
				      instr_32(op: opcode.strd_32, rt: reg.r2, rt_2: reg.r3, rn: reg.r7, imm: 0),
				      cortex_m_cpu(r2: 0xffffffee, r3: 0xffffffff, r7: 2),
				      cortex_m_cpu(r2: 0xffffffee, r3: 0xffffffff, r7: 2),
				      memory(),
				      memory(ram: make_ram_with([2,3], [0xffffffee, 0xffffffff]))),
		test_case_mem(0xe92d4fb0, // stmdb	sp!, {r4, r5, r7, r8, r9, sl, fp, lr}
				      instr_32(op: opcode.push_mult_reg_32, reg_list: [reg.r4, reg.r5, reg.r7, reg.r8, reg.r9, reg.r10, reg.r11, reg.lr]),
				      cortex_m_cpu(sp: memory.stack_base, r4: 1, r5: 2, r7: 3, r8: 4, r9: 5, r10: 6, r11: 7, lr: 8),
				      cortex_m_cpu(sp: memory.stack_base-8, r4: 1, r5: 2, r7: 3, r8: 4, r9: 5, r10: 6, r11: 7, lr: 8),
				      memory(),
				      memory(ram: make_ram_with([memory.stack_base,memory.stack_base-1,memory.stack_base-2,memory.stack_base-3,
				      						     memory.stack_base-4,memory.stack_base-5,memory.stack_base-6,memory.stack_base-7],
				      						    [1,2,3,4,5,6,7,8]))),
		test_case_mem(0xe8533f00, // ldrex	r3, [r3]
				      instr_32(op: opcode.ld_rex, rt: reg.r3, rn: reg.r3),
				      cortex_m_cpu(r3: 2),
				      cortex_m_cpu(r3: 0xffffffee),
				      memory(ram: make_ram_with(2, 0xffffffee)),
				      memory(ram: make_ram_with(2, 0xffffffee))),
		test_case_mem(0xe8412300, // strex	r3, r2, [r1]
	     		  	  instr_32(op: opcode.str_rex, rd: reg.r3, rt: reg.r2, rn: reg.r1),
					  cortex_m_cpu(r2: 0xffffffee, r1: 2),
				      cortex_m_cpu(r3: 0xffffffff, r2: 0xffffffee, r1: 2),
				      memory(),
				      memory(ram: make_ram_with(2, 0xffffffee))),
		test_case_mem(0xf9b4500c, // ldrsh.w	r5, [r4, #12]
				  	  instr_32(op: opcode.ldh_32, rt: reg.r5, rn: reg.r4, imm: 12),
				  	  cortex_m_cpu(r4: 8),
				      cortex_m_cpu(r5: 2, r4: 8),
				      memory(ram: make_ram_with(20, 2)),
				      memory(ram: make_ram_with(20, 2))),
		test_case_mem(0xf8dfd034, 
				  	  instr_32(op: opcode.ldr_imm_32, rt: reg.sp, rn: reg.pc, imm: 52),
				  	  cortex_m_cpu(pc: 0x800a18c),
				      cortex_m_cpu(pc: 0x800a190, sp: memory.stack_base),
				      memory(),
				      memory())
		*/
	];

	foreach (t; tests) {
		execute_instr(t.instr, t.before);
		assert(
		    t.before == t.expected,
		    format("Failed for instruction 0x%08X", t.instr_bytes)
		);
    }

    foreach (t; tests_mem) {
    	execute_load_store(t.instr, t.before, t.mem_before);
    	assert(
    		t.before == t.expected && t.mem_before == t.mem_after,
    		format("Failed for instruction 0x%04X", t.instr_bytes)
    	);
    }
}

string[opcode] opcode_strings = [
	opcode.adc_reg: "adcs",
	opcode.adc_32: "adc.w",
	opcode.add_32: "add.w",
	opcode.add_32_reg: "add.w",
	opcode.add_imm_3: "adds",
	opcode.add_imm_8: "adds",
	opcode.add_high_reg_1: "add",
	opcode.add_high_reg_2: "add",
	opcode.add_lo_reg: "add",
	opcode.add_reg: "adds",
	opcode.add_sp_t1: "add",
	opcode.add_sp_t2: "add",
	opcode.adr: "add",
	opcode.and_imm_32: "and.w",
	opcode.asr_imm: "asrs",
	opcode.and_reg: "ands",
	opcode.b_32: "b.w",
	opcode.b_cond: "b",
	opcode.b_uncond_32: "b.w",
	opcode.b_imm_11: "b",
	opcode.bic_reg_32: "bic.w",
	opcode.bic_imm_32: "bic.w",
	opcode.bit_not_32: "mvn.w", 
	opcode.bl_32: "bl",
	opcode.blx: "blx",
	opcode.bx: "bx",
	opcode.cmp_br_nz: "cbnz",
	opcode.cmp_br_z: "cbz",
	opcode.cmp_high_1: "cmp",
	opcode.cmp_high_2: "cmp",
	opcode.cmp_imm: "cmp",
	opcode.cmp_imm_32: "cmp",
	opcode.cmp_reg: "cmp",
	opcode.dmb_32: "dmb",
	opcode.dsb_32: "dsb",
	opcode.if_then: "it",
	opcode.isb_32: "isb",
	opcode.ldr_imm: "ldr",
	opcode.ldr_imm_32_t3: "ldr.w",
	opcode.ldr_lit_32: "ldr.w",
	opcode.ldr_pool: "ldr",
	opcode.ldr_imm_32_t4: "ldr.w",
	opcode.ldr_reg: "ldr",
	opcode.ldr_reg_32: "ldr.w",
	opcode.ldr_sp: "ldr",
	opcode.ldrb_imm: "ldrb",
	opcode.ldrb_imm_32_t2: "ldrb.w",
	opcode.ldrb_imm_32_t3: "ldrb.w",
	opcode.ldrb_reg: "ldrb",
	opcode.ldrd_imm_32: "ldrd",
	opcode.ldrh_imm: "ldrh",
	opcode.ldrsb_imm_32_t1: "ldrsb.w",
	opcode.ldrsb_imm_32_t2: "ldrsb.w",
	opcode.lor_reg: "orrs",
	opcode.lsl_reg_32: "lsl.w",
	opcode.lsl_imm: "lsls",
	opcode.lsl_reg: "lsls",
	opcode.lsr_imm: "lsrs",
	opcode.lsr_reg: "lsrs",
	opcode.lsr_reg_32: "lsr.w",
	opcode.mls_32: "mls",
	opcode.mov_32: "mov.w",
	opcode.mov_16_imm_32: "movw",
	opcode.mov_high_1: "mov",
	opcode.mov_high_2: "mov",
	opcode.mov_imm: "movs",
	opcode.mov_imm_32_t2: "mov.w",
	opcode.mov_lo: "mov",
	opcode.msr_32: "msr",
	opcode.mrs_32: "mrs",
	opcode.mvn_reg: "mvns",
	opcode.mul_32: "mul.w",
	opcode.negs: "negs",
	opcode.nop: "nop",
	opcode.nop_32: "nop.w",
	opcode.orr_32: "orr.w",
	opcode.orr_reg_32: "orr.w",
	opcode.pop_mult_reg: "pop",
	opcode.pop_mult_reg_32: "ldmia.w sp!,",
	opcode.push_mult_reg: "push",
	opcode.push_mult_reg_32: "push",
	opcode.rsb_32: "rsb",
	opcode.sbc_32: "sbc.w",
	opcode.str_imm: "str",
	opcode.strb_imm_32_t2: "strb.w",
	opcode.strb_imm_32_t3: "strb.w",
	opcode.str_imm_32_t3: "str.w",
	opcode.str_imm_32_t4: "str.w",
	opcode.strb_imm: "strb",
	opcode.strh_imm: "strh",
	opcode.strd_32: "strd",
	opcode.str_sp: "str",
	opcode.str_reg: "str",
	opcode.str_reg_32: "str.w",
	opcode.sub_imm_3: "subs",
	opcode.sub_imm_8: "subs",
	opcode.sub_imm_32: "sub.w",
	opcode.sub_reg: "subs",
	opcode.subs_32: "sub.w",
	opcode.tst: "tst",
	opcode.sub_sp: "sub",
	opcode.udiv_32: "udiv",
	opcode.umull_32: "umull",
	opcode.ubfx_32: "ubfx",
	opcode.uxtb: "uxtb"
];

string get_register_name(reg r) {
	switch (r) {
		case reg.r10:
			return "sl";
		case reg.r11:
			return "fp";
		case reg.r12:
			return "ip";
		default: 
			return r.to!string;
	}
}

bool is_store(opcode op) {
	switch (op) {
		case opcode.ldr_imm:
		case opcode.ldr_imm_32:
		case opcode.ldr_pool:
		//case opcode.ldr_post_inc:
		case opcode.ldr_reg:
		case opcode.ldr_sp:
		case opcode.ldrb_imm:
		case opcode.ldrb_reg:
		case opcode.ldrb_imm_32_t2:
		case opcode.ldr_imm_32_t3:
		case opcode.ldr_imm_32_t4:
		case opcode.ldrd_imm_32:
		case opcode.ldrh_imm:
		case opcode.ldrsb_imm_32_t1:
		case opcode.ldrsb_imm_32_t2:
		case opcode.pop_mult_reg:
		case opcode.pop_mult_reg_32:
		case opcode.push_mult_reg:
		case opcode.push_mult_reg_32:
		case opcode.str_imm:
		case opcode.str_imm_32_t3:
		case opcode.str_imm_32_t4:
		case opcode.str_sp:
		case opcode.str_reg:
		case opcode.str_reg_32:
		case opcode.strb_imm:
		case opcode.strb_imm_32_t2:
		case opcode.strb_imm_32_t3:
		case opcode.strb_reg:
		case opcode.strd_32:
		case opcode.strh_imm:
		case opcode.ldr_lit_32:
		case opcode.ldr_reg_32:
		case opcode.ldrb_imm_32_t3:
			return true;
		default:
			return false;
	}
}

string convert_to_string(ushort instr) {
	instr_16 parsed_instr = decode_instr(instr);
	string res = opcode_strings.get(parsed_instr.op, "unimplemented");
	if (parsed_instr.op == opcode.b_cond) {
		if (parsed_instr.cond == condition.cc) {
			res ~= "cc";
		}
	}
	string[] ops;
	auto fields = field_map.get(parsed_instr.op, null);
	if (fields is null) {
	    return "unimplemented";
	}
	if (parsed_instr.op == opcode.if_then) {
		ubyte mask = parsed_instr.mask;
		ubyte first_cond = parsed_instr.first_cond;
		ubyte first_cond_mask = cast(ubyte)((first_cond << 4) | mask);
		xyz it_block = get_xyz(first_cond_mask);
		if (it_block != xyz.none) {
			res ~= it_block.to!string;
		}
	}
	res ~= " ";
	foreach (field; field_map[parsed_instr.op]) {
		if (field == "rt") {
			ops ~= get_register_name(parsed_instr.rt);
		}
		if (field == "rn") {
			string rn_s;
			if (is_store(parsed_instr.op)) {
				rn_s ~= "[";
			}
			rn_s ~= get_register_name(parsed_instr.rn);
			ops ~= rn_s;
		}
		if (field == "rd") {
			ops ~= get_register_name(parsed_instr.rd);
		}
		if (field == "condition") {
			condition c = cast(condition)(parsed_instr.first_cond);
			ops ~= c.to!string;
		}
		if (field == "rm") {
			string rm_s;
			rm_s ~= get_register_name(parsed_instr.rm);
			if (is_store(parsed_instr.op)) {
				rm_s ~= "]";
			}
			ops ~= rm_s;
		}
		if (field == "imm") {
			if (parsed_instr.imm == 0 && parsed_instr.op == opcode.add_lo_reg) {
				continue;
			}
			string imm = "#";
			imm ~= parsed_instr.imm.to!string;
			if (parsed_instr.op == opcode.str_sp || is_store(parsed_instr.op)) {
				imm ~= "]";
			}
			ops ~= imm; 
		}
		if (field == "reg_list") {
			auto reg_list_copy = parsed_instr.reg_list;
			if (reg_list_copy.length == 1) {
				string s = "{";
				s ~= get_register_name(reg_list_copy.front);
				s ~= "}";
				ops ~= s;
				continue;
			}
			string first = "{"; 
			first ~= get_register_name(reg_list_copy[0]);
			ops ~= first;
			for (uint i = 1; i < reg_list_copy.length - 1; ++i) {
				ops ~= get_register_name(reg_list_copy[i]);
			}
			string last;
			last ~= get_register_name(reg_list_copy[reg_list_copy.length - 1]);
			last ~= "}";
			ops ~= last; 
		}
		if (field == "sp") {
			if (parsed_instr.op == opcode.str_sp || parsed_instr.op == opcode.ldr_sp) {
				ops ~= "[sp";
			} else {
				ops ~= "sp";
			}
		}
		if (field == "pc") {
			if (parsed_instr.op == opcode.ldr_pool) {
				ops ~= "[pc";
			} else {
				ops ~= "pc";
			}
		}
	}
	res ~= ops.join(", ");
	return res;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		string expected;
	}

	test_case[] tests = [
		test_case(0x2b00, "cmp r3, #0"),
		test_case(0x10b6, "asrs r6, r6, #2"),
		test_case(0x3730, "adds r7, #48"),
		test_case(0x4013, "ands r3, r2"),
		test_case(0x2300, "movs r3, #0"),		
		test_case(0x3902, "subs r1, #2"),
		test_case(0x00d9, "lsls r1, r3, #3"),
		test_case(0x099b, "lsrs r3, r3, #6"),
		test_case(0x4313, "orrs r3, r2"),
		test_case(0x43db, "mvns r3, r3"),
		test_case(0x4283, "cmp r3, r0"),
		test_case(0x1a1b, "subs r3, r3, r0"),
		test_case(0x469d, "mov sp, r3"),		
		test_case(0x460f, "mov r7, r1"),
		test_case(0xaf00, "add r7, sp, #0"),
		test_case(0xb092, "sub sp, #72"),
		test_case(0x1d3b, "adds r3, r7, #4"),
		test_case(0x4413, "add r3, r2"),
		test_case(0x409a, "lsls r2, r3"),
		test_case(0x40da, "lsrs r2, r3"),	
		test_case(0xa201, "add r2, pc, #4"),
		test_case(0x4652, "mov r2, sl"),
		test_case(0x9300, "str r3, [sp, #0]"),
		test_case(0x1891, "adds r1, r2, r2"),
		test_case(0x458c, "cmp ip, r1"),
		test_case(0x4463, "add r3, ip"),		
		test_case(0x1e54, "subs r4, r2, #1"),
		test_case(0x44e6, "add lr, ip"),
		test_case(0x4572, "cmp r2, lr"),
		test_case(0x4241, "negs r1, r0"),
		test_case(0x608b, "str r3, [r1, #8]"),
		test_case(0x80fb, "strh r3, [r7, #6]"),
		test_case(0x88fb, "ldrh r3, [r7, #6]"),
		test_case(0x781a, "ldrb r2, [r3, #0]"),
		test_case(0x701a, "strb r2, [r3, #0]"),
		test_case(0x68fb, "ldr r3, [r7, #12]"),
		test_case(0x4803, "ldr r0, [pc, #12]"),
		test_case(0xb510, "push {r4, lr}"),
		test_case(0xbd10, "pop {r4, pc}"),
		test_case(0x5cd3, "ldrb r3, [r2, r3]"),
		test_case(0x58fb, "ldr r3, [r7, r3]"),
		test_case(0x50c4, "str r4, [r0, r3]"),
		test_case(0xb2db, "uxtb r3, r3"),
		test_case(0x415b, "adcs r3, r3"),
		test_case(0xbf08, "it eq"),
		test_case(0xbf1c, "itt ne"),
		test_case(0x9d08, "ldr r5, [sp, #32]"),
		test_case(0xb083, "sub sp, #12"),
		test_case(0xb0c0, "sub sp, #256"),
		test_case(0xb580, "push {r7, lr}"),
		test_case(0xb082, "sub sp, #8"),
		test_case(0xaf00, "add r7, sp, #0"),
		test_case(0x6078, "str r0, [r7, #4]"),
		test_case(0x687b, "ldr r3, [r7, #4]"),
		test_case(0x2b00, "cmp r3, #0"),
		test_case(0x2301, "movs r3, #1"),
		test_case(0x687b, "ldr r3, [r7, #4]"),
		test_case(0x9301, "str r3, [sp, #4]"),
        test_case(0xb480, "push {r7}"),
        test_case(0xb083, "sub sp, #12"),
        test_case(0xaf00, "add r7, sp, #0"),
        test_case(0x2300, "movs r3, #0"),
        test_case(0x607b, "str r3, [r7, #4]"),
        test_case(0x4b0f, "ldr r3, [pc, #60]"),
        test_case(0x6c5b, "ldr r3, [r3, #68]"),
        test_case(0x4a0e, "ldr r2, [pc, #56]"),
        test_case(0x6453, "str r3, [r2, #68]"),
        test_case(0x4b0c, "ldr r3, [pc, #48]"),
        test_case(0x6c5b, "ldr r3, [r3, #68]"),
        test_case(0x607b, "str r3, [r7, #4]"),
        test_case(0x687b, "ldr r3, [r7, #4]"),
        test_case(0x2300, "movs r3, #0"),
        test_case(0x603b, "str r3, [r7, #0]"),
        test_case(0x4b08, "ldr r3, [pc, #32]"),
        test_case(0x6c1b, "ldr r3, [r3, #64]"),
        test_case(0x4a07, "ldr r2, [pc, #28]"),
        test_case(0x6413, "str r3, [r2, #64]"),
        test_case(0x4b05, "ldr r3, [pc, #20]"),
        test_case(0x6c1b, "ldr r3, [r3, #64]"),
        test_case(0x603b, "str r3, [r7, #0]"),
        test_case(0x683b, "ldr r3, [r7, #0]"),
        test_case(0x370c, "adds r7, #12"),
        test_case(0x46bd, "mov sp, r7"),
        test_case(0xbc80, "pop {r7}")
	];

	foreach (t; tests) {
		string actual = convert_to_string(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction [0x%04X], got '%s'", t.instr, actual)
		);
    }
}

string get_function_str(string file_name, string function_name) {
	File file;
	try {
		file = File(file_name, "r");
	} catch (Exception e) {
		writeln("Error opening file: ", e.msg);
		return "";
	}
    auto lines = file.byLineCopy.array;
    ptrdiff_t start = -1;
    foreach (i, line; lines) {
    	string to_find = format("<%s>", function_name);
        if (line.canFind(to_find) && line.front == '0') {
            start = i;
            break;
        }
    }
    if (start == -1) {
        return "";
    }
    ptrdiff_t end = start + 1;
    while (end < lines.length && lines[end].strip.length > 0) {
        ++end;
    }
    return lines[start .. end].join("\n");
}

immutable reset_handler =
    "0800a18c <Reset_Handler>:\n"
  ~ " 800a18c:	f8df d034 	ldr.w	sp, [pc, #52]	@ 800a1c4 <LoopFillZerobss+0xe>\n"
  ~ " 800a190:	f7f6 f89c 	bl	80002cc <SystemInit>\n"
  ~ " 800a194:	480c      	ldr	r0, [pc, #48]	@ (800a1c8 <LoopFillZerobss+0x12>)\n"
  ~ " 800a196:	490d      	ldr	r1, [pc, #52]	@ (800a1cc <LoopFillZerobss+0x16>)\n"
  ~ " 800a198:	4a0d      	ldr	r2, [pc, #52]	@ (800a1d0 <LoopFillZerobss+0x1a>)\n"
  ~ " 800a19a:	2300      	movs	r3, #0\n"
  ~ " 800a19c:	e002      	b.n	800a1a4 <LoopCopyDataInit>";

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	string actual = get_function_str("../test/cortex_m_asm.txt", "Reset_Handler");
	auto bytesExpected = cast(ubyte[]) reset_handler;
	auto bytesGot = cast(ubyte[]) actual;
	writeln(bytesExpected);
	writeln(bytesGot);
	assert(actual == reset_handler,
		   format("Failed, got '%s'", actual));
}

alias instruction = Algebraic!(instr_16, instr_32);

struct addr_instr {
	instruction i;
	uint _in_32;
	ushort _in_16;
	uint _addr;
	string _instr_bytes;

	this(uint addr, string bytes_string) {
		_instr_bytes = bytes_string;
		_addr = addr;
		if (bytes_string.length == 8) {
			_in_32 = parse!uint(bytes_string, 16);
			i = decode_instr(_in_32);
		}
		if (bytes_string.length == 4) {
			_in_16 = cast(ushort) parse!uint(bytes_string, 16);
			i = decode_instr(_in_16);
		}
	}
}

struct func {
	string name;
	addr_instr[] instrs;
}

string extract_angle_brackets(string s) {
    auto start = s.indexOf('<');
    auto end = s.indexOf('>');
    if (start != -1 && end != -1 && end > start) {
        return s[start + 1 .. end];
    }
    return "";
}

func get_function(string file_name, string function_name) {
	string f_s = get_function_str(file_name, function_name);
	auto lines = f_s.splitLines();
    func f;
    f.name = extract_angle_brackets(lines[0]);

    foreach(line; lines[1..$]) {
        line = line.strip();
        if (line.length == 0) continue;
        auto parts = split(line, ":");
        if (parts.length < 2) continue;
        auto addr_str = parts[0].strip();

        string addr_str_clean = addr_str.startsWith("0x") ? addr_str[2..$] : addr_str;
		uint addr = parse!uint(addr_str_clean, 16);

        auto rest = parts[1].strip();
        auto bytes_part = rest.split("\t")[0].replace(" ", "");
        f.instrs ~= addr_instr(addr, bytes_part);        
    }
    return f;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	func actual = get_function("../test/cortex_m_asm.txt", "Reset_Handler");
	func expected = func(name: "Reset_Handler",
		   			     instrs: [addr_instr(0x800a18c, "f8dfd034"),
		   			              addr_instr(0x800a190, "f7f6f89c"),
		   			              addr_instr(0x800a194,     "480c"),
		   			              addr_instr(0x800a196,     "490d"),
		   			              addr_instr(0x800a198,     "4a0d"),
		   			              addr_instr(0x800a19a,     "2300"),
		   			              addr_instr(0x800a19c,	    "e002")]);
	func actual_freertos = get_function("../test/freertos_blink_asm.txt", "Reset_Handler");
	func expected_freertos = func(name: "Reset_Handler",
		   			     instrs: [addr_instr(0x8017ce4, "f8dfd034"),
		   			              addr_instr(0x8017ce8, "f7e8fad8"),
		   			              addr_instr(0x8017cec,     "480c"),
		   			              addr_instr(0x8017cee,     "490d"),
		   			              addr_instr(0x8017cf0,     "4a0d"),
		   			              addr_instr(0x8017cf2,     "2300"),
		   			              addr_instr(0x8017cf4,	    "e002")]);
	assert(actual == expected);
	assert(actual_freertos == expected_freertos);
}

// ======================
//  Get Entry Point Addr
// ======================

uint get_entry_point_addr(string filename) {
	if (filename == "../test/zephyr_led_asm.txt") {
		auto reset_handler = get_function(filename, "__start");
		return reset_handler.instrs[0]._addr;
	} else {
		auto reset_handler = get_function(filename, "Reset_Handler");
		return reset_handler.instrs[0]._addr;
	}
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	uint actual = get_entry_point_addr("../test/cortex_m_asm.txt");
	assert(actual == 0x800a18c);
	uint actual_freertos = get_entry_point_addr("../test/freertos_blink_asm.txt");
	assert(actual_freertos == 0x8017ce4);
}

// =======================
//  Load Init Array Start 
// =======================

void load_init_array_start(ref memory mem, string filename) {
    auto file = File(filename, "r");
    bool foundStart = false;
    uint val;
    size_t addr;

    foreach(line; file.byLine()) {
        line = line.strip();
        if (!foundStart && line.canFind("__init_array_start")) {
            auto parts = line.split(" ");
            addr = parse!uint(parts[0], 16);
            foundStart = true;
        } else if (foundStart) {
            auto parts = line.split(":");
            if (parts.length >= 2) {
                auto hexWords = parts[1].strip().split();
                if (hexWords.length >= 1) {
                    val = parse!uint(hexWords[0], 16);
                    break;
                }
            }
        }
    }
    mem.write_word(addr, val);
    foundStart = false;
    size_t addr_2;
    foreach(line; file.byLine()) {
        line = line.strip();
        if (!foundStart && line.canFind("__frame_dummy_init_array_entry")) {
            auto parts = line.split(" ");
            addr_2 = parse!uint(parts[0], 16);
            foundStart = true;
        } else if (foundStart) {
            auto parts = line.split(":");
            if (parts.length >= 2) {
                auto hexWords = parts[1].strip().split();
                if (hexWords.length >= 1) {
                    val = parse!uint(hexWords[0], 16);
                    break;
                }
            }
        }
    }
    mem.write_word(addr_2, val);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	memory mem;
	load_init_array_start(mem, "../test/cortex_m_asm.txt");
	uint val = mem.read_word(0x800a2dc);
	assert(val == 0x800a1e1, format("Got [0x%04X] instead of 0x800a1e1", val));
}

string convert_to_string(uint instr) {
	instr_32 parsed_instr = decode_instr(instr);
	string res = opcode_strings.get(parsed_instr.op, "unimplemented");
	if (res == "unimplemented opcode string") {
		return res;
	}
	string[] ops;
	auto fields = field_map.get(parsed_instr.op, null);
	if (fields is null) {
	    return "unimplemented tuple";
	}
	res ~= " ";
	foreach (field; fields) {
		if (field == "rt") {
			ops ~= get_register_name(parsed_instr.rt);
		}
		if (field == "rn") {
			string rn_s;
			if (is_store(parsed_instr.op) || parsed_instr.op == opcode.ldr_imm_32_t4) {
				rn_s ~= "[";
			}
			rn_s ~= get_register_name(parsed_instr.rn);
			if (parsed_instr.op == opcode.ldr_imm_32_t4) {
				rn_s ~= "]";
			}
			if ((parsed_instr.op == opcode.strd_32) && (parsed_instr.imm == 0)) {
				rn_s ~= "]";
			}
			ops ~= rn_s;
		}
		if (field == "rd") {
			ops ~= get_register_name(parsed_instr.rd);
		}
		if (field == "rd_hi") {
			ops ~= get_register_name(parsed_instr.rd_hi);
		}
		if (field == "spec_reg") {
			ops ~= parsed_instr.spec_reg.to!string;
		}
		if (field == "rd_lo") {
			ops ~= get_register_name(parsed_instr.rd_lo);
		}
		if (field == "rt2") {
			ops ~= get_register_name(parsed_instr.rt_2);
		}
		if (field == "ra") {
			ops ~= get_register_name(parsed_instr.ra);
		}
		if (field == "rm") {
			string rm_s;
			rm_s ~= get_register_name(parsed_instr.rm);
			if (is_store(parsed_instr.op)) {
				rm_s ~= "]";
			}
			ops ~= rm_s;
		}
		if (field == "imm") {
			if ((parsed_instr.op == opcode.strd_32) && (parsed_instr.imm == 0)) {
				continue;	
			}
			if (parsed_instr.imm == 0 && parsed_instr.op == opcode.add_lo_reg) {
				continue;
			}
			string imm = "#";
			if (parsed_instr.op == opcode.strd_32 && !parsed_instr.add) {
				imm ~= (-cast(int)parsed_instr.imm).to!string;
			} else {
				imm ~= parsed_instr.imm.to!string;
			}
			if (parsed_instr.op == opcode.str_sp || is_store(parsed_instr.op)) {
				imm ~= "]";
			}
			if (parsed_instr.op == opcode.mov_32) {
				string final_ = "asr ";
				final_ ~= imm;
				ops ~= final_;
			} else { 
				ops ~= imm;
			} 
		}
		if (field == "width") {
			string width = "#";
			width ~= parsed_instr.width.to!string;
			ops ~= width;
		}
		if (field == "lsb") {
			string ls_bit = "#";
			ls_bit ~= parsed_instr.ls_bit.to!string;
			ops ~= ls_bit;
		}
		if (field == "reg_list") {
			auto reg_list_copy = parsed_instr.reg_list;
			if (reg_list_copy.length == 1) {
				string s = "{";
				s ~= get_register_name(reg_list_copy.front);
				s ~= "}";
				ops ~= s;
				continue;
			}
			string first = "{"; 
			first ~= get_register_name(reg_list_copy[0]);
			ops ~= first;
			for (uint i = 1; i < reg_list_copy.length - 1; ++i) {
				ops ~= get_register_name(reg_list_copy[i]);
			}
			string last;
			last ~= get_register_name(reg_list_copy[reg_list_copy.length - 1]);
			last ~= "}";
			ops ~= last; 
		}
		if (field == "sp") {
			if (parsed_instr.op == opcode.str_sp) {
				ops ~= "[sp";
			} else {
				ops ~= "sp";
			}
		}
		if (field == "pc") {
			if (parsed_instr.op == opcode.ldr_pool || parsed_instr.op == opcode.ldr_lit_32) {
				ops ~= "[pc";
			} else {
				ops ~= "pc";
			}
		}
	}
	res ~= ops.join(", ");
	if ((parsed_instr.op == opcode.strd_32) && parsed_instr.wback) {
		res ~= "!";
	}
	return res;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		uint instr;
		string expected;
	}

	test_case[] tests = [
		test_case(0xf8dfd034, "ldr.w sp, [pc, #52]"), // 1111 1000 1101 1111 1101 0000 0011 0100
		test_case(0xeba30605, "sub.w r6, r3, r5"),
		//test_case(0xf8553b04, "ldr.w r3, [r5], #4"), // 1111 1000 0101 0101 0011 1011 0000 0100
		test_case(0xf8c46188, "str.w r6, [r4, #392]"),
		test_case(0xf4437300, "orr.w r3, r3, #512"),
		test_case(0xf4436380, "orr.w r3, r3, #1024"),
		test_case(0xf4437380, "orr.w r3, r3, #256"),
		test_case(0xf0030307, "and.w r3, r3, #7"),
		test_case(0xf64f03ff, "movw r3, #63743"),
		test_case(0xfbb3f3f1, "udiv r3, r3, r1"),
		test_case(0xfa02f303, "lsl.w r3, r2, r3"),
		test_case(0xf4225200, "bic.w r2, r2, #8192"),
		test_case(0xfba32302, "umull r2, r3, r3, r2"),
		test_case(0xfb02f303, "mul.w r3, r2, r3"),
		test_case(0xfa22f303, "lsr.w r3, r2, r3"),
		test_case(0xf8c73098, "str.w r3, [r7, #152]"),
		test_case(0xeb43050c, "adc.w r5, r3, ip"),
		test_case(0xf04f31ff, "mov.w r1, #4294967295"),
		test_case(0xf1ad0c08, "sub.w ip, sp, #8"),
		test_case(0xe96dce04, "strd ip, lr, [sp, #-16]!"),
		test_case(0xf1c10720, "rsb r7, r1, #32"),
		test_case(0xfb00331e, "mls r3, r0, lr, r3"),
		test_case(0xeb66060c, "sbc.w r6, r6, ip"),
		test_case(0xe8bd83f8, "ldmia.w sp!, {r3, r4, r5, r6, r7, r8, r9, pc}"),
		test_case(0xf8832034, "strb.w r2, [r3, #52]"),
		test_case(0xf883203c, "strb.w r2, [r3, #60]"),
		test_case(0xf9973007, "ldrsb.w r3, [r7, #7]"),
		test_case(0xf893303d, "ldrb.w r3, [r3, #61]"),
		test_case(0xf8832300, "strb.w r2, [r3, #768]"),
		test_case(0xf3c202c0, "ubfx r2, r2, #3, #1"),
		test_case(0xe9c54700, "strd r4, r7, [r5]"),
		test_case(0xf0030310, "and.w r3, r3, #16"),
		test_case(0xf0030301, "and.w r3, r3, #1"),
		test_case(0xf0030307, "and.w r3, r3, #7"),
		test_case(0xf003021f, "and.w r2, r3, #31"),
		test_case(0xf0230301, "bic.w r3, r3, #1")

		//test_case(0xf3808808, "msr MSP, r0")
		//test_case(0xf8032b01, "strb.w r2, [r3], #1")
		// ldrb.w r3, [r7, #7]
		// str.w r0, [r0, #0]
		//test_case(0xf0100407, "ands.w r4, r0, #7")
		// 0001 1000 1000 sbc.w r6, r6, #0
	];

	foreach (t; tests) {
		string actual = convert_to_string(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction [0x%04X], got '%s'", t.instr, actual)
		);
    }
}

struct cortex_m_vm {
	cortex_m_cpu cpu;
	memory mem;
	addr_instr[] current_program;

	void load_program(string filename) {
		if (filename == "../test/cortex_m_asm.txt") {
			foreach (s; bare_metal_func_names) {
				func f = get_function(filename, s);
				current_program ~= f.instrs;
			}
		} else if (filename == "../test/zephyr_led_asm.txt") {
			foreach (s; zephyr_func_names) {
				func f = get_function(filename, s);
				current_program ~= f.instrs;
			}
		} else {
			foreach (s; freertos_func_names) {
				func f = get_function(filename, s);
				current_program ~= f.instrs;
			}
		}
		
		uint entry_point = get_entry_point_addr(filename);
    	cpu.set(reg.pc, entry_point);

    	load_literals(mem, filename);
    	if (filename != "../test/zephyr_led_asm.txt") {
    		load_init_array_start(mem, filename);
    	}
	}

	void execute_next_instr() {
	    auto inOpt = current_program.find!(ins => ins._addr == cpu.pc);

	    if (inOpt is null) {
	        writeln("Error: PC not found in program");
	        return;
	    }

	    auto ins = inOpt.front.i;

	    instr_16 i16;
		bool is16;

		try {
		    i16 = ins.get!instr_16;
		    is16 = true;
		} catch (Exception e) {
		    is16 = false;
		}

		if (is16) {
		    if (is_store(i16.op))
		        execute_load_store(i16, cpu, mem);
		    else
		        execute_instr(i16, cpu);
		    return;
		}


		auto i32 = ins.get!instr_32;
		if (is_store(i32.op) || i32.op == opcode.ldr_imm_32_t4)
		    execute_load_store(i32, cpu, mem);
		else
		    execute_instr(i32, cpu);
	}

	void run_to(uint addr) {
		uint last_instr_addr;
		while (1) {
			last_instr_addr = cpu.pc;
			execute_next_instr();
			if (cpu.pc == addr) {
				break;
			}
		}
		/*
		reset();
		while (1) {
			if (cpu.pc == last_instr_addr) {
				break;
			}
			execute_next_instr();
		}
		*/
	}

	void reset() {
		cpu = cortex_m_cpu();
		mem = memory();
		load_literals(mem, "../test/cortex_m_asm.txt");
		uint entry_point = get_entry_point_addr("../test/cortex_m_asm.txt");
		load_init_array_start(mem, "../test/cortex_m_asm.txt");
    	cpu.set(reg.pc, entry_point);
	}
}

// ===============
//  Load Literals
// ===============

void load_literals(ref memory mem, string filename) {
	File file;
	try {
		file = File(filename, "r");
	} catch (Exception e) {
		writeln("Error opening file: ", e.msg);
	}
    auto lines = file.byLineCopy.array;
    foreach (i, line; lines) {
        if (line.canFind(".word")) {
            auto parts = split(line, ":");
            auto addr_str = parts[0].strip();
            string addr_str_clean = addr_str.startsWith("0x") ? addr_str[2..$] : addr_str;
			uint addr = parse!uint(addr_str_clean, 16);
			auto rest = parts[1].strip();
			auto rest_parts = split(rest, "x");
			auto literal_part = rest_parts[1].strip();
			uint literal = parse!uint(literal_part, 16);
            mem.write_word(addr, literal);
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	memory mem;
	load_literals(mem, "../test/cortex_m_asm.txt");
	assert(mem.read_word(0x800a1c4) == 0x20020000, format("Failed to load [0x%04X] into [0x%04X]", 0x20020000, 0x800a1c4));
	assert(mem.read_word(0x800a1c8) == 0x20000000, format("Failed to load [0x%04X] into [0x%04X]", 0x20000000, 0x800a1c8));
	assert(mem.read_word(0x800a1cc) == 0x20000560, format("Failed to load [0x%04X] into [0x%04X]", 0x20000560, 0x800a1cc));
	assert(mem.read_word(0x800a1d0) == 0x0800a2e8, format("Failed to load [0x%04X] into [0x%04X]", 0x0800a2e8, 0x800a1d0));
	assert(mem.read_word(0x800a1d4) == 0x20000560, format("Failed to load [0x%04X] into [0x%04X]", 0x20000560, 0x800a1d4));
	assert(mem.read_word(0x800a1d8) == 0x20000958, format("Failed to load [0x%04X] into [0x%04X]", 0x20000958, 0x800a1d8));
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	memory mem;
	load_literals(mem, "../test/freertos_blink_asm.txt");
	assert(mem.read_word(0x8017c10) == 0x20000038, format("Failed to load [0x%04X] into [0x%04X]", 0x20020000, 0x800a1c4));
	assert(mem.read_word(0x8017d1c) == 0x20020000, format("Failed to load [0x%04X] into [0x%04X]", 0x20000000, 0x800a1c8));
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    memory mem = memory();
    cortex_m_cpu cpu = cortex_m_cpu(r3: 1, r4: 2, r5: 3, r6: 4, r7: 5, lr: 6, msp: memory.stack_base);
    instr_16 push = instr_16(op: opcode.push_mult_reg, reg_list: [reg.r3, reg.r4, reg.r5, reg.r6, reg.r7, reg.lr]);
    execute_load_store(push, cpu, mem);
    writeln(cpu.get_sp());
    writeln(memory.stack_base);
    instr_16 pop1 = instr_16(op: opcode.pop_mult_reg, reg_list: [reg.r3, reg.r4, reg.r5, reg.r6, reg.r7]);
    execute_load_store(pop1, cpu, mem);
    writeln("---------------------------------");
    writeln(mem.read_word(memory.stack_base-4));
    instr_16 pop2 = instr_16(op: opcode.pop_mult_reg, reg_list: [reg.r3]);
    execute_load_store(pop2, cpu, mem);
    writeln("---------------------------------");
    writeln(mem.read_word(memory.stack_base-4));
    //assert(cpu.r3 == 1);
}


