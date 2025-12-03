import std.algorithm : all, canFind, map;
import std.conv : to, ConvException, parse;
import std.exception;
import std.string : indexOf, replace, split, strip, stripLeft;
import std.traits;
import std.variant : Algebraic;
import std.format : format;
import std.stdio;
import std.regex;
import std.array;

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
	b_n 			= 0b11100,
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
	negs            = 0b1001
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
	blx				= 0b111
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
	adr,
	add_imm_3,
	add_imm_8,
	and_reg,
	bx,
	cmp_br_z,
	cmp_br_nz,
	br_t1,
	cmp_reg,
	lor_reg,
	mvn_reg,
	pop_mult_reg,
	asr_imm,
	cmp_imm,
	ldrb_imm,
	ldrb_reg,
	ldr_imm,
	lsl_imm,
	lsl_reg,
	lsr_imm,
	ldrh_imm,
	mov_imm,
	str_reg,
	str_imm,
	strh_reg,
	strb_imm,
	strh_imm,
	sub_imm_8,
	ldr_pool,
	sub_reg,
	push_mult_reg,
	b_n,
	if_then,
	mov_high_1,
	mov_high_2,
	mov_lo,
	blx,
	add_sp,
	sub_sp,
	add_lo_reg,
	lsr_reg,
	mov_high_reg,
	str_sp,
	ld_sp,
	add_reg,
	adc_reg,
	cmp_high_1,
	cmp_high_2,
	add_high_reg_1,
	sub_imm_3,
	add_high_reg_2,
	ldr_reg,
	negs,
	add_32_reg,
	bl_32,
	nop_32,
	pop_mult_reg_32,
	sub_imm_32,
	and_imm_32,
	udiv_32,
	ubfx_32,
	mul_32,
	lsr_32,
	orr_32,
	add_32,
	bit_clear_32,
	mov_32,
	mov_16_imm_32,
	ldrsb_32,
	str_reg_32,
	dsb,
	rsb_32,
	umull_32,
	strd_32,
	b_32,
	stmb_32,
	stmdb_32,
	push_mult_reg_32,
	orr_reg_32,
	subs_32,
	sbc_32,
	adc_32,
	or_not_32,
	mvn_reg_32,
	bit_not_32,
	bit_or_not_32,
	ld_rex,
	str_rex,
	mls_32,
	ldr_sh_32,
	ldh_32,
	tst_32,
	and_reg_32,
	bic_reg_32,
	invalid
}

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
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == instr_grp.single_str_1) {
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.str) {
    		return opcode.str_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.strh) {
    		return opcode.strh_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.ldrb_reg) {
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
    			return opcode.ld_sp;
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
    	return opcode.br_t1;
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == instr_grp.misc) {
    	if (cast(ubyte)((instr >> 8) & 0b1111) == misc.cmp_br) {
    		if (cast(ubyte)((instr >> 7) & 0b1) == cmp_br.cmp_br_z) {
    			return opcode.cmp_br_z;
    		}
    		if (cast(ubyte)((instr >> 7) & 0b1) == cmp_br.cmp_br_nz) {
    			return opcode.cmp_br_nz;
    		}
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == misc.push_mult_reg) {
    		return opcode.push_mult_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == misc.pop_mult_reg) {
    		return opcode.pop_mult_reg;
    	}
    	if (cast(ubyte)((instr >> 8) & 0b1111) == misc.if_then) {
    		return opcode.if_then;
    	}
    	if (cast(ubyte)((instr >> 7) & 0b11111) == misc.sub_sp) {
    		return opcode.sub_sp;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b1) == cmp_br.cmp_br_z) {
    			return opcode.cmp_br_z;
		}
		if (cast(ubyte)((instr >> 11) & 0b1) == cmp_br.cmp_br_nz) {
			return opcode.cmp_br_nz;
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
    if (cast(ubyte)((instr >> 11) & 0b11111) == instr_grp.b_n) {
    	return opcode.b_n;
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
		test_case(0xd002, opcode.br_t1),
		test_case(0xb103, opcode.cmp_br_z),
		test_case(0x4718, opcode.bx),
		test_case(0x1a1b, opcode.sub_reg),
		test_case(0xb510, opcode.push_mult_reg),
		test_case(0xb943, opcode.cmp_br_nz),
		test_case(0xbd10, opcode.pop_mult_reg),
		test_case(0xe7cf, opcode.b_n),
		test_case(0xbf00, opcode.if_then),
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
		test_case(0x58fb, opcode.ldr_reg)
	];

	foreach (t; tests) {
		assert(
		    decode_mnemonic(t.instr) == t.expected,
		    format("Failed for instruction 0x%04X", t.instr)
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
	ldh  					= 0b1100111
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
				if (rd != 0b1111) {
					return opcode.orr_reg_32;
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
			if (op == 0b01) {
				ubyte L = cast(ubyte)((instr >> 20) & 0b1);
				if (L == 0b1) {
					if (rn == 0b1101) {
						return opcode.pop_mult_reg_32;
					}
				}
			}
			if (op == 0b10) {
				ubyte L = cast(ubyte)((instr >> 20) & 0b1);
				if (L == 0b0) {
					if (rn == 0b1101) {
						return opcode.push_mult_reg_32;
					}
				}
			}
		}
		if ((op2 & op2_32.ld_str_dual) == 0b0000100) {
			ubyte _op1 = cast(ubyte)((instr >> 20) & 0b11);
			ubyte _op2 = cast(ubyte)((instr >> 23) & 0b11);
			if (((_op1 & 0b10) == 0b10) && ((_op2 & 0b01) == 0b00)) {
				return opcode.strd_32;
			}
			if (((_op1 & 0b10) == 0b00) && ((_op2 & 0b10) == 0b10)) {
				return opcode.strd_32;
			}
			if ((_op2 == 0b00) && (_op1 == 0b01)) {
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
			if ((_op1 & 0b101) == 0b101) {
				return opcode.bl_32;
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
			if (_op == 0b0111011) {
				ubyte __op = cast(ubyte)((instr >> 4) & 0b1111);
				return opcode.dsb; 
			}
			if (((_op1 & 0b101) == 0b000) && ((_op & 0b0111000) != 0b0111000)) {
				return opcode.b_32;
			}
			if ((_op1 & 0b101) == 0b001) {
				return opcode.b_32;
			}
		}
		if ((op2 & op2_32.data_proc_imm) == 0b0000000) {
			ubyte _op = cast(ubyte)((instr >> 21) & 0b1111);
			ubyte rn = cast(ubyte)((instr >> 12) & 0b1111);
			if (_op == 0b1101) {
				if (rd != 0b1111) {
					return opcode.sub_imm_32;
				}
			} 
			if (_op == 0b0000) {
				if (rd != 0b1111) {
					return opcode.and_imm_32;
				}
			}
			if (_op == 0b0010) {
				if (rn != 0b1111) {
					return opcode.orr_32;
				} else {
					return opcode.mov_32;
				}
			}
			if (_op == 0b0011) {
				if (rn != 0b1111) {
					return opcode.bit_or_not_32;
				}
				if (rn == 0b1111) {
					return opcode.bit_not_32;
				}
			}
			if (_op == 0b1000) {
				if (rd != 0b1111) {
					return opcode.add_32;
				}
			}
			if (_op == 0b0001) {
				return opcode.bit_clear_32;
			}
			if (_op == 0b1110) {
				return opcode.rsb_32;
			}
		}
		if ((op2 & op2_32.data_proc_bin_imm) == op2_32.data_proc_bin_imm) {
			ubyte _op = cast(ubyte)((instr >> 20) & 0b11111);
			if (_op == 0b11100) {
				return opcode.ubfx_32;
			}
			if (_op == 0b00100) {
				return opcode.mov_16_imm_32;
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
		if ((op2 & op2_32.ld_bytes_mem_hints) == 0b0000001) {
			return opcode.ldrsb_32;
		}
		if ((op2 & op2_32.data_proc_reg) == 0b0100000) {
			return opcode.lsr_32;
		}
		if ((op2 & op2_32.data_proc_reg) == 0b0000000) {
			return opcode.str_reg_32;
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
		test_case(0xfa22f303, opcode.lsr_32),
		test_case(0xf4434380, opcode.orr_32),
		test_case(0xf1070314, opcode.add_32),
		test_case(0xf0230310, opcode.bit_clear_32),
		test_case(0xf64f03ff, opcode.mov_16_imm_32),
		test_case(0xf9973007, opcode.ldrsb_32),
		test_case(0xf8412023, opcode.str_reg_32),
		test_case(0xf3bf8f4f, opcode.dsb),
		test_case(0xf1c30307, opcode.rsb_32),
		test_case(0xfba22303, opcode.umull_32),
		test_case(0xe9c72300, opcode.strd_32),
		test_case(0xf67fae90, opcode.b_32),
		test_case(0xe92d4fb0, opcode.push_mult_reg_32),
		test_case(0xea4161d2, opcode.orr_reg_32),
		test_case(0xebb2080a, opcode.subs_32),
		test_case(0xeb63090b, opcode.sbc_32),
		test_case(0xeb45030b, opcode.adc_32),
		test_case(0xf06f0240, opcode.bit_or_not_32),
		test_case(0xe8533f00, opcode.ld_rex),
		test_case(0xe8412300, opcode.str_rex),
		test_case(0xfb0e7711, opcode.mls_32),
		test_case(0xf9b4500c, opcode.ldh_32),
		test_case(0xea1c0f0e, opcode.tst_32),
		test_case(0xea010808, opcode.and_reg_32),
		test_case(0xea23030c, opcode.bic_reg_32),
		test_case(0xf7ffbfbb, opcode.b_32)
	];

	foreach (t; tests) {
		assert(
		    decode_mnemonic_32(t.instr) == t.expected,
		    format("Failed for instruction 0x%08X", t.instr)
		);
    }
}

enum condition : ubyte {
	eq = 0b0000,
	ne = 0b0001
}

struct instr_16 {
	opcode op;
	reg rd;
	reg rm;
	reg rn;
	reg rt;
	ubyte imm;
	short offset;
	int imm_long;
	condition cond;
	reg[] reg_list;
	bool set_flags;
}

instr_16 parse_cmp_imm(short instr) {
	instr_16 res;
	res.op = opcode.cmp_imm;
	ubyte rn = cast(ubyte)((instr >> 8) & 0b111);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	res.rn = cast(reg)(rn);
	return res;
}

// ===========
//  Parse ASR
// ===========

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

// ===========
//  Parse ADD
// ===========

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

// ===========
//  Parse MOV
// ===========

instr_16 parse_mov_imm(short instr) {
	instr_16 res;
	res.op = opcode.mov_imm;
	ubyte rd = cast(ubyte)((instr >> 8) & 0b111);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	res.rd = cast(reg)(rd);
	return res;
}

// ===========
//  Parse AND
// ===========

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

// ===========
//  Parse Sub
// ===========

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

// ===========
//  Parse LSL
// ===========

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

// ===========
//  Parse LSR
// ===========

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

// ===========
//  Parse LOR
// ===========

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

// ===========
//  Parse MVN 
// ===========

instr_16 parse_mvn_reg(short instr) {
	instr_16 res;
	res.op = opcode.mvn_reg;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

// ================
//  Parse STRH Imm
// ================

instr_16 parse_strh_imm(short instr) {
	instr_16 res;
	res.op = opcode.strh_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = cast(ubyte)(imm * 2);
	return res; 
}

// ===============
//  Parse STR IMM 
// ===============

instr_16 parse_str_imm(short instr) {
	instr_16 res;
	res.op = opcode.str_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = cast(ubyte)(imm * 4);
	return res;
}

// ================
//  Parse LDRH IMM 
// ================

instr_16 parse_ldrh_imm(short instr) {
	instr_16 res;
	res.op = opcode.ldrh_imm;
	ubyte rt = cast(ubyte)( instr        & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = cast(ubyte)(imm * 2);
	return res;
}

// ================
//  Parse LDRB IMM
// ================

instr_16 parse_ldrb_imm(short instr) {
	instr_16 res;
	res.op = opcode.ldrb_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm;
	return res;
}

// =================
//  Parse STRRB IMM
// =================

instr_16 parse_strb_imm(short instr) {
	instr_16 res;
	res.op = opcode.strb_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	res.imm = imm;
	return res;
}

// ===============
//  Parse LDR IMM 
// ===============

instr_16 parse_ldr_imm(short instr) {
	instr_16 res;
	res.op = opcode.ldr_imm;
	ubyte rt = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = cast(ubyte)(imm * 4);
	return res;
}

// ===============
//  Parse CMP REG 
// ===============

instr_16 parse_cmp_reg(short instr) {
	instr_16 res;
	res.op = opcode.cmp_reg;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// ================
//  Parse LDR Pool 
// ================

instr_16 parse_ldr_pool(short instr) {
	instr_16 res;
	res.op = opcode.ldr_pool;
	ubyte rt = cast(ubyte)((instr >> 8) & 0b111);
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	res.rt = cast(reg)(rt);
	res.imm = cast(ubyte)(imm_8 * 4);
	return res;
}

// =============
//  Parse BR T1
// =============

instr_16 parse_br_t1(short instr) {
	instr_16 res;
	res.op = opcode.br_t1;
	ubyte cond = cast(ubyte)((instr >> 8 ) & 0xf);
	res.cond = cast(condition)(cond);
	ubyte imm = cast(short)(instr & 0xff);
	res.offset = imm;
	return res;
}

// ==========
//  Parse BX
// ==========

instr_16 parse_bx(short instr) {
	instr_16 res;
	res.op = opcode.bx;
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	res.rm = cast(reg)(rm);
	return res;
}

// ==============
//  Parse CMPBRZ
// ==============

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
instr_16 parse_cmp_br_z(short instr) {
	instr_16 res;
	res.op = opcode.cmp_br_z;
	ubyte rn = cast(ubyte)(instr & 0b111);
	short imm_5 = cast(short)((instr >> 3) & 0b11111);
	res.rn = cast(reg)(rn);
	res.offset = imm_5;
	return res;
}

// ===============
//  Parse CMPBRNZ
// ===============

instr_16 parse_cmp_br_nz(short instr) {
	instr_16 res;
	res.op = opcode.cmp_br_nz;
	ubyte rn = cast(ubyte)(instr & 0b111);
	short imm_5 = cast(short)((instr >> 3) & 0b11111);
	res.rn = cast(reg)(rn);
	res.offset = imm_5;
	return res;
}

// ===============
//  Parse SUB Reg
// ===============

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

// =====================
//  Parse Push Mult Reg
// =====================

instr_16 parse_push_mult_reg(short instr) {
	instr_16 res;
	res.op = opcode.push_mult_reg;
	ubyte m = cast(ubyte)((instr >> 8) & 0b1);
	if (m) {
		res.reg_list ~= reg.lr;
	}
	ubyte reg_mask = cast(ubyte)(instr & 0xff);
	if (reg_mask & 0b00000001) res.reg_list ~= reg.r0;
	if (reg_mask & 0b00000010) res.reg_list ~= reg.r1;
	if (reg_mask & 0b00000100) res.reg_list ~= reg.r2;
	if (reg_mask & 0b00001000) res.reg_list ~= reg.r3;
	if (reg_mask & 0b00010000) res.reg_list ~= reg.r4;
	if (reg_mask & 0b00100000) res.reg_list ~= reg.r5;
	if (reg_mask & 0b01000000) res.reg_list ~= reg.r6;
	if (reg_mask & 0b10000000) res.reg_list ~= reg.r7;
	return res;
}

// =====================
//  Parse Push Mult Reg
// =====================

instr_16 parse_pop_mult_reg(short instr) {
	instr_16 res;
	res.op = opcode.pop_mult_reg;
	ubyte p = cast(ubyte)((instr >> 8) & 0b1);
	if (p) {
		res.reg_list ~= reg.pc;
	}
	ubyte reg_mask = cast(ubyte)(instr & 0xff);
	if (reg_mask & 0b00000001) res.reg_list ~= reg.r0;
	if (reg_mask & 0b00000010) res.reg_list ~= reg.r1;
	if (reg_mask & 0b00000100) res.reg_list ~= reg.r2;
	if (reg_mask & 0b00001000) res.reg_list ~= reg.r3;
	if (reg_mask & 0b00010000) res.reg_list ~= reg.r4;
	if (reg_mask & 0b00100000) res.reg_list ~= reg.r5;
	if (reg_mask & 0b01000000) res.reg_list ~= reg.r6;
	if (reg_mask & 0b10000000) res.reg_list ~= reg.r7;
	return res;
}

// ==========
//  Parse BN
// ==========

instr_16 parse_b_n(short instr) {
	instr_16 res;
	res.op = opcode.b_n;
	int imm_11 = cast(int)(instr & 0b11111111111);
	if ((imm_11 & 0x400) == 0x400) {
        imm_11 |= 0xfffff800;
	}
	res.imm_long = imm_11;
	return res; 
}

// ===========
//  Parse MOV
// ===========

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

// ===========
//  Parse MOV
// ===========

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

// ===========
//  Parse BLX
// ===========

instr_16 parse_blx(short instr) {
	instr_16 res;
	res.op = opcode.blx;
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	res.rm = cast(reg)(rm);
	return res;
} 

// ==============
//  Parse ADD SP
// ==============

instr_16 parse_add_sp(short instr) {
	instr_16 res;
	res.op = opcode.add_sp;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0b111);
	res.imm = imm_8;
	res.rd = cast(reg)(rd);
	return res;
}

// ================
//  Parse LDRB REG
// ================

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

// ==============
//  Parse SUB SP
// ==============

instr_16 parse_sub_sp(short instr) {
	instr_16 res;
	res.op = opcode.sub_sp;
	ubyte imm_7 = cast(ubyte)(instr & 0x7f);
	res.imm = cast(ubyte)(imm_7 * 4);
	return res;
}

// ===============
//  Parse ADD IMM
// ===============

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

// ==================
//  Parse ADD LO REG
// ==================

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

// ===============
//  Parse LSL REG
// ===============

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

// ===============
//  Parse LSR REG
// ===============

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

// ===========
//  Parse ADR
// ===========

/*
	Generate PC-Relative Address
	ADR <Rd>,<Label>
	[15:11] 10100
	[10:8] Rd
	[7:0] Imm8  
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

// ================
//  Parse MOV HIGH
// ================

/*
	Special Data Instructions and Branch and Exchange
	MOV <Rd>,<Rm>
	[15:8] 01000110
	[7] D
	[6:3] Rm
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

// ==============
//  Parse STR SP
// ==============

/*
	Load/Store Single Data Item
	STR <Rt>,[SP,#<imm8>]
	[15:11] 10010
	[10:8] Rt
	[7:0] Imm8
*/
instr_16 parse_str_sp(short instr) {
	instr_16 res;
	res.op = opcode.str_sp;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rt = cast(ubyte)((instr >> 8) & 0b111);
	res.imm = imm_8;
	res.rt = cast(reg)(rt);
	return res;
}

// ===============
//  Parse ADD REG
// ===============

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

// ================
//  Parse CMP HIGH
// ================

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

// ====================
//  Parse ADD HIGH REG
// ====================

/*
	Special Data Instructions and Compare and Exchange
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

// ====================
//  Parse ADD HIGH REG
// ====================

/*
	Special Data Instructions and Compare and Exchange
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

// ================
//  Parse SUB IMM3
// ================

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

// ================
//  Parse CMP HIGH
// ================

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

// ============
//  Parse NEGS
// ============

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

// ===============
//  Parse LDR REG
// ===============

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

// ==============
//  Decode Instr
// ==============

instr_16 decode_instr(ushort instr) {
    instr_16 res;
    auto op = decode_mnemonic(instr);

    switch (op) {

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

       	case opcode.ldr_imm:
       		return parse_ldr_imm(instr);

       	case opcode.cmp_reg:
       		return parse_cmp_reg(instr);

       	case opcode.ldr_pool:
       		return parse_ldr_pool(instr); 

       	case opcode.br_t1:
       		return parse_br_t1(instr);

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

       	case opcode.b_n:
       		return parse_b_n(instr);

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

        default:
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
		test_case(0xd002, instr_16(op: opcode.br_t1,         cond: condition.eq,      offset: 2)),
		test_case(0xb103, instr_16(op: opcode.cmp_br_z,      rn: reg.r3,              offset: 0)),
		test_case(0x4718, instr_16(op: opcode.bx,            rm: reg.r3)),
		test_case(0x1a1b, instr_16(op: opcode.sub_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r0)),
		test_case(0xb510, instr_16(op: opcode.push_mult_reg, reg_list: [reg.lr, reg.r4])),
		test_case(0xb943, instr_16(op: opcode.cmp_br_nz,     rn: reg.r3,			  offset: 8)),
		test_case(0xbd10, instr_16(op: opcode.pop_mult_reg,  reg_list: [reg.pc, reg.r4])),
		test_case(0xe7cf, instr_16(op: opcode.b_n,					 				  imm_long: 0xffffffcf)),
		//test_case(0xbf00, instr_16(op: if_then))
		test_case(0x469d, instr_16(op: opcode.mov_high_1,    rd: reg.sp,  rm: reg.r3)),
		test_case(0x460f, instr_16(op: opcode.mov_lo,        rd: reg.r7,  rm: reg.r1)),
		test_case(0x4798, instr_16(op: opcode.blx,           rm: reg.r3)),
		test_case(0xaf00, instr_16(op: opcode.add_sp,        rd: reg.r7, 			  imm: 0)),
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
		test_case(0x58fb, instr_16(op: opcode.ldr_reg,	     rt: reg.r3,  rn: reg.r7, rm: reg.r3))
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

struct ram_mem_section {
	uint[128 * 1024] cells;

    ref uint opIndex(size_t idx) {
        return cells[idx];
    }

    const(uint) opIndex(size_t idx) const {
        return cells[idx];
    }
}

struct flash_mem_section {
	__gshared uint[1024 * 1024] cells;

    ref uint opIndex(size_t idx) {
        return cells[idx];
    }

    const(uint) opIndex(size_t idx) const {
        return cells[idx];
    }
}

struct memory {
	ram_mem_section ram;
	flash_mem_section flash;

	static uint stack_base = (128 * 1024) - 1;

	void push(uint sp, uint val) {
		ram[sp] = val;
	}

	uint pop(uint sp) {
		uint res = ram[sp];
		ram[sp] = 0;
		return res;
	}
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

	bool n;
	bool z;
	bool c;
	bool v;

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
			case reg.r6:
				return r6;
			case reg.r7:
				return r7;
			case reg.r10:
				return r10;
			case reg.r12:
				return r12;
			case reg.pc:
				return pc;
			case reg.lr:
				return lr;
			case reg.sp:
				return sp;
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
			case reg.r6:
				r6 = cast(uint)(val);
				return;
			case reg.r7:
				r7 = cast(uint)(val);
				return;
			case reg.r10:
				r10 = cast(uint)(val);
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
				sp = cast(uint)(val);
				return;
			default:
				return;
		}
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
	return;
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
	return;
}

// =============
//  Execute ADD
// =============

void execute_add_imm_8(instr_16 add_imm_8_instr, ref cortex_m_cpu cpu) {
	int rm_val = cast(int)(cpu.get(add_imm_8_instr.rm));
	int res = rm_val + add_imm_8_instr.imm;
	if (add_imm_8_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = (res >= add_imm_8_instr.imm);
		cpu.v = (rm_val < 0 && res > 0);
	}
	cpu.set(add_imm_8_instr.rd, res);
	return;
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
	return;
}

// =============
//  Execute MOV
// =============

void execute_mov_imm(instr_16  mov_imm_instr, ref cortex_m_cpu cpu) {
	cpu.set(mov_imm_instr.rd, mov_imm_instr.imm);
}

// ==================
//  Execute SUB IMM8
// ==================

void execute_sub_imm_8(instr_16 sub_imm_8_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(sub_imm_8_instr.rn);
	int res = rn - sub_imm_8_instr.imm;
	if (sub_imm_8_instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = (res >= sub_imm_8_instr.imm);
		cpu.v = (rn < 0 && res > 0);
	}
	cpu.set(sub_imm_8_instr.rd, res);
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
}

// =============
//  Execute STR
// =============

void execute_str_imm(instr_16 str_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(str_imm_instr.rt);
	int rn = cpu.get(str_imm_instr.rn);
	int addr = rn + str_imm_instr.imm;
	mem.ram[addr] = rt;
}

// =============
//  Execute LDR
// =============

void execute_ldr_imm(instr_16 ldr_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rn = cpu.get(ldr_imm_instr.rn);
	int addr = rn + ldr_imm_instr.imm;
	int rt = mem.ram[addr];
	cpu.set(ldr_imm_instr.rt, rt);
}

// ==============
//  Execute STRH
// ==============

void execute_strh_imm(instr_16 strh_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(strh_imm_instr.rt);
	int rn = cpu.get(strh_imm_instr.rn);
	int addr = rn + strh_imm_instr.imm;
	int target = mem.ram[addr];
	target = (target & 0xffff0000) | rt;  
	mem.ram[addr] = target;
}

// ==============
//  Execute LDRH
// ==============

void execute_ldrh_imm(instr_16 ldrh_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(ldrh_imm_instr.rt);
	int rn = cpu.get(ldrh_imm_instr.rn);
	int addr = rn + ldrh_imm_instr.imm;
	int val = mem.ram[addr];
	rt = (rt & 0xffff0000) | val;  
	cpu.set(ldrh_imm_instr.rt, rt);
}

// ==============
//  Execute LDRB
// ==============

void execute_ldrb_imm(instr_16 ldrb_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(ldrb_imm_instr.rt);
	int rn = cpu.get(ldrb_imm_instr.rn);
	int addr = rn + ldrb_imm_instr.imm;
	int val = mem.ram[addr];
	rt = (rt & 0xffffff00) | val;  
	cpu.set(ldrb_imm_instr.rt, rt);
}

// ==============
//  Execute STRB
// ==============

void execute_strb_imm(instr_16 strb_imm_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rt = cpu.get(strb_imm_instr.rt);
	int rn = cpu.get(strb_imm_instr.rn);
	int addr = rn + strb_imm_instr.imm;
	int target = mem.ram[addr];
	target = (target & 0xffffff00) | rt;  
	mem.ram[addr] = target;
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
}

// ==================
//  Execute LDR POOL
// ==================

void execute_ldr_pool(instr_16 ldr_pool_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int pc = cpu.get(reg.pc);
	pc += ldr_pool_instr.imm;
	int val = mem.flash[pc];
	cpu.set(ldr_pool_instr.rt, val);
}

// ============
//  Execute BX
// ============

void execute_bx(instr_16 bx_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(bx_instr.rn);
	int pc = cpu.get(reg.pc);
	pc += rn;
	cpu.set(reg.pc, pc);
}

// ============
//  Execute BR
// ============

void execute_br_t1(instr_16 br_t1_instr, ref cortex_m_cpu cpu) {
	int pc = cpu.get(reg.pc);
	pc += br_t1_instr.offset;
	cpu.set(reg.pc, pc);
}

// ==================
//  Execute CMP BR Z
// ==================

void execute_cmp_br_z(instr_16 cmp_br_z_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(cmp_br_z_instr.rn);
	if (rn == 0) {
		int pc = cpu.get(reg.pc);
		pc += cmp_br_z_instr.imm;
		cpu.set(reg.pc, pc);
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
}

// =======================
//  Execute PUSH MULT REG
// =======================

void execute_push_mult_reg(instr_16 push_mult_reg_instr, ref cortex_m_cpu cpu, ref memory mem) {
	foreach (r; push_mult_reg_instr.reg_list) {
		int sp = cpu.get(reg.sp);
		mem.push(sp, cpu.get(r));
		sp -= 1;
		cpu.set(reg.sp, sp);
	}
} 

// ======================
//  Execute POP MULT REG
// ======================

void execute_pop_mult_reg(instr_16 pop_mult_reg_instr, ref cortex_m_cpu cpu, ref memory mem) {
	foreach (r; pop_mult_reg_instr.reg_list) {
		int sp = cpu.get(reg.sp);
		sp += 1;
		int val = mem.pop(sp);
		cpu.set(r, val);
		cpu.set(reg.sp, sp);
	}
} 

// ===================
//  Execute CMP BR NZ
// ===================

void execute_cmp_br_nz(instr_16 cmp_br_nz_instr, ref cortex_m_cpu cpu) {
	if (cpu.get(cmp_br_nz_instr.rn) != 0) {
		int pc = cpu.get(reg.pc);
		pc += cmp_br_nz_instr.offset;
		cpu.set(reg.pc, pc);
	}
}

// ==================
//  Execute MOV HIGH
// ==================

void execute_mov_high_1(instr_16 mov_high_1_instr, ref cortex_m_cpu cpu) {
	cpu.set(mov_high_1_instr.rd, cpu.get(mov_high_1_instr.rm));
}

// =============
//  Execute BLX
// =============

void execute_blx(instr_16 blx_instr, ref cortex_m_cpu cpu) {
	cpu.set(reg.lr, cpu.get(reg.pc) - 2);
	cpu.set(reg.pc, cpu.get(blx_instr.rm));
}

// ================
//  Execute ADD SP
// ================

void execute_add_sp(instr_16 add_sp_instr, ref cortex_m_cpu cpu) {
	int sp = cpu.get(reg.sp);
	int res = sp + add_sp_instr.imm;
	cpu.set(add_sp_instr.rd, res);
}

// ==================
//  Execute LDRB REG
// ==================

void execute_ldrb_reg(instr_16 ldrb_reg_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int addr = cpu.get(ldrb_reg_instr.rn) + cpu.get(ldrb_reg_instr.rm);
	int val = mem.ram[addr];
	int target = cpu.get(ldrb_reg_instr.rt);
	target = (target & 0xffffff00) | (val & 0x000000ff);
	cpu.set(ldrb_reg_instr.rt, target);
}

// ================
//  Execute SUB SP
// ================

void execute_sub_sp(instr_16 sub_sp_instr, ref cortex_m_cpu cpu) {
	int sp = cpu.get(reg.sp);
	sp -= sub_sp_instr.imm;
	cpu.set(reg.sp, sp);
}

// ==================
//  Execute ADD IMM3
// ==================

void execute_add_imm_3(instr_16 add_imm_3_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(add_imm_3_instr.rn);
	int res = rn + add_imm_3_instr.imm;
	cpu.set(add_imm_3_instr.rd, res);
}

// ====================
//  Execute ADD LO REG
// ====================

void execute_add_lo_reg(instr_16 add_lo_reg_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(add_lo_reg_instr.rn);
	int rm = cpu.get(add_lo_reg_instr.rm);
	int res = rn + rm;
	cpu.set(add_lo_reg_instr.rd, res);
}

// =================
//  Execute LSL REG
// =================

void execute_lsl_reg(instr_16 lsl_reg_instr, ref cortex_m_cpu cpu) {
	int shift = cpu.get(lsl_reg_instr.rm);
	int val = cpu.get(lsl_reg_instr.rn);
	val = val << shift;
	cpu.set(lsl_reg_instr.rd, val);
}

// =================
//  Execute LSR REG
// =================

void execute_lsr_reg(instr_16 lsr_reg_instr, ref cortex_m_cpu cpu) {
	int shift = cpu.get(lsr_reg_instr.rm);
	int val = cpu.get(lsr_reg_instr.rn);
	val = val >> shift;
	cpu.set(lsr_reg_instr.rd, val);
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
}

// =================
//  Execute ADD REG
// =================

void execute_add_reg(instr_16 add_reg_instr, ref cortex_m_cpu cpu) {
	cpu.set(add_reg_instr.rd, cpu.get(add_reg_instr.rn) + cpu.get(add_reg_instr.rm));
}

// =================
//  Execute LDR REG
// =================

void execute_ldr_reg(instr_16 ldr_reg_instr, ref cortex_m_cpu cpu, ref memory mem) {
	int rn = cpu.get(ldr_reg_instr.rn);
	int rm = cpu.get(ldr_reg_instr.rm);
	uint addr = rn + rm;
	int val = mem.ram[addr];
	cpu.set(ldr_reg_instr.rt, val);
}

// ==================
//  Execute SUB IMM3
// ==================

void execute_sub_imm_3(instr_16 sub_imm_3_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(sub_imm_3_instr.rn);
	int res = rn - sub_imm_3_instr.imm;
	cpu.set(sub_imm_3_instr.rd, res);
}

// ==============
//  Execute NEGS
// ==============

void execute_negs(instr_16 negs_instr, ref cortex_m_cpu cpu) {
	int rn = cpu.get(negs_instr.rn);
	rn = -rn;
	cpu.set(negs_instr.rd, rn);
}

// ===============
//  Execute Instr
// ===============

void execute_instr(instr_16 instr, ref cortex_m_cpu cpu) {
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
		case opcode.br_t1:
			return execute_br_t1(instr, cpu);
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
		case opcode.add_sp:
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
		default:
			return;
	}
}

void execute_load_store(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	switch (instr.op) {
		case opcode.str_imm:
			return execute_str_imm(instr, cpu, mem);
		case opcode.strh_imm:
			return execute_strh_imm(instr, cpu, mem);
		case opcode.ldrh_imm:
			return execute_ldrh_imm(instr, cpu, mem);
		case opcode.ldrb_imm:
			return execute_ldrb_imm(instr, cpu, mem);
		case opcode.strb_imm:
			return execute_strb_imm(instr, cpu, mem);
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
    r.cells[index] = value;
    return r;
}

ram_mem_section make_ram_with(size_t[] indices, uint[] values)
{
	ram_mem_section r;
	uint count = 0;
	foreach (i; indices) {
    	r.cells[i] = values[count];
    	count++;
    }
    return r;
}

flash_mem_section make_flash_with(size_t index, uint value)
{
    flash_mem_section f;
    f.cells[index] = value;
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
			      cortex_m_cpu(z: true, n: false, c: true, v: false)),
		test_case(0x10b6,
				  instr_16(op: opcode.asr_imm,       rd: reg.r6,  rm: reg.r6, imm: 2),
			      cortex_m_cpu(r6: 0b10),
			      cortex_m_cpu(r6: 0)),
		test_case(0x1076,
				  instr_16(op: opcode.asr_imm,       rd: reg.r6,  rm: reg.r6, imm: 1),
			      cortex_m_cpu(r6: 0b10),
			      cortex_m_cpu(r6: 0b1)),
		test_case(0x3730, 
			      instr_16(op: opcode.add_imm_8,     rd: reg.r7,  rn: reg.r7, imm: 48),
			      cortex_m_cpu(r7: 0),
			      cortex_m_cpu(r7: 48)),
		test_case(0x4013, 
			      instr_16(op: opcode.and_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r2),
			      cortex_m_cpu(r3: 0b11100, r2: 0b00111),
			      cortex_m_cpu(r3: 0b00100, r2: 0b00111)),
		test_case(0x2300, 
			      instr_16(op: opcode.mov_imm,       rd: reg.r3,              imm: 0),
			      cortex_m_cpu(r3: 0b111),
			      cortex_m_cpu(r3: 0b000)),
		test_case(0x3902, 
			      instr_16(op: opcode.sub_imm_8,     rd: reg.r1,  rn: reg.r1, imm: 2),
			      cortex_m_cpu(r1: 0b0100),
			      cortex_m_cpu(r1: 0b0010)),
		test_case(0x00d9, 
				  instr_16(op: opcode.lsl_imm,       rd : reg.r1, rm: reg.r3, imm: 3),
				  cortex_m_cpu(r3: 0b00010000000000000000000111000000),
				  cortex_m_cpu(r3: 0b00010000000000000000000111000000,
				  			   r1: 0b10000000000000000000111000000000)),
		test_case(0x099b, 
				  instr_16(op: opcode.lsr_imm,       rd: reg.r3,  rm: reg.r3, imm: 6),
				  cortex_m_cpu(r3: 0b00000000000000000111000000000001),
				  cortex_m_cpu(r3: 0b00000000000000000000000111000000)),
		test_case(0x4313, 
			      instr_16(op: opcode.lor_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r2),
			      cortex_m_cpu(r3: 0b1100, r2: 0b0011),
			      cortex_m_cpu(r3: 0b1111, r2: 0b0011)),
		test_case(0x43db, 
			      instr_16(op: opcode.mvn_reg,       rd: reg.r3,  rm: reg.r3),
			      cortex_m_cpu(r3: 0b00000000000000000111000000000001),
			      cortex_m_cpu(r3: 0b11111111111111111000111111111110)),
		test_case(0x4283, 
				  instr_16(op: opcode.cmp_reg,       rn: reg.r3,  rm: reg.r0),
				  cortex_m_cpu(r3: 0, r0: 0),
			      cortex_m_cpu(z: true, n: false, c: true, v: false)),
		test_case(0xd002, 
				  instr_16(op: opcode.br_t1,         cond: condition.eq,      offset: 2),
				  cortex_m_cpu(pc: 10),
				  cortex_m_cpu(pc: 12)),
		test_case(0xb103, 
			      instr_16(op: opcode.cmp_br_z,      rn: reg.r3,              offset: 0),
			      cortex_m_cpu(r3: 0, pc: 10),
				  cortex_m_cpu(r3: 0, pc: 10)),
		test_case(0x4718, 
			      instr_16(op: opcode.bx,            rm: reg.r3),
			      cortex_m_cpu(r3: 0, pc: 10),
				  cortex_m_cpu(r3: 0, pc: 10)),
		test_case(0x1a1b, 
				  instr_16(op: opcode.sub_reg,       rd: reg.r3,  rn: reg.r3, rm: reg.r0),
				  cortex_m_cpu(r3: 10, r0: 3),
				  cortex_m_cpu(r3: 7,  r0: 3)),
		test_case(0xb943, 
			      instr_16(op: opcode.cmp_br_nz,     rn: reg.r3,			  offset: 8),
			      cortex_m_cpu(pc: 10, r3: 1),
				  cortex_m_cpu(pc: 18, r3: 1)),
		/*
		test_case(0xe7cf, 
			      instr_16(op: opcode.b_n,					 				  imm_long: 0xffffffcf),
			      cortex_m_cpu(pc: 10, r3: 1),
				  cortex_m_cpu(pc: 18, r3: 1))
		*/
		////test_case(0xbf00, instr_16(op: if_then))
		test_case(0x469d, 
			      instr_16(op: opcode.mov_high_1,    rd: reg.sp,  rm: reg.r3),
			      cortex_m_cpu(sp: 10, r3: 1),
				  cortex_m_cpu(sp: 1,  r3: 1)),
		test_case(0x460f, 
				  instr_16(op: opcode.mov_lo,        rd: reg.r7,  rm: reg.r1),
				  cortex_m_cpu(r7: 10, r1: 1),
				  cortex_m_cpu(r7: 1,  r1: 1)),
		test_case(0x4798, 
				  instr_16(op: opcode.blx,           rm: reg.r3),
				  cortex_m_cpu(pc: 10, r3: 20),
				  cortex_m_cpu(pc: 20, lr:  8, r3: 20)),
		test_case(0xaf00, 
			      instr_16(op: opcode.add_sp,        rd: reg.r7, 			  imm: 0),
			      cortex_m_cpu(sp: 10, r7: 20),
				  cortex_m_cpu(sp: 10, r7: 10)),
		test_case(0xb092, 
			      instr_16(op: opcode.sub_sp,		 						  imm: 72),
			      cortex_m_cpu(sp: 90),
				  cortex_m_cpu(sp: 18)),
		test_case(0x1d3b, 
			      instr_16(op: opcode.add_imm_3,     rd: reg.r3,  rn: reg.r7, imm: 4),
			      cortex_m_cpu(r3: 3, r7: 4),
				  cortex_m_cpu(r3: 8, r7: 4)),
		test_case(0x4413, 
				  instr_16(op: opcode.add_lo_reg,    rd: reg.r3,  rn: reg.r3, rm: reg.r2),
				  cortex_m_cpu(r3: 3, r2: 2),
				  cortex_m_cpu(r3: 5, r2: 2)),
		test_case(0x409a, 
			      instr_16(op: opcode.lsl_reg,       rd: reg.r2,  rn: reg.r2, rm: reg.r3),
			      cortex_m_cpu(r2: 0b0101, r3: 1),
			      cortex_m_cpu(r2: 0b1010, r3: 1)),
		test_case(0x40da, 
			      instr_16(op: opcode.lsr_reg,	     rd: reg.r2,  rn: reg.r2, rm: reg.r3),
			      cortex_m_cpu(r2: 0b1010, r3: 1),
			      cortex_m_cpu(r2: 0b0101, r3: 1)),
		test_case(0xa201, 
			      instr_16(op: opcode.adr,			 rd: reg.r2,  			  imm: 4),
			      cortex_m_cpu(r2: 10, pc: 10),
			      cortex_m_cpu(r2: 14, pc: 10)),
		test_case(0x4652, 
			      instr_16(op: opcode.mov_high_2, 	 rd: reg.r2,  rm: reg.r10),
			      cortex_m_cpu(r2: 1, r10: 3),
			      cortex_m_cpu(r2: 3, r10: 3)),
		/*
		test_case(0x9300, 
			      instr_16(op: opcode.str_sp,		 rt: reg.r3,			  imm: 0),
			      cortex_m_cpu(r2: 1, r10: 3),
			      cortex_m_cpu(r2: 3, r10: 3))
		*/
		test_case(0x1891, 
			      instr_16(op: opcode.add_reg, 		 rd: reg.r1,  rn: reg.r2, rm: reg.r2),
			      cortex_m_cpu(r1: 10, r2: 10),
			      cortex_m_cpu(r1: 20, r2: 10)),
		test_case(0x458c, 
			      instr_16(op: opcode.cmp_high_1,    rn: reg.r12, rm: reg.r1),
			      cortex_m_cpu(r3: 0, r0: 0),
			      cortex_m_cpu(z: true, n: false, c: true, v: false)),
		test_case(0x4463, 
				  instr_16(op: opcode.add_high_reg_1,rd: reg.r3,  rn: reg.r3, rm: reg.r12),
				  cortex_m_cpu(r3: 3, r12: 4),
				  cortex_m_cpu(r3: 7, r12: 4)),
		test_case(0x1e54, 
			      instr_16(op: opcode.sub_imm_3,     rd: reg.r4,  rn: reg.r2, imm: 1),
			      cortex_m_cpu(r4: 7, r2: 9),
			      cortex_m_cpu(r4: 8, r2: 9)),
		test_case(0x44e6, 
			      instr_16(op: opcode.add_high_reg_2,rd: reg.lr,  rn: reg.lr, rm: reg.r12),
			      cortex_m_cpu(lr:  7, r12: 9),
			      cortex_m_cpu(lr: 16, r12: 9)),
		test_case(0x4572, 
			      instr_16(op: opcode.cmp_high_2,	 rn: reg.r2,  rm: reg.lr),
			      cortex_m_cpu(r2: 0, lr: 0),
			      cortex_m_cpu(z: true, n: false, c: true, v: false)),
		test_case(0x4241, 
			      instr_16(op: opcode.negs,			 rd: reg.r1,  rn: reg.r0),
				  cortex_m_cpu(r0: 1),
			      cortex_m_cpu(r1: -1, r0: 1))
	];

	test_case_mem[] tests_mem = [
		test_case_mem(0x608b, 
			          instr_16(op: opcode.str_imm,       rt: reg.r3,  rn: reg.r1, imm: 8),
			          cortex_m_cpu(r3: 0b0101, r1: 10),
			          cortex_m_cpu(r3: 0b0101, r1: 10),
			          memory(ram: make_ram_with(18, 0)),
			          memory(ram: make_ram_with(18, 0b0101))),
		test_case_mem(0x80fb, 
			          instr_16(op: opcode.strh_imm,      rt: reg.r3,  rn: reg.r7, imm: 6),
			          cortex_m_cpu(r3: 0x0000eeee, r7: 10),
			          cortex_m_cpu(r3: 0x0000eeee, r7: 10),
			          memory(ram: make_ram_with(16, 0xffffffff)),
			          memory(ram: make_ram_with(16, 0xffffeeee))),
		test_case_mem(0x88fb, 
			          instr_16(op: opcode.ldrh_imm,      rt: reg.r3,  rn: reg.r7, imm: 6),
			          cortex_m_cpu(r3: 0xffffffff, r7: 10),
			          cortex_m_cpu(r3: 0xffffeeee, r7: 10),
			          memory(ram: make_ram_with(16, 0x0000eeee)),
			          memory(ram: make_ram_with(16, 0x0000eeee))),
		test_case_mem(0x781a, 
					  instr_16(op: opcode.ldrb_imm,      rt: reg.r2,  rn: reg.r3, imm: 0),
					  cortex_m_cpu(r2: 0xffffffff, r3: 10),
			          cortex_m_cpu(r2: 0xffffffee, r3: 10),
			          memory(ram: make_ram_with(10, 0x000000ee)),
			          memory(ram: make_ram_with(10, 0x000000ee))),
		test_case_mem(0x701a, 
				      instr_16(op: opcode.strb_imm,      rt: reg.r2,  rn: reg.r3, imm: 0),
				      cortex_m_cpu(r2: 0x000000ee, r3: 10),
			          cortex_m_cpu(r2: 0x000000ee, r3: 10),
			          memory(ram: make_ram_with(10, 0xffffffff)),
			          memory(ram: make_ram_with(10, 0xffffffee))),
		test_case_mem(0x68fb, 
					  instr_16(op: opcode.ldr_imm,       rt: reg.r3,  rn: reg.r7, imm: 12),
					  cortex_m_cpu(r3: 0x000000ff, r7: 10),
			          cortex_m_cpu(r3: 0x000000ee, r7: 10),
			          memory(ram: make_ram_with(22, 0x000000ee)),
			          memory(ram: make_ram_with(22, 0x000000ee))),
		test_case_mem(0x4803, 
					  instr_16(op: opcode.ldr_pool,      rt: reg.r0,              imm: 12),
					  cortex_m_cpu(r0: 0x000000ff, pc: 10),
			          cortex_m_cpu(r0: 0x000000ee, pc: 10),
			          memory(flash: make_flash_with(22, 0x000000ee)),
			          memory(flash: make_flash_with(22, 0x000000ee))),
		test_case_mem(0xb510, 
			      	  instr_16(op: opcode.push_mult_reg, reg_list: [reg.lr, reg.r4]),
			      	  cortex_m_cpu(sp: memory.stack_base, lr: 0x000000ff, r4: 0x000000ee),
			          cortex_m_cpu(sp: memory.stack_base-2, lr: 0x000000ff, r4: 0x000000ee),
			          memory(),
			          memory(ram: make_ram_with([memory.stack_base, memory.stack_base-1],
			          							[0x000000ff, 0x000000ee]))),
		test_case_mem(0xbd10, 
				      instr_16(op: opcode.pop_mult_reg,  reg_list: [reg.pc, reg.r4]),
				      cortex_m_cpu(sp: memory.stack_base-2),
			          cortex_m_cpu(sp: memory.stack_base, pc: 0x000000ee, r4: 0x000000ff),
			          memory(ram: make_ram_with([memory.stack_base, memory.stack_base-1],
			          							[0x000000ff, 0x000000ee])),
				      memory()),
		test_case_mem(0x5cd3, 
			      	  instr_16(op: opcode.ldrb_reg,      rt: reg.r3,  rn: reg.r2, rm: reg.r3),
			          cortex_m_cpu(r2: 10, r3: 10),
				      cortex_m_cpu(r3: 0x000000ee, r2: 10),
				      memory(ram: make_ram_with(20, 0xffffffee)),
				      memory(ram: make_ram_with(20, 0xffffffee))),
		test_case_mem(0x58fb, 
			          instr_16(op: opcode.ldr_reg,	     rt: reg.r3,  rn: reg.r7, rm: reg.r3),
			          cortex_m_cpu(r3:         10, r7: 10),
			          cortex_m_cpu(r3: 0xffffffee, r7: 10),
			          memory(ram: make_ram_with(20, 0xffffffee)),
				      memory(ram: make_ram_with(20, 0xffffffee)))
	];

	foreach (t; tests) {
		execute_instr(t.instr, t.before);
		assert(
		    t.before == t.expected,
		    format("Failed for instruction 0x%04X", t.instr_bytes)
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
}

enum shift_type : ubyte {
	lsl,
	lsr,
	asr,
	rrx,
	ror,
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

// ===========
//  Parse ADD
// ===========

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

instr_32 parse_nop_32(uint instr) {
	instr_32 res;
	res.op = opcode.nop_32;
	return res;
}

// ====================
//  Parse Pop Mult Reg
// ====================

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
	int rotate_by = (i << 3) | imm_3;
	uint rotated = rotr(imm_8, rotate_by * 2 + 1);
	res.imm = rotated;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// ==================
//  Parse AND IMM 32
// ==================

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
	int rotate_by = (i << 3) | imm_3;
	uint rotated = rotr(imm_8, rotate_by * 2);
	res.imm = rotated;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	//writeln(res.imm);
	return res;
}

// ============
//  Parse UDIV
// ============

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

/*
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
	writeln(res.width);
	return res;
}

// ===========
//  Parse MUL
// ===========

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

// ===========
//  Parse LSR
// ===========

/*
	Multiply, Multiply Accumulate, and Absolute Difference
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
instr_32 parse_lsr_32(uint instr) {
	instr_32 res;
	res.op = opcode.lsr_32;
	ubyte rm = cast(ubyte)(instr & 0xf);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	res.rn = cast(reg)(rn);
	return res;
}

// ===========
//  Parse ORR
// ===========

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
	int rotate_by = (i << 3) | imm_3;
	uint rotated = rotr(imm_8, rotate_by * 2 + 1);
	res.imm = rotated;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	writeln(res.imm);
	return res;
}

// ===========
//  Parse ADD
// ===========

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
	int rotate_by = (i << 3) | imm_3;
	uint rotated = rotr(imm_8, rotate_by * 2);
	res.imm = rotated;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	writeln(res.imm);
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
instr_32 parse_bit_fleld_clear_32(uint instr) {
	instr_32 res;
	res.op = opcode.add_32;
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

// =================
//  Parse Bit Clear
// =================

/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:11] 11110
	[10] i
	[9:5] 00001
	[4] S
	[3:0] Rn 
	Second Half-Word:
	[15] 0
	[14:12] imm3
	[11:8] Rd
	[7:0] imm8
*/
instr_32 parse_bit_clear_32(uint instr) {
	instr_32 res;
	res.op = opcode.bit_clear_32;
	ubyte imm_8 = cast(ubyte)(instr & 0xff);
	ubyte rd = cast(ubyte)((instr >> 8) & 0xf);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
 	uint rotate_by = (i << 3) | imm_3;
	uint rotated = rotr(imm_8, rotate_by * 2);
	res.imm = rotated;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	writeln(res.imm);
	return res;
}

// ===========
//  Parse MOV
// ===========

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
	writeln("xxxxx");
	writeln(res.imm);
	return res;
}

// =============
//  Parse LDRSB
// =============

/*
	Multiply, Multiply Accumulate, and Absolute Difference
	First Half-Word:
	[15:4] 111110011001
	[3:0] Rn
	Second Half-Word:
	[15:12] Rt
	[11:0] imm12
*/
instr_32 parse_ldrsb_32(uint instr) {
	instr_32 res;
	res.op = opcode.ldrsb_32;
	uint imm_12 = cast(ubyte)(instr & 0xfff);
	ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.imm = imm_12;
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	writeln("xxxxx");
	writeln(res.imm);
	return res;
}

// ===========
//  Parse STR
// ===========

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
	writeln("xxxxx");
	writeln(res.imm);
	return res;
}

// ===========
//  Parse DSB
// ===========

instr_32 parse_dsb(uint instr) {
	instr_32 res;
	res.op = opcode.dsb;
	return res;
}

// ===========
//  Parse RSB
// ===========

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
	writeln("xxxxx");
	uint imm = rotr(imm_8, rotate_by * 2);
	res.imm = imm;
	writeln(res.imm);
	return res;
}

// =============
//  Parse UMULL
// =============

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
	writeln("xxxxx");
	return res;
}

// ============
//  Parse STRD
// ============

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
	res.rt = cast(reg)(rt);
	res.rt_2 = cast(reg)(rt_2);
	res.rn = cast(reg)(rn);
	uint imm = (imm_8 << 2) | 0b00;
	res.imm = imm;
	writeln("xxxxx");
	writeln(res.imm);
	return res;
}

// =========
//  Parse B
// =========

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
instr_32 parse_b_32(uint instr) {
	instr_32 res;
	res.op = opcode.b_32;
	ushort imm_11 = cast(ushort)(instr & 0x7ff);
	ushort imm_6 = cast(ushort)((instr >> 16) & 0x3f);
	ubyte j1 = cast(ubyte)((instr >> 13) & 0b1);
	ubyte j2 = cast(ubyte)((instr >> 11) & 0b1);
	ubyte s = cast(ubyte)((instr >> 26) &0b1);
	int imm_32 = (s << 20) | (!(j1 ^ s) << 19) | (!(j2 ^ s) << 18) | (imm_6 << 12) | (imm_11 << 1) | 0b0;
	if (s == 0b1) {
		imm_32 |= 0xffe00000;
	}
	res.offset = imm_32;
	writeln(res.offset);
	return res;
}

// =====================
//  Parse PUSH MULT REG
// =====================

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
	ubyte i = cast(ubyte)((instr >> 26) & 0b1);
	uint rotate_by = cast(ubyte)((i << 3) | imm_3);
	uint rotated = rotr(imm_8, rotate_by * 2);
	res.imm = rotated;
	res.rd = cast(reg)(rd);
	writeln(res.imm);
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
	writeln(res.imm);
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
	writeln(res.imm);
	return res;
}

// ===========
//  Parse MLS
// ===========

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
//  Parse LDRSH(immediate)
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
//  Parse BIC(Register)
// =====================

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
		case opcode.lsr_32:
			return parse_lsr_32(instr);
		case opcode.orr_32:
			return parse_orr_32(instr);
		case opcode.add_32:
			return parse_add_32(instr);
		case opcode.bit_clear_32:
			return parse_bit_clear_32(instr);
		case opcode.mov_16_imm_32:
			return parse_mov_16_imm_32(instr);
		case opcode.ldrsb_32:
			return parse_ldrsb_32(instr);
		case opcode.str_reg_32:
			return parse_str_reg_32(instr);
		case opcode.dsb:
			return parse_dsb(instr);
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
		case opcode.bic_reg_32:
			return parse_bic_reg_32(instr);
		default:
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
				  instr_32(op: opcode.lsr_32, rd: reg.r3, rn: reg.r2, rm: reg.r3)),
		test_case(0xf4434380, // orr.w	r3, r3, #16384	@ 0x4000
				  instr_32(op: opcode.orr_32, rd: reg.r3, rn: reg.r3, imm: 16384)),
		test_case(0xf1070314, // add.w	r3, r7, #20
				  instr_32(op: opcode.add_32, rd: reg.r3, rn: reg.r7, imm: 20)),
		test_case(0xf0230310, // bic.w	r3, r3, #16
				  instr_32(op: opcode.bit_clear_32, rd: reg.r3, rn: reg.r3, imm: 16)),
		test_case(0xf64f03ff, // movw	r3, #63743	@ 0xf8ff
				  instr_32(op: opcode.mov_16_imm_32, rd: reg.r3, imm: 63743)),
		// 1111 0110 0100 1111 000 0011 1111 1111
		test_case(0xf9973007, // ldrsb.w	r3, [r7, #7]
				  instr_32(op: opcode.ldrsb_32, rt: reg.r3, rn: reg.r7, imm: 7)),
		// 1111 1001 1001 0111 0011 0000 0000 0111
		test_case(0xf8412023, // str.w	r2, [r1, r3, lsl #2]
				  instr_32(op: opcode.str_reg_32, rt: reg.r2, rn: reg.r1, rm: reg.r3, imm: 2)),
		// 1111 1000 0100 0001 0010 0000 0010 0011
		test_case(0xf3bf8f4f, 
				  instr_32(op: opcode.dsb)),
		// 1111 0011 1011 1111 1000 1111 0100 1111
		test_case(0xf1c30307, // rsb	r3, r3, #7
				  instr_32(op: opcode.rsb_32, rd: reg.r3, rn: reg.r3, imm: 7)),
		test_case(0xfba22303, // umull	r2, r3, r2, r3
				  instr_32(op: opcode.umull_32, rd_lo: reg.r2, rd_hi: reg.r3, rn: reg.r2, rm: reg.r3)),
		// 1111 1011 1010 0010 0010 0011 0000 0011
		test_case(0xe9c72300, // strd	r2, r3, [r7]
				  instr_32(op: opcode.strd_32, rt: reg.r2, rt_2: reg.r3, rn: reg.r7, imm: 0)),
		// 1110 1001 1100 0111 0010 0011 0000 0000
		//		  instr_32(op: opcode.strd_32)),
		test_case(0xf67fae90, // bls.w	8004360
				  instr_32(op: opcode.b_32, offset: -736)),
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
				  instr_32(op: opcode.bit_or_not_32, rd: reg.r2, imm: 64)),
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
				  instr_32(op: opcode.b_32, offset: -138))
	];//

	foreach (t; tests) {
		assert(
		    decode_instr(t.instr) == t.expected,
		    format("Failed for instruction 0x%08X", t.instr)
		);
    }
}


