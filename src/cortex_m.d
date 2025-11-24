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
    	writeln("Check");
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
			writeln("hereb");
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
			writeln("herec");
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
						writeln("hereb");
						return opcode.push_mult_reg_32;
					}
				}
			}
		}
		if ((op2 & op2_32.ld_str_dual) == 0b0000100) {
			writeln("herel");
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
		writeln("herea");
		ubyte op = cast(ubyte)((instr >> 15) & 0b1); 
		ubyte rd = cast(ubyte)((instr >> 20) & 0b1111); 
		if (op) {
			ubyte _op1 = cast(ubyte)((instr >> 12) & 0b111);
			ubyte _op = cast(ubyte)((instr >> 20) & 0b1111111);
			writeln("here0");
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
			writeln("here0000000");
			if (_op == 0b0011) {
				if (rn != 0b1111) {
					return opcode.bit_or_not_32;
				}
				if (rn == 0b1111) {
					return opcode.bit_not_32;
				}
			}
			writeln("here0000001");
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

struct instr_16 {
	opcode op;
	reg rd;
	reg rm;
	reg rn;
	ubyte imm;
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

instr_16 decode_instr(ushort instr) {
	instr_16 res;
	auto op = decode_mnemonic(instr);
	if (op == opcode.cmp_imm) {
		return parse_cmp_imm(instr);
	}
	return res;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		instr_16 expected;
	}

	test_case[] tests = [
		test_case(0x2b00, instr_16( op: opcode.cmp_imm, rn: reg.r3, imm: 0 ))
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

struct cortex_m_cpu {
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
	uint ldr;
	uint pc;

	bool n;
	bool z;
	bool c;
	bool v;
}

void execute_cmp_imm(instr_16 cmp_imm_instr, ref cortex_m_cpu cpu) {
	//auto rn_val = cpu.get(cmp_imm_instr.rn);
	//uint res = rn_val - cmp_imm_instr.imm;
	return;
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
    		writeln(instr);
    		auto res = decode_mnemonic(value);
    		writeln(instr);
    		assert(res != opcode.invalid, "Error decoding instruction opcode: " ~ instr);
    	}
    	if (instr.length == 8) {
    		auto copy = instr;
    		uint value = parse!uint(copy, 16);
    		writeln(instr);
    		auto res = decode_mnemonic_32(value);
    		writeln(instr);
    		assert(res != opcode.invalid, "Error decoding instruction opcode: " ~ instr);
    	}
    }
}




