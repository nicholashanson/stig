import std.format;
import std.conv;

enum opcode : ubyte {
	adc_reg,
	add_32,
	add_high_reg_1,
	add_high_reg_2,
	add_imm_3,
	add_imm_8,
	add_imm_32,
	add_lo_reg,
	add_reg,
	add_sp,	
	add_sp_t1,
	add_sp_t2,
	adr,
	adr_32,
	and_reg,
	and_imm_32,
	asr_imm,
	b_32,
	b_cond_32,
	b_imm_11,
	b_uncond_32,
	bfc_32,
	bfi_32,
	bic_imm_32,
	bit_not_32,
	bit_or_not_32,
	bl_32,
	blx,
	b_cond,
	bx,
	clz_32,
	cmn_32,
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
	mla_32,
	mls_32,
	mov_16_imm_32,
	mov_high_1,
	mov_high_2,
	mov_high_reg,
	mov_imm,
	mov_imm_32_t2,
	mov_lo,
	movt_32,
	mul_32,
	mvn_reg,
	mrs_32,
	msr_32,
	negs,
	nop,
	nop_32,
	orn_32,
	orr_32,
	pld_32,
	pld_imm_32,
	pld_reg_32,
	pop_mult_reg,
	pop_mult_reg_32,
	push_mult_reg,
	push_mult_reg_32,
	rev,
	rsb_32,
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
	svc,
	uadd8_32,
	uxth,

	// --------------------------Data Processing (Shifted Register)-------------------------- 
	and_reg_32, // bitwise AND
	add_reg_32, // add
	adc_reg_32, // add with carry
	bic_reg_32, // bitwise bit clear
	cmn_reg_32, // compare negative
	cmp_reg_32, // compare
	mvn_reg_32, // bitwise NOT
	orn_reg_32, // bitwise OR NOT
	orr_reg_32, // bitwise OR
	sbc_reg_32,	// subtract with carry
	sub_reg_32,
	tst_reg_32,	// test
	// -------------------------------------------------------------------------------------- 
	// --------------------------Move Register and Immediate Shifts-------------------------- 
	asr_imm_32,	
	lsl_imm_32,
	lsr_imm_32,
	mov_reg_32,	// move
	ror_imm_32,
	rrx_32,
	// -------------------------------------------------------------------------------------- 
	invalid
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
	asr             = 0b010,
	cmp				= 0b101,
	lsl             = 0b000,
	lsr 			= 0b001,
	movs            = 0b100,
	subs_8			= 0b111
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

// =================
//  Decode Mnemonic
// =================

opcode decode_mnemonic(ushort instr) { 
    if (((instr >> 14) & 0b11) == instr_grp.alu_imm) {
    	ubyte opcode_ = cast(ubyte)((instr >> 9) & 0b11111);
    	ubyte opcode_short = cast(ubyte)((opcode_ >> 2) & 0b111);
    	if (opcode_short == alu_imm.cmp) {
    		return opcode.cmp_imm;
    	}
    	if (opcode_short == alu_imm.movs) {
    		return opcode.mov_imm;
    	}
    	if (opcode_short == alu_imm.subs_8) {
    		return opcode.sub_imm_8;
    	}
    	if (opcode_ == 0b01110) {
    		return opcode.add_imm_3;
    	}
    	if (opcode_short == alu_imm.add_8) {
    		return opcode.add_imm_8;
    	}
    	if (opcode_short == alu_imm.asr) {
    		return opcode.asr_imm;
    	}
    	if (opcode_short == alu_imm.lsl) {
    		return opcode.lsl_imm;
    	}
    	if (opcode_short == alu_imm.lsr) {
    		return opcode.lsr_imm;
    	}
    	if (opcode_ == 0b01101) {
    		return opcode.sub_reg;
    	}
    	if (opcode_ == 0b01100) {
    		return opcode.add_reg;
    	}
    	if (opcode_ == 0b01111) {
    		return opcode.sub_imm_3;
    	}
    }
    if (cast(ubyte)((instr >> 10) & 0b111111) == instr_grp.data_proc) {
    	ubyte opcode_ = cast(ubyte)((instr >> 6) & 0b1111);
    	if (opcode_ == data_proc.and) {
    		return opcode.and_reg;
    	}
    	if (opcode_ == data_proc.lor) {
    		return opcode.lor_reg;
    	}
    	if (opcode_ == data_proc.mvn) {
    		return opcode.mvn_reg;
    	}
    	if (opcode_ == data_proc.cmp) {
    		return opcode.cmp_reg;
    	}
    	if (opcode_ == data_proc.lsl_reg) {
    		return opcode.lsl_reg;
    	}
    	if (opcode_ == data_proc.lsr_reg) {
    		return opcode.lsr_reg;
    	}
    	if (opcode_ == data_proc.adc_reg) {
    		return opcode.adc_reg;
    	}
    	if (opcode_ == data_proc.negs) {
    		return opcode.negs;
    	}
    	if (opcode_ == data_proc.tst) {
    		return opcode.tst;
    	}
    }
    if (((instr >> 12) & 0b1111) == instr_grp.single_str_1) {
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
    if (((instr >> 13) & 0b111)  == instr_grp.single_str_2) {
    	if (((instr >> 12) & 0b1) == 0) {
    		if (((instr >> 11) & 0b1) == 0) {
    			return opcode.str_imm;
    		}
    	}
    	if (((instr >> 12) & 0b1) == 0) {
    		if (((instr >> 11) & 0b1) == 1) {
    			return opcode.ldr_imm;
    		}
    	}
    	if (((instr >> 12) & 0b1) == 1) {
    		if (((instr >> 11) & 0b1) == 0) {
    			return opcode.strb_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (((instr >> 11) & 0b1) == 1) {
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
    if (((instr >> 12) & 0b1111) == 0b1101) {
    	if (((instr >> 8) & 0b1111) == 0b1111) {
    		return opcode.svc;

    	} else {
    		return opcode.b_cond;
    	}
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == instr_grp.misc) {
    	ubyte _opcode_ = cast(ubyte)((instr >> 5) & 0b1111111);
    	if ((_opcode_ & 0b1111100) == 0b0000000) {
    		if (cast(ubyte)(instr >> 12) == 0b1010) {
				return opcode.add_sp_t1;
			}
			if (cast(ubyte)(instr >> 12) == 0b1011) {
				return opcode.add_sp_t2;
			}
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
    if (cast(ubyte)((instr >> 10) & 0b111110) == 0b101010) {
		if (cast(ubyte)(instr >> 12) == 0b1010) {
			return opcode.add_sp_t1;
		}
		if (cast(ubyte)(instr >> 12) == 0b1011) {
			return opcode.add_sp_t2;
		}
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
		test_case(0x415b, opcode.adc_reg),
		test_case(0x4463, opcode.add_high_reg_1),
		test_case(0x44e6, opcode.add_high_reg_2),
		test_case(0x1d3b, opcode.add_imm_3),
		test_case(0x3730, opcode.add_imm_8),
		test_case(0x4413, opcode.add_lo_reg),
		test_case(0x1891, opcode.add_reg),
		test_case(0xa904, opcode.add_sp_t1),
		test_case(0xaf00, opcode.add_sp_t1),
		test_case(0xb005, opcode.add_sp_t2),
		test_case(0xa201, opcode.adr),
		test_case(0x4013, opcode.and_reg),
		test_case(0x10b6, opcode.asr_imm),
		test_case(0xd002, opcode.b_cond),
		test_case(0xe7cf, opcode.b_imm_11),
		test_case(0xe7fe, opcode.b_imm_11),
		test_case(0x4798, opcode.blx),
		test_case(0x4718, opcode.bx),
		test_case(0xb943, opcode.cmp_br_nz),
		test_case(0xb103, opcode.cmp_br_z),
		test_case(0x458c, opcode.cmp_high_1),
		test_case(0x4572, opcode.cmp_high_2),
		test_case(0x2b00, opcode.cmp_imm),
		test_case(0x4283, opcode.cmp_reg),
		test_case(0xb661, opcode.cps),
		test_case(0xbf08, opcode.if_then),
		test_case(0x681b, opcode.ldr_imm),
		test_case(0x682b, opcode.ldr_imm),
		test_case(0x68fb, opcode.ldr_imm),
		test_case(0x4803, opcode.ldr_pool),
		test_case(0x4a0a, opcode.ldr_pool),
		test_case(0x58d4, opcode.ldr_reg),
		test_case(0x58fb, opcode.ldr_reg),
		test_case(0x9d08, opcode.ldr_sp),
		test_case(0x781a, opcode.ldrb_imm),
		test_case(0x5cd3, opcode.ldrb_reg),
		test_case(0x88fb, opcode.ldrh_imm),
		test_case(0x4313, opcode.lor_reg),
		test_case(0x00d9, opcode.lsl_imm),
		test_case(0x409a, opcode.lsl_reg),
		test_case(0x099b, opcode.lsr_imm),
		test_case(0x40da, opcode.lsr_reg),
		test_case(0x4680, opcode.mov_high_1),
		test_case(0x469d, opcode.mov_high_1),
		test_case(0x4652, opcode.mov_high_2),
		test_case(0x2300, opcode.mov_imm),
		test_case(0x460f, opcode.mov_lo),
		test_case(0x43db, opcode.mvn_reg),
		test_case(0x4241, opcode.negs),
		test_case(0xbf00, opcode.nop),
		test_case(0xbd10, opcode.pop_mult_reg),
		test_case(0xb480, opcode.push_mult_reg),
		test_case(0xb510, opcode.push_mult_reg),
		test_case(0xb580, opcode.push_mult_reg),
		test_case(0x3902, opcode.sub_imm_8),	
		test_case(0x6013, opcode.str_imm),
		test_case(0x608b, opcode.str_imm),
		test_case(0x50c4, opcode.str_reg),
		test_case(0x9300, opcode.str_sp),
		test_case(0x9301, opcode.str_sp),
		test_case(0x701a, opcode.strb_imm),
		test_case(0x559a, opcode.strb_reg),
		test_case(0x80fb, opcode.strh_imm),
		test_case(0x1e54, opcode.sub_imm_3),
		test_case(0x1a1b, opcode.sub_reg),
		test_case(0xb092, opcode.sub_sp),
		test_case(0xdf00, opcode.svc),
		test_case(0x4208, opcode.tst),
		test_case(0xb2db, opcode.uxtb),
		test_case(0xb29a, opcode.uxth)
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
	data_proc_shift_reg 	= 0b0100000,	// Data Processing (Shifted Register)
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

// ==========================
//  Decode Mov Reg Imm Shift
// ==========================

opcode decode_mov_reg_imm_shift(uint instr) {
	ubyte type  = cast(ubyte)((instr >>  4) & 0x3);
	ubyte imm_2 = cast(ubyte)((instr >>  6) & 0x3);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x7);

	ubyte imm_5 = cast(ubyte)((imm_3 << 2) | imm_2);
	final switch (type)
	{
		case 0b00: return imm_5 == 0 ? opcode.mov_reg_32 : opcode.lsl_imm_32;
		case 0b01: return opcode.lsr_imm_32;
		case 0b10: return opcode.asr_imm_32;
		case 0b11: return imm_5 == 0 ? opcode.rrx_32 : opcode.ror_imm_32;
	}
	return opcode.invalid;
}

// ============================
//  Decode Data Proc Shift Reg
// ============================

opcode decode_data_proc_shift_reg(uint instr) {
	ubyte op = cast(ubyte)((instr >> 21) & 0xf);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	ubyte rd = cast(ubyte)((instr >>  8) & 0xf);
	ubyte s  = cast(ubyte)((instr >> 20) & 0x1);
	enum ubyte pc = 0xf;
	final switch (op)
	{
		case 0b1101: 
			if (rd == pc && s == 1) return opcode.cmp_reg_32; 
			if (rd != pc) return opcode.sub_reg_32;
			return opcode.invalid;
		case 0b1011: return opcode.sbc_reg_32;
		case 0b1010: return opcode.adc_reg_32;
		case 0b1000: return rd == pc ? opcode.cmn_reg_32 : opcode.add_reg_32;
		case 0b0011: return rn == pc ? opcode.mvn_reg_32 : opcode.orn_reg_32; 
		case 0b0010: return rn == pc ? decode_mov_reg_imm_shift(instr) : opcode.orr_reg_32;
		case 0b0001: return opcode.bic_reg_32;
		case 0b0000:
			if (rd == pc && s == 1) return opcode.tst_reg_32;
			if (rd != pc) return opcode.and_reg_32;
			return opcode.invalid;
	}
	return opcode.invalid;
}

// ==========================
//  Decode Data Proc Bin Imm
// ==========================

opcode decode_data_proc_bin_imm(uint instr) {
	enum ubyte pc = 0xf;
	ubyte op = cast(ubyte)((instr >> 20) & 0x1f);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	final switch (op)
	{
		case 0b00000: return rn == pc ? opcode.adr_32 : opcode.add_imm_32;
		case 0b10110: return rn == pc ? opcode.bfc_32 : opcode.bfi_32;
		case 0b00100: return opcode.mov_16_imm_32;
		case 0b01100: return opcode.movt_32;
		case 0b10100: return opcode.sbfx_32;
		case 0b01010: return rn == pc ? opcode.adr_32 : opcode.sub_imm_32;
		case 0b11100: return opcode.ubfx_32;
	}
}

opcode decode_mnemonic_32(uint instr) {
	ubyte op1 = cast(ubyte)((instr >> 27) & 0b11);
	ubyte op2 = cast(ubyte)((instr >> 20) & 0b1111111);
	if (op1 == op1_32.grp1) { 
		if ((op2 & op2_32.data_proc_shift_reg) == op2_32.data_proc_shift_reg) {
			return decode_data_proc_shift_reg(instr);
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
					return opcode.tst_reg_32;
				}
			}
			if (((_op & 0b11110) == 0b00100) && (rn != 0b1111)) {
				return opcode.orr_32;
			}
			if (((_op & 0b11110) == 0b00100) && (rn == 0b1111)) {	
				return opcode.mov_reg_32;
			}
			if ((_op & 0b11110) == 0b00110) {
				if (rn != 0b1111) {
					return opcode.bit_or_not_32;
				}
				if (rn == 0b1111) {
					return opcode.bit_not_32;
				}
			}
			// 0xf1100f16
			if (((_op & 0b11110) == 0b10000) && (rd_ == 0b1111)) {	
				return opcode.cmn_32;
				// 1111 0001 0001 0000 0000 1111 0001 0110
			}
			if (((_op & 0b11110) == 0b10000) && (rd_ != 0b1111)) {	
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
			return decode_data_proc_bin_imm(instr);
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
			ubyte _op1 = cast(ubyte)((instr >> 20) & 0b111);
			ubyte _op2 = cast(ubyte)((instr >>  4) & 0b11);
			if (_op1 == 0b000) { 
				if (_op2 == 0b00) {
					if (ra == 0b1111) {
						return opcode.mul_32;
					}
					if (ra != 0b1111) {
						return opcode.mla_32;
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
		test_case(0xeb0101a3, opcode.add_reg_32),
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
		test_case(0xebb2080a, opcode.sub_reg_32),
		test_case(0xeb63090b, opcode.sbc_reg_32),
		test_case(0xeb45030b, opcode.adc_reg_32),
		test_case(0xf06f0240, opcode.bit_not_32),
		test_case(0xe8533f00, opcode.ld_rex),
		test_case(0xe8412300, opcode.str_rex),
		test_case(0xfb0e7711, opcode.mls_32),
		test_case(0xf9b4500c, opcode.ldh_32),
		test_case(0xea1c0f0e, opcode.tst_reg_32),
		test_case(0xea010808, opcode.and_reg_32),
		test_case(0xea23030c, opcode.bic_reg_32),
		test_case(0xf7ffbfbb, opcode.b_uncond_32),
		test_case(0xeba30605, opcode.sub_reg_32),
		test_case(0xea4f06a6, opcode.asr_imm_32),
		// 1110 1010 0100 1111 0000 0110 1010 0110
		test_case(0xf8553b04, opcode.ldr_imm_32_t4), // f8553b04
		test_case(0xf7ffb8f7, opcode.b_uncond_32),
		test_case(0xf8441023, opcode.str_reg_32),
		test_case(0xf8c46188, opcode.str_imm_32_t3),
		// 1111 1000 1100 0100 0110 0001 1000 1000
		test_case(0xe8bd4008, opcode.pop_mult_reg_32),
		// 1110 1000 1011 1101 0100 0000 0000 1000
		test_case(0xeb0101a3, opcode.add_reg_32),
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
	 	test_case(0xf0230301, opcode.bic_imm_32),
	 	test_case(0xfb035500, opcode.mla_32),
	 	test_case(0xfab0f080, opcode.clz_32),
	 	test_case(0xf1100f16, opcode.cmn_32),
	 	test_case(0xf8973033, opcode.ldrb_imm_32_t2),
	 	test_case(0xf8a320f8, opcode.strh_imm_32_t2),
	 	test_case(0xe8b04ff0, opcode.ldmia),
	    test_case(0xea620205, opcode.orn_reg_32),
	    test_case(0xea4f06a6, opcode.asr_imm_32)
	];

	foreach (t; tests) {
		auto actual = decode_mnemonic_32(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%08X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}