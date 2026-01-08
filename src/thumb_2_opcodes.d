import std.format;
import std.conv;

enum opcode : ubyte {
	adc_reg,
	add_32,
	add_high_reg_1,
	add_high_reg_2,
	add_imm_3,
	add_imm_8,
	add_lo_reg,
	add_reg,
	add_sp,	
	add_sp_t1,
	add_sp_t2,
	adr,
	and_imm_32,
	and_reg,
	asr_imm,
	b_32,
	b_cond_32,
	b_imm_11,
	b_uncond_32,
	bic_imm_32,
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
	ldmdb_32,
	ldmia_32,
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
	mov_high_1,
	mov_high_2,
	mov_high_reg,
	mov_imm,
	mov_imm_32_t2,
	mov_lo,
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
	stmb_32,
	stmia_32,
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
	sub_reg,
	sub_sp,
	tst,	
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


	//lsl_reg_32,
	//lsr_reg_32,
	//asr_reg_32,
	ror_reg_32,


	// --------------------------Data Processing (Modified Immediate)-------------------------- 
	adc_imm_32,		// add with carry
	eor_imm_32,		// bitwise exclusive OR
	cmn_imm_32,		// compare negative
	mov_imm_32_t3,	// 
	mvn_imm_32,		// bitwise NOT
	orn_imm_32,		// bitwise OR NOT
	orr_imm_32,		// bitwise inclusive OR
	rsb_imm_32,		// reverse subtract
	sbc_imm_32,		// subtract with carry
	teq_imm_32,		// test equivalence
	tst_imm_32,		// test
	// -------------------------------------------------------------------------------------- 
	// --------------------------Data Processing (Shifted Register)-------------------------- 
	and_reg_32, 	// bitwise AND
	add_reg_32, 	// add
	adc_reg_32, 	// add with carry
	bic_reg_32, 	// bitwise bit clear
	cmn_reg_32, 	// compare negative
	cmp_reg_32, 	// compare
	mvn_reg_32, 	// bitwise NOT
	orn_reg_32, 	// bitwise OR NOT
	orr_reg_32, 	// bitwise OR
	sbc_reg_32,		// subtract with carry
	sub_reg_32,
	tst_reg_32,		// test
	// -------------------------------------------------------------------------------------- 
	// -----------------------Data Processing (Plain Binary Immediate)----------------------- 
	adr_32,			// form PC-relative address
	add_imm_32,		// add wide, 12-bit
	bfc_32,			// bit field clear
	bfi_32,			// bit field insert
	mov_16_imm_32,	// move wide, 16-bit
	movt_32,		// move top, 16-bit
	sbfx_32,		// signed bit field extract
	sub_imm_32,		// subtract wide, 12-bit 
	ubfx_32,		// unsigned bit field extract
	// -------------------------------------------------------------------------------------- 
	// --------------------------Move Register and Immediate Shifts-------------------------- 
	asr_imm_32,		// arithmetic shift right
	lsl_imm_32,		// logical shift left
	lsr_imm_32,		// logical shift right
	mov_reg_32,		// move
	ror_imm_32,		// rotate right
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
		test_case(0xd3fb, opcode.b_cond),
		test_case(0xe7cf, opcode.b_imm_11),
		test_case(0xe7fe, opcode.b_imm_11),
		test_case(0x4798, opcode.blx),
		test_case(0x4718, opcode.bx),
		test_case(0x4770, opcode.bx),
		test_case(0xb943, opcode.cmp_br_nz),
		test_case(0xb103, opcode.cmp_br_z),
		test_case(0x458c, opcode.cmp_high_1),
		test_case(0x4572, opcode.cmp_high_2),
		test_case(0x2b00, opcode.cmp_imm),
		test_case(0x4283, opcode.cmp_reg),
		test_case(0x42a2, opcode.cmp_reg),
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
		test_case(0x2301, opcode.mov_imm),
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
	data_proc_bin_imm 		= 0b0100000,	// Data Processing (Plain Binary Immediate)
	data_proc_imm           = 0b0100000,	// Data Processing (Modified Immediate)
	load_store_mult 		= 0b1100100,
	long_mult               = 0b1111000,
	mult					= 0b1111000,	// Multiply, Multiply Accumulate, and Absolute Difference
	data_proc_reg           = 0b1110000,
	ld_bytes_mem_hints      = 0b1100111,
	str_single              = 0b1110001,
	load_store_dual         = 0b1100100,
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
	return opcode.invalid;
}

// ======================
//  Decode Data Proc Imm
// ======================

opcode decode_data_proc_imm(uint instr) {
	ubyte op = cast(ubyte)((instr >> 20) & 0x1f);
	ubyte rd = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte rn = cast(ubyte)((instr >> 16) & 0x0f);
	enum ubyte pc = 0xf;
	ubyte masked_op = op & 0b11110;
	final switch (masked_op)
	{
		case 0b11010: return rd == pc ? opcode.cmp_imm_32 : opcode.sub_imm_32;
		case 0b00000: return rd == pc ? opcode.tst_imm_32 : opcode.and_imm_32;
		case 0b00100: 
			if (rn == pc) {
				ubyte ninth_bit = cast(ubyte)((instr >> 25) & 0x1);
				if (ninth_bit == 1) {
					return opcode.mov_imm_32_t3;
				} else {
					return opcode.mov_imm_32_t2;
				}
			} 
			return opcode.orr_imm_32;
		case 0b00110: return rn == pc ? opcode.mvn_imm_32 : opcode.orn_imm_32;
		case 0b01000: return rd == pc ? opcode.teq_imm_32 : opcode.eor_imm_32;
		case 0b10000: return rd == pc ? opcode.cmn_imm_32 : opcode.add_imm_32;
		case 0b10100: return opcode.adc_imm_32;
		case 0b10110: return opcode.sbc_imm_32;
		case 0b00010: return opcode.bic_imm_32;
		case 0b11100: return opcode.rsb_imm_32;
	}
	return opcode.invalid;  
}

// ========================
//  Decode Load Store Mult
// ========================

opcode decode_load_store_mult(uint instr) {
	ubyte op   = cast(ubyte)((instr >> 23) & 0x3);
	ubyte rn   = cast(ubyte)((instr >> 16) & 0xf);
	ubyte W    = cast(ubyte)((instr >> 21) & 0x1);
	ubyte Wrn  = cast(ubyte)((W << 4) | rn);
	ubyte L    = cast(ubyte)((instr >> 20) & 0x1);
	ubyte op_L = cast(ubyte)((op << 1) | L);
	final switch (op_L) {
		case 0b011: return Wrn == 0b11101 ? opcode.pop_mult_reg_32  : opcode.ldmia_32;
		case 0b100: return Wrn == 0b11101 ? opcode.push_mult_reg_32 : opcode.stmb_32;
		case 0b101: return opcode.ldmdb_32;
		case 0b010: return opcode.stmia_32;
	}
	return opcode.invalid;
}

// ========================
//  Decode Load Store Dual
// ========================

opcode decode_load_store_dual(uint instr) {
	ubyte op1 = cast(ubyte)((instr >> 23) & 0x3);
	ubyte op2 = cast(ubyte)((instr >> 20) & 0x3);
	ubyte op1_masked = cast(ubyte)(op1 & 0b10);
	ubyte op2_masked = cast(ubyte)(op2 & 0b01);
	if (op1_masked == 0b00 && op2 == 0b10) {
		return opcode.strd_32;
	}
	if (op1_masked == 0b10 && op2_masked == 0b00) {
		return opcode.strd_32;
	}
	if (op1_masked == 0b00 && op2 == 0b11) {
		return opcode.ldrd_imm_32;
	}
	if (op1_masked == 0b10 && op2_masked == 0b01) {
		return opcode.ldrd_imm_32;
	}
	if (op1 == 0b00 && op2 == 0b01) {
		return opcode.ld_rex;
	}
	if (op2 == 0b00 && op1 == 0b00) {
		return opcode.str_rex;
	}
	return opcode.invalid;
}

// =============
//  Decode Mult
// =============

opcode decode_mult(uint instr) {
	ubyte ra  = cast(ubyte)((instr >> 12) & 0xf);
	ubyte op1 = cast(ubyte)((instr >> 20) & 0x7);
	ubyte op2 = cast(ubyte)((instr >>  4) & 0x3);
	enum ubyte pc = 0xf;
	ubyte op12 = cast(ubyte)((op1 << 2) | op2); 
	final switch (op12) {
		case 0b00000: return ra == pc ? opcode.mul_32 : opcode.mla_32;
		case 0b00001: return opcode.mls_32;
	}
	return opcode.invalid;
}

// ==========
//  Misc Ops
// ==========

opcode misc_ops(uint instr) {
	ubyte op1  = cast(ubyte)((instr >> 20) & 0x3);
	ubyte op2  = cast(ubyte)((instr >>  4) & 0x3);
	ubyte op12 = cast(ubyte)((op1 << 2) | op2);
	final switch (op12) {
		case 0b0000: return opcode.qadd_32;
		case 0b0001: return opcode.qdadd_32;
		case 0b0010: return opcode.qsub_32;
		case 0b0011: return opcode.qdsub_32;
		case 0b0100: return opcode.rev_32;
		case 0b0101: return opcode.rev_16_32;
		case 0b0110: return opcode.rbit_32;
		case 0b0111: return opcode.revsh_32;
		case 0b1000: return opcode.sel_32;
		case 0b1100: return opcode.clz_32;
	}
	return opcode.invalid;
}

// ======================
//  Decode Data Proc Reg
// ======================

opcode decode_data_proc_reg(uint instr) {
	ubyte rn  = cast(ubyte)((instr >> 16) & 0xf);
	ubyte op1 = cast(ubyte)((instr >> 20) & 0xf);
	ubyte op2 = cast(ubyte)((instr >>  4) & 0xf);
	ubyte op1_masked = cast(ubyte)(op1 & 0b1110);
	ubyte op2_masked = cast(ubyte)(op2 & 0b1000);
	ubyte op1m_op2 = cast(ubyte)((op1_masked << 4) | op2);
	ubyte op1_op2m = cast(ubyte)((op1 << 4) | op2_masked);
	enum ubyte pc = 0xf;
	switch (op1m_op2) {
		case 0b00000000: return opcode.lsl_reg_32;
		case 0b00100000: return opcode.lsr_reg_32;
		case 0b01000000: return opcode.asr_reg_32;
		case 0b01100000: return opcode.ror_reg_32;
		default: break;
	}
	switch (op1_op2m) {
		case 0b00001000: return rn == pc ? opcode.sxth_32   : opcode.sxtah_32;
		case 0b00011000: return rn == pc ? opcode.uxth_32   : opcode.uxtah_32;
		case 0b00101000: return rn == pc ? opcode.sxtb16_32 : opcode.sxtab_16_32;
		case 0b00111000: return rn == pc ? opcode.uxtb16_32 : opcode.uxtab_16_32;
		case 0b01001000: return rn == pc ? opcode.sxtb_32   : opcode.sxtab_32;
		case 0b01011000: return rn == pc ? opcode.uxtb_32   : opcode.uxtab_32;
		default: break;
	}
	if (((op1 & 0b1000) == 0b1000) && ((op2 & 0b1100) == 0b0000)) {
		return opcode.uadd8_32;
	}
	if (((op1 & 0b1000) == 0b1000) && ((op2 & 0b1100) == 0b0100)) {
		return opcode.uadd8_32;
	}
	if (((op1 & 0b1100) == 0b1000) && ((op2 & 0b1100) == 0b1000)) {
		return misc_ops(instr);
	}
	return opcode.invalid;
}

// ===============================
//  Decode Store Single Data Item
// ===============================

opcode decode_store_single_data_item(uint instr) {
	ubyte op1 = cast(ubyte)((instr >> 21) & 0x7);
	ubyte op2 = cast(ubyte)((instr >>  6) & 0x3f);
	ubyte maksed_op2 = cast(ubyte)(op2 & 0x20);
	ushort op1_masked_op2 = cast(ushort)((op1 << 6) | maksed_op2);
	final switch (op1_masked_op2) 
	{
		case 0b100100000:
		case 0b100000000: return opcode.strb_imm_32_t2;
		case 0b000100000: return opcode.strb_imm_32_t3;
		case 0b000000000: return opcode.strb_reg_32;
		case 0b101000000:
		case 0b101100000: return opcode.strh_imm_32_t2;
		case 0b001100000: return opcode.strh_imm_32_t3;
		case 0b001000000: return opcode.strh_reg_32;
		case 0b110000000:
		case 0b110100000: return opcode.str_imm_32_t3;
		case 0b010100000: return opcode.str_imm_32_t4;
		case 0b010000000: return opcode.str_reg_32;
	}
	return opcode.invalid;
}

opcode decode_mnemonic_32(uint instr) {
	ubyte op1 = cast(ubyte)((instr >> 27) & 0b11);
	ubyte op2 = cast(ubyte)((instr >> 20) & 0b1111111);
	if (op1 == op1_32.grp1) { 
		if ((op2 & op2_32.data_proc_shift_reg) == op2_32.data_proc_shift_reg) {
			return decode_data_proc_shift_reg(instr);
		}
		if ((op2 & op2_32.load_store_mult) == 0b0000000)  {
			return decode_load_store_mult(instr);
		}
		if ((op2 & op2_32.load_store_dual) == 0b0000100) {
			return decode_load_store_dual(instr);
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
			return decode_data_proc_imm(instr);
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
			return decode_mult(instr);
		}
		if ((op2 & op2_32.data_proc_reg) == 0b0100000) {
			return decode_data_proc_reg(instr);
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
			return decode_store_single_data_item(instr);
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
		test_case(0xf4434380, opcode.orr_imm_32),
		test_case(0xf1070314, opcode.add_imm_32),
		test_case(0xf0230310, opcode.bic_imm_32),
		test_case(0xf64f03ff, opcode.mov_16_imm_32),
		test_case(0xf9973007, opcode.ldrsb_imm_32_t1),
		test_case(0xf8412023, opcode.str_reg_32),
		test_case(0xf8dfd034, opcode.ldr_lit_32),
		test_case(0xf3bf8f4f, opcode.dsb_32),
		test_case(0xf1c30307, opcode.rsb_imm_32),
		test_case(0xfba22303, opcode.umull_32),
		test_case(0xe9c72300, opcode.strd_32),
		test_case(0xf67fae90, opcode.b_32),
		test_case(0xe92d4fb0, opcode.push_mult_reg_32),
		test_case(0xea4161d2, opcode.orr_reg_32),
		test_case(0xebb2080a, opcode.sub_reg_32),
		test_case(0xeb63090b, opcode.sbc_reg_32),
		test_case(0xeb45030b, opcode.adc_reg_32),
		test_case(0xf06f0240, opcode.mvn_imm_32),
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
		test_case(0xf8553b04, opcode.ldr_imm_32_t4), 
		test_case(0xf7ffb8f7, opcode.b_uncond_32),
		test_case(0xf8441023, opcode.str_reg_32),
		test_case(0xf8c46188, opcode.str_imm_32_t3),
		test_case(0xe8bd4008, opcode.pop_mult_reg_32),
		test_case(0xeb0101a3, opcode.add_reg_32),
		test_case(0xf1b37f80, opcode.cmp_imm_32),
		test_case(0xf1070318, opcode.add_imm_32),
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
	 	test_case(0xf1100f16, opcode.cmn_imm_32),
	 	test_case(0xf8973033, opcode.ldrb_imm_32_t2),
	 	test_case(0xf8832042, opcode.strb_imm_32_t2),
	 	test_case(0xf8a320f8, opcode.strh_imm_32_t2),
	 	test_case(0xe8b04ff0, opcode.ldmia_32),
	    test_case(0xea620205, opcode.orn_reg_32),
	    test_case(0xea4f06a6, opcode.asr_imm_32),
	    test_case(0xf4434380, opcode.orr_imm_32),
	    test_case(0xf7feffc5, opcode.bl_32),
	    test_case(0xf7f6f9b5, opcode.bl_32)
	];

	foreach (t; tests) {
		auto actual = decode_mnemonic_32(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%08X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}