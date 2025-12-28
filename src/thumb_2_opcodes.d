import std.format;
import std.conv;

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
	uadd8_32,
	uxth,
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

// =================
//  Decode Mnemonic
// =================

opcode decode_mnemonic(ushort instr) { 
    if (cast(ubyte)((instr >> 14) & 0b11) == instr_grp.alu_imm) {
    	ubyte opcode_ = cast(ubyte)((instr >> 9) & 0b11111);
    	if (((instr >> 11) & 0b111) == alu_imm.cmp) {
    		return opcode.cmp_imm;
    	}
    	if (((instr >> 11) & 0b111) == alu_imm.movs) {
    		return opcode.mov_imm;
    	}
    	if (((instr >> 11) & 0b111) == alu_imm.subs_8) {
    		return opcode.sub_imm_8;
    	}
    	if (opcode_ == 0b01110) {
    		return opcode.add_imm_3;
    	}
    	if (((instr >> 11) & 0b111) == alu_imm.add_8) {
    		return opcode.add_imm_8;
    	}
    	if (((instr >> 11) & 0b111) == alu_imm.asr) {
    		return opcode.asr_imm;
    	}
    	if (((instr >> 11) & 0b111) == alu_imm.lsl) {
    		return opcode.lsl_imm;
    	}
    	if (((instr >> 11) & 0b111) == alu_imm.lsr) {
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
		test_case(0x4208, opcode.tst),
		test_case(0xb2db, opcode.uxtb),
		test_case(0xb29a, opcode.uxth),
		test_case(0x58d4, opcode.ldr_imm)
	];

	foreach (t; tests) {
		opcode actual = decode_mnemonic(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%04X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}