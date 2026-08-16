import std.format;
import std.conv;

private uint slice(const uint instr, const uint shift, const uint width) {
	return (instr >> shift) & decimal_to_hex_mask(width);
}

private uint decimal_to_hex_mask(uint n) {
    return (1u << n) - 1;
}

enum opcode : ushort {
	// store multiple registers
	stm_t1,
	// load multiple registers
	ldm_t1,
	// pc-rel
	adr_t1,
	// branch sup call
	svc_t1,
	b_t1,
	// add, shift
	lsl_imm_t1,
	lsr_imm_t1,
	asr_imm_t1,
	add_reg_t1,
	sub_reg_t1,
	add_imm_t1,
	add_imm_t2,
	sub_imm_t1,
	sub_imm_t2,
	mov_imm_t1,
	cmp_imm_t1,
	// Data processing
	cmn_reg_t1,
	tst_reg_t1,
	adc_reg_t1,
	and_reg_t1,
	bic_reg_t1,
	cmp_reg_t1,
	eor_reg_t1,
	lsl_reg_t1,
	lsr_reg_t1,
	asr_reg_t1,
	mvn_reg_t1,
	rsb_imm_t1,
	sbc_reg_t1,
	mul_t1,
	orr_reg_t1,
	ror_reg_t1,
	// ????
	mov_reg_t2,
	// misc
	cps_t1,
	add_sp_t1,
	add_sp_t2,
	sub_sp_t1,
	cbnz_t1,
	cbz_t1,
	sxth_t1,
	sxtb_t1,
	uxth_t1,
	uxtb_t1,
	push_t1,
	rev_t1,
	rev16_t1,
	revsh_t1,
	pop_t1,
	bkpt_t1,
	if_then_t1,
	nop_t1,
	yield_t1,
	wfe_t1,
	wfi_t1,
	sev_t1,
	// decode special and exchange
	add_reg_t2,
	cmp_reg_t2,
	mov_reg_t1,
	bx_t1,
	blx_t1,
	// uncond branch
	b_t2,
	// load store
	str_reg_t1,
	strh_reg_t1,
	strb_reg_t1,
	ldrsb_reg_t1,
	ldr_reg_t1,
	ldrh_reg_t1,
	ldrb_reg_t1,
	ldrsh_reg_t1,
	str_imm_t1,
	ldr_imm_t1,
	strb_imm_t1,
	ldrb_imm_t1,
	strh_imm_t1,
	ldrh_imm_t1,
	str_imm_t2,
	ldr_imm_t2,
	// load from pool
	ldr_lit_t1,
	//--------------------------------------------------------------------------------------
	// dual or excusive
	strex_t1,
	ldrex_t1,
	lda_t1, // v8-M
	ldaex_t1, // v8-M
	strd_imm_t1,
	ldrd_imm_t1,
	strexb_t1,
	strexh_t1,
	stlex_t1, // v8-M
	tbb_tbh_t1,
	ldrexb_t1,
	ldrexh_t1,
	// load multiple
	pop_t2,
	pop_t3,
	push_t2,
	push_t3,
	stmdb_t1,
	ldmdb_t1,
	ldm_t2,
	stm_t2,
	// Branch-----------------------------------
	bl_t1,
	msr_t1,
	mrs_t1,
	b_t3,
	b_t4,
	// misc control
	clrex_t1,
	dsb_t1,
	dmb_t1,
	isb_t1,
	// hint
	nop_t2,
	yield_t2,
	wfe_t2,
	wfi_t2,
	sev_t2,
	dbg_t1,
	// --------------------------Data Processing (Modified Immediate)-------------------------- 
	adc_imm_t1,		// add with carry
	bic_imm_t1,
	and_imm_t1,
	add_imm_t3,
	cmp_imm_t2,
	sub_imm_t3,
	eor_imm_t1,		// bitwise exclusive OR
	cmn_imm_t1,		// compare negative
	mov_imm_t2,	    // 
	mvn_imm_t1,		// bitwise NOT
	orn_imm_t1,		// bitwise OR NOT
	orr_imm_t1,		// bitwise inclusive OR
	rsb_imm_t2,		// reverse subtract
	sbc_imm_t1,		// subtract with carry
	teq_imm_t1,		// test equivalence
	tst_imm_t1,		// test
	// -------------------------------------------------------------------------------------- 
	// --------------------------Data Processing (Shifted Register)-------------------------- 
	and_reg_t2, 	// bitwise AND
	add_reg_t3, 	// add
	adc_reg_t2, 	// add with carry
	bic_reg_t2, 	// bitwise bit clear
	cmn_reg_t2, 	// compare negative
	cmp_reg_t3, 	// compare
	eor_reg_t2,		// exclusive or
	mvn_reg_t2, 	// bitwise NOT
	orn_reg_t1, 	// bitwise OR NOT
	orr_reg_t2, 	// bitwise OR
	sbc_reg_t2,		// subtract with carry
	teq_reg_t1, 	// test equivalence
	tst_reg_t2,		// test
	sub_reg_t2,
	rsb_reg_t1,		// reverse subtract
	// -------------------------------------------------------------------------------------- 
	// -----------------------Data Processing (Plain Binary Immediate)----------------------- 
	adr_imm_t2,		// form PC-relative address
	adr_imm_t3,
	add_imm_t4,		// add wide, 12-bit
	bfc_t1,			// bit field clear
	bfi_t1,			// bit field insert
	mov_imm_t3,		// move wide, 16-bit
	movt_t1,		// move top, 16-bit
	sbfx_t1,		// signed bit field extract
	sub_imm_t4,		// subtract wide, 12-bit 
	ubfx_t1,		// unsigned bit field extract
	// -------------------------------------------------------------------------------------- 
	// --------------------------Move Register and Immediate Shifts-------------------------- 
	asr_imm_t2,		// arithmetic shift right
	lsl_imm_t2,		// logical shift left
	lsr_imm_t2,		// logical shift right
	mov_reg_t3,		// move
	ror_imm_t1,		// rotate right
	rrx_t1,
	// -------------------------------------------------------------------------------------- 
	// --------DATA processing register
	asr_reg_t2,
	uxth_t2,
	uxtb_t2,
	sxth_t2,
	sxtb_t2,
	sxtab_t1,
	sxtah_t1,
	uxtah_t1,
	sxtab16_t1,
	sxtb16_t1,
	uxtab16_t1,
	uxtb16_t1,
	uxtab_t1,
	lsr_reg_t2,
	lsl_reg_t2,
	ror_reg_t2,
	// ---> unsigned add
	uadd8_t1,
	smuad_t1, 
	smlad_t1,	                                                
	smulw_t1,
	smlaw_t1,
	smusd_t1,
	smlsd_t1,
	smmul_t1,
	smmla_t1, 
	smmls_t1,
	usada8_t1,
	usad8_t1,
	sadd16_t1,
	sasx_t1,
	ssax_t1,
	ssub16_t1,
	sadd8_t1,
	ssub8_t1,
	qadd16_t,
	qasx_t1,
	qsax_t1,
	qsub16_t1,
	qadd8_t1,
	qsub8_t1,
	shadd16_t1,
	shasx_t1,
	shsax_t1,
	shsub16_t1,
	shadd8_t1,
	shsub8_t1,
	uadd16_t1,
	uasx_t1,
	usax_t1,
	usub16_t1,
	usub8_t1,
	uqadd16_t1,
	uqasx_t1,
	uqsax_t1,
	uqsub16_t1,
	uqadd8_t1,
	uqsub8_t1,
	uhadd16_t1,
	uhasx_t1,
	uhsax_t1,
	uhsub16_t1,
	uhadd8_t1,
	uhsub8_t1,
	// misc ops
	qadd_t1,
	qdadd_t1,
	qsub_t1,
	qdsub_t1,
	rev_t2,
	rev16_t2,
	rbit_t2,
	revsh_t2,
	sel_t1,
	clz_t1,
	// mult mult acc
	mla_t1,
	mul_t2,
	mls_t1,
	smul_t1,
	smla_t1,
	// long mult
	smull_t1,
	umull_t1,
	udiv_t1,
	sdiv_t1,
	umlal_t1,
	umaal_t1,
	smlal_t1,
	smlsls_t1,
	smlalxy_t1,	
	smlald_t1,
	// load word
	ldr_imm_t3,
	ldr_imm_t4,
	ldrt_t1,
	ldr_reg_t2,
	ldr_lit_t2,
	// Load halfword
	ldrh_lit_t1,
	ldrh_imm_t2,
	ldrh_imm_t3,
	ldrh_reg_t2,
	ldrht_t1,
	ldrsh_t1,
	ldrsh_t2,
	ldrsh_lit_t1,
	ldrsh_reg_t2,
	ldrsht_t1,
	ldrsh_imm_t1,
	ldrsh_imm_t2,
	// load byte
	ldrb_lit_t1,
	ldrb_imm_t2,
	ldrb_imm_t3,
	ldrbt_t1,
	ldrb_reg_t2,
	ldrsb_lit_t1,
	ldrsbt_t1,
	ldrsb_imm_t1,
	ldrsb_imm_t2,
	ldrsb_reg_t2,
	pld_lit_t1,
	pld_imm_t1,
	pld_imm_t2,
	pld_reg_t1,	
	// store single data item
	strb_imm_t2,
	strb_imm_t3,
	strb_reg_t2,
	strh_imm_t2,
	strh_imm_t3,
	strh_reg_t2,
	str_imm_t3,
	str_imm_t4,
	str_reg_t2,

	invalid,

	vmsr_t1, vmrs_t1, vpush_t1, vpush_t2, 

	// loop instructions
	le_t2, le_t3, le_t1, wls_t1, wls_t2, wls_t3, vctp_t1, lctp_t1, wls_t4,

	// vector load
	vmov_t1,  vldrw_t7, vscclrm_t1, vscclrm_t2,
	vldr_t2,  vldr_t1,  vlldm_t1,   vlldm_t2, vstr_t2,
	vlstm_t1, vlstm_t2, vstr_t1,

	tt_t1,
}

// ==================
//  Decode Data Proc
// ==================

opcode decode_data_proc(const ushort instr) {
	immutable op = slice(instr, 6, 4);
	switch (op) 
	{
		case 0b0000: return opcode.and_reg_t1;
		case 0b0100: return opcode.asr_reg_t1;
		case 0b0001: return opcode.eor_reg_t1;
		case 0b0010: return opcode.lsl_reg_t1;
		case 0b0011: return opcode.lsr_reg_t1;
		case 0b0101: return opcode.adc_reg_t1;
		case 0b1000: return opcode.tst_reg_t1;
		case 0b1001: return opcode.rsb_imm_t1;
		case 0b1010: return opcode.cmp_reg_t1;
		case 0b1100: return opcode.orr_reg_t1;
		case 0b1101: return opcode.mul_t1;
		case 0b1110: return opcode.bic_reg_t1;
		case 0b1111: return opcode.mvn_reg_t1;
		case 0b0110: return opcode.sbc_reg_t1;
		case 0b1011: return opcode.cmn_reg_t1;
		case 0b0111: return opcode.ror_reg_t1; 
		default    : break; 
	}
    return opcode.invalid;
}

// ==============================
//  Decode Shift Add Sub Mov Cmp
// ==============================

opcode decode_shift_add_sub_mov_cmp(const ushort instr) {
	immutable op 	   = slice(instr, 9, 5);
	immutable op_short = slice(op,    2, 3);
	switch (op) {
		case 0b01110: return opcode.add_imm_t1;
		case 0b01101: return opcode.sub_reg_t1;
		case 0b01100: return opcode.add_reg_t1;
		case 0b01111: return opcode.sub_imm_t1;
		default     : break;
	}
	final switch (op_short) {
		case 0b101: return opcode.cmp_imm_t1;
		case 0b100: return opcode.mov_imm_t1;
		case 0b111: return opcode.sub_imm_t2;
		case 0b110: return opcode.add_imm_t2;
		case 0b010: return opcode.asr_imm_t1;
		case 0b000: return opcode.lsl_imm_t1;
		case 0b001: return opcode.lsr_imm_t1;
	}
	return opcode.invalid;
}

// ====================================
//  Decode Load Store Single Data Item
// ====================================

opcode decode_load_store_single_data_item(const ushort instr) {
	immutable opb = slice(instr,  9, 3);
	immutable opa = slice(instr, 12, 4);
	immutable opb_first_bit = slice(opb, 2, 1);
	switch (opa) {
		case 0b0101:
			switch (opb) {
				case 0b000: return opcode.str_reg_t1;
				case 0b001: return opcode.strh_reg_t1;
				case 0b100: return opcode.ldr_reg_t1;
				case 0b010: return opcode.strb_reg_t1;
				case 0b110: return opcode.ldrb_reg_t1;
				case 0b101: return opcode.ldrh_reg_t1;
				case 0b111: return opcode.ldrsh_reg_t1;
				case 0b011: return opcode.ldrsb_reg_t1;
				default   : return opcode.invalid;
			} 
		case 0b0110:
			return opb_first_bit == 1 ? opcode.ldr_imm_t1  : opcode.str_imm_t1;
		case 0b0111:
			return opb_first_bit == 1 ? opcode.ldrb_imm_t1 : opcode.strb_imm_t1;
		case 0b1000:
			return opb_first_bit == 1 ? opcode.ldrh_imm_t1 : opcode.strh_imm_t1;
		case 0b1001:
			return opb_first_bit == 1 ? opcode.ldr_imm_t2  : opcode.str_imm_t2;
		default    : return opcode.invalid;
	}
}

// ===========================
//  Decode Misc 16 Bit Instrs
// ===========================

opcode decode_misc_16_bit_instrs(const ushort instr) {
    immutable op = slice(instr, 5, 7);
    // 00000xx Add Immediate to SP ADD (SP plus immediate)
	if ((op & 0b1111100) == 0) {
		if (slice(instr, 12, 4) == 0b1010) 
			return opcode.add_sp_t1;
		if (slice(instr, 12, 4) == 0b1011) 
			return opcode.add_sp_t2;
	}
	// 101000x Byte-Reverse Word REV
	if (slice(instr, 6, 6) == 0b101000) 
		return opcode.rev_t1;
	// 101001x Byte-Reverse Packed Halfword REV16
	if (slice(instr, 6, 6) == 0b101001) 
		return opcode.rev16_t1;
	// 101011x Byte-Reverse Signed Halfword REVSH
	if (slice(instr, 6, 6) == 0b101011) 
		return opcode.revsh_t1;
	// 001011x Unsigned Extend Byte UXTB
	if (slice(instr, 6, 6) == 0b001011) 
		return opcode.uxtb_t1;
	// 001001x Signed Extend Byte SXTB
	if (slice(instr, 6, 6) == 0b001001) 
		return opcode.sxtb_t1;
	// 001000x Signed Extend Halfword SXTH
	if (slice(instr, 6, 6) == 0b001000) 
		return opcode.sxth_t1;
	// 010xxxx Push Multiple Registers PUSH
	if (slice(instr, 9, 3) == 0b010) 
		return opcode.push_t1;
	// 110xxxx Pop Multiple Registers POP
	if (slice(instr, 9, 3) == 0b110) 
		return opcode.pop_t1;
	// 1111xxx If-Then, and hints
	if (slice(instr, 8, 4) == 0b1111) 
		return decode_if_then_and_hints(instr);
	// Subtract Immediate from SP SUB (SP minus immediate)
	if (slice(instr, 7, 5) == 0b00001) 
		return opcode.sub_sp_t1;
	// 0011xxx Compare and Branch on Zero CBNZ, CBZ
	if ((op & 0b1111000) == 0b0001000 ||
		(op & 0b1111000) == 0b0011000 ||
		(op & 0b1111000) == 0b1001000 ||
		(op & 0b1111000) == 0b1011000) 
    	return slice(instr, 11, 1) == 0 ? opcode.cbz_t1 : opcode.cbnz_t1;
    // 001010x Unsigned Extend Halfword UXTH 
	if ((op & 0b1111110) == 0b0010100) 
		return opcode.uxth_t1;
	// 0110011 Change Processor State CPS
	if (op == 0b0110011) 
		return opcode.cps_t1;
	// 1110xxx Breakpoint BKPT
	if (slice(instr, 8, 4) == 0b1110)
		return opcode.bkpt_t1;
	return opcode.invalid;
}

opcode decode_if_then_and_hints(const ushort instr) {
	immutable opb = slice(instr, 0, 4);
	immutable opa = slice(instr, 4, 4);
	if (opb != 0x0)
		// xxxx not 0000 If-Then IT 
		return opcode.if_then_t1;
	else {
		switch (opb) {
			// 0000 0000 No Operation hint NOP
			case 0b0000: return opcode.nop_t1;
			// 0001 0000 Yield hint YIELD 
			case 0b0001: return opcode.yield_t1;
			// 0010 0000 Wait for Event hint WFE 
			case 0b0010: return opcode.wfe_t1;
			// 0011 0000 Wait for Interrupt hint WFI 
			case 0b0011: return opcode.wfi_t1;
			// 0100 0000 Send Event hint SEV
			case 0b0100: return opcode.sev_t1;
			default: 	 break;
		} 
	}
	return opcode.invalid;
}

// =============================
//  Decode Special and Exchange
// =============================

opcode decode_special_and_exchange(const ushort instr) {
	immutable op 		 = slice(instr, 6, 4);
	immutable op_first_2 = slice(op, 2, 2);
	immutable op_first_3 = slice(op, 1, 3);
    if (op_first_2 == 0) 
    	return opcode.add_reg_t2;
    if ((op == 0b0101) || (op_first_3 == 0b011))
    	return opcode.cmp_reg_t2;
    if (op_first_2 == 0b10)
    	return opcode.mov_reg_t1;
    if (op_first_3 == 0b110) 
    	return opcode.bx_t1;
    if (op_first_3 == 0b111)
    	return opcode.blx_t1;
    return opcode.invalid;
}

// =================
//  Decode Mnemonic
// =================

opcode decode_mnemonic(const ushort instr) { 
    // Shift (immediate), add, subtract, move, and compare
    if (slice(instr, 14, 2) == 0b00) {
    	return decode_shift_add_sub_mov_cmp(instr);
    }
    // Data processing
    if (slice(instr, 10, 6) == 0b010000) {
    	return decode_data_proc(instr);
    }
    // Load/store single data item
    if ( slice(instr, 12, 4)           == 0b0101 ||
    	(slice(instr, 12, 4) & 0b1110) == 0b0110 ||
    	(slice(instr, 12, 4) & 0b1110) == 0b1000) {
    	return decode_load_store_single_data_item(instr);
    }
    // Load from literal pool
    if (slice(instr, 11, 5) == 0b01001) {
    	return opcode.ldr_lit_t1;
    }
    // Conditional branch and supervisor call
    if (slice(instr, 12, 4) == 0b1101) 
    	return slice(instr, 8, 4) == 0b1111 ? opcode.svc_t1 : opcode.b_t1;
    // Miscellaneous 16-bit instructions
    if (slice(instr, 12, 4) == 0b1011) 
    	return decode_misc_16_bit_instrs(instr);
    // Special data instructions and branch and exchange
    if (slice(instr, 10, 6) == 0b010001) {
    	return decode_special_and_exchange(instr);
    }
    // Unconditional branch
    if (slice(instr, 11, 5) == 0b11100)
    	return opcode.b_t2;
    // Store multiple registers
	if (slice(instr, 11, 5) == 0b11000)
    	return opcode.stm_t1;
    // Load multiple registers
	if (slice(instr, 11, 5) == 0b11001)
    	return opcode.ldm_t1;
    // Generate SP-relative address
    if (slice(instr, 11, 5) == 0b10101) {
		if (slice(instr, 12, 4) == 0b1010) {
			return opcode.add_sp_t1;
		}
		if (slice(instr, 12, 4) == 0b1011) {
			return opcode.add_sp_t2;
		}
    } 
    // Generate PC-relative address
    if (slice(instr, 11, 5) == 0b10100) 
    	return opcode.adr_t1;
    return opcode.invalid;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		opcode expected;
	}

	test_case[] tests = [
		test_case(0x415b, opcode.adc_reg_t1), // adcs	r3, r3
		test_case(0x4463, opcode.add_reg_t2),
		test_case(0x44e6, opcode.add_reg_t2),
		test_case(0x1d3b, opcode.add_imm_t1),
		test_case(0x3730, opcode.add_imm_t2),
		test_case(0x4413, opcode.add_reg_t2),
		test_case(0x1891, opcode.add_reg_t1),
		test_case(0xa904,  opcode.add_sp_t1),
		test_case(0xaf00,  opcode.add_sp_t1),
		test_case(0xb005,  opcode.add_sp_t2),
		test_case(0xa201,     opcode.adr_t1),
		test_case(0x4013, opcode.and_reg_t1),
		test_case(0x10b6, opcode.asr_imm_t1),
		test_case(0xd002,       opcode.b_t1),
		test_case(0xd3fb,       opcode.b_t1),
		test_case(0xe7cf,       opcode.b_t2),
		test_case(0xe7fe,       opcode.b_t2),
		test_case(0x4798,     opcode.blx_t1),
		test_case(0x4718,      opcode.bx_t1),
		test_case(0x4770,      opcode.bx_t1),
		test_case(0xb943,    opcode.cbnz_t1),
		test_case(0xb103,     opcode.cbz_t1),
		test_case(0x458c, opcode.cmp_reg_t2),
		test_case(0x4572, opcode.cmp_reg_t2),
		test_case(0x2b00, opcode.cmp_imm_t1),
		test_case(0x4283, opcode.cmp_reg_t1),
		test_case(0x42a2, opcode.cmp_reg_t1),
		test_case(0xb661,     opcode.cps_t1),
		test_case(0xbf08, opcode.if_then_t1),
		test_case(0x681b, opcode.ldr_imm_t1),
		test_case(0x682b, opcode.ldr_imm_t1),
		test_case(0x68fb, opcode.ldr_imm_t1),
		test_case(0x691a, opcode.ldr_imm_t1),
		test_case(0x4803, opcode.ldr_lit_t1),
		test_case(0x4a0a, opcode.ldr_lit_t1),
		test_case(0x4b08, opcode.ldr_lit_t1),
		test_case(0x4b09, opcode.ldr_lit_t1),
		test_case(0x4b0a, opcode.ldr_lit_t1),
		test_case(0x4b01, opcode.ldr_lit_t1),
		test_case(0x482d, opcode.ldr_lit_t1),
		test_case(0x58d4, opcode.ldr_reg_t1),
		test_case(0x58fb, opcode.ldr_reg_t1),
		test_case(0x9d08, opcode.ldr_imm_t2),
		test_case(0x781a,opcode.ldrb_imm_t1),
		test_case(0x5cd3,opcode.ldrb_reg_t1),
		test_case(0x88fb,opcode.ldrh_imm_t1),
		test_case(0x4313, opcode.orr_reg_t1),
		test_case(0x00d9, opcode.lsl_imm_t1),
		test_case(0x409a, opcode.lsl_reg_t1),
		test_case(0x099b, opcode.lsr_imm_t1),
		test_case(0x40da, opcode.lsr_reg_t1),
		test_case(0x4680, opcode.mov_reg_t1),
		test_case(0x469d, opcode.mov_reg_t1),
		test_case(0x4652, opcode.mov_reg_t1),
		test_case(0x2000, opcode.mov_imm_t1),
		test_case(0x2210, opcode.mov_imm_t1),
		test_case(0x2300, opcode.mov_imm_t1),
		test_case(0x2301, opcode.mov_imm_t1),
		test_case(0x460f, opcode.mov_reg_t1),
		test_case(0x43db, opcode.mvn_reg_t1),
		test_case(0x4241, opcode.rsb_imm_t1),
		test_case(0xbf00, 	  opcode.nop_t1),
		test_case(0xbd10, 	  opcode.pop_t1),
		test_case(0xb480, 	 opcode.push_t1),
		test_case(0xb510,    opcode.push_t1),
		test_case(0xb580,    opcode.push_t1),
		test_case(0x3902, opcode.sub_imm_t2),	
		test_case(0x6013, opcode.str_imm_t1),
		test_case(0x601a, opcode.str_imm_t1),
		test_case(0x6018, opcode.str_imm_t1),
		test_case(0x608b, opcode.str_imm_t1),
		test_case(0x611a, opcode.str_imm_t1),
		test_case(0x615a, opcode.str_imm_t1),
		test_case(0x6198, opcode.str_imm_t1),
		test_case(0x50c4, opcode.str_reg_t1),
		test_case(0x559a,opcode.strb_reg_t1),
		test_case(0x9300, opcode.str_imm_t2),
		test_case(0x9301, opcode.str_imm_t2),
		test_case(0x701a,opcode.strb_imm_t1),
		test_case(0x559a,opcode.strb_reg_t1),
		test_case(0x80fb,opcode.strh_imm_t1),
		test_case(0x53a3,opcode.strh_reg_t1),
		test_case(0x1e54, opcode.sub_imm_t1),
		test_case(0x1a1b, opcode.sub_reg_t1),
		test_case(0xb092,  opcode.sub_sp_t1),
		test_case(0xdf00,     opcode.svc_t1),
		test_case(0xb240,    opcode.sxtb_t1),
		test_case(0x4208, opcode.tst_reg_t1),
		test_case(0xb2db,    opcode.uxtb_t1),
		test_case(0xb29a,    opcode.uxth_t1),
		test_case(0xb208,    opcode.sxth_t1)
	];

	foreach (t; tests) {
		opcode actual = decode_mnemonic(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%04X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}

// ==========================
//  Decode Mov Reg Imm Shift
// ==========================

opcode decode_mov_reg_imm_shift(const uint instr) {
	immutable type  = slice(instr,  4, 2);
	immutable imm_2 = slice(instr,  6, 2);
	immutable imm_3 = slice(instr, 12, 3);
	immutable imm_5 = cast(ubyte)((imm_3 << 2) | imm_2);
	final switch (type)
	{
		case 0b00: return imm_5 == 0 ? opcode.mov_reg_t3 : opcode.lsl_imm_t2;
		case 0b01: return opcode.lsr_imm_t2;
		case 0b10: return opcode.asr_imm_t2;
		case 0b11: return imm_5 == 0 ? opcode.rrx_t1 : opcode.ror_imm_t1;
	}
	return opcode.invalid;
}

// ============================
//  Decode Data Proc Shift Reg
// ============================

opcode decode_data_proc_shift_reg(const uint instr) {
	immutable op = slice(instr, 21, 4);
	immutable rn = slice(instr, 16, 4);
	immutable rd = slice(instr,  8, 4);
	immutable s  = slice(instr, 20, 1);
	enum ubyte pc = 0xf;
	switch (op)
	{
		case 0b1101: 
			if (rd == pc && s == 1) return opcode.cmp_reg_t3; 
			if (rd != pc) return opcode.sub_reg_t2;
			return opcode.invalid;
		case 0b0100: return rd == pc ? opcode.teq_reg_t1 : opcode.eor_reg_t2;
		case 0b1011: return opcode.sbc_reg_t2;
		case 0b1010: return opcode.adc_reg_t2;
		case 0b1000: return rd == pc ? opcode.cmn_reg_t2 : opcode.add_reg_t3;
		case 0b0011: return rn == pc ? opcode.mvn_reg_t2 : opcode.orn_reg_t1; 
		case 0b0010: return rn == pc ? decode_mov_reg_imm_shift(instr) : opcode.orr_reg_t2;
		case 0b0001: return opcode.bic_reg_t2;
		case 0b0000:
			if (rd == pc && s == 1) return opcode.tst_reg_t2;
			if (rd != pc) return opcode.and_reg_t2;
			return opcode.invalid;
		case 0b1110: return opcode.rsb_reg_t1;
		default: break;
	}
	return opcode.invalid;
}

// ==========================
//  Decode Data Proc Bin Imm
// ==========================

opcode decode_data_proc_bin_imm(uint instr) {
	enum ubyte pc = 0xf;
	immutable op = slice(instr, 20, 5);
	immutable rn = slice(instr, 16, 4);
	switch (op)
	{
		case 0b00000: return rn == pc ? opcode.adr_imm_t3 : opcode.add_imm_t4;
		case 0b10110: return rn == pc ? opcode.bfc_t1     : opcode.bfi_t1;
		case 0b00100: return opcode.mov_imm_t3;
		case 0b01100: return opcode.movt_t1;
		case 0b10100: return opcode.sbfx_t1;
		case 0b01010: return rn == pc ? opcode.adr_imm_t2 : opcode.sub_imm_t4;
		case 0b11100: return opcode.ubfx_t1;
		default: break;
	}
	return opcode.invalid;
}

// ======================
//  Decode Data Proc Imm
// ======================

opcode decode_data_proc_imm(const uint instr) {
	immutable op = slice(instr, 20, 5);
	immutable rd = slice(instr,  8, 4);
	immutable rn = slice(instr, 16, 4);
	enum ubyte pc = 0xf;
	ubyte masked_op = op & 0b11110;
	switch (masked_op)
	{
		case 0b11010: return rd == pc ? opcode.cmp_imm_t2 : opcode.sub_imm_t3;
		case 0b00000: return rd == pc ? opcode.tst_imm_t1 : opcode.and_imm_t1;
		case 0b00100: 
			if (rn == pc) {
				ubyte ninth_bit = cast(ubyte)((instr >> 25) & 0x1);
				if (ninth_bit == 1) {
					return opcode.mov_imm_t3;
				} else {
					return opcode.mov_imm_t2;
				}
			} 
			return opcode.orr_imm_t1;
		case 0b00110: return rn == pc ? opcode.mvn_imm_t1 : opcode.orn_imm_t1;
		case 0b01000: return rd == pc ? opcode.teq_imm_t1 : opcode.eor_imm_t1;
		case 0b10000: return rd == pc ? opcode.cmn_imm_t1 : opcode.add_imm_t3;
		case 0b10100: return opcode.adc_imm_t1;
		case 0b10110: return opcode.sbc_imm_t1;
		case 0b00010: return opcode.bic_imm_t1;
		case 0b11100: return opcode.rsb_imm_t2;
		default: break;
	}
	return opcode.invalid;  
}

// ========================
//  Decode Load Store Mult
// ========================

opcode decode_load_store_mult(uint instr) {
	immutable op   = slice(instr,23, 2);
	immutable rn   = slice(instr,16, 4);
	immutable W    = slice(instr,21, 1);
	immutable Wrn  = cast(ubyte)((W << 4) | rn);
	immutable L    = slice(instr,20, 1);
	immutable op_L = cast(ubyte)((op << 1) | L);
	switch (op_L) {
		case 0b011: return Wrn == 0b11101 ? opcode.pop_t2  : opcode.ldm_t2;
		case 0b100: return Wrn == 0b11101 ? opcode.push_t2 : opcode.stmdb_t1;
		case 0b101: return opcode.ldmdb_t1;
		case 0b010: return opcode.stm_t2;
		default: break;
	}
	return opcode.invalid;
}

// ======================
//  Decode Load Halfword
// ======================
	
opcode decode_load_half_word(const uint instr) {
	immutable op1 = slice(instr, 23, 2);
    immutable op2 = slice(instr,  6, 6);
    immutable rt  = slice(instr, 12, 4);
    immutable rn  = slice(instr, 16, 4);
	enum pc = 0b1111;
	if (((op1 & 0b10) == 0b00) && (rn == pc) && (rt != pc)) 
		return opcode.ldrh_lit_t1;
	if (((op1 == 0b00) && ((op2 & 0b100100) == 0b100100) && (rn != pc) && (rt != pc)) |
		((op1 == 0b00) && ((op2 & 0b111100) == 0b110000) && (rn != pc) && (rt != pc)) |
		((op1 == 0b01) && (rn != pc) && (rt != pc))) 
		return opcode.ldrh_imm_t2;
	if ((op1 == 0b00) && (op2 == 0b000000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrh_reg_t2;
	if ((op1 == 0b00) && ((op2 & 0b111100) == 0b111000) && (rn != pc) && (rt != pc))
		return opcode.ldrht_t1;
	if (((op1 & 0b10) == 0b10) && (rn == pc) && (rt != pc)) 
		return opcode.ldrsh_lit_t1;
	if ((op1 == 0b10) && (op2 == 0b000000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsh_reg_t2;
	if ((op1 == 0b10) && ((op2 & 0b111100) == 0b111000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsht_t1;
	if (((op1 == 0b10) && ((op2 & 0b100100) == 0b100100) && (rn != pc) && (rt != pc)) |
		((op1 == 0b10) && ((op2 & 0b111100) == 0b110000) && (rn != pc) && (rt != pc)) |
		((op1 == 0b11) && (rn != pc) && (rt != pc))) {
		if (slice(instr, 20, 4) == 0xb)
			return opcode.ldrsh_imm_t1;
		else
			return opcode.ldrsh_imm_t2;
	}
	return opcode.invalid;
}

// ========================
//  Decode Load Store Dual
// ========================

opcode decode_load_store_dual(const uint instr) {
	ubyte op1 = cast(ubyte)((instr >> 23) & 0x3);
	ubyte op2 = cast(ubyte)((instr >> 20) & 0x3);
	ubyte op3 = cast(ubyte)((instr >>  4) & 0xf);
	ubyte op1_masked = cast(ubyte)(op1 & 0b10);
	ubyte op2_masked = cast(ubyte)(op2 & 0b01);
	if (op1_masked == 0b00 && op2 == 0b10) {
		return opcode.strd_imm_t1;
	}
	if (op1_masked == 0b10 && op2_masked == 0b00) {
		return opcode.strd_imm_t1;
	}
	if (op1_masked == 0b00 && op2 == 0b11) {
		return opcode.ldrd_imm_t1;
	}
	if (op1_masked == 0b10 && op2_masked == 0b01) {
		return opcode.ldrd_imm_t1;
	}
	if (op1 == 0b00 && op2 == 0b01) {
		return opcode.ldrex_t1;
	}
	if (op1 == 0b01 && op2 == 0b01 && op3 == 0b1110) {
		return opcode.ldaex_t1;
	}
	if (op1 == 0b01 && op2 == 0b01 && op3 == 0b1010) {
		return opcode.lda_t1;
	}
	if (op2 == 0b00 && op1 == 0b00) {
		if (slice(instr, 12, 4) == 0xF) {
			return opcode.tt_t1;
		}
		return opcode.strex_t1;
	}
	if (op2 == 0b00 && op1 == 0b01 && op3 == 0b1110) {
		return opcode.stlex_t1;
	}
	if (op1 == 0b01 && op2 == 0b01 && ((op3 == 0b0001) | (op3 == 0b0000))) {
		return opcode.tbb_tbh_t1;
	}
	return opcode.invalid;
}

// =============
//  Decode Mult
// =============

opcode decode_mult(uint instr) {
	immutable ra  = slice(instr, 12, 4);
	immutable op1 = slice(instr, 20, 3);
	immutable op2 = slice(instr,  4, 2);
	enum ubyte pc = 0xf;
	if (op1 == 0b001) {
		if (ra == pc) 
			// 1111 Signed Multiply, Halfwords SMULBB, SMULBT, SMULTB, SMULTT (v7E-M)
			return opcode.smul_t1;
		// 001 - not 1111 Signed Multiply Accumulate, Halfwords SMLABB, SMLABT, SMLATB, SMLATT (v7E-M)
		return opcode.smla_t1;
	}
	ubyte op12 = cast(ubyte)((op1 << 2) | op2); 
	switch (op12) {
		// 000 00 not 1111 Multiply Accumulate MLA
		// 			  1111 Multiply MUL
		case 0b00000: return ra == pc ? opcode.mul_t2 : opcode.mla_t1;
		// 01 - Multiply and Subtract MLS
		case 0b00001: return opcode.mls_t1;
		// 010 0x not 1111 Signed Multiply Accumulate Dual SMLAD, SMLADX (v7E-M)
		// 1111 Signed Dual Multiply Add SMUAD, SMUADX (v7E-M)
		case 0b01000:
		case 0b01001: return ra == pc ? opcode.smuad_t1 : opcode.smlad_t1;
		// 011 0x not 1111 Signed Multiply Accumulate, Word by halfword SMLAWB, SMLAWT (v7E-M)
		// 1111 Signed Multiply, Word by halfword SMULWB, SMULWT (v7E-M)
		case 0b01100:
		case 0b01101: return ra == pc ? opcode.smulw_t1 : opcode.smlaw_t1;
		// 100 0x not 1111 Signed Multiply Subtract Dual SMLSD, SMLSDX (v7E-M)
		// 1111 Signed Dual Multiply Subtract SMUSD, SMUSDX (v7E-M)
   		case 0b10000:
   		case 0b10001: return ra == pc ? opcode.smusd_t1 : opcode.smlsd_t1;
		// 101 0x not 1111 Signed Most Significant Word Multiply Accumulate SMMLA, SMMLAR (v7E-M)
		// 1111 Signed Most Significant Word Multiply SMMUL, SMMULR (v7E-M)
		case 0b10100:
		case 0b10101: return ra == pc ? opcode.smmul_t1 : opcode.smmla_t1;
		// 110 0x - Signed Most Significant Word Multiply Subtract SMMLS, SMMLSR (v7E-M)
		case 0b11000:
		case 0b11001: return opcode.smmls_t1;
		// 111 00 not 1111 Unsigned Sum of Absolute Differences USAD8 (v7E-M)
		// 1111 Unsigned Sum of Absolute Differences, Accumulate USADA8 (v7E-M)
		case 0b11100: return ra == pc ? opcode.usada8_t1 : opcode.usad8_t1;
		default: break;
	}
	return opcode.invalid;
}

// ==========
//  Misc Ops
// ==========

opcode misc_ops(const uint instr) {
	ubyte op1  = cast(ubyte)((instr >> 20) & 0x3);
	ubyte op2  = cast(ubyte)((instr >>  4) & 0x3);
	ubyte op12 = cast(ubyte)((op1 << 2) | op2);
	final switch (op12) {
		case 0b0000: return opcode.qadd_t1;
		case 0b0001: return opcode.qdadd_t1;
		case 0b0010: return opcode.qsub_t1;
		case 0b0011: return opcode.qdsub_t1;
		case 0b0100: return opcode.rev_t2;
		case 0b0101: return opcode.rev16_t2;
		case 0b0110: return opcode.rbit_t2;
		case 0b0111: return opcode.revsh_t2;
		case 0b1000: return opcode.sel_t1;
		case 0b1100: return opcode.clz_t1;
	}
	return opcode.invalid;
}

// ====================================
//  Decode Signed Parallel Add and Sub
// ====================================

opcode decode_signed_parallel_add_and_sub(const uint instr) {
	immutable  op1  = slice(instr, 20, 3);
	immutable  op2  = slice(instr,  4, 2);
	const uint op12 = (op1 << 2) | op2;
	switch (op12) {
		// 001 00 Add 16-bit SADD16 v7E-M
		case 0b00100: return opcode.sadd16_t1;
		// 010 00 Add, Subtract SASX v7E-M
		case 0b01000: return opcode.sasx_t1;
		// 110 00 Subtract, Add SSAX v7E-M
		case 0b11000: return opcode.ssax_t1;
		// 101 00 Subtract 16-bit SSUB16 v7E-M
		case 0b10100: return opcode.ssub16_t1;
		// 000 00 Add 8-bit SADD8 v7E-M
		case 0b00000: return opcode.sadd8_t1;
		// 100 00 Subtract 8-bit SSUB8 v7E-M
		case 0b10000: return opcode.ssub8_t1;
		// Saturating instructions
		// 001 01 Saturating Add 16-bit QADD16 v7E-M
		case 0b00101: return opcode.qadd16_t;
		// 010 01 Saturating Add, Subtract QASX v7E-M
		case 0b01001: return opcode.qasx_t1;
		// 110 01 Saturating Subtract, Add QSAX v7E-M
		case 0b11001: return opcode.qsax_t1;
		// 101 01 Saturating Subtract 16-bit QSUB16 v7E-M
		case 0b10101: return opcode.qsub16_t1;
		// 000 01 Saturating Add 8-bit QADD8 v7E-M
		case 0b00001: return opcode.qadd8_t1;
		// 100 01 Saturating Subtract 8-bit QSUB8 v7E-M
		case 0b10001: return opcode.qsub8_t1;
		// Halving instructions
		// 001 10 Halving Add 16-bit SHADD16 on page A7-427 v7E-M
		case 0b00110: return opcode.shadd16_t1;
		// 010 10 Halving Add, Subtract SHASX on page A7-429 v7E-M
		case 0b01010: return opcode.shasx_t1;
		// 110 10 Halving Subtract, Add SHSAX on page A7-430 v7E-M
		case 0b11010: return opcode.shsax_t1;
		// 101 10 Halving Subtract 16-bit SHSUB16 on page A7-431 v7E-M
		case 0b10110: return opcode.shsub16_t1;
		// 000 10 Halving Add 8-bit SHADD8 on page A7-428 v7E-M
		case 0b00010: return opcode.shadd8_t1;
		// 100 10 Halving Subtract 8-bit SHSUB8 on page A7-432 v7E-M
		case 0b10010: return opcode.shsub8_t1;
		default:      break;
	}
	return opcode.invalid;
}

// ======================================
//  Decode Unsigned Parallel Add and Sub
// ======================================		
		
opcode decode_unsigned_parallel_add_and_sub(const uint instr) {
	immutable  op1  = slice(instr, 20, 3);
	immutable  op2  = slice(instr,  4, 2);
	const uint op12 = (op1 << 2) | op2;
	switch (op12) {		
		// 001 00 Add 16-bit UADD16 on page A7-525 v7E-M
		case 0b00100: return opcode.uadd16_t1;
		// 010 00 Add, Subtract UASX on page A7-527 v7E-M
		case 0b01000: return opcode.uasx_t1;
		// 110 00 Subtract, Add USAX on page A7-550 v7E-M
		case 0b11000: return opcode.usax_t1;
		// 101 00 Subtract 16-bit USUB16 on page A7-551 v7E-M
		case 0b10100: return opcode.usub16_t1;
		// 000 00 Add 8-bit UADD8 on page A7-526 v7E-M
		case 0b00000: return opcode.uadd8_t1;
		// 100 00 Subtract 8-bit USUB8 on page A7-552 v7E-M
		case 0b10000: return opcode.usub8_t1;
		// Saturating instructions
		// 001 01 Saturating Add 16-bit UQADD16 on page A7-539 v7E-M
		case 0b00101: return opcode.uqadd16_t1;
		// 010 01 Saturating Add, Subtract UQASX on page A7-541 v7E-M
		case 0b01001: return opcode.uqasx_t1;
		// 110 01 Saturating Subtract, Add UQSAX on page A7-542 v7E-M
		case 0b11001: return opcode.uqsax_t1;
		// 101 01 Saturating Subtract 16-bit UQSUB16 on page A7-543 v7E-M
		case 0b10101: return opcode.uqsub16_t1;
		// 000 01 Saturating Add 8-bit UQADD8 on page A7-540 v7E-M
		case 0b00001: return opcode.uqadd8_t1;
		// 100 01 Saturating Subtract 8-bit UQSUB8 on page A7-544 v7E-M
		case 0b10001: return opcode.uqsub8_t1;
		// Halving instructions
		// 001 10 Halving Add 16-bit UHADD16 on page A7-530 v7E-M
		case 0b00110: return opcode.uhadd16_t1;
		// 010 10 Halving Add, Subtract UHASX on page A7-532 v7E-M
		case 0b01010: return opcode.uhasx_t1;
		// 110 10 Halving Subtract, Add UHSAX on page A7-533 v7E-M
		case 0b11010: return opcode.uhsax_t1;
		// 101 10 Halving Subtract 16-bit UHSUB16 on page A7-534 v7E-M
		case 0b10110: return opcode.uhsub16_t1;
		// 000 10 Halving Add 8-bit UHADD8 on page A7-531 v7E-M
		case 0b00010: return opcode.uhadd8_t1;
		// 100 10 Halving Subtract 8-bit UHSUB8 on page A7-535 v7E-M
		case 0b10010: return opcode.uhsub8_t1;
		default: break;
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
		case 0b00000000: return opcode.lsl_reg_t2;
		case 0b00100000: return opcode.lsr_reg_t2;
		case 0b01000000: return opcode.asr_reg_t2;
		case 0b01100000: return opcode.ror_reg_t2;
		default: break;
	}
	switch (op1_op2m) {
		case 0b00001000: return rn == pc ? opcode.sxth_t2   : opcode.sxtah_t1;
		case 0b00011000: return rn == pc ? opcode.uxth_t2   : opcode.uxtah_t1;
		case 0b00101000: return rn == pc ? opcode.sxtb16_t1 : opcode.sxtab16_t1;
		case 0b00111000: return rn == pc ? opcode.uxtb16_t1 : opcode.uxtab16_t1;
		case 0b01001000: return rn == pc ? opcode.sxtb_t2   : opcode.sxtab_t1;
		case 0b01011000: return rn == pc ? opcode.uxtb_t2   : opcode.uxtab_t1;
		default: break;
	}
	// 1xxx 00xx
	if (((op1 & 0b1000) == 0b1000) && ((op2 & 0b1100) == 0b0000)) {
		return decode_signed_parallel_add_and_sub(instr);
	}
	if (((op1 & 0b1000) == 0b1000) && ((op2 & 0b1100) == 0b0100)) {
		return decode_unsigned_parallel_add_and_sub(instr);
	}
	if (((op1 & 0b1100) == 0b1000) && ((op2 & 0b1100) == 0b1000)) {
		return misc_ops(instr);
	}
	return opcode.invalid;
}

// ===============================
//  Decode Store Single Data Item
// ===============================

opcode decode_store_single_data_item(const uint instr) {
	immutable op1 		     = slice(instr, 21, 3);
	immutable op2 		     = slice(instr,  6, 6);
	immutable masked_op2     = cast(ubyte)(op2 & 0x20);
	immutable op1_masked_op2 = cast(ushort)((op1 << 6) | masked_op2);
	switch (op1_masked_op2) 
	{
		case 0b100100000:
		case 0b100000000: return opcode.strb_imm_t2;
		case 0b000100000: return opcode.strb_imm_t3;
		case 0b000000000: return opcode.strb_reg_t2;
		case 0b101000000:
		case 0b101100000: return opcode.strh_imm_t2;
		case 0b001100000: return opcode.strh_imm_t3;
		case 0b001000000: return opcode.strh_reg_t2;
		case 0b110000000:
		case 0b110100000: return opcode.str_imm_t3;
		case 0b010100000: return opcode.str_imm_t4;
		case 0b010000000: return opcode.str_reg_t2;
		default         : break;
	}
	return opcode.invalid;
}

// op0 op1 op2 op3 op4 op5 op6 op7 Instruction
// - 1x00 1 0 != 11 - - - VLDRB, VLDRH, VLDRW T2
// 1x01
// 0x01
// 1 01xx - 1 != 11 - - 1 VLD4 T1
// 1 01xx - 1 != 11 - - 0 VLD2 T1
// 0 - - 1 01 - - - VLDRB, VLDRH, VLDRW T6
// 0 - - 1 10 - - - VLDRB, VLDRH, VLDRW T7
// 0 - - 1 00 - - - VLDRB, VLDRH, VLDRW T5
// 1 1xxx - 1 0x - - - VLDRB, VLDRH, VLDRW, VLDRD (vector) T5
// - 01x0 - 0 - 1 1 - VLDRB, VLDRH, VLDRW, VLDRD (vector) T4
// 1 1xxx - 1 1x - - - VLDRB, VLDRH, VLDRW, VLDRD (vector) T6
// - 01x0 - 0 - 0 0 - VLDRB, VLDRH, VLDRW, VLDRD (vector) T1
// - 01x0 - 0 - 1 0 - VLDRB, VLDRH, VLDRW, VLDRD (vector) T3
// - 01x0 - 0 - 0 1 - VLDRB, VLDRH, VLDRW, VLDRD (vector) T2
// - 1xx0 - 0 11 - - - VLDR (System Register) T1
// 1xx1
// 0xx1
// - 1x00 0 0 != 11 - - - VLDRB, VLDRH, VLDRW T1
// 1x01
// 0x01
// 0 00x0 - 0 1x - - - VMOV (two general-purpose registers to two 32 bit vector lanes) T1
opcode decode_vector_load(const uint instr) {
	immutable op0 = slice(instr, 28, 1);
	immutable op1 = slice(instr, 21, 4);
	immutable op2 = slice(instr, 19, 1);
	immutable op3 = slice(instr, 12, 1);
	immutable op4 = slice(instr,  7, 2);
	immutable op5 = slice(instr,  6, 1);
	immutable op7 = slice(instr,  0, 1);
	if ((op0 == 0b0010) && (op3 == 0b100) && (op4 == 0b1)) {
		return opcode.vmov_t1;
	}
	if ((op0 == 0b0) && (op3 == 0b1) && (op4 == 0b10)) {
		return opcode.vldrw_t7;
	}
	if (((op0 & 0b1101) == 0b0100) && (op1 == 0b1) && (op2 == 0b1111) && ((op3 & 0b100) == 0b100) && (op5 == 0b0)) {
		return opcode.vscclrm_t1;
	}   
	if (((op0 & 0b1101) == 0b0100) && (op1 == 0b1) && (op2 == 0b1111) && ((op3 & 0b100) == 0b000)) {
		return opcode.vscclrm_t2;
	} 
	if (((op0 & 0b1001) == 0b1000) && (op1 == 0b1) && ((op3 & 0b100) == 0b000)) {
		return opcode.vldr_t2;
	}  
	if (((op0 & 0b1001) == 0b1000) && (op1 == 0b1) && ((op3 & 0b100) == 0b100)) {
		return opcode.vldr_t1;
	}  
	if (((op0 & 0b1101) == 0b0001) && (op1 == 0b1) && ((op3 & 0b110) == 0b000)) {
		return opcode.vlldm_t1;
	}  
	if (((op0 & 0b1101) == 0b0001) && (op1 == 0b1) && ((op3 & 0b110) == 0b010)) {
		return opcode.vlldm_t2;
	}
	if (((op0 & 0b1001) == 0b1000) && (op1 == 0b0) && ((op3 & 0b100) == 0b000)) {
		return opcode.vstr_t2;
	}
	if (((op0 & 0b1101) == 0b0001) && (op1 == 0b0) && ((op3 & 0b110) == 0b000)) {
		return opcode.vlstm_t1;
	}
	if (((op0 & 0b1101) == 0b0001) && (op1 == 0b0) && ((op3 & 0b110) == 0b010)) {
		return opcode.vlstm_t2;
	}     
	if (((op0 & 0b1001) == 0b1000) && (op1 == 0b0) && ((op3 & 0b100) == 0b100)) {
		return opcode.vstr_t1;
	} 
	return opcode.invalid;
}

opcode decode_vector_store(const uint instr) {
	return opcode.invalid;
}

opcode decode_copro_ldst_mv(const uint instr) {
	return opcode.invalid;
}

opcode decode_fp_vec_ldst_mv_cmplx_arithmetic(const uint instr) {
	return opcode.invalid;
}

opcode decode_copro_fp_ldst_mv_sec(const uint instr) {
	return opcode.invalid;
}

opcode decode_fp_vec_misc(const uint instr) {
	return opcode.invalid;
}

opcode misc_vec_arithmetic(const uint instr) {
	return opcode.invalid;
}

opcode fp_vec_ldst_mv_copro(const uint instr) {
	immutable op0 = slice(instr,  9, 4);
	immutable op1 = slice(instr, 20, 1);
	switch (op0) {
		case 0b111:
			return (op1 == 0b1) ? decode_vector_load(instr) : decode_vector_store(instr);
		case 0b110:
			// UNALLOCATED
			assert(0); 
		case 0b000:
		case 0b001:
		case 0b010:
		case 0b011:
			return decode_copro_ldst_mv(instr);
		case 0b100:
			return decode_fp_vec_ldst_mv_cmplx_arithmetic(instr);
		case 0b101:
			return decode_copro_fp_ldst_mv_sec(instr);
		default:
			break;
	}
	return opcode.invalid;			
}

opcode decode_copro_fp_vec(const uint instr) {
	immutable op0 = slice(instr, 24, 2);
	switch (op0) {
		case 0b10:
			return decode_fp_vec_misc(instr);
		case 0b11:
			return misc_vec_arithmetic(instr);
		case 0b01:
		case 0b00:
			return fp_vec_ldst_mv_copro(instr);
		default: break;
	}
	return opcode.invalid;	
}

// =======================
//  Decode Floating Point
// =======================

opcode decode_floating_point(const uint instr) {
	immutable L  = slice(instr, 20, 1);
	immutable C  = slice(instr,  8, 1);
	immutable A  = slice(instr, 21, 3);
	immutable B  = slice(instr,  5, 2);
	immutable LC = (L << 1) | C;
	switch (LC) 
	{
		case 0b00: 
			return (A == 0b111) ? opcode.vmsr_t1 : opcode.invalid;
		case 0b10:
			// 32-bit transfer between ARM core and extension registers
			return (A == 0b111) ? opcode.vmrs_t1 : opcode.invalid; 
		default: 
			break;
	} 
	// Extension register load or store instructions
	immutable opc = slice(instr, 20, 5);
	immutable rn  = slice(instr, 16, 4);
	switch (opc) {
		case 0b10010:
		case 0b10110:
			if (rn == 0b1101)
				return opcode.vpush_t1;
			goto default;
		default:
			break;
			// assert(0, format("Unrecognized floating-point instruction: %08X", instr));
	}
	return decode_vector_load(instr);
}

opcode decode_load_byte_memory_hints(const uint instr) {
	immutable op2 = slice(instr,  6, 6);
	immutable op1 = slice(instr, 23, 2);
	immutable rt  = slice(instr, 12, 4);
	immutable rn  = slice(instr, 16, 4);
	// 0xF8180006
	enum pc = 0b1111;
	if (((op1 & 0b10) == 0b00) && (rn == pc) && (rt != pc)) 
		return opcode.ldrb_lit_t1;
	if ((op1 == 0b01) && (rn != pc) && (rt != pc)) 
		return opcode.ldrb_imm_t2;
	if ((op1 == 0b00) && ((op2 & 0b100100) == 0b100100) && (rn != pc) && (rt != pc)) 
		return opcode.ldrb_imm_t3;
	if ((op1 == 0b00) && ((op2 & 0b111100) == 0b110000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrb_imm_t3;
	if ((op1 == 0b00) && ((op2 & 0b111100) == 0b111000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrbt_t1;
	if ((op1 == 0b00) && (op2 == 0) && (rn != pc) && (rt != pc)) 
		return opcode.ldrb_reg_t2;
	if (((op1 & 0b10) == 0b10) && (rn == pc) && (rt != pc)) 
		return opcode.ldrsb_lit_t1;
	if ((op1 == 0b11) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsb_imm_t1;
	if ((op1 == 0b10) && ((op2 & 0b100100) == 0b100100) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsb_imm_t2;
	if ((op1 == 0b10) && ((op2 & 0b111100) == 0b110000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsb_imm_t2;
	if ((op1 == 0b10) && ((op2 & 0b111100) == 0b111000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsbt_t1;
	if ((op1 == 0b10) && (op2 == 0b000000) && (rn != pc) && (rt != pc)) 
		return opcode.ldrsb_reg_t2;
	if ((op1 == 0b00) && (op2 == 0b000000) && (rn != pc) && (rt == pc)) 
		return opcode.pld_reg_t1;
	if ((op1 == 0b01) && (rn != pc) && (rt == pc)) 
		return opcode.pld_imm_t1;
	if ((op1 == 0b00) && ((op2 & 0b111100) == 0b110000) && (rn != pc) && (rt == pc)) 
		return opcode.pld_imm_t2;
	if (((op1 & 0b10) == 0b00) && (rn == pc) && (rt == pc)) 
		return opcode.pld_lit_t1;
	return opcode.invalid;
}

opcode decode_loop(const uint instr) {
	immutable op0 = slice(instr, 20, 3);
	immutable op1 = slice(instr, 16, 4);
	immutable op2 = slice(instr, 13, 1);
	immutable op3 = slice(instr, 11, 1);
	if (((op0 & 0b010) == 0b010) && (op1 == 0b1111) && (op2 == 0b0)) {
		return opcode.le_t2;
	}
	if ((op0 == 0b001) && (op1 == 0b1111) && (op2 == 0b0)) {
		return opcode.le_t3;
	}
	if ((op0 == 0b000) && (op1 == 0b1111) && (op2 == 0b0)) {
		return opcode.le_t1;
	}
	if (((op0 & 0b100) == 0b100) && (op2 == 0b0)) {
		return opcode.wls_t1;
	}
	if (((op0 & 0b100) == 0b100) && (op2 == 0b1)) {
		return opcode.wls_t2;
	}
	if (((op0 & 0b100) == 0b000) && (op1 != 0b1111) && (op3 == 0b0)) {
		return opcode.wls_t3;
	}
	if (((op0 & 0b100) == 0b000) && (op1 != 0b1111) && (op2 == 0b1) && (op3 == 0b1)) {
		return opcode.vctp_t1;
	}
	if (((op0 & 0b100) == 0b000) && (op1 == 0b1111) && (op2 == 0b0)) {
		return opcode.lctp_t1;
	}
	if (((op0 & 0b100) == 0b000) && (op1 != 0b1111) && (op3 == 0b0)) {
		return opcode.wls_t4;
	}
	return opcode.invalid;
}

opcode decode_loop_and_branch(const uint instr) {
	immutable op0 = slice(instr, 23, 1);
	if (op0 == 0b0000) {
		return decode_loop(instr);
	}
	return opcode.invalid;
}

opcode decode_branch_misc_ctrl(const uint instr) {
	version (ARMv8_M) {
		immutable op3 = slice(instr, 14, 1);
		immutable op4 = slice(instr, 12, 1);
		immutable op6 = slice(instr,  0, 1);
		if ((op3 == 0b1) && (op4 == 0b0) && (op6 == 0b1)) {
			return decode_loop_and_branch(instr);
		}
	}
	immutable op1 = slice(instr, 12, 3);
	immutable op  = slice(instr, 20, 7);
	if (((op1 & 0b101) == 0b000) & (op == 0b0111011)) {
		immutable option = slice(instr, 0, 4);
		immutable opc    = slice(instr, 4, 4);
		if ((opc == 0b100) & ((option & 1011) != 0b0000)) 
			return opcode.dsb_t1;
		if (opc == 0b110) 
			return opcode.isb_t1;
		if (opc == 0b0101) 
			return opcode.dmb_t1;
	}
	if ((op1 & 0b101) == 0b101) 
		return opcode.bl_t1;
	if (((op1 & 0b101) == 0b000) & ((op & 0b1111110) == 0b0111110)) 
		return opcode.mrs_t1;
	if (((op1 & 0b101) == 0b000) & ((op & 0b1111110) == 0b0111000)) 
		return opcode.msr_t1;
	if (op == 0b0111010) {
		immutable _op1 = slice(instr, 8, 3);
		immutable _op2 = slice(instr, 0, 8);
		if (_op1 == 0b000) 
			if (_op2 == 0b00000000) 
				return opcode.nop_t2;
	}
	/*
	if (_op == 0b0111011) {
		ubyte __op = cast(ubyte)((instr >> 4) & 0b1111);
		return opcode.dsb; 
	}
	*/
	if (((op1 & 0b101) == 0b000) && ((op & 0b0111000) != 0b0111000)) {
		if (slice(instr, 12, 1) == 0b1) 
			return opcode.b_t4;
		return opcode.b_t3;
	}
	if ((op1 & 0b101) == 0b001) {
		if (slice(instr, 12, 1) == 0b1) 
			return opcode.b_t4;
		return opcode.b_t3;
	}
	return opcode.invalid;
}

opcode decode_load_word(const uint instr) {
	immutable op2 = slice(instr,  6, 6);
	immutable op1 = slice(instr, 23, 2);
	immutable rn  = slice(instr, 16, 4);
	enum pc = 0b1111;
	if ((op1 == 0b01) && (rn != pc)) 
		return opcode.ldr_imm_t3;
	if ((op1 == 0b00) && ((op2 & 0b100100) == 0b100100) && (rn != pc)) 
		return opcode.ldr_imm_t4;	
	if ((op1 == 0b00) && ((op2 & 0b111100) == 0b110000) && (rn != pc)) 
		return opcode.ldr_imm_t4;
	if ((op1 == 0b00) && ((op2 & 0b111100) == 0b111000) && (rn != pc)) 
		return opcode.ldrt_t1;
	if ((op1 == 0b00) && (op2 == 0b0) && (rn != pc)) 
		return opcode.ldr_reg_t2;
	if (((op1 & 0b10) == 0b00) && (rn == pc)) 
		return opcode.ldr_lit_t2;
	return opcode.invalid;
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

opcode decode_long_mult(const uint instr) {
	immutable op = slice(instr, 20, 3);
	// 011 1111 Unsigned Divide UDIV
	if (op == 0b011)
		return opcode.udiv_t1;
	// 010 0000 Unsigned Multiply Long UMULL
	if (op == 0b010) 
		return opcode.umull_t1;
	immutable _op1 = slice(instr, 20, 3);
	immutable _op2 = slice(instr,  4, 4);
	// 000 0000 Signed Multiply Long SMULL
	if ((_op1 == 0) && (_op2 == 0)) 
		return opcode.smull_t1;
	// 110 0000 Unsigned Multiply Accumulate Long UMLAL
	if ((_op1 == 0b110) && (_op2 == 0))
		return opcode.umlal_t1;
	// 0110 Unsigned Multiply Accumulate Accumulate Long
	// UMAAL (v7E-M)
	if ((_op1 == 0b110) && (_op2 == 0b0110))
		return opcode.umaal_t1;
	// 100 0000 Signed Multiply Accumulate Long SMLAL
	if ((_op1 == 0b100) && (_op2 == 0))
		return opcode.smlal_t1;
	// 001 1111 Signed Divide SDIV
	if ((_op1 == 0b001) && (_op2 == 0b1111))
		return opcode.sdiv_t1;
	// 101 110x Signed Multiply Subtract Long Dual SMLSLD, SMLSLDX (v7E-M)
	if ((_op1 == 0b101) && ((_op2 & 0b1110) == 0b1100))
		return opcode.smlsls_t1;
	// 10xx Signed Multiply Accumulate Long, Halfwords SMLALBB, SMLALBT, SMLALTB, SMLALTT (v7E-M)
	if ((_op1 == 0b100) && ((_op2 & 0b1100) == 0b1000))
		return opcode.smlalxy_t1;	
	// 110x Signed Multiply Accumulate Long Dual SMLALD, SMLALDX (v7E-M)
	if ((_op1 == 0b100) && ((_op2 & 0b1110) == 0b1100))
		return opcode.smlald_t1;	
	return opcode.invalid;
}
	
opcode decode_mnemonic(const uint instr) {
	immutable op1 = slice(instr, 27, 2);
	immutable op2 = slice(instr, 20, 7);
version (ARMv8_M) {
	{
		immutable op0 = slice(instr, 25, 4);
		if ((op0 & 0b0110) == 0b0110)
			return decode_copro_fp_vec(instr);
	}
}
version (ARMv7_M) {
	if ((op1 == 0b01) && ((op2 & 0b1000000) == 0b1000000)) 
		return decode_floating_point(instr);
}
	if (op1 == op1_32.grp1) { 
		// Data processing (shifted register)
		if ((op2 & op2_32.data_proc_shift_reg) == op2_32.data_proc_shift_reg) 
			return decode_data_proc_shift_reg(instr);
		// Load multiple and sotre multiple
		if ((op2 & op2_32.load_store_mult) == 0b0000000)  
			return decode_load_store_mult(instr);
		// Load/store dual or exclusive
		if ((op2 & op2_32.load_store_dual) == 0b0000100) 
			return decode_load_store_dual(instr);
	}
	if (op1 == op1_32.grp2) {
		immutable op = slice(instr, 15, 1); 
		immutable rd = slice(instr, 20, 4); 
		if (op)
			return decode_branch_misc_ctrl(instr);
		// Data processing (modified immediate)
		if (((op2 & op2_32.data_proc_imm) == 0b0000000) && !op) 
			return decode_data_proc_imm(instr);
		// Data processing (plain binary immediate)
		if (((op2 & op2_32.data_proc_bin_imm) == op2_32.data_proc_bin_imm) && !op) 
			return decode_data_proc_bin_imm(instr);
	}
	if (op1 == op1_32.grp3) {
		// Load halfword, memory hints
		if ((op2 & op2_32.ldh) == 0b0000011) 
			return decode_load_half_word(instr);
		// Long multiply, long multiply accumulate, and divide
		if ((op2 & op2_32.long_mult) == 0b0111000) 
			return decode_long_mult(instr);
		// Multiply, multiply accumulate, and absolute difference
		if ((op2 & op2_32.mult) == 0b0110000) 
			return decode_mult(instr);
		// Data processing (register)
		if ((op2 & op2_32.data_proc_reg) == 0b0100000) 
			return decode_data_proc_reg(instr);
		// Load word
		if ((op2 & op2_32.load_word) == 0b0000101) 
			return decode_load_word(instr);
		// Store single data item
		if ((op2 & op2_32.store_single_data_item) == 0b0000000) 
			return decode_store_single_data_item(instr);
		// Load byte, memory hints
		if ((op2 & op2_32.load_byte) == 0b0000001) 
			return decode_load_byte_memory_hints(instr);
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
		test_case(0xeb0101a3,  opcode.add_reg_t3),
		test_case(0xf7ffffda,       opcode.bl_t1),
		test_case(0xf3af8000, 	   opcode.nop_t2),
		test_case(0xe8bd4008, 	   opcode.pop_t2),
		test_case(0xf5a33a80,  opcode.sub_imm_t3),
		test_case(0xf008ff15,       opcode.bl_t1),
		test_case(0xf009f8a6, 	    opcode.bl_t1),
		test_case(0xf003030c,  opcode.and_imm_t1),
		test_case(0xfbb2f3f3,     opcode.udiv_t1),
		test_case(0xf3c20208,     opcode.ubfx_t1),
		test_case(0xfb02f303,      opcode.mul_t2),
		test_case(0xfa22f303,  opcode.lsr_reg_t2),
		test_case(0xf4434380,  opcode.orr_imm_t1),
		test_case(0xf1070314,  opcode.add_imm_t3),
		test_case(0xf0230310,  opcode.bic_imm_t1),
		test_case(0xf64f03ff,  opcode.mov_imm_t3),
		test_case(0xf9973007,opcode.ldrsb_imm_t1),
		test_case(0xf8412023,  opcode.str_reg_t2),
		test_case(0xf8dfd034,  opcode.ldr_lit_t2),
		test_case(0xf3bf8f4f,      opcode.dsb_t1),
		test_case(0xf1c30307,  opcode.rsb_imm_t2),
		test_case(0xfba22303,    opcode.umull_t1),
		test_case(0xe9c72300, opcode.strd_imm_t1),
		test_case(0xf67fae90,        opcode.b_t3),
		test_case(0xe92d4fb0,     opcode.push_t2),
		test_case(0xea4161d2,  opcode.orr_reg_t2),
		test_case(0xebb2080a,  opcode.sub_reg_t2),
		test_case(0xeb63090b,  opcode.sbc_reg_t2),
		test_case(0xeb45030b,  opcode.adc_reg_t2),
		test_case(0xf06f0240,  opcode.mvn_imm_t1),
		test_case(0xe8533f00,    opcode.ldrex_t1),
		test_case(0xe8533f00,    opcode.ldrex_t1),
		test_case(0xe8412300,    opcode.strex_t1),
		test_case(0xfb0e7711,      opcode.mls_t1),
		test_case(0xea1c0f0e,  opcode.tst_reg_t2),
		test_case(0xea010808,  opcode.and_reg_t2),
		test_case(0xea23030c,  opcode.bic_reg_t2),
		test_case(0xf7ffbfbb,        opcode.b_t4),
		test_case(0xeba30605,  opcode.sub_reg_t2),
		test_case(0xea4f06a6,  opcode.asr_imm_t2),
		test_case(0xf8553b04,  opcode.ldr_imm_t4), 
		test_case(0xf7ffb8f7,        opcode.b_t4),
		test_case(0xf8441023,  opcode.str_reg_t2),
		test_case(0xf8c46188,  opcode.str_imm_t3),
		test_case(0xe8bd4008,      opcode.pop_t2),
		test_case(0xeb0101a3,  opcode.add_reg_t3),
		test_case(0xf1b37f80,  opcode.cmp_imm_t2),
		test_case(0xf1070318,  opcode.add_imm_t3),
		test_case(0xfa02f303,  opcode.lsl_reg_t2),
		test_case(0xe92d4fb0,     opcode.push_t2),
		test_case(0xea400301,  opcode.orr_reg_t2),
		test_case(0xe9d7453a, opcode.ldrd_imm_t1),
		test_case(0xe9d78928, opcode.ldrd_imm_t1),
		test_case(0xf04f31ff,  opcode.mov_imm_t2),
		test_case(0xf04f30ff,  opcode.mov_imm_t2),
		test_case(0xe8bd4010,      opcode.pop_t2),
		test_case(0xf883203c, opcode.strb_imm_t2),
		test_case(0xf9973007,opcode.ldrsb_imm_t1),
		test_case(0xf890f000,  opcode.pld_imm_t1),
		test_case(0xf893303d, opcode.ldrb_imm_t2),
		test_case(0xf997300f,opcode.ldrsb_imm_t1),
		test_case(0xf8832300, opcode.strb_imm_t2),
		test_case(0xf8032b01, opcode.strb_imm_t3),
		test_case(0xf8522023,  opcode.ldr_reg_t2),
		test_case(0xf8dfd034,  opcode.ldr_lit_t2),
		test_case(0xf8d33088,  opcode.ldr_imm_t3),
		test_case(0xf8533022,  opcode.ldr_reg_t2),
		test_case(0xf3ef8305,      opcode.mrs_t1),
	 	test_case(0xf3808808,      opcode.msr_t1),
	 	test_case(0xf3bf8f6f, 	   opcode.isb_t1),
	 	test_case(0xf3bf8f4f, 	   opcode.dsb_t1),
	 	test_case(0xf8114b01, opcode.ldrb_imm_t3),
	 	test_case(0xf3c20208,     opcode.ubfx_t1),
	 	test_case(0xf8423c20,  opcode.str_imm_t4),
	 	test_case(0xf003030f,  opcode.and_imm_t1),
	 	test_case(0xf0230301,  opcode.bic_imm_t1),
	 	test_case(0xfb035500,      opcode.mla_t1),
	 	test_case(0xfab0f080,      opcode.clz_t1),
	 	test_case(0xf1100f16,  opcode.cmn_imm_t1),
	 	test_case(0xf8973033, opcode.ldrb_imm_t2),
	 	test_case(0xf8832042, opcode.strb_imm_t2),
	 	test_case(0xf8a320f8, opcode.strh_imm_t2),
	 	test_case(0xe8b04ff0,      opcode.ldm_t2),
	    test_case(0xea620205,  opcode.orn_reg_t1),
	    test_case(0xf4434380,  opcode.orr_imm_t1),
	    test_case(0xf7feffc5,       opcode.bl_t1),
	    test_case(0xf7f6f9b5, 		opcode.bl_t1),
	    test_case(0xf8832023, opcode.strb_imm_t2),
		test_case(0xf24412a0,  opcode.mov_imm_t3),
		test_case(0xf04f23e0,  opcode.mov_imm_t2),
		test_case(0xf244129f,  opcode.mov_imm_t3),
		test_case(0xf0420207,  opcode.orr_imm_t1),
		test_case(0xf1420200,  opcode.adc_imm_t1),
		test_case(0xf8245035, opcode.strh_reg_t2),
		test_case(0xf8a28002, opcode.strh_imm_t2),
		test_case(0xf1720100,  opcode.sbc_imm_t1),
		test_case(0xfa90f7a0,     opcode.rbit_t2),
		test_case(0xf837c012, opcode.ldrh_reg_t2),
		test_case(0xe8dff012,  opcode.tbb_tbh_t1),
		test_case(0xF3838814,      opcode.msr_t1),
		test_case(0xf8213012, opcode.strh_reg_t2),
		test_case(0xeee13a10,     opcode.vmsr_t1),
		test_case(0xf9b4500c,opcode.ldrsh_imm_t1),
		test_case(0xe8d30fef, 	 opcode.ldaex_t1),
		test_case(0xe8c32fe1,    opcode.stlex_t1),
		test_case(0xe840f300,       opcode.tt_t1),
		test_case(0xe8d00faf, 	   opcode.lda_t1),
	];

	foreach (t; tests) {
		auto actual = decode_mnemonic(t.instr);
		assert(
		    actual == t.expected,
		    format("Failed for instruction 0x%08X, got %s instead of %s", t.instr, actual.to!string, t.expected.to!string)
		);
    }
}
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

