enum string ARMv7_M_OPCODES = q{
	// store multiple registers
	stm_t1,
	// load multiple registers
	ldm_t1,
	// pc-rel
	adr_t1,
	// branch sup call
	svc_t1, b_t1,
	// add, shift
	lsl_imm_t1, lsr_imm_t1, asr_imm_t1, add_reg_t1, sub_reg_t1,
	add_imm_t1, add_imm_t2, sub_imm_t1, sub_imm_t2, mov_imm_t1,
	cmp_imm_t1,
	// data processing
	cmn_reg_t1, tst_reg_t1, adc_reg_t1, and_reg_t1, bic_reg_t1,
	cmp_reg_t1, eor_reg_t1, lsl_reg_t1, lsr_reg_t1, asr_reg_t1,
	mvn_reg_t1, rsb_imm_t1, sbc_reg_t1, mul_t1,     orr_reg_t1,
	ror_reg_t1,
	// ????
	mov_reg_t2,
	// misc
	cps_t1,   add_sp_t1, add_sp_t2, sub_sp_t1, cbnz_t1,    cbz_t1,
	sxth_t1,  sxtb_t1,   uxth_t1,   uxtb_t1,   push_t1,    rev_t1,
	rev16_t1, revsh_t1,  pop_t1,    bkpt_t1,   if_then_t1, nop_t1,
	yield_t1, wfe_t1,    wfi_t1,    sev_t1,
	// decode special and exchange
	add_reg_t2, cmp_reg_t2, mov_reg_t1, bx_t1, blx_t1,
	// uncond branch
	b_t2,
	// load store
	str_reg_t1, strh_reg_t1, strb_reg_t1,
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
	strd_imm_t1,
	ldrd_imm_t1,
	strexb_t1,
	strexh_t1,
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

	vmsr_t1, vmrs_t1, vpush_t1, vpush_t2, 

	invalid,
};

enum string ARMv8_M_OPCODES = q{
	// loop instructions
	le_t2, le_t3, le_t1, wls_t1, wls_t2, wls_t3, vctp_t1, lctp_t1, wls_t4,

	// vector load
	vmov_t1,  vldrw_t7, vscclrm_t1, vscclrm_t2,
	vldr_t2,  vldr_t1,  vlldm_t1,   vlldm_t2, vstr_t2,
	vlstm_t1, vlstm_t2, vstr_t1,

	// floating-point and vector complex arithmetic
	vcadd_t1, //vcmla_t1,

	tt_t1,

	lda_t1, ldaex_t1, stlex_t1, 
};

mixin(() {
    string code = "enum opcode : ushort {\n";

    code ~= ARMv7_M_OPCODES;

version (ARMv8_M) {
	code ~= ARMv8_M_OPCODES;
}

    code ~= "}\n";

    return code;
}());                 