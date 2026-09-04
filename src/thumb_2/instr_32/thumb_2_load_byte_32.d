// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Load Byte, Memory Hints	    					     *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;
import std.format   : format;
import std.algorithm.comparison : clamp;
import std.traits               : isSigned, isIntegral;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ***************************************************************************************
// *									   LDRB 										 *
// ***************************************************************************************

// =======================
//  Parse LDRB(Immediate)
// =======================

// LDRB<c>.W <Rt>,[<Rn>{,#<imm12>}]
// First Half-Word: [15:4] 111110001001, [3:0] Rn
// Second Half-Word: [15:12] Rt, [10] P, [9] U, [8] W, [7:0] imm8
instr_32 parse_ldrb_imm_t2(const uint instr) {
	return instr_32(wback: cast(bool)slice(instr,  8, 1),
				    add:   true,
				    index: true,
				    rt:    cast(reg )slice(instr, 12, 4),
				    rn:    cast(reg )slice(instr, 16, 4),
				    imm:   slice(instr, 0, 12)); 
	// index = TRUE; add = TRUE; wback = FALSE;
}

// =======================
//  Parse LDRB(Immediate)
// =======================

// LDRB<c> <Rt>,[<Rn>,#-<imm8>]
// LDRB<c> <Rt>,[<Rn>],#+/-<imm8>
// LDRB<c> <Rt>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:4] 111110000001, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11] 1, [10] P, [9] U, [8] W, [7:0] imm8
instr_32 parse_ldrb_imm_t3(const uint instr) {
	return instr_32(wback: cast(bool)slice(instr,  8, 1),
				    add:   cast(bool)slice(instr,  9, 1),
				    index: cast(bool)slice(instr, 10, 1),
				    rt:    cast(reg )slice(instr, 12, 4),
				    rn:    cast(reg )slice(instr, 16, 4),
				    imm:   slice(instr, 0, 8)); 
}

// =========================
//  Execute LDRB(Immediate)
// =========================

void 
execute_ldrb_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_ldrb_imm(instr, vm);
}	

void 
execute_ldrb_imm_t3
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_ldrb_imm(instr, vm);
}	

void 
execute_ldrb_imm
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rn  			 = vm.get_reg(instr.rn);
	immutable imm 			 = instr.imm;
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm;
	const size_t addr        = instr.index ? offset_addr : rn;
	immutable b   			 = vm.read_byte(addr);
	vm.set_reg(instr.rt, b);
	if (instr.wback)
		vm.set_reg(instr.rn, offset_addr);  
}

// LDRB<c>.W <Rt>,[<Rn>{,#<imm12>}]
string convert_ldrb_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrb%s.w %s, [%s%s]", get_condition_string(cond),
										 get_reg_name(instr.rt),
									     get_reg_name(instr.rn),
									     instr.imm != 0 ? format(", #%d", instr.imm) : "");
}

// LDRB<c> <Rt>,[<Rn>,#-<imm8>]
// LDRB<c> <Rt>,[<Rn>],#+/-<imm8>
// LDRB<c> <Rt>,[<Rn>,#+/-<imm8>]!
string convert_ldrb_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrb%s.w %s, %s", get_condition_string(cond),
									 get_reg_name(instr.rt),
									 get_addr_string(instr));
}
// ---------------------------------------------------------------------------------------


// ***************************************************************************************
// *									  LDRSB 										 *
// ***************************************************************************************
// Load Register Signed Byte (immediate) calculates an address from a base register value 
// and an immediate offset, loads a byte from memory, sign-extends it to form a 32-bit word, 
// and writes it to a register. It can use offset, post-indexed, or pre-indexed addressing

// ========================
//  Parse LDRSB(Immediate)
// ========================

// LDRSB<c> <Rt>,[<Rn>,#<imm12>]
// First Half-Word: [15:4] 111110011001, [3:0] Rn
// Second Half-Word: [15:12] Rt,[11:0] imm12
instr_32 parse_ldrsb_imm_t1(const uint instr) {
	return instr_32(rn:    cast(reg)slice(instr, 16, 4),
					rt:    cast(reg)slice(instr, 12, 4),
					// imm32 = ZeroExtend(imm12, 32);
					imm:   slice(instr, 0, 12),
					index: true,
					add:   true);
	// index = TRUE; add = TRUE; wback = FALSE;
}

// ========================
//  Parse LDRSB(Immediate)
// ========================

// LDRSB<c> <Rt>,[<Rn>,#-<imm8>]
// LDRSB<c> <Rt>,[<Rn>],#+/-<imm8>
// LDRSB<c> <Rt>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:4] 111110011001, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_ldrsb_imm_t2(const uint instr) {
	return instr_32(wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rn:    cast(reg )slice(instr, 16, 4),
					rt:    cast(reg )slice(instr, 12, 4),
					// imm32 = ZeroExtend(imm8, 32);
					imm:   slice(instr, 0, 8));
}

// ==========================
//  Execute LDRSB(Immediate)
// ==========================

void 
execute_ldrsb_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_ldrsb_imm(instr, vm);
}

void 
execute_ldrsb_imm_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_ldrsb_imm(instr, vm);
}

void 
execute_ldrsb_imm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rn  			 = vm.get_reg(instr.rn);
	immutable imm 			 = instr.imm;
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm;
	const size_t addr        = instr.index ? offset_addr : rn;
	immutable b   			 = vm.read_byte(addr);
	immutable data           = cast(int)cast(byte)b;
	vm.set_reg(instr.rt, data);
	if (instr.wback)
		vm.set_reg(instr.rn, offset_addr);  
}

// LDRSB<c> <Rt>,[<Rn>,#<imm12>]
string convert_ldrsb_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrsb.w%s %s, [%s, #%d]", get_condition_string(cond), 
									         get_reg_name(instr.rt),
									         get_reg_name(instr.rn),
									         instr.imm);
}

// LDRSB<c> <Rt>,[<Rn>,#-<imm8>]
// LDRSB<c> <Rt>,[<Rn>],#+/-<imm8>
// LDRSB<c> <Rt>,[<Rn>,#+/-<imm8>]!
string convert_ldrsb_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrsb%s.w %s, %s", get_condition_string(cond), 
									  get_reg_name(instr.rt),
									  get_addr_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LDRSB 										 *
// ***************************************************************************************
// LDRSB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]

// ***************************************************************************************
// *									   LDRB 										 *
// ***************************************************************************************

// LDRB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
instr_32 parse_ldrb_reg_t2(const uint instr) { 
	return instr_32(rm:	     cast(reg)slice(instr,  0, 4), 
					rt:	     cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4),
					shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					index:   true,
		            add:     true);
	// index = TRUE; add = TRUE; wback = FALSE;
}

void 
execute_ldrb_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable    rm          = vm.get_reg(instr.rm);
	immutable    rn 	     = vm.get_reg(instr.rn);
	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
	immutable    offset      = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// offset_addr = if add then (R[n] + offset) else (R[n] - offset);
	const size_t offset_addr = instr.add   ? rn + offset : rn - offset;
	// address = if index then offset_addr else R[n];
	const size_t addr        = instr.index ? offset_addr : rn;
	// R[t] = ZeroExtend(MemU[address,1],32);
	immutable data           = vm.read_byte(addr);
	vm.set_reg(instr.rt, data);
}

// LDRB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_ldrb_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrb%s.w %s, [%s, %s%s]", get_condition_string(cond),
											 get_reg_name(instr.rt),
											 get_reg_name(instr.rn),
											 get_reg_name(instr.rm),
											 get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   PLD 										     *
// ***************************************************************************************

instr_32 parse_pld_reg_t1(const uint instr) {
	return instr_32(rm:      cast(reg)slice(instr,  0, 4),
					rn:      cast(reg)slice(instr, 16, 4),
					shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl);
}

void
execute_pld_reg_t1 
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	return;
}

// PLD<c> [<Rn>,<Rm>{,LSL #<imm2>}]
string convert_pld_reg_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("pld%s [%s, %s%s]", get_condition_string(cond),
									  get_reg_name(instr.rn),
									  get_reg_name(instr.rm),
									  get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   PLD 										     *
// ***************************************************************************************

// PLD<c> [<Rn>,#<imm12>]
instr_32 parse_pld_imm_t1(const uint instr) {
	return instr_32(rn:  cast(reg)slice(instr, 16, 4),
					imm: slice(instr, 0, 12));
}

void 
execute_pld_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {}

// PLD<c> [<Rn>,#<imm12>]
string convert_pld_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("pld%s [%s%s]", get_condition_string(cond),
								  get_reg_name(instr.rn),
								  instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

void execute_ldrexh_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pop_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_push_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_stmb_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldmb_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_clrex_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_wfe_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_wfi_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sev_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_dbg_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_cmn_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_adr_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

// MOVT<c> <Rd>,#<imm16>
instr_32 parse_movt_t1(const uint instr) {
	immutable imm8  = slice(instr,  0, 8);
	immutable imm3  = slice(instr, 12, 3);
	immutable imm4  = slice(instr, 16, 4);
	immutable i     = slice(instr, 26, 1);
	immutable imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
	return instr_32(rd:  cast(reg)slice(instr, 8, 4),
					imm: imm16);
}

void 
execute_movt_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// if ConditionPassed() then
	// EncodingSpecificOperations();
	uint imm = instr.imm;
	imm = (imm << 16);
	// R[d]<31:16> = imm16;
	uint val = vm.get_reg(instr.rd);
	val &= 0x0000ffff;
	const uint res = imm | val;
	vm.set_reg(instr.rd, res);
	// R[d]<15:0> unchanged
}

string convert_movt_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("movt%s %s%s", get_condition_string(cond),
								 get_reg_name(instr.rd),
								 get_imm_string(instr.imm));
}

void execute_ror_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}


void execute_sxtab_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_sxtab16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sxtb16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uxtab16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uxtb16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ror_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

instr_32 parse_qadd_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_qadd_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	long sum = cast(long)vm.get_reg(instr.rm) + cast(long)vm.get_reg(instr.rn);
	auto res = signed_sat_q!int(sum);
	vm.set_reg(instr.rd, cast(uint)res.value);
	if (res.saturated)
		vm.set_q(true);
}

void execute_qdadd_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qsub_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qdsub_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_rev_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrh_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrh_imm_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrht_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}






void execute_ldrsh_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {


}


void execute_ldrsh_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsh_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrsht_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}


void execute_ldrb_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrbt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsb_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsbt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

instr_32 parse_ldrsb_reg_t2(const uint instr) {
	// if Rt == '1111' then SEE "PLI (register)";
	// if Rn == '1111' then SEE "LDRSB (literal)";
	// if !HaveMainExt() then UNDEFINED;
	// if t == 13 || m IN {13,15} then UNPREDICTABLE;
	return instr_32(
		rm:		 cast(reg)slice(instr,  0, 4),
		rt: 	 cast(reg)slice(instr, 12, 4),
		rn:  	 cast(reg)slice(instr, 16, 4),
		index:   true,
		add:	 true,
		wback:   true,
		shift_t: shift_type.lsl,
		shift_n: slice(instr, 4, 2)
	);
}

void execute_ldrsb_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm = vm.get_reg(instr.rm);
	immutable rn = vm.get_reg(instr.rn);
	immutable offset = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	immutable offset_addr = instr.add ? (rn + offset) : (rn - offset);
	immutable address = instr.index ? offset_addr : rn;
	// R[t] = SignExtend(MemU[address, 1], 32);
	vm.set_reg(instr.rt, cast(uint)cast(byte)vm.read_byte(address));
}

string convert_ldrsb_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	// return format("vmrs%s %s, FPSCR", get_condition_string(cond),
	// 								  get_reg_name(instr.rt));
	return "x";
}

void execute_pld_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}


void execute_smlsls_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_smlalxy_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_smlald_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_invalid(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

instr_32 
parse_smusd_t1
(const uint instr) {
	return instr_32(rm:     cast(reg)slice(instr,  0, 4),
					m_swap: cast(bool)slice(instr, 5, 1),
					rd:     cast(reg)slice(instr,  8, 4),
					rn:     cast(reg)slice(instr, 16, 4));
}

void 
execute_smusd_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint op_2 = (instr.m_swap) ? rotr(vm.get_reg(instr.rm), 16) : vm.get_reg(instr.rm);
	int product_1 = cast(int)cast(short)slice(vm.get_reg(instr.rn),  0, 16) * 
				 	cast(int)cast(short)slice(vm.get_reg(instr.rm),  0, 16);
	int product_2 = cast(int)cast(short)slice(vm.get_reg(instr.rn), 16, 16) * 
				 	cast(int)cast(short)slice(vm.get_reg(instr.rm), 16, 16);	
	int res = product_1 - product_2;
	vm.set_reg(instr.rd, cast(uint)res);
}

void execute_smlaw_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_smulw_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_smlad_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

instr_32 parse_smuad_t1(const uint instr) {
	return instr_32(rm:     cast(reg)slice(instr,  0, 4),
					m_swap: cast(bool)slice(instr, 5, 1),
					rd:     cast(reg)slice(instr,  8, 4),
					rn:     cast(reg)slice(instr, 16, 4));
}

void 
execute_smuad_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint op_2 = (instr.m_swap) ? rotr(vm.get_reg(instr.rm), 16) : vm.get_reg(instr.rm);
	int product_1 = cast(int)cast(short)slice(vm.get_reg(instr.rn),  0, 16) * 
				 	cast(int)cast(short)slice(vm.get_reg(instr.rm),  0, 16);
	int product_2 = cast(int)cast(short)slice(vm.get_reg(instr.rn), 16, 16) * 
				 	cast(int)cast(short)slice(vm.get_reg(instr.rm), 16, 16);	
	const long wide = cast(long)product_1 * cast(long)product_2;
	const int  res  = cast(int )wide;
	vm.set_reg(instr.rd, cast(uint)res);
	if (wide != cast(long)res) 
		vm.set_q(true); // APSR.Q
}

instr_32 parse_smlsd_t1(const uint instr) {
	return instr_32(rm:     cast(reg)slice(instr,  0, 4),
					m_swap: cast(bool)slice(instr, 5, 1),
					ra:     cast(reg)slice(instr, 12, 1),
					rd:     cast(reg)slice(instr,  8, 4),
					rn:     cast(reg)slice(instr, 16, 4));
}

void 
execute_smlsd_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint op_2 = (instr.m_swap) ? rotr(vm.get_reg(instr.rm), 16) : vm.get_reg(instr.rm);
	int product_1 = cast(int)cast(short)slice(vm.get_reg(instr.rn),  0, 16) * 
				 	cast(int)cast(short)slice(vm.get_reg(instr.rm),  0, 16);
	int product_2 = cast(int)cast(short)slice(vm.get_reg(instr.rn), 16, 16) * 
				 	cast(int)cast(short)slice(vm.get_reg(instr.rm), 16, 16);	
	const long wide = cast(long)product_1 - cast(long)product_2 + cast(long)vm.get_reg(instr.ra);
	const int  res  = cast(int )wide;
	vm.set_reg(instr.rd, cast(uint)res);
	if (wide != cast(long)res) 
		vm.set_q(true); // APSR.Q
}

// SMMUL{R}<c> <Rd>,<Rn>,<Rm>
instr_32 parse_smmul_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_smmul_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {

}

string convert_smmul_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("smmul%s %s, %s, %s", get_condition_string(cond),
										get_reg_name(instr.rd),
										get_reg_name(instr.rn),
										get_reg_name(instr.rm));
}

void execute_smmla_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_smmls_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_usada8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_usad8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sadd16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sasx_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ssax_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ssub16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sadd8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ssub8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

// QADD16{<c>}{<q>} {<Rd>,} <Rn>, <Rm>
instr_32 parse_qadd16_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void execute_qadd16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {
	int sum_1 = cast(int)cast(short)slice(vm.get_reg(instr.rn),  0, 16) + 
				cast(int)cast(short)slice(vm.get_reg(instr.rm),  0, 16);
	int sum_2 = cast(int)cast(short)slice(vm.get_reg(instr.rn), 16, 16) + 
				cast(int)cast(short)slice(vm.get_reg(instr.rm), 16, 16);			
	ushort sat_1 = cast(ushort)(sum_1 > 32767 ? 32767 : (sum_1 < -32768 ? -32768 : sum_1));
    ushort sat_2 = cast(ushort)(sum_2 > 32767 ? 32767 : (sum_2 < -32768 ? -32768 : sum_2));
	uint res = (cast(uint)sat_2 << 16) | cast(uint)sat_1;
	vm.set_reg(instr.rd, res);
}

instr_32 parse_qasx_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_qasx_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint sum  = cast(uint)cast(short)slice(vm.get_reg(instr.rn),  0, 16) 
			  + cast(uint)cast(short)slice(vm.get_reg(instr.rm), 16, 16);
	uint diff = cast(uint)cast(short)slice(vm.get_reg(instr.rn), 16, 16) 
			  - cast(uint)cast(short)slice(vm.get_reg(instr.rm), 0, 16);
	ushort sum_sat  = cast(ushort)(sum  > 32767 ? 32767 : (sum  < -32768 ? -32768 : sum));
    ushort diff_sat = cast(ushort)(diff > 32767 ? 32767 : (diff < -32768 ? -32768 : diff));
	uint res = (cast(uint)sum_sat << 16) | cast(uint)diff_sat;
	vm.set_reg(instr.rd, res);
}

instr_32 parse_qsax_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_qsax_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint sum  = cast(uint)cast(short)slice(vm.get_reg(instr.rn),  0, 16) 
			  + cast(uint)cast(short)slice(vm.get_reg(instr.rm), 16, 16);
	uint diff = cast(uint)cast(short)slice(vm.get_reg(instr.rn), 16, 16) 
			  - cast(uint)cast(short)slice(vm.get_reg(instr.rm), 0, 16);
	ushort sum_sat  = cast(ushort)(sum  > 32767 ? 32767 : (sum  < -32768 ? -32768 : sum));
    ushort diff_sat = cast(ushort)(diff > 32767 ? 32767 : (diff < -32768 ? -32768 : diff));
	uint res = (cast(uint)diff_sat << 16) | cast(uint)sum_sat;
	vm.set_reg(instr.rd, res);
}

instr_32 parse_shasx_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_shasx_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint sum  = cast(uint)cast(short)slice(vm.get_reg(instr.rn),  0, 16) 
			  + cast(uint)cast(short)slice(vm.get_reg(instr.rm), 16, 16);
	uint diff = cast(uint)cast(short)slice(vm.get_reg(instr.rn), 16, 16) 
			  - cast(uint)cast(short)slice(vm.get_reg(instr.rm), 0, 16);
	uint res = (cast(uint)diff << 16) | cast(uint)sum;
	vm.set_reg(instr.rd, res);
}

instr_32 parse_shsax_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_shsax_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint sum  = cast(uint)cast(short)slice(vm.get_reg(instr.rn),  0, 16) 
			  + cast(uint)cast(short)slice(vm.get_reg(instr.rm), 16, 16);
	uint diff = cast(uint)cast(short)slice(vm.get_reg(instr.rn), 16, 16) 
			  - cast(uint)cast(short)slice(vm.get_reg(instr.rm), 0, 16);
	uint res = (cast(uint)sum << 16) | cast(uint)diff;
	vm.set_reg(instr.rd, res);
}

instr_32 parse_qsub16_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void execute_qsub16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {
	int diff_1 = cast(int)cast(short)slice(vm.get_reg(instr.rn),  0, 16) - 
				 cast(int)cast(short)slice(vm.get_reg(instr.rm),  0, 16);
	int diff_2 = cast(int)cast(short)slice(vm.get_reg(instr.rn), 16, 16) - 
				 cast(int)cast(short)slice(vm.get_reg(instr.rm), 16, 16);	
	ushort sat_1 = cast(ushort)(diff_1 > 32767 ? 32767 : (diff_1 < -32768 ? -32768 : diff_1));
    ushort sat_2 = cast(ushort)(diff_2 > 32767 ? 32767 : (diff_2 < -32768 ? -32768 : diff_2));
	uint res = (cast(uint)sat_2 << 16) | cast(uint)sat_1;
	vm.set_reg(instr.rd, res);
}

void execute_qadd8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qsub8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

instr_32 parse_shadd16_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_shadd16_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint sum_1 = cast(uint)cast(short)vm.get_reg(instr.rn) + cast(uint)cast(short)vm.get_reg(instr.rm);
	uint sum_2 = cast(uint)cast(short)slice(vm.get_reg(instr.rn), 16, 16) 
			   + cast(uint)cast(short)slice(vm.get_reg(instr.rm), 16, 16);
	uint res = (slice(sum_2, 1, 16) << 16) | slice(sum_1, 1, 16);
	vm.set_reg(instr.rd, res);  
}

instr_32 parse_shsub16_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

void 
execute_shsub16_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint diff_1 = cast(uint)cast(short)vm.get_reg(instr.rn) 
	            - cast(uint)cast(short)vm.get_reg(instr.rm);
	uint diff_2 = cast(uint)cast(short)slice(vm.get_reg(instr.rn), 16, 16) 
			    - cast(uint)cast(short)slice(vm.get_reg(instr.rm), 16, 16);
	uint res = (slice(diff_2, 1, 16) << 16) | slice(diff_1, 1, 16);
	vm.set_reg(instr.rd, res);  
}

void execute_shadd8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_shsub8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uadd16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uasx_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_usax_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_usub16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_usub8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uqadd16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uqasx_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uqsax_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uqsub16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uqadd8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uqsub8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uhadd16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uhasx_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uhsax_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uhsub16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uhadd8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uhsub8_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_qadd16_t(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

struct sat_result(T)
{
    T value;
    bool saturated;
}

sat_result!T 
signed_sat_q
(T)
(long i) if (isIntegral!T && isSigned!T) {
    long clamped = clamp(i, cast(long)T.min, cast(long)T.max);
    return sat_result!T(cast(T) clamped, clamped != i);
}