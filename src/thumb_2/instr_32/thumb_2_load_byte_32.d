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
	return format("ldrsb%s %s, %s", get_condition_string(cond), 
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
void execute_adr_imm_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_movt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_mov_reg_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ror_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}


void execute_sxtab_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_sxtab16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sxtb16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uxtab16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uxtb16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ror_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qadd_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
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
void execute_ldrsb_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_reg_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_invalid(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

