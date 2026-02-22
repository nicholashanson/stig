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

enum field_tuples_ldrb_imm_t2 = [Tuple!(opcode, string[])(opcode.ldrb_imm_t2, ["rt","rn","imm"])];
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

enum field_tuples_ldrb_imm_t3 = [Tuple!(opcode, string[])(opcode.ldrb_imm_t3, ["rt","rn","imm"])];
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

enum field_tuples_ldrsb_imm_t1 = [Tuple!(opcode, string[])(opcode.ldrsb_imm_t1, ["rt","rn", "imm"])];
// LDRSB <Rt>,[<Rn>,#<imm12>]
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

enum field_tuples_ldrsb_imm_t2 = [Tuple!(opcode, string[])(opcode.ldrsb_imm_t2, ["rt","rn","imm"])];
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
(const ref instr_32 instr, ref vm) {
	execute_ldrsb_imm(instr, vm);
}

void 
execute_ldrsb_imm_t2
(vm_t)
(const ref instr_32 instr, ref vm) {
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
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LDRSB 										 *
// ***************************************************************************************
// LDRSB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]









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

void execute_teq_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_cmn_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_cmp_reg_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_mvn_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_orn_reg_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_rsb_reg_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_adr_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_adr_imm_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_movt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_sbfx_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_mov_reg_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ror_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_rrx_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_uxtb_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sxth_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sxtb_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_sxtab_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sxtah_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_uxtah_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_sxtab16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_sxtb16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_uxtab16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_uxtb16_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_uxtab_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ror_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_qadd_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qdadd_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qsub_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_qdsub_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_rev_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_rev16_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_sdiv_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrh_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrh_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrh_imm_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrh_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrht_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrsh_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsh_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsh_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsh_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsht_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsh_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsh_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrb_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrbt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrb_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_ldrsb_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsbt_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_ldrsb_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_pld_lit_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_imm_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_imm_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_pld_reg_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}

void execute_strb_reg_t2(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_strh_imm_t3(vm_t)(const ref instr_32 instr, ref vm_t vm) {}


void execute_invalid(vm_t)(const ref instr_32 instr, ref vm_t vm) {}
void execute_vmsr_t1(vm_t)(const ref instr_32 instr, ref vm_t vm) {}