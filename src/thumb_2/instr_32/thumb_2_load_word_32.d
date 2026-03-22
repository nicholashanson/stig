// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                        Load Word	    					             *    
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

// ***************************************************************************************
// *									 LDR 											 *
// ***************************************************************************************

// ======================
//  Parse LDR(Immediate)
// ======================

// First Half-Word: [15:4] 111110001101, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_ldr_imm_t3(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 12),
					add:   true,
					index: true,
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// ======================
//  Parse LDR(Immediate)
// ======================

// LDR<c> <Rt>,[<Rn>,#-<imm8>]
// LDR<c> <Rt>,[<Rn>],#+/-<imm8>
// LDR<c> <Rt>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:4] 111110000101, [3:0] Rn
// Second Half-Word: [15:12] Rt, [10] P, [9] U, [8] W, [7:0] imm8
instr_32 parse_ldr_imm_t4(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// ========================
//  Execute LDR(Immediate)
// ========================

void 
execute_ldr_imm_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_ldr_imm(instr, vm);
}

void 
execute_ldr_imm_t4
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_ldr_imm(instr, vm);
}

void 
execute_ldr_imm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable    rn          = vm.get_reg(instr.rn);
	immutable    imm         = instr.imm;
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm;
	const size_t addr        = instr.index ? offset_addr : rn;
	uint         data        = vm.read_word(addr);
	if (instr.wback)
		vm.set_reg(instr.rn, cast(uint)offset_addr);
	vm.set_reg(instr.rt, data);
}

// LDR<c>.W <Rt>,[<Rn>{,#<imm12>}]
string convert_ldr_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldr%s.w %s, [%s%s]", get_condition_string(cond),
										get_reg_name(instr.rt),
										get_reg_name(instr.rn),
										get_imm_string(instr.imm));
}

// LDR<c> <Rt>,[<Rn>,#-<imm8>]
// LDR<c> <Rt>,[<Rn>],#+/-<imm8>
// LDR<c> <Rt>,[<Rn>,#+/-<imm8>]!
string convert_ldr_imm_t4_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldr%s.w %s, %s", get_condition_string(cond),
								    get_reg_name(instr.rt),
								    get_addr_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 LDR 											 *
// ***************************************************************************************

// =====================
//  Parse LDR(Register)
// =====================

// LDR<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
// First Half-Word:	[15:4] 111110000101, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:6] 000000, [5:4] imm2, [3:0] Rm 
instr_32 parse_ldr_reg_t2(const uint instr) {
	return instr_32(shift_t: shift_type.lsl,
					shift_n: slice(instr, 4, 2),
					rm:      cast(reg)slice(instr,  0, 4),
					rt:      cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4));
}

// =======================
//  Execute LDR(Register)
// =======================

void 
execute_ldr_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable    rn      = vm.get_reg(instr.rn);
	immutable    rm      = vm.get_reg(instr.rm);
	const int    shifted = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	const size_t addr    = rn + shifted;
	immutable    data    = vm.read_word(addr);
	vm.set_reg(instr.rt, data);
}

// LDR<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_ldr_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldr%s.w %s, [%s, %s%s]", get_condition_string(cond),
											get_reg_name(instr.rt),
											get_reg_name(instr.rn),
											get_reg_name(instr.rm),
											get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 LDR 											 *
// ***************************************************************************************

// ====================
//  Parse LDR(Literal)
// ====================

// LDR<c>.W <Rt>,[PC,#-0]
// First Half-Word: [15:8] 11111000, [7] U, [6:0] 1011111
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_ldr_lit_t2(const uint instr) {
	return instr_32(add: cast(bool)slice(instr, 23, 1),
		            rt:  cast(reg )slice(instr, 12, 4),
		            imm: slice(instr, 0, 12));
}

// ======================
//  Execute LDR(Literal)
// ======================

void 
execute_ldr_lit_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	size_t addr;
	uint   base = word_align(vm.get_reg(reg.pc));
	addr        = instr.add ? base + instr.imm : base - instr.imm;
	immutable data = vm.read_word(addr);
	vm.set_reg(instr.rt, data);
}

// LDR<c>.W <Rt>,[PC,#-0]
string convert_ldr_lit_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldr%s.w %s, [pc, #%s%d]", get_condition_string(cond), get_reg_name(instr.rt),
										     instr.add ? "" : "-", instr.imm);
}
// ---------------------------------------------------------------------------------------