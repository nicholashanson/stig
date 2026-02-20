// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                 Store Single Data Item	    					         *    
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
// *					                   STR  										 *
// ***************************************************************************************

// ======================
//  Parse STR(Immediate)
// ======================

enum field_tuples_str_imm_t3 = [Tuple!(opcode, string[])(opcode.str_imm_t3, ["rt","rn","imm"])];
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_str_imm_t3(const uint instr) {
	return instr_32(rt:  cast(reg)slice(instr, 12,  4), 
					rn:  cast(reg)slice(instr, 16,  4),
					imm: cast(reg)slice(instr,  0, 12),
					index: true, add: true);
}

// ======================
//  Parse STR(Immediate)
// ======================

enum field_tuples_str_imm_t4 = [Tuple!(opcode, string[])(opcode.str_imm_t4, ["rt","rn","imm"])];
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11] 1, [10] P, [9] U, [8] W, [7:0] imm8
instr_32 parse_str_imm_t4(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// ========================
//  Execute STR(Immediate)
// ========================

void 
execute_str_imm_t3
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_str_imm(instr, vm);
}

void 
execute_str_imm_t4
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_str_imm(instr, vm);
}

void 
execute_str_imm
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t offset_addr; 
	immutable rn = vm.get_reg(instr.rn);
	offset_addr  = instr.add   ? rn + instr.imm : rn - instr.imm;
	size_t addr  = instr.index ? offset_addr : rn;
	const uint data = vm.get_reg(instr.rt);
	mem.write_word(addr, data);
	if (instr.wback) 
		vm.set_reg(instr.rn, cast(uint)offset_addr);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRB 										 *
// ***************************************************************************************

// =======================
//  Parse STRB(Immediate)
// =======================

enum field_tuples_strb_imm_t2 = [Tuple!(opcode, string[])(opcode.strb_imm_t2, ["rt","rn","imm"])];
// STRB<c>.W <Rt>,[<Rn>,#<imm12>]
// First Half-Word: [15:4] 111110001000, [3:0] Rn 
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_strb_imm_t2(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 12),
					add:   true,
					index: true,
					rt:    cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4));
}

// =======================
//  Parse STRB(Immediate)
// =======================

enum field_tuples_strb_imm_t3 = [Tuple!(opcode, string[])(opcode.strb_imm_t3, ["rt","rn","imm"])];
// STRB<c>.W <Rt>,[<Rn>,#<imm12>]
// First Half-Word:[15:4] 111110001000, [3:0] Rn 
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_strb_imm_t3(uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// =========================
//  Execute STRB(Immediate)
// =========================

void 
execute_strb_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	return execute_strb_imm(instr, vm);
}

void 
execute_strb_imm_t3
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	return execute_strb_imm(instr, vm);
}

void 
execute_strb_imm
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	const uint   rn   = vm.get_reg(instr.rn);
	size_t       offset_addr;
	offset_addr       = instr.add   ? rn + instr.imm : rn - instr.imm;
	const size_t addr = instr.index ? offset_addr    : rn;
	uint         data = cpu.get_reg(instr.rt);
	data              = (data & 0xff);
	vm.write_byte(addr, data);
	if (instr.wback) 
		vm.set_reg(instr.rn, cast(uint)offset_addr);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRH 										 *
// ***************************************************************************************

// ======================
//  Parse STRH(Register)
// ======================

enum field_tuples_strh_reg_t2 = [Tuple!(opcode, string[])(opcode.strh_reg_t2, ["rt","rn","rm"])];
// STRH<c> <Rt>,[<Rn>,<Rm>]
// First Half-Word: [15:4] 111110000010, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_strh_reg_t2(const uint instr) {
	return instr_32(shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					add:     true,
					index:   true,
					rm:      cast(reg)slice(instr, 0,  4),
					rt:      cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4));
}

// ========================
//  Execute STRH(Register)
// ========================

void 
execute_strh_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm        = vm.get_reg(instr.rm); 
	immutable rn        = vm.get_reg(instr.rn);
	immutable rt        = vm.get_reg(instr.rt);
	const size_t offset = shift(instr.shift_t, instr.shift_n, rm);	
	const size_t addr   = rn + offset;
	const uint   target = (rt & 0xffff);
	vm.write_half_word(addr, cast(ushort)target);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRH 										 *
// ***************************************************************************************

enum field_tuples_strh_imm_t2 = [Tuple!(opcode, string[])(opcode.strh_imm_t2, ["rt","rn","imm"])];
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_strh_imm_t2(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 12),
					rt:    cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4),
					index: true, 
					add:   true);
}


void 
execute_strh_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t offset_addr; 
	immutable rn = vm.get_reg(instr.rn);
	immutable rt = vm.get_reg(instr.rt);
	offset_addr  = instr.add   ? rn + instr.imm : rn - instr.imm;
	const size_t addr = instr.index ? offset_addr : rn;
	const ushort data = cast(ushort)(rt & 0xffff);
	vm.write_half_word(addr, data);
	if (instr.wback) 
		vm.set_reg(instr.rn, cast(uint)offset_addr);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *								       STR 											 *
// ***************************************************************************************

// =====================
//  Parse STR(Register)
// =====================

enum field_tuples_str_reg_t2 = [Tuple!(opcode, string[])(opcode.str_reg_t2, ["rt","rn","rm","imm"])];
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_str_reg_t2(const uint instr) {
	return instr_32(rm:      cast(reg)slice(instr,  0, 4),
					shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					rt:      cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4));
}

// =======================
//  Execute STR(Register)
// =======================

void 
execute_str_reg_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	const int offset  = shift(instr.shift_t, instr.shift_n, vm/get_reg(instr.rm));
	const size_t addr = vm.get_reg(instr.rn) + offset;
	immutable data    = vm.get_reg(instr.rt);
	vm.write_word(addr, data);
}
// ---------------------------------------------------------------------------------------
