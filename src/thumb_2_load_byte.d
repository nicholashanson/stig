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
// First Half-Word: [15:4] 111110001001, [3:0] Rn
// Second Half-Word: [15:12] Rt, [10] P, [9] U, [8] W, [7:0] imm8
instr_32 parse_ldrb_imm_t2(const uint instr) {
	return instr_32(wback: cast(bool)slice(instr,  8, 1),
				    add:   true,
				    index: true,
				    rt:    cast(reg )slice(instr, 12, 4),
				    rn:    cast(reg )slice(instr, 16, 4),
				    imm:   slice(instr, 0, 12)); 
}

// =======================
//  Parse LDRB(Immediate)
// =======================

enum field_tuples_ldrb_imm_t3 = [Tuple!(opcode, string[])(opcode.ldrb_imm_t3, ["rt","rn","imm"])];
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
					imm:   slice(instr, 0, 8));
}

// ==========================
//  Execute LDRSB(Immediate)
// ==========================

void 
exectue_ldrsb_imm
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
