// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *	                 Load/Store Dual of Exclusive, Table Branch	    				 *    
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
// *                                       TBB/TBH                                       *
// ***************************************************************************************
// Table Branch Byte causes a PC-relative forward branch using a table of single byte 
// offsets. A base register provides a pointer to the table, and a second register 
// supplies an index into the table. The branch length is twice the value of the byte 
// returned from the table.

// Table Branch Halfword causes a PC-relative forward branch using a table of single 
// halfword offsets. A base register provides a pointer to the table, and a second 
// register supplies an index into the table. The branch length is twice the value of the 
// halfword returned from the table.

// ===============
//  Parse TBB/TBH
// ===============

enum field_tuples_tbb_tbh_t1 = [Tuple!(opcode, string[])(opcode.tbb_tbh_t1, ["rn","rm"])];
// TBB [<Rn>,<Rm>]
// TBH [<Rn>,<Rm>,LSL #1]
// First Half-Word: [15:5] 11101010100, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd. [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_tbb_tbh_t1(const uint instr) {
	return instr_32(is_tbh: cast(bool)slice(instr,  4, 1),
					rm:     cast(reg )slice(instr,  0, 4),
					rn:     cast(reg )slice(instr, 16, 4));
}

// =================
//  Execute TBB/TBH
// =================

void 
execute_tbb_tbh_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint half_words;
	//const uint rn = cpu.get(instr.rn);
	immutable  rm   = vm.get_reg(instr.rm);
	const uint base = (vm.get_pc() + 4) & ~3;
	const uint addr = base + (instr.is_tbh ? (rm << 1) : rm);
	half_words = instr.is_tbh ? vm.read_half_word(addr) : vm.read_byte(addr);
	vm.increment_pc(2 * half_words);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 LDREX 											 *
// ***************************************************************************************

// =============
//  Parse LDREX
// =============

enum field_tuples_ldrex_t1 = [Tuple!(opcode, string[])(opcode.ldrex_t1, ["rt","rn","imm"])];
// LDREX <Rt>,[<Rn>{,#<imm8>}]
// First Half-Word: [15:4] 111010000101, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:8] 1111, [7:0] imm8
instr_32 parse_ldrex_t1(const uint instr) {
	return instr_32(rt:  cast(reg )slice(instr, 12, 4),
				    rn:  cast(reg )slice(instr, 16, 4),
				    imm: slice(instr, 0, 8) << 2); 
}

// ===============
//  Execute LDREX
// ===============

void 
execute_ldrex_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	uint addr = vm.get_reg(instr.rn);
	addr += instr.imm;
	immutable val = vm.read_word(addr);
	vm.set_reg(instr.rt, val);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRD 										 *
// ***************************************************************************************
// Store Register Dual (immediate) calculates an address from a base register value and an 
// immediate offset, and stores two words from two registers to memory. It can use offset, 
// post-indexed, or pre-indexed addressing. 

// ============
//  Parse STRD
// ============

enum field_tuples_strd_imm_t1 = [Tuple!(opcode, string[])(opcode.strd_imm_t1, ["rt","rt2","rn","imm"])];
// STRD<c> <Rt>,<Rt2>,[<Rn>{,#+/-<imm8>}]
// STRD<c> <Rt>,<Rt2>,[<Rn>],#+/-<imm8>
// STRD<c> <Rt>,<Rt2>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:9] 1110100, [8] P, [7] U, [6] 1, [5] W, [4] 0, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:8] Rt2, [7:0] imm8
instr_32 parse_strd_imm_t1(const uint instr) {
	return instr_32(rt:    cast(reg )slice(instr, 12, 4),
				    rt_2:  cast(reg )slice(instr,  8, 4),
				    rn:    cast(reg )slice(instr, 16, 4),
				    imm:   slice(instr, 0, 8) << 2,
				    add:   cast(bool)slice(instr, 23, 1),
				    index: cast(bool)slice(instr, 24, 1),
				    wback: cast(bool)slice(instr, 21, 1)); 
}

// =========================
//  Execute STRD(Immediate)
// =========================

void 
execute_strd_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t offset;
	immutable index = vm.get_reg(instr.rn);
	offset = instr.add ? index + instr.imm : index - instr.imm;
	immutable data1 = vm.get_reg(instr.rt);
	immutable data2 = vm.get_reg(instr.rt_2);
	vm.write_word(offset, data1);
	vm.write_word(offset + 4, data2);
	if (instr.wback) 
		vm.set_reg(instr.rn, offset);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 STREX 											 *
// ***************************************************************************************
// Store Register Exclusive calculates an address from a base register value and an 
// immediate offset, and stores a word from a register to memory if the executing 
// processor has exclusive access to the memory addressed.

// =============
//  Parse STREX
// =============

// STREX<c> <Rd>,<Rt>,[<Rn>{,#<imm8>}]
// First Half-Word: [15:4] 111010000100, [3:0] Rd
// Second Half-Word: [15:12] Rt, [11:8] Rn, [7:0] imm8
instr_32 parse_strex_t1(const uint instr) {
	return instr_32(rd:  cast(reg )slice(instr,  8, 4),
				    rt:  cast(reg )slice(instr, 12, 4),
				    rn:  cast(reg )slice(instr, 16, 4),
				    imm: slice(instr, 0, 8) << 2); 
}

// ===============
//  Execute STREX
// ===============

void 
execute_strex_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable target = vm.get_reg(instr.rt);
	size_t addr 	 = vm.get_reg(instr.rn);
	addr += instr.imm;
	vm.write_word(addr, target);
	vm.set_reg(instr.rd, 0);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   LDRD 										 *
// ***************************************************************************************
// Load Register Dual (immediate) calculates an address from a base register value and an 
// immediate offset, loads two words from memory, and writes them to two registers. It can 
// use offset, post-indexed, or pre-indexed addressing.

// =======================
//  Parse LDRD(Immediate)
// =======================

enum field_tuples_ldrd_imm_t1 = [Tuple!(opcode, string[])(opcode.ldrd_imm_t1, ["rt","rt2","rn","imm"])];
// LDRD<c> <Rt>,<Rt2>,[<Rn>{,#+/-<imm8>}]
// LDRD<c> <Rt>,<Rt2>,[<Rn>],#+/-<imm8>
// LDRD<c> <Rt>,<Rt2>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:9] 1110100, [8] P, [7] U, [6] 1, [5] W, [4] 1, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:8] Rt2, [7:0] imm8
instr_32 parse_ldrd_imm_t1(const uint instr) {
	return instr_32(rd:    cast(reg )slice(instr, 12, 4),
				    rt:    cast(reg )slice(instr, 12, 4),
				    rt_2:  cast(reg )slice(instr,  8, 4),
				    rn:    cast(reg )slice(instr, 16, 4),
				    imm:   slice(instr, 0, 8) << 2,
				    add:   cast(bool)slice(instr, 23, 1),
				    index: cast(bool)slice(instr, 24, 1),
				    wback: cast(bool)slice(instr, 21, 1)); 
}

// =========================
//  Execute LDRD(Immediate)
// =========================

void 
execute_ldrd_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t       offset_addr;
	const uint   rn    = vm.get_reg(instr.rn);
	offset_addr        = instr.add   ? rn + instr.imm : rn - instr.imm;
	const size_t addr  = instr.index ? offset_addr    : rn;
	immutable    data1 = vm.read_word(addr);
	immutable    data2 = vm.read_word(addr + 4);
	vm.set_reg(instr.rt,   data1);
	vm.set_reg(instr.rt_2, data2);
	if (instr.wback) 
		vn.set_reg(instr.rn, cast(uint)offset_addr);
}
// ---------------------------------------------------------------------------------------