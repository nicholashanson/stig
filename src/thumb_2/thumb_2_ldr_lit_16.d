// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Load from Literal Pool    					         *    
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

// ====================
//  Parse LDR(Literal)
// ====================

enum field_tuples_ldr_lit_t1 = [Tuple!(opcode, string[])(opcode.ldr_lit_t1, ["rt","pc","imm"])];
// LDR <Rt>,<label>
// [15:11] 01001,[10:8] Rm, [7:0] imm8
instr_16 parse_ldr_lit_t1(const ushort instr) {
	return instr_16(rt: cast(reg)slice(instr, 8, 3), 
		            imm: slice(instr, 0, 8) << 2);
}

// ======================
//  Execute LDR(Literal)
// ======================

void 
execute_ldr_lit_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	uint base 		= vm.get_reg(reg.pc) + 4;
	base     	   &= ~0x3;   
	const uint addr = base + instr.imm;
	const uint data = mem.read_word(addr);
	vm.set_reg(instr.rt, data);
}
