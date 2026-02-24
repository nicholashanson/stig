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

// LDR<c><q> <Rt>, [PC, #+/-<imm>]
// [15:11] 01001,[10:8] Rm, [7:0] imm8
instr_16 parse_ldr_lit_t1(const ushort instr) {
	return instr_16(rt:  cast(reg)slice(instr, 8, 3), 
		            imm: slice(instr, 0, 8) << 2);
}

// ======================
//  Execute LDR(Literal)
// ======================

void 
execute_ldr_lit_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	uint base 		= vm.get_reg(reg.pc) + 4;
	base     	   &= ~0x3;   
	const uint addr = base + instr.imm;
	const uint data = vm.read_word(addr);
	vm.set_reg(instr.rt, data);
}

// LDR<c><q> <Rt>, [PC, #+/-<imm>]
string convert_ldr_lit_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldr%s %s, [pc, #%d]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 instr.imm);
}

