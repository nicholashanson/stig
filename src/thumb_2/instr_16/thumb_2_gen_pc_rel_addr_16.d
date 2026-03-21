// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Generate PC-Relative Address	    					 *    
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
// *								       ADR 											 *
// ***************************************************************************************
// Address to Register adds an immediate value to the PC value, and writes the result to 
// the destination register.

// ===========
//  Parse ADR
// ===========

// ADR<c> <Rd>,<label>
// [15:11] 10100, [10:8] Rd, [7:0] imm8  
instr_16 parse_adr_t1(const ushort instr) {
	return instr_16(imm: slice(instr, 0, 8) << 2,
					rd:  cast(reg)slice(instr, 8, 3));
	// imm32 = ZeroExtend(imm8:’00’, 32); add = TRUE;
}

// =============
//  Execute ADR
// =============

void 
execute_adr_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	uint res = word_align(vm.get_reg(reg.pc));
	res += instr.imm;
	vm.set_reg(instr.rd, res);
}

// =======================
//  Convert ADR to String
// =======================

string convert_adr_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("add%s %s, pc, #%d", get_condition_string(cond),
							  	       get_reg_name(instr.rd),
							  	       instr.imm);
}
// ---------------------------------------------------------------------------------------