// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Generate SP-Relative Address	    					 *    
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
// *								       ADD 											 *
// ***************************************************************************************
// ADD (SP plus immediate) adds an immediate value to the SP value, and writes the result 
// to the destination register.

// ==============================
//  Parse ADD(SP Plus Immediate)
// ==============================

enum field_tuples_add_sp_t1 = [Tuple!(opcode, string[])(opcode.add_sp_t1, ["rd","sp","imm"])];
// ADD <Rd>,SP,#<imm8>
// [15:11] 10101, [10:8] Rd, [7:0] imm8
instr_16 parse_add_sp_t1(const ushort instr) {
	return instr_16(imm: slice(instr, 0, 8) << 2, 
					rd:  cast(reg)slice(instr, 8, 3));
}

// ==============================
//  Parse ADD(SP Plus Immediate)
// ==============================

enum field_tuples_add_sp_t2 = [Tuple!(opcode, string[])(opcode.add_sp_t2, ["sp","imm"])];
// ADD<c> SP,SP,#<imm7>
instr_16 parse_add_sp_t2(const ushort instr) {
	return instr_16(imm: slice(instr, 0, 7) << 2);
}

// ================
//  Execute ADD SP
// ================

void 
execute_add_sp
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable  sp  = vm.get_sp();
	const uint res = sp + instr.imm;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------