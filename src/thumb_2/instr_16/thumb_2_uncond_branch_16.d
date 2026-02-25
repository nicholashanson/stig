// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Unconditional Branch	    					         *    
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

// =========
//  Parse B
// =========

// B <label>
// [15:11] 11100, [10:0] imm11
instr_16 parse_b_t2(const ushort instr) {
	auto imm_11 = cast(int)slice(instr, 0, 11); 
	imm_11 <<= 1;              
    if ((imm_11 & 0x800) != 0) 
        imm_11 |= ~0xfff; 
	return instr_16(offset: imm_11);
}

// ===========
//  Execute B
// ===========

void 
execute_b_t2
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	auto pc = vm.get_reg(reg.pc);
	pc += instr.offset + 4;
	vm.set_reg(reg.pc, pc);
}

string convert_b_t2_to_string(const ref instr_16 instr, const condition cond) {
	return "b <label>";
}
// ---------------------------------------------------------------------------------------