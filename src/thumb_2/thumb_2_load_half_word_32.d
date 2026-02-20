import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ***************************************************************************************
// *									   LDRH 										 *
// ***************************************************************************************

// ========================
//  Parse LDRSH(Immediate)
// ========================

/*
	Branches and Miscellaneous Control
	First Half-Word: [15:4] 111110011011, [3:0] Rn
	Second Half-Word: [15:12] Rt, [11:0] imm12
*/
instr_32 parse_ldh_32(const uint instr) {
	instr_32 res;
	res.op = opcode.ldrh_imm_t1;
	const ubyte imm_12 = cast(ubyte)(instr         & 0xfff);
	const ubyte rt     = cast(ubyte)((instr >> 12) & 0x00f);
	const ubyte rn     = cast(ubyte)((instr >> 16) & 0x00f);
	res.rt  = cast(reg)(rt);
	res.rn  = cast(reg)(rn);
	res.imm = imm_12;
	return res;
}


// ==============
//  Execute LDRH
// ==============

// TODO: why is there only one ldrh instruction????
void 
execute_ldrh
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t addr = vm.get_reg(instr.rn);
	addr += instr.imm;
	ushort val = vm.read_half_word(addr);
	int target = vm.get_reg(instr.rt);
	int res = (target << 16) | val;
	vm.set_reg(instr.rt, res);
}
// ---------------------------------------------------------------------------------------
