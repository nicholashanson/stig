import std.typecons : Tuple;
import std.format : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ---------------------------------------- LSL ------------------------------------------

// ======================
//  Parse LSL(Immediate)
// ======================

enum field_tuples_lsl_imm = [Tuple!(opcode, string[])(opcode.lsl_imm, ["rd","rm","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	LSL <Rd>,<Rm>,#<imm5>
	[15:11] 00000, [10:6] imm5, [5:3] Rm, [2:0] Rd
*/
instr_16 parse_lsl_imm(short instr) {
	instr_16 res;
	res.op = opcode.lsl_imm;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	ubyte imm = cast(ubyte)((instr >> 6) & 0b11111);
	res.imm = imm;
	return res;
}

// =============
//  Execute LSL 
// =============

void execute_lsl_imm(instr_16 instr, ref cortex_m_cpu cpu) {
	int rm = cpu.get(instr.rm);
	int res = rm << (instr.imm - 1);
	bool carry = ((res & 0x80000000) != 0);
	res = res << 1;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res < 0);
		cpu.c = carry;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------
