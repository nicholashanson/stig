import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ----------------------------------------- AND -----------------------------------------

// =====================
//  Parse AND(Register)
// =====================

enum field_tuples_and_reg = [Tuple!(opcode, string[])(opcode.and_reg, ["rd","rm"])];
/*
	Data Processing
	AND <Rdn>,<Rm>
	[15:6] 0100000000, [5:3] Rm, [2:0] Rdn
*/
instr_16 parse_and_reg(short instr) {
	instr_16 res;
	res.op    = opcode.and_reg;
	ubyte rdn = cast(ubyte)( instr       & 0x7);
	ubyte rm  = cast(ubyte)((instr >> 3) & 0x7);
	res.rn    = cast(reg)(rdn);
	res.rd    = cast(reg)(rdn);
	res.rm    = cast(reg)(rm);
	return res;
}

// =============
//  Execute AND
// =============

void execute_and_reg(instr_16 instr, ref cortex_m_cpu cpu) {
	uint rn = cast(int)(cpu.get(instr.rn));
	uint rm = cast(int)(cpu.get(instr.rm));
	uint res = rn & rm;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- MUL -----------------------------------------

// ===========
//  Parse MUL
// ===========

enum field_tuples_mul = [Tuple!(opcode, string[])(opcode.mul, ["rd","rn"])];
/*
	Data Processing
	MUL <Rdm>,<Rn>,<Rdm>
	[15:6] 0100001101, [5:3] Rn, [2:0] Rdm
*/
instr_16 parse_mul(ushort instr) {
	instr_16 res;
	res.op    = opcode.mul;
	ubyte rdm = cast(ubyte)( instr       & 0x7);
	ubyte rn  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd    = cast(reg)(rdm);
	res.rm    = cast(reg)(rdm);
	res.rn    = cast(reg)(rn);
	return res;
}

// =============
//  Execute MUL
// =============

void execute_mul(instr_16 instr, ref cortex_m_cpu cpu) {
	uint rm  = cpu.get(instr.rm);
	uint rn  = cpu.get(instr.rn);
	uint res = rm * rn;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------


