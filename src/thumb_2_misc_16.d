import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ---------------------------------------- SXTB -----------------------------------------

enum field_tuples_sxtb = [Tuple!(opcode, string[])(opcode.sxtb, ["rd","rm"])];
/*
	Miscellaneous 16-bit Instructions
	SXTB <Rd>,<Rm>
	[15:6] 1011001001, [5:3] Rm, [2:0] Rd  
*/
instr_16 parse_sxtb(ushort instr) {
	instr_16 res;
	res.op   = opcode.sxtb;
	ubyte rd = cast(ubyte)( instr       & 0x7);
	ubyte rm = cast(ubyte)((instr >> 3) & 0x7);
	res.rd   = cast(reg)(rd);
	res.rm   = cast(reg)(rm);
	return res;
}

void execute_sxtb(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint res = (rm & 0xff);
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------