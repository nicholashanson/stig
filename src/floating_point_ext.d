import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

enum field_tuples_vmsr = [Tuple!(opcode, string[])(opcode.vmsr, ["rt"])];
// move to floating-point special register
instr_32
parse_vmsr(const uint instr) {
	instr_32 res;
	res.op = opcode.vmsr;
	const ubyte rt = cast(ubyte)((instr >> 12) & 0xf);
	res.rt = cast(reg)(rt);
	return res;
}

void execute_vmsr(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rt = cpu.get(instr.rt);
	cpu.set_fpscr(rt);
	cpu.increment_pc(4);
}