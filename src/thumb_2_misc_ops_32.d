import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ---------------------------------------- RBIT -----------------------------------------

enum field_tuples_rbit_32 = [Tuple!(opcode, string[])(opcode.rbit_32, ["rd","rm"])];
/*
	Miscellaneous Operations
	First Half-Word: [15:4] 111110101001, [3:0] Rm
	Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 1010, [3:0] Rm
*/
instr_32 parse_rbit_32(uint instr) {
	instr_32 res;
	res.op = opcode.rbit_32;
	ubyte rm = cast(ubyte)( instr       & 0x0f);
	ubyte rd = cast(ubyte)((instr >> 8) & 0x0f);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	return res;
}

void execute_rbit_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	uint v = cpu.get(instr.rm);
	uint res;
	foreach (i; 0 .. 32) {
        res = (res << 1) | (v & 1);
        v >>= 1;
    }
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------
