import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

instr_16 parse_mul(ushort instr) {
	instr_16 res;
	res.op = opcode.mul;
	ubyte rdm = cast(ubyte)( instr       & 0x7);
	ubyte rn  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdm);
	res.rm = cast(reg)(rdm);
	res.rn = cast(reg)(rn);
	return res;
}

void execute_mul(instr_16 instr, ref cortex_m_cpu cpu) {
	uint rm = cpu.get(instr.rm);
	uint rn = cpu.get(instr.rn);
	uint res = rm * rn;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}


