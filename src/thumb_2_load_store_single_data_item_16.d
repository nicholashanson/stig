import std.typecons : Tuple;
import std.format : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ---------------------------------------- STRH -----------------------------------------

// ======================
//  Parse STRH(Register)
// ======================

enum field_tuples_strh_reg = [Tuple!(opcode, string[])(opcode.strh_reg, ["rt","rn","rm"])];
/*
	Load/Store Single Data Item
	STRH <Rt>,[<Rn>,<Rm>]
	[15:9] 0101001, [8:6] Rm, [5:3] Rn, [2:0] Rt
*/
instr_16 parse_strh_reg(ushort instr) {
	instr_16 res;
	const ubyte rt = cast(ubyte)( instr       & 0x7);
	const ubyte rn = cast(ubyte)((instr >> 3) & 0x7);
	const ubyte rm = cast(ubyte)((instr >> 6) & 0x7);
	res.rn   = cast(reg)(rn);
	res.rt   = cast(reg)(rt);
	res.rm   = cast(reg)(rm);
	return res;
}

// ========================
//  Execute STRH(Register)
// ========================

void execute_strh_reg(const ref instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	const uint   rm     = cpu.get(instr.rm); 
	const uint   rn     = cpu.get(instr.rn);
	const uint   rt     = cpu.get(instr.rt);
	const size_t addr   = rn + rm;	
	const uint   target = (rt & 0xffff);
	mem.write_half_word(addr, cast(ushort)target, cpu.pc);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------






































































