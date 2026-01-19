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

enum field_tuples_strh_reg_32 = [Tuple!(opcode, string[])(opcode.strh_reg_32, ["rt","rn","rm"])];
/*
	Store Single Data Item
	First Half-Word: [15:4] 111110000010, [3:0] Rn
	Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
*/
instr_32 parse_strh_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.strh_reg_32;
	ubyte rm    = cast(ubyte)( instr        & 0x0f);
	ubyte imm_2 = cast(ubyte)((instr >>  4) & 0x03);
	ubyte rt    = cast(ubyte)((instr >> 12) & 0x0f);
	ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	res.rn = cast(reg)(rn);
	res.rt = cast(reg)(rt);
	res.rm = cast(reg)(rm);
	res.index = true; 
	res.add = true; 
	res.shift_t = shift_type.lsl;
	res.shift_n = imm_2;
	return res;
}

// ========================
//  Execute STRH(Register)
// ========================

void execute_strh_reg_32(const ref instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	const uint rm = cpu.get(instr.rm); 
	const uint rn = cpu.get(instr.rn);
	const uint rt = cpu.get(instr.rt);
	const size_t offset = shift(instr.shift_t, instr.shift_n, rm);	
	const size_t addr = rn + offset;
	auto f = load_store_log();
	f.writeln(format("Attempting to access [%08X]", addr));
	uint target = (rt & 0xffff);
	mem.write_half_word(addr, cast(ushort)target);
	f.writeln(format("%08X: %08X stored to [%08X]", cpu.pc, target, addr));
	f.flush();
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------
