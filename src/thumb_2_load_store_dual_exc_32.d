import std.typecons : Tuple;
import std.format : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// --------------------------------------- TBB/TBH ---------------------------------------

// ===============
//  Parse TBB/TBH
// ===============

enum field_tuples_tbb_tbh_32 = [Tuple!(opcode, string[])(opcode.tbb_tbh_32, ["rn","rm"])];

/*
	Load/Store Dual or Exclusive, Table Branch
	TBB [<Rn>,<Rm>]
	TBH [<Rn>,<Rm>,LSL #1]
	[15:5] 11101010100, [4] S, [3:0] Rn
	[15] 0, [14:12] imm3, [11:8] Rd. [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_tbb_tbh_32(uint instr) {
	instr_32 res;
	res.op = opcode.tbb_tbh_32;
	ubyte rm = cast(ubyte)( instr        & 0xf);
	ubyte H  = cast(ubyte)((instr >>  4) & 0x1);
	ubyte rn = cast(ubyte)((instr >> 16) & 0xf);
	res.is_tbh = H == 1 ? true : false;
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// ===============
//  Parse TBB/TBH
// ===============

void execute_tbb_tbh_32(const ref instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = load_store_log();
	uint half_words;
	uint rn = cpu.get(instr.rn);
	uint rm = cpu.get(instr.rm);
	uint shifted = shift(shift_type.lsl, 1, rm);
	size_t addr = instr.is_tbh ? rn + shifted : rn + rm;
	f.writeln(format("Attempting to access [%08X]", addr));
	if (instr.is_tbh) {
		half_words = mem.read_half_word(addr);
	} else {
		half_words = mem.read_byte(addr);
	}
	f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, half_words, addr));
	f.flush();
	cpu.increment_pc(2 * half_words);
}
// ---------------------------------------------------------------------------------------