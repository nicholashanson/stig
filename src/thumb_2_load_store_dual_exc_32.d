import std.typecons : Tuple;
import std.format : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;
//import load_store_log_;

// --------------------------------------- TBB/TBH ---------------------------------------

// ===============
//  Parse TBB/TBH
// ===============

enum field_tuples_tbb_tbh_32 = [Tuple!(opcode, string[])(opcode.tbb_tbh_32, ["rn","rm"])];

/*
	Load/Store Dual or Exclusive, Table Branch
	TBB [<Rn>,<Rm>]
	TBH [<Rn>,<Rm>,LSL #1]
	First Half-Word: [15:5] 11101010100, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd. [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_tbb_tbh_32(const uint instr) {
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

// =================
//  Execute TBB/TBH
// =================

void execute_tbb_tbh_32(const ref instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	//auto f = load_store_log();
	uint half_words;
	//const uint rn    = cpu.get(instr.rn);
	const uint rm 	   = cpu.get(instr.rm);
	auto       base    = (cpu.pc + 4) & ~3;
	auto       addr    = base + (instr.is_tbh ? (rm << 1) : rm);
	//f.writeln(format("Attempting to access [%08X]", addr));
	if (instr.is_tbh) {
		half_words = mem.read_half_word(addr);
	} else {
		half_words = mem.read_byte(addr);
	}
	//f.writeln(format("%08X: %08X loaded from [%08X]", cpu.pc, half_words, addr));
	//f.flush();
	cpu.increment_pc(2 * half_words);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------- LDREX ----------------------------------------

// =============
//  Parse LDREX
// =============

enum field_tuples_ldrex_32 = [Tuple!(opcode, string[])(opcode.ldr_ex, ["rt","rn","imm"])];

/*
	Load/Store Dual or Exclusive, Table Branch
	LDREX <Rt>,[<Rn>{,#<imm8>}]
	First Half-Word: [15:4] 111010000101, [3:0] Rn
	Second Half-Word: [15:12] Rt, [11:8] 1111, [7:0] imm8
*/
instr_32 parse_ldrex_32(uint instr) {
	instr_32 res;
	res.op = opcode.ldr_ex;
	const ubyte imm_8 = cast(ubyte)( instr        & 0xff);
	const ubyte rt 	  = cast(ubyte)((instr >> 12) & 0x0f);
	const ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	res.imm = imm_8 << 2;
	res.rt = cast(reg)(rt);
	res.rn = cast(reg)(rn);
	return res;
}

// ===============
//  Execute LDREX
// ===============

void execute_ldrex(const ref instr_32 instr, ref cortex_m_cpu cpu, ref memory mem) {
	uint addr = cpu.get(instr.rn);
	addr += instr.imm;
	const uint val = mem.read_word(addr, cpu.pc);
	cpu.set(instr.rt, val);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------