import std.typecons : Tuple;
import std.format : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// --------------------------------------- SMULL -----------------------------------------

// =============
//  Parse SMULL
// =============

enum field_tuples_smull_32 = [Tuple!(opcode, string[])(opcode.smull_32, ["rd_lo","rd_hi","rn","rm"])];
/*
	Long Multiply, Long Multiply Accumulate and Divide
	SMULL <RdLo>,<RdHi>,<Rn>,<Rm>
	First Half-Word: [15:4] 111110111000, [3:0] Rn
	Second Half-Word: [15:12] RdLo, [11:8] RdHi, [7:4] 0000, [3:1] Rm 
*/
instr_32 parse_smull_32(uint instr) {
	instr_32 res;
	res.op = opcode.smull_32;
	ubyte rm    = cast(ubyte)( instr        & 0xf);
	ubyte rd_hi = cast(ubyte)((instr >>  8) & 0xf);
	ubyte rd_lo = cast(ubyte)((instr >> 12) & 0xf);
	ubyte rn 	= cast(ubyte)((instr >> 16) & 0xf);
	res.rd_hi = cast(reg)(rd_hi);
	res.rd_lo = cast(reg)(rd_lo);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// ===============
//  Execute SMULL
// ===============

void execute_smull_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const int rm = cpu.get(instr.rm); 
	const int rn = cpu.get(instr.rn);
	const long res = cast(long)rm * cast(long)rn;
	const uint res_hi = cast(uint)((res >> 32) & 0xffff_ffff);
	const uint res_lo = cast(uint)( res        & 0xffff_ffff);
	cpu.set(instr.rd_lo, res_lo);
	cpu.set(instr.rd_hi, res_hi);  
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

