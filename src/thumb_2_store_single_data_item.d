import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ======================
//  Parse STR(Immediate)
// ======================

enum field_tuples_str_imm_32_t4 = [Tuple!(opcode, string[])(opcode.str_imm_32_t4, ["rt","rn","imm"])];
/*
	Store Single Data Item
	First Half-Word: [15:4] 111110000100, [3:0] Rn
	Second Half-Word: [15:12] Rt, [11] 1, [10] P, [9] U, [8] W, [7:0] imm8
*/
instr_32 parse_str_imm_32_t4(const uint instr) {
	instr_32 res;
	const ushort imm_8 = cast(ushort)( instr        & 0xff);
	const ubyte  W     = cast(ubyte )((instr >>  8) & 0x01);
	const ubyte  U     = cast(ubyte )((instr >>  9) & 0x01);
	const ubyte  P     = cast(ubyte )((instr >> 10) & 0x01);
	const ubyte  rt    = cast(ubyte )((instr >> 12) & 0x0f);
	const ubyte  rn    = cast(ubyte )((instr >> 16) & 0x0f);
	const bool   wback = W == 1 ? true: false;
	const bool   add   = U == 1 ? true: false;
	const bool   index = P == 1 ? true: false;
	res.rn    = cast(reg)(rn);
	res.rt    = cast(reg)(rt);
	res.wback = wback;
	res.add   = add;
	res.index = index;
	res.imm   = imm_8;
	return res;
}

// =======================
//  Parse STRB(Immediate)
// =======================

enum field_tuples_strb_imm_32_t2 = [Tuple!(opcode, string[])(opcode.strb_imm_32_t2, ["rt","rn","imm"])];
/*
	Store Single Data Item
	STRB<c>.W <Rt>,[<Rn>,#<imm12>]
	First Half-Word: [15:4] 111110001000, [3:0] Rn 
	Second Half-Word: [15:12] Rt, [11:0] imm12
*/
instr_32 parse_strb_imm_32_t2(const uint instr) {
	instr_32 res;
	const ushort imm_12 = cast(ushort)( instr 		 & 0xfff);
	const ubyte rt 		= cast(ubyte )((instr >> 12) & 0x00f);
	const ubyte rn 		= cast(ubyte )((instr >> 16) & 0x00f);
	res.rt    = cast(reg)(rt);
	res.rn    = cast(reg)(rn);
	res.imm   = imm_12;
	res.index = true;
	res.add   = true;
	return res;
}

// =======================
//  Parse STRB(Immediate)
// =======================

enum field_tuples_strb_imm_32_t3 = [Tuple!(opcode, string[])(opcode.strb_imm_32_t3, ["rt","rn","imm"])];
/*
	Store Single Data Item
	STRB<c>.W <Rt>,[<Rn>,#<imm12>]
	First Half-Word:[15:4] 111110001000, [3:0] Rn 
	Second Half-Word: [15:12] Rt, [11:0] imm12
*/
instr_32 parse_strb_imm_32_t3(uint instr) {
	instr_32 res;
	const ubyte imm_8 = cast(ushort)( instr        & 0xff);
	const ubyte W  	  = cast(ubyte )((instr >>  8) & 0x01);
	const ubyte U  	  = cast(ubyte )((instr >>  9) & 0x01);
	const ubyte P     = cast(ubyte )((instr >> 10) & 0x01);
	const ubyte rt 	  = cast(ubyte )((instr >> 12) & 0x0f);
	const ubyte rn 	  = cast(ubyte )((instr >> 16) & 0x0f);
	const bool  wback = W == 0b1 ? true : false;
	const bool  add   = U == 0b1 ? true : false;
	const bool  index = P == 0b1 ? true : false;
	res.rt    = cast(reg)(rt);
	res.rn    = cast(reg)(rn);
	res.imm   = imm_8;
	res.wback = wback;
	res.add   = add;
	res.index = index;
	return res;
}

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
instr_32 parse_strh_reg_32(const uint instr) {
	instr_32 res;
	const ubyte rm    = cast(ubyte)( instr        & 0x0f);
	const ubyte imm_2 = cast(ubyte)((instr >>  4) & 0x03);
	const ubyte rt    = cast(ubyte)((instr >> 12) & 0x0f);
	const ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	res.rn      = cast(reg)(rn);
	res.rt      = cast(reg)(rt);
	res.rm      = cast(reg)(rm);
	res.index   = true; 
	res.add     = true; 
	res.shift_t = shift_type.lsl;
	res.shift_n = imm_2;
	return res;
}

// ========================
//  Execute STRH(Register)
// ========================

void execute_strh_reg_32
(mem_t)
(const ref instr_32 instr, ref cortex_m_cpu cpu, ref mem_t mem) {
	const uint   rm     = cpu.get(instr.rm); 
	const uint   rn     = cpu.get(instr.rn);
	const uint   rt     = cpu.get(instr.rt);
	const size_t offset = shift(instr.shift_t, instr.shift_n, rm);	
	const size_t addr   = rn + offset;
	const uint   target = (rt & 0xffff);
	mem.write_half_word(addr, cast(ushort)target, cpu.pc);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------
