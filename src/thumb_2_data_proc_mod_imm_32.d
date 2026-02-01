import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ----------------------------------------- ADC -----------------------------------------

// ======================
//  Parse ADC(Immediate)
// ======================

enum field_tuples_adc_imm_32 = [Tuple!(opcode, string[])(opcode.adc_imm_32, ["rd","rn","imm"])];

instr_32 parse_adc_imm_32(const uint instr) {
	instr_32 res;
	res.op      = opcode.adc_imm_32;
	ubyte imm_8 = cast(ubyte)( instr        & 0xff);
	ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	ubyte S     = cast(ubyte)((instr >> 20) & 0x01);
	ubyte i     = cast(ubyte)((instr >> 26) & 0x01);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.set_flags = S == 1 ? true : false;
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	res.imm = thumb_expand_imm(imm_12);
	return res;
}

// ========================
//  Execute ADC(Immediate)
// ========================

void execute_adc_imm_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	uint imm = instr.imm;
	uint rn  = cpu.get(instr.rn);
	uint c   = cast(uint)(cpu.c);
	ulong wide_res = cast(ulong)rn + cast(ulong)imm + cast(ulong)c;
    uint res = cast(uint)wide_res;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x8000_0000) != 0;
		cpu.c = cast(bool)((wide_res >> 32) & 1);
		bool signed_overflow = ((cast(int)rn > 0 && cast(int)imm > 0 && cast(int)res < 0) ||
                                (cast(int)rn < 0 && cast(int)imm < 0 && cast(int)res > 0));
        cpu.v = signed_overflow;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

// ==================
//  Parse AND IMM 32
// ==================

enum field_tuples_and_imm_32 = [Tuple!(opcode, string[])(opcode.and_imm_32, ["rd","rn","imm"])];
/*
	Data Processing (Modified Immediate)
	First Half-Word: [15:11] 11110, [10] i, [9:5] 00000, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
*/
instr_32 parse_and_imm_32(const uint instr) {
	instr_32 res;
	const ubyte  imm_8  = cast(ubyte)( instr        & 0xff);
	const ubyte  rd     = cast(ubyte)((instr >>  8) & 0x0f);
	const ubyte  rn     = cast(ubyte)((instr >> 16) & 0x0f);
	const ubyte  imm_3  = cast(ubyte)((instr >> 12) & 0x07);
	const ubyte  i      = cast(ubyte)((instr >> 26) & 0x01);
	const ubyte  S      = cast(ubyte)((instr >> 26) & 0x01);
	const ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	const uint   imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	res.set_flags = S == 1 ? true : false;
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	return res;
}

// ----------------------------------------- EOR -----------------------------------------

// ======================
//  Parse EOR(Immediate)
// ======================

enum field_tuples_eor_imm_32 = [Tuple!(opcode, string[])(opcode.eor_imm_32, ["rd","rn","imm"])];

instr_32 parse_eor_imm_32(const uint instr) {
	instr_32 res;
	res.op      = opcode.eor_imm_32;
	ubyte imm_8 = cast(ubyte)( instr        & 0xff);
	ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	ubyte S     = cast(ubyte)((instr >> 20) & 0x01);
	ubyte i     = cast(ubyte)((instr >> 26) & 0x01);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.set_flags = S == 1 ? true : false;
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	res.imm = thumb_expand_imm(imm_12);
	return res;
}

// ========================
//  Execute EOR(Immediate)
// ========================

void execute_eor_imm_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint imm = cpu.get(instr.rm);
	const uint rn  = cpu.get(instr.rn);
    const uint res = rn ^ imm;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- MVN -----------------------------------------

// ===============
//  Parse BIT NOT
// ===============

enum field_tuples_mvn_imm_32 = [Tuple!(opcode, string[])(opcode.mvn_imm_32, ["rd","imm"])];
/*
	Data Processing (Modified Immediate)
	First Half-Word: [15:5] 11101011010, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_mvn_imm_32(const uint instr) {
	instr_32 res = parse_orn_imm_32(instr);
	res.op = opcode.mvn_imm_32;
	return res;
}

// =================
//  Execute BIT NOT
// =================

void execute_mvn_imm_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint res = ~instr.imm;
	if (instr.set_flags) {
		cpu.n = (res == 0);
		cpu.n = (res & 0x8000_0000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

// ==================
//  Parse BIT OR NOT
// ==================

/*
	Data Processing (Modified Immediate)
	First Half-Word: [15:5] 11101011010, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_orn_imm_32(uint instr) {
	instr_32 res;
	res.op = opcode.orn_imm_32;
	const ubyte imm_8 = cast(ubyte)( instr        & 0xff);
	const ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	const ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	const ubyte S     = cast(ubyte)((instr >> 20) & 0x01);
	const ubyte i     = cast(ubyte)((instr >> 26) & 0x01);
	const ushort imm_12 = cast(ushort)((i << 3) | (imm_3 << 8) | imm_8);
	const int imm_32 = thumb_expand_imm(imm_12);
	res.imm = imm_32;
	res.set_flags = S == 1 ? true : false;
	res.rd = cast(reg)(rd);
	return res;
}

// ====================
//  Execute BIT OR NOT
// ====================

void execute_orn_imm_32(instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rn = cpu.get(instr.rn);
	const uint res = rn | (~instr.imm);
	cpu.set(instr.rd, res);
	if (instr.set_flags) {
		cpu.n = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.increment_pc(4);
}
// ----------------------------------------- SBC -----------------------------------------

// ======================
//  Parse SBC(Immediate)
// ======================

enum field_tuples_sbc_imm_32 = [Tuple!(opcode, string[])(opcode.sbc_imm_32, ["rd","rn","imm"])];

instr_32 parse_sbc_imm_32(const uint instr) {
	instr_32 res;
	res.op      = opcode.sbc_imm_32;
	ubyte imm_8 = cast(ubyte)( instr        & 0xff);
	ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	ubyte S     = cast(ubyte)((instr >> 20) & 0x01);
	ubyte i     = cast(ubyte)((instr >> 26) & 0x01);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.set_flags = S == 1 ? true : false;
	ushort imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	res.imm = thumb_expand_imm(imm_12);
	return res;
}

// ========================
//  Execute SBC(Immediate)
// ========================

void execute_sbc_imm_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint imm = cpu.get(instr.rm);
	const uint rn  = cpu.get(instr.rn);
	const uint c   = cast(uint)(cpu.c);
	ulong wide_res = cast(ulong)rn + cast(ulong)(~imm) + cast(ulong)c;
    const uint res = cast(uint)wide_res;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x8000_0000) != 0;
		cpu.c = cast(bool)((wide_res >> 32) & 1);
		bool overflow =
    		(((rn ^ imm) & 0x8000_0000) &&
     		(( rn ^ res) & 0x8000_0000));
		cpu.v = overflow;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------



