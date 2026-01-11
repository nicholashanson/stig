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
	uint imm  = cpu.get(instr.rm);
	uint rn   = cpu.get(instr.rn);
	uint c    = cast(uint)(cpu.c);
	ulong wide_res = cast(ulong)rn + cast(ulong)imm + cast(ulong)c;
    uint res = cast(uint)wide_res;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
		cpu.c = cast(bool)((wide_res >> 32) & 1);
		bool signed_overflow = ((cast(int)rn > 0 && cast(int)imm > 0 && cast(int)res < 0) ||
                                (cast(int)rn < 0 && cast(int)imm < 0 && cast(int)res > 0));
        cpu.v = signed_overflow;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

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
	uint imm  = cpu.get(instr.rm);
	uint rn   = cpu.get(instr.rn);
	uint c    = cast(uint)(cpu.c);
	ulong wide_res = cast(ulong)rn + cast(ulong)(~imm) + cast(ulong)c;
    uint res = cast(uint)wide_res;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
		cpu.c = cast(bool)((wide_res >> 32) & 1);
		bool overflow =
    		(((rn ^ imm) & 0x80000000) &&
     		(( rn ^ res) & 0x80000000));
		cpu.v = overflow;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

