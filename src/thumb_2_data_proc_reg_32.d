import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ----------------------------------------- ASR -----------------------------------------

// =====================
//  Parse ASR(Register)
// =====================

enum field_tuples_asr_reg_32 = [Tuple!(opcode, string[])(opcode.asr_reg_32, ["rd","rn","rm"])];

/*
	Data Processing (Register)
	ASR <Rd>, <Rn>, <Rm>
	First Half-Word: [15:5] 11111010010, [4] S, [3:0] Rn
	Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000. [3:0] Rm
*/
instr_32 parse_asr_reg_32(const uint instr) {
	instr_32 res;
	res.op   = opcode.asr_reg_32;
	ubyte rm = cast(ubyte)( instr        & 0x0f);
	ubyte rd = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte rn = cast(ubyte)((instr >> 16) & 0x0f);
	ubyte S  = cast(ubyte)((instr >> 20) & 0x01);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	res.set_flags = S == 1 ? true : false;
	return res;
}

// =======================
//  Execute ASR(Register)
// =======================

void execute_asr_reg_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint shift_n = rm & 0xff;
	uint res;
	bool carry = cpu.c;
    if (shift_n == 0) {
        res = rm;
    }
    else if (shift_n < 32) {
        carry = ((rm >> (shift_n - 1)) & 1) != 0;
        res = cast(uint)(cast(int)rm >> shift_n);
    }
    else {
        carry = ((rm >> 31) & 1) != 0;
        res = (rm & 0x8000_0000) != 0
              ? 0xffff_ffff
              : 0;
    }
	if (instr.set_flags) {
        cpu.n = (res & 0x8000_0000) != 0;
        cpu.z = res == 0;
        cpu.c = carry;
    }
	cpu.set(instr.rd, res);	
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------- UXTH -----------------------------------------

// ============
//  Parse UXTH
// ============

enum field_tuples_uxth_32 = [Tuple!(opcode, string[])(opcode.uxth_32, ["rd","rm","imm"])];

/*
	Data Processing (Register)
	UXTH.W <Rd>,<Rm>{,<rotation>}
	First Half-Word: [15:5] 11111010010, [4] S, [3:0] Rn
	Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000. [3:0] Rm
*/
instr_32 parse_uxth_32(const uint instr) {
	instr_32 res;
	res.op = opcode.uxth_32;
	ubyte rm     = cast(ubyte)( instr       & 0x0f);
	ubyte rotate = cast(ubyte)((instr >> 4) & 0x03);
	ubyte rd 	 = cast(ubyte)((instr >> 8) & 0x0f);
	res.rd  = cast(reg)(rd);
	res.imm = rotate << 3; 
	res.rm  = cast(reg)(rm);
	return res;
}

// ==============
//  Execute UXTH
// ==============

void execute_uxth_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint rotated = rotr(rm, instr.imm);
	cpu.set(instr.rd, rotated);	
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------