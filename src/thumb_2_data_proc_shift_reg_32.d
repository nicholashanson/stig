import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ----------------------------------------- EOR -----------------------------------------

// =====================
//  Parse EOR(Register)
// =====================

enum field_tuples_eor_reg_32 = [Tuple!(opcode, string[])(opcode.eor_reg_32, ["rd","rn","rm"])];

/*
	Data Processing (Shifted Register)
	EOR <Rdn>,<Rm> 
	[15:5] 11101010100, [4] S, [3:0] Rn
	[15] 0, [14:12] imm3, [11:8] Rd. [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_eor_reg_32(const uint instr) {
	instr_32 res;
	res.op     = opcode.eor_reg_32;
	ubyte rm   = cast(ubyte)( instr        & 0x0f);
	ubyte rd   = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte type = cast(ubyte)((instr >>  4) & 0x03);
	ubyte imm2 = cast(ubyte)((instr >>  6) & 0x03);
	ubyte imm3 = cast(ubyte)((instr >> 12) & 0x07);
	ubyte S    = cast(ubyte)((instr >> 20) & 0x01);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	ubyte imm5 = cast(ubyte)((imm3 << 2) | imm2);
	res.shift_t = get_shift_type(type, imm5);
	res.set_flags = S == 1 ? true : false;
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm5;
	}
	return res;
}

// =======================
//  Execute EOR(Register)
// =======================

void execute_eor_reg_32(const ref instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint rn = cpu.get(instr.rn);
	const uint shifted = shift(instr.shift_t, instr.shift_n, rm); 
	const uint res = rn ^ shifted;
	if (instr.set_flags) {
		cpu.n = (res & 0x8000_0000) != 0;
    	cpu.z = (res == 0);
    	cpu.c = get_shifter_carry(rm, instr.shift_t, instr.shift_n, cpu.c);
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------
