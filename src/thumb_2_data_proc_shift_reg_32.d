import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ----------------------------------------- ADD -----------------------------------------

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_reg_32 = [Tuple!(opcode, string[])(opcode.add_reg_32, ["rd","rn","rm","shift"])];
/*
	Data Processing (Shifted Register)
	First Half-Word: [15:5] 1110101000, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_add_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.add_reg_32;
	const ubyte rm    = cast(ubyte)( instr        & 0x0f);
	const ubyte type  = cast(ubyte)((instr >>  4) & 0x03);
	const ubyte imm_2 = cast(ubyte)((instr >>  6) & 0x03);
	const ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	const ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	const ubyte imm_5 = cast(ubyte)((imm_3 << 2) | (imm_2));
	const ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	res.shift_t = get_shift_type(type, imm_5);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm_5;
	}
	return res;
}

// =======================
//  Execute ADD(Register)
// =======================

void execute_add_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	const uint  rn =  cpu.get(instr.rn);
	const uint  rm =  cpu.get(instr.rm);
	const uint  shifted = shift(instr.shift_t, instr.shift_n, rm);
	const ulong wide = cast(ulong)rn + cast(ulong)shifted;
    const uint  res  = cast(uint)wide;
	if (instr.set_flags) {
		cpu.n = (res & 0x8000_0000) != 0;
		cpu.z = (res == 0);
		cpu.c = (wide >> 32) & 1;
		bool rn_sign  = (rn      & 0x8000_0000) != 0;
    	bool op_sign  = (shifted & 0x8000_0000) != 0;
    	bool res_sign = (res     & 0x8000_0000) != 0;
    	cpu.v = (rn_sign == op_sign) && (rn_sign != res_sign);
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- ADC -----------------------------------------

// =====================
//  Parse ADC(Register)
// =====================

enum field_tuples_adc_reg_32 = [Tuple!(opcode, string[])(opcode.adc_reg_32, ["rd","rn","rm","shift"])];
/*
	ADC.W <Rd>,<Rn>,<Rm>{,<shift>}
	Data Processing (Shifted Register)
	First Half-Word: [15:5] 11101011010, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_adc_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.adc_reg_32;
	ubyte rm    = cast(ubyte)( instr        & 0x0f);
	ubyte type  = cast(ubyte)((instr >>  4) & 0x03);
	ubyte imm_2 = cast(ubyte)((instr >>  6) & 0x03);
	ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	ubyte imm   = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// =======================
//  Execute ADC(Register)
// =======================

void execute_adc_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint rn = cpu.get(instr.rn);
	const uint shifted = shift(instr.shift_t, instr.shift_n, rm);
	const uint res = rn + shifted + cast(uint)(cpu.c);
	if (instr.set_flags) {
		cpu.n = (res & 0x8000_0000) != 0;
		cpu.z = (res == 0);
		cpu.c = get_shifter_carry(rm, instr.shift_t, instr.shift_n, cpu.c);
		bool rn_sign  = (rn      & 0x8000_0000) != 0;
    	bool op_sign  = (shifted & 0x8000_0000) != 0;
    	bool res_sign = (res     & 0x8000_0000) != 0;
    	cpu.v = (rn_sign == op_sign) && (rn_sign != res_sign);
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- EOR -----------------------------------------

// =====================
//  Parse EOR(Register)
// =====================

enum field_tuples_eor_reg_32 = [Tuple!(opcode, string[])(opcode.eor_reg_32, ["rd","rn","rm","shift"])];

/*
	Data Processing (Shifted Register)
	EOR <Rdn>,<Rm> 
	First Half-Word: [15:5] 11101010100, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd. [7:6] imm2, [5:4] type, [3:0] Rm
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

// ----------------------------------------- SBC -----------------------------------------

// =====================
//  Parse SBC(Register)
// =====================

enum field_tuples_sbc_reg_32 = [Tuple!(opcode, string[])(opcode.sbc_reg_32, ["rd","rn","rm","shift"])];
/*
	Data Processing (Shifted Register)
	First Half-Word: [15:5] 11101011101, [4] S, [3:0] Rn
	Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
*/
instr_32 parse_sbc_reg_32(uint instr) {
	instr_32 res;
	res.op = opcode.sbc_reg_32;
	const ubyte rm    = cast(ubyte)( instr        & 0x0f);
	const ubyte type  = cast(ubyte)((instr >>  4) & 0x03);
	const ubyte imm_2 = cast(ubyte)((instr >>  6) & 0x03);
	const ubyte rd    = cast(ubyte)((instr >>  8) & 0x0f);
	const ubyte imm_3 = cast(ubyte)((instr >> 12) & 0x07);
	const ubyte rn    = cast(ubyte)((instr >> 16) & 0x0f);
	const ubyte imm   = cast(ubyte)((imm_3 << 2) | imm_2);
	res.shift_t = get_shift_type(type, imm);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	if (res.shift_t == shift_type.rrx) {
		res.shift_n = 1;
	} else {
		res.shift_n = imm;
	}
	return res;
}

// =======================
//  Execute SBC(Register)
// =======================

void execute_sbc_reg_32(instr_32 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint rn = cpu.get(instr.rn);
	const uint shifted = shift(instr.shift_t, instr.shift_n, rm);
	const uint borrow = cpu.c ? 0u : 1u;
	const uint res = rn - shifted - borrow;
	if (instr.set_flags) {
		cpu.n = (res & 0x8000_0000) != 0;
    	cpu.z = (res == 0);
    	cpu.c = (cast(ulong)rn >= cast(ulong)shifted + borrow);
    	bool overflow =
    		((rn ^ shifted) & 0x8000_0000) != 0 &&
    		((rn ^ res)     & 0x8000_0000) != 0;
    	cpu.v = overflow;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(4);
}
// ---------------------------------------------------------------------------------------
