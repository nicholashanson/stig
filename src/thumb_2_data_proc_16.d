import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ----------------------------------------- ADC -----------------------------------------

// =====================
//  Parse ADC(Register)
// =====================

enum field_tuples_adc_reg = [Tuple!(opcode, string[])(opcode.adc_reg, ["rd","rm"])];
/*
	Data Processing
	ADC <Rdn>,<Rm>
	[15:6] 0100000101, [5:3] Rm, [2:0] Rd  
*/
instr_16 parse_adc_reg(ushort instr) {
	instr_16 res;
	res.op = opcode.adc_reg;
	const ubyte rdn = cast(ubyte)( instr       & 0x7);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute ADC(Register)
// =======================

void execute_adc_reg(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rn  = cpu.get(instr.rn);
	const uint rm  = cpu.get(instr.rm);
	const uint c   = cast(uint)(cpu.c);
	const uint res = rn + rm + c;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- AND -----------------------------------------

// =====================
//  Parse AND(Register)
// =====================

enum field_tuples_and_reg = [Tuple!(opcode, string[])(opcode.and_reg, ["rd","rm"])];
/*
	Data Processing
	AND <Rdn>,<Rm>
	[15:6] 0100000000, [5:3] Rm, [2:0] Rdn
*/
instr_16 parse_and_reg(ushort instr) {
	instr_16 res;
	res.op = opcode.and_reg;
	const ubyte rdn = cast(ubyte)( instr       & 0x7);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x7);
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute AND(Register)
// =======================

void execute_and_reg(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rn  = cast(int)(cpu.get(instr.rn));
	const uint rm  = cast(int)(cpu.get(instr.rm));
	const uint res = rn & rm;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- BIC -----------------------------------------

// =====================
//  Parse BIC(Register)
// =====================

enum field_tuples_bic_reg = [Tuple!(opcode, string[])(opcode.bic_reg, ["rd","rn"])];
/*
	Data Processing
	MUL <Rdm>,<Rn>,<Rdm>
	[15:6] 0100001110, [5:3] Rm, [2:0] Rdn
*/
instr_16 parse_bic_reg(ushort instr) {
	instr_16 res;
	res.op = opcode.bic_reg;
	const ubyte rdn = cast(ubyte)( instr       & 0x7);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute BIC(Register)
// =======================

void execute_bic_reg(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm  = cpu.get(instr.rm);
	const uint rn  = cpu.get(instr.rn);
	const uint res = rm & ~rn;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- CMP -----------------------------------------

// =====================
//  Parse CMP(Register)
// =====================

enum field_tuples_cmp_reg = [Tuple!(opcode, string[])(opcode.cmp_reg, ["rn","rm"])];
/*
	Data Processing
	CMP <Rn>,<Rm>
	[15:6] 0100001010, [5:3] Rm, [2:0] Rn
*/
instr_16 parse_cmp_reg(short instr) {
	instr_16 res;
	res.op = opcode.cmp_reg;
	ubyte rn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute CMP(Register)
// =======================

void execute_cmp_reg(instr_16 cmp_reg_instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(cmp_reg_instr.rm);
	const uint rn = cpu.get(cmp_reg_instr.rn);
	const int res = rn - rm;
	cpu.z = (res == 0);
	cpu.n = (res < 0);
	cpu.c = cast(uint)rn >= cast(uint)rm;
	cpu.v = (rn < 0 && res > 0);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- EOR -----------------------------------------

// =====================
//  Parse EOR(Register)
// =====================

enum field_tuples_eor_reg = [Tuple!(opcode, string[])(opcode.bic_reg, ["rd","rn"])];
/*
	Data Processing
	EOR <Rdn>,<Rm>
	[15:6] 0100000001, [5:3] Rm, [2:0] Rdn
*/
instr_16 parse_eor_reg(ushort instr) {
	instr_16 res;
	res.op = opcode.eor_reg;
	const ubyte rdn = cast(ubyte)( instr       & 0x7);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute EOR(Register)
// =======================

void execute_eor_reg(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm  = cpu.get(instr.rm);
	const uint rn  = cpu.get(instr.rn);
	const uint res = rm & ~rn;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- LSL -----------------------------------------

// =====================
//  Parse LSL(Register)
// =====================

enum field_tuples_lsl_reg = [Tuple!(opcode, string[])(opcode.lsl_reg, ["rd","rm"])];
/*
	Data Processing
	LSL <Rdn>,<Rm>
	[15:6] 0100000010, [5:3] Rm, [2:0] Rdn  
*/
instr_16 parse_lsl_reg(ushort instr) {
	instr_16 res;
	res.op = opcode.lsl_reg;
	const ubyte rdn = cast(ubyte)( instr       & 0x7);
	const ubyte rm =  cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute LSL(Register)
// =======================

void execute_lsl_reg(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint shift = cpu.get(instr.rm);
	const uint rn    = cpu.get(instr.rn);
	const uint res   = rn << shift;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
		if (shift != 0) {
        	cpu.c = (rn << (32 - shift)) & 1;
    	}
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- LSR -----------------------------------------

// =====================
//  Parse LSR(Register)
// =====================

enum field_tuples_lsr_reg = [Tuple!(opcode, string[])(opcode.lsr_reg, ["rd","rm"])];
/*                
    Data Processing
	LSR <Rdn>,<Rm>
	[15:6] 0100000011, [5:3] Rm, [2:0] Rdn  
*/
instr_16 parse_lsr_reg(short instr) {
	instr_16 res;
	res.op = opcode.lsr_reg;
	const ubyte rdn = cast(ubyte)( instr       & 0x7);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute LSR(Register)
// =======================

void execute_lsr_reg(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint shift = cpu.get(instr.rm);
	const uint rn    = cpu.get(instr.rn);
	const uint res   = rn >> shift;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
		if (shift != 0) {
        	cpu.c = (rn >> (shift - 1)) & 1;
    	}
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- MUL -----------------------------------------

// ===========
//  Parse MUL
// ===========

enum field_tuples_mul = [Tuple!(opcode, string[])(opcode.mul, ["rd","rn"])];
/*
	Data Processing
	MUL <Rdm>,<Rn>,<Rdm>
	[15:6] 0100001101, [5:3] Rn, [2:0] Rdm
*/
instr_16 parse_mul(ushort instr) {
	instr_16 res;
	res.op = opcode.mul;
	const ubyte rdm = cast(ubyte)( instr       & 0x7);
	const ubyte rn  = cast(ubyte)((instr >> 3) & 0x7);
	res.rd = cast(reg)(rdm);
	res.rm = cast(reg)(rdm);
	res.rn = cast(reg)(rn);
	return res;
}

// =============
//  Execute MUL
// =============

void execute_mul(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm  = cpu.get(instr.rm);
	const uint rn  = cpu.get(instr.rn);
	const uint res = rm * rn;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- LOR -----------------------------------------

// =====================
//  Parse ORR(Register)
// =====================

enum field_tuples_lor_reg = [Tuple!(opcode, string[])(opcode.lor_reg, ["rd","rm"])];
/*
	Data Processing
	ORR <Rdn>,<Rm>
	[15:6] 0100001100, [5:3] Rm, [2:0] Rdn
*/
instr_16 parse_lor_reg(short instr) {
	instr_16 res;
	res.op = opcode.lor_reg;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b111);
	res.rd = cast(reg)(rdn);
	res.rn = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute ORR(Register)
// =======================

void execute_lor_reg(const instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rn = cpu.get(instr.rn);
	const uint rm = cpu.get(instr.rm);
	const uint res = rn | rm;
	if (instr.set_flags) {
		cpu.z = (res == 0);
		cpu.n = (res & 0x80000000) != 0;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------