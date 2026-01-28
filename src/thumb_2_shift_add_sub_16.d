import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_reg = [Tuple!(opcode, string[])(opcode.add_reg, ["rd","rn","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move, and Compare
	ADD <Rd>,<Rn>,<Rm>
	[15:9] 0001100, [8:6] Rm, [5:3] Rn, [2:0] Rd
*/
instr_16 parse_add_reg(short instr) {
	instr_16 res;
	res.op = opcode.add_reg;
	ubyte rd = cast(ubyte)(instr & 0b111);
	ubyte rn = cast(ubyte)((instr >> 3) & 0b111);
	ubyte rm = cast(ubyte)((instr >> 6) & 0b111);
	res.rd = cast(reg)(rd);
	res.rn = cast(reg)(rn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_high_reg_1 = [Tuple!(opcode, string[])(opcode.add_high_reg_1, ["rd","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ADD <Rdn>,<Rm>
	[15:8] 01000100, [7] DN, [6:3] Rm, [2:0] Rdn
*/
instr_16 parse_add_high_reg_1(short instr) {
	instr_16 res;
	res.op = opcode.add_high_reg_1;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm  = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte dn  = cast(ubyte)((instr >> 7) & 0b1);
	if (dn) {
		rdn |= 0b1000;
	}
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_high_reg_2 = [Tuple!(opcode, string[])(opcode.add_high_reg_2, ["rd","rm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ADD <Rdn>,<Rm>
	[15:8] 01000100, [7] DN, [6:3] Rm, [2:0] Rdn
*/
instr_16 parse_add_high_reg_2(short instr) {
	instr_16 res;
	res.op = opcode.add_high_reg_2;
	ubyte rdn = cast(ubyte)(instr & 0b111);
	ubyte rm = cast(ubyte)((instr >> 3) & 0b1111);
	ubyte dn = cast(ubyte)((instr >> 7) & 0b1);
	if (dn) {
		rdn |= 0b1000;
	}
	res.rn = cast(reg)(rdn);
	res.rd = cast(reg)(rdn);
	res.rm = cast(reg)(rm);
	return res;
}

// =======================
//  Execute ADD(Register)
// =======================

void execute_add_reg(const instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rn  = cpu.get(instr.rn);
	const uint rm  = cpu.get(instr.rm);
	const uint res = rn + rm;
	if (!cpu.in_it_block()) { // TODO: this doesn't handle encoding T2 
		cpu.z = (res == 0); 						// APSR.Z = IsZeroBit(result);
		cpu.n = ((res & 0x8000_0000) != 0);			// APSR.N = result<31>;
        cpu.c = (res < rn);                 		// APSR.C = carry;
        const int srn  = cast(int)rn;
        const int srm  = cast(int)rm;
        const int sres = cast(int)res;
        cpu.v = ((srn ^ sres) & (srm ^ sres)) < 0;	// APSR.V = overflow;
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------- ASR ------------------------------------------

// ======================
//  Parse ASR(Immediate)
// ======================

enum field_tuples_asr_imm = [Tuple!(opcode, string[])(opcode.asr_imm, ["rm","rd","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	ASR <Rd>,<Rm>,#<imm5>
	[15:11] 00010, [10:6] imm5, [5:3] Rm, [2:0] Rd  
*/
instr_16 parse_asr_imm(const ushort instr) {
	instr_16 res;
	res.op = opcode.asr_imm;
	const ubyte rd  = cast(ubyte)( instr       & 0x07);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x07);
	const ubyte imm = cast(ubyte)((instr >> 6) & 0x1f);
	res.rm = cast(reg)(rm);
	res.rd = cast(reg)(rd);
	res.imm = imm;
	return res;
}

// =============
//  Execute ASR
// =============

void execute_asr_imm(const instr_16 instr, ref cortex_m_cpu cpu) {
	int 	   rm = cast(int)(cpu.get(instr.rm));
	rm = 	   rm >> (instr.imm - 1);
	const bool carry = (1 & rm);
	rm = 	   rm >> 1;
	if (!cpu.in_it_block()) {
		cpu.z = (rm == 0);			// APSR.Z = IsZeroBit(result);
		cpu.n = (rm < 0);			// APSR.N = result<31>;
		cpu.c = carry;				// APSR.C = carry;
		// APSR.V unchanged
	}
	cpu.set(instr.rd, rm);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------- LSL ------------------------------------------

// ======================
//  Parse LSL(Immediate)
// ======================

enum field_tuples_lsl_imm = [Tuple!(opcode, string[])(opcode.lsl_imm, ["rd","rm","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	LSL <Rd>,<Rm>,#<imm5>
	[15:11] 00000, [10:6] imm5, [5:3] Rm, [2:0] Rd
*/
instr_16 parse_lsl_imm(const ushort instr) {
	instr_16 res;
	res.op = opcode.lsl_imm;
	ubyte rd  = cast(ubyte)( instr 	     & 0x07);
	ubyte rm  = cast(ubyte)((instr >> 3) & 0x07);
	res.rd    = cast(reg)(rd);
	res.rm    = cast(reg)(rm);
	ubyte imm = cast(ubyte)((instr >> 6) & 0x1f);
	res.imm = imm;
	return res;
}

// =============
//  Execute LSL 
// =============

void execute_lsl_imm(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm    = cpu.get(instr.rm);
	uint res   = rm << (instr.imm - 1);
	const bool carry = ((res & 0x8000_0000) != 0);
	res 	   = res << 1;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);						// APSR.Z = IsZeroBit(result);
		cpu.n = ((res & 0x8000_0000) != 0);		// APSR.N = result<31>;
		cpu.c = carry;							// APSR.C = carry;	
		// APSR.V unchanged
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------- LSR ------------------------------------------

// ======================
//  Parse LSR(Immediate)
// ======================

enum field_tuples_lsr_imm = [Tuple!(opcode, string[])(opcode.lsr_imm, ["rd","rm","imm"])];
/*
	Shift(Immediate), Add, Subtract, Move and Compare
	LSR <Rd>,<Rm>,#<imm5>
	[15:11] 00001, [10:6] imm5, [5:3] Rm, [2:0] Rd
*/
instr_16 parse_lsr_imm(const ushort instr) {
	instr_16 res;
	res.op = opcode.lsr_imm;
	const ubyte rd  = cast(ubyte)( instr       & 0x07);
	const ubyte rm  = cast(ubyte)((instr >> 3) & 0x07);
	const ubyte imm = cast(ubyte)((instr >> 6) & 0x1f);
	res.rd = cast(reg)(rd);
	res.rm = cast(reg)(rm);
	res.imm = imm;
	return res;
}

// ========================
//  Execute LSR(Immediate) 
// ========================

void execute_lsr_imm(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm    = cpu.get(instr.rm);
	uint       res   = rm >>> (instr.imm - 1);
	const bool carry = (res & 1);
	res = res >>> 1;
	if (!cpu.in_it_block()) {
		cpu.z = (res == 0);		// APSR.Z = IsZeroBit(result); 	
		cpu.n = (res < 0);		// APSR.N = result<31>;
		cpu.c = carry;			// APSR.C = carry;
		// APSR.V unchanged
	}
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------



