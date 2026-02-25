// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			   Multiply, Multiply Accumualate and Absolute Difference	    	     *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.conv;
import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *									  MLA 											 *
// ***************************************************************************************
// Multiply Accumulate multiplies two register values, and adds a third register value. 
// The least significant 32 bits of the result are written to the destination register. 
// These 32 bits do not depend on whether signed or unsigned calculations are performed.

// ===========
//  Parse MLA
// ===========

// MLA<c> <Rd>,<Rn>,<Rm>,<Ra>
// First Half-Word: [15:4] 111110110000, [3:0] Rn
// Second Half-Word: [15:12] Ra, [11:8] Rd, [7:4] 0000, [3:0] Rm
instr_32 parse_mla_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					ra: cast(reg)slice(instr, 12, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

// =============
//  Execute MLA
// =============

void 
execute_mla_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	const int op1    = vm.get_reg(instr.rn);
	const int op2    = vm.get_reg(instr.rm);
	const int addend = vm.get_reg(instr.ra);
	const int res    = op1 * op2 + addend;
	// setflags = FALSE;
	vm.set_reg(instr.rd, res);
}

// MLA<c> <Rd>,<Rn>,<Rm>,<Ra>
string convert_mla_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("mla%s %s, %s, %s, %s", cond != condition.none ? cond.to!string : "",
										  get_reg_name(instr.rd), 
										  get_reg_name(instr.rn), 
										  get_reg_name(instr.rm), 
										  get_reg_name(instr.ra));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  MUL 											 *
// ***************************************************************************************
// Multiply multiplies two register values. The least significant 32 bits of the result 
// are written to the destination register. These 32 bits do not depend on whether signed 
// or unsigned calculations are performed.

// It can optionally update the condition flags based on the result. This option is 
// limited to only a few forms of the instruction in the Thumb instruction set, and use 
// of it will adversely affect performance on many processor implementations.

// ===========
//  Parse MUL
// ===========

enum field_tuples_mul_t2 = [Tuple!(opcode, string[])(opcode.mul_t2, ["rd","rn","rm"])];
// MUL<c> <Rd>,<Rn>,<Rm>
// First Half-Word: [15:4] 111110110000, [3:0] Rn
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000, [3:0] Rm
instr_32 parse_mul_t2(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

// =============
//  Execute MUL
// =============

void 
execute_mul_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	const int op1 = vm.get_reg(instr.rn);
	const int op2 = vm.get_reg(instr.rm);
	const int res = op1 * op2;
	// setflags = FALSE;
	vm.set_reg(instr.rd, res);
}

// =======================
//  Convert MUL to String
// =======================

string convert_mul_t2_to_string(const ref instr_32 instr, const condition cond) {
	return "mul.w" ~ get_condition_string(cond) ~ " " ~ get_reg_name(instr.rd) ~ ", " 
		~ get_reg_name(instr.rn) ~ ", " ~ get_reg_name(instr.rm); 
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  MLS 											 *
// ***************************************************************************************
// Multiply and Subtract multiplies two register values, and subtracts the least 
// significant 32 bits of the result from a third register value. These 32 bits do not 
// depend on whether signed or unsigned calculations are performed. The result is written 
// to the destination register.

// ===========
//  Parse MLS
// ===========

enum field_tuples_mls_t1 = [Tuple!(opcode, string[])(opcode.mls_t1, ["rd","rn","rm","ra"])];
// MLS<c> <Rd>,<Rn>,<Rm>,<Ra>
// First Half-Word: [15:4] 111110110000, [3:0] Rn
// Second Half-Word: [15:12] Ra, [11:8] Rd, [7:4] 0001, [3:0] Rm
instr_32 parse_mls_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					ra: cast(reg)slice(instr, 12, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

// =============
//  Execute MLS
// =============

void 
execute_mls_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	const int op1    = vm.get_reg(instr.rn);
	const int op2    = vm.get_reg(instr.rm);
	const int addend = vm.get_reg(instr.ra);
	const int res    = addend - op1 * op2;
	vm.set_reg(instr.rd, res);
}

string convert_mls_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("mls%s %s, %s, %s, %s", cond != condition.none ? cond.to!string : "",
										  get_reg_name(instr.rd),
										  get_reg_name(instr.rn),
										  get_reg_name(instr.rm),
										  get_reg_name(instr.ra));
}
// ---------------------------------------------------------------------------------------
