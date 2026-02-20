// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *	           Long Multiply, Long Multiply Accumulate and Divide	    			 *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *									  SMULL 										 *
// ***************************************************************************************
// Signed Multiply Long multiplies two 32-bit signed values to produce a 64-bit result.

// =============
//  Parse SMULL
// =============

enum field_tuples_smull_t1 = [Tuple!(opcode, string[])(opcode.smull_t1, ["rd_lo","rd_hi","rn","rm"])];
// SMULL <RdLo>,<RdHi>,<Rn>,<Rm>
// First Half-Word: [15:4] 111110111000, [3:0] Rn
// Second Half-Word: [15:12] RdLo, [11:8] RdHi, [7:4] 0000, [3:1] Rm 
instr_32 parse_smull_t1(const uint instr) {
	return instr_32(rm:    cast(reg)slice(instr,  0, 4),
					rd_hi: cast(reg)slice(instr,  8, 4),
					rd_lo: cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4));
}

// ===============
//  Execute SMULL
// ===============

void 
execute_smull_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	const int rm 	  = vm.get_reg(instr.rm); 
	const int rn 	  = vm.get_reg(instr.rn);
	const long res    = cast(long)rm * cast(long)rn;
	const uint res_hi = cast(uint)((res >> 32) & 0xffff_ffff);
	const uint res_lo = cast(uint)( res        & 0xffff_ffff);
	vm.set_reg(instr.rd_lo, res_lo);
	vm.set_reg(instr.rd_hi, res_hi);  
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UDIV 											 *
// ***************************************************************************************
// Unsigned Divide divides a 32-bit unsigned integer register value by a 32-bit unsigned 
// integer register value, and writes the result to the destination register. The 
// condition code flags are not affected.

// ============
//  Parse UDIV
// ============

enum field_tuples_udiv_t1 = [Tuple!(opcode, string[])(opcode.udiv_t1, ["rd","rn","rm"])];
// First Half-Word: [15:4] 11110111011, [3:0] Rn
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 1111, [3:0] Rm 
instr_32 parse_udiv_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd:	cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

// ==============
//  Execute UDIV
// ==============

void 
execute_udiv_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	if (vm.get_reg(instr.rm) == 0) {
		vm.set_reg(instr.rd, 0);
		return;
	}
	const uint res = vm.get_reg(instr.rn) / vm.get_reg(instr.rm);
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UMULL											 *
// ***************************************************************************************
// Unsigned Multiply Long multiplies two 32-bit unsigned values to produce a 64-bit 
// result.

enum field_tuples_umull_t1 = [Tuple!(opcode, string[])(opcode.umull_t1, ["rd_lo","rd_hi","rn","rm"])];
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01110, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_umull_t1(const uint instr) {
	return instr_32(rm:    cast(reg)slice(instr,  0, 4),
					rd_hi: cast(reg)slice(instr,  8, 4),
					rd_lo: cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4));
}

// ===============
//  Execute UMULL
// ===============

void 
execute_umull_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	ulong res =
        cast(ulong)(vm.get_reg(instr.rn)) *
        cast(ulong)(vm.get_reg(instr.rm));
    vm.set_reg(instr.rd_lo, cast(uint)res);
    vm.set_reg(instr.rd_hi, cast(uint)(res >> 32));
}
// ---------------------------------------------------------------------------------------