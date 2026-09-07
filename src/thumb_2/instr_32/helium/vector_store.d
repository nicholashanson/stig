import std.format;
import std.algorithm : canFind;
import std.typecons : Tuple, tuple;
import std.algorithm;
import std.conv;

import thumb_2_floating_point_ext_32;
import thumb_2_execute_instr;
import thumb_2_instrs;

import cortex_m_core;
import vm;
import ra81d;
import helium;

// ***************************************************************************************
// *									   VSTR                                          *
// ***************************************************************************************
// Store System Register. Store a system register in memory. The target address is 
// calculated from a base register plus an immediate offset. If the Floating-point Extension 
// is not implemented, access to the FPCXT payload is RES0. This instruction is UNDEFINED 
// if executed in Non-secure state.

// ============
//  Parse VSTR
// ============
// VDUP<v>.<size> Qd, Rt
instr_32
parse_vvstr_t1
(const uint instr) {
	return instr_32(
		rn:  		cast(reg)slice(instr, 16, 4),
		wback: 		cast(bool)slice(instr, 21, 1),
		add:        cast(bool)slice(instr, 23, 1),
		index:      cast(bool)slice(instr, 24, 1),
		r:          (slice(instr, 22, 1) << 3) | slice(instr, 13, 3),
		imm: 		slice(instr, 0, 7),
	);
}

// ==============
//  Execute VSTR
// ==============

void
execute_vvstr_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	preserve_fp_state(vm);
}

// ========================
//  Convert VSTR to String
// ========================

// VDUP<v>.<size> Qd, Rt
string convert_vvstr_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("vdup.%s %s, %s", instr.esize.to!string,
								    get_reg_name(instr.qd), 
								  	get_reg_name(instr.rt));
}
// ---------------------------------------------------------------------------------------