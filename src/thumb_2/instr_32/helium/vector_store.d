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
	// n = UInt(Rn);
	// index = (P == '1');
	// add = (A == '1');
	// wback = (W == '1');
	// r = regh:regl;
	// imm32 = ZeroExtend(imm:'00', 32);
	return instr_32();
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