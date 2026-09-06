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
// *									   VDUP                                          *
// ***************************************************************************************

// ============
//  Parse VDUP
// ============
// VDUP<v>.<size> Qd, Rt
instr_32
parse_vdup_t1
(const uint instr) {
	uint B_E = (slice(instr, 22, 1) << 1) | slice(instr, 5, 1);
	uint elements, esize;
	switch (B_E) {
		case 0b00:
			esize = 32;
			elements = 1;
			break;
		case 0b01: 
			esize = 16;
			elements = 2;
			break;
		case 0b10:
			esize = 8;
			elements = 4;
			break;
		default:
			assert(0, format("Invalid BE inside parse_vdup_t10: x%08X", instr));
	}
	return instr_32(
		qd:       to_q_reg((slice(instr, 7, 1) << 3 | slice(instr, 17, 3))), 
		rt:       cast(reg)slice(instr, 12, 4),
		esize:    esize,
		elements: elements,
	);
}

// ==============
//  Execute VDUP
// ==============

void
execute_vdup_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
	auto curr_ib = get_curr_instr_beat(vm);
	uint res = slice(vm.get_reg(instr.rt), 0, instr.esize);
	foreach (e; 0 .. instr.elements) {
		auto v = set_elem(res, e, instr.esize, slice(vm.get_reg(instr.rt), 0, instr.esize));
		res = v;
	}
	uint curr_word;
	foreach (e; 0 .. 4) {
		if (slice(curr_ib.elmt_mask, e, 1) == 1) {	
			curr_word = set_elem!uint(curr_word, e, 8, elem!uint(res, e, 8));
		}
	}
	vm.set_reg_s(q_to_s(instr.qd, curr_ib.curr_beat), curr_word);
} 

// ========================
//  Convert VDUP to String
// ========================

// VDUP<v>.<size> Qd, Rt
string convert_vdup_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("vdup.%s %s, %s", instr.esize.to!string,
								    get_reg_name(instr.qd), 
								  	get_reg_name(instr.rt));
}
// ---------------------------------------------------------------------------------------


