import std.format;
import std.algorithm : canFind;
import std.typecons : Tuple, tuple;
import std.algorithm;

import thumb_2_floating_point_ext_32;
import thumb_2_execute_instr;
import thumb_2_instrs;

import cortex_m_core;
import vm;
import ra81d;

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
		qd:       cast(reg)(slice(instr, 7, 1) << 3 | slice(instr, 17, 3)), 
		rt:       cast(reg)slice(instr, 12, 4),
		esize:    esize,
		elements: elements,
	);
}




