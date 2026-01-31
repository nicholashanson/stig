package arm64

import "core:fmt"
import "core:strings"
import "core:testing"

a64_opcode :: enum(u32) {
	hint,
	orr_shift_reg_32,
	invalid
}

get_opcode :: proc(instr: u32) -> a64_opcode {
	op0: u32 = (instr >> 31) & 0x1
	op1: u32 = (instr >> 25) & 0xf

	if ( (op1 & 0b0111) == 0b0101 ) {
		return decode_data_proc_reg(instr)
	}

	if ( (op1 & 0b1110) == 0b1010 ) {
		return decode_branches(instr)
	}

	return a64_opcode.invalid
}

decode_data_proc_reg :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.orr_shift_reg_32
}

decode_branches :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.hint;
}

opcode_to_string :: proc(op: a64_opcode) -> string {
    switch op {
    	case a64_opcode.hint 			: return "hint"
    	case a64_opcode.orr_shift_reg_32: return "orr_shift_reg_32"
    	case a64_opcode.invalid			: return "invalid"
    }
    return ""
}

@(test)
decode_ORR_test :: proc(t: ^testing.T) {
	instr: u32 = 0x2a1f03e0
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.orr_shift_reg_32, msg)
}

@(test)
decode_HINT_test :: proc(t: ^testing.T) {
	instr: u32 = 0xd503249f
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.hint, msg)
}