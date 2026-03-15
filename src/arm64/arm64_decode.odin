package parse_elf

import "core:fmt"
import "core:strings"
import "core:testing"

a64_opcode :: enum(u32) {
	hint,
	mov_z_64,
	// bitfield
	ubfm_32,
	// add/subtract extended register
	add_ext_64,
	// loigical shifted register
	and_shift_reg_32, bic_shift_reg_32,  orr_shift_reg_32,  orn_shift_reg_32, eor_shift_reg_32,
	eon_shift_reg_32, ands_shift_reg_32, bics_shift_reg_32, and_shift_reg_64, bic_shift_reg_64,
	orr_shift_reg_64, orn_shift_reg_64,  eor_shift_reg_64,  eon_shift_reg_64, ands_shift_reg_64, 
	bics_shift_reg_64,
	// load/store register (register offset)
	ldr_reg_32,		  ldr_reg_simd_fp,	
	invalid
}

decode_bitfield :: proc(instr: u32) -> a64_opcode {
	// 0 00 0 SBFM — 32-bit
	// 0 01 0 BFM — 32-bit
	// 0 10 0 UBFM — 32-bit
	return a64_opcode.ubfm_32
	// 0 11 0 UNALLOCATED
	// 1 xx 0 UNALLOCATED
	// 1 00 1 SBFM — 64-bit
	// 1 01 1 BFM — 64-bit
	// 1 10 1 UBFM — 64-bit
}

decode_load_store_reg_offset :: proc(instr: u32) -> a64_opcode {
	size: u32 = (instr >> 30) & 0x3 
	VR:   u32 = (instr >> 26) & 0x1
	opc:  u32 = (instr >> 22) & 0x3
	// 10 0 01 xxx xxxxx
	if ((size == 0b10) && (VR == 0b0) && (opc == 0b01)) {
		return a64_opcode.ldr_reg_32
	} 
	// 10 1 01 xxx xxxxx LDR (register, SIMD&FP) — 32-bit FEAT_FP
	if ((size == 0b10) && (VR == 0b1) && (opc == 0b01)) {
		return a64_opcode.ldr_reg_simd_fp
	} 
	return a64_opcode.invalid
}

decode_load_and_stores :: proc(instr: u32) -> a64_opcode {
	op0: u32 = (instr >> 28) & 0xf 
	op1: u32 = (instr >> 26) & 0x1 
	op2: u32 = (instr >> 10) & 0x7fff
	// xx11 x 0xx1xxxxxxxxx10
	if ( ((op0 & 0b0011) == 0b0011) && ((op2 & 0b100100000000011) == 0b000100000000010) ) {
		return decode_load_store_reg_offset(instr)
	} 
	return a64_opcode.invalid
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

	if ( (op1 & 0b1110) == 0b1000 ) {
		return decode_data_proc_imm(instr)
	}

	// x x1x0
	if ( (op1 & 0b0101) == 0b0100 ) {
		return decode_load_and_stores(instr)
	}

	return a64_opcode.invalid
}

decode_logical_shift_reg :: proc(instr: u32) -> a64_opcode {
	sf:  u32 = (instr >> 31) & 0x1 
	opc: u32 = (instr >> 29) & 0x3
	N:   u32 = (instr >> 21) & 0x1
	s:   u32 = u32(sf << 3) | u32(opc << 1) | u32(N)
	switch s {
		// 0 00 0 AND (shifted register) — 32-bit
		case 0b0000: return a64_opcode.and_shift_reg_32
		// 0 00 1 BIC (shifted register) — 32-bit
		case 0b0001: return a64_opcode.bic_shift_reg_32
		// 0 01 0 ORR (shifted register) — 32-bit
		case 0b0010: return a64_opcode.orr_shift_reg_32
		// 0 01 1 ORN (shifted register) — 32-bit
		case 0b0011: return a64_opcode.orn_shift_reg_32
		// 0 10 0 EOR (shifted register) — 32-bit
		case 0b0100: return a64_opcode.eor_shift_reg_32
		// 0 10 1 EON (shifted register) — 32-bit
		case 0b0101: return a64_opcode.eon_shift_reg_32
		// 0 11 0 ANDS (shifted register) — 32-bit
		case 0b0110: return a64_opcode.ands_shift_reg_32
		// 0 11 1 BICS (shifted register) — 32-bit
		case 0b0111: return a64_opcode.bics_shift_reg_32
		// 1 00 0 AND (shifted register) — 64-bit
		case 0b1000: return a64_opcode.and_shift_reg_64
		// 1 00 1 BIC (shifted register) — 64-bit
		case 0b1001: return a64_opcode.bic_shift_reg_64
		// 1 01 0 ORR (shifted register) — 64-bit
		case 0b1010: return a64_opcode.orr_shift_reg_64
		// 1 01 1 ORN (shifted register) — 64-bit
		case 0b1011: return a64_opcode.orn_shift_reg_64
		// 1 10 0 EOR (shifted register) — 64-bit
		case 0b1100: return a64_opcode.eor_shift_reg_64
		// 1 10 1 EON (shifted register) — 64-bit
		case 0b1101: return a64_opcode.eon_shift_reg_64 
		// 1 11 0 ANDS (shifted register) — 64-bit       
		case 0b1110: return a64_opcode.ands_shift_reg_64
		// 1 11 1 BICS (shifted register) — 64-bit
		case 0b1111: return a64_opcode.bics_shift_reg_64
	}
	return a64_opcode.invalid
}

decode_proc_2_src :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_proc_1_src :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_add_sub_shifted_reg :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_add_sub_ext_reg :: proc(instr: u32) -> a64_opcode {
	// 0 0 0 00 ADD (extended register) — 32-bit
	// 0 0 1 00 ADDS (extended register) — 32-bit
	// 0 1 0 00 SUB (extended register) — 32-bit
	// 0 1 1 00 SUBS (extended register) — 32-bit
	// 1 0 0 00 ADD (extended register) — 64-bit
	return a64_opcode.add_ext_64
	// 1 0 1 00 ADDS (extended register) — 64-bit
	// 1 1 0 00 SUB (extended register) — 64-bit
	// 1 1 1 00 SUBS (extended register) — 64-bit
	// return a64_opcode.invalid
}

decode_add_sub_carry :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_add_sub_checked_ptr :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_data_proc_reg :: proc(instr: u32) -> a64_opcode {
	op0: u32 = (instr >> 30) &  0x1
	op1: u32 = (instr >> 28) &  0x1
	op2: u32 = (instr >> 21) &  0xf
	op3: u32 = (instr >> 10) & 0x3f
	// 0 1 0110 xxxxxx Data-processing (2 source)
	if ( (op0 == 0b0) && (op1 == 0b1) && (op2 == 0b0110)) {
		return decode_proc_2_src(instr)
	}
	// 1 1 0110 xxxxxx Data-processing (1 source)
	if ( (op0 == 0b1) && (op1 == 0b1) && (op2 == 0b0110)) {
		return decode_proc_1_src(instr)
	}
	// x 0 0xxx xxxxxx Logical (shifted register)
	if ( (op1 == 0b0) && (op2 & 0b1000) == 0b0000) {
		return decode_logical_shift_reg(instr)
	}
	// x 0 1xx0 xxxxxx Add/subtract (shifted register)
	if ( (op1 == 0b0) && (op2 & 0b1001) == 0b1000) {
		return decode_add_sub_shifted_reg(instr)
	}
	// x 0 1xx1 xxxxxx Add/subtract (extended register)
	if ( (op1 == 0b0) && (op2 & 0b1001) == 0b1001) {
		return decode_add_sub_ext_reg(instr)
	}
	// x 1 0000 000000 Add/subtract (with carry)
	if ( (op1 == 0b1) && (op2 & 0b0000) == 0b0000 && (op3 == 0b000000)) {
		return decode_add_sub_carry(instr)
	}
	// x 1 0000 001xxx Add/subtract (checked pointer)
	if ( (op1 == 0b1) && (op2 == 0b0000) && ((op3 & 0b111000) == 0b001000)) {
		return decode_add_sub_checked_ptr(instr)
	}
	return a64_opcode.invalid
}

decode_mov_wide_imm :: proc(instr: u32) -> a64_opcode {
	sf:  u32 = (instr >> 31) & 0x1
	opc: u32 = (instr >> 29) & 0x3
	if sf == 0b1 && opc == 0b10 {
		return a64_opcode.mov_z_64
	} 
	return a64_opcode.invalid
}

decode_data_proc_1_src :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_pc_rel :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_add_sub_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_add_dub_imm_tags :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_min_max_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_logical_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_extract :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

decode_data_proc_imm :: proc(instr: u32) -> a64_opcode {
	op1: u32 = (instr >> 22) & 0xf
	op0: u32 = (instr >> 29) & 0x3
	// 11 111x Data-processing (1 source immediate)
	if ( (op1 == 0b11) && ( op1 & 0b1110 == 0b1110)) {
		return decode_data_proc_1_src(instr)
	}
	// xx 00xx PC-rel. addressing
	if ( (op1 & 0b1100) == 0b0000 ) {
		return decode_pc_rel(instr)
	}
	// xx 010x Add/subtract (immediate)
	if ( (op1 & 0b1110) == 0b0100 ) {
		return decode_add_sub_imm(instr)
	}
	// xx 0110 Add/subtract (immediate, with tags)
	if ( op1 == 0b0110 ) {
		return decode_add_dub_imm_tags(instr)
	}
	// xx 0111 Min/max (immediate)
	if ( (op1 & 0b1111) == 0b0111) {
		return decode_min_max_imm(instr)
	}
	// xx 100x Logical (immediate)
	if ( (op1 & 0b1110) == 0b1000) {
		return decode_logical_imm(instr)
	}
	// xx 101x Move wide (immediate)
	if ( (op1 & 0b1110) == 0b1010) {
		return decode_mov_wide_imm(instr)
	}
	// xx 110x Bitfield
	if ( (op1 & 0b1110) == 0b1100) {
		return decode_bitfield(instr)
	}
	// != 11 111x Extract
	if ( (op0 != 0b11) && ((op1 & 0b1110) == 0b1110)) {
		return decode_extract(instr)
	}
	return a64_opcode.invalid
}

decode_branches :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.hint;
}

opcode_to_string :: proc(op: a64_opcode) -> string {
    switch op {
    	case a64_opcode.hint 			 : return "hint"
    	case a64_opcode.mov_z_64		 : return "mov_z_64"
    	// loigical shifted register
    	case a64_opcode.and_shift_reg_32 : return "and_shift_reg_32"
		case a64_opcode.bic_shift_reg_32 : return "bic_shift_reg_32"
		case a64_opcode.orr_shift_reg_32 : return "orr_shift_reg_32"
		case a64_opcode.orn_shift_reg_32 : return "orn_shift_reg_32"
		case a64_opcode.eor_shift_reg_32 : return "eor_shift_reg_32"
		case a64_opcode.eon_shift_reg_32 : return "eon_shift_reg_32"
		case a64_opcode.ands_shift_reg_32: return "ands_shift_reg_32"
		case a64_opcode.bics_shift_reg_32: return "bics_shift_reg_32"
		case a64_opcode.and_shift_reg_64 : return "and_shift_reg_64"
		case a64_opcode.bic_shift_reg_64 : return "bic_shift_reg_64"
		case a64_opcode.orr_shift_reg_64 : return "orr_shift_reg_64"
		case a64_opcode.orn_shift_reg_64 : return "orn_shift_reg_64"
		case a64_opcode.eor_shift_reg_64 : return "eor_shift_reg_64"
		case a64_opcode.eon_shift_reg_64 : return "eon_shift_reg_64"
		case a64_opcode.ands_shift_reg_64: return "ands_shift_reg_64"
		case a64_opcode.bics_shift_reg_64: return "bics_shift_reg_64"
		// load/store register (register offset)
		case a64_opcode.ldr_reg_32       : return "ldr_reg_32"
		case a64_opcode.ldr_reg_simd_fp  : return "ldr_reg_simd_fp"
		// add/subtract extended register
		case a64_opcode.add_ext_64       : return "add_ext_64"
		// bitfield
		case a64_opcode.ubfm_32			 : return "ubfm_32"
		case a64_opcode.invalid			 : return "invalid"
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

@(test)
decode_MOV_test :: proc(t: ^testing.T) {
	instr: u32 = 0xd2800082
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.mov_z_64, msg)
}

