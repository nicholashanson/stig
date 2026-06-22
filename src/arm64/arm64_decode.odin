package parse_elf

import "core:fmt"
import "core:strings"
import "core:testing"

// ---------------------------------------------------------------------------------------
a64_opcode :: enum(u32) {
	// conditional branch imm
	b_cond, bc_cond,
	hint, b, bl,
	// data proc one source
	rbit_32, rbit_64, rev16_32, rev16_64, clz_32, clz_64, cls_32, cls_64, rev32, rev_32, rev_64,
	// mov_wide_imm
	mov_z_32, mov_k_32, mov_n_32,
	mov_z_64, mov_k_64, mov_n_64,
	// bitfield
	ubfm_32,
	// add/subtract extended register
	add_ext_64,
	// add/sub imm
	add_imm_32,  adds_imm_32, sub_imm_32, subs_imm_32, add_imm_64,
	adds_imm_64, sub_imm_64,  subs_imm_64,
	// loigical shifted register
	and_shift_reg_32, bic_shift_reg_32,  orr_shift_reg_32,  orn_shift_reg_32, eor_shift_reg_32,
	eon_shift_reg_32, ands_shift_reg_32, bics_shift_reg_32, and_shift_reg_64, bic_shift_reg_64,
	orr_shift_reg_64, orn_shift_reg_64,  eor_shift_reg_64,  eon_shift_reg_64, ands_shift_reg_64, 
	bics_shift_reg_64,
	// load/store register (register offset)
	ldr_reg_32,		  ldr_reg_simd_fp,	
	// add shift reg
	add_shift_reg_32,  adds_shift_reg_32, sub_shift_reg_32, subs_shift_reg_32, add_shift_reg_64,
	adds_shift_reg_64, sub_shift_reg_64,  subs_shift_reg_64,

	stp_32_pre_index, stp_64_pre_index, stp_64_post_index, stp_64_offset,

	// unconditional branch (register)
	ret,
	invalid
}
// ---------------------------------------------------------------------------------------

// Store Pair of Registers calculates an address from a base register value and an immediate offset, and 
// stores two 32-bit words or two 64-bit doublewords to the calculated address, from two registers.
decode_stp :: proc(instr: u32) -> a64_opcode {
	opc: u32 = (instr >> 30) & 0x3
	if (opc == 0b00) {
		return a64_opcode.stp_32_pre_index;
	}
	if (opc == 0b10) {
		return a64_opcode.stp_64_pre_index;
	}
	return a64_opcode.invalid;
}
// ---------------------------------------------------------------------------------------
// =================
//  DECODE BITFIELD
// =================

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
// ---------------------------------------------------------------------------------------
// ==============================
//  DECODE LOAD STORE REG OFFSET
// ==============================

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
// ---------------------------------------------------------------------------------------
// ========================
//  DECODE LOAD AND STORES
// ========================

decode_load_and_stores :: proc(instr: u32) -> a64_opcode {
	op0: u32 = (instr >> 28) & 0xf 
	op1: u32 = (instr >> 26) & 0x1 
	op2: u32 = (instr >> 10) & 0x7fff
	op3: u32 = (instr >> 23) & 0x3
	// xx11 x 0xx1xxxxxxxxx10
	if ( ((op0 & 0b0011) == 0b0011) && ((op2 & 0b100100000000011) == 0b000100000000010) ) {
		return decode_load_store_reg_offset(instr)
	} 
	if ( (op3 == 0b11)) {
		return a64_opcode.stp_64_pre_index
	}
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------
// ============
//  GET OPCODE
// ============

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
// ---------------------------------------------------------------------------------------
// ==========================
//  DECODE LOGICAL SHIFT REG
// ==========================

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
// ---------------------------------------------------------------------------------------
// ==================
//  DECODE POC 2 SRC
// ==================

decode_proc_2_src :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------
// ==================
//  DECODE POC 1 SRC
// ==================

decode_data_proc_1_src_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------
// ============================
//  DECODE ADD/SUB SHIFTED REG
// ============================

decode_add_sub_shifted_reg :: proc(instr: u32) -> a64_opcode {
	sf_op_S := slice(instr, 29, 3)
	switch sf_op_S {
		// 0 0 0 ADD (shifted register) — 32-bit
		case 0b000: return a64_opcode.add_shift_reg_32
		// 0 0 1 ADDS (shifted register) — 32-bit
		case 0b001: return a64_opcode.adds_shift_reg_32
		// 0 1 0 SUB (shifted register) — 32-bit
		case 0b010: return a64_opcode.sub_shift_reg_32
		// 0 1 1 SUBS (shifted register) — 32-bit
		case 0b011: return a64_opcode.subs_shift_reg_32
		// 1 0 0 ADD (shifted register) — 64-bit
		case 0b100: return a64_opcode.add_shift_reg_64
		// 1 0 1 ADDS (shifted register) — 64-bit
		case 0b101: return a64_opcode.adds_shift_reg_64
		// 1 1 0 SUB (shifted register) — 64-bit
		case 0b110: return a64_opcode.sub_shift_reg_64
		// 1 1 1 SUBS (shifted register) — 64-bit
		case 0b111: return a64_opcode.subs_shift_reg_64
	}
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------
// ========================
//  DECODE ADD/SUB EXT REG
// ========================

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
// ---------------------------------------------------------------------------------------
// ======================
//  DECODE ADD/SUB CARRY
// ======================

decode_add_sub_carry :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ================================
//  DECODE ADD/SUB CHECKED POINTER
// ================================

decode_add_sub_checked_ptr :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ======================
//  DECODE DATA PROC REG
// ======================

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
		return decode_data_proc_1_src_reg(instr)
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

// ======================
//  DECODE MOVE WIDE IMM
// ======================

decode_mov_wide_imm :: proc(instr: u32) -> a64_opcode {
	sf:  u32 = (instr >> 31) & 0x1
	opc: u32 = (instr >> 29) & 0x3
	hw:  u32 = (instr >> 21) & 0x3
	// 1 10 MOVZ — 64-bit
 	if sf == 0b1 && opc == 0b10 {
		return a64_opcode.mov_z_64
	}
	// 0 10 0x MOVZ — 32-bit
	if sf == 0b0 && opc == 0b10 && (hw & 0b10) == 0b00 { 
	 	return a64_opcode.mov_z_32
	}
	// 00 0x MOVN — 32-bit
	if sf == 0b0 && opc == 0b00 && (hw & 0b10) == 0b00 { 
	 	return a64_opcode.mov_n_32
	}
	// 0 11 0x MOVK — 32-bit
	if sf == 0b0 && opc == 0b11 && (hw & 0b10) == 0b00 { 
		return a64_opcode.mov_k_32
	}
	// 1 00 MOVN — 64-bit
	if sf == 0b1 && opc == 0b00 { 
	 	return a64_opcode.mov_n_64
	}
	// 1 11 MOVK — 64-bit
	if sf == 0b1 && opc == 0b11 { 
	 	return a64_opcode.mov_k_64
	}
	return a64_opcode.invalid
}

// ========================
//  DECODE DATA PROC 1 SRC
// ========================

decode_data_proc_1_src_reg :: proc(instr: u32) -> a64_opcode {
	sf       := slice(instr, 31, 1)
	S        := slice(instr, 29, 1)
	opcode2  := slice(instr, 16, 5)
	opcode   := slice(instr, 10, 6)
	combined := (sf << 12) | (S << 11) | (opcode2 << 6) | opcode;
	switch combined {
		// 0 0 00000 000000 RBIT — 32-bit -
		case 0b0000000000000: return a64_opcode.rbit_32
		// 0 0 00000 000001 REV16 — 32-bit -
		case 0b0000000000001: return a64_opcode.rev16_32
		// 0 0 00000 000010 REV — 32-bit -
		case 0b0000000000010: return a64_opcode.rev_32
		// 0 0 00000 000011 UNALLOCATED -
		// 0 0 00000 000100 CLZ — 32-bit -
		case 0b0000000000100: return a64_opcode.clz_32
		// 0 0 00000 000101 CLS — 32-bit -
		case 0b0000000000101: return a64_opcode.cls_32
		// 1 0 00000 000000 RBIT — 64-bit -
		case 0b1000000000000: return a64_opcode.rbit_64
		// 1 0 00000 000001 REV16 — 64-bit -
		case 0b1000000000001: return a64_opcode.rev16_64
		// 1 0 00000 000010 REV32 -
		case 0b1000000000010: return a64_opcode.rev32
		// 1 0 00000 000011 REV — 64-bit -
		case 0b1000000000011: return a64_opcode.rev_64
		// 1 0 00000 000100 CLZ — 64-bit -
		case 0b1000000000100: return a64_opcode.clz_64
		// 1 0 00000 000101 CLS — 64-bit
		case 0b1000000000101: return a64_opcode.cls_64
	}
	return a64_opcode.invalid
}

// ===============
//  DECODE PC REL
// ===============

decode_pc_rel :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ====================
//  DECODE ADD/SUB IMM
// ====================

decode_add_sub_imm :: proc(instr: u32) -> a64_opcode {
	sf 		 := slice(instr, 31, 1)
	op 		 := slice(instr, 30, 1)
	S  		 := slice(instr, 29, 1)
	combined := (sf << 2) | (op << 1) | S;
	switch combined {
		case 0b000: return a64_opcode.add_imm_32 
		case 0b001: return a64_opcode.adds_imm_32
		case 0b010: return a64_opcode.sub_imm_32
		case 0b011: return a64_opcode.subs_imm_32
		case 0b100: return a64_opcode.add_imm_64
		case 0b101: return a64_opcode.adds_imm_64
		case 0b110: return a64_opcode.sub_imm_64
		case 0b111: return a64_opcode.subs_imm_64
	}
	return a64_opcode.invalid
}

// =========================
//  DECODE ADD/SUB IMM TAGS
// =========================

decode_add_sub_imm_tags :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ====================
//  DECODE MIN/MAX IMM
// ====================

decode_min_max_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ====================
//  DECODE LOGICAL IMM
// ====================

decode_logical_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ================
//  DECODE EXTRACT
// ================

decode_extract :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ======================
//  DECODE DATA PROC IMM
// ======================

decode_data_proc_imm :: proc(instr: u32) -> a64_opcode {
	op1: u32 = (instr >> 22) & 0xf
	op0: u32 = (instr >> 29) & 0x3
	// 11 111x Data-processing (1 source immediate)
	if ( (op1 == 0b11) && ( op1 & 0b1110 == 0b1110)) {
		return decode_data_proc_1_src_imm(instr)
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
		return decode_add_sub_imm_tags(instr)
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

// =================================
//  DECODE UNCONDITIONAL BRANCH REG
// =================================

decode_unconditional_branch_reg :: proc(instr: u32) -> a64_opcode {
	// 0010 11111 000000 xxxxx 00000 RET 
	return a64_opcode.ret
}

// =================================
//  DECODE UNCONDITIONAL BRANCH IMM
// =================================

decode_unconditional_branch_imm :: proc(instr: u32) -> a64_opcode {
	op := slice(instr, 31, 1)
	if ( (op == 0b0) ) {
		return a64_opcode.b;
	}
	if ( (op == 0b1) ) {
		return a64_opcode.bl;
	}
	return a64_opcode.invalid;
}

// ===============================
//  DECODE CONDITIONAL BRANCH IMM
// ===============================

decode_conditional_branch_imm :: proc(instr: u32) -> a64_opcode {
	o0 := slice(instr,  4, 1)
	o1 := slice(instr, 24, 1)
	if ( (o0 == 0b0) && (o1 == 0b0) ) {
		return a64_opcode.b_cond;
	}
	if ( (o0 == 0b0) && (o1 == 0b1) ) {
		return a64_opcode.bc_cond;
	}
	return a64_opcode.invalid;
}

// =================
//  DECODE BRANCHES
// =================

decode_branches :: proc(instr: u32) -> a64_opcode {
	op0: u32 = (instr >> 29) &    0x7
	op1: u32 = (instr >> 12) & 0x3fff
	// 010 00xxxxxxxxxxxx xxxxx Conditional branch (immediate)
	if ( (op0 == 0b010) && (op1 & 0b10000000000000) == 0b00000000000000) {
		return decode_conditional_branch_imm(instr)
	}
	// 010 01xxxxxxxxxxxx xxxxx Miscellaneous branch (immediate)
	// 011 00xxxxxxxx1xxx xxxxx Compare bytes/halfwords in registers and
	// branch
	// 01x 1xxxxxxxxxxxxx xxxxx UNALLOCATED
	// 110 00xxxxxxxxxxxx xxxxx Exception generation
	// 110 010000000x00xx xxxxx UNALLOCATED
	// 110 010000001000xx xxxxx UNALLOCATED
	// 110 01000000110000 xxxxx UNALLOCATED
	// 110 01000000110001 xxxxx System instructions with register argument
	// 110 01000000110010 11111 Hints
	// 110 01000000110010 != 11111 UNALLOCATED
	// 110 01000000110011 xxxxx Barriers
	// 110 01000001xx00xx xxxxx UNALLOCATED
	// 110 0100000xxx0100 xxxxx PSTATE
	// 110 0100000xxx0101 xxxxx UNALLOCATED
	// 110 0100000xxx011x xxxxx UNALLOCATED
	// 110 0100000xxx1xxx xxxxx UNALLOCATED
	// 110 0100100xxxxxxx xxxxx UNALLOCATED
	// 110 0100x01xxxxxxx xxxxx System instructions
	// 110 0100x1xxxxxxxx xxxxx System register move
	// 110 0101x00xxxxxxx xxxxx UNALLOCATED
	// 110 0101x01xxxxxxx xxxxx System pair instructions
	// 110 0101x1xxxxxxxx xxxxx System register pair move
	// 110 011xxxxxxxxxxx xxxxx UNALLOCATED
	// 110 1xxxxxxxxxxxxx xxxxx Unconditional branch (register)
	if ( (op0 == 0b110) && (op1 & 0b10000000000000) == 0b10000000000000) {
		return decode_unconditional_branch_reg(instr)
	}
	// 111 00xxxxxxxx1xxx xxxxx UNALLOCATED
	// 111 1xxxxxxxxxxxxx xxxxx UNALLOCATED
	// x00 xxxxxxxxxxxxxx xxxxx Unconditional branch (immediate)
	if ( (op0 & 0b011) == 0b000 ) {
		return decode_unconditional_branch_imm(instr);
	} 
	// x01 0xxxxxxxxxxxxx xxxxx Compare and branch (immediate)
	return a64_opcode.hint;
}

// ==================
//  OPCODE TO STRING
// ==================

opcode_to_string :: proc(op: a64_opcode) -> string {
    #partial switch op {
    	// condtional branch imm
    	case a64_opcode.b_cond           : return "b_cond"
    	case a64_opcode.bc_cond          : return "bc_cond"
    	case a64_opcode.hint 			 : return "hint"
    	case a64_opcode.b                : return "b"
    	case a64_opcode.bl               : return "bl"
    	// mov wide immu
    	case a64_opcode.mov_z_64		 : return "mov_z_64"
    	case a64_opcode.mov_z_32   		 : return "mov_z_32" 
    	case a64_opcode.mov_k_32 		 : return "mov_k_32" 
    	case a64_opcode.mov_n_32		 : return "mov_n_32"
		case a64_opcode.mov_k_64		 : return "mov_k_64"
		case a64_opcode.mov_n_64		 : return "mov_n_64"
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

		case a64_opcode.stp_64_pre_index : return "stp_64_pre_index"
		// unconditional branch (register)
	 	case a64_opcode.ret              : return "ret"
	 	// add/sub imm
	 	case a64_opcode.add_imm_32 	     : return "add_imm_32"					
		case a64_opcode.adds_imm_32		 : return "adds_imm_32"					
		case a64_opcode.sub_imm_32		 : return "sub_imm_32"				
		case a64_opcode.subs_imm_32		 : return "subs_imm_32"					
		case a64_opcode.add_imm_64		 : return "add_imm_64"				
		case a64_opcode.adds_imm_64		 : return "adds_imm_64"					
		case a64_opcode.sub_imm_64		 : return "sub_imm_64"				
		case a64_opcode.subs_imm_64		 : return "subs_imm_64"		

		// data proc one src
		case a64_opcode.rbit_32			 : return "rbit_32"
		case a64_opcode.rbit_64 		 : return "rbit_64" 
		case a64_opcode.rev16_32 		 : return "rev16_32" 
		case a64_opcode.rev16_64 		 : return "rev16_64" 
		case a64_opcode.clz_32			 : return "clz_32"
		case a64_opcode.clz_64 			 : return "clz_64" 
		case a64_opcode.cls_32 			 : return "cls_32" 
		case a64_opcode.cls_64 			 : return "cls_64" 
		case a64_opcode.rev32 			 : return "rev32" 
		case a64_opcode.rev_32 			 : return "rev_32" 
		case a64_opcode.rev_64			 : return "rev_64"

		// add/sub shift reg
		case a64_opcode.add_shift_reg_32	: return "add_shift_reg_32"
		case a64_opcode.adds_shift_reg_32	: return "adds_shift_reg_32"
		case a64_opcode.sub_shift_reg_32	: return "sub_shift_reg_32"
		case a64_opcode.subs_shift_reg_32	: return "subs_shift_reg_32"
		case a64_opcode.add_shift_reg_64	: return "add_shift_reg_64"
		case a64_opcode.adds_shift_reg_64	: return "adds_shift_reg_64"
		case a64_opcode.sub_shift_reg_64	: return "sub_shift_reg_64"
		case a64_opcode.subs_shift_reg_64	: return "subs_shift_reg_64"

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

@(test)
decode_STP_test :: proc(t: ^testing.T) {
	instr: u32 = 0xa9bf7bfd
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.stp_64_pre_index, msg)
}

@(test)
decode_BL_test :: proc(t: ^testing.T) {
	instr: u32 = 0x97fffff7
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.bl, msg)
}

@(test)
decode_BCOND_test :: proc(t: ^testing.T) {
	instr: u32 = 0x54000260
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.b_cond, msg)
}

@(test)
decode_MOV_Z_32_test :: proc(t: ^testing.T) {
	instr: u32 = 0x528003e1
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.mov_z_32, msg)
}

@(test)
decode_CLZ_32_test :: proc(t: ^testing.T) {
	instr: u32 = 0x5ac01000
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.clz_32, msg)
}

@(test)
decode_SUB_SHIFT_REG_32_test :: proc(t: ^testing.T) {
	instr: u32 = 0x4b000021
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.sub_shift_reg_32, msg)
}


