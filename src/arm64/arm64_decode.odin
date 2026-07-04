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
	ubfm_32, sbfm_32, bfm_32, sbfm_64, bfm_64, ubfm_64,
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
	ldr_reg_32,		  			 ldr_reg_simd_fp,				strb_reg_ext_reg, 				strb_reg_shift_reg,
	ldr_reg_ext_reg,  			 ldrb_reg_shift_reg, 			ldrsb_reg_64_ext_reg_offset, 	ldrsb_reg_64_shift_reg_offset,
	ldrsb_reg_32_ext_reg_offset, ldrsb_reg_32_shift_reg_offset, str_reg_simd_fp,  				ldrh_reg, 					 
	ldrsh_reg_64, 				 ldrsh_reg_32,                  str_reg_32, 				    ldrsw_reg,		  		     
	ldr_reg_64,                  prfm,
	// load/store register (unsigned immediate)
	ldr_imm_32,
	// add shift reg
	add_shift_reg_32,  adds_shift_reg_32, sub_shift_reg_32, subs_shift_reg_32, add_shift_reg_64,
	adds_shift_reg_64, sub_shift_reg_64,  subs_shift_reg_64,

	stp_32_pre_index, stp_64_pre_index, stp_64_post_index, stp_64_offset,

	udiv_32, sdiv_32, lslv_32, lsrv_32, asrv_32, rorv_32, udiv_64, sdiv_64, lslv_64, lsrv_64, asrv_64,
	rorv_64, subps,

	// load/store register pair offset
	stp_32, ldp_32, stp_simd_fp, ldp_simd_fp, stgp, ldpsw, stp_64, ldp_64, stp_simd_fp_128, ldp_simd_fp_128,

	// load/store unprivileged
	sttrb,  ldtrb,   ldtrsb_64, ldtrsb_32, sttrh, ldtrh, ldtrsh_64, ldtrsh_32, sttr_32, ldtr_32,
	ldtrsw, sttr_64, ldtr_64,

	adr, adrp,

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
	sf  	 := slice(instr, 31, 1)
	opc 	 := slice(instr, 29, 2)
	N   	 := slice(instr, 22, 1)
	combined := (sf << 3) | (opc << 1) | N
	switch (combined) {
		case 0b0000:
			// 0 00 0 SBFM — 32-bit
			return a64_opcode.sbfm_32
		case 0b0010:	
			// 0 01 0 BFM — 32-bit
			return a64_opcode.bfm_32
		case 0b0100:
			// 0 10 0 UBFM — 32-bit
			return a64_opcode.ubfm_32
		// 0 11 0 UNALLOCATED
		// 1 xx 0 UNALLOCATED
		case 0b1001:
			// 1 00 1 SBFM — 64-bit
			return a64_opcode.sbfm_64
			// 1 01 1 BFM — 64-bit
		case 0b1011:
			return a64_opcode.bfm_64
		case 0b1101:
			// 1 10 1 UBFM — 64-bit
			return a64_opcode.ubfm_64
	}
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------
// ==============================
//  DECODE LOAD STORE REG OFFSET
// ==============================

decode_ld_st_reg_reg_offset :: proc(instr: u32) -> a64_opcode {
	size     := slice(instr, 30, 2) 
	VR       := slice(instr, 26, 1)
	opc      := slice(instr, 22, 2)
	option   := slice(instr, 13, 3)
	combined := (size << 3) | (VR << 2) | opc
	switch (combined) {
		case 0b00000:
			if option != 0b011 {
			// 00 0 00 != 011 STRB (register) — extended register
				return a64_opcode.strb_reg_ext_reg
			} else {
			// 00 0 00 011 STRB (register) — shifted register
				return a64_opcode.strb_reg_shift_reg
			}
		case 0b00001:	
			// 00 0 01 != 011 LDRB (register) — extended register
			if option != 0b011 {
				return a64_opcode.ldr_reg_ext_reg
			} else {
			// 00 0 01 011 LDRB (register) — shifted register
				return a64_opcode.ldrb_reg_shift_reg
			}
		case 0b00010:
			// 00 0 10 != 011 LDRSB (register) — 64-bit with extended register offset
			if option != 0b011 {
				return a64_opcode.ldrsb_reg_64_ext_reg_offset
			} else {
			// 00 0 10 011 LDRSB (register) — 64-bit with shifted register offset
				return a64_opcode.ldrsb_reg_64_shift_reg_offset
			}
		case 0b00011:
			// 00 0 11 != 011 LDRSB (register) — 32-bit with extended register offset
			if option != 011 {
				return a64_opcode.ldrsb_reg_32_ext_reg_offset
			} else {
			// 00 0 11 011 LDRSB (register) — 32-bit with shifted register offset
				return a64_opcode.ldrsb_reg_32_shift_reg_offset
			}
		case 0b00100:
			// 00 1 00 != 011 STR (register, SIMD&FP)
			if option != 0b011 {
				return a64_opcode.str_reg_simd_fp
			} else {
			// 00 1 00 011 STR (register, SIMD&FP)
				return a64_opcode.str_reg_simd_fp
			}
		case 0b00101:
			// 00 1 01 != 011 LDR (register, SIMD&FP)
			if option != 0b011 {
				return a64_opcode.ldr_reg_simd_fp
			} else {
			// 00 1 01 011 LDR (register, SIMD&FP)
				return a64_opcode.ldr_reg_simd_fp
			}
			// 00 1 10 STR (register, SIMD&FP)
		case 0b00110:
			return a64_opcode.str_reg_simd_fp
			// 00 1 11 LDR (register, SIMD&FP)
		case 0b00111:
			return a64_opcode.ldr_reg_simd_fp
			// 01 0 00 STRH (register)
		case 0b01001:
			// 01 0 01 LDRH (register)
			return a64_opcode.ldrh_reg
			// 01 0 10 LDRSH (register) — 64-bit
		case 0b01010:
			return a64_opcode.ldrsh_reg_64
			// 01 0 11 LDRSH (register) — 32-bit
		case 0b01011:
			return a64_opcode.ldrsh_reg_32
			// 01 1 00 STR (register, SIMD&FP)
		case 0b01100:
			return a64_opcode.str_reg_simd_fp
			// 01 1 01 LDR (register, SIMD&FP)
		case 0b01101:
			return a64_opcode.ldr_reg_simd_fp
	// 1x 0 11 UNALLOCATED
	// 1x 1 1x UNALLOCATED
			// 10 0 00 STR (register) — 32-bit
		case 0b10000:
			return a64_opcode.str_reg_32
			// 10 0 01 LDR (register) — 32-bit
		case 0b10001:
			return a64_opcode.ldr_reg_32
			// 10 0 10 LDRSW (register)
		case 0b10010:
			return a64_opcode.ldrsw_reg
			// 10 1 00 STR (register, SIMD&FP)
		case 0b10100:
			return a64_opcode.str_reg_simd_fp
		// 10 1 01 LDR (register, SIMD&FP)
		case 0b10101:
			return a64_opcode.ldr_reg_simd_fp
		// 11 0 00 STR (register) — 64-bit
		case 0b11000:
			return a64_opcode.str_reg_32
		// 11 0 01 LDR (register) — 64-bit
		case 0b11001:
			return a64_opcode.ldr_reg_64
		// 11 0 10 PRFM (register)
		case 0b11010:
			return a64_opcode.prfm
		// 11 1 00 STR (register, SIMD&FP)	
		case 0b11100:
			return a64_opcode.str_reg_simd_fp
		// 11 1 01 LDR (register, SIMD&FP)
		case 0b11101:
			return a64_opcode.ldr_reg_simd_fp
	}
	return a64_opcode.invalid
}

decode_cmp_and_swap_pair :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_adv_simd_ld_st_mult_structs :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_adv_simd_ld_st_mult_structs_post_indexed :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_adv_simd_ld_st_single_struct :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_adv_simd_ld_st_single_struct_post_indexed :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_mem_tags :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_excl_pair :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_excl_reg :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_ordered :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_cmp_and_swap :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ldapr_strl_unscaled_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_reg_lit :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_mem_cpy_set :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_no_alloc_pair :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_reg_pair_post_indexed :: proc(instr: u32) -> a64_opcode {
	opc 	 := slice(instr, 30, 2)
	V   	 := slice(instr, 26, 1)
	L   	 := slice(instr, 22, 1)
	combined := (opc << 2) | (V << 1) | L
	switch (combined) {
		// 00 0 0 STP — 32-bit -
		case 0b0000: return a64_opcode.stp_32
		// 00 0 1 LDP — 32-bit -
		case 0b0001: return a64_opcode.ldp_32
		// 00 1 0 STP (SIMD&FP) — 32-bit -
		case 0b0010: return a64_opcode.stp_simd_fp
		// 00 1 1 LDP (SIMD&FP) — 32-bit -
		case 0b0011: return a64_opcode.ldp_simd_fp
		// 01 0 0 STGP FEAT_MTE
		case 0b0100: return a64_opcode.stgp
		// 01 0 1 LDPSW -
		case 0b0101: return a64_opcode.ldpsw
		// 01 1 0 STP (SIMD&FP) — 64-bit -
		case 0b0110: return a64_opcode.stp_simd_fp
		// 01 1 1 LDP (SIMD&FP) — 64-bit -
		case 0b0111: return a64_opcode.ldp_simd_fp
		// 10 0 0 STP — 64-bit -
		case 0b1000: return a64_opcode.stp_64
		// 10 0 1 LDP — 64-bit -
		case 0b1001: return a64_opcode.ldp_64
		// 10 1 0 STP (SIMD&FP) — 128-bit -
		case 0b1010: return a64_opcode.stp_simd_fp_128
		// 10 1 1 LDP (SIMD&FP) — 128-bit -
		case 0b1011: return a64_opcode.ldp_simd_fp_128
		// 11 UNALLOCATED
	} 
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------
// ===================================
//  DECODE LOAD STORE REG PAIR OFFSET
// ===================================

decode_ld_st_reg_pair_offset :: proc(instr: u32) -> a64_opcode {
	opc 	 := slice(instr, 30, 2)
	V   	 := slice(instr, 26, 1)
	L   	 := slice(instr, 22, 1)
	combined := (opc << 2) | (V << 1) | L
	switch (combined) {
		// 00 0 0 STP — 32-bit -
		case 0b0000: return a64_opcode.stp_32
		// 00 0 1 LDP — 32-bit -
		case 0b0001: return a64_opcode.ldp_32
		// 00 1 0 STP (SIMD&FP) — 32-bit -
		case 0b0010: return a64_opcode.stp_simd_fp
		// 00 1 1 LDP (SIMD&FP) — 32-bit -
		case 0b0011: return a64_opcode.ldp_simd_fp
		// 01 0 0 STGP FEAT_MTE
		case 0b0100: return a64_opcode.stgp
		// 01 0 1 LDPSW -
		case 0b0101: return a64_opcode.ldpsw
		// 01 1 0 STP (SIMD&FP) — 64-bit -
		case 0b0110: return a64_opcode.stp_simd_fp
		// 01 1 1 LDP (SIMD&FP) — 64-bit -
		case 0b0111: return a64_opcode.ldp_simd_fp
		// 10 0 0 STP — 64-bit -
		case 0b1000: return a64_opcode.stp_64
		// 10 0 1 LDP — 64-bit -
		case 0b1001: return a64_opcode.ldp_64
		// 10 1 0 STP (SIMD&FP) — 128-bit -
		case 0b1010: return a64_opcode.stp_simd_fp_128
		// 10 1 1 LDP (SIMD&FP) — 128-bit -
		case 0b1011: return a64_opcode.ldp_simd_fp_128
		// 11 UNALLOCATED
	} 
	return a64_opcode.invalid
}
decode_ld_st_reg_pair_pre_indexed :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.stp_64_pre_index
}
decode_ld_st_unscaled_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_reg_imm_post_indexed :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}

// ---------------------------------------------------------------------------------------
// ==============================
//  DECODE LOAD STORE REG UNPRIV
// ==============================

decode_ld_st_reg_unpriv :: proc(instr: u32) -> a64_opcode {
	size     := slice(instr, 31, 2)
	V        := slice(instr, 26, 1)
	opc      := slice(instr, 22, 2)
	combined := (size << 3) | (V << 2) | opc
	// 1 UNALLOCATED
	switch (combined) {
		// 00 0 00 STTRB
		case 0b00000: return a64_opcode.sttrb
		// 00 0 01 LDTRB
		case 0b00001: return a64_opcode.ldtrb
		// 00 0 10 LDTRSB — 64-bit
		case 0b00010: return a64_opcode.ldtrsb_64
		// 00 0 11 LDTRSB — 32-bit
		case 0b00011: return a64_opcode.ldtrsb_32
		// 01 0 00 STTRH
		case 0b01000: return a64_opcode.sttrh
		// 01 0 01 LDTRH
		case 0b01001: return a64_opcode.ldtrh
		// 01 0 10 LDTRSH — 64-bit
		case 0b01010: return a64_opcode.ldtrsh_64
		// 01 0 11 LDTRSH — 32-bit
		case 0b01011: return a64_opcode.ldtrsh_32
		// 1x 0 11 UNALLOCATED
		// 10 0 00 STTR — 32-bit
		case 0b10000: return a64_opcode.sttr_32
		// 10 0 01 LDTR — 32-bit
		case 0b10001: return a64_opcode.ldtr_32
		// 10 0 10 LDTRSW
		case 0b10010: return a64_opcode.ldtrsw
		// 11 0 00 STTR — 64-bit
		case 0b11000: return a64_opcode.sttr_64
		// 11 0 01 LDTR — 64-bit
		case 0b11001: return a64_opcode.ldtr_64
		// 11 0 10 UNALLOCATED
	}
	return a64_opcode.invalid
}
// ---------------------------------------------------------------------------------------

decode_ld_st_reg_imm_pre_indexed :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_atomic_mem_ops :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
}
decode_ld_st_reg_pac :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.invalid
} 
decode_ld_st_unsigned_imm :: proc(instr: u32) -> a64_opcode {
	return a64_opcode.ldr_imm_32
}

// ---------------------------------------------------------------------------------------
// ========================
//  DECODE LOAD AND STORES
// ========================

decode_load_and_stores :: proc(instr: u32) -> a64_opcode {
	op0 := slice(instr, 28, 4)
	op1 := slice(instr, 26, 1)
	op2 := slice(instr, 23, 2)
	op3 := slice(instr, 16, 6)
	op4 := slice(instr, 10, 2)
	// 0x00 0 00 1xxxxx Compare and swap pair
	if ( ( (op0 & 0b1011) == 0b0000 ) && (op1 == 0b0) && (op2 == 0b00) && ( (op3 & 0b100000) == 0b100000 ) ) {
		return decode_cmp_and_swap_pair(instr)
	}
	// 0x00 1 00 000000 Advanced SIMD load/store multiple structures
	if ( ( (op0 & 0b1011) == 0b0000 ) && (op1 == 0b1) && (op2 == 0b00) && (op3 == 0b000000) ) {
		return decode_adv_simd_ld_st_mult_structs(instr)
	}
	// 0x00 1 01 0xxxxx Advanced SIMD load/store multiple structures (post-indexed)
	if ( ( (op0 & 0b1011) == 0b0000 ) && (op1 == 0b1) && (op2 == 0b01) && ( (op3 & 0b100000) == 0b000000 ) ) {
		return decode_adv_simd_ld_st_mult_structs_post_indexed(instr)
	}
	// 0x00 1 0x 1xxxxx UNALLOCATED
	// 0x00 1 10 x00000 Advanced SIMD load/store single structure
	if ( ( (op0 & 0b1011) == 0b0000 ) && (op1 == 0b1) && (op2 == 0b10) && ( (op3 & 0b100000) == 0b000000 ) ) {
		return decode_adv_simd_ld_st_single_struct(instr)
	}
	// 0x00 1 11 Advanced SIMD load/store single structure (post-indexed)
	if ( ( (op0 & 0b1011) == 0b0000 ) && (op1 == 0b1) && (op2 == 0b11) ) {
		return decode_adv_simd_ld_st_single_struct_post_indexed(instr)
	}
	// 0x00 1 x0 x1xxxx UNALLOCATED
	// 0x00 1 x0 xx1xxx UNALLOCATED
	// 0x00 1 x0 xxx1xx UNALLOCATED
	// 0x00 1 x0 xxxx1x UNALLOCATED
	// 0x00 1 x0 xxxxx1 UNALLOCATED
	// 1101 0 1x 1xxxxx Load/store memory tags
	if ( ( (op0 == 0b1101) ) && (op1 == 0b0) && ( (op2 & 0b10) == 0b10 ) && ( (op3 & 0b100000) == 0b100000 ) ) {
		return decode_ld_st_mem_tags(instr)
	}
	// 1x00 0 00 1xxxxx Load/store exclusive pair
	if ( ( (op0 & 0b1011) == 0b1000 ) && (op1 == 0b0) && (op2 == 0b00) && ( (op3 & 0b100000) == 0b1000000 ) ) {
		return decode_ld_st_excl_pair(instr)
	}
	// 1x00 1 UNALLOCATED
	// xx00 0 00 0xxxxx Load/store exclusive register
	if ( ( (op0 & 0b0011) == 0b0000 ) && (op1 == 0b0) && (op2 == 0b00) && ( (op3 & 0b100000) == 0b0000000 ) ) {
		return decode_ld_st_excl_reg(instr)
	}
	// xx00 0 01 0xxxxx Load/store ordered
	if ( ( (op0 & 0b0011) == 0b0000 ) && (op1 == 0b0) && (op2 == 0b01) && ( (op3 & 0b100000) == 0b0000000 ) ) {
		return decode_ld_st_ordered(instr)
	}
	// xx00 0 01 1xxxxx Compare and swap
	if ( ( (op0 & 0b0011) == 0b0000 ) && (op1 == 0b0) && (op2 == 0b01) && ( (op3 & 0b100000) == 0b1000000 ) ) {
		return decode_cmp_and_swap(instr)
	}
	// xx01 0 1x 0xxxxx 00 LDAPR/STLR (unscaled immediate)
	if ( ( (op0 & 0b0011) == 0b0001 ) && (op1 == 0b0) && ( (op2 & 0b10) == 0b10 ) && ( (op3 & 0b100000) == 0b0000000 ) && (op4 == 0b00) ) {
		return decode_ldapr_strl_unscaled_imm(instr)
	}
	// xx01 0x Load register (literal)
	if ( ( (op0 & 0b0011) == 0b0001 ) && ( (op1 & 0b10) == 0b00 ) ) {
		return decode_ld_reg_lit(instr)
	}
	// xx01 1x 0xxxxx 01 Memory Copy and Memory Set
	if ( ( (op0 & 0b0011) == 0b0001 ) && ( (op2 & 0b10) == 0b10 ) && ( (op3 & 0b100000) == 0b0000000 ) && (op4 == 0b01) ) {
		return decode_mem_cpy_set(instr)
	}
	// xx10 00 Load/store no-allocate pair (offset)
	if ( ( (op0 & 0b0011) == 0b0010 ) && (op2 == 0b00) ) {
		return decode_ld_st_no_alloc_pair(instr)
	}
	// xx10 01 Load/store register pair (post-indexed)
	if ( ( (op0 & 0b0011) == 0b0010 ) && (op2 == 0b01) ) {
		return decode_ld_st_reg_pair_post_indexed(instr)
	}
	// xx10 10 Load/store register pair (offset)
	if ( ( (op0 & 0b0011) == 0b0010 ) && (op2 == 0b10) ) {
		return decode_ld_st_reg_pair_offset(instr)
	}
	// xx10 11 Load/store register pair (pre-indexed)
	if ( ( (op0 & 0b0011) == 0b0010 ) && (op2 == 0b11) ) {
		return decode_ld_st_reg_pair_pre_indexed(instr)
	}
	// xx11 0x 0xxxxx 00 Load/store register (unscaled immediate)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 ) && ( (op3 & 0b100000) == 0b100000 ) && (op4 == 0b00) ) {
		return decode_ld_st_unscaled_imm(instr)
	}
	// xx11 0x 0xxxxx 01 Load/store register (immediate post-indexed)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 )  && ( (op3 & 0b100000) == 0b000000 ) && (op4 == 0b01) ) {
		return decode_ld_st_reg_imm_post_indexed(instr)
	}
	// xx11 0x 0xxxxx 10 Load/store register (unprivileged)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 )  && ( (op3 & 0b100000) == 0b000000 ) && (op4 == 0b10) ) {
		return decode_ld_st_reg_unpriv(instr)
	}
	// xx11 0x 0xxxxx 11 Load/store register (immediate pre-indexed)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 )  && ( (op3 & 0b100000) == 0b000000 ) && (op4 == 0b11) ) {
		return decode_ld_st_reg_imm_pre_indexed(instr)
	}
	// xx11 0x 1xxxxx 00 Atomic memory operations
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 )  && ( (op3 & 0b100000) == 0b100000 ) && (op4 == 0b00) ) {
		return decode_atomic_mem_ops(instr)
	}
	// xx11 0x 1xxxxx 10 Load/store register (register offset)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 )  && ( (op3 & 0b100000) == 0b100000 ) && (op4 == 0b10) ) {
		return decode_ld_st_reg_reg_offset(instr)
	}
	// xx11 0x 1xxxxx x1 Load/store register (pac)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b00 )  && ( (op3 & 0b100000) == 0b100000 ) &&  ( (op4 & 0b01) == 0b01 ) ) {
		return decode_ld_st_reg_pac(instr)
	}
	// xx11 1x Load/store register (unsigned immediate)
	if ( ( (op0 & 0b0011) == 0b0011 ) && ( (op2 & 0b10) == 0b10 ) ) {
		return decode_ld_st_unsigned_imm(instr)
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

decode_data_proc_2_src :: proc(instr: u32) -> a64_opcode {
	sf       := slice(instr, 31, 1)
	S        := slice(instr, 29, 1)
	opcode   := slice(instr, 10, 6)
	combined := (sf << 7) | (S << 6) | opcode;
	switch (combined) {
	// 1 01xxxx UNALLOCATED -
	// 0 000000 UNALLOCATED -
		case 0b00000010:
			// 0 0 000010 UDIV — 32-bit -
			return a64_opcode.udiv_32
		case 0b00000011:
			// 0 0 000011 SDIV — 32-bit -
			return a64_opcode.sdiv_32
	// 0 0 00010x UNALLOCATED -
		case 0b00001000:
			// 0 0 001000 LSLV — 32-bit -
			return a64_opcode.lslv_32
		case 0b00001001:
			// 0 0 001001 LSRV — 32-bit -
			return a64_opcode.lsrv_32
		case 0b00001010:
			// 0 0 001010 ASRV — 32-bit -
			return a64_opcode.asrv_32
		case 0b00001011:
			// 0 0 001011 RORV — 32-bit -
			return a64_opcode.rorv_32
	// 0 0 001100 UNALLOCATED -
	// 0 0 010x11 UNALLOCATED -
	// 0 0 010000 CRC32B, CRC32H, CRC32W, CRC32X — CRC32B -
	// 0 0 010001 CRC32B, CRC32H, CRC32W, CRC32X — CRC32H -
	// 0 0 010010 CRC32B, CRC32H, CRC32W, CRC32X — CRC32W -
	// 0 0 010100 CRC32CB, CRC32CH, CRC32CW, CRC32CX — CRC32CB -
	// 0 0 010101 CRC32CB, CRC32CH, CRC32CW, CRC32CX — CRC32CH -
	// 0 0 010110 CRC32CB, CRC32CH, CRC32CW, CRC32CX — CRC32CW -
	// 1 0 000000 SUBP FEAT_MTE
		case 0b10000010:
			// 1 0 000010 UDIV — 64-bit -
			return a64_opcode.udiv_64
		case 0b10000011:	
			// 1 0 000011 SDIV — 64-bit -
			return a64_opcode.sdiv_64
	// 1 0 000100 IRG FEAT_MTE
	// 1 0 000101 GMI FEAT_MTE
		case 0b10001000:
			// 1 0 001000 LSLV — 64-bit -
			return a64_opcode.lslv_64
		case 0b10001001:
			// 1 0 001001 LSRV — 64-bit -
			return a64_opcode.lsrv_64
		case 0b10001010:
			// 1 0 001010 ASRV — 64-bit -
			return a64_opcode.asrv_64
		case 0b10001011:
			// 1 0 001011 RORV — 64-bit -
			return a64_opcode.rorv_64
	// 1 0 001100 PACGA FEAT_PAuth
	// 1 0 010xx0 UNALLOCATED -
	// 1 0 010x0x UNALLOCATED -
	// 1 0 010011 CRC32B, CRC32H, CRC32W, CRC32X — CRC32X -
	// 1 0 010111 CRC32CB, CRC32CH, CRC32CW, CRC32CX — CRC32CX -
		case 0b11000000:
			// 1 1 000000 SUBPS 
			return a64_opcode.subps
	}
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
		return decode_data_proc_2_src(instr)
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
	op := slice(instr, 31, 1)
	if (op == 0) { 
		return a64_opcode.adr 
	} 
	else { 
		return a64_opcode.adrp
	}
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
		case a64_opcode.sbfm_32			 : return "sbfm_32"
		case a64_opcode.bfm_32			 : return "bfm_32"
		case a64_opcode.sbfm_64			 : return "sbfm_64"
		case a64_opcode.bfm_64			 : return "bfm_64"
		case a64_opcode.ubfm_64			 : return "ubfm_64"			

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

		// load/store unprivileged
		case a64_opcode.sttrb			: return "sttrb"
		case a64_opcode.ldtrb 			: return "ldtrb"
		case a64_opcode.ldtrsb_64       : return "ldtrsb_64"
		case a64_opcode.ldtrsb_32       : return "ldtrsb_32"
		case a64_opcode.sttrh           : return "sttrh"
		case a64_opcode.ldtrh           : return "ldtrh"
		case a64_opcode.ldtrsh_64  		: return "ldtrsh_64"
		case a64_opcode.ldtrsh_32 		: return "ldtrsh_32"
		case a64_opcode.sttr_32    		: return "sttr_32"
		case a64_opcode.ldtr_32 		: return "ldtr_32"
		case a64_opcode.ldtrsw 			: return "ldtrsw"
		case a64_opcode.sttr_64 		: return "sttr_64"
		case a64_opcode.ldtr_64  		: return "ldtr_64"

		// load/store register pair offset
		case a64_opcode.stp_32			  : return "stp_32"
		case a64_opcode.ldp_32 			  : return "ldp_32"
		case a64_opcode.stp_simd_fp       : return "stp_simd_fp"
		case a64_opcode.ldp_simd_fp       : return "ldp_simd_fp"
		case a64_opcode.stgp           	  : return "stgp"
		case a64_opcode.ldpsw             : return "ldpsw"
		case a64_opcode.stp_64    		  : return "stp_64"
		case a64_opcode.ldp_64 			  : return "ldp_64"
		case a64_opcode.stp_simd_fp_128   : return "stp_simd_fp_128"
		case a64_opcode.ldp_simd_fp_128   : return "ldp_simd_fp_128"

		// load/store register (unsigned immediate)
		case a64_opcode.ldr_imm_32          : return "ldr_imm_32" 

		case a64_opcode.adr 		: return "adr"
		case a64_opcode.adrp  		: return "adrp"

		case a64_opcode.invalid			 : return "invalid"
    }
    return ""
}

@(test)
decode_LDR_REG_32_test :: proc(t: ^testing.T) {
	instr: u32 = 0xb8616800
	op: a64_opcode = get_opcode(instr)
	msg: string = fmt.aprint("Decoded opcode:", opcode_to_string(op))
	assert(op == a64_opcode.ldr_reg_32, msg)
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


