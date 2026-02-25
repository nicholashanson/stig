// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			          Data Processing (Modified Immediate)	    					 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.format;
import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

instr_32 parse_data_proc_mod_imm(const uint instr) {
	immutable imm_8  = slice(instr,  0, 8);
	immutable imm_3  = slice(instr, 12, 3);
	immutable i 	 = slice(instr, 26, 1);
	immutable imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	return instr_32(rd:  			cast(reg)slice(instr,  8, 4),
					rn:  			cast(reg)slice(instr, 16, 4),
					imm: 			thumb_expand_imm(imm_12),
					unexpanded_imm: imm_12);
}

instr_32 parse_data_proc_mod_imm_expand(const uint instr) {
	immutable imm_8  = slice(instr,  0, 8);
	immutable imm_3  = slice(instr, 12, 3);
	immutable i 	 = slice(instr, 26, 1);
	immutable imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	return instr_32(rd:  	   cast(reg )slice(instr,  8, 4),
					rn:  	   cast(reg )slice(instr, 16, 4),
					set_flags: cast(bool)slice(instr, 20, 1),
		            imm: 	   thumb_expand_imm(imm_12));
}

// ***************************************************************************************
// *									  ADD 											 *
// ***************************************************************************************

// ADD{S}<c>.W <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01000, [4] S, [3:0] Rn 
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_add_imm_t3(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

void 
execute_add_imm_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(R[n], imm32, ‘0’);
	immutable res = add_with_carry(rn, imm, false);
	// R[d] = result;
	// if setflags then
	if (instr.set_flags) {
		vm.set_n(res.result);	// APSR.N = result<31>;
		vm.set_z(res.result);	// APSR.Z = IsZeroBit(result);
		vm.set_c(res.carry);	// APSR.C = carry;
		vm.set_v(res.overflow); // APSR.V = overflow;
 	}
 	vm.set_reg(instr.rd, res.result);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  MOV 											 *
// ***************************************************************************************
// Move (immediate) writes an immediate value to the destination register. It can 
// optionally update the condition flags based on the value.

// ======================
//  Parse MOV(Immediate)
// ======================

// MOV{S}<c>.W <Rd>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [8:5] 00010, [4] S, [3:0] 1111
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_mov_imm_t2(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute MOV(Immediate)
// ========================

void 
execute_mov_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable imm        = instr.unexpanded_imm;
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	immutable expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c());
	if (instr.set_flags) {
		vm.set_n(expand_res.imm); 	// APSR.N = result<31>;
		vm.set_z(expand_res.imm); 	// APSR.Z = IsZeroBit(result);
		vm.set_c(expand_res.carry);	// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, expand_res.imm);
}

string convert_mov_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("mov%s.w %s, #%d", add_suffix(instr, cond), get_reg_name(instr.rd), instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ADC  											 *
// ***************************************************************************************
// Add with Carry (immediate) adds an immediate value and the carry flag value to a 
// register value, and writes the result to the destination register. It can optionally 
// update the condition flags based on the result.

// ======================
//  Parse ADC(Immediate)
// ======================

// ADC{S}<c> <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01010, [4] S, [3:0] 1111
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_adc_imm_t1(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

// ========================
//  Execute ADC(Immediate)
// ========================

void 
execute_adc_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable imm  = instr.imm;
	immutable rn   = vm.get_reg(instr.rn);
	immutable res  = add_with_carry(rn, imm, vm.get_c());
	if (instr.set_flags) {
		vm.set_z(res.result);
		vm.set_n(res.result);
		vm.set_c(res.carry);
        vm.set_v(res.overflow);
	}
	vm.set_reg(instr.rd, res.result);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  AND 											 *
// ***************************************************************************************
// AND (immediate) performs a bitwise AND of a register value and an immediate value, and 
// writes the result to the destination register.

// ======================
//  Parse AND(Immediate)
// ======================

// AND{S}<c> <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 00000, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_and_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute AND(Immediate)
// ========================

void 
execute_and_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rn  		  = vm.get_reg(instr.rn);
	immutable  imm        = instr.unexpanded_imm;
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c());
	const uint res 		  = rn & expand_res.imm;
	if (instr.set_flags) {
		vm.set_n(res);					// APSR.N = result<31>;
		vm.set_z(res);					// APSR.Z = IsZeroBit(result);
		vm.set_c(expand_res.carry);		// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

// AND{S}<c> <Rd>,<Rn>,#<const>
string convert_and_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("and%s.w %s, %s, #%d", add_suffix(instr, cond),
									     get_reg_name(instr.rd),
									     get_reg_name(instr.rn),
									     instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  EOR 											 *
// ***************************************************************************************
// Exclusive OR (immediate) performs a bitwise Exclusive OR of a register value and an 
// immediate value, and writes the result to the destination register. It can optionally 
// update the condition flags based on the result.

// ======================
//  Parse EOR(Immediate)
// ======================

// EOR{S}<c> <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 00100, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_eor_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute EOR(Immediate)
// ========================

void 
execute_eor_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable  imm 		  = instr.unexpanded_imm;
	immutable  rn  		  = vm.get_reg(instr.rn);
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)instr.imm, vm.get_c());
    const uint res 		  = rn ^ expand_res.imm;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
		vm.set_c(expand_res.carry);
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  MVN 											 *
// ***************************************************************************************
// Bitwise NOT (immediate) writes the bitwise inverse of an immediate value to the 
// destination register. It can optionally update the condition flags based on the value.

// ======================
//  Parse MVN(Immediate)
// ======================

// MVN{S}<c> <Rd>,#<const>
// First Half-Word: [15:5] 11101011010, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_mvn_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	immutable imm_8  = slice(instr,  0, 8);
	immutable imm_3  = slice(instr, 12, 3);
	immutable i 	 = slice(instr, 26, 1);
	immutable imm_12 = cast(ushort)((i << 11) | (imm_3 << 8) | imm_8);
	return instr_32(rd:  			cast(reg)slice(instr,  8, 4),
					imm: 			thumb_expand_imm(imm_12),
					unexpanded_imm: imm_12);
}

// ========================
//  Execute MVN(Immediate)
// ========================

void 
execute_mvn_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable  imm 		  = instr.unexpanded_imm;
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c()); 
	// result = NOT(imm32);
	const uint res 		  = ~expand_res.imm;
	if (instr.set_flags) {
		vm.set_z(res);					// APSR.Z = IsZeroBit(result);
		vm.set_n(res);					// APSR.N = result<31>;
		vm.set_c(expand_res.carry);		// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

// MVN{S}<c> <Rd>,#<const>
string convert_mvn_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("mvn%s.w %s, #%d", add_suffix(instr, cond), get_reg_name(instr.rd), instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ORN 											 *
// ***************************************************************************************
// Logical OR NOT (immediate) performs a bitwise (inclusive) OR of a register value and 
// the complement of an immediate value, and writes the result to the destination register. 
// It can optionally update the condition flags based on the result.

// ======================
//  Parse ORN(Immediate)
// ======================

// ORN{S}<c> <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 00011, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_orn_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute ORN(Immediate)
// ========================

void 
execute_orn_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rn  	      = vm.get_reg(instr.rn);
	immutable  imm 		  = instr.unexpanded_imm;
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c());
	// result = R[n] OR NOT(imm32);
	const uint res 		  = rn | (~expand_res.imm); 
	if (instr.set_flags) {
		vm.set_z(res);				// APSR.N = result<31>;
		vm.set_n(res);				// APSR.Z = IsZeroBit(result);
		vm.set_c(expand_res.carry); // APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      SBC                                            *
// ***************************************************************************************
// Subtract with Carry (immediate) subtracts an immediate value and the value of 
// NOT(Carry flag) from a register value, and writes the result to the destination 
// register. It can optionally update the condition flags based on the result.

// ======================
//  Parse SBC(Immediate)
// ======================

// SBC{S}<c> <Rd>,<Rn>,#<const>
instr_32 parse_sbc_imm_t1(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

// ========================
//  Execute SBC(Immediate)
// ========================

void 
execute_sbc_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm; 
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), APSR.C);
	immutable res = add_with_carry(rn, ~imm, vm.get_c());
	if (instr.set_flags) {
		vm.set_n(res.result);
		vm.set_z(res.result);
		vm.set_c(res.carry);
		vm.set_v(res.overflow);
	}
	vm.set_reg(instr.rd, res.result);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      ORR                                            *
// ***************************************************************************************
// Logical OR (immediate) performs a bitwise (inclusive) OR of a register value and an 
// immediate value, and writes the result to the destination register. It can optionally 
// update the condition flags based on the result.

// ======================
//  Parse ORR(Immediate)
// ======================

// ORR{S}<c> <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 00010, [4] S, [3:0] Rn 
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_orr_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute ORR(Immediate)
// ========================

void 
execute_orr_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rn         = vm.get_reg(instr.rn);
	immutable  imm 		  = instr.unexpanded_imm;
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c());
	// result = R[n] OR imm32;
	const uint res        = rn | instr.imm;
	if (instr.set_flags) {
		vm.set_n(res);				// APSR.N = result<31>;
		vm.set_z(res); 				// APSR.Z = IsZeroBit(result);
		vm.set_c(expand_res.carry); // APSR.C = carry;
		// // APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

// ORR{S}<c> <Rd>,<Rn>,#<const>
string convert_orr_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("orr%s.w %s, %s, #%d", add_suffix(instr, cond),
										 get_reg_name(instr.rd),
										 get_reg_name(instr.rn),
										 instr.imm);  
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  CMP 											 *
// ***************************************************************************************
// Compare (immediate) subtracts an immediate value from a register value. It updates the 
// condition flags based on the result, and discards the result.

// ======================
//  Parse CMP(immediate)
// ======================

// CMP<c>.W <Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:4] 011011, [3:0] Rn
// Second Half-Word: [15] 0, [14:2] imm3, [11:8] 1111, [7:0] imm8 
instr_32 parse_cmp_imm_t2(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

// ========================
//  Execute CMP(Immediate)
// ========================

void 
execute_cmp_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), ‘1’);
	immutable res = add_with_carry(rn, ~imm, true);
	vm.set_z(res.result);			// APSR.Z = IsZeroBit(result);
	vm.set_n(res.result);			// APSR.N = result<31>; 
	vm.set_c(res.carry);			// APSR.C = carry;
	vm.set_v(res.overflow);			// APSR.V = overflow;
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  CMN 											 *
// ***************************************************************************************
// Compare Negative (immediate) adds a register value and an immediate value. It updates 
// the condition flags based on the result, and discards the result.

// ======================
//  Parse CMN(Immediate)
// ======================

// CMN<c> <Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:4] 010001, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] 1111, [7:0] imm8 
instr_32 parse_cmn_imm_t1(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

// ========================
//  Execute CMN(Immediate)
// ========================

void 
execute_cmn_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(R[n], imm32, ‘0’);
	immutable res = add_with_carry(rn, imm, false);
	vm.set_n(res.result);	// APSR.N = result<31>;
	vm.set_z(res.result); 	// APSR.Z = IsZeroBit(result);
	vm.set_c(res.carry);	// APSR.C = carry;
	vm.set_v(res.overflow); // APSR.V = overflow;
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      BIC                                            *
// ***************************************************************************************
// Bit Clear (immediate) performs a bitwise AND of a register value and the complement of 
// an immediate value, and writes the result to the destination register. It can 
// optionally update the condition flags based on the result.

// ======================
//  Parse BIC(Immediate)
// ======================

// BIC{S}<c> <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 00001, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_bic_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute BIC(Immediate)
// ========================

void 
execute_bic_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rn  		  = vm.get_reg(instr.rn);
	immutable  imm 		  = instr.unexpanded_imm;
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c());
	// result = R[n] AND NOT(imm32);
	const uint res 		  = rn & ~instr.imm;
	if (instr.set_flags) {
		vm.set_n(res);				// APSR.N = result<31>;
		vm.set_z(res);				// APSR.Z = IsZeroBit(result);
		vm.set_c(expand_res.carry);	// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

string convert_bic_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("bic%s.w %s, %s, #%d", add_suffix(instr, cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rn),
									   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      RSB                                            *
// ***************************************************************************************
// Reverse Subtract (immediate) subtracts a register value from an immediate value, and 
// writes the result to the destination register. It can optionally update the condition 
// flags based on the result.

// ======================
//  Parse RSB(Immediate)
// ======================

// RSB{S}<c>.W <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01110, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_rsb_imm_t2(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

// ========================
//  Execute RSB(Immediate)
// ========================

void 
execute_rsb_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(NOT(R[n]), imm32, ‘1’);
	immutable res = add_with_carry(~rn, imm, true);
	if (instr.set_flags) {
		vm.set_n(res.result);		// APSR.N = result<31>;
		vm.set_z(res.result);		// APSR.Z = IsZeroBit(result);
		vm.set_c(res.carry);		// APSR.C = carry;
		vm.set_v(res.overflow);		// APSR.V = overflow;
	}
	vm.set_reg(instr.rd, res.result);
}

string convert_rsb_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("rsb%s %s, %s, #%d", add_suffix(instr, cond), get_reg_name(instr.rd),
									   get_reg_name(instr.rn), instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      TST                                            *
// ***************************************************************************************
// Test (immediate) performs a logical AND operation on a register value and an immediate 
// value. It updates the condition flags based on the result, and discards the result.

// ======================
//  Parse TST(Immediate)
// ======================

// TST<c> <Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:4] 000001, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] 1111, [7:0] imm8 
instr_32 parse_tst_imm_t1(const uint instr) {
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	return parse_data_proc_mod_imm(instr);
}

// ========================
//  Execute TST(Immediate)
// ========================

void 
execute_tst_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rn  		  = vm.get_reg(instr.rn);
	immutable  imm 		  = instr.unexpanded_imm;
	// (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
	immutable  expand_res = thumb_expand_imm_c(cast(ushort)imm, vm.get_c());
	// result = R[n] AND imm32;
	const uint res 		  = rn & expand_res.imm; 
	vm.set_n(res); 					// APSR.N = result<31>;
	vm.set_z(res);					// APSR.Z = IsZeroBit(result);
	vm.set_c(expand_res.carry);		// APSR.C = carry;
	// APSR.V unchanged
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      SUB                                            *
// ***************************************************************************************
// Subtract (immediate) subtracts an immediate value from a register value, and writes 
// the result to the destination register. It can optionally update the condition flags 
// based on the result.

// ======================
//  Parse SUB(Immediate)
// ======================

// SUB{S}<c>.W <Rd>,<Rn>,#<const>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01101, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_sub_imm_t3(const uint instr) {
	// imm32 = ThumbExpandImm(i:imm3:imm8);
	return parse_data_proc_mod_imm_expand(instr);
}

// ========================
//  Execute SUB(Immediate)
// ========================

void 
execute_sub_imm_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	immutable res = add_with_carry(rn, ~imm, true);
	if (instr.set_flags) {
		vm.set_n(res.result);	      // APSR.N = result<31>;
		vm.set_z(res.result);		  // APSR.Z = IsZeroBit(result);
		vm.set_c(res.carry);  	      // APSR.C = carry;
		vm.set_v(res.overflow);		  // APSR.V = overflow;
	}
	vm.set_reg(instr.rd, res.result);
}

// SUB{S}<c>.W <Rd>,<Rn>,#<const>
string convert_sub_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
	return format("sub%s.w %s, %s, #%d", add_suffix(instr, cond), 
										 get_reg_name(instr.rd), 
										 get_reg_name(instr.rn), 
										 instr.imm);
}
// ---------------------------------------------------------------------------------------
