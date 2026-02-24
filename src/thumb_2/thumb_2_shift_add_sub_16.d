// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			   Shift(Immediate), Add, Subtract, Move and Compare	    	         *    
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
import memory_sections;

void 
execute_shift_instr
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	immutable res = shift_c(rm, instr.shift_t, instr.imm, vm.get_c());
	if (!vm.in_it_block()) {
		vm.set_c(res.carry);
		vm.set_n(res.result);
		vm.set_z(res.result);
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res.result);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									SUB SP											 *
// ***************************************************************************************

// ===============================
//  Parse SUB(SP Minus Immediate)
// ===============================

// SUB SP,SP,#<imm7>
// [15:7] 101100001, [6:0] imm7  
instr_16 parse_sub_sp_t1(short instr) {
	// imm32 = ZeroExtend(imm7:’00’, 32);
	return instr_16(imm: slice(instr, 0, 7) << 2); 
	// setflags = FALSE;
}

// ===============================
//  Parse SUB(SP Minus Immediate)
// ===============================

void 
execute_sub_sp_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	uint res = vm.get_sp();
	res -= instr.imm;
	vm.set_reg(reg.sp, res);
}

// SUB<c> SP,SP,#<imm7>
string convert_sub_sp_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("sub%s sp, #%d", get_condition_string(cond), 
								   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  CMP 											 *
// ***************************************************************************************

// ======================
//  Parse CMP(Immediate)
// ======================

// CMP<c> <Rn>,#<imm8>
// [15:11] 00101, [10:8] Rn, [7:0] imm8  
instr_16 parse_cmp_imm_t1(const ushort instr) {
	return instr_16(imm: slice(instr, 0, 8), // imm32 = ZeroExtend(imm8, 32); 
					rn:  cast(reg)slice(instr, 8, 3)); 
}

// ========================
//  Execute CMP(Immediate)
// ========================

void 
execute_cmp_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), ‘1’);
	immutable res = add_with_carry(rn, ~imm, true);
	vm.set_z(res.result);
	vm.set_n(res.result);
	vm.set_c(res.carry);
	vm.set_v(res.overflow);
}

// ==================================
//  Execute CMP(Immediate) to String
// ==================================

string convert_cmp_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("cmp%s %s, #%d", get_condition_string(cond),
								   get_reg_name(instr.rn),
								   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *								      SUB 											 *
// ***************************************************************************************

// =====================
//  Parse SUB(Register)
// =====================

// SUBS <Rd>,<Rn>,<Rm>
// SUB<c> <Rd>,<Rn>,<Rm>
// [15:9] 0001101, [8:6] Rm, [5:3] Rn, [2:0] Rd  
instr_16 parse_sub_reg_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rn: cast(reg)slice(instr, 3, 3),
					rm: cast(reg)slice(instr, 6, 3));
}

// =======================
//  Execute SUB(Register)
// =======================

void 
execute_sub_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	immutable rn  = vm.get_reg(instr.rn);
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), ‘1’);
	immutable res = add_with_carry(rn, ~rm, true);
	if (!vm.in_it_block()) {
		vm.set_z(res.result);
		vm.set_n(res.result);
		vm.set_c(res.carry);
		vm.set_v(res.overflow);
	}
	vm.set_reg(instr.rd, res.result);
}

// SUBS <Rd>,<Rn>,<Rm>
// SUB<c> <Rd>,<Rn>,<Rm>
string convert_sub_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("sub%s %s, %s, %s", get_it_block_string(cond),
									  get_reg_name(instr.rd),
									  get_reg_name(instr.rn),
									  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ADD 											 *
// ***************************************************************************************

// ======================
//  Parse ADD(Immediate)
// ======================

// ADDS <Rd>,<Rn>,#<imm3>
// ADD<c> <Rd>,<Rn>,#<imm3>
// [15:9] 0001110, [8:6] imm3, [5:3] Rn, [2:0] Rd
instr_16 parse_add_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 0, 3),
					rn:  cast(reg)slice(instr, 3, 3),
					imm: slice(instr, 6, 3));
}

// ======================
//  Parse ADD(Immediate)
// ======================

// ADDS <Rdn>,#<imm8>
// ADD<c> <Rdn>,#<imm8>
// [15:11] 00110, [10:8] Rdn, [7:0] imm8
instr_16 parse_add_imm_t2(const ushort instr) {
	immutable rdn = cast(reg)slice(instr, 8, 3);
	return instr_16(rn:  rdn, 
					rd:  rdn, 
					imm: slice(instr, 0, 8));
}

// ========================
//  Execute ADD(Immediate)
// ========================

void 
execute_add_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_add_imm(instr, vm);
}

void 
execute_add_imm_t2
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_add_imm(instr, vm);
}

void 
execute_add_imm
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(R[n], imm32, ‘0’);
	immutable res = add_with_carry(rn, imm, false);
	if (!vm.in_it_block()) {
		vm.set_z(res.result);
		vm.set_n(res.result);
		vm.set_c(res.carry);
		vm.set_v(res.overflow);
	}
	vm.set_reg(instr.rd, res.result);
}

string convert_add_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("add%s %s, %s, #%d", get_it_block_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rn),
									   instr.imm);
}

string convert_add_imm_t2_to_string(const ref instr_16 instr, const condition cond) {
	return format("add%s %s, #%d", get_it_block_string(cond),
								   get_reg_name(instr.rd),
								   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ADD 											 *
// ***************************************************************************************

// =====================
//  Parse ADD(Register)
// =====================

// ADDS <Rd>,<Rn>,<Rm>
// ADD<c> <Rd>,<Rn>,<Rm>
// [15:9] 0001100, [8:6] Rm, [5:3] Rn, [2:0] Rd
instr_16 parse_add_reg_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rn: cast(reg)slice(instr, 3, 3),
					rm: cast(reg)slice(instr, 6, 3));
}

// =======================
//  Execute ADD(Register)
// =======================

void 
execute_add_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable rm  = vm.get_reg(instr.rm);
	// (result, carry, overflow) = AddWithCarry(R[n], shifted, ‘0’);
	immutable res = add_with_carry(rn, rm, false);
	vm.set_reg(instr.rd, res.result); 
	if (instr.rd == reg.pc)  // setflags is always FALSE here
		return;
	if (!vm.in_it_block()) { 
		vm.set_z(res.result); 			// APSR.Z = IsZeroBit(result);
		vm.set_n(res.result);			// APSR.N = result<31>;
        vm.set_c(res.carry);            // APSR.C = carry;
        vm.set_v(res.overflow);			// APSR.V = overflow;
	}
}

string convert_add_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("add%s %s, %s, %s", get_it_block_string(cond),
									  get_reg_name(instr.rd),
									  get_reg_name(instr.rn),
									  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ASR                                            *
// ***************************************************************************************

// ======================
//  Parse ASR(Immediate)
// ======================

// ASRS <Rd>,<Rm>,#<imm5>			Outside IT block.
// ASR<c> <Rd>,<Rm>,#<imm5>			Inside IT block.
// [15:11] 00010, [10:6] imm5, [5:3] Rm, [2:0] Rd  
instr_16 parse_asr_imm_t1(const ushort instr) {
	return instr_16(rd:  	 cast(reg)slice(instr, 0, 3),
					rm:  	 cast(reg)slice(instr, 3, 3),
					imm:     slice(instr, 6, 5),
					shift_t: shift_type.asr);
}

// ========================
//  Execute ASR(Immediate)
// ========================

void 
execute_asr_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}

// ==================================
//  Convert ASR(Immediate) to String
// ==================================

string convert_asr_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("asr%s %s, %s, #%d", get_it_block_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rm),
									   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LSL 											 *
// ***************************************************************************************

// ======================
//  Parse LSL(Immediate)
// ======================

// LSLS <Rd>,<Rm>,#<imm5>
// LSL<c> <Rd>,<Rm>,#<imm5>
// [15:11] 00000, [10:6] imm5, [5:3] Rm, [2:0] Rd
instr_16 parse_lsl_imm_t1(const ushort instr) {
	return instr_16(rd:  	 cast(reg)slice(instr, 0, 3),
					rm:  	 cast(reg)slice(instr, 3, 3),
					imm:     slice(instr, 6, 5),
					shift_t: shift_type.lsl);
}

// ========================
//  Execute LSL(Immediate) 
// ========================

void 
execute_lsl_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}

// ==================================
//  Convert LSL(Immediate) to String 
// ==================================

string convert_lsl_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("lsl%s %s, %s, #%d", get_it_block_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rm),
									   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LSR 											 *
// ***************************************************************************************

// ======================
//  Parse LSR(Immediate)
// ======================

// LSR <Rd>,<Rm>,#<imm5>
// [15:11] 00001, [10:6] imm5, [5:3] Rm, [2:0] Rd
instr_16 parse_lsr_imm_t1(const ushort instr) {
	return instr_16(rd:  	 cast(reg)slice(instr, 0, 3),
					rm:  	 cast(reg)slice(instr, 3, 3),
					imm:     slice(instr, 6, 5),
					shift_t: shift_type.lsr);
}

// ========================
//  Execute LSR(Immediate) 
// ========================

void 
execute_lsr_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}

// ==================================
//  Convert LSR(Immediate) to String 
// ==================================

string convert_lsr_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("lsr%s %s, %s, #%d", get_it_block_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rm),
									   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  SUB 											 *
// ***************************************************************************************

// ======================
//  Parse SUB(Immediate)
// ======================

// SUB <Rd>,<Rn>,#<imm3>
// [15:9] 0001111, [8:6] imm3, [5:3] Rn, [2:0] Rd
instr_16 parse_sub_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 0, 3),
					rn:  cast(reg)slice(instr, 3, 3),
					// imm32 = ZeroExtend(imm3, 32);
					imm: slice(instr, 6, 3));
}

// ======================
//  Parse SUB(Immediate)
// ======================

// SUBS <Rdn>,#<imm8>
//SUB<c> <Rdn>,#<imm8>
// [15:9] 0001111, [8:6] imm3, [5:3] Rn, [2:0] Rd
instr_16 parse_sub_imm_t2(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 8, 3),
					// imm32 = ZeroExtend(imm8, 32);
					imm: slice(instr, 0, 8),
					rn:  cast(reg)slice(instr, 8, 3));
}

// ========================
//  Execute SUB(Immediate)
// ========================

void 
execute_sub_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_sub_imm(instr, vm);
}

void 
execute_sub_imm_t2
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_sub_imm(instr, vm);
}

void 
execute_sub_imm
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), ‘1’);
	immutable res = add_with_carry(rn, ~imm, true);
	if (!vm.in_it_block()) {
		vm.set_c(res.carry);
		vm.set_n(res.result);
		vm.set_v(res.overflow);
		vm.set_z(res.result);
	}
	vm.set_reg(instr.rd, res.result);
}

string convert_sub_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("sub%s %s, %s, #%d", get_it_block_string(cond),
								       get_reg_name(instr.rd),
								       get_reg_name(instr.rn),
								       instr.imm);
}

string convert_sub_imm_t2_to_string(const ref instr_16 instr, const condition cond) {
	return format("sub%s %s, #%d", get_it_block_string(cond),
								   get_reg_name(instr.rd),
								   instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   MOV 											 *
// ***************************************************************************************

// ======================
//  Parse MOV(Immediate)
// ======================

// MOVS <Rd>,#<imm8>
// MOV<c> <Rd>,#<imm8>
// [15:11] 00100, [10:8] Rd, [7:0] imm8
instr_16 parse_mov_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 8, 3),
		            imm: slice(instr, 0, 8)); // imm32 = ZeroExtend(imm8, 32);
}

// ========================
//  Execute MOV(Immediate)
// ========================

void 
execute_mov_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable res = instr.imm;
	if (!vm.in_it_block()) {
		vm.set_z(res);			// APSR.Z = IsZeroBit(result);
		vm.set_n(res);		 	// APSR.N = result<31>;
		// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

string convert_mov_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("mov%s %s, #%d", get_it_block_string(cond),
								   get_reg_name(instr.rd),
								   instr.imm);
}
// ---------------------------------------------------------------------------------------
