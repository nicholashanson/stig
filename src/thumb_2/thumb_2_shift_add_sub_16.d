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
	immutable res = shift_c(instr.shift_t, instr.imm, rm, vm.get_c());
	if (!vm.in_it_block()) {
		vm.set_c(res.carry);
		vm.set_n(res.result);
		vm.set_z(res.result);
		// APSR.V unchanged
	}
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									SUB SP											 *
// ***************************************************************************************

// ===============================
//  Parse SUB(SP Minus Immediate)
// ===============================

enum field_tuples_sub_sp_t1 = [Tuple!(opcode, string[])(opcode.sub_sp_t1, ["sp","imm"])];
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
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  CMP 											 *
// ***************************************************************************************

// ======================
//  Parse CMP(Immediate)
// ======================

enum field_tuples_cmp_imm_t1 = [Tuple!(opcode, string[])(opcode.cmp_imm_t1, ["rn","imm"])];
// CMP <Rn>,#<imm8>
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
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *								      SUB 											 *
// ***************************************************************************************

// =====================
//  Parse SUB(Register)
// =====================

enum field_tuples_sub_reg_t1 = [Tuple!(opcode, string[])(opcode.sub_reg_t1, ["rd","rn","rm"])];
// SUB <Rd>,<Rn>,<Rm>
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
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ADD 											 *
// ***************************************************************************************

// ======================
//  Parse ADD(Immediate)
// ======================

enum field_tuples_add_imm_t1 = [Tuple!(opcode, string[])(opcode.add_imm_t1, ["rd","rn","imm"])];
// ADD <Rd>,<Rn>,#<imm3>
// [15:9] 0001110, [8:6] imm3, [5:3] Rn, [2:0] Rd
instr_16 parse_add_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 0, 3),
					rn:  cast(reg)slice(instr, 3, 3),
					imm: slice(instr, 6, 3));
}

// ======================
//  Parse ADD(Immediate)
// ======================

enum field_tuples_add_imm_t2 = [Tuple!(opcode, string[])(opcode.add_imm_t2, ["rn","imm"])];
// ADD <Rd>,<Rn>,#<imm3>
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
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ADD 											 *
// ***************************************************************************************

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_reg_t1 = [Tuple!(opcode, string[])(opcode.add_reg_t1, ["rd","rn","rm"])];
// ADD <Rd>,<Rn>,<Rm>
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
	vm.set_reg(instr.rd, res); 
	if (instr.rd == reg.pc)  // setflags is always FALSE here
		return;
	if (!vm.in_it_block()) { 
		vm.set_z(res.result); 			// APSR.Z = IsZeroBit(result);
		vm.set_n(res.result);			// APSR.N = result<31>;
        vm.set_c(res.carry);            // APSR.C = carry;
        vm.set_v(res.overflow);			// APSR.V = overflow;
	}
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ASR                                            *
// ***************************************************************************************

// ======================
//  Parse ASR(Immediate)
// ======================

enum field_tuples_asr_imm_t1 = [Tuple!(opcode, string[])(opcode.asr_imm_t1, ["rm","rd","imm"])];
// ASR <Rd>,<Rm>,#<imm5>
// [15:11] 00010, [10:6] imm5, [5:3] Rm, [2:0] Rd  
instr_16 parse_asr_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 0, 3),
					rm:  cast(reg)slice(instr, 3, 3),
					imm: slice(instr, 6, 5));
}

// ========================
//  Execute ASR(Immediate);
// ========================

void 
execute_asr_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LSL 											 *
// ***************************************************************************************

// ======================
//  Parse LSL(Immediate)
// ======================

enum field_tuples_lsl_imm_t1 = [Tuple!(opcode, string[])(opcode.lsl_imm_t1, ["rd","rm","imm"])];
// LSL <Rd>,<Rm>,#<imm5>
// [15:11] 00000, [10:6] imm5, [5:3] Rm, [2:0] Rd
instr_16 parse_lsl_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 0, 3),
					rm:  cast(reg)slice(instr, 3, 3),
					imm: slice(instr, 6, 5));
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
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LSR 											 *
// ***************************************************************************************

// ======================
//  Parse LSR(Immediate)
// ======================

enum field_tuples_lsr_imm_t1 = [Tuple!(opcode, string[])(opcode.lsr_imm_t1, ["rd","rm","imm"])];
// LSR <Rd>,<Rm>,#<imm5>
// [15:11] 00001, [10:6] imm5, [5:3] Rm, [2:0] Rd
instr_16 parse_lsr_imm_t1(const ushort instr) {
	return instr_16(rd:  cast(reg)slice(instr, 0, 3),
					rm:  cast(reg)slice(instr, 3, 3),
					imm: slice(instr, 6, 5));
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
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  SUB 											 *
// ***************************************************************************************

// ======================
//  Parse SUB(Immediate)
// ======================

enum field_tuples_sub_imm_t1 = [Tuple!(opcode, string[])(opcode.sub_imm_t1, ["rd","rn","imm"])];
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

enum field_tuples_sub_imm_t2 = [Tuple!(opcode, string[])(opcode.sub_imm_t2, ["rd","imm"])];
// SUB <Rd>,<Rn>,#<imm8>
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
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   MOV 											 *
// ***************************************************************************************

// ======================
//  Parse MOV(Immediate)
// ======================

enum field_tuples_mov_imm_t1 = [Tuple!(opcode, string[])(opcode.mov_imm_t1, ["rd","imm"])];
// MOVS <Rd>,#<imm8> 
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
// ---------------------------------------------------------------------------------------
