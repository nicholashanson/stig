// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			   Special Data Instructions and Branch and Exchange	    	         *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;
import std.format   : format;
import std.conv;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *									   MOV 											 *
// ***************************************************************************************

// =====================
//  Parse MOV(Register)
// =====================

// MOV<c> <Rd>,<Rm>
// [15:8] 01000110, [7] D, [6:3] Rm, [2:0] Rd  
instr_16 parse_mov_reg_t1(const ushort instr) {
	auto rd = slice(instr, 0, 3);
	auto d  = slice(instr, 7, 1);
	if (d) 
		rd |= 0b1000;
	return instr_16(rd: cast(reg)rd,
					rm: cast(reg)slice(instr, 3, 4));
}

// =======================
//  Execute MOV(Register)
// =======================

void
execute_mov_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable res = vm.get_reg(instr.rm);
	vm.set_reg(instr.rd, res);
	// setflags = FALSE;
}

// =================================
//  Convert MOV(Register) to String
// =================================

// MOV<c> <Rd>,<Rm>
string convert_mov_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("mov%s %s, %s", get_condition_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ADD 											 *
// ***************************************************************************************

// =====================
//  Parse ADD(Register)
// =====================

// ADD <Rdn>,<Rm>
// [15:8] 01000100, [7] DN, [6:3] Rm, [2:0] Rdn
instr_16 parse_add_reg_t2(short instr) {
	auto 	  rdn = slice(instr, 0, 3);
	immutable dn  = slice(instr, 7, 1);
	if (dn)
		rdn |= 0b1000;
	return instr_16(rn: cast(reg)(rdn), 
					rd: cast(reg)(rdn), 
					rm: cast(reg)slice(instr, 3, 4));
}

// =======================
//  Execute ADD(Register)
// =======================

void 
execute_add_reg_t2
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable rm  = vm.get_reg(instr.rm);
	// (result, carry, overflow) = AddWithCarry(R[n], shifted, ‘0’);
	immutable res = add_with_carry(rn, rm, false);
	vm.set_reg(instr.rd, res.result); 
	// setflags = FALSE;
}

// =================================
//  Execute ADD(Register) to String
// =================================

// ADD<c> <Rdn>,<Rm>
string convert_add_reg_t2_to_string(const ref instr_16 instr, const condition cond) {
	return format("add%s %s, %s", get_condition_string(cond), 
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));

}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   BLX 											 *
// ***************************************************************************************
// Branch with Link and Exchange calls a subroutine at an address and instruction set 
// specified by a register.

// ARMv7-M only supports the Thumb instruction set. An attempt to change the instruction 
// execution state causes the processor to take an exception on the instruction at the 
// target address.


// =====================
//  Parse BLX(Register)
// =====================

// BLX <Rm>
// [15:8] 010001111, [6:3] Rm, [2:0] 000
instr_16 parse_blx_t1(const ushort instr) {
	return instr_16(rm: cast(reg)slice(instr, 3, 4));
}

// =======================
//  Execute BLX(Register)
// =======================

void 
execute_blx_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  rm = vm.get_reg(instr.rm);
	vm.set_reg(reg.lr, vm.get_pc() + 2);
	vm.set_reg(reg.pc, rm);
}

// =================================
//  Execute BLX(Register) to String
// =================================

string convert_blx_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("blx %s", instr.rm.to!string);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   BX 											 *
// ***************************************************************************************
// Branch and Exchange causes a branch to an address and instruction set specified by a 
// register.

// ARMv7-M only supports the Thumb instruction set. An attempt to change the instruction 
// execution state causes the processor to take an exception on the instruction at the 
// target address.

// BX can also be used for an exception return(*).

// ==========
//  Parse BX
// ==========

// BX <Rm>
// [15:7] 010001110, [6:3] Rm, [2:0] 000
instr_16 parse_bx_t1(const ushort instr) {
	return instr_16(rm: cast(reg)slice(instr, 3, 4));
}

// ============
//  Execute BX
// ============

void 
execute_bx_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rm = vm.get_reg(instr.rm);
	if (is_exc_ret_val(rm)) { // (*)
        exc_rtr(rm, vm);
        return;
    }
	vm.set_reg(reg.pc, rm);
}

// ======================
//  Convert BX to String
// ======================

string convert_bx_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("bx %s", get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------