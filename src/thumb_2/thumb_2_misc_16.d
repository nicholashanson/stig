// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			            Miscellaneous 16-Bit Instructions	    					 *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;
import std.algorithm;
import std.format;
import std.conv;
import std.array;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ***************************************************************************************
// *								 IF THEN 											 *
// ***************************************************************************************

// ===============
//  Parse IF THEN
// ===============

enum field_tuples_if_then_t1 = [Tuple!(opcode, string[])(opcode.if_then_t1, ["condition"])];
// IT{x{y{z}}} <firstcond>
// [15:8] 10111111, [7:4] firstcond, [3:0] mask  
instr_16 parse_if_then_t1(const ushort instr) {
	return instr_16(mask:       cast(ubyte)slice(instr, 0, 4),
					first_cond: cast(ubyte)slice(instr, 4, 4));
}

// =================
//  Execute IF THEN
// =================

void 
execute_if_then_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable mask 		  	  = instr.mask;
	immutable first_cond  	  = instr.first_cond;
	immutable cond 		  	  = cast(condition)(first_cond);
	immutable first_cond_mask = cast(ubyte)((first_cond << 4) | mask);
	xyz it_block = get_xyz(first_cond_mask);
	vm.cpu.it_block = it_block;
	vm.cpu.init_it_block_stack(cond);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *								       REV 											 *
// ***************************************************************************************
// Byte-Reverse Word reverses the byte order in a 32-bit register.

// ===========
//  Parse REV
// ===========

enum field_tuples_rev_t1 = [Tuple!(opcode, string[])(opcode.rev_t1, ["rd","rm"])];
// REV<c> <Rd>,<Rm>
// [15:6] 1011101000, [5:3] Rm, [2:0] Rd
instr_16 parse_rev_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 3));
}

// =============
//  Execute REV
// =============

void 
execute_rev_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rm = vm.get_reg(instr.rm);
	const uint res = ((rm << 24) & 0xff00_0000) |
		      		 ((rm <<  8) & 0x00ff_0000) |
			  		 ((rm >>  8) & 0x0000_ff00) |
			  		 ((rm >> 24) & 0x0000_00ff);
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   CBNZ 										 *
// ***************************************************************************************

// ============
//  Parse CBNZ
// ============

enum field_tuples_cbnz_t1 = [Tuple!(opcode, string[])(opcode.cbnz_t1, ["rn", "label"])];
// CBNZ <Rn>,<label>
// [15:12] 1011, [11] op, [10] 0, [9] i, [8] 1, [7:3] imm5, [2:0] Rn  
instr_16 parse_cbnz_t1(const ushort instr) {
	immutable  i     = slice(instr, 9, 1);
	immutable  imm_5 = slice(instr, 3, 5);
	const uint imm   = (i << 6) | (imm_5 << 1);
	return instr_16(rn:     cast(reg)slice(instr, 0, 3),
					offset: imm);
}

// ==============
//  Execute CBNZ
// ==============

void 
execute_cbnz_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	if (vm.get_reg(instr.rn) != 0) {
		int pc = vm.get_reg(reg.pc);
		pc += instr.offset;
		pc += 4;
		vm.set_reg(reg.pc, pc);
	} 
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   CBZ 											 *
// ***************************************************************************************

// ===========
//  Parse CBZ
// ===========

enum field_tuples_cbz_t1 = [Tuple!(opcode, string[])(opcode.cbz_t1, ["rn", "label"])];
// CBZ <Rn>,<label>
// [15:12] 1011, [11] op, [10] 0, [9] i, [8] 1, [7:3] imm5, [2:0] Rn  
instr_16 parse_cbz_t1(const ushort instr) {
	immutable  i     = slice(instr, 9, 1);
	immutable  imm_5 = slice(instr, 3, 5);
	const uint imm   = (i << 6) | (imm_5 << 1);
	return instr_16(rn:     cast(reg)slice(instr, 0, 3),
					offset: imm);
}

// =============
//  Execute CBZ
// =============

void 
execute_cbz_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rn = vm.get_reg(instr.rn);
	if (rn == 0) {
		auto pc = vm.get_pc();
		pc += instr.offset;
		pc += 4;
		vm.set_reg(reg.pc, pc);
	} 
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *							           CPS 											 *
// ***************************************************************************************
// Change Processor State changes one or more of the special-purpose register PRIMASK and 
// FAULTMASK values.

// ===========
//  Parse CPS
// ===========

enum field_tuples_cps_t1 = [Tuple!(opcode, string[])(opcode.cps_t1, ["effect", "iflags"])];
// CPS<effect> <iflags>
// [15:5] 10110110011, [4] im, [3:2] 00, [1] I, [0] F
instr_16 parse_cps_t1(const ushort instr) {
	return instr_16(enable:      !cast(bool)slice(instr, 4, 1),
					affect_pri:   cast(bool)slice(instr, 1, 1),
					affect_fault: cast(bool)slice(instr, 0, 1));
}

// =============
//  Execute CPS
// =============

void 
execute_cps_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable enable 	   = instr.enable;
	immutable affect_pri   = instr.affect_pri;
	immutable affect_fault = instr.affect_fault;
	if (enable) {
		// if affectPRI then PRIMASK<0> = ‘0’;
		if (affect_pri) 
			vm.cpu.pri_mask 	= false;
		// if affectFAULT then FAULTMASK<0> = ‘0’;
		if (affect_fault) 
			vm.cpu.fault_mask 	= false;
	}
	if (!enable) {
		// if affectPRI then PRIMASK<0> = ‘1’;
		if (affect_pri) 
			vm.cpu.pri_mask 	= true;
		// if affectFAULT && ExecutionPriority() > -1 then FAULTMASK<0> = ‘1’;
		if (affect_fault) 
			vm.cpu.fault_mask 	= true;
	}
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   POP 											 *
// ***************************************************************************************
// Pop Multiple Registers loads a subset, or possibly all, of the general-purpose 
// registers R0-R12 and the PC or the LR from the stack.

// If the registers loaded include the PC, the word loaded for the PC is treated as a 
// branch address or an exception return value (*).

// ===========
//  Parse POP
// ===========

enum field_tuples_pop_t1 = [Tuple!(opcode, string[])(opcode.pop_t1, ["reg_list"])];
// POP <registers>
// [15:9] 1011110, [8] P, [7:0] register_list  
instr_16 parse_pop_t1(const ushort instr) {
	instr_16 res;
	immutable p        = slice(instr, 8, 1);
	immutable reg_mask = slice(instr, 0, 8);
	reg[]	  reg_list;
	foreach (i; 0 .. 8)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	if (p) 
		reg_list ~= reg.pc; // registers = P:'0000000':register_list;
	return instr_16(reg_list: reg_list);
}

// =============
//  Execute POP
// =============

void 
execute_pop_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	foreach (r; regs) {
		immutable val = vm.pop();
		vm.set_reg(r, val);
	}
	if (regs.back == reg.pc) {
		if ((vm.get_pc() & 0xff00_0000) == 0xff00_0000) { // (*)
	        exception_return(vm, vm.get_pc());
	        return;
	    }
		vm.clear_thumb_bit();
	}
} 
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 PUSH 										 *
// ***************************************************************************************
// Push Multiple Registers stores a subset, or possibly all, of the general-purpose 
// registers R0-R12 and the LR to the stack.

// ============
//  Parse PUSH
// ============

enum field_tuples_push_t1 = [Tuple!(opcode, string[])(opcode.push_t1, ["reg_list"])];
// PUSH <registers>
// [15:9] 1011010, [8] M, [7:0] register_list  
instr_16 parse_push_t1(const ushort instr) {
	immutable m        = slice(instr, 8, 1);
	immutable reg_mask = slice(instr, 0, 8);
	reg[]     reg_list;
	foreach (i; 0 .. 8)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	if (m) 
		reg_list ~= reg.lr; // registers = '0':M:'000000':register_list;
	return instr_16(reg_list: reg_list);
}

// ==============
//  Execute PUSH
// ==============

void 
execute_push_t1
(vm_t)
(instr_16 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	foreach (r; regs) {
		vm.push(r);	
	}
} 
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   SXTB 										 *
// ***************************************************************************************
// Signed Extend Byte extracts an 8-bit value from a register, sign extends it to 32 bits, 
// and writes the result to the destination register. You can specify a rotation by 0, 8, 
// 16, or 24 bits before extracting the 8-bit value.

// ============
//  Parse SXTB
// ============

enum field_tuples_sxtb_t1 = [Tuple!(opcode, string[])(opcode.sxtb_t1, ["rd","rm"])];
// SXTB <Rd>,<Rm>
// [15:6] 1011001001, [5:3] Rm, [2:0] Rd  
instr_16 parse_sxtb_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 3));
}

// ==============
//  Execute SXTB
// ==============

void 
execute_sxtb_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	immutable res = cast(int)(cast(byte)rm);
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   UXTB 										 *
// ***************************************************************************************
// Unsigned Extend Byte extracts an 8-bit value from a register, zero extends it to 32 
// bits, and writes the result to the destination register. You can specify a rotation by 
// 0, 8, 16, or 24 bits before extracting the 8-bit value.

// ============
//  Parse UXTB
// ============

enum field_tuples_uxtb_t1 = [Tuple!(opcode, string[])(opcode.uxtb_t1, ["rd","rm"])];
// UXTB <Rd>,<Rm>
// [15:6] 1011001011, [5:3] Rm, [2:0] Rd  
instr_16 parse_uxtb_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 3));
}

// ==============
//  Execute UXTB
// ==============

void 
execute_uxtb_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable  rm  = vm.get_reg(instr.rm);
	const uint res = rm & 0xff;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   UXTH 										 *
// ***************************************************************************************
// Unsigned Extend Halfword extracts a 16-bit value from a register, zero extends it to 
// 32 bits, and writes the result to the destination register. You can specify a rotation 
// by 0, 8, 16, or 24 bits before extracting the 16-bit value.

// ============
//  Parse UXTH
// ============

enum field_tuples_uxth_t1 = [Tuple!(opcode, string[])(opcode.uxth_t1, ["rd","rm"])];
// UXTB <Rd>,<Rm>
// [15:6] 1011001011, [5:3] Rm, [2:0] Rd  
instr_16 parse_uxth_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 3));
}

// ==============
//  Execute UXTH
// ==============

void 
execute_uxth_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable  rm  = vm.get_reg(instr.rm);
	// R[d] = ZeroExtend(rotated<15:0>, 32);
	const uint res = rm & 0xffff;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ===========
//  Parse NOP
// ===========

enum field_tuples_nop_t1 = [Tuple!(opcode, string[])(opcode.nop_t1, [])];

instr_16 parse_nop_t1(const ushort instr) {
	return instr_16();
}

void
execute_nop_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {}

// ***************************************************************************************
// *									   SXTH 										 *
// ***************************************************************************************

// ============
//  Parse SXTH
// ============

// SXTH<c> <Rd>,<Rm>
instr_16 parse_sxth_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
			        rm: cast(reg)slice(instr, 3, 3));
}

// ==============
//  Execute SXTH
// ==============

void 
execute_sxth_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	// rotated = ROR(R[m], rotation);
	// R[d] = SignExtend(rotated<15:0>, 32);
	immutable res = cast(int)cast(short)rm;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   REV16										 *
// ***************************************************************************************	
// Byte-Reverse Packed Halfword reverses the byte order in each 16-bit halfword of a 
// 32-bit register.

// =============
//  Parse REV16
// =============

// REV16<c> <Rd>,<Rm>
instr_16 parse_rev16_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 3));
}

// ===============
//  Execute REV16
// ===============

void 
execute_rev16_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rm = vm.get_reg(instr.rm);
	// bits(32) result;
	// result<31:24> = R[m]<23:16>;
	// result<23:16> = R[m]<31:24>;
	// result<15:8> = R[m]<7:0>;
	// result<7:0> = R[m]<15:8>;
	const uint res = ((rm >> 8) & 0x00ff_0000) |
					 ((rm << 8) & 0xff00_0000) |
					 ((rm >> 8) & 0x0000_00ff) |
					 ((rm << 8) & 0x0000_ff00);
	// R[d] = result;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									REVSH										     *
// ***************************************************************************************
// Byte-Reverse Signed Halfword reverses the byte order in the lower 16-bit halfword of a 
// 32-bit register, and sign extends the result to 32 bits.

// REVSH<c> <Rd>,<Rm>
instr_16 parse_revsh_t1(const uint instr) {
	return instr_16(rm: cast(reg)slice(instr, 0, 3),
				    rd: cast(reg)slice(instr, 3, 3));
}

void 
execute_revsh_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	// bits(32) result;
	// result<31:8> = SignExtend(R[m]<7:0>, 24);
	// result<7:0> = R[m]<15:8>;
	immutable res = cast(int)((rm << 8) & 0x0000_ff00) | ((rm >> 8) & 0x0000_00ff);
	// R[d] = result;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   BKPT 										 *
// ***************************************************************************************

// BKPT #<imm8>
instr_16 parse_bkpt_t1(const ushort instr) {
	// imm32 = ZeroExtend(imm8, 32);
	// imm32 is for assembly/disassembly only and is ignored by hardware.
	return instr_16(imm: slice(instr, 0, 8));
}

void 
execute_bkpt_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	// BKPTInstrDebugEvent();
}
// ---------------------------------------------------------------------------------------