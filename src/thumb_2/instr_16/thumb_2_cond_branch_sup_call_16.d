import std.typecons : Tuple;
import std.format;
import std.conv;

import thumb_2_opcodes;
import thumb_2_instrs;
import thumb_2_misc_16;
import cortex_m_core;

// ***************************************************************************************
// *									   SVC 											 *
// ***************************************************************************************
// The Supervisor Call instruction generates a call to a system supervisor.

// ===========
//  Parse SVC
// ===========

// SVC<c> #<imm8>
// [15:8] 11011111, [7:0] imm8
instr_16 parse_svc_t1(const ushort instr) {
	return instr_16(imm: slice(instr, 0, 8));
	// imm32 = ZeroExtend(imm8, 32);
	// imm32 is for assembly/disassembly, and is ignored by hardware. 
	// SVC handlers in some systems interpret imm8 in software, for 
	// example to determine the required service.
}

// =============
//  Execute SVC
// =============

void 
execute_svc_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	vm.increment_pc(2);
	if (vm.get_current_exception() == exception.thread_mode) {
		vm.push(vm.get_xpsr());
		auto push_instr = instr_16(op:       opcode.push_t1, 
			                       reg_list: hardware_saved_frame);
		execute_push_t1(push_instr, vm);
	}
	vm.set_current_exception(exception.svc_irqn);
	vm.set_npriv(false);
	vm.set_reg(reg.lr, 0xffff_fffd);
	immutable  vtor_raw    = vm.read_word(0xe000_ed08);
	const uint vector_base = vtor_raw & 0xffff_ff80;
	immutable pc = vm.read_word(vector_base + 4 * exception.svc_irqn);
	vm.set_reg(reg.pc, pc);
}

// =======================
//  Convert SVC to String
// =======================

// SVC<c> #<imm8>
string convert_svc_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("svc%s %d", get_condition_string(cond), 
							  instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					            Conditional Branch					                 *
// ***************************************************************************************

// =========
//  Parse B
// =========

// B<c> <label>
// [15:12] 1101, [11:8] cond, [7:0] imm8
instr_16 parse_b_t1(const ushort instr) {
	return instr_16(cond:   cast(condition)slice(instr, 8, 4),
					offset: cast(int)cast(byte)slice(instr, 0, 8) << 1);
}

// ===========
//  Execute B
// ===========

void 
execute_b_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	if (condition_is_met(instr.cond, vm.cpu)) {
		auto pc = vm.get_reg(reg.pc);
		pc += instr.offset + 4;
		vm.set_reg(reg.pc, pc);
	} 
}

string convert_b_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("b%s <label>", get_condition_string(instr.cond));
}
// ---------------------------------------------------------------------------------------
