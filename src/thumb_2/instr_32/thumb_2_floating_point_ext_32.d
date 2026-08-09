import std.typecons : Tuple;
import std.format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

bool LSPACT_SET(const uint fpccr) {
	return (fpccr & 0x1) == 0x1;
}

bool ASPEN_SET(const uint fpccr) {
	return slice(fpccr, 31, 1) == 0x1;
}

void preserve_fp_state() {
}

bool check_vfp_enabled() {
	return true;
}

// ==================
//  ExecuteFPCheck()
// ==================

void 
execute_fp_check
(vm_t)
(ref vm_t vm) {
	immutable fpccr = vm.get_fpccr();
	// Check access to FP coprocessor is enabled
	check_vfp_enabled();
	// If FP lazy context save is enabled then save state
	if (LSPACT_SET(fpccr))
		preserve_fp_state();
		
	// Update CONTROL.FPCA, and create new FP context
	// if this has been enabled by setting FPCCR.ASPEN to 1
	if (ASPEN_SET(fpccr) && !vm.get_fpca()) {
		// FPSCR<26:22> = FPDSCR<26:22>;
		// CONTROL.FPCA = ‘1’;
	}
}

// move to floating-point special register
instr_32 parse_vmsr_t1(const uint instr) {
	return instr_32(rt: cast(reg)slice(instr, 12, 4));
}

void 
execute_vmsr_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rt = vm.get_reg(instr.rt);
	vm.set_fpscr(rt);
}

// VMRS<c> <Rt>, FPSCR
string convert_vmsr_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("vmrs%s %s, FPSCR", get_condition_string(cond),
									  get_reg_name(instr.rt));
}

void
copy_apsr_to_fpscr
(vm_t)
(ref vm_t vm) {
	uint fpscr = vm.get_fpscr();
	vm.set_n(cast(bool)slice(fpscr, 31, 1));
	vm.set_z(cast(bool)slice(fpscr, 30, 1));
	vm.set_c(cast(bool)slice(fpscr, 29, 1));
	vm.set_v(cast(bool)slice(fpscr, 28, 1));
}

void serialize_vfp() {
	return;
}

void fvp_exec_barrier() {
	return;
}

instr_32 parse_vmrs_t1(const uint instr) {
	return instr_32(rt: cast(reg)slice(instr, 12, 4));
}

// Floating-point Status and Control Register, FPSCR
void 
execute_vmrs_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	//if ConditionPassed() then
	//EncodingSpecificOperations();
	execute_fp_check(vm);
	serialize_vfp();
	fvp_exec_barrier();
	if (instr.rt == 15) {
		copy_apsr_to_fpscr(vm);
	} else {
		vm.set_reg(instr.rt, vm.get_fpscr());
	}
}

void
execute_vpush_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
}

void
execute_vpush_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
}