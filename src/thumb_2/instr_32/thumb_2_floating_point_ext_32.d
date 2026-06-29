import std.typecons : Tuple;
import std.format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

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

// Floating-point Status and Control Register, FPSCR
void 
execute_vmrs_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	//if ConditionPassed() then
	//EncodingSpecificOperations();
	//ExecuteFPCheck();
	//SerializeVFP();
	//VFPExcBarrier();
	//if t == 15 then
	//APSR.N = FPSCR.N;
	//APSR.Z = FPSCR.Z;
	//APSR.C = FPSCR.C;
	//APSR.V = FPSCR.V;
	//else
	//R[t] = FPSCR;
}