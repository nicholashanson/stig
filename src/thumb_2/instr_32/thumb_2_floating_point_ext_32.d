import std.typecons : Tuple;
import std.format;
import std.conv;

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

instr_32 parse_vpush_t1(const uint instr) {
	// single_regs = FALSE; 
	// d = UInt(D:Vd); 
	// imm32 = ZeroExtend(imm8:’00’, 32);
	// regs = UInt(imm8) DIV 2;
	auto parsed_instr = parse_vpush(instr);
	parsed_instr.regs = (slice(instr, 0, 8) << 2) / 2;
	parsed_instr.single_regs = false;
	return parsed_instr;
}

instr_32 parse_vpush_t2(const uint instr) {
	// single_regs = TRUE; d = UInt(Vd:D);
	// imm32 = ZeroExtend(imm8:’00’, 32); regs = UInt(imm8);
	// if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;
	auto parsed_instr = parse_vpush(instr);
	parsed_instr.regs = cast(uint)(slice(instr, 0, 8) << 2);
	parsed_instr.single_regs = true;
	return parsed_instr;
}

instr_32 parse_vpush(const uint instr) {
	return instr_32(
		rd: 		cast(reg)((slice(instr, 22, 1) << 4) | slice(instr, 12, 4)),
		D:          cast(bool)slice(instr, 22, 1)
	);
}

// single_regs = TRUE; d = UInt(Vd:D);
// imm32 = ZeroExtend(imm8:’00’, 32); regs = UInt(imm8);
// if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;

void
execute_vpush_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vpush(instr, vm);
}

void
execute_vpush_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vpush(instr, vm);
}

void
execute_vpush
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// if ConditionPassed() then
	// EncodingSpecificOperations();
	// ExecuteFPCheck();
	// address = SP - imm32;
	uint addr = vm.get_reg(reg.sp) - instr.imm;
	// SP = SP - imm32;
	vm.set_reg(reg.sp, addr);
	if (instr.single_regs) {
		// r = 0 to regs-1
		for (uint r = 0; r < instr.regs; ++r) {
			// MemA[address,4] = S[d+r]; address = address+4;
			vm.write_word(addr, vm.get_reg_s(cast(reg)(instr.rd + r)));
			addr += 4;
		}
	} else {
		for (uint r = 0; r < instr.regs; ++r) {
			// Store as two word-aligned words in the correct order for current endianness.
			// MemA[address,4] = if BigEndian() then D[d+r]<63:32> else D[d+r]<31:0>;
			vm.write_word(addr,     slice(vm.get_reg_d(cast(reg)(instr.rd + r)),  0, 32));
			// MemA[address+4,4] = if BigEndian() then D[d+r]<31:0> else D[d+r]<63:32>;
			vm.write_word(addr + 4, slice(vm.get_reg_d(cast(reg)(instr.rd + r)), 31, 32));
			// address = address+8;
			addr += 8;
		}
	}
}

// VPUSH<c> <list>
string convert_vpush_t1_to_string(const ref instr_32 instr, const condition cond) {
	return convert_vpush_to_string(instr, cond);
}

// VPUSH<c> <list>
string convert_vpush_t2_to_string(const ref instr_32 instr, const condition cond) {
	return convert_vpush_to_string(instr, cond);
}

string convert_vpush_to_string(const ref instr_32 instr, const condition cond) {
	const uint d = instr.single_regs 
        ? ((instr.rd << 1) | cast(uint)instr.D)
        : ((cast(uint)instr.D << 4)  | instr.rd);
	return format("vpush%s %s", cond != condition.none ? cond.to!string : "", 
							    get_reg_list_string(d, instr.regs, instr.single_regs));
}