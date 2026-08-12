import cortex_m_core;

import thumb_2_instrs;
import thumb_2_floating_point_ext_32;
import helium;
// LE, LETP
// Loop End, Loop End with Tail Predication. 
// If additional iterations of a loop are required this instruction branches back to the <label>. 
// It also stores the loop information in the loop info cache so that future iterations of the
// loop will branch back to the start just before the LE instruction is encountered. The first 
// variant of the instruction checks a loop iteration counter (stored in LR) to determine if additional 
// iterations are required. It also decrements the counter ready for the next iteration.
// The second variant does not use an iteration count and always triggers another iteration of the loop.
// The third (TP) variant also checks the loop iteration counter to determine if additional iterations 
// are required. However the counter is decremented by the number of elements in a vector (as indicated 
// by the FPSCR.LTPSIZE field). On the last iteration of the loop, this variant disables tail predication.
// This instruction is not permitted in an IT block.

void
execute_le_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_le(instr, vm);
}

void
execute_le_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_le(instr, vm);
}

void
execute_le_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_le(instr, vm);
}

void
execute_le
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	if (instr.tp)
		execute_fp_check(vm);
	// elsif LTPSIZE != 4 then
		// Tail predicated loop starts should be paired with an LETP loop end.
 		// Using a LE instruction in this case is a programming error.
		// UFSR.INVSTATE = '1';
		// HandleException(CreateException(UsageFault));
	// if !forever && IsLastLowOverheadLoop() then
	if (instr.forever && is_last_low_overhead_loop(vm)) {
		if (instr.tp) {
			// FPSCR.LTPSIZE = 4[2:0]; // Disable loop predication
		}
	} else {
		// Decrement the loop counter
		if (!instr.forever) {
			// LR = LR - (1 << (4 - LTPSIZE))[31:0];
		}
		// Set up the branch cache info
		uint jump_addr = vm.get_reg(reg.pc) - instr.imm;
		// if CCR.LOB == '1' then
			// LO_BRANCH_INFO.VALID = '1';
			// LO_BRANCH_INFO.BF = '0';
			// LO_BRANCH_INFO.LF = if forever then '1' else '0';
			// LO_BRANCH_INFO.T16IND = '0';
			// LO_BRANCH_INFO.JUMP_ADDR = jumpAddr[31:1];
			// LO_BRANCH_INFO.END_ADDR = ThisInstrAddr()[31:1];
		// // Branch to the start of the loop
		// BranchTo(jumpAddr);
		branch_to(jump_addr, false, vm);
	}
}

// ==========
// BranchTo()
// ==========

void branch_to
(vm_t)
(const uint addr, const bool commit, ref vm_t vm) {
	// if HaveLOBExt() then
	// Any branch between a branch future instruction and the associated
	// branch point invalidates the branch info cache
	if (VALID_SET(vm) && BF_SET(vm)) {
		VALID_CLEAR(vm);
	}

 	// Sets the address to fetch the next instruction from. NOTE: The current PC
 	// is not changed directly as this would modify the result of
	// ThisInstrAddr(), which would cause the wrong return addresses to be used
	// for some types of exception. The actual update of the PC is done in the
	// InstructionAdvance() function after the instruction finishes executing.
	// _NextInstrAddr = address[31:1]:'0';
	vm.set_next_instr_addr(addr & ~1u);
	// _PCChanged = TRUE;
	vm.set_pc_changed(true);
	// Clear any pending exception returns
	// _PendingReturnOperation = FALSE;
	vm.set_pending_ret_op(false);

	if (commit) {
		// This directly commits the change to the PC, so ThisInstrAddr()
		// and NextInstrAddr() both point to the target address. Used for exception
		// returns and resets so the state is consistent before the next instruction
		// (or exception) is taken.
		vm.set_reg(reg.pc, addr);
	}
}

instr_32 parse_wls_t1(const uint instr) {
	// if !HaveLOBExt() then UNDEFINED;
	// imm32 = ZeroExtend(immh:imml:'0', 32);
	uint imm_32 = (slice(instr, 1, 10) << 2) | (slice(instr, 11, 1) << 1);		
	return instr_32(
		rn:			   cast(reg)slice(instr, 16, 4),
		// No truncation. Set size to full vector length
		t_size:        4,
		imm: 	       imm_32,
		is_while_loop: true
	);
	// if InITBlock() then CONSTRAINED_UNPREDICTABLE;
	// if Rn == '11x1' then CONSTRAINED_UNPREDICTABLE;
}

void
execute_wls_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	return execute_wls(instr, vm);
}

void
execute_wls_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	return execute_wls(instr, vm);
}

void
execute_wls_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	return execute_wls(instr, vm);
}

void
execute_wls_t4
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	return execute_wls(instr, vm);
}

void
execute_wls 
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
 	// EncodingSpecificOperations();
	// count = R[n];
	uint count = vm.get_reg(instr.rn);	
	// if isWhileLoop && count == Zeros(32) then BranchTo(PC + imm32);
	if (instr.is_while_loop && (count == 0)) {
		branch_to(vm.get_reg(reg.pc) + instr.imm, false, vm);
	} else {
		// To avoid creating unnecessary FP context, the LTPSIZE is only set if
		// tail predication is being used.
		// if tSize != 4[2:0] then ExecuteFPCheck();
		if (instr.t_size != 4) {
			execute_fp_check(vm);
 			// FPSCR.LTPSIZE = tSize;
 			SET_LTPSIZE(vm, instr.t_size);
		}
 		
 		// Set up the new iteration count
 		// LR = count;
 		vm.set_reg(reg.lr, count);
 	}
}