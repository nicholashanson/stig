import std.format;

import thumb_2_floating_point_ext_32;
import thumb_2_instrs;

import cortex_m_core;

struct instr_beat {
	uint 	    curr_beat;
	ushort 		elmt_mask;
}

bool 
is_last_low_overhead_loop
(vm_t)
(ref vm_t vm) {
	return is_last_low_overhead_loop(vm, vm.get_curr_instr_exec_state());
}

bool 
is_last_low_overhead_loop
(vm_t)
(ref vm_t vm, const instr_exec_state state) {
	// This does not check whether a loop is currently active.
	// If the PE were in a loop, would this be the last one?
	return state.loop_count <= (1 << (4 - GET_FPSCR_LTPSIZE(vm)));
}

// Elem[]
// ======
// Non-assignment form
// bits(size) Elem[bits(N) vector, integer e, integer size]
R
elem
(R,T)
(T vector, uint e, uint size) {
	// assert e >= 0 && (e+1)*size <= N;
	assert((e >= 0) && (((e + 1) * size) <= (T.sizeof * 8)));
	// return vector[(e+1)*size-1:e*size];
	return cast(R)slice(vector, e * size, size - 1);
}

// bits(size) Elem[bits(N) vector, integer e]

	// return Elem[vector, e, size];
	
// Assignment form
// Elem[bits(N) &vector, integer e, integer size] = bits(size) value
		// assert e >= 0 && (e+1)*size <= N;
		// vector[(e+1)*size-1:e*size] = value;
		// return;
pragma(inline, true)
T 
set_elem
(T)
(T vector, const size_t e, const size_t size, T value) pure nothrow @nogc {
    T mask 		   = cast(T)((1u << size) - 1u);
    T shifted_mask = cast(T)(mask << (e * size));
    T cleared 	   = vector & ~shifted_mask;
    T inserted 	   = cast(T)((value & mask) << (e * size));
    return cast(T)(cleared | inserted);
}


// Elem[bits(N) &vector, integer e] = bits(size) value
	// Elem[vector, e, size] = value;
	// return;

bool vpt_active() {
	return true;
}

// ===================
//  GetCurInstrBeat()
// ===================
// (integer, bits(4)) GetCurInstrBeat()
instr_beat get_cur_instr_beat
(vm_t)
(ref vm_t vm) {
	// assert HaveMve();
	// By default assume all lanes are active.
	// elmtMask = Ones(4);
	ubyte elmt_mask = 0b1111;
	// If VPT active apply the predicate flags in VPR.P0.
	if (vpt_active()) {
		// elmtMask = elmtMask AND Elem[VPR.P0, _BeatID, 4];
	}
	// LOB truncation may override the flags on the last iteration of a loop
	// LTPSIZE < 4 is a proxy for knowing if loop and tail predication is active.
	ubyte LTPSIZE = cast(ubyte)GET_FPSCR_LTPSIZE(vm);
	ubyte lptsize = vm.get_curr_instr_exec_state().reset_ltp_size ? 4 : LTPSIZE;
	// if ltpsize < 4 && IsLastLowOverheadLoop() then
	if ((lptsize < 4) && is_last_low_overhead_loop(vm)) {
		uint loop_count = vm.get_curr_instr_exec_state().loop_count;
		ubyte pred_size = lptsize;
		// fullMask = ZeroExtend(Ones(UInt(loopCount[4-predSize:0] : Zeros(predSize))), 16);
		ushort full_mask = cast(ushort)slice(loop_count, 0, 4 - pred_size);
		// elmtMask = elmtMask AND Elem[fullMask, _BeatID, 4];
		elmt_mask &= elem!(ubyte,ushort)(full_mask, vm.get_beat_id(), 4);  
	}
	// return (_BeatID, elmtMask);
	return instr_beat(curr_beat: vm.get_beat_id(), elmt_mask: elmt_mask);
}

// T7: VLDRW variant (Post-indexed: P=0, W=1)
// VLDRW<v><q>.<dt> Qd, [Rn], #+/-<imm>
instr_32 parse_vldrw_t7(const uint instr) {
	return instr_32(
		qd:    cast(reg)((slice(instr, 22, 1) << 3) | slice(instr, 13, 3)),
		imm:   slice(instr, 0, 7),
		rn:    cast(reg)slice(instr, 16, 4),
		wback: cast(bool)slice(instr, 21, 1),
		add:   cast(bool)slice(instr, 23, 1),
		index: cast(bool)slice(instr, 24, 1)
	);
}

//if P == '0' && W == '0' then SEE "Related encodings";
//CheckDecodeFaults(ExtType_Mve);
//if D == '1' then UNDEFINED;
//d = UInt(D:Qd);
//n = UInt(Rn);
//msize = 32;
//mbytes = msize DIV 8;
//esize = msize;
//elements = 32 DIV esize;
//imm32
//= ZeroExtend(imm:'00', 32);
//index
//= (P == '1');
//add
//= (A == '1');
//wback
//= (W == '1');
//unsigned = TRUE;
//if InITBlock()
//then CONSTRAINED_UNPREDICTABLE;
//if Rn == '1101' && W == '1' then CONSTRAINED_UNPREDICTABLE;
//if Rn == '1111'
//then CONSTRAINED_UNPREDICTABLE;

void
execute_vldrw_t7
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	execute_fp_check(vm);
	// (curBeat, elmtMask) = GetCurInstrBeat();
	instr_beat ib = get_cur_instr_beat(vm);
	// result = Zeros(32);
	// offsetAddr = if add then (R[n] + imm32) else (R[n] - imm32);
	uint offset_addr = instr.add ? (vm.get_reg(instr.rn) + instr.imm) : (vm.get_reg(instr.rn) - instr.imm);
	// address = if index then offsetAddr else R[n];
	uint addr = instr.index ? offset_addr : vm.get_reg(instr.rn);
	// address = address + (curBeat * mbytes * elements);
	addr += (ib.curr_beat *  4 /* instr.mbytes */ * 8 /* instr.elements */);
	// for e = 0 to elements-1
	for (uint e = 0; e < 8 /*instr.elements*/; ++e) {
		// if elmtMask[e*(esize >> 3)] == '1' then
		if (cast(bool)slice(ib.elmt_mask, e * ( /* instr.esize */ 32 >> 3), 1)) {
			// Elem[result, e, esize] = Extend(MemA_MVE[address + (e * mbytes), mbytes], unsigned);

		}
	}
	// The optional write back to the base register is only performed on the
	// last beat of the instruction.
	// if wback && IsLastBeat() then
		// R[n] = offsetAddr;
	// Q[d, curBeat] = result;
}

// VLDRW<v>.<dt> Qd, [Rn{, #+/-<imm>}]
string convert_vldrw_t7_to_string(const ref instr_32 instr, const condition cond) {
	return format("vldrw %s, [%s%s]", get_reg_name(instr.qd),
									  get_reg_name(instr.rn),
									  get_imm_string(instr.imm));
}

instr_32 parse_vctp_t1(const uint instr) {
	// Rn == '1111' then SEE "Related encodings";
	// if !HaveMve() then UNDEFINED;
	// HandleException(CheckCPEnabled(10));
 	// n = UInt(Rn);
	// predSize = UInt(size);
	return instr_32(
		rn: 	   cast(reg)slice(instr, 16, 2),
		pred_size: slice(instr, 20, 2),
		);
	// if InITBlock() then CONSTRAINED_UNPREDICTABLE;
	// if Rn == '1101' then CONSTRAINED_UNPREDICTABLE;
}

void
execute_vctp_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vctp(instr, vm);
}

// Create Vector Tail Predicate. Creates a predicate pattern in VPR.P0 such that 
// any element numbered the value of Rn or greater is predicated. Any element 
// numbered lower than the value of Rn is not predicated. If placed within a VPT 
// block and a lane is predicated, the corresponding VPR.P0 pattern will also be 
// predicated. The generated VPR.P0 pattern can be used by an ensuing predication 
// instruction to apply tail predication on a vector register.
// This instruction is subject to beat-wise execution.
// This instruction is VPT compatible.
// This instruction is not permitted in an IT block.
void
execute_vctp
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// ExecuteFPCheck();
	execute_fp_check(vm);

	// (curBeat, elmtMask) = GetCurInstrBeat();
	instr_beat ib = get_cur_instr_beat(vm);

	// loopCount = R[n];
	uint loop_count = vm.get_reg(instr.rn);
	ushort full_mask;
	if (loop_count <= (1 << (4 - instr.pred_size))) 
		// fullMask = ZeroExtend(Ones(UInt(loopCount[4-predSize:0] : Zeros(predSize))), 16);
		full_mask = cast(ushort)(slice(loop_count, 0, 32 - 4 + instr.pred_size) << instr.pred_size);
	else
		// fullMask = Ones(16);
		full_mask = 0xffff;

	// Elem[VPR.P0, curBeat, 4] = elmtMask AND Elem[fullMask, curBeat, 4];
	ushort val = ib.elmt_mask & elem!(ushort,ushort)(full_mask, ib.curr_beat, 4);
	val = cast(ushort)set_elem(GET_VPR_P0(vm), ib.curr_beat, 4, val);
	SET_VPR_P0(vm, val);
}

// VCTP<v>.<dt> Rn
string convert_vctp_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("vctp %s", get_reg_name(instr.rn));
}

// Loop Clear with Tail Predication. Exits loop mode by invalidating LO_BRANCH_INFO 
// and clears any tail predication being applied.
void
execute_lctp_t1 
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
	// Disable loop predication
	SET_FPSCR_LTPSIZE(vm, 4);
	if (LO_BRANCH_INFO_HIGH_BF_SET(vm))
		CLEAR_LO_BRANCH_INFO_LOW_VALID(vm);
}

instr_32 parse_vmov_t1(const uint instr) {
	return instr_32(
		to_arm_registers: cast(bool)slice(instr, 20, 1),
		rt_2: 			  cast(reg)slice(instr, 16, 4),
		rt:				  cast(reg)slice(instr, 12, 4),
		rm:               cast(reg)((slice(instr, 5, 1) << 4) | slice(instr, 0, 4))                           
		);
}

void 
execute_vmov_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
	if (instr.to_arm_registers) {
		vm.set_reg(instr.rt,   slice(vm.get_reg_d(instr.rm),  0, 32));
		vm.set_reg(instr.rt_2, slice(vm.get_reg_d(instr.rm), 32, 32));
	}
	else {
		vm.set_reg_d(instr.rm, (cast(ulong)vm.get_reg(instr.rt) << 32) | cast(ulong)vm.get_reg(instr.rt_2));
	}
}

void
execute_vscclrm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vscclrm(instr, vm);
}

void
execute_vscclrm_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vscclrm(instr, vm);
}

void
execute_vscclrm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	if (/*HaveMveOrFPExt() &&*/ (GET_FPCCR_S_ASPEN(vm) == 0) || /*(GET_CONTROL_S_SFPA(vm)*/ vm.get_fpca())
		execute_fp_check(vm);
	foreach (r; 0 .. instr.regs) {
		if (instr.single_regs) {
			if ((cast(uint)instr.rm + r) < 32) 
				vm.set_reg_s(cast(reg)(cast(uint)instr.rm + r), 0);
		} else {
			if ((cast(uint)instr.rm + r) < 16)
				vm.set_reg_d(cast(reg)(cast(uint)instr.rm + r), 0);
		}
	}
	// VPR = Zeros(32);
}

void
execute_vldr_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vldr(instr, vm);
}

void
execute_vldr_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vldr(instr, vm);
}

void 
execute_vldr 
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
	uint base;
	if (instr.rn == reg.pc) {
		base = vm.get_pc();
		word_align(base);
	} else {
		base = vm.get_reg(instr.rn);
	}
	uint addr = instr.add ? (base + instr.imm) : (base - instr.imm);
	switch (instr.fp_size) {
		case 16: 
			vm.set_reg_s(instr.rd, cast(uint)vm.read_half_word(addr));
			break;
		case 32:
			vm.set_reg_s(instr.rd, vm.read_word(addr));
			break;
		case 64:
			uint high = vm.read_word(addr + 4);
			uint low  = vm.read_word(addr);
			// D[d] = if BigEndian(address, 8) then word1:word2 else word2:word1;
			vm.set_reg_d(instr.rd, (cast(ulong)high << 32) | cast(ulong)low);
			break;
		default:
			assert(0);
	}
}

// Floating-point Lazy Load Multiple. Floating-point Lazy Load Multiple restores 
// the contents of the Secure Floating-point registers that were protected by a 
// VLSTM instruction, and marks the Floating-point context as active.
// If the lazy state preservation set up by a previous VLSTM instruction is active 
// (FPCCR.LSPACT == 1), this instruction deactivates lazy state preservation and 
// enables access to the Secure Floating-point registers.
// If lazy state preservation is inactive (FPCCR.LSPACT == 0), either because lazy 
// state preservation was not enabled (FPCCR.LSPEN == 0) or because a Floating-point 
// instruction caused the Secure Floating-point register contents to be stored to 
// memory, this instruction loads the stored Secure Floating-point register contents 
// back into the Floating-point registers.
// If Secure Floating-point is not in use (CONTROL_S.SFPA == 0), this instruction 
// behaves as a NOP. This instruction is only available in Secure state, and is 
// UNDEFINED in Non-secure state.
// If the Floating-point Extension and MVE are not implemented, this instruction is 
// available in Secure state, but behaves as a NOP.

bool 
is_aligned(const uint addr, const size_t size) {
	return (addr % size == 0);
}

void
execute_vlldm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vlldm(instr, vm);
}

void
execute_vlldm_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vlldm(instr, vm);
}

void 
execute_vlldm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// if CONTROL_S.SFPA == '1' then
		// Check access to the co-processor is permitted
	// exc = CheckCPEnabled(10);
	// HandleException(exc);
	immutable rn = vm.get_reg(instr.rn);

	if (GET_FPCCR_S_LSPACT(vm) == 1) // state in FP is still valid
		SET_FPCCR_S_LSPACT(vm, 0);
	else {
		if (!is_aligned(rn, 8))
 			SET_UFSR_UNALIGNED(vm, 1);
			// exc = CreateException(UsageFault);
	}
	// HandleException(exc);

	foreach (i; 0 .. 16) 
		vm.set_reg(cast(reg)(cast(uint)reg.s0 + i), vm.read_word(rn + (4 * i)));
	vm.set_fpscr(rn + 0x40);
	vm.set_vpr(rn + 0x44);
	if (GET_FPCCR_S_TS(vm) == 1) {
		foreach (i; 0 .. 16)
			vm.set_reg_s(cast(reg)(cast(uint)reg.s0 +16 + i), vm.read_word(rn + 0x48 + (4*i)));
	}
	vm.set_fpca(true);
}

void
execute_vstr_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vstr(instr, vm);
}

void
execute_vstr_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vstr(instr, vm);
}

void 
execute_vstr
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_fp_check(vm);
	immutable rn   = vm.get_reg(instr.rn);
	immutable addr = instr.add ? (rn + instr.imm) : (rn - instr.imm);
	switch (instr.fp_size) {
		case 16:
			vm.write_half_word(addr, cast(ushort)vm.get_reg_s(instr.rd));
			break;
		case 32:
			vm.write_word(addr, vm.get_reg_s(instr.rd));
			break;
		case 64:
			// Store as two word-aligned words in the correct order for current endianness.
			// bigEndian = BigEndian(address, 8);
			// MemA[address,4] = if bigEndian then D[d][63:32] else D[d][31:0];
			vm.write_word(addr, slice(vm.get_reg_d(instr.rd),  0, 32));
			// MemA[address+4,4] = if bigEndian then D[d][31:0] else D[d][63:32];
			vm.write_word(addr, slice(vm.get_reg_d(instr.rd), 32, 32));
			break;
		default:
			assert(0);
	}
}

// Floating-point Lazy Store Multiple. Floating-point Lazy Store Multiple stores the contents of
// Secure Floating-point registers to a prepared stack frame, and clears the Secure Floating-point 
// registers.
// If Floating-point lazy preservation is enabled (FPCCR.LSPEN == 1), then the next time a 
// Floating-point instruction other than VLSTM or VLLDM is executed:
// 	- The contents of Secure Floating-point registers are stored to memory.
//	- The Secure Floating-point registers are cleared.
// If Secure Floating-point is not in use (CONTROL_S.SFPA == 0), this instruction behaves as a NOP.
// This instruction is only available in Secure state, and is UNDEFINED in Non-secure state.
// If the Floating-point Extension and MVE are not implemented, this instruction is available in 
// Secure state, but behaves as a NOP.
void 
execute_vlstm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vlstm(instr, vm);
}

void 
execute_vlstm_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_vlstm(instr, vm);
}

void 
UPDATE_FPCCR
(vm_t)
(const uint frame_ptr, const bool apply_sp_lin, ref vm_t vm) {
	return;
}

void 
execute_vlstm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// if CONTROL_S_SFPA == '1' then
	// Check access to the co-processor is permitted
	// exc = CheckCPEnabled(10);
	//HandleException(exc);
	immutable rn = vm.get_reg(instr.rn);

	// LSPACT should not be active at the same time as there is active FP
	// state. This is a possible attack senario so raise a SecureFault.
	bool lspact = (GET_FPCCR_S_S(vm) == 1) ? cast(bool)GET_FPCCR_S_LSPACT(vm) : cast(bool)GET_FPCCR_NS_LSPACT(vm);
	if (lspact)
		SET_SFSR_LSERR(vm, 1);
	//exc = CreateException(SecureFault);
	// HandleException(exc);
	// else
	if (!is_aligned(rn, 8))
		SET_UFSR_UNALIGNED(vm, 1);
	//exc = CreateException(UsageFault);
	//HandleException(exc);

	if (GET_FPCCR_LSPEN(vm) == 0)
		foreach (i; 0 .. 15)
			vm.write_word(rn + (4 * i), vm.get_reg_s(cast(reg)(cast(uint)reg.s0 + i)));
	vm.write_word(rn + 0x40, vm.get_fpscr());
	vm.write_word(rn + 0x44 + 4, vm.get_vpr());
	bool push_fp_callee_frame = (GET_FPCCR_TS(vm) == 1);
 	if (push_fp_callee_frame)
	foreach (i; 0 .. 15) 
		vm.write_word(rn + 0x48 + (4 * i), vm.get_reg_s(cast(reg)(cast(uint)reg.s0 + 16 + i)));

	//InvalidateFPRegs(pushFPCalleeFrame, pushFPCalleeFrame);

	if (!instr.low_regs_only)
		foreach(i; 0 .. 31)
				vm.write_word(rn + 0x88 + (4*i), 0);
	else
		UPDATE_FPCCR(rn, false, vm);
	vm.set_fpca(false);
}

// FPDefaultNaN()
// ==============

ulong fp_default_NaN
(size_t N)() {
	static assert([16, 32, 64].canFind(N), "Invalid width N");
	enum int E = (N == 16) ? 5 : (N == 32) ? 8 : 11;
	enum int F = cast(int)N - E - 1;
	const ulong sign = 0UL;
    const ulong exp  = (1UL << E) - 1;
    const ulong frac = 1UL << (F - 1);
	return (sign << (F + E)) | (exp << F) | frac;
}
