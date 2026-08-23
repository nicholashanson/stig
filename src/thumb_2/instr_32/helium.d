import std.format;
import std.algorithm : canFind;
import std.typecons : Tuple, tuple;
import std.algorithm;

import thumb_2_floating_point_ext_32;
import thumb_2_execute_instr;
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
instr_beat 
get_cur_instr_beat
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

enum fp_exception {
	invalid_op,
	divide_by_zero,
	overflow,
	underflow,
	inexact,
	input_denorm,
}

void 
fp_process_exception
(vm_t)
(fp_exception exc, fpscr_t fpscr_val, ref vm_t vm) {
	// Get appropriate FPSCR bit numbers.
	uint enable;
	switch (exc) {
		case fp_exception.invalid_op:
			enable = 8;
			SET_FPSCR_IOC(vm);
			break;
		case fp_exception.divide_by_zero: 
			enable = 9;
			SET_FPSCR_DZC(vm);
			break;
		case fp_exception.overflow:
			enable = 10; 
			SET_FPSCR_OFC(vm);
			break;
		case fp_exception.underflow:
			enable = 11;
			SET_FPSCR_UFC(vm);
			break;
		case fp_exception.inexact:
			enable = 12; 
			SET_FPSCR_IXC(vm);
			break;
		case fp_exception.input_denorm:
			enable = 15;
			SET_FPSCR_IDC(vm);
			break;
		default:
			assert(0);
	}
	// if fpscr_val[enable] == '1' then
	// IMPLEMENTATION_DEFINED "floating-point trap handling";
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

enum fp_type : ubyte {
	zero, non_zero, infinity, QNaN, SNaN,
}

struct unpacked_fp {
	fp_type fpt;
	bool    sign_bit;
	double  val;
}

alias fpscr_t = uint;

fpscr_t 
get_standard_fpscr_val
(vm_t)
(ref vm_t vm) {
	return (((cast(uint)FPSCR_AHP_SET(vm) << 2) | 0b11) << 23) | (cast(uint)FPSCR_FZ16_SET(vm) << 19);
}

unpacked_fp 
fp_unpack_base
(T,size_t N,vm_t)
(T fp_val, fpscr_t fpscr_val, ref vm_t vm) {
	static assert([16, 32, 64].canFind(N), "Invalid width N");
	double  val;
	fp_type fpt;
	bool sign;
	if (N == 16) {
		sign         = cast(bool)slice(fp_val, 15, 1);
		uint exp_16  = slice(fp_val, 10, 5);
		uint frac_16 = slice(fp_val,  0, 9);
		if (exp_16 == 0) {
			// Produce zero if value is zero or flush-to-zero is selected.
			if (frac_16 == 0 || /* fpscr_val.FZ16 == '1'*/ cast(bool)slice(fpscr_val, 19, 1)) {
				fpt = fp_type.zero; 
				val = 0;
			} else {
				fpt = fp_type.non_zero; 
				val = (2.0 ^^ -14  * (cast(double)frac_16 * 2.0 ^^ - 10));
			}
		} else if (matches(exp_16, 0b11111, 0b11111) && /* fpscr_val.AHP */ cast(bool)slice(fpscr_val, 25, 1)) { // Infinity or NaN in IEEE format
			if (frac_16 == 0) {
				fpt   = fp_type.infinity; 
				val = 2.0 ^^ 1000000;
			} else {
				fpt = (cast(bool)slice(frac_16, 9, 1)) ? fp_type.QNaN : fp_type.SNaN;
				val = 0;
			}
		} else {
			fpt = fp_type.non_zero;
			val = 2.0 ^^ (exp_16 - 15) * (1.0 + cast(double)frac_16 * 2.0 ^^ -10);
		}
	} else if (N == 32) {
		sign    = cast(bool)slice(fp_val, 31, 1);
		uint exp_32  = slice(fp_val, 23,  8);
		uint frac_32 = slice(fp_val,  0, 23);
		if (exp_32 == 0) {
			// Produce zero if value is zero or flush-to-zero is selected.
			if ((frac_32 == 0) || /* fpscr_val.FZ16 == '1'*/ cast(bool)slice(fpscr_val, 24, 1)) {
				fpt = fp_type.zero; 
				val = 0;
				if (frac_32 != 0) { // Denormalized input flushed to zero
					// FPProcessException(FPExc_InputDenorm, fpscr_val, predicated);
					fp_process_exception(fp_exception.input_denorm, fpscr_val, vm);
				}
			} else {
				fpt = fp_type.non_zero; 
				val = 2.0 ^^ -126 * (cast(double)frac_32 * 2.0 ^^ - 23);
			}
		} else if (matches(exp_32, 0b1111_1111, 0b1111_1111)) {
 				if (frac_32 == 0) {
					fpt = fp_type.infinity; 
					val = 2.0 ^^ 1000000;
				} else {
					fpt = (cast(bool)slice(frac_32, 22, 1)) ? fp_type.QNaN : fp_type.SNaN;
					val = 0;
				}
		} else {
			fpt = fp_type.non_zero;
			val = 2.0 ^^ (exp_32 - 127) * (1.0 + cast(double)frac_32 * 2.0 ^^ - 23);
		}
	} else { // N == 64.
		sign     	  = cast(bool)slice(fp_val, 63, 1);
		uint  exp_64  = slice(fp_val, 52, 11);
		ulong frac_64 = slice(fp_val,  0, 52);
		if (exp_64 == 0) { 
			// Produce zero if value is zero or flush-to-zero is selected.
			if ((frac_64 == 0) || /* fpscr_val.FZ16 == '1'*/ cast(bool)slice(fpscr_val, 19, 1)) {
				fpt = fp_type.zero; 
				val = 0;
			}
			if (frac_64 != 0) { // Denormalized input flushed to zero
				// FPProcessException(FPExc_InputDenorm, fpscr_val, predicated);
			} else {
				fpt = fp_type.non_zero;
				val = 2.0 ^^ - 1022 * (cast(double)frac_64 * 2.0 ^^ -52);
			}
		} else if (matches(exp_64, 0b111_1111_1111, 0b111_1111_1111)) {
			if (frac_64 == 0) {
				fpt = fp_type.infinity;
				val = 2.0 ^^ 1000000;
			} else {
				fpt = cast(bool)slice(frac_64, 51, 1) ? fp_type.QNaN : fp_type.SNaN;
				val = 0;
			}
		} else {
			fpt = fp_type.non_zero;
			val = 2.0 ^^ (exp_64 - 1023) * (1.0 + cast(double)frac_64 * 2.0 ^^ -52);
		}
	}
	if (sign) 
		val = -1 * val;
	return unpacked_fp(fpt: fpt, sign_bit: sign, val: val);
}

// ================
//  FPDefaultNaN()
// ================

I fp_default_NaN
(I,size_t N)() {
	static assert([16, 32, 64].canFind(N), "Invalid width N");
	enum int E = (N == 16) ? 5 : (N == 32) ? 8 : 11;
	enum int F = cast(int)N - E - 1;
	const I sign = cast(I)0UL;
    const I exp  = cast(I)((1UL << E) - 1);
    const I frac = cast(I)(1UL << (F - 1));
	return cast(I)((sign << (F + E)) | (exp << F) | frac);
}

T 
fp_add
(T,I,size_t N,vm_t)
(T op1, T op2, bool fpscr_controlled, ref vm_t vm) {
	static assert([16, 32, 64].canFind(T.sizeof * 8), "Invalid width");
	const uint fpscr_val = (fpscr_controlled) ? vm.get_fpscr() : get_standard_fpscr_val(vm);
	auto unpacked_fp_1 = fp_unpack_base!(I,N)(cast(I)op1, fpscr_val, vm);
	auto unpacked_fp_2 = fp_unpack_base!(I,N)(cast(I)op2, fpscr_val, vm);

	auto n = fp_process_NaNs!(T,I)(unpacked_fp_1.fpt, unpacked_fp_2.fpt, op1, op2, fpscr_val, vm);
	bool done = n[0];
	T result = n[1];
	T result_value;
	bool result_sign;
	
	if (!done) {
		bool sign_1 = unpacked_fp_1.sign_bit;
		bool sign_2 = unpacked_fp_2.sign_bit;
		bool inf_1  = (unpacked_fp_1.fpt == fp_type.infinity); 
		bool inf_2  = (unpacked_fp_2.fpt == fp_type.infinity);
 		bool zero_1 = (unpacked_fp_1.fpt == fp_type.zero); 
 		bool zero_2 = (unpacked_fp_2.fpt == fp_type.zero);
		if (inf_1 && inf_2 && (sign_1 == !sign_2)) {
			result = fp_default_NaN!(I,N)();
			fp_process_exception(fp_exception.invalid_op, fpscr_val, vm);
		} else if ((inf_1 && !sign_1) || (inf_2 && !sign_2)) {
			result = fp_infinity!(T,N)(false);
		} else if ((inf_1 && sign_1) || (inf_2 && sign_2)) { 
			result = fp_infinity!(T,N)(true);
		} else if (zero_1 && zero_2 && (sign_1 == sign_2)) { 
			result = fp_zero!(T,N)(sign_1);
		} else { 
			result_value = unpacked_fp_1.val + unpacked_fp_2.val;
			if (result_value == 0.0) { // Sign of exact zero result depends on rounding mode
				result_sign = (cast(rmode)GET_FPSCR_RMode(vm, fpscr_val) == rmode.rm) 
					  		? true : false;
				result = fp_zero!(T,N)(result_sign);
			} else {
				result = fp_round!(T,T,N)(result_value, fpscr_val, vm);
			}
		}
	}
	return result;
}

T 
fp_sub
(T,I,size_t N,vm_t)
(T op1, T op2, bool fpscr_controlled, ref vm_t vm) {
	static assert([16, 32, 64].canFind(T.sizeof * 8), "Invalid width");
	const uint fpscr_val = (fpscr_controlled) ? vm.get_fpscr() : get_standard_fpscr_val(vm);
	auto unpacked_fp_1 = fp_unpack_base!(I,N)(cast(I)op1, fpscr_val, vm);
	auto unpacked_fp_2 = fp_unpack_base!(I,N)(cast(I)op2, fpscr_val, vm);

	auto n = fp_process_NaNs!(T,I)(unpacked_fp_1.fpt, unpacked_fp_2.fpt, op1, op2, fpscr_val, vm);
	bool done = n[0];
	T result = n[1];
	T result_value;
	bool result_sign;
	
	if (!done) {
		bool sign_1 = unpacked_fp_1.sign_bit;
		bool sign_2 = unpacked_fp_2.sign_bit;
		bool inf_1  = (unpacked_fp_1.fpt == fp_type.infinity); 
		bool inf_2  = (unpacked_fp_2.fpt == fp_type.infinity);
 		bool zero_1 = (unpacked_fp_1.fpt == fp_type.zero); 
 		bool zero_2 = (unpacked_fp_2.fpt == fp_type.zero);
		if (inf_1 && inf_2 && (sign_1 == sign_2)) {
			result = fp_default_NaN!(I,N)();
			fp_process_exception(fp_exception.invalid_op, fpscr_val, vm);
		} else if ((inf_1 && !sign_1) || (inf_2 && sign_2)) {
			result = fp_infinity!(T,N)(false);
		} else if ((inf_1 && sign_1) || (inf_2 && !sign_2)) { 
			result = fp_infinity!(T,N)(true);
		} else if (zero_1 && zero_2 && (sign_1 == !sign_2)) { 
			result = fp_zero!(T,N)(sign_1);
		} else { 
			result_value = unpacked_fp_1.val - unpacked_fp_2.val;
			if (result_value == 0.0) { // Sign of exact zero result depends on rounding mode
				result_sign = (cast(rmode)GET_FPSCR_RMode(vm, fpscr_val) == rmode.rm) 
					  		? true : false;
				result = fp_zero!(T,N)(result_sign);
			} else {
				result = fp_round!(T,T,N)(result_value, fpscr_val, vm);
			}
		}
	}
	return result;
}

// ================
//  FPProcessNaN()
// ================

T 
fp_process_NaN
(T,I,vm_t)
(ref fp_type fpt, T operand, fpscr_t fpscr_val, ref vm_t vm) {
	enum N = T.sizeof * 8;
	uint top_frac;
	static assert([16, 32, 64].canFind(N), "Invalid width");
	top_frac = (N == 16) ? 9 : (N == 32) ? 22 : 51;
	I res = cast(I)operand;
	if (fpt == fp_type.SNaN) {
		res |= (1 << top_frac);
		fp_process_exception(fp_exception.invalid_op, fpscr_val, vm);
	}
	if (cast(bool)GET_FPSCR_DN(vm, fpscr_val)) // DefaultNaN requested 
		res = fp_default_NaN!(I,N)();
	return cast(T)res;
}

// =================
//  FPProcessNaNs()
// =================
// The boolean part of the return value says whether a NaN has been found and
// processed. The bits(N) part is only relevant if it has and supplies the
// result of the operation.
//
// The 'fpscr_val' argument supplies FPSCR control bits. Status information is
// updated directly in FPSCR where appropriate.
Tuple!(bool,T) 
fp_process_NaNs
(T,I,vm_t)
(fp_type type_1, fp_type type_2, T op_1, T op_2, const uint fpscr_val, ref vm_t vm) {
	//static assert([16, 32, 64].canFind(N), "Invalid width");
	bool done;
	T res;
	if (type_1 == fp_type.SNaN) {
		done = true;
		res  = fp_process_NaN!(T,I)(type_1, op_1, fpscr_val, vm);
	} else if (type_2 == fp_type.SNaN) {
		done = true;
		res  = fp_process_NaN!(T,I)(type_2, op_2, fpscr_val, vm);
	} else if (type_1 == fp_type.QNaN) {
		done = true; 
		res  = fp_process_NaN!(T,I)(type_1, op_1, fpscr_val, vm);
	} else if (type_2 == fp_type.QNaN) {
		done = true; 
		res  = fp_process_NaN!(T,I)(type_2, op_2, fpscr_val, vm);
	} else {
		done = false; 
		res  = 0; // 'Don't care' result
	}
	return tuple(done, res);
}

uint 
get_Q
(vm_t)
(const reg r, const uint beat, ref vm_t vm) {
	assert((beat >= 0) && (beat <= 3));
	return (beat > 1) ? 
		slice(vm.get_reg_q(r).high, 32 * (beat - 2), 32) :
		slice(vm.get_reg_q(r).low,  32 * beat,       32);
}

instr_32
parse_vcadd_t1
(const uint instr) {
	const uint esize = (slice(instr, 20, 1) == 0) ? 16 : 32;
	return instr_32(
		rd: 		cast(reg)((slice(instr, 22, 1) << 3) | slice(instr, 13, 3)),
		rm: 		cast(reg)((slice(instr,  5, 1) << 3) | slice(instr,  1, 3)),
		rn:     	cast(reg)((slice(instr,  7, 1) << 3) | slice(instr, 17, 3)),
		esize:  	esize,
		elements:	32 / esize
	);
}

void 
execute_vcadd_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	auto ib = get_cur_instr_beat(vm);
	auto op_1 = get_Q(instr.qn, ib.curr_beat, vm);
	auto op_2 = get_Q(instr.qm, ib.curr_beat, vm);

	uint res;
	if (instr.esize == 32) {
		switch ((instr.rot << 1) | slice(ib.curr_beat, 0, 1)) {
			case 0b00: 
				res = cast(uint)fp_sub!(float,uint,32)(get_Q(instr.rn, ib.curr_beat, vm),
							 				 		   get_Q(instr.rm, ib.curr_beat + 1, vm), false, vm);
				break;
			case 0b01: 
				res = cast(uint)fp_add!(float,uint,32)(get_Q(instr.rn, ib.curr_beat, vm), 
							 				           get_Q(instr.rm, ib.curr_beat - 1, vm), false, vm);
				break;
			case 0b10: 
				res = cast(uint)fp_add!(float,uint,32)(get_Q(instr.rn, ib.curr_beat, vm), 
							 				           get_Q(instr.rm, ib.curr_beat + 1, vm), false, vm);
				break;
			case 0b11: 
				res = cast(uint)fp_sub!(float,uint,32)(get_Q(instr.rn, ib.curr_beat, vm), 
							 				 		   get_Q(instr.rm, ib.curr_beat - 1, vm), false, vm);
				break;
			default:
				assert(0);
		}
	}
	else {
		uint val;
		op_1 = get_Q(instr.rn, ib.curr_beat, vm);
		op_2 = get_Q(instr.rm, ib.curr_beat, vm);
		foreach (e; 0 .. instr.elements) {
			// Avoid Floating-point exceptions on a predicated lane by checking the element mask
			bool pred = (slice(ib.elmt_mask, e * (instr.esize >> 3), 1) == 0);
			switch ((instr.rot << 1) | slice(e, 0, 1)) {
				case 0b00: 
					val = cast(uint)fp_sub!(float,uint,32)(elem!(uint)(op_1, e, instr.esize), 
												 		   elem!(uint)(op_2, e + 1, instr.esize), false, vm);
					break;
				case 0b01: 
					val = cast(uint)fp_add!(float,uint,32)(elem!(uint)(op_1, e, instr.esize), 
												 		   elem!(uint)(op_2, e - 1, instr.esize), false, vm);
					break;
				case 0b10: 
					val = cast(uint)fp_add!(float,uint,32)(elem!(uint)(op_1, e, instr.esize), 
												 		   elem!(uint)(op_2, e + 1, instr.esize), false, vm);
					break;
				case 0b11:
					val = cast(uint)fp_sub!(float,uint,32)(elem!(uint)(op_1, e, instr.esize), 
														   elem!(uint)(op_2, e - 1, instr.esize), false, vm);
					break;
				default:
					assert(0);
			}
			set_elem(res, e, instr.esize, val);
		}
	}
	
	foreach (e; 0 .. 4) {
		if (slice(ib.elmt_mask, e, 1) == 1) {
			auto v = set_elem(get_Q(instr.rn, ib.curr_beat, vm), e, 8, elem!(uint)(res, e, 8));
			vm.set_reg_s(q_to_s(instr.rn, e), v);
		}
	}
}

ulong 
round_down
(T)
(T val) pure nothrow @nogc {
    return cast(ulong)val;
}

enum rmode {
	rn, 
	rp, 
	rm,
	rz,
}

// ===============
//  FPRoundBase()
// ===============
// The 'fpscr_val' argument supplies FPSCR control bits. Status information is
// updated directly in FPSCR where appropriate.
R
fp_round_base
(R,T,size_t N,vm_t)
(T val, fpscr_t fpscr_val, ref vm_t vm) {
	static assert((R.sizeof * 8) == N);
 	static assert([16, 32, 64].canFind(N), "Invalid width");
	assert(val != 0);
	// Obtain format parameters - minimum exponent, numbers of exponent and fraction bits.
	enum int E 	 	= (N == 16) ? 5 : (N == 32) ? 8 : 11;
	int minimum_exp = 2 - 2 ^^ (E - 1);
	int F 			= N - E - 1;

	// Split value into sign, unrounded mantissa and exponent.
	bool sign;
	T mantissa;
	if (val < 0) {
		sign = true; 
		mantissa = -val;
	} else {
		sign = false; 
		mantissa = val;
	}
	uint exponent = 0;
	while (mantissa < 1.0) {
		mantissa = mantissa * 2.0; 
		exponent = exponent - 1;
	}
	while (mantissa >= 2.0) {
		mantissa = mantissa / 2.0; 
		exponent = exponent + 1;
	}

	R res;
	uint biased_exp;
	// Deal with flush-to-zero.
	if ((((N != 16) && cast(bool)slice(fpscr_val, 24, 1)) || ((N == 16) && cast(bool)slice(fpscr_val, 24, 1))) && (exponent < minimum_exp)) {
		res = 0;
		SET_FPSCR_UFC(vm); // Flush-to-zero never generates a trapped exception.
	} else {
		// Start creating the exponent value for the result. Start by biasing the actual
		// exponent so that the minimum exponent becomes 1, lower values 0 (indicating
		// possible underflow).
		biased_exp = max(exponent - minimum_exp + 1, 0);
		if (biased_exp == 0) 
			mantissa = mantissa / 2.0 ^^ (minimum_exp - exponent);

		// Get the unrounded mantissa as an integer, and the "units in last place"
		// rounding error.
		auto mant = round_down(mantissa * 2.0 ^^ F); // if biased_exp == 0, < 2.0^F otherwise >= 2.0^F
		T error = mantissa * 2.0 ^^ F - T(mant);
	
		// Underflow occurs if exponent is too small before rounding, and result is inexact
		// or the Underflow exception is trapped.
		if ((biased_exp == 0) && (error != 0.0))
			fp_process_exception(fp_exception.underflow, fpscr_val, vm);

		T round_up;
		bool overflow_to_inf;
		// Round result according to rounding mode.
		switch (cast(rmode)GET_FPSCR_RMode(vm, fpscr_val)) {
			case rmode.rn: // round to nearest (rounding to even if exactly halfway)
				round_up = (error > 0.5 || (error == 0.5 && cast(bool)slice(mant, 0, 1)));
				overflow_to_inf = true;
				break;
			case rmode.rp: // round towards plus infinity
				round_up = ((error != 0.0) && !sign);
				overflow_to_inf = !sign;
				break;
			case rmode.rm: // round towards minus infinity
				round_up = ((error != 0.0) && sign);
				overflow_to_inf = sign;
				break;
			case rmode.rz: // round towards zero
				round_up = false;
				overflow_to_inf = false;
				break;
			default: 
				assert(0);
		}

		if (round_up) 
			mant = mant + 1;
		if (mant == 2 ^^ F) // rounded up from denormalized to normalized
			biased_exp = 1;
		if (mant == 2 ^^ (F + 1)) { // rounded up to next exponent
			biased_exp = biased_exp + 1; 
			mant = mant / 2;
		}

		// Deal with overflow and generate result.
		if ((N != 16) || !cast(bool)GET_FPSCR_AHP(vm, fpscr_val)) { // Single, double or IEEE half precision
			if (biased_exp >= (2 ^^ (E - 1))) { 
				res = (overflow_to_inf) ? fp_infinity!(R,N)(sign) : fp_max_normal!(R,N)(sign);
 				fp_process_exception(fp_exception.overflow, fpscr_val, vm);
				error = 1.0; // Ensure that an Inexact exception occurs
			} else {
				res = cast(R)((cast(ulong)sign << (N - 1)) | (slice(biased_exp, 0, E - 1) << (F - 1)) | slice(mant, 0, F - 1));
			}
		} else { // Alternative half precision
			if (biased_exp >= (2 ^^ E)) {
				res = cast(R)((cast(ulong)sign << (N - 1)) | ((1 << (N - 1)) - 1));
				fp_process_exception(fp_exception.invalid_op, fpscr_val, vm);
				error = 0.0; // Ensure that an Inexact exception does not occur
			} else {
				res = cast(R)((cast(ulong)sign << (N - 1)) | (slice(biased_exp, 0, E - 1) << (F - 1)) | slice(mant, 0, F - 1));
			}
		}
		// Deal with Inexact exception.
		if (error != 0.0) {
			fp_process_exception(fp_exception.inexact, fpscr_val, vm);
		}
	}

	return res;
}

Tuple!(bool,bool) 
is_cp_enabled
(vm_t)
(int cp, bool privileged, bool secure, ref vm_t vm) {
	// Check Coprocessor Access Control Register for permission to use coprocessor.
	bool enabled;
	bool force_to_secure = false;

	switch (get_bit_val!("CPACR", "CP")(vm, cp)) {
		case 0b00:
			enabled = false;
			break;
		case 0b01:
			enabled = privileged;
			break;
		case 0b10:
			assert(0);
		case 0b11:
			enabled = true;
			break;
		default:
			assert(0);
	}

	if (enabled /*&& HaveSecurityExt()*/) {
		// Check if access is forbidden by NSACR.
		if (!secure && (get_bit_val!("NSACR", "CP")(vm, cp) == 0)) {
			enabled = false;
			force_to_secure = true;
		}
		// Check if the coprocessor state unknown flag.
		if (enabled && (get_bit_val!("CPPWR_S", "SU")(vm, cp) == 1)) {
			enabled = false;
			// Check SUS bit to determine the target state of any fault.
			force_to_secure = (get_bit_val!("CPPWR_S", "SUS")(vm, cp) == 1);
		}
	}
	return tuple(enabled, secure || force_to_secure);
}

// ===============
//  FPMaxNormal()
// ===============

R 
fp_max_normal
(R,size_t N)
(bool sign) {
	static assert([16, 32, 64].canFind(N), "Invalid width");
	enum int E = (N == 16) ? 5 : (N == 32) ? 8 : 11;
	enum int F = N - E - 1;
	ulong exp;
	ulong frac;
	exp  = ((1UL << (E - 1)) - 1) << 1;
	frac = (1UL << F) - 1;
	return cast(R)((cast(ulong)sign << (N - 1)) | (exp << F) | frac);
}

// ==============
//  FPInfinity()
// ==============

R 
fp_infinity
(R,size_t N)
(bool sign) {
	static assert([16, 32, 64].canFind(N), "Invalid width");
	enum int E = (N == 16) ? 5 : (N == 32) ? 8 : 11;
	enum int F = N - E - 1;
	ulong exp;
	ulong frac;
	exp  = ((1UL << E) - 1);
	return cast(R)((cast(ulong)sign << (N - 1)) | (exp << F));
}

// ==========
//  FPZero()
// ==========

R
fp_zero
(R,size_t N)
(bool sign) {
	static assert([16, 32, 64].canFind(N), "Invalid width");
	return cast(R)((cast(ulong)sign << (N - 1)));
}

// =========
// Used by data processing and int/fixed <-> floating-point conversion instructions.
// For half-precision data it ignores AHP, and observes FZ16.

R 
fp_round
(T,R,size_t N,vm_t)
(T value, fpscr_t fpscr_val, ref vm_t vm) {
	return fp_round!(T,R,N)(value, fpscr_val, false, vm);
}

R 
fp_round
(T,R,size_t N,vm_t)
(T value, fpscr_t fpscr_val, bool predicated, ref vm_t vm) {
	SET_FPSCR_AHP(vm, fpscr_val, 0);
	return fp_round_base!(T,R,N)(value, fpscr_val, vm);
}
