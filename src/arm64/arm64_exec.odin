package parse_elf

import "core:testing"

EL0 : u8 = 0b00
EL1 : u8 = 0b01
EL2 : u8 = 0b10
EL3 : u8 = 0b11

// =====
//  REG
// =====

reg :: enum {
	x0,   x1,  x2,  x3,  x4,  x5,  x6,  x7,  x8,  x9, x10, x11, x12, x13, x14, x15,
	x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31,
	sp = x31,  pc,
}

// ---------------------------------------------------------------------------------------
ds :: enum {
	_32 = 32,
	_64 = 64
}

rs :: enum {
	_32 = 32,
	_64 = 64
}
// ---------------------------------------------------------------------------------------
// =============
//  ARM64 INSTR
// =============

arm64_instr :: struct {
    op:        a64_opcode,
    d:                reg,
    n:                reg,
    m:                reg,
    t:                reg,
    t2:   			  reg,
    ext_type: extend_type,
    shift:            u32,
    datasize:          ds,
    regsize:           rs,
    post_index:      bool,
    wback:           bool,
    offset:           i64,
    imm:			  u32,
    shift_t:   shift_type,
    shift_n:          u32,
}
// ---------------------------------------------------------------------------------------
branch_type :: enum {
	dir_call,		// direct branch with link
	ind_call,		// indirect branch with link
	eret,			// exception return (indirect)
	dbg_exit,		// exit from debug state
	ret,			// indirect branch with function return hint
	dir,			// direct branch
	indir,			// indirect branch
	exception,		// exception entry
	reset,			// reset
	unknown,		// other
}

elu_using_aarch_32 :: proc(el: u8) -> bool {
	return false
}

// ELIsInHost()
// ============
// boolean ELIsInHost(bits(2) el)
eli_is_in_host :: proc(vm: ^cortex_a_vm, el: u8) -> bool {
	// if !HaveVirtHostExt() || ELUsingAArch32(EL2) then
		// return FALSE;
	// case el of
	switch (el) {
		// when EL3
		case EL3:
			return false
		// when EL2
		case EL2:
			// return EL2Enabled() && HCR_EL2.E2H == '1';
			return (el2_enabled() && (get_bit(vm, .HCR_EL2, .E2H) == 1)) 
		// when EL1
		case EL1:
			return false
		// when EL0
		case EL0:
			// return EL2Enabled() && HCR_EL2.<E2H,TGE> == '11';
			return (el2_enabled() && ((get_bit(vm, .HCR_EL2, .E2H) == 1) && (get_bit(vm, .HCR_EL2, .TGE) == 1)))
		// otherwise
			// Unreachable();
	}
	return false
}

// EL2Enabled()
// ============
// Returns TRUE if EL2 is present and executing
// - with the PE in Non-secure state when Non-secure EL2 is implemented, or
// - with the PE in Secure state when Secure EL2 is implemented and enabled, or
// - when EL3 is not implemented.
// boolean EL2Enabled()
el2_enabled :: proc() -> bool {
	// return HaveEL(EL2) && (!HaveEL(EL3) || SCR_GEN[].NS == '1' || IsSecureEL2Enabled());
	return true
}

// HaveEL()
// ========
// Return TRUE if Exception level 'el' is supported
// boolean HaveEL(bits(2) el)
have_el :: proc(el: u8) -> bool {
	return true
}

// HaveVirtHostExt()
// =================
// boolean HaveVirtHostExt()
have_virt_host_ext :: proc() -> bool {
	// return HasArchVersion(ARMv8p1);
	return true
}

// S1TranslationRegime()
// =====================
// Stage 1 translation regime for the given Exception level
// bits(2) S1TranslationRegime(bits(2) el)
s1_translation_regime :: proc(vm: ^cortex_a_vm, el: u8) -> u8 {
		// if el != EL0 then return el;
		if el != EL0 {
			return el
		// elsif HaveEL(EL3) && ELUsingAArch32(EL3) && SCR.NS == '0' then
		} else if have_el(EL3) && elu_using_aarch_32(EL3) && 0 == 0 {
			return EL3
		// elsif HaveVirtHostExt() && ELIsInHost(el) then
		} else if have_virt_host_ext() && eli_is_in_host(vm, el) {
			return EL2
		}
		else {
			return EL1
		}
}

// HavePACExt()
// ============
// Returns TRUE if support for the PAC extension is implemented, FALSE otherwise.
// boolean HavePACExt()
has_pac_ext :: proc() -> bool {
	// return HasArchVersion(ARMv8p3);
	return true
}

// EffectiveTBI()
// ==============
// Returns the effective TBI in the AArch64 stage 1 translation regime for "el".
// bit EffectiveTBI(bits(64) address, boolean IsInstr, bits(2) el)
effective_tbi :: proc(vm: ^cortex_a_vm, addr: u64, is_instr: bool, el: u8) -> u8 {
	// bit tbi;
	tbi : u8
	// bit tbid;
	tbid : u8
	// assert HaveEL(el);
	// regime = S1TranslationRegime(el);
	regime := s1_translation_regime(vm, el)
	// assert(!ELUsingAArch32(regime));
	// case regime of
	switch (regime) {
		// when EL1
		case EL1:
			// tbi = if address<55> == '1' then TCR_EL1.TBI1 else TCR_EL1.TBI0;
			tbi = get_bit(vm, .TCR_EL1, .TBI1) if (slice(addr, 55, 1) == 1) else get_bit(vm, .TCR_EL1, .TBI0)
			// if HavePACExt() then
			if has_pac_ext() {
				// tbid = if address<55> == '1' then TCR_EL1.TBID1 else TCR_EL1.TBID0;
				tbid = get_bit(vm, .TCR_EL1, .TBID1) if (slice(addr, 55, 1)) == 1 else get_bit(vm, .TCR_EL1, .TBID0)
			}
		// when EL2
		case EL2:
			// if HaveVirtHostExt() && ELIsInHost(el) then
			if have_virt_host_ext() && eli_is_in_host(vm, el) {
				// tbi = if address<55> == '1' then TCR_EL2.TBI1 else TCR_EL2.TBI0;
				tbi = get_bit(vm, .TCR_EL2, .TBI1) if (slice(addr, 55, 1) == 1) else get_bit(vm, .TCR_EL2, .TBI0)
			}
			//	if HavePACExt() then
			if has_pac_ext() {
				// tbid = if address<55> == '1' then TCR_EL2.TBID1 else TCR_EL2.TBID0;
				tbid = get_bit(vm, .TCR_EL2, .TBID1) if (slice(addr, 55, 1) == 1) else get_bit(vm, .TCR_EL2, .TBID0)
			} else {
				// tbi = TCR_EL2.TBI;
				tbi = get_bit(vm, .TCR_EL2, .TBI)
				// if HavePACExt() then tbid = TCR_EL2.TBID;
				if has_pac_ext() {
					tbid = get_bit(vm, .TCR_EL2, .TBID)
				}
			}
		// when EL3
		case EL3:
			// tbi = TCR_EL3.TBI;
			tbi = get_bit(vm, .TCR_EL3, .TBI)
			// if HavePACExt() then tbid = TCR_EL3.TBID;
			if has_pac_ext() {
				tbid = get_bit(vm, .TCR_EL3, .TBID)
			}
	}
			
	// return (if tbi == '1' && (!HavePACExt() || tbid == '0' || !IsInstr) then '1' else '0');
	return 1 if (tbi == 1 && (!has_pac_ext() || tbid == 0 || !is_instr)) else 0 
}

// AddrTop()
// =========
// Return the MSB number of a virtual address in the stage 1 translation regime for "el".
// If EL1 is using AArch64 then addresses from EL0 using AArch32 are zero-extended to 64 bits.
// integer AddrTop(bits(64) address, boolean IsInstr, bits(2) el)
addr_top :: proc(vm: ^cortex_a_vm, addr: u64, is_instr: bool, el: u8) -> u64 {
	// assert HaveEL(el);
	// regime = S1TranslationRegime(el);
	// if ELUsingAArch32(regime) then
	// AArch32 translation regime.
		// return 31;
	// else {
	// 	if EffectiveTBI(address, IsInstr, el) == '1' then
		if effective_tbi(vm, addr, is_instr, el) == 0b1 {
			return 55
		}
 		else {
			return 63
 		}
 	// }
 }

// AArch64.BranchAddr()
// ====================
// Return the virtual address with tag bits removed for storing to the program counter.
// bits(64) AArch64.BranchAddr(bits(64) vaddress)
aarch64_branch_addr :: proc(vm: ^cortex_a_vm, vaddress: u64) -> u64 {
		// assert !UsingAArch32();
		// msbit = AddrTop(vaddress, TRUE, PSTATE.EL);
		ms_bit := addr_top(vm, vaddress, true, get_pstate_el(vm))
		// if msbit == 63 then return vaddress;
		if ms_bit == 63 {
			return vaddress
		} else if (EL(get_pstate_el(vm)) in (bit_set[EL]{.EL0, .EL1}) || eli_is_in_host(vm, get_pstate_el(vm))) && slice(vaddress, u32(ms_bit), 1) == 0b1 { 
		// IsInHost()
		// ==========
		// boolean IsInHost()
		//		return ELIsInHost(PSTATE.EL); 
		// elsif (PSTATE.EL IN {EL0, EL1} || IsInHost()) && vaddress<msbit> == '1' then return SignExtend(vaddress<msbit:0>);
			return sign_extend(u64, u64(slice(vaddress, u32(ms_bit), u32(64 - ms_bit))))
		} else {
		// else return ZeroExtend(vaddress<msbit:0>);
			return zero_extend(u64, u64(slice(vaddress, u32(ms_bit), u32(64 - ms_bit))))
		}
}

// BranchTo()
// ==========
// Set program counter to a new address, with a branch type.
// Parameter branch_conditional indicates whether the executed branch has a conditional encoding.
// In AArch64 state the address might include a tag in the top eight bits.
// BranchTo(bits(N) target, BranchType branch_type, boolean branch_conditional)
branch_to :: proc(vm: ^cortex_a_vm, target: $T, bt: branch_type, branch_conditional: bool) {
	// Hint_Branch(branch_type);
	// if N == 32 then 
	//		assert UsingAArch32();
	// 		_PC = ZeroExtend(target);
	// else
			// assert N == 64 && !UsingAArch32();
			assert(T == u64)
			// bits(64) target_vaddress = AArch64.BranchAddr(target<63:0>);
			target_addr: u64 = aarch64_branch_addr(vm, target)
			// _PC = target_vaddress;
			set_reg(vm, reg.pc, target_addr)
	// return;
}

parse_ret :: proc(instr: u32) -> arm64_instr {
	return arm64_instr {
		n  		= reg(slice(instr, 5, 5))
	}
}

exec_ret :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// bits(64) target = X[n];
	target := get_reg(vm, instr.n)
	// Value in BTypeNext will be used to set PSTATE.BTYPE
	// BTypeNext = '00';
	// BranchTo(target, BranchType_RET, FALSE);
	branch_to(vm, target, branch_type.ret, false)
}

parse_bl :: proc(instr: u32) -> arm64_instr {
	// bits(64) offset = SignExtend(imm26:'00', 64);
	imm: i64 = i64(slice(instr, 0, 26))
	imm = imm << 2
	return arm64_instr {
		offset		= sign_extend(i64, imm)
	}
}

exec_bl :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// X[30] = PC[] + 4;
	pc: u64 = get_reg(vm, reg.pc, ds._64)
	set_reg(vm, reg.x30, pc + 4, ds._64)
	// BranchTo(PC[] + offset, BranchType_DIRCALL, FALSE);
	branch_to(vm, pc + u64(instr.offset), branch_type.dir_call, false);
}

parse_b_cond :: proc(instr: u32) -> arm64_instr {
	// bits(64) offset = SignExtend(imm19:'00', 64);
	imm := slice(instr, 5, 19)
	imm = imm << 2
	return arm64_instr {
		offset		= sign_extend(i64, imm),
		imm         = slice(instr, 0, 4)	// cond
	}
}

condition_holds :: proc(cond: u8) -> bool {
	// ConditionHolds()
	// ================
	// Return TRUE iff COND currently holds
	// boolean ConditionHolds(bits(4) cond)
	// Evaluate base condition.
	// boolean result;
	// case cond<3:1> of
	// when '000' result = (PSTATE.Z == '1'); // EQ or NE
	// when '001' result = (PSTATE.C == '1'); // CS or CC
	// when '010' result = (PSTATE.N == '1'); // MI or PL
	// when '011' result = (PSTATE.V == '1'); // VS or VC
	// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
	// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
	// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
	// when '111' result = TRUE; // AL
	// Condition flag values in the set '111x' indicate always true
	// Otherwise, invert condition if necessary.
	// if cond<0> == '1' && cond != '1111' then
	// result = !result;
	// return result;
	return true
}

exec_b_cond :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// if ConditionHolds(cond) then
	if (condition_holds(u8(instr.imm))) {
		// BranchTo(PC[] + offset, BranchType_DIR, TRUE);
		branch_to(vm, get_pc(vm) + u64(instr.offset), branch_type.dir, true)
	}
}
// ---------------------------------------------------------------------------------------
// ============
// SignExtend()
// ============
// bits(N) SignExtend(bits(M) x, integer N)
sign_extend :: proc($R: typeid, x: $T) -> R {
	// assert N >= M;
    when size_of(R) < size_of(T) {
        #panic("sign_extend: destination type is smaller than source type");
    }
	// return Replicate(x<M-1>, N-M) : x;
	return cast(R)x;
}

// ============
// ZeroExtend()
// ============
// bits(N) ZeroExtend(bits(M) x, integer N)
zero_extend :: proc($R: typeid, x: $T) -> R {
	// assert N >= M;
	when size_of(R) < size_of(T) {
        #panic("zero_extend: destination type is smaller than source type");
    }
    // return Zeros(N-M) : x;
    when size_of(T) == 1 {
 		return cast(R)cast(u8)x
    } else when size_of(T) == 4 {
        return cast(R)cast(u32)x
    } else when size_of(T) == 8 {
        return cast(R)cast(u64)x
    } else {
        #panic("zero_extend: unsupported integer size");
    }
}

zero_extend_to :: proc(x: $T, regsize: rs) -> u64 {
	if regsize == rs._32 {
        return u64(u32(x)) 
    }
    return u64(x)
}
// ---------------------------------------------------------------------------------------
// =============
//  EXTEND TYPE
// =============

extend_type :: enum {
	sxtb,    
	uxtb,    
	sxth,    
	uxth,    
	sxtw,    
	uxtw,    
	sxtx,    
	uxtx,    
	invalid
}
// ---------------------------------------------------------------------------------------
// ============
//  SHIFT TYPE
// ============

shift_type :: enum {
	lsl,
	lsr,
	asr,
	ror,
	invalid,
}
// ---------------------------------------------------------------------------------------
// ==============
//  DECODE SHIFT
// ==============

decode_shift :: proc(op: u32) -> shift_type {
	switch op {
		case 0b00: return shift_type.lsl
		case 0b01: return shift_type.lsr 
		case 0b10: return shift_type.asr 
		case 0b11: return shift_type.ror
	}
	return shift_type.invalid
}

// ---------------------------------------------------------------------------------------
// =============
//  LEN IN BITS
// =============

len_in_bits :: proc(ext: extend_type) -> u32 {
    switch ext {
        case extend_type.sxtb, extend_type.uxtb: return 8
        case extend_type.sxth, extend_type.uxth: return 16
        case extend_type.sxtw, extend_type.uxtw: return 32
        case extend_type.sxtx, extend_type.uxtx: return 64
        case extend_type.invalid: return 0
    }
    return 0
}
// ---------------------------------------------------------------------------------------
// ========
//  EXTEND
// ========

// bits(N) Extend(bits(M) x, integer N, boolean unsigned)
extend :: proc(x: u32, n: u32, unsigned: bool) -> u64 {
	// return if unsigned then ZeroExtend(x, N) else SignExtend(x, N);
	if (unsigned) {
        return u64(x)
	} else {
		return u64(i64(i32(x)))
	}
}
// ---------------------------------------------------------------------------------------
// =======
//  SLICE
// =======

slice :: proc(val: $T, s: u32, n: u32) -> T {
	return T(val >> s) & T((1 << n) - 1)
}
// ---------------------------------------------------------------------------------------
// ===================
//  DECODE REG EXTEND
// ===================

// ExtendType DecodeRegExtend(bits(3) op)
decode_reg_extend :: proc(op: u32) -> extend_type { 
	// case op of
	switch (op) {
		// when '000' return ExtendType_UXTB;
		case 0b000: return extend_type.uxtb
		// when '001' return ExtendType_UXTH;
		case 0b001: return extend_type.uxth
		// when '010' return ExtendType_UXTW;
		case 0b010: return extend_type.uxtw
		// when '011' return ExtendType_UXTX;
		case 0b011: return extend_type.uxtx
		// when '100' return ExtendType_SXTB;
		case 0b100: return extend_type.sxtb
		// when '101' return ExtendType_SXTH;
		case 0b101: return extend_type.sxth
		// when '110' return ExtendType_SXTW;
		case 0b110: return extend_type.sxtw
		// when '111' return ExtendType_SXTX;
		case 0b111: return extend_type.sxtx
	}
	return extend_type.invalid
}
// ---------------------------------------------------------------------------------------
// ============
//  EXTEND REG
// ============

// bits(N) ExtendReg(integer reg, ExtendType exttype, integer shift, integer N)
extend_reg :: proc(val: u64, ext_type: extend_type, shift: u32, n: u32) -> u64 {
	// assert shift >= 0 && shift <= 4;
	assert(shift >= 0 && shift <= 4)
	// constant bits(N) val = X[reg, N];
	// boolean unsigned;
	unsigned : bool
	// ESize len;
	len      : u32

	// case exttype of
	switch (ext_type) {
		// when ExtendType_SXTB unsigned = FALSE; len = 8;
		case extend_type.sxtb:
		// when ExtendType_SXTH unsigned = FALSE; len = 16;
		case extend_type.sxth:
		// when ExtendType_SXTW unsigned = FALSE; len = 32;
		case extend_type.sxtw:
		// when ExtendType_SXTX unsigned = FALSE; len = 64;
		case extend_type.sxtx: 
			unsigned = false
		// when ExtendType_UXTB unsigned = TRUE; len = 8;
		case extend_type.uxtb:
		// when ExtendType_UXTH unsigned = TRUE; len = 16;
		case extend_type.uxth:
		// when ExtendType_UXTW unsigned = TRUE; len = 32;
		case extend_type.uxtw:
		// when ExtendType_UXTX unsigned = TRUE; len = 64;
		case extend_type.uxtx: 
			unsigned = true
		case extend_type.invalid: 
	        unsigned = false
	}
	len = len_in_bits(ext_type)
	// Sign or zero extend bottom LEN bits of register and shift left by SHIFT
	// constant nbits = Min(len, N);
	nbits   := min(len, n)
	// constant bits(N) extval = Extend(val<nbits-1:0>, N, unsigned);
	ext_val := extend(u32(slice(val, 0, nbits)), n, unsigned)
	// return LSL(extval, shift);
	return lsl(ext_val, shift)
}
// ---------------------------------------------------------------------------------------
// =====
//  LSL
// =====

// bits(N) LSL(bits(N) x, integer shift)
lsl :: proc(x: $T, shift: u32) -> T {
	// assert shift >= 0;
	assert(shift >= 0)
	// bits(N) result;
	// if shift == 0 then
	if (shift == 0) {
		// result = x;
		return x
	} else {
		// (result, -) = LSL_C(x, shift);
		return cast(T) lsl_c(x, shift).result
	}
	// return result;
}
// ---------------------------------------------------------------------------------------
shift_result :: struct {
	result:    u64,
	carry_out: bool
}

// =======
//  LSL C
// =======

// (bits(N), bit) LSL_C(bits(N) x, integer shift)
lsl_c :: proc(x: $T, shift: u32) -> shift_result {
	N: u32 = u32(size_of(T) * 8)  
	// assert shift > 0 && shift < 256;
	assert(shift > 0 && shift < 256)
	// extended_x = x : Zeros(shift);
	extended_x: u64  = u64(x)
	// result = extended_x<N-1:0>;
	result:     u64  = slice(extended_x, shift, N)
	// carry_out = extended_x<N>;
	carry_out:  bool = bool(slice(extended_x, N-1, 1))
	// return (result, carry_out);
	return shift_result{ result = result, carry_out = carry_out}
}
// ---------------------------------------------------------------------------------------
// ======================
//  ADD ITH CARRY RESULT
// ======================

add_with_carry_result :: struct($T: typeid) {
	result: T,
	n     : bool,
	z     : bool,
	c     : bool,
	v     : bool
}

// ================
//  ADD WITH CARRY
// ================

// (bits(N), bits(4)) AddWithCarry(bits(N) x, bits(N) y, bit carry_in)
add_with_carry :: proc(x: $T, y: T, carry_in: bool) -> add_with_carry_result(T) {
	// constant integer unsigned_sum = UInt(x) + UInt(y) + UInt(carry_in);
	unsigned_sum : u64  = u64(x) + u64(y) + u64(carry_in)
	// constant integer signed_sum = SInt(x) + SInt(y) + UInt(carry_in);
	signed_sum   : i64  = i64(x) + i64(y) + i64(u64(carry_in))
	// constant bits(N) result = unsigned_sum<N-1:0>; // same value as signed_sum<N-1:0>
	result       : T    = T(unsigned_sum)
	// constant bit n = result<N-1>;
	n            : bool = bool(slice(result, 31, 1)) 
	// constant bit z = if IsZero(result) then '1' else '0';
	z            : bool = (result == 0)
	// constant bit c = if UInt(result) == unsigned_sum then '0' else '1';
	c            : bool = !bool(u64(result) == unsigned_sum)
	// constant bit v = if SInt(result) == signed_sum then '0' else '1';
	v            : bool = !bool(i64(result) == signed_sum)
	// return (result, n:z:c:v);
	return add_with_carry_result(T){result = result, n = n, z = z, c = c, v = v}
}
// ---------------------------------------------------------------------------------------
// ===============
//  PARSE ADD EXT
// ===============

parse_add_ext :: proc(instr: u32) -> arm64_instr {
	// if imm3 IN {'101', '110', '111'} 
	// then EndOfDecode(Decode_UNDEF);
	return arm64_instr {
		// constant integer d = UInt(Rd);
		d        = reg(slice(instr,  0, 5)),
		// constant integer n = UInt(Rn);
		n        = reg(slice(instr,  5, 5)),
		// constant integer m = UInt(Rm);
		m        = reg(slice(instr, 16, 5)),
		// constant integer shift = UInt(imm3);
		shift    = slice(instr, 10, 3),
		// constant integer datasize = 32 << UInt(sf);
		datasize = ds._32 if slice(instr, 31, 1) == 0 else ds._64,
		// constant ExtendType extend_type = DecodeRegExtend(option);
		ext_type = decode_reg_extend(slice(instr, 13, 3)) 
	}
}
// ---------------------------------------------------------------------------------------
// ========================
//  PARSE STP 64 PRE INDEX
// ========================
// STP <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
parse_stp_64_pre_index :: proc(instr: u32) -> arm64_instr {
	parsed_instr 		    := parse_stp(instr)
	parsed_instr.wback 		 = true
	parsed_instr.post_index  = false
	return parsed_instr
}
// ---------------------------------------------------------------------------------------
// ============
//  PASRSE STP
// ============

parse_stp :: proc(instr: u32) -> arm64_instr {
	// if L:opc<0> == '01' || opc == '11' then UNDEFINED;
	// integer scale = 2 + UInt(opc<1>);
	scale := 2 + slice(instr, 31, 1)
	imm7  := slice(instr, 15, 7)
	return arm64_instr {
		// integer n = UInt(Rn);
		n 		 = reg(slice(instr, 5, 5)),
		// integer t = UInt(Rt);
		t 		 = reg(slice(instr, 0, 5)),
		// integer t2 = UInt(Rt2);
		t2       = reg(slice(instr, 10, 5)),
		// integer datasize = 8 << scale;
		datasize = ds._32 if (8 << scale) == 2 else ds._64,
		// bits(64) offset = LSL(SignExtend(imm7, 64), scale);
		offset   = lsl(sign_extend(i64, imm7), scale),
		// boolean tag_checked = wback || n != 31;
	}
}
// ---------------------------------------------------------------------------------------
// ====================
//  CHECK SP ALIGNMENT
// ====================

check_sp_alignment ::proc() -> bool {
	return true
}
// ---------------------------------------------------------------------------------------
// ============
//  INSTR FLAG
// ============

instr_flag :: enum(u8) {
	wback,
	post_index,
}
// ---------------------------------------------------------------------------------------
// ============
//  CHECK FLAG
// ============

check_flag ::proc(instr: ^arm64_instr, flag: instr_flag) -> bool {
	switch (flag) {
		case instr_flag.wback: 		   return instr.wback
		case instr_flag.post_index:    return instr.post_index
	}
	return false

}
// ---------------------------------------------------------------------------------------
// ==============
//  EXEC STP EXT
// ==============

exec_stp_ext :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	addr : u64
	dbytes : u8 = 4 if instr.datasize == ds._32 else 8
	
	// if HaveMTE2Ext() then SetTagCheckedInstruction(tag_checked);
	
	if instr.n == reg.sp {
		check_sp_alignment();
		addr = get_reg(vm, reg.sp)
	} else {
		addr = get_reg(vm, instr.n)
	}
	if check_flag(instr, instr_flag.post_index) {
		addr += transmute(u64)instr.offset
	}
	// if rt_unknown && t == n then data1 = bits(datasize) UNKNOWN;
	data1 := get_reg(vm, instr.t, instr.datasize)
	// if rt_unknown && t2 == n then ata2 = bits(datasize) UNKNOWN;
	data2 := get_reg(vm, instr.t2, instr.datasize)
	// if HaveLSE2Ext() then
	if has_lse2_ext(vm) {
		// bits(2*datasize) full_data;
		// if BigEndian(AccType_NORMAL) then full_data = data1:data2;
		if true {
		} else {
			// full_data = data2:data1;
			full_data := u64((u64(data2) << 32) | u64(data1))
			// Mem[address, 2*dbytes, AccType_NORMAL, TRUE] = full_data;
			write(vm, addr, 2 * dbytes, acc_type.normal, full_data, true)
		}
	} else {
		// Mem[address, dbytes, AccType_NORMAL] = data1;
		write(vm, addr, dbytes, acc_type.normal, data1)
		// Mem[address+dbytes, dbytes, AccType_NORMAL] = data2;
		write(vm, addr + u64(dbytes), dbytes, acc_type.normal, data2)
	}
	if check_flag(instr, instr_flag.wback) {
		// if postindex then address = address + offset;
		if instr.n == reg.sp { 
			set_reg(vm, reg.sp, addr)
		} else {
			set_reg(vm, instr.n, addr)
		}
	}
}
// ---------------------------------------------------------------------------------------
// ==================
//  PARSE ADD IMM 64
// ==================

// Add (immediate) adds a register value and an optionally-shifted immediate value, and writes the result to the
// destination register.
// This instruction is used by the alias MOV (to/from SP).
// ADD <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
parse_add_imm_64 :: proc(instr: u32) -> arm64_instr {
	sf := slice(instr, 31, 1)
	return arm64_instr {
		// integer d = UInt(Rd);
		d  			= reg(slice(instr, 0, 5)),
		// integer n = UInt(Rn);
		n 			= reg(slice(instr, 5, 5)),
		// integer datasize = if sf == '1' then 64 else 32;
		datasize    = ds._32 if (sf == 0) else ds._64,
		// bits(datasize) imm;
		imm         = slice(instr, 10, 12),
	}
}

// ---------------------------------------------------------------------------------------
// ==============
//  EXEC ADD IMM
// ==============

exec_add_imm :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// bits(datasize) result;
	// bits(datasize) operand1 = if n == 31 then SP[] else X[n];
	op1     := get_reg(vm, instr.n, instr.datasize)
	// (result, -) = AddWithCarry(operand1, imm, '0');
	add_res := add_with_carry(op1, u64(instr.imm), false)
	set_reg(vm, instr.d, add_res.result, instr.datasize)
}
// ---------------------------------------------------------------------------------------
// ========================
//  PARSE ORR SHIFT REG 64
// ========================

// Bitwise OR (shifted register) performs a bitwise (inclusive) OR of a register value and an optionally-shifted register
// value, and writes the result to the destination register.
// This instruction is used by the alias MOV (register).
parse_orr_shift_reg_64 :: proc(instr: u32) -> arm64_instr {
	sf := slice(instr, 31, 1)
	return arm64_instr {
		// integer d = UInt(Rd);
		d 			= reg(slice(instr,  0, 5)),
		// integer n = UInt(Rn);
		n           = reg(slice(instr,  5, 5)),
		// integer m = UInt(Rm);
		m 			= reg(slice(instr, 16, 5)),
		// integer datasize = if sf == '1' then 64 else 32;
		datasize    = ds._32 if (sf == 0) else ds._64,
		// if sf == '0' && imm6<5> == '1' then UNDEFINED;
		// ShiftType shift_type = DecodeShift(shift);
		shift_t     = decode_shift(slice(instr, 22, 2)),
		// integer shift_amount = UInt(imm6);
		shift_n     = slice(instr, 10, 6),
	}
}

orr :: proc(op1: $T, op2: T) -> T {
	return op1 | op2
}

shift_reg :: proc(x: $T, shift_t: shift_type, shift_n: u32) -> T {
	return T(0)
}

exec_orr_shift_reg :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// bits(datasize) operand1 = X[n];
	op1 := get_reg(vm, instr.n, instr.datasize)
	// bits(datasize) operand2 = ShiftReg(m, shift_type, shift_amount);
	op2 := shift_reg(get_reg(vm, instr.n, instr.datasize), instr.shift_t, instr.shift_n)
	// bits(datasize) result;
	// result = operand1 OR operand2;
	res := orr(op1, op2)
	// X[d] = result;
	set_reg(vm, instr.d, res)
}
// ---------------------------------------------------------------------------------------
// ==============
//  EXTEND REG M
// ==============

extend_reg_m :: proc(vm: ^cortex_a_vm, instr: ^arm64_instr) -> u64 {
	m := get_reg(vm, instr.m, ds._64)
	return extend_reg(m, instr.ext_type, instr.shift, u32(instr.datasize))
} 
// ---------------------------------------------------------------------------------------
// ==============
//  EXEC ADD EXT
// ==============

exec_add_ext :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// constant bits(datasize) operand1 = if n == 31 then SP[datasize] else X[n, datasize];
	op1       := get_reg(vm, instr.n, instr.datasize)
    // constant bits(datasize) operand2 = ExtendReg(m, extend_type, shift, datasize);
    op2       := extend_reg_m(vm, instr)
	// bits(datasize) result;
	// (result, -) = AddWithCarry(operand1, operand2, '0');
	add_res   := add_with_carry(op1, op2, false)
	if instr.d == reg.sp {
		// SP[64] = ZeroExtend(result, 64);
		set_sp(vm, u64(add_res.result))
	} else {
		// X[d, datasize] = result;
		set_reg(vm, instr.d, add_res.result, instr.datasize)
	}
}

// ---------------------------------------------------------------------------------------
parse_ldr_reg :: proc(instr: u32) -> arm64_instr {
	scale  := slice(instr, 30, 2)
	option := slice(instr, 13, 3) 
	S 	   := slice(instr, 12, 1)
	return arm64_instr {
		ext_type 	= decode_reg_extend(option),
		shift 		= scale if (S == 1) else 0
	}
}

// ==============
//  EXEC LDR REG
// ==============

exec_ldr_reg :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	dbytes : u8 = 4 if instr.datasize == ds._32 else 8
	m      := get_reg(vm, instr.m, ds._64)
	offset := extend_reg_m(vm, instr)
	addr   : u64
	// if HaveMTE2Ext() then
	// SetTagCheckedInstruction(TRUE);
	if instr.n == reg.sp {
		check_sp_alignment()
		addr = get_reg(vm, reg.sp, ds._64)
	} else {
		addr = get_reg(vm, instr.n, ds._64)
	}
	// address = address + offset;
	addr += transmute(u64)instr.offset
	// bits(datasize) data = Mem[address, datasize DIV 8, AccType_NORMAL];
	data := read(vm, addr, dbytes, acc_type.normal)
	// X[t] = ZeroExtend(data, regsize);
	set_reg(vm, instr.t, zero_extend_to(data, instr.regsize))
}
// ---------------------------------------------------------------------------------------

parse_mov_z_64 :: proc(instr: u32) -> arm64_instr {
	// integer d = UInt(Rd);
	// integer pos;
	// pos = UInt(hw:'0000');
	hw   := slice(instr, 21, 2)
	pos  := (hw << 4)
	imm_ := slice(instr, 5, 16) 
	return arm64_instr {
		d 		= reg(slice(instr, 0, 5)),
		imm     = (imm_ << pos)
	}
}

exec_mov_z_64 :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	set_reg(vm, instr.d, u64(instr.imm), ds._64)
}

parse_subs_imm_32 :: proc(instr: u32) -> arm64_instr {
	return parse_sub_imm_32(instr)
}

parse_subs_imm_64 :: proc(instr: u32) -> arm64_instr {
	return parse_sub_imm_64(instr)
}

parse_subs_imm :: proc(instr: u32) -> arm64_instr {
	// integer d = UInt(Rd);
	// integer n = UInt(Rn);
	// integer datasize = if sf == '1' then 64 else 32;
	// bits(datasize) imm;
	// case sh of
	//		when '0' imm = ZeroExtend(imm12, datasize);
	//		when '1' imm = ZeroExtend(imm12:Zeros(12), datasize);
	return parse_sub_imm(instr)
}


parse_sub_imm_32 :: proc(instr: u32) -> arm64_instr {
	parsed_instr := parse_sub_imm(instr)
	imm := u32(slice(instr, 10, 12))
	parsed_instr.imm = zero_extend(u32, (imm << 12))
	parsed_instr.datasize = ds._32
	return parsed_instr
}

parse_sub_imm_64 :: proc(instr: u32) -> arm64_instr {
	parsed_instr := parse_sub_imm(instr)
	imm := slice(instr, 10, 12)
	parsed_instr.imm = u32(zero_extend(u64, imm))
	parsed_instr.datasize = ds._64 
	return parsed_instr
}

exec_subs_imm :: proc($T: typeid, instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// bits(datasize) result;
	// bits(datasize) operand1 = if n == 31 then SP[] else X[n];
	op1 := T(get_reg(vm, instr.n, instr.datasize))
	// bits(datasize) operand2;
	// bits(4) nzcv;
	// operand2 = NOT(imm);
	op2 := T(~instr.imm)
	// (result, nzcv) = AddWithCarry(operand1, operand2, '1');
	res := add_with_carry(op1, op2, true)
	// PSTATE.<N,Z,C,V> = nzcv;
	set_pstate_nzcv(vm, flags_to_u8(res.n, res.z, res.c, res.v))
	// X[d] = result;
	set_reg(vm, instr.d, u64(res.result), instr.datasize)
}

parse_sub_imm :: proc(instr: u32) -> arm64_instr {
	// integer d = UInt(Rd);
	// integer n = UInt(Rn);
	// integer datasize = if sf == '1' then 64 else 32;
	// bits(datasize) imm;
	// case sh of
	// 		when '0' imm = ZeroExtend(imm12, datasize);
	//		when '1' imm = ZeroExtend(imm12:Zeros(12), datasize);
	
	return arm64_instr {
		d 		 = reg(slice(instr, 0, 5)),
		n 		 = reg(slice(instr, 5, 5)), 
	}
}

exec_sub_imm :: proc($T: typeid, instr: ^arm64_instr, vm: ^cortex_a_vm) {
	// bits(datasize) result;
	// bits(datasize) operand1 = if n == 31 then SP[] else X[n];
	op1 := T(get_reg(vm, instr.n, ds._64))
	// bits(datasize) operand2;
	// operand2 = NOT(imm);
	op2 := T(~instr.imm)
	// (result, -) = AddWithCarry(operand1, operand2, '1');
	res := add_with_carry(op1, op2, true).result
	// if d == 31 then
	// 		SP[] = result;
	// else
	// 		X[d] = result;
	// }
	set_reg(vm, instr.d, res, datasize)
}

// ===============
// HighestSetBit()
// ===============
// integer HighestSetBit(bits(N) x)
highest_set_bit :: proc(x: $T) -> i8  {
	// for i = N-1 downto 0
	//     if x<i> == '1' then return i;
	// return -1;
	i: i8 = i8(size_of(T) * 8) // number of bits in T
	for i - 1 >= 0 {
		if (slice(x, u32(i), 1) == 1) {
			return i
		}
		i = i - 1
	}
	return -1
}

ones := proc(n: u64) -> u64 {
	return (u64(1) << n) - 1
}

// ===========
//  Replicate
// ===========

replicate :: proc(x: u64, esize: u64) -> u64 {
	result: u64 = 0

	for i := u64(0); i < 64; i += esize {
		result |= (x << i)
	}

	return result
}

// =====
//  ROR
// =====

ror :: proc(x: $T, n: T) -> T {
	width := T(size_of(T) * 8)
	r := n % width
	return (x >> r) | (x << (width - r))
}
 
// ================
// DecodeBitMasks()
// ================
// Decode AArch64 bitfield and logical immediate masks which use a similar encoding structure
// (bits(M), bits(M)) DecodeBitMasks(bit immN, bits(6) imms, bits(6) immr, boolean immediate)
decode_bit_masks :: proc($R: typeid, immn: u8, imms: u8, immr: u8, imm: bool) -> (R, R) {
	// bits(64) tmask, wmask;
	// bits(6) tmask_and, wmask_and;
	tmask_and, wmask_and : u8
	// bits(6) tmask_or, wmask_or;
	tmask_or, wmask_or : u8
	// bits(6) levels;
	levels : u8
	// Compute log2 of element size
	// 2^len must be in range [2, M]
	combined := u64((u64(immn) << 6) | u64(~imms))
	// len = HighestSetBit(immN:NOT(imms));
	len := highest_set_bit(combined)
	// if len < 1 then UNDEFINED;
	// assert M >= (1 << len);)
	// Determine S, R and S - R parameters
	// levels = ZeroExtend(Ones(len), 6);
	levels = zero_extend(u8, len)
	// For logical immediates an all-ones value of S is reserved
	// since it would generate a useless all-ones result (many times)
	// if immediate && (imms AND levels) == levels then UNDEFINED;
	// S = UInt(imms AND levels);
	s := u64(u64(imms) & u64(levels))
	// R = UInt(immr AND levels);
	r := u64(u64(immr) & u64(levels))
	// diff = S - R; // 6-bit subtract with borrow
	diff := s - r
	// esize = 1 << len;
	esize := u64(1) << u8(len)
	// d = UInt(diff<len-1:0>);
	d := u64(slice(diff, 0, u32(len)))
	// welem = ZeroExtend(Ones(S + 1), esize);
	welem := ones(s + 1)
	// telem = ZeroExtend(Ones(d + 1), esize);
	telem := ones(d + 1)
	// wmask = Replicate(ROR(welem, R));
	wmask := replicate(ror(welem, r), esize)
	// tmask = Replicate(telem);
	tmask := replicate(telem, esize) 
	return R(wmask), R(tmask)
}

parse_ubfm :: proc(instr: u32) -> arm64_instr { 
	// if sf == '1' && N != '1' then UNDEFINED;
	// if sf == '0' && (N != '0' || immr<5> != '0' || imms<5> != '0') then UNDEFINED;
	return arm64_instr {
		d 		= reg(slice(instr, 0, 5)),
		n 		= reg(slice(instr, 5, 5)),
		imm     = slice(instr, 10, 13)
	}
}

exec_ubfm  :: proc($T: typeid, instr: ^arm64_instr, vm: ^cortex_a_vm) {
	datasize := ds._64 if T == u64 else ds._32
	N    := slice(instr.imm, 12, 1)
	immr := slice(instr.imm,  6, 6)
	imms := slice(instr.imm,  0, 6)
	wmask, tmask := decode_bit_masks(T, u8(N), u8(imms), u8(immr), false)
	// bits(datasize) src = X[n];
	src: T = T(get_reg(vm, instr.n, datasize))
	// perform bitfield move on low bits
	// bits(datasize) bot = ROR(src, R) AND wmask;
	bot: T = T(ror(src, instr.imm))
	// combine extension bits and result bits
	// X[d] = bot AND tmask;
	res: T = bot & tmask;
	set_reg(vm, instr.d, u64(res), datasize)
}

parse_instr :: proc(instr: u32) -> arm64_instr {
	op := get_opcode(instr)
	parsed_instr : arm64_instr
	if (op == a64_opcode.orr_shift_reg_64) {
		parsed_instr = parse_orr_shift_reg_64(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.mov_z_64) {
		parsed_instr = parse_mov_z_64(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.add_ext_64) {
		parsed_instr = parse_add_ext(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.ldr_reg_32) {
		parsed_instr = parse_ldr_reg(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.ubfm_32) {
		parsed_instr = parse_ubfm(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.ret) {
		parsed_instr = parse_ret(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.stp_64_pre_index) {
		parsed_instr = parse_stp_64_pre_index(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.orr_shift_reg_64 || op == a64_opcode.orr_shift_reg_32) {
		parsed_instr = parse_orr_shift_reg_64(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.add_imm_64) {
		parsed_instr = parse_add_imm_64(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.bl) {
		parsed_instr = parse_bl(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.subs_imm_32) {
		parsed_instr = parse_subs_imm_32(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.subs_imm_64) {
		parsed_instr = parse_subs_imm_64(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	if (op == a64_opcode.b_cond) {
		parsed_instr = parse_b_cond(instr)
		parsed_instr.op = op
		return parsed_instr
	}
	assert(false)
	return arm64_instr{};
}

exec_instr :: proc(instr: ^arm64_instr, vm: ^cortex_a_vm) {
	if (instr.op == a64_opcode.mov_z_64) {
		exec_mov_z_64(instr, vm)
		return
	}
	if (instr.op == a64_opcode.add_ext_64) {
		exec_add_ext(instr, vm)
		return
	}
	if (instr.op == a64_opcode.ldr_reg_32) {
		exec_ldr_reg(instr, vm)
		return
	}
	if (instr.op == a64_opcode.ubfm_32) {
		exec_ubfm(u32, instr, vm)
		return
	}
	if (instr.op == a64_opcode.ret) {
		exec_ret(instr, vm)
		return
	}
	if (instr.op == a64_opcode.stp_64_pre_index) {
		exec_stp_ext(instr, vm)
		return
	}
	if (instr.op == a64_opcode.orr_shift_reg_64 || instr.op == a64_opcode.orr_shift_reg_32) {
		exec_orr_shift_reg(instr, vm)
		return
	}
	if (instr.op == a64_opcode.add_imm_64) {
		exec_add_imm(instr, vm)
		return
	}
	if (instr.op == a64_opcode.bl) {
		exec_bl(instr, vm)
		return
	}
	if (instr.op == a64_opcode.subs_imm_32) {
		exec_subs_imm(u32, instr, vm)
		return
	}
	if (instr.op == a64_opcode.subs_imm_64) {
		exec_subs_imm(u64, instr, vm)
		return
	}
	if (instr.op == a64_opcode.b_cond) {
		exec_b_cond(instr, vm)
		return
	}
}

@(test)
execute_ADD_EXT_test :: proc(t: ^testing.T) {
    vm: cortex_a_vm = cortex_a_vm{}
    set_reg(&vm, reg.x0, 0x1000, ds._64)        
    set_reg(&vm, reg.x1, 0x20,   ds._64)          
    instr: arm64_instr
    instr.n        = reg.x0
    instr.m        = reg.x1
    instr.d        = reg.x2
    instr.datasize = ds._64
    instr.ext_type = extend_type.uxtb 
    instr.shift    = 0
    exec_add_ext(&instr, &vm)
    expected: u64 = 0x1000 + 0x20 
    actual:   u64 = get_reg(&vm, reg.x2, ds._64)
    assert(actual == expected)
}

@(test) 
parse_ADD_IMM_64_test :: proc(t: ^testing.T) {
	actual := parse_add_imm_64(0x910003fd)
	expected: arm64_instr
	expected.n   = reg.sp 
	expected.d   = reg.x29
	expected.imm = 0
	expected.datasize = ds._64
	assert(actual == expected)
}

@(test)
parse_ORR_SHIFT_REG_64_test :: proc(t: ^testing.T) {
	// aa0003e3 	mov	x3, x0
	actual := parse_orr_shift_reg_64(0xaa0003e3)
	expected: arm64_instr
	expected.shift_t  = shift_type.lsl
	expected.shift_n  = 0
	expected.imm      = 0
	expected.n        = reg.sp 
	expected.d        = reg.x3
	expected.m        = reg.x0
	expected.datasize = ds._64
	assert(actual == expected)
}

@(test)
REPLICATE_test :: proc(t: ^testing.T) {
	expected: u64 = 0xf0f0f0f0f0f0f0f0
	x: u64 = 0xf0
	assert(expected == replicate(x, 8))
}