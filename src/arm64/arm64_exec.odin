package parse_elf

import "core:testing"

// =====
//  REG
// =====

reg :: enum {
	x0,   x1,  x2,  x3,  x4,  x5,  x6,  x7,  x8,  x9, x10, x11, x12, x13, x14, x15,
	x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31,
	sp = x31,
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

add_with_carry_result :: struct {
	result: u64,
	n     : bool,
	z     : bool,
	c     : bool,
	v     : bool
}

// ================
//  ADD WITH CARRY
// ================

// (bits(N), bits(4)) AddWithCarry(bits(N) x, bits(N) y, bit carry_in)
add_with_carry :: proc(x: $T, y: T, carry_in: bool) -> add_with_carry_result {
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
	return add_with_carry_result{result = result, n = n, z = z, c = c, v = v}
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

check_flag ::proc(instr: arm64_instr, flag: instr_flag) -> bool {
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

exec_stp_ext :: proc(instr: arm64_instr, vm: ^cortex_a_vm) {
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

exec_orr_shift_reg :: proc(instr: arm64_instr, vm: ^cortex_a_vm) {
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
	assert(false)
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