package parse_elf

import "core:testing"

// =====
//  REG
// =====

reg :: enum {
	x0, 
	x1, 
	x2,
	x3,
	x4,
	x5,
	x6,
	x7,
	x8,
	x9,
	x10, 
	x11,
	x12,
	x13,
	x14,
	x15,
	x16,
	x17,
	x18,
	x19,
	x20,
	x21,
	x22,
	x23,
	x24,
	x25,
	x26,
	x27,
	x28,
	x29,
	x30,
	x31
}

ds :: enum {
	_32 = 32,
	_64 = 64
}
// ---------------------------------------------------------------------------------------
// =============
//  ARM64 INSTR
// =============

arm64_instr :: struct {
    d:                reg,
    n:                reg,
    m:                reg,
    ext_type: extend_type,
    shift:            u32,
    datasize:          ds
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
		return lsl_c(x, shift).result
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

// ===============
//  ADD ITH CARRY
// ===============

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
// ==============
//  EXEC ADD EXT
// ==============

exec_add_ext :: proc(instr: arm64_instr, vm: ^cortex_a_vm) {
	// constant bits(datasize) operand1 = 
	// if n == 31 
	// then SP[datasize] else X[n, datasize];
	op1       := get_reg(vm, instr.n, instr.datasize)
    // constant bits(datasize) operand2 = 
    // ExtendReg(m, extend_type, shift, datasize);
    unext_op2 := get_reg(vm, instr.m) 
    op2       := extend_reg(unext_op2, instr.ext_type, instr.shift, u32(instr.datasize))
	// bits(datasize) result;
	// (result, -) = AddWithCarry(operand1, operand2, '0');
	add_res   := add_with_carry(op1, op2, false)
	// if d == 31 then
	if (instr.d == reg.x31) {
		// SP[64] = ZeroExtend(result, 64);
		set_sp(vm, u64(add_res.result))
	} else {
		// X[d, datasize] = result;
		set_reg(vm, instr.d, add_res.result, instr.datasize)
	}
}
// ---------------------------------------------------------------------------------------

@(test)
decode_ADD_EXT_test :: proc(t: ^testing.T) {
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
    exec_add_ext(instr, &vm)
    expected: u64 = 0x1000 + 0x20 
    actual:   u64 = get_reg(&vm, reg.x2, ds._64)
    assert(actual == expected)
}