import std.format;
import std.conv    : to, ConvException, parse;
import std.array;
import std.algorithm;

import thumb_2_opcodes;
import cortex_m_core;

// ---------------------------------------- Shift ----------------------------------------

// ============
//  SHIFT TYPE
// ============

enum shift_type : ubyte {
	lsl,
	lsr,
	asr,
	rrx,
	ror,
	none,
	invalid
}

// ================
//  GET SHIFT TYPE
// ================

shift_type get_shift_type(ubyte type, ubyte imm) {
	switch (type) {
		case 0b00:
			return shift_type.lsl;
		case 0b01:
			return shift_type.lsr;
		case 0b10:
			return shift_type.asr;
		case 0b11:
			if (imm == 0b0000) {
				return shift_type.rrx;
			} else {
				return shift_type.ror;
			}
		default:
			return shift_type.invalid;
	}
}

// =======
//  S
// =======

uint shift(uint val, shift_type t, uint n, bool carry_in) {
	switch (t) {
		case shift_type.lsl:
			return (n >= 32) ? 0 : (val << n);
		case shift_type.lsr:
			return (n >= 32) ? 0 : (val >>> n);
		case shift_type.asr:
			return (n >= 32)
				? (val & 0x8000_0000) != 0 ? 0xFFFF_FFFF : 0
				: (val >> n);
		case shift_type.ror:
			n &= 31; 
			if (n == 0) return val;
			return (val >>> n) | (val << (32 - n));
		case shift_type.none:
			return val;
		case shift_type.invalid:
		default:
			assert(false, "Invalid shift type");
	}
}

// ==============
//  SHIFT RESULT
// ==============

struct shift_result {
	uint result;
	bool carry;
}

// =========
//  SHIFT C 
// =========

shift_result shift_c(uint val, shift_type t, uint n, bool c) {
	return shift_result(result: shift(val, t, n, c), carry: get_shifter_carry(val, t, n, c));
}

// ===================
//  GET SHIFT STRING
// ===================

string get_shift_string(const ref instr_32 instr) {
	return instr.shift_n != 0 ? format(", %s #%d", instr.shift_t, instr.shift_n) : "";
}
// ---------------------------------------------------------------------------------------

// ===================
//  GET SHIFTER CARRY
// ===================

bool get_shifter_carry(uint val, shift_type t, uint n, bool c) {
	if (n == 0) {
		return c;
	}
    final switch (t) {
        case shift_type.lsl:
        	return (n < 32)
            	? ((val >> (32 - n)) & 1) != 0
            	: (n == 32)
                	? (val & 1) != 0
                	: false;
        case shift_type.lsr:
            return (n <= 32)
                ? ((val >> (n - 1)) & 1) != 0
                : false;
        case shift_type.asr:
            return (n <= 32)
                ? ((val >> (n - 1)) & 1) != 0
                : ((val & 0x8000_0000) != 0);
        case shift_type.ror:
            const uint rot = n & 31;
            return rot != 0
                ? ((val >> (rot - 1)) & 1) != 0
                : c;
        case shift_type.rrx:
        	return (val & 1) != 0;
        case shift_type.none:
            return c;
        case shift_type.invalid:
            assert(false, "Invalid shift type");
    }
}
// ---------------------------------------------------------------------------------------
// =======================
//  ADD WITH CARRY RESULT
// =======================

struct add_with_carry_result {
	bool carry;
	bool overflow;
	uint result;
}

// ================
//  ADD WITH CARRY 
// ================

add_with_carry_result add_with_carry(const uint x, const uint y, bool carry_in) {
	ulong unsigned_sum = cast(ulong)x + cast(ulong)y + (carry_in ? 1 : 0);;
	long  signed_sum   = cast(long)cast(int)x + cast(long)cast(int)y + (carry_in ? 1 : 0);;
	uint  result       = cast(uint)unsigned_sum;
	bool  carry_out    = unsigned_sum != cast(ulong)result;
	bool  overflow 	   = cast(long)cast(int)result != signed_sum;
	return add_with_carry_result(carry:    carry_out,
		                         overflow: overflow,
		                         result:   result);
} 
// ---------------------------------------------------------------------------------------

// ----------------------------------------- ROTR ----------------------------------------

// ======
//  ROTR
// ======

uint rotr(uint value, uint n) {
    n %= 32;
    return (value >> n) | (value << (32 - n));
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- SLICE ----------------------------------------

// =====================
//  DECIMAL TO HEX MASK
// =====================

uint decimal_to_hex_mask(uint n) {
    return (1u << n) - 1;
}

// =======
//  SLICE
// =======

uint slice(const uint instr, const uint shift, const uint width) {
	return (instr >> shift) & decimal_to_hex_mask(width);
}
// ---------------------------------------------------------------------------------------

// ------------------------------------- Thumb Expand ------------------------------------

// =====================
//  THUMB EXPAND RESULT
// =====================

struct thumb_expand_result {
	uint imm;
	bool carry;
}

// ====================
//  THUMB EXPAND IMM C
// ====================

thumb_expand_result thumb_expand_imm_c(ushort imm_12, bool carry_in) {
	immutable first_four_bits = slice(imm_12, 8, 4);
	immutable imm_8 		  = slice(imm_12, 0, 8);
	uint 	  imm;
	switch (first_four_bits) {
		case 0b0010: imm = (imm_8 << 24) | (imm_8 << 8);						 break;
		case 0b0000: imm =  imm_8;												 break;
		case 0b0011: imm = (imm_8 << 24) | (imm_8 << 16) | (imm_8 << 8) | imm_8; break;
		case 0b0001: imm = (imm_8 << 24) | (imm_8 << 8);						 break;
		default    : 
			return handle_rotate_expand(imm_12, carry_in);
	}  
	return thumb_expand_result(imm: imm, carry: carry_in);
}

// ======================
//  HANDLE ROTATE EXPAND
// ======================

thumb_expand_result handle_rotate_expand(const ushort imm_12, bool carry_in) {
	const uint rotate_by = ((imm_12) >> 7) & 0x1f;
	const uint unrotated = (1 << 7) | (imm_12 & 0x7f);
	const uint rotated   = rotr(unrotated, rotate_by);
	bool       carry_out = get_shifter_carry(unrotated, shift_type.ror, rotate_by, carry_in);
	return thumb_expand_result(imm: rotated, carry: carry_out);
}

// ==================
//  THUMB EXPAND IMM
// ==================

uint thumb_expand_imm(ushort imm_12) {
	return thumb_expand_imm_c(imm_12, false).imm;
}
// ---------------------------------------------------------------------------------------

// --------------------------------------- INSTR 16 --------------------------------------
struct instr_16 {
	opcode 		    op;
	reg 		    rd;
	reg 		    rm;
	reg 		    rn;
	reg 		    rt;
	uint 	   	   imm;
	int 	    offset;
	int   	  imm_long;
	condition 	  cond;
	reg[] 	  reg_list;
	bool  	 set_flags;
	ubyte   first_cond;
	ubyte 	   	  mask;
	bool   	    enable;
	bool    affect_pri;
	bool  affect_fault;
	bool		 index;
	bool		   add;
	shift_type shift_t;
}
// ---------------------------------------------------------------------------------------

// --------------------------------------- INSTR 32 --------------------------------------
struct instr_32 {
	opcode 			  op;
	reg 			  rd;
	reg 			  rn;
	reg 			  rm;
	reg 			  rt;
	shift_type   shift_t;
	uint 		     imm;
	uint 	     shift_n;
	int 		  offset;
	reg[] 	    reg_list;
	uint 		     lsb;
	uint 		 widthm1;
	uint 		     msb;
	reg 		   rd_hi;
	reg 		   rd_lo;
	reg 		    rt_2;
	reg 			  ra;
	condition 	    cond;
	bool 		   wback;
	bool 		     add;
	bool 		   index;
	ubyte 		    mask;
	bool 		  is_tbh;
	special_reg spec_reg;
	bool 	   set_flags;
	uint  unexpanded_imm;
	bool   		  m_high;
	bool 		  n_high;
}
// ---------------------------------------------------------------------------------------
// ============
//  BYTE TABLE
// ============

struct byte_table {
    uint        offset;
    uint          addr;
    ubyte[]       data;
}
// --------------------------------------- Strings ---------------------------------------

// =====================
//  GET REG LIST STRING
// =====================

string get_reg_list_string(const ref reg[] reg_list) {
	return reg_list.map!(r => get_reg_name(r)).join(", ");
}

// ================
//  GET IMM STRING
// ================

string get_imm_string(const uint imm) {
 	return format(", #%d", imm);
}

// =====================
//  GET IT BLOCK STRING
// =====================

string get_it_block_string(const condition cond) {
	return cond != condition.none ? cond.to!string : "s";
}

// ======================
//  GET CONDITION STRING
// ======================

string get_condition_string(const condition cond) {
	return cond != condition.none ? cond.to!string : "";
}

// ============
//  ADD SUFFIX
// ============

string add_suffix(const ref instr_32 instr, const condition cond) {
	return (instr.set_flags ? "s" : "") ~ (cond != condition.none ? cond.to!string : "");
}

// ==============
//  GET REG NAME
// ==============

string get_reg_name(const reg r) {
	switch (r) {
		case reg.r10: return "sl";
		case reg.r11: return "fp";
		case reg.r12: return "ip";
		default     : return r.to!string;
	}
}

// =================
//  GET ADDR STRING
// =================

string get_addr_string(const ref instr_32 instr) {
    string sign = instr.add ? "" : "-";
    string imm  = format("#%s%d", sign, instr.imm);
    string rn   = get_reg_name(instr.rn);
    if (instr.index && !instr.wback) {
        if (instr.imm == 0)
            return format("[%s]", rn);
        else
            return format("[%s, %s]", rn, imm);
    } else if (instr.index && instr.wback) 
        return format("[%s, %s]!", rn, imm);
    else if (!instr.index && instr.wback) 
        return format("[%s], %s", rn, imm);
    return "<invalid>";
}
// ---------------------------------------------------------------------------------------
// ============
//  WORD ALIGN
// ============

uint word_align(uint val) {
	return val &= ~3;
}
// ---------------------------------------------------------------------------------------