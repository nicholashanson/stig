import thumb_2_opcodes;
import cortex_m_core;

// ---------------------------------------- Shift ----------------------------------------
enum shift_type : ubyte {
	lsl,
	lsr,
	asr,
	rrx,
	ror,
	none,
	invalid
}

// =======
//  Shift
// =======

uint shift(shift_type t, uint n, uint val) {
	switch (t) {
		case shift_type.lsl:
			return (n >= 32) ? 0 : (val << n);
		case shift_type.lsr:
			return (n >= 32) ? 0 : (val >>> n);
		case shift_type.asr:
			return (n >= 32)
				? (val & 0x80000000) != 0 ? 0xFFFF_FFFF : 0
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

// ------------------------------------- Thumb Expand ------------------------------------

// ==================
//  THUMB EXPAND IMM
// ==================

uint thumb_expand_imm(ushort imm_12) {
	ubyte first_four_bits = cast(ubyte)((imm_12 >> 8) & 0xf);
	ubyte imm_8 = cast(ubyte)(imm_12 & 0xff);
	switch (first_four_bits) {
		case 0b0010: return (imm_8 << 24) | (imm_8 << 8);
		case 0b0000: return imm_8;
		case 0b0011: return (imm_8 << 24) | (imm_8 << 16) | (imm_8 << 8) | imm_8;
		case 0b0001: return (imm_8 << 24) | (imm_8 << 8);
		default: break;
	}  
	uint rotate_by = ((imm_12) >> 7) & 0x1f;
	uint unrotated = (1 << 7) | (imm_12 & 0x7f);
	uint rotated = rotr(unrotated, rotate_by);
	return rotated;
}
// ---------------------------------------------------------------------------------------

// --------------------------------------- INSTR 16 --------------------------------------
struct instr_16 {
	uint addr;
	opcode op;
	reg rd;
	reg rm;
	reg rn;
	reg rt;
	uint imm;
	int offset;
	int imm_long;
	condition cond;
	reg[] reg_list;
	bool set_flags;
	ubyte first_cond;
	ubyte mask;
	bool enable;
	bool affect_pri;
	bool affect_fault;
}
// ---------------------------------------------------------------------------------------

// --------------------------------------- INSTR 32 --------------------------------------
struct instr_32 {
	opcode op;
	reg rd;
	reg rn;
	reg rm;
	reg rt;
	shift_type shift_t;
	uint imm;
	ubyte shift_n;
	int offset;
	reg[] reg_list;
	uint ls_bit;
	uint width;
	uint ms_bit;
	reg rd_hi;
	reg rd_lo;
	reg rt_2;
	reg ra;
	condition cond;
	bool wback;
	bool add;
	bool index;
	ubyte mask;
	special_reg spec_reg;
	bool set_flags;
}
// ---------------------------------------------------------------------------------------

bool is_store(opcode op) {
	switch (op) {
		case opcode.ldr_imm:
		case opcode.ldr_imm_32:
		case opcode.ldr_pool:
		//case opcode.ldr_post_inc:
		case opcode.ldr_reg:
		case opcode.ldr_sp:
		case opcode.ldrb_imm:
		case opcode.ldrb_reg:
		case opcode.ldrb_imm_32_t2:
		case opcode.ldr_imm_32_t3:
		case opcode.ldr_imm_32_t4:
		case opcode.ldrd_imm_32:
		case opcode.ldrh_imm:
		case opcode.ldrsb_imm_32_t1:
		case opcode.ldrsb_imm_32_t2:
		case opcode.pop_mult_reg:
		case opcode.pop_mult_reg_32:
		case opcode.push_mult_reg:
		case opcode.push_mult_reg_32:
		case opcode.stmia_32:
		case opcode.str_imm:
		case opcode.str_imm_32_t3:
		case opcode.str_imm_32_t4:
		case opcode.str_sp:
		case opcode.str_reg:
		case opcode.str_reg_32:
		case opcode.strb_imm:
		case opcode.strb_imm_32_t2:
		case opcode.strb_imm_32_t3:
		case opcode.strb_reg:
		case opcode.strd_32:
		case opcode.strh_imm:
		case opcode.ldr_lit_32:
		case opcode.ldr_reg_32:
		case opcode.ldrb_imm_32_t3:
		case opcode.strh_imm_32_t2:
		case opcode.svc:
		case opcode.ldmia_32:
		case opcode.bx:
		case opcode.strh_reg_32:
		case opcode.strh_reg:
		case opcode.ldr_ex:
		case opcode.str_rex:
		case opcode.ldh_32:
			return true;
		default:
			return false;
	}
}
