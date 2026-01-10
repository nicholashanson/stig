import thumb_2_opcodes;
import cortex_m_core;

// -------------------------------------- Shift Type -------------------------------------
enum shift_type : ubyte {
	lsl,
	lsr,
	asr,
	rrx,
	ror,
	none,
	invalid
}
// ---------------------------------------------------------------------------------------

// ----------------------------------------- ROTR ----------------------------------------
uint rotr(uint value, uint n) {
    n %= 32;
    return (value >> n) | (value << (32 - n));
}
// ---------------------------------------------------------------------------------------

// ------------------------------------- Thumb Expand ------------------------------------
uint thumb_expand_imm(ushort imm_12) {
	if ((cast(ubyte)(imm_12 >> 10) & 0b11) == 0b00) {
		ubyte imm_8 = cast(ubyte)(imm_12 & 0xff);
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b10) {
			return (imm_8 << 24) | (imm_8 << 8);
		}
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b0) {
			return imm_8;
		}
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b11) {
			return (imm_8 << 24) | (imm_8 << 16) | (imm_8 << 8) | imm_8;
		}
		if ((cast(ubyte)(imm_12 >> 8) & 0b11) == 0b01) {
			return (imm_8 << 24) | (imm_8 << 8);
		}
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