// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Data Processing (Register)	    					 *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.conv;
import std.format;
import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ---------------------------------------------------------------------------------------
// =====================
//  Execute Shift Instr
// =====================

void 
execute_shift_instr
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable  rm  	   = vm.get_reg(instr.rm);
	immutable  rn      = vm.get_reg(instr.rn);
	// shift_n = UInt(R[m]<7:0>);
	const uint shift_n = rm & 0xff;
	// (result, carry) = Shift_C(R[n], SRType_LSL, shift_n, APSR.C);
	immutable res 	   = shift_c(rn, instr.shift_t, shift_n, vm.get_c());
	if (instr.set_flags) {
		// APSR.C = carry;
		vm.set_c(res.carry);	
		// APSR.Z = IsZeroBit(result);
		vm.set_z(res.result);	
		// APSR.N = result<31>;	
		vm.set_n(res.result);	
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res.result);
}
// ---------------------------------------------------------------------------------------
// ===============================
//  Parse Data Proc Reg Shift Rot
// ===============================

instr_32 parse_data_proc_reg_shift_rot(const uint instr) {
	return instr_32(rm: 	   cast(reg )slice(instr,  0, 4), 
					rd: 	   cast(reg )slice(instr,  8, 4),
					rn: 	   cast(reg )slice(instr, 16, 4), 
					set_flags: cast(bool)slice(instr, 20, 1));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  ASR 											 *
// ***************************************************************************************

// =====================
//  Parse ASR(Register)
// =====================

// ASR <Rd>, <Rn>, <Rm>
// First Half-Word: [15:5] 11111010010, [4] S, [3:0] Rn
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000. [3:0] Rm
instr_32 parse_asr_reg_t2(const uint instr) {
	return parse_data_proc_reg_shift_rot(instr);
}

// =======================
//  Execute ASR(Register)
// =======================

void 
execute_asr_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);	
}

// ASR{S}<c>.W <Rd>,<Rn>,<Rm>
string convert_asr_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("asr%s.w %s, %s, %s", add_suffix(instr, cond), 
										get_reg_name(instr.rd),
										get_reg_name(instr.rn),
										get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UXTH 											 *
// ***************************************************************************************

// ============
//  Parse UXTH
// ============

// UXTH<c>.W <Rd>,<Rm>{,<rotation>}
// First Half-Word: [15:5] 11111010010, [4] S, [3:0] Rn
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000. [3:0] Rm
instr_32 parse_uxth_t2(const uint instr) {
	return instr_32(rm:  cast(reg)slice(instr, 0, 4), 
				    imm: slice(instr, 4, 2) << 3,
				    rd:  cast(reg)slice(instr, 8, 4));
}

// ==============
//  Execute UXTH
// ==============

void 
execute_uxth_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm       = vm.get_reg(instr.rm);
	//rotated = ROR(R[m], rotation);
	const uint rotated = rotr(rm, instr.imm);
	// R[d] = ZeroExtend(rotated<15:0>, 32);
	vm.set_reg(instr.rd, cast(uint)cast(ushort)rotated);	
}

// UXTH<c>.W <Rd>,<Rm>{,<rotation>}
string convert_uxth_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("uxth%s.w %s, %s", get_condition_string(cond),
									 get_reg_name(instr.rd), 
									 get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									LSL 											 *
// ***************************************************************************************

// =====================
//  Parse LSL(Register)
// =====================

// LSL{S}<c>.W <Rd>,<Rn>,<Rm>
// First Half-Word: [15:5] 11111010000, [4] S, [3:0] Rn 
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000, [3:0] Rm
instr_32 parse_lsl_reg_t2(const uint instr) {
	return parse_data_proc_reg_shift_rot(instr);
}

// =======================
//  Execute LSL(Register)
// =======================

void 
execute_lsl_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}

// LSL{S}<c>.W <Rd>,<Rn>,<Rm>
string convert_lsl_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("lsl%s.w %s, %s, %s", add_suffix(instr, cond),
										get_reg_name(instr.rd),
										get_reg_name(instr.rn),
										get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 LSR 											 *
// ***************************************************************************************

// =====================
//  Parse LSR(Register)
// =====================

// First Half-Word: [15:5] 11111010001, [4] S, [3:0] Rn 
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 0000, [3:0] Rm
instr_32 parse_lsr_reg_t2(const uint instr) {
	return parse_data_proc_reg_shift_rot(instr);
}

// =======================
//  Execute LSR(Register)
// =======================

void 
execute_lsr_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}

// LSR{S}<c>.W <Rd>,<Rn>,<Rm>
string convert_lsr_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("lsr%s.w %s, %s, %s", add_suffix(instr, cond),
										get_reg_name(instr.rd),
										get_reg_name(instr.rn),
										get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UADD8 										 *
// ***************************************************************************************
// Unsigned Add 8 performs four unsigned 8-bit integer additions, and writes the results 
// to the destination register. It sets the APSR.GE bits according to the results of the 
// additions.

// =============
//  Parse UADD8
// =============

// UADD8<c> <Rd>,<Rn>,<Rm>
// [15:4] 111110101000 [3:0] Rn
// [15:12] 1111, [11:8] Rd, [7:4] 0100, [3:0] Rm
instr_32 parse_uadd8_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
		            rd: cast(reg)slice(instr,  8, 4),
		            rn: cast(reg)slice(instr, 16, 4));
}

// ===============
//  Execute UADD8
// ===============

void 
execute_uadd8_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	int rn = vm.get_reg(instr.rn);
	int rm = vm.get_reg(instr.rm);
	// sum4 = UInt(R[n]<31:24>) + UInt(R[m]<31:24>);
	int sum4 = ((rn >> 24) & 0xff) + ((rm >> 24) & 0xff); 
	// sum3 = UInt(R[n]<23:16>) + UInt(R[m]<23:16>);
	int sum3 = ((rn >> 16) & 0xff) + ((rm >> 16) & 0xff);
	// sum2 = UInt(R[n]<15:8>) + UInt(R[m]<15:8>);
	int sum2 = ((rn >>  8) & 0xff) + ((rm >>  8) & 0xff);
	// sum1 = UInt(R[n]<7:0>) + UInt(R[m]<7:0>);
	int sum1 = ((rn      ) & 0xff) + ((rm      ) & 0xff);
	int res  = ((sum4 & 0xff) << 24) |
      		   ((sum3 & 0xff) << 16) |
      		   ((sum2 & 0xff) << 8)  |
      		   ( sum1 & 0xff);
	vm.set_ge0(sum1 >= 0x100);
	vm.set_ge1(sum2 >= 0x100);
	vm.set_ge2(sum3 >= 0x100);
	vm.set_ge3(sum4 >= 0x100);
	vm.set_reg(instr.rd, res);
}

string convert_uadd8_t1_to_string(const ref instr_32 instr, const condition cond) {
	return "uadd8" ~ get_condition_string(cond) ~ " " ~ get_reg_name(instr.rd) ~ ", "
		~ get_reg_name(instr.rn) ~ ", " ~ get_reg_name(instr.rm); 
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UXTB 											 *
// ***************************************************************************************
// Unsigned Extend Byte extracts an 8-bit value from a register, zero extends it to 32 
// bits, and writes the result to the destination register. You can specify a rotation by 
// 0, 8, 16, or 24 bits before extracting the 8-bit value.

// ============
//  Parse UXTB
// ============

// UXTB<c>.W <Rd>,<Rm>{,<rotation>}
instr_32 parse_uxtb_t2(const uint instr) {
	// rotation = UInt(rotate:’000’);
	return instr_32(rm:  cast(reg)slice(instr, 0, 4),
					rd:  cast(reg)slice(instr, 8, 4),
					imm: slice(instr, 4, 2) << 3);
}

// ==============
//  Execute UXTB
// ==============

void
execute_uxtb_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable rm       = vm.get_reg(instr.rm);
	// rotated = ROR(R[m], rotation);
	const uint rotated = rotr(rm, instr.imm);
	// R[d] = ZeroExtend(rotated<7:0>, 32);
	vm.set_reg(instr.rd, cast(uint)cast(ubyte)rotated);
}

// UXTB<c>.W <Rd>,<Rm>{,<rotation>}
string convert_uxtb_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("uxtb%s.w %s, %s%s", get_condition_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rm),
									   instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UXTAH 										 *
// ***************************************************************************************

// =============
//  Parse UXTAH
// =============

// UXTAH<c> <Rd>,<Rn>,<Rm>{,<rotation>}
instr_32 parse_uxtah_t1(const uint instr) {
	// rotation = UInt(rotate:’000’);
	return instr_32(rm:  cast(reg)slice(instr,  0, 4),
					rd:  cast(reg)slice(instr,  8, 4),
					rn:  cast(reg)slice(instr, 16, 4),
					imm: slice(instr, 4, 2) << 3);
}

// ===============
//  Execute UXTAH
// ===============

void 
execute_uxtah_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable rm  = vm.get_reg(instr.rm);
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// rotated = ROR(R[m], rotation);
	const uint rotated = rotr(rm, imm);
	// R[d] = R[n] + ZeroExtend(rotated<15:0>, 32);
	vm.set_reg(instr.rd, rn + (rotated & 0xffff));
}

// UXTAH<c> <Rd>,<Rn>,<Rm>{,<rotation>}
string convert_uxtah_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("uxtah%s %s, %s, %s%s", get_condition_string(cond),
										  get_reg_name(instr.rd),
										  get_reg_name(instr.rn),
										  get_reg_name(instr.rm),
										  instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  SXTH 											 *
// ***************************************************************************************

// ============
//  Parse SXTH
// ============

// SXTH<c>.W <Rd>,<Rm>{,<rotation>}
instr_32 parse_sxth_t2(const uint instr) {
	return instr_32(rm:  cast(reg)slice(instr,  0, 4),
					rd:  cast(reg)slice(instr,  8, 4),
					imm: slice(instr, 4, 2) << 3);
}

// ==============
//  Execute SXTH
// ==============

void 
execute_sxth_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
    immutable  rm      = vm.get_reg(instr.rm);
    immutable  imm     = instr.imm;
    // rotated = ROR(R[m], rotation);
    const uint rotated = cast(int)cast(short)rotr(rm, imm); 
	// R[d] = SignExtend(rotated<15:0>, 32);
	vm.set_reg(instr.rd, cast(uint)rotated);
}

// SXTH<c>.W <Rd>,<Rm>{,<rotation>}
string convert_sxth_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("sxth%s.w %s, %s%s", get_condition_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rm),
									   instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  SXTAH 										 *
// ***************************************************************************************

// =============
//  Parse SXTAH
// =============

// SXTAH<c> <Rd>,<Rn>,<Rm>{,<rotation>}
instr_32 parse_sxtah_t1(const uint instr) {
	return instr_32(rm:  cast(reg)slice(instr,  0, 4),
				    rd:  cast(reg)slice(instr,  8, 4),
					rn:  cast(reg)slice(instr, 16, 4),
					imm: slice(instr, 4, 2) << 3);
}

// ===============
//  Execute SXTAH
// ===============

void 
execute_sxtah_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable  rm      = vm.get_reg(instr.rm);
	immutable  rn      = vm.get_reg(instr.rn);
	immutable  imm 	   = instr.imm; 
	// rotated = ROR(R[m], rotation);
	const uint rotated = rotr(rm, imm);
 	// R[d] = R[n] + SignExtend(rotated<15:0>, 32);
 	const uint res     = rn + cast(int)cast(short)rotated;
 	vm.set_reg(instr.rd, res);
}

// SXTAH<c> <Rd>,<Rn>,<Rm>{,<rotation>}
string convert_sxtah_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("sxtah%s %s, %s, %s%s", get_condition_string(cond),
										  get_reg_name(instr.rd),
										  get_reg_name(instr.rn),
										  get_reg_name(instr.rm),
										  instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UXTAB 										 *
// ***************************************************************************************

// =============
//  Parse UXTAB
// =============

// UXTAB<c> <Rd>,<Rn>,<Rm>{,<rotation>}
instr_32 parse_uxtab_t1(const uint instr) {
	return instr_32(rm:  cast(reg)slice(instr,  0, 4),
				    rd:  cast(reg)slice(instr,  8, 4),
					rn:  cast(reg)slice(instr, 16, 4),
					imm: slice(instr, 4, 2) << 3);
}

// ===============
//  Execute UXTAB
// ===============

void 
execute_uxtab_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable  rm      = vm.get_reg(instr.rm);
	immutable  rn      = vm.get_reg(instr.rn);
	immutable  imm 	   = instr.imm; 
	// rotated = ROR(R[m], rotation);
	const uint rotated = rotr(rm, imm);
 	// R[d] = R[n] + ZeroExtend(rotated<7:0>, 32);
 	const uint res     = rn + cast(uint)cast(ubyte)rotated;
 	vm.set_reg(instr.rd, res);
}

// UXTAB<c> <Rd>,<Rn>,<Rm>{,<rotation>}
string convert_uxtab_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("uxtab%s %s, %s, %s%s", get_condition_string(cond),
										  get_reg_name(instr.rd),
										  get_reg_name(instr.rn),
										  get_reg_name(instr.rm),
										  instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  SXTB 											 *
// ***************************************************************************************

// ============
//  Parse SXTB
// ============

// SXTB<c>.W <Rd>,<Rm>{,<rotation>}
instr_32 parse_sxtb_t2(const uint instr) {
	return instr_32(rd:  cast(reg)slice(instr, 8, 4),
					rm:  cast(reg)slice(instr, 0, 4),
					// rotation = UInt(rotate:’000’);
					imm: slice(instr, 4, 2) << 3);
}

// ==============
//  Execute SXTB
// ==============

void 
execute_sxtb_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable  rm      = vm.get_reg(instr.rm);
	// rotated = ROR(R[m], rotation);
	const uint rotated = rotr(rm, instr.imm);
	// R[d] = SignExtend(rotated<7:0>, 32);
	vm.set_reg(instr.rd, cast(int)cast(byte)rotated);
}

// SXTB<c>.W <Rd>,<Rm>{,<rotation>}
string convert_sxtb_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("sxtb%s.w %s, %s%s", get_condition_string(cond),
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rm),
									   instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------