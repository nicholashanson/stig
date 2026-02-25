// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                Data Processing (Shifted Register)	    		         *    
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

instr_32 parse_data_proc_shift_reg(const uint instr) {
	immutable type    = cast(ubyte)slice(instr,  4, 2);
	immutable imm_2   = slice(instr,  6, 2);
	immutable imm_3   = slice(instr, 12, 3);
	immutable imm_5   = cast(ubyte)((imm_3 << 2) | imm_2);
	immutable shift_t = get_shift_type(type, imm_5);
	return instr_32(rm: 	   cast(reg)slice(instr,  0, 4),
		            rd: 	   cast(reg)slice(instr,  8, 4),
		            rn:        cast(reg)slice(instr, 16, 4),
		            shift_t:   shift_t,
		            shift_n:   shift_t == shift_type.rrx ? 1 : imm_5,
		            set_flags: cast(bool)slice(instr, 20, 1));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ADD                                           *
// ***************************************************************************************

// =====================
//  Parse ADD(Register)
// =====================

enum field_tuples_add_reg_t3 = [Tuple!(opcode, string[])(opcode.add_reg_t3, ["rd","rn","rm","shift"])];
// ADD{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 1110101000, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_add_reg_t3(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute ADD(Register)
// =======================

void 
execute_add_reg_t3
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rn      = vm.get_reg(instr.rn);
	immutable rm      = vm.get_reg(instr.rm);
	// shifted = Shift(R[m], shift_t, shift_n, APSR.C);
	immutable shifted = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// (result, carry, overflow) = AddWithCarry(R[n], shifted, ‘0’);
	immutable res     = add_with_carry(rn, shifted, false);
	vm.set_reg(instr.rd, res.result);
	if (instr.rd == reg.pc) 
		return; // setflags is always FALSE here
	if (instr.set_flags) {
		vm.set_n(res.result);
		vm.set_z(res.result);
		vm.set_c(res.carry);
    	vm.set_v(res.overflow);
	}
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *							           ADC 											 *
// ***************************************************************************************

// =====================
//  Parse ADC(Register)
// =====================

enum field_tuples_adc_reg_t2 = [Tuple!(opcode, string[])(opcode.adc_reg_t2, ["rd","rn","rm","shift"])];
// ADC.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101011010, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_adc_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute ADC(Register)
// =======================

void 
execute_adc_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable  rm      = vm.get_reg(instr.rm);
	immutable  rn      = vm.get_reg(instr.rn);
	// shifted = Shift(R[m], shift_t, shift_n, APSR.C);
	immutable  shifted = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// (result, carry, overflow) = AddWithCarry(R[n], shifted, APSR.C);
	immutable res      = add_with_carry(rn, shifted, vm.get_c());
	if (instr.set_flags) {
		vm.set_n(res.result);		// APSR.N = result<31>;
		vm.set_z(res.result);		// APSR.Z = IsZeroBit(result);
		vm.set_c(res.carry);		// APSR.C = carry;
    	vm.set_v(res.overflow);		// APSR.V = overflow;
	}
	vm.set_reg(instr.rd, res.result);
}

// ADC.W <Rd>,<Rn>,<Rm>{,<shift>}
string convert_adc_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("adc%s.w %s, %s, %s%s", add_suffix(instr, cond),
										  get_reg_name(instr.rd), 
								    	  get_reg_name(instr.rn), 
								    	  get_reg_name(instr.rm),
								    	  get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   AND                                           *
// ***************************************************************************************

// =====================
//  Parse AND(Register)
// =====================

enum field_tuples_and_reg_t2 = [Tuple!(opcode, string[])(opcode.and_reg_t2, ["rd","rn","rm","shift"])];
// AND.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101010000, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_and_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute AND(Register)
// =======================

void 
execute_and_reg_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rm        = vm.get_reg(instr.rm);
	immutable  rn        = vm.get_reg(instr.rn);
	immutable  shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c()); 
	const uint res       = rn & shift_res.result;
	if (instr.set_flags) {
		vm.set_n(res);
    	vm.set_z(res);
		vm.set_c(shift_res.carry);
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   EOR 											 *
// ***************************************************************************************

// =====================
//  Parse EOR(Register)
// =====================

enum field_tuples_eor_reg_t2 = [Tuple!(opcode, string[])(opcode.eor_reg_t2, ["rd","rn","rm","shift"])];
// EOR{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101010100, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd. [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_eor_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute EOR(Register)
// =======================

void 
execute_eor_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable  rm        = vm.get_reg(instr.rm);
	immutable  rn        = vm.get_reg(instr.rn);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable  shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c()); 
	// result = R[n] EOR shifted;
	const uint res       = rn ^ shift_res.result;
	if (instr.set_flags) {
		vm.set_n(res);				// APSR.N = result<31>;
    	vm.set_z(res);				// APSR.Z = IsZeroBit(result);
    	vm.set_c(shift_res.carry);	// APSR.C = carry;
    	// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   SBC 											 *
// ***************************************************************************************
// Subtract with Carry (register) subtracts an optionally-shifted register value and the 
// value of NOT(Carry flag) from a register value, and writes the result to the 
// destination register. It can optionally update the condition flags based on the result.

// =====================
//  Parse SBC(Register)
// =====================

enum field_tuples_sbc_reg_t2 = [Tuple!(opcode, string[])(opcode.sbc_reg_t2, ["rd","rn","rm","shift"])];
// SBC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101011101, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_sbc_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute SBC(Register)
// =======================

void 
execute_sbc_reg_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rm      = vm.get_reg(instr.rm);
	immutable rn      = vm.get_reg(instr.rn);
	// shifted = Shift(R[m], shift_t, shift_n, APSR.C);
	immutable shifted = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), APSR.C);
	immutable res     = add_with_carry(rn, ~shifted, vm.get_c());
	if (instr.set_flags) {
		vm.set_n(res.result);		// APSR.N = result<31>;
    	vm.set_z(res.result);		// APSR.Z = IsZeroBit(result);
    	vm.set_v(res.overflow);		// APSR.V = overflow;
    	vm.set_c(res.carry);		// APSR.C = carry;
	}
	vm.set_reg(instr.rd, res.result);
}

// SBC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
string convert_sbc_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("sbc%s.w %s, %s, %s%s", add_suffix(instr, cond),
										  get_reg_name(instr.rd),
										  get_reg_name(instr.rn),
										  get_reg_name(instr.rm),
										  get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ORR 											 *
// ***************************************************************************************

// =====================
//  Parse ORR(Register)
// =====================

enum field_tuples_orr_reg_t2 = [Tuple!(opcode, string[])(opcode.orr_reg_t2, ["rd","rn","rm","shift"])];
// ORR{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101010010, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_orr_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute ORR(Register)
// =======================

void 
execute_orr_reg_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rm        = vm.get_reg(instr.rm);
	immutable  rn        = vm.get_reg(instr.rn);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable  shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// result = R[n] OR shifted;
	const uint res       = rn | shift_res.result;
	if (instr.set_flags) {
		vm.set_n(res);				// APSR.N = result<31>;
		vm.set_z(res);				// APSR.Z = IsZeroBit(result);
		vm.set_c(shift_res.carry);	// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 BIC 											 *
// ***************************************************************************************

// =====================
//  Parse BIC(Register)
// =====================

enum field_tuples_bic_reg_t2 = [Tuple!(opcode, string[])(opcode.bic_reg_t2, ["rd","rn","rm"])];
// BIC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101010001, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type. [3:0] Rm
instr_32 parse_bic_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute BIC(Register)
// =======================

void 
execute_bic_reg_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rm 		 = vm.get_reg(instr.rm);
	immutable  rn 		 = vm.get_reg(instr.rn);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable  shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// result = R[n] AND NOT(shifted);
	const uint res     	 = rn & ~shift_res.result;
	if (instr.set_flags) {
		vm.set_n(res);				// APSR.N = result<31>;
		vm.set_z(res);				// APSR.Z = IsZeroBit(result);
		vm.set_c(shift_res.carry);	// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

// BIC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
string convert_bic_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("bic%s.w %s, %s, %s%s", add_suffix(instr, cond), get_reg_name(instr.rd),
										  get_reg_name(instr.rn),  get_reg_name(instr.rm),
										  get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ORN 											 *
// ***************************************************************************************

// =====================
//  Parse ORN(Register)
// =====================

// ORN{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}
instr_32 parse_orn_reg_t1(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

// =======================
//  Execute ORN(Register)
// =======================

void 
execute_orn_reg_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable  rm 		 = vm.get_reg(instr.rm);
	immutable  rn 		 = vm.get_reg(instr.rn);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable  shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// result = R[n] OR NOT(shifted);
	const uint res       = rn | ~shift_res.result;
	vm.set_reg(instr.rd, res);
	if (instr.set_flags) {
		vm.set_n(res);				// APSR.N = result<31>;
		vm.set_z(res);				// APSR.Z = IsZeroBit(result);
		vm.set_c(shift_res.carry);	// APSR.C = carry;
		// APSR.V unchanged
	}
}

// =================================
//  Convert ORN(Register) to String
// =================================

string convert_orn_reg_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("orn%s %s, %s, %s%s", add_suffix(instr, cond), 
									    get_reg_name(instr.rd), 
									  	get_reg_name(instr.rn), 
									    get_reg_name(instr.rm),
									    get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   TST                                           *
// ***************************************************************************************

// =====================
//  Parse TST(Register)
// =====================

// TST<c> <Rn>,<Rm>
// First Half-Word: [15:4] 111010100001, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3. [11:8] 1111. [7:6] imm2. [5:4] type, [3:0] Rm
instr_32 parse_tst_reg_t2(const uint instr) {
	immutable type    = cast(ubyte)slice(instr,  4, 2);
	immutable imm_2   = slice(instr,  6, 2);
	immutable imm_3   = slice(instr, 12, 3);
	immutable imm_5   = cast(ubyte)((imm_3 << 2) | imm_2);
	immutable shift_t = get_shift_type(type, imm_5);
	return instr_32(rm: 	   cast(reg)slice(instr,  0, 4),
		            rn:        cast(reg)slice(instr, 16, 4),
		            shift_t:   shift_t,
		            shift_n:   shift_t == shift_type.rrx ? 1 : imm_5);
}

// =======================
//  Execute TST(Register)
// =======================

void 
execute_tst_reg_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rm 		= vm.get_reg(instr.rm);
	immutable rn 		= vm.get_reg(instr.rn);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// result = R[n] AND shifted;
	const uint res      = rn & shift_res.result;
	vm.set_n(res);  			// APSR.N = result<31>;
	vm.set_z(res);  			// APSR.Z = IsZeroBit(result);
	vm.set_c(shift_res.carry);	// APSR.C = carry;
	// APSR.V unchanged
}
// ---------------------------------------------------------------------------------------

void 
execute_shift_instr
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm        = vm.get_reg(instr.rm);
	// (result, carry) = Shift_C(R[m], SRType_ASR, shift_n, APSR.C);
	immutable shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	if (instr.set_flags) {
		vm.set_c(shift_res.carry);		// APSR.C = carry;
		vm.set_z(shift_res.result);		// APSR.Z = IsZeroBit(result);
		vm.set_n(shift_res.result);		// APSR.N = result<31>;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, shift_res.result);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ASR 											 *
// ***************************************************************************************

// ======================
//  Parse ASR(Immediate)
// ======================

enum field_tuples_asr_imm_t2 = [Tuple!(opcode, string[])(opcode.asr_imm_t2, ["rd","rm","imm"])];
// ASR{S}<c>.W <Rd>,<Rm>,#<imm5>
// First Half-Word: [15:0] 11101010010, [4] S, [3:0] 1111 
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] 10, [3:0] Rm
instr_32 parse_asr_imm_t2(const uint instr) {
	immutable imm_2  = slice(instr,  6, 2);
	immutable imm_3  = slice(instr, 12, 3);
	immutable imm_5  = cast(ubyte)((imm_3 << 2) | imm_2);
	return instr_32(rm: cast(reg)slice(instr, 0, 4),
		            rd: cast(reg)slice(instr, 8, 4),
		            shift_t: shift_type.asr,
		            shift_n: imm_5);
}

// ========================
//  Execute ASR(Immediate)
// ========================

void 
execute_asr_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   LSL                                           *
// ***************************************************************************************

// ========================
//  Execute LSL(Immediate)
// ========================

instr_32 parse_lsl_imm_t2(const uint instr) {
	immutable imm_2  = slice(instr,  6, 2);
	immutable imm_3  = slice(instr, 12, 3);
	immutable imm_5  = cast(ubyte)((imm_3 << 2) | imm_2);
	return instr_32(rm: cast(reg)slice(instr, 0, 4),
		            rd: cast(reg)slice(instr, 8, 4),
		            shift_t: shift_type.lsl,
		            shift_n: imm_5);
}

// ========================
//  Execute LSL(Immediate)
// ========================

void 
execute_lsl_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// * 									   LSR 											 *
// ***************************************************************************************

// ======================
//  Parse LSL(Immediate)
// ======================

enum field_tuples_lsr_imm_t2 = [Tuple!(opcode, string[])(opcode.lsr_imm_t2, ["rd","rm","imm"])];
// First Half-Word: [15:0] 11101010010, [4] S. [3:0] 1111 
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] 10, [3:0] Rm
instr_32 parse_lsr_imm_t2(const uint instr) {
	immutable imm_2  = slice(instr,  6, 2);
	immutable imm_3  = slice(instr, 12, 3);
	immutable imm_5  = (imm_3 <<  2) | imm_2;
	return instr_32(rm: 	 cast(reg)slice(instr,  0, 4), 
					rd: 	 cast(reg)slice(instr,  8, 4),
					imm:     imm_5, 
					shift_t: shift_type.lsr);
}

// ========================
//  Execute LSR(Immediate)
// ========================

void 
execute_lsr_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_shift_instr(instr, vm);
}
// ---------------------------------------------------------------------------------------

// ===========
//  Parse SUB
// ===========

// SUB{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
// First Half-Word: [15:5] 11101011101, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5:4] type, [3:0] Rm
instr_32 parse_sub_reg_t2(const uint instr) {
	return parse_data_proc_shift_reg(instr);
}

void 
execute_sub_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm      = vm.get_reg(instr.rm);
	immutable rn 	  = vm.get_reg(instr.rn);
	immutable shifted = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	immutable res     = add_with_carry(rn, ~shifted, true);
	if (instr.set_flags) {
		vm.set_c(res.carry);
		vm.set_v(res.overflow);
		vm.set_n(res.result);
		vm.set_z(res.result);
	}
	vm.set_reg(instr.rd, res.result);
}

// SUB{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
string convert_sub_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("sub%s.w %s, %s, %s%s", add_suffix(instr, cond), get_reg_name(instr.rd),
										  get_reg_name(instr.rn), get_reg_name(instr.rm),
										  get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// * 									   TEQ 											 *
// ***************************************************************************************

// =====================
//  Parse TEQ(Register)
// =====================

// TEQ<c> <Rn>,<Rm>{,<shift>}
instr_32 parse_teq_reg_t1(const uint instr) {
	immutable type    = cast(ubyte)slice(instr,  4, 2);
	immutable imm_2   = slice(instr,  6, 2);
	immutable imm_3   = slice(instr, 12, 3);
	immutable imm_5   = cast(ubyte)((imm_3 << 2) | imm_2);
	immutable shift_t = get_shift_type(type, imm_5);
	return instr_32(rm: 	   cast(reg)slice(instr,  0, 4),
		            rn:        cast(reg)slice(instr, 16, 4),
		            shift_t:   shift_t,
		            shift_n:   shift_t == shift_type.rrx ? 1 : imm_5,
		            set_flags: cast(bool)slice(instr, 20, 1));
}

// =======================
//  Execute TEQ(Register)
// =======================

void 
execute_teq_reg_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	// if ConditionPassed() then
    // EncodingSpecificOperations();
    immutable rm 		= vm.get_reg(instr.rm);
    immutable rn 		= vm.get_reg(instr.rn);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// result = R[n] EOR shifted;
	const uint res 		= rn ^ shift_res.result;
	vm.set_n(res); 				// APSR.N = result<31>;
	vm.set_z(res); 				// APSR.Z = IsZeroBit(result);
	vm.set_c(shift_res.carry);	// APSR.C = carry;
	// APSR.V unchanged	
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// * 									   MVN 											 *
// ***************************************************************************************

// =====================
//  Parse MVN(Register)
// =====================

// MVN{S}<c>.W <Rd>,<Rm>{,shift>}
instr_32 parse_mvn_reg_t2(const uint instr) {
	immutable type    = cast(ubyte)slice(instr,  4, 2);
	immutable imm_2   = slice(instr,  6, 2);
	immutable imm_3   = slice(instr, 12, 3);
	immutable imm_5   = cast(ubyte)((imm_3 << 2) | imm_2);
	immutable shift_t = get_shift_type(type, imm_5);
	return instr_32(rm: 	   cast(reg)slice(instr,  0, 4),
		            rd: 	   cast(reg)slice(instr,  8, 4),
		            shift_t:   shift_t,
		            shift_n:   shift_t == shift_type.rrx ? 1 : imm_5,
		            set_flags: cast(bool)slice(instr, 20, 1));
}


void
execute_mvn_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable  rm        = vm.get_reg(instr.rm);
	// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
	immutable  shift_res = shift_c(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// result = NOT(shifted);
	const uint res       = ~shift_res.result;
	// R[d] = result;
	vm.set_reg(instr.rd, res);
	// if setflags then
	if (instr.set_flags) {
		vm.set_n(res); 			   // APSR.N = result<31>;
		vm.set_z(res); 			   // APSR.Z = IsZeroBit(result);
		vm.set_c(shift_res.carry); // APSR.C = carry;
		// APSR.V unchanged
	}
}

string convert_mvn_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("mvn%s.w %s, %s%s", add_suffix(instr, cond),
									  get_reg_name(instr.rd),
									  get_reg_name(instr.rm),
									  get_shift_string(instr));
}