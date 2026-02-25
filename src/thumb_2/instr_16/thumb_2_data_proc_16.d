import std.format;
import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *									   TST 											 *
// ***************************************************************************************

// ===========
//  Parse TST 
// ===========

// TST<c> <Rn>,<Rm>
// [15:6] 0100001000, [5:3] Rm, [2:0] Rn
instr_16 parse_tst_reg_t1(short instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
					rm: cast(reg)slice(instr, 3, 3));
}

// =============
//  Execute TST
// =============

void 
execute_tst_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable  rn  = vm.get_reg(instr.rn);
	immutable  rm  = vm.get_reg(instr.rm);
	const uint res = rm & rm;
	vm.set_z(res);
	vm.set_n(res);
	// APSR.C = carry;
	// APSR.V unchanged
}

string convert_tst_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("tst%s %s, %s", get_condition_string(cond),
								  get_reg_name(instr.rn),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ADC 											 *
// ***************************************************************************************

// =====================
//  Parse ADC(Register)
// =====================

// ADCS <Rdn>,<Rm>
// ADC<c> <Rdn>,<Rm>
// [15:6] 0100000101, [5:3] Rm, [2:0] Rdn  
instr_16 parse_adc_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
		            rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute ADC(Register)
// =======================

void 
execute_adc_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable rm  = vm.get_reg(instr.rm);
	// (result, carry, overflow) = AddWithCarry(R[n], shifted, APSR.C);
	immutable res = add_with_carry(rn, rm, vm.get_c()); 
	if (!vm.in_it_block()) {
		vm.set_z(res.result);	// APSR.N = result<31>;
		vm.set_n(res.result);	// APSR.Z = IsZeroBit(result);
		// APSR.C = carry;
		// APSR.V = overflow;
	}
	vm.set_reg(instr.rd, res.result);
}

// ADCS <Rdn>,<Rm>
// ADC<c> <Rdn>,<Rm>
string convert_adc_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("adc%s %s, %s", get_it_block_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   AND 											 *
// ***************************************************************************************

// =====================
//  Parse AND(Register)
// =====================

// ANDS <Rdn>,<Rm>
// AND<c> <Rdn>,<Rm>
// [15:6] 0100000000, [5:3] Rm, [2:0] Rdn
instr_16 parse_and_reg_t1(ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
					rd: cast(reg)slice(instr, 0, 3), 
					rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute AND(Register)
// =======================

void 
execute_and_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  rn  = cast(int)vm.get_reg(instr.rn);
	immutable  rm  = cast(int)vm.get_reg(instr.rm);
	const uint res = rn & rm;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
	}
	vm.set_reg(instr.rd, res);
}

string convert_and_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("and%s %s, %s", get_it_block_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   BIC 											 *
// ***************************************************************************************

// =====================
//  Parse BIC(Register)
// =====================

enum field_tuples_bic_reg_t1 = [Tuple!(opcode, string[])(opcode.bic_reg_t1, ["rd","rn"])];
// [15:6] 0100001110, [5:3] Rm, [2:0] Rdn
instr_16 parse_bic_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
					rd: cast(reg)slice(instr, 0, 3), 
					rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute BIC(Register)
// =======================

void 
execute_bic_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  rm  = vm.get_reg(instr.rm);
	immutable  rn  = vm.get_reg(instr.rn);
	const uint res = rm & ~rn;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   CMP 											 *
// ***************************************************************************************

// =====================
//  Parse CMP(Register)
// =====================

// CMP<c> <Rn>,<Rm>
// [15:6] 0100001010, [5:3] Rm, [2:0] Rn
instr_16 parse_cmp_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
					rm: cast(reg)slice(instr, 3, 3));
}

// =====================
//  Parse CMP(Register)
// =====================

// CMP<c> <Rn>,<Rm>
// [15:8] 01000101, [7] N, [6:3] Rm, [2:0] Rn
instr_16 parse_cmp_reg_t2(const ushort instr) {
	auto rn = slice(instr, 0, 3);
	auto n  = slice(instr, 7, 1);
	if (n) 
		rn |= 0b1000; 
	return instr_16(rm: cast(reg)slice(instr, 3, 4), rn: cast(reg)rn);
}

// =======================
//  Execute CMP(Register)
// =======================

void 
execute_cmp_reg_t1
(vm_t)   
(const instr_16 instr, ref vm_t vm) {
	execute_cmp_reg(instr, vm);
}

void 
execute_cmp_reg_t2
(vm_t)   
(const instr_16 instr, ref vm_t vm) {
	execute_cmp_reg(instr, vm);
}

void 
execute_cmp_reg
(vm_t)   
(const instr_16 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	immutable rn  = vm.get_reg(instr.rn);
	immutable res = add_with_carry(rm, ~rn, true);
	vm.set_z(res.result);
	vm.set_n(res.result);
	vm.set_c(res.carry);;
	vm.set_v(res.overflow);
}

string convert_cmp_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return convert_cmp_reg_to_string(instr, cond);
}

string convert_cmp_reg_t2_to_string(const ref instr_16 instr, const condition cond) {
	return convert_cmp_reg_to_string(instr, cond);
}

string convert_cmp_reg_to_string(const ref instr_16 instr, const condition cond) {
	return format("cmp%s %s, %s", get_condition_string(cond),
								  get_reg_name(instr.rn),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       EOR                                           *
// ***************************************************************************************

// =====================
//  Parse EOR(Register)
// =====================

// EORS <Rdn>,<Rm> 
// EOR<c> <Rdn>,<Rm> 
// [15:6] 0100000001, [5:3] Rm, [2:0] Rdn
instr_16 parse_eor_reg_t1(ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
		            rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute EOR(Register)
// =======================

void 
execute_eor_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  rm  = vm.get_reg(instr.rm);
	immutable  rn  = vm.get_reg(instr.rn);
	const uint res = rm & ~rn;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
	}
	vm.set_reg(instr.rd, res);
}

string convert_eor_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("eor%s %s, %s", get_it_block_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       LSL                                           *
// ***************************************************************************************

// =====================
//  Parse LSL(Register)
// =====================

// LSLS <Rdn>,<Rm>
// LSL<c> <Rdn>,<Rm>
// [15:6] 0100000010, [5:3] Rm, [2:0] Rdn  
instr_16 parse_lsl_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
		            rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute LSL(Register)
// =======================

void 
execute_lsl_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  shift = vm.get_reg(instr.rm);
	immutable  rn    = vm.get_reg(instr.rn);
	const uint res   = rn << shift;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
		if (shift != 0) {
        	bool carry = (rn << (32 - shift)) & 1;
        	vm.set_c(carry);
    	}
	}
	vm.set_reg(instr.rd, res);
}

string convert_lsl_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("lsl%s %s, %s", get_it_block_string(cond), 
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   LSR 											 *
// ***************************************************************************************

// =====================
//  Parse LSR(Register)
// =====================

enum field_tuples_lsr_reg_t1 = [Tuple!(opcode, string[])(opcode.lsr_reg_t1, ["rd","rm"])];
// LSR <Rdn>,<Rm>
// [15:6] 0100000011, [5:3] Rm, [2:0] Rdn  
instr_16 parse_lsr_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
		            rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute LSR(Register)
// =======================

void 
execute_lsr_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  shift = vm.get_reg(instr.rm);
	immutable  rn    = vm.get_reg(instr.rn);
	const uint res   = rn >> shift;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
		if (shift != 0) {
        	bool carry = (rn >> (shift - 1)) & 1;
    		vm.set_c(carry);
    	}
	}
	vm.set_reg(instr.rd, res);
}

string convert_lsr_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("lsr%s %s, %s", get_it_block_string(cond), 
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ASR 											 *
// ***************************************************************************************

// =====================
//  Parse ASR(Register)
// =====================

enum field_tuples_asr_reg_t1 = [Tuple!(opcode, string[])(opcode.asr_reg_t1, ["rd","rm"])];
// LSR <Rdn>,<Rm>
// [15:6] 0100000100, [5:3] Rm, [2:0] Rdn  
instr_16 parse_asr_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
		            rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute ASR(Register)
// =======================

void 
execute_asr_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable shift = vm.get_reg(instr.rm);
	immutable rn_u  = vm.get_reg(instr.rn);
	const int rn    = cast(int)(rn_u);
	uint res;
    if (shift >= 32) {
        res = (rn < 0) ? 0xFFFF_FFFF : 0;
        if (!vm.in_it_block()) {
            vm.set_c(rn < 0);
        }
    } else {
        res = cast(uint)(rn >> shift);
        if (!vm.in_it_block() && shift != 0) {
            bool carry = (rn_u >> (shift - 1)) & 1;
            vm.set_c(carry);
        }
    }

    if (!vm.in_it_block()) {
        vm.set_z(res);
        vm.set_n(res);
    }
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   MVN 											 *
// ***************************************************************************************

// =====================
//  Parse MVN(Register) 
// =====================

// MVNS <Rd>,<Rm>
// MVN<c> <Rd>,<Rm>
// [15:6] 0100001111, [5:3] Rm, [2:0] Rd
instr_16 parse_mvn_reg_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute MVN(Register)
// =======================

void 
execute_mvn_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable  rm  = vm.get_reg(instr.rm);
	const uint res = ~rm;
	if (instr.set_flags) {
		vm.set_z(res);			// APSR.Z = IsZeroBit(result);
		vm.set_n(res);			// APSR.N = result<31>;
		// APSR.C = carry;
		// APSR.V unchanged
	}
	vm.set_reg(instr.rd, res);
}

// MVNS <Rd>,<Rm>
// MVN<c> <Rd>,<Rm>
string convert_mvn_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("mvn%s %s, %s", get_it_block_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// =====================
//  Parse MOV(Register)
// =====================

enum field_tuples_mov_reg_t2 = [Tuple!(opcode, string[])(opcode.mov_reg_t2, ["rd","rm"])];
// MOV <Rd>,<Rm>
// [15:6] 0000000000, [7] D, [5:3] Rm, [2:0] Rd  
instr_16 parse_mov_reg_t2(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 4));
}

// =====================
//  Parse MOV(Register)
// =====================

void
execute_mov_reg_t2
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable res = vm.get_reg(instr.rm);
	vm.set_reg(instr.rd, res);
	// setflags = TRUE;
	vm.set_n(res);	// APSR.N = result<31>;
	vm.set_z(res);	// APSR.Z = IsZeroBit(result);
	// APSR.C unchanged
	// APSR.V unchanged
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   MUL 											 *
// ***************************************************************************************

// ===========
//  Parse MUL
// ===========

enum field_tuples_mul_t1 = [Tuple!(opcode, string[])(opcode.mul_t1, ["rd","rn"])];
// MUL <Rdm>,<Rn>,<Rdm>
// [15:6] 0100001101, [5:3] Rn, [2:0] Rdm
instr_16 parse_mul_t1(const ushort instr) {
	return instr_16(rm: cast(reg)slice(instr, 0, 3), 
					rd: cast(reg)slice(instr, 0, 3), 
					rn: cast(reg)slice(instr, 3, 3));
}

// =============
//  Execute MUL
// =============

void 
execute_mul_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  rm  = vm.get_reg(instr.rm);
	immutable  rn  = vm.get_reg(instr.rn);
	const uint res = rm * rn;
	if (!vm.in_it_block()) {
		vm.set_z(res);
		vm.set_n(res);
	}
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ORR 											 *
// ***************************************************************************************

// =====================
//  Parse ORR(Register)
// =====================

enum field_tuples_orr_reg_t1 = [Tuple!(opcode, string[])(opcode.orr_reg_t1, ["rd","rm"])];
// ORRS <Rdn>,<Rm>
// ORR<c> <Rdn>,<Rm>
// [15:6] 0100001100, [5:3] Rm, [2:0] Rdn
instr_16 parse_orr_reg_t1(const ushort instr) {
	return instr_16(rn: cast(reg)slice(instr, 0, 3), 
		            rd: cast(reg)slice(instr, 0, 3), 
		            rm: cast(reg)slice(instr, 3, 3));
}

// =======================
//  Execute ORR(Register)
// =======================

void 
execute_orr_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable  rn  = vm.get_reg(instr.rn);
	immutable  rm  = vm.get_reg(instr.rm);
	const uint res = rn | rm;
	if (instr.set_flags) {
		vm.set_z(res);
		vm.set_n(res);
	}
	vm.set_reg(instr.rd, res);
}

// ORRS <Rdn>,<Rm>
// ORR<c> <Rdn>,<Rm>
string convert_orr_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("orr%s %s, %s", get_it_block_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   RSB 											 *
// ***************************************************************************************

// ======================
//  Parse RSB(Immediate) 
// ======================

// RSBS <Rd>,<Rn>,#0 Outside IT block.
// RSB<c> <Rd>,<Rn>,#0 Inside IT block.
instr_16 parse_rsb_imm_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
		  			rn: cast(reg)slice(instr, 3, 3));
}

// ========================
//  Execute RSB(Immediate) 
// ========================

void 
execute_rsb_imm_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable rn  = vm.get_reg(instr.rn);
	immutable imm = instr.imm;
	// (result, carry, overflow) = AddWithCarry(NOT(R[n]), imm32, ‘1’);
	immutable res = add_with_carry(~rn, imm, true);
	if (!vm.in_it_block()) {
		vm.set_n(res.result);	// APSR.N = result<31>;
		vm.set_z(res.result);	// APSR.Z = IsZeroBit(result);
		vm.set_c(res.carry);	// APSR.C = carry;
		vm.set_v(res.overflow);	// APSR.V = overflow;
	}
	vm.set_reg(instr.rd, res.result);
}

// ==================================
//  Convert RSB(Immediate) to String
// ==================================

string convert_rsb_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("neg%s %s, %s", get_it_block_string(cond),
								  get_reg_name(instr.rd),
								  get_reg_name(instr.rn));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   SBC											 *
// ***************************************************************************************

// =====================
//  Parse SBC(Register)
// =====================

// SBCS <Rdn>,<Rm> Outside IT block.
// SBC<c> <Rdn>,<Rm> Inside IT block
instr_16 parse_sbc_reg_t1(const ushort instr) {
	return instr_16(rd: cast(reg)slice(instr, 0, 3),
					rn: cast(reg)slice(instr, 0, 3),
					rm: cast(reg)slice(instr, 3, 6));
}

// =======================
//  Execute SBC(Register)
// =======================

void 
execute_sbc_reg_t1
(vm_t)
(const ref instr_16 instr, vm_t vm) {
	immutable rn = vm.get_reg(instr.rn);
	immutable rm = vm.get_reg(instr.rm);
	// shifted = Shift(R[m], shift_t, shift_n, APSR.C);
	// (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), APSR.C);
	immutable res = add_with_carry(rn, ~rm, vm.get_c());
	if (!vm.in_it_block()) {
		vm.set_n(res.result);		// APSR.N = result<31>;
		vm.set_z(res.result);		// APSR.Z = IsZeroBit(result);
		vm.set_c(res.carry);		// APSR.C = carry;
		vm.set_v(res.overflow);		// APSR.V = overflow;
	}
	vm.set_reg(instr.rd, res.result);
}
// ---------------------------------------------------------------------------------------








