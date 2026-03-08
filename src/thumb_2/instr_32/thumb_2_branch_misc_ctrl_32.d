import std.typecons : Tuple;
import std.format;
import std.conv;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *									   BL 											 *
// ***************************************************************************************
// Branch with Link (immediate) calls a subroutine at a PC-relative address.

// ==========
//  Parse BL
// ==========

// BL<c> <label> 
// First Half-Word: [15:11] 11110, [10] S, [9:0] imm10
// Second Half-Word: [15:14] 11, [13] J1, [12] 1, [11] J2, [10:0] imm11
instr_32 parse_bl_t1(const uint instr) {
	immutable imm_11 = slice(instr,  0, 11);
	immutable imm_10 = slice(instr, 16, 10);
	immutable j1 	 = slice(instr, 13,  1);
	immutable j2 	 = slice(instr, 11,  1);
	immutable s      = slice(instr, 26,  1);
	int imm_32 = (s << 24) | (!(j1 ^ s) << 23) 
						   | (!(j2 ^ s) << 22) 
						   | (imm_10 << 12) 
						   | (imm_11 << 1);
	if (s == 0b1) 
		imm_32 |= 0xfe00_0000;
	return instr_32(offset: imm_32);
}

// ============
//  Execute BL
// ============

void 
execute_bl_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	const uint pc  = vm.get_reg(reg.pc);
	const uint res = ((pc + 4) | 0b1);
	vm.set_reg(reg.lr, res);
	vm.set_reg(reg.pc, pc + instr.offset + 4);
}

// ======================
//  Convert BL to String
// ======================

// BL<c> <label> 
string convert_bl_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("bl%s <label>", get_condition_string(cond)); 
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 MSR 											 *
// ***************************************************************************************
// Move to Special Register from ARM Register moves the value of a general-purpose ARM 
// register to the specified special-purpose register.

// ===========
//  Parse MSR
// ===========

// MSR<c> <spec_reg>,<Rn>
// First Half-Word: [15:4] 111100111000, [3:0] Rn
// Second Half-Word: [15:12] 1000, [11:10] mask, [9:8] 00, [7:0] SYSm
instr_32 parse_msr_t1(const uint instr) {
	return instr_32(mask:     cast(ubyte)slice(instr, 10, 2),
					rn:       cast(reg)slice(instr, 16, 4),
					spec_reg: cast(special_reg)slice(instr, 0, 8));
}

// =============
//  Execute MSR
// =============

void 
execute_msr_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	immutable rn = vm.get_reg(instr.rn);
	switch (instr.spec_reg) {
		case special_reg.APSR:
			// if mask<0> == ‘1’ then /* GE[3:0] bits */
			//		if !HaveDSPExt() then
			//			UNPREDICTABLE
			//		else
			//			APSR<19:16> = R[n]<19:16>;
			// if mask<1> == ‘1’ then /* N, Z, C, V, Q bits */
			//		APSR<31:27> = R[n]<31:27>;
			immutable  _nzcvq  = slice(rn, 27, 5);
			immutable  _g      = slice(rn, 16, 4);
			const uint _nzcvqg = _nzcvq | _g;
			final switch(instr.mask) {
				case 0b00: 					         break;
				case 0b01: vm.cpu.set_apsr(_g);	     break;
				case 0b10: vm.cpu.set_apsr(_nzcvq);  break;
				case 0b11: vm.cpu.set_apsr(_nzcvqg); break;
			}
			break;
		case special_reg.BASEPRI:
			auto b = cast(ubyte)(rn & 0xf0); 
			vm.set_basepri(b);  
			vm.log_msr("BASEPRI", b);
			break;
		case special_reg.MSP    : 
			vm.set_msp(rn);						   
			vm.log_msr("MSP", rn);
			break;
		case special_reg.PSP    : 
			vm.set_psp(rn); 						   
			vm.log_msr("PSP", rn);
			break;
		case special_reg.CONTROL: 
		    vm.set_npriv(( rn & 0x1) != 0);
			vm.set_sp_sel((rn & 0x2) != 0);
			vm.log_msr("CONTROL", rn); 							   
			break;
		case special_reg.BASEPRI_MAX:
		    ubyte new_val = cast(ubyte)(rn & 0xff);
    		if (new_val > vm.get_basepri() || vm.get_basepri() == 0) 
        		vm.set_basepri(new_val);
    		break;
    	// All fields read as zero using an MRS instruction, and the 
    	// processor ignores writes to the EPSR by an MSR instruction.
    	case special_reg.EPSR:
    		break;
		default:
			return;
	}
}

// =======================
//  Convert MSR to String
// =======================

string convert_msr_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("msr%s %s, %s", cond != condition.none ? cond.to!string : "",
								  instr.spec_reg.to!string, 
								  get_reg_name(instr.rn));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   MRS 											 *
// ***************************************************************************************
// Move to Special Register from ARM Register moves the value of a general-purpose ARM 
// register to the specified special-purpose register.

// ===========
//  Parse MRS
// ===========

// MRS<c> <Rd>,<spec_reg>
// First Half-Word: [15:4] 111100111000, [3:0] Rn
// Second Half-Word: [15:12] 1000, [11:10] mask, [9:8] 00, [7:0] SYSm
instr_32 parse_mrs_t1(const uint instr) {
	return instr_32(rd:       cast(reg)slice(instr, 8, 4),
					spec_reg: cast(special_reg)slice(instr, 0, 8));
}

// =============
//  Execute MRS
// =============

void 
execute_mrs_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	switch (instr.spec_reg) {
		case special_reg.APSR:
			vm.set_reg(instr.rd, vm.cpu.get_apsr());
			break;
		case special_reg.BASEPRI:
			vm.set_reg(instr.rd, cast(uint)vm.get_basepri());
			break;
		case special_reg.IPSR:
			// IPSR<8:0> = ExceptionNumber
			vm.set_reg(instr.rd, vm.cpu.get_ipsr());
			break;
		case special_reg.MSP:
			vm.set_reg(instr.rd, vm.get_msp());
			vm.log_mrs("MSP", vm.get_msp());
			break;
		case special_reg.PSP:
			vm.set_reg(instr.rd, vm.get_psp());
			vm.log_mrs("PSP", vm.get_psp());
			break;
		case special_reg.CONTROL:
			uint val = 0;
			if (vm.get_sp_sel())
        		val |= 0x2; 
			vm.set_reg(instr.rd, val);
			break;
		// All fields read as zero using an MRS instruction, and the 
    	// processor ignores writes to the EPSR by an MSR instruction.
    	case special_reg.EPSR:
    		vm.set_reg(instr.rd, 0);
    		break;
		default:
			return;
	}
}

// =======================
//  Convert MRS to String
// =======================

// MRS<c> <Rd>,<spec_reg>
string convert_mrs_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("mrs%s %s, %s", cond != condition.none ? cond.to!string : "", 
								  get_reg_name(instr.rd),
								  instr.spec_reg.to!string);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					            Conditional Branch					                 *
// ***************************************************************************************

// First Half-Word: [15:11] 11110, [10] S, [9:0] imm10
// Second Half-Word: [15:14] 10, [13] J1, [12] 1, [11] J2, [10:0] imm11
instr_32 parse_b_t4(const uint instr) {
	immutable imm_11 = slice(instr,  0, 11);
	immutable imm_10 = slice(instr, 16, 10);
	immutable j1 	 = slice(instr, 13,  1);
	immutable j2 	 = slice(instr, 11,  1);
	immutable s  	 = slice(instr, 26,  1);
	int imm_32 = (s << 24) | (!(j1 ^ s) << 23) 
						   | (!(j2 ^ s) << 22) 
						   | (imm_10 << 12) 
						   | (imm_11 << 1);
	if (s == 0b1) 
		imm_32 |= 0xfe00_0000;
	return instr_32(offset: imm_32);
}

// ===========
//  Execute B
// ===========

void 
execute_b_t4
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	auto pc = vm.get_pc();
	pc += instr.offset + 4;
	vm.set_reg(reg.pc, pc);
}

// B<c>.W <label>
string convert_b_t4_to_string(const ref instr_32 instr, const condition cond) {
	return format("b%s.w <label>", get_condition_string(cond));
}
// ---------------------------------------------------------------------------------------

// =========
//  Parse B
// =========

// B<c>.W <label>
// First Half-Word: [15:11] 11110, [10] S, [9:6] cond, [5:0] imm6
// Second Half-Word: [15:14] 10, [13] J1, [12] 1, [11] J2, [10:0] imm11
instr_32 parse_b_t3(const uint instr) {
	immutable imm_11 = slice(instr,  0, 11);
	immutable imm_6  = slice(instr, 16,  6);
	immutable j1 	 = slice(instr, 13,  1);
	immutable j2 	 = slice(instr, 11,  1);
	immutable s      = slice(instr, 26,  1);
	int imm_32 = (s << 20) | (j1 << 19) 
						   | (j2 << 18) 
						   | (imm_6 << 12) 
						   | (imm_11 << 1);
	if (s == 0b1) 
		imm_32 |= 0xffe0_0000;
	return instr_32(offset: imm_32, cond: cast(condition)slice(instr, 22, 4));
}

// ===========
//  Execute B
// ===========

void 
execute_b_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	if (condition_is_met(instr.cond, vm.cpu)) {
		int pc = vm.get_pc();
		pc += instr.offset + 4;
		vm.set_reg(reg.pc, pc);
	}
}

// =====================
//  Convert B to String
// =====================

string convert_b_t3_to_string(const ref instr_32 instr, const condition cond) {
	return "b.w <label>";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   NOP 											 *
// ***************************************************************************************

// ===========
//  Parse NOP
// ===========

instr_32 parse_nop_t2(uint instr) {
	return instr_32();
}

// =============
//  Execute NOP
// =============

void 
execute_nop_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert NOP to String
// =======================

string convert_nop_t2_to_string(const ref instr_32 instr, const condition cond) {
	return "nop";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ISB 											 *
// ***************************************************************************************

// ===========
//  Parse ISB
// ===========

// ISB<c> #<option>
instr_32 parse_isb_t1(const uint instr) {
	return instr_32();
}

// =============
//  Execute ISB
// =============

void 
execute_isb_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert ISB to String
// =======================

string convert_isb_t1_to_string(const ref instr_32 instr, const condition cond) {
	return "isb sy";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   DSB 											 *
// ***************************************************************************************

// ===========
//  Parse DSB
// ===========

instr_32 parse_dsb_t1(uint instr) {
	return instr_32();
}

// =============
//  Execute DSB
// =============

void 
execute_dsb_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert DSB to String
// =======================

string convert_dsb_t1_to_string(const ref instr_32 instr, const condition cond) {
	return "dsb";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   DMB 											 *
// ***************************************************************************************

// ===========
//  Parse DMB
// ===========

instr_32 parse_dmb_t1(uint instr) {
	return instr_32();
}

// =============
//  Execute DMB
// =============

void 
execute_dmb_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert DSB to String
// =======================

string convert_dmb_t1_to_string(const ref instr_32 instr, const condition cond) {
	return "dmb";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 YIELD 											 *
// ***************************************************************************************

// =============
//  Parse YIELD
// =============

instr_32 parse_yield_t2(uint instr) {
	return instr_32();
}

// =============
//  Execute DSB
// =============

void 
execute_yield_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert DSB to String
// =======================

string convert_yield_t2_to_string(const ref instr_32 instr, const condition cond) {
	return "yield";
}
// --------------------------------------------------------------------------------------