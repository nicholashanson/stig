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

enum field_tuples_bl_t1 = [Tuple!(opcode, string[])(opcode.bl_t1, ["label"])];
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
(const instr_32 instr, ref vm_t vm) {
	const uint pc  = vm.get_reg(reg.pc);
	const uint res = ((pc + 4) | 0b1);
	vm.set_reg(reg.lr, res);
	vm.set_reg(reg.pc, pc + instr.offset + 4);
}

// ======================
//  Convert BL to String
// ======================

string convert_bl_t1_to_string(const ref instr_32 instr) {
	return "bl <label>"; 
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

enum field_tuples_msr_t1 = [Tuple!(opcode, string[])(opcode.msr_t1, ["spec_reg", "rn"])];
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
		case special_reg.BASEPRI: vm.cpu.basepri = cast(ubyte)(rn & 0xf0); break;
		case special_reg.MSP    : vm.cpu.msp = rn;						   break;
		case special_reg.PSP    : vm.cpu.psp = rn; 						   break;
		case special_reg.CONTROL: 
		    vm.cpu.npriv  = (rn & 0x1) != 0;
			vm.cpu.sp_sel = (rn & 0x2) != 0; 							   break;
		case special_reg.BASEPRI_MAX:
		    ubyte new_val = cast(ubyte)(rn & 0xff);
    		if (new_val > vm.cpu.basepri || vm.cpu.basepri == 0) 
        		vm.cpu.basepri = new_val;
    		break;
		default:
			return;
	}
}

string convert_msr_t1_to_string(const ref instr_32 instr) {
	return format("msr %s, %s", instr.spec_reg.to!string, instr.rn.to!string);
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

enum field_tuples_mrs_t1 = [Tuple!(opcode, string[])(opcode.mrs_t1, ["rd", "spec_reg"])];
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
		case special_reg.BASEPRI:
			vm.set_reg(instr.rd, cast(uint)vm.cpu.basepri);
			break;
		case special_reg.IPSR:
			vm.set_reg(instr.rd, cast(uint)vm.cpu.current_exception & 0x1ff);
			break;
		case special_reg.MSP:
			vm.set_reg(instr.rd, vm.cpu.msp);
			break;
		case special_reg.PSP:
			vm.set_reg(instr.rd, vm.cpu.psp);
			break;
		case special_reg.CONTROL:
			uint val = 0;
			if (vm.cpu.sp_sel)
        		val |= 0x2; 
			vm.set_reg(instr.rd, val);
			break;
		default:
			return;
	}
}

// =======================
//  Convert MRS to String
// =======================

// MRS<c> <Rd>,<spec_reg>
string convert_mrs_t1_to_string(const ref instr_32 instr) {
	return format("mrs %s, %s", instr.rd.to!string, instr.spec_reg.to!string);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					            Conditional Branch					                 *
// ***************************************************************************************

enum field_tuples_b_t4 = [Tuple!(opcode, string[])(opcode.b_t4, ["label"])];
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
(const instr_32 instr, ref vm_t vm) {
	auto pc = vm.get_pc();
	pc += instr.offset + 4;
	vm.set_reg(reg.pc, pc);
}
// ---------------------------------------------------------------------------------------

// =========
//  Parse B
// =========

enum field_tuples_b_t3 = [Tuple!(opcode, string[])(opcode.b_t3, ["label"])];
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
(const instr_32 instr, ref vm_t vm) {
	if (condition_is_met(instr.cond, vm.cpu)) {
		int pc = vm.get_pc();
		pc += instr.offset + 4;
		vm.set_reg(reg.pc, pc);
	}
}

// =====================
//  Convert B to String
// =====================

string convert_b_t3_to_string(const ref instr_32 instr) {
	return "b.w <label>";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   NOP 											 *
// ***************************************************************************************

// ===========
//  Parse NOP
// ===========

enum field_tuples_nop_t2 = [Tuple!(opcode, string[])(opcode.nop_t2, [])];

instr_32 parse_nop_t2(uint instr) {
	return instr_32();
}

// =============
//  Execute NOP
// =============

void 
execute_nop_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert NOP to String
// =======================

string convert_nop_t2_to_string(const ref instr_32 instr) {
	return "nop";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   ISB 											 *
// ***************************************************************************************

enum field_tuples_isb_t1 = [Tuple!(opcode, string[])(opcode.isb_t1, [])];

// ===========
//  Parse ISB
// ===========

instr_32 parse_isb_t1(uint instr) {
	return instr_32();
}

// =============
//  Execute ISB
// =============

void 
execute_isb_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert ISB to String
// =======================

string convert_isb_t1_to_string(const ref instr_32 instr) {
	return "isb";
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   DSB 											 *
// ***************************************************************************************

enum field_tuples_dsb_t1 = [Tuple!(opcode, string[])(opcode.dsb_t1, [])];

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
(const instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert DSB to String
// =======================

string convert_dsb_t1_to_string(const ref instr_32 instr) {
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
(const instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert DSB to String
// =======================

string convert_dmb_t1_to_string(const ref instr_32 instr) {
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
(const instr_32 instr, ref vm_t vm) {}

// =======================
//  Convert DSB to String
// =======================

string convert_yield_t2_to_string(const ref instr_32 instr) {
	return "yield";
}
// --------------------------------------------------------------------------------------