// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			            Load/Store Single Data Item	    					         *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;
import std.format : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

instr_16 parse_load_store_reg(const ushort instr) {
	return instr_16(rt: cast(reg)slice(instr, 0, 3),
	                rn: cast(reg)slice(instr, 3, 3),
	                rm: cast(reg)slice(instr, 6, 3));
}

// ***************************************************************************************
// *                                       LDR                                           *
// ***************************************************************************************

// =====================
//  Parse LDR(Register)
// =====================

enum field_tuples_ldr_reg_t1 = [Tuple!(opcode, string[])(opcode.ldr_reg_t1, ["rt","rn","rm"])];
// LDR <Rt>,[<Rn>,<Rm>]
// [15:9] 0101100, [8:6] Rm, [5:3] Rn, [2:0] Rt
instr_16 parse_ldr_reg_t1(const ushort instr) {
	return parse_load_store_reg(instr);
}

// =======================
//  Execute LDR(Register)
// =======================

void 
execute_ldr_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    rn   = vm.get_reg(instr.rn);
	immutable    rm   = vm.get_reg(instr.rm);
	const size_t addr = rn + rm;
	const uint   data = vm.read_word(addr);
	vm.set_reg(instr.rt, data);
}	
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRB 										 *
// ***************************************************************************************

// =======================
//  Parse LDRB(Immediate)
// =======================

enum field_tuples_ldrb_imm_t1 = [Tuple!(opcode, string[])(opcode.ldrb_imm_t1, ["rt","rn","imm"])];
// LDRB <Rt>,[<Rn>{,#<imm5>}]
// [15:11] 01111, [10:6] imm5, [5:3] Rn, [2:0] Rt
instr_16 parse_ldrb_imm_t1(const ushort instr) {
	return instr_16(rt:  cast(reg)slice(instr, 0, 3),
		            rn:  cast(reg)slice(instr, 3, 3),
		            imm: slice(instr, 6, 5));
}

// =========================
//  Execute LDRB(Immediate)
// =========================

void 
execute_ldrb_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rt = vm.get_reg(instr.rt);
	immutable rn = vm.get_reg(instr.rn);
	size_t addr  = rn + instr.imm;
	auto data = mem.read_byte(addr);
	cpu.set(ldrb_imm_instr.rt, cast(uint)data);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRH 										 *
// ***************************************************************************************

// =======================
//  Parse LDRH(Immediate)
// =======================

enum field_tuples_ldrh_imm_t1 = [Tuple!(opcode, string[])(opcode.ldrh_imm_t1, ["rt","rn","imm"])];
// LDRH <Rt>,[<Rn>{,#<imm5>}]
// [15:11] 10001, [10:6] imm5, [5:3] Rn, [2:0] Rt
instr_16 parse_ldrh_imm_t1(const ushort instr) {
	return instr_16(rt:  cast(reg)slice(instr, 0, 3),
	            rn:  cast(reg)slice(instr, 3, 3),
	            imm: slice(instr, 6, 5) << 1);
}

// =========================
//  Execute LDRH(Immediate)
// =========================

void 
execute_ldrh_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rt   = vm.get_reg(instr.rt);
	immutable rn   = vm.get_reg(instr.rn);
	size_t addr    = rn + instr.imm;
	immutable data = vm.read_half_word(addr);
	vm.set_reg(instr.rt, cast(uint)data);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRH 										 *
// ***************************************************************************************

// ======================
//  Parse STRH(Register)
// ======================

enum field_tuples_strh_reg_t1 = [Tuple!(opcode, string[])(opcode.strh_reg_t1, ["rt","rn","rm"])];
// STRH <Rt>,[<Rn>,<Rm>]
// [15:9] 0101001, [8:6] Rm, [5:3] Rn, [2:0] Rt
instr_16 parse_strh_reg_t1(const ushort instr) {
	return parse_load_store_reg(instr);
}

// ========================
//  Execute STRH(Register)
// ========================

void 
execute_strh_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable    rm     = vm.get_reg(instr.rm); 
	immutable    rn     = vm.get_reg(instr.rn);
	immutable    rt     = vm.get_reg(instr.rt);
	const size_t addr   = rn + rm;	
	const uint   target = (rt & 0xffff);
	mem.write_half_word(addr, cast(ushort)target);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRB 										 *
// ***************************************************************************************

// =======================
//  Parse STRRB(Register)
// =======================

enum field_tuples_strb_reg_t1 = [Tuple!(opcode, string[])(opcode.strb_reg_t1, ["rt","rn","rm"])];
// STRB <Rt>,[<Rn>{,#<imm5>}]
// [15:11] 01110, [10:6] imm5, [5:3] Rn, [2:0] Rt
instr_16 parse_strb_reg_t1(short instr) {
	return parse_load_store_reg(instr);
}

// =========================
//  Execute STRRB(Register)
// =========================

void 
execute_strb_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    rt   = vm.get_reg(instr.rt);
	immutable    rn   = vm.get_reg(instr.rn);
	immutable    rm   = vm.get_reg(instr.rm);
	const size_t addr = rn + rm;
	const uint   data = rt & 0xff;
	mem.write_byte(addr, data);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 STR 											 *
// ***************************************************************************************

// ======================
//  Parse STR(Immediate) 
// ======================

enum field_tuples_str_imm_t1 = [Tuple!(opcode, string[])(opcode.str_imm_t1, ["rt","rn","imm"])];
// STR <Rt>,[<Rn>{,#<imm5>}]
// [15:11] 10000, [10:6] imm5, [5:3] Rn, [2:0] Rt
instr_16 parse_str_imm_t1(short instr) {
	return instr_16(rt:  cast(reg)slice(instr, 0, 3),
	            	rn:  cast(reg)slice(instr, 3, 3),
	            	imm: slice(instr, 6, 5) << 2);
}

// ========================
//  Execute STR(Immediate)
// ========================

void 
execute_str_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rt      = vm.get_reg(instr.rt);
	immutable rn      = vm.get_reg(instr.rn);
	const size_t addr = rn + instr.imm;
	vm.write_word(addr, rt);
} 
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDR 										 *
// ***************************************************************************************

// ======================
//  Parse LDR(Immediate)
// ======================

enum field_tuples_ldr_imm_t1 = [Tuple!(opcode, string[])(opcode.ldr_imm_t1, ["rt","rn","imm"])];
// LDRB <Rt>,[<Rn>{,#<imm5>}]
// [15:11] 01101, [10:6] imm5, [5:3] Rn, [2:0] Rt
instr_16 parse_ldr_imm_t1(const ushort instr) {
	return instr_16(rt:  cast(reg)slice(instr, 0, 3),
	                rn:  cast(reg)slice(instr, 3, 3),
	                imm: slice(instr, 6, 5) << 2);
}

// ========================
//  Execute LDR(Immediate)
// ========================

void 
execute_ldr_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    rn   = cpu.get(instr.rn);
	const size_t addr = rn + instr.imm;
	immutable    data = mem.read_word(addr);
	vm.set_reg(instr.rt, data);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRH 										 *
// ***************************************************************************************

// =======================
//  Parse STRH(Immediate)
// =======================

enum field_tuples_strh_imm_t1 = [Tuple!(opcode, string[])(opcode.strh_imm_t1, ["rt","rn","imm"])];
// STRH <Rd>,<Rm>
// [15:11] 10000, [10:6] imm5, [5:3] Rd, [2:0] Rt
instr_16 parse_strh_imm_t1(short instr) {
	return instr_16(rt:  cast(reg)slice(instr, 0, 3),
		            rn:  cast(reg)slice(instr, 3, 3),
		            imm: slice(instr, 6, 5) << 1);
}

// =========================
//  Execute STRH(Immediate)
// =========================

void 
execute_strh_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    rt     = vm.get_reg(instr.rt);
	immutable    rn     = vm.get_reg(instr.rn);
	const size_t addr   = rn + instr.imm;
	auto         target = vm.read_word(addr);
	target = (target & 0xffff_0000) | rt;  
	mem.write_half_word(addr, cast(ushort)target);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRB 										 *
// ***************************************************************************************

// ========================
//  Parse STRRB(Immediate)
// ========================

enum field_tuples_strb_imm_t1 = [Tuple!(opcode, string[])(opcode.strb_imm_t1, ["rt","rn","imm"])];
// STRB <Rt>,[<Rn>{,#<imm5>}]
// [15:11] 01110, [10:6] imm5, [5:3] Rn, [2:0] Rt
instr_16 parse_strb_imm_t1(const ushort instr) {
	return instr_16(rt:  cast(reg)slice(instr, 0, 3),
	            	rn:  cast(reg)slice(instr, 3, 3),
	            	imm: slice(instr, 6, 5));
}

// =========================
//  Execute STRB(Immediate)
// =========================

void 
execute_strb_imm_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    rt   = vm.get_reg(instr.rt);
	immutable    rn   = vm.get_reg(instr.rn);
	const size_t addr = rn + instr.imm;
	const uint   data = rt & 0xff;
	vm.write_byte(addr, data);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
enum field_tuples_ldr_imm_t2 = [Tuple!(opcode, string[])(opcode.ldr_imm_t2, ["rt","sp","imm"])];
// LDR <Rt>,[SP{,#<imm8>}]
// [15:11] 10011, [10:8] Rt, [7:0] imm8
instr_16 parse_ldr_imm_t2(const ushort instr) {
	instr_16 res;
	immutable imm_8 = slice(instr, 0, 8);
	immutable rt    = slice(instr, 8, 3);
	res.rt    		= cast(reg)(rt);
	res.imm 		= (imm_8 << 2);
	return res;
}

void 
execute_ldr_imm_t2
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    sp   = cpu.get_sp();
	const size_t addr = sp + instr.imm;
	immutable    data = mem.read_word(addr);
	vm.set_reg(instr.rt, data);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
enum field_tuples_str_imm_t2 = [Tuple!(opcode, string[])(opcode.str_imm_t2, ["rt","sp","imm"])];
// STR <Rt>,[SP,#<imm8>]
// [15:11] 10010, [10:8] Rt, [7:0] imm8
instr_16 parse_str_imm_t2(const ushort instr) {
	instr_16 res;
	immutable imm_8 = slice(instr, 0, 8);
	immutable rt    = slice(instr, 8, 3);
	res.rt          = cast(reg)rt;
	res.imm         = imm_8 << 2;
	return res;
}

void 
execute_str_imm_t2
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rt      = cpu.get(instr.rt);
	const size_t addr = vm.get_sp() + instr.imm;
	vm.write_word(addr, rt);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 STR 											 *
// ***************************************************************************************

// =====================
//  Parse STR(Register)
// =====================

enum field_tuples_str_reg_t1 = [Tuple!(opcode, string[])(opcode.str_reg_t1, ["rt","rn","rm"])];
// STR <Rt>,[<Rn>,<Rm>]
// [15:9] 0101000, [8:6] Rm, [5:3] Rn, [2:0] Rt
instr_16 parse_str_reg_t1(const short instr) {
	return parse_load_store_reg(instr);
}

// =======================
//  Execute STR(Register)
// =======================

void 
execute_str_reg_t1(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable    rn   = vm.get_reg(instr.rn);
	immutable    rm   = vm.get_reg(instr.rm);
	const size_t addr = rn + rm;
	immutable    data = vm.get_reg(instr.rt);
	mem.write_word(addr, data);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRB 										 *
// ***************************************************************************************

// ======================
//  Parse LDRB(Register)
// ======================

enum field_tuples_ldrb_reg_t1 = [Tuple!(opcode, string[])(opcode.ldrb_reg_t1, ["rt","rn","rm"])];
// LDRB <Rt>,[<Rn>,<Rm>]
// [15:9] 0101110, [8:6] Rm, [5:3] Rn, [2:0] Rt
instr_16 parse_ldrb_reg_t1(const ushort instr) {
	return parse_load_store_reg(instr);
}

// ========================
//  Execute LDRB(Register)
// ========================

void 
execute_ldrb_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	immutable rn   = cpu.get(instr.rn);
	immutable rm   = cpu.get(instr.rm);
	size_t addr    = rn + rm;
	immutable data = vm.read_byte(addr);
	vm.set_reg(instr.rt, cast(uint)data);
}
// ---------------------------------------------------------------------------------------


// ================
//  Executre LDRSB
// ================

void 
execute_ldrsb_imm_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t addr = vm.get_reg(instr.rn) + instr.imm;
	byte val = cast(byte)vm.read_byte(addr);
	vm.set_reg(instr.rt, cast(int)val);	
}