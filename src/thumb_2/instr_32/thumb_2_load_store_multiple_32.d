// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			             Load Multiple and Store Multiple	    					 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.array;
import std.conv;
import std.algorithm;
import std.format   : format;
import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ***************************************************************************************
// *									 LDMIA 											 *
// ***************************************************************************************
// Load Multiple loads multiple registers from consecutive memory locations using an 
// address from a base register. The sequential memory locations start at this address, 
// and the address just above the last of those locations can optionally be written back 
// to the base register.

// The registers loaded can include the PC. If they do, the word loaded for the PC is 
// treated as a branch address or an exception return value.

// =============
//  Parse LMDIA
// =============

// LDM<c>.W <Rn>{!},<registers>
instr_32 parse_ldm_t2(const uint instr) {
	immutable reg_mask = slice(instr, 0, 16);
	reg[] reg_list;
	foreach (i; 0 .. 16)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	return instr_32(rn:       cast(reg )slice(instr, 16, 4),
					wback:    cast(bool)slice(instr, 21, 1),
					reg_list: reg_list);	
}

// ===============
//  Execute LMDIA
// ===============

void 
execute_ldm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	uint rn   = vm.get_reg(instr.rn);
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	foreach (r; regs) {
		immutable data = vm.read_word(rn);
		vm.set_reg(r, data);
		rn += 4;
	}
	if (instr.wback) 
		vm.set_reg(instr.rn, rn);
}

// LDM<c>.W <Rn>{!},<registers>
string convert_ldm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldmia%s.w %s%s, {%s}", get_condition_string(cond),
									      get_reg_name(instr.rn),
									      instr.wback ? "!": "",
									      get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------

// ===========
//  Parse POP
// ===========

// First Half-Word: [15:6] 1110100010, [5] W, [4] 1, [3:0] Rn
// Second Half-Word: [15] P, [14] M, [13] 0, [12:0] register_list 
instr_32 parse_pop_t2(const uint instr) {
	// registers = ‘0’:M:’000000’:register_list;
	immutable reg_mask = slice(instr, 0, 16); 
	reg[] reg_list;
	foreach (i; 0 .. 16)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	return instr_32(reg_list: reg_list);
}

// =============
//  Execute POP
// =============

void 
execute_pop_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	foreach (r; regs) {
		immutable val = vm.pop();
		vm.set_reg(r, val);
	}
	if (regs.back == reg.pc) 
		vm.clear_thumb_bit();
}

// ldmia.w sp!, {r3, r4, r5, r6, r7, r8, r9, pc}
string convert_pop_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldmia.w sp!, {%s}", get_reg_list_string(instr.reg_list));
}

// ---------------------------------------------------------------------------------------

// STM<c>.W <Rn>{!},<registers>
instr_32 parse_stm_t2(const uint instr) {
	immutable reg_mask = slice(instr, 0, 16);
	reg[] reg_list;
	foreach (i; 0 .. 16)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	return instr_32(rn:    	  cast(reg )slice(instr, 16, 4),
					wback:    cast(bool)slice(instr, 21, 1),
					reg_list: reg_list);	
}

// ================
//  Execute  STMIA
// ================

void 
execute_stm_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	uint rn   = vm.get_reg(instr.rn);
	foreach (r; regs) {
		uint data = vm.get_reg(r);
		vm.write_word(rn, data);
		rn += 4;
	}
	if (instr.wback) 
		vm.set_reg(instr.rn, rn);
}

// STM<c>.W <Rn>{!},<registers>
string convert_stm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("stmia%s.w %s%s, {%s}", get_condition_string(cond),
										  get_reg_name(instr.rn),
										  instr.wback ? "!": "",
										  get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------

// ============
//  Parse PUSH
// ============

// First Half-Word: [15:0] 1110100100101101
// Second Half-Word: [15] 0, [14] M, [13] 0, [12:0] register_list
instr_32 parse_push_t2(const uint instr) {
	immutable reg_mask = slice(instr, 0, 16); // registers = ‘0’:M:’000000’:register_list;
	reg[] reg_list;
	foreach (i; 0 .. 16)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	return instr_32(reg_list: reg_list);
}

// ==============
//  Execute PUSH
// ==============

void 
execute_push_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup;
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	foreach (r; regs) {
		vm.push(vm.get_reg(r));
	}
}

// STMDB<c><q> SP!, <registers>
string convert_push_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("stmdb%s sp!, {%s}", get_condition_string(cond),
									   get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 STMDB 											 *
// ***************************************************************************************

// STMDB<c> <Rn>{!},<registers>
instr_32 parse_stmdb_t1(const uint instr) {
	immutable reg_mask = slice(instr, 0, 16);
	reg[] reg_list;
	foreach (i; 0 .. 16)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	return instr_32(rn:    	  cast(reg )slice(instr, 16, 4),
					wback:    cast(bool)slice(instr, 21, 1),
					reg_list: reg_list);
}

void 
exeucte_stmdb_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	// EncodingSpecificOperations();
	immutable rn      = vm.get_reg(instr.rn);
	// address = R[n] - 4*BitCount(registers);
	const size_t addr = rn - (4 * instr.reg_list.length);
	// for i = 0 to 14
	foreach (r; regs) {
		// if registers<i> == ‘1’ then
		uint data = vm.get_reg(r);
		// MemA[address,4] = R[i];
		vm.write_word(addr, data);
		// address = address + 4;
		addr += 4;
	}
	// if wback then R[n] = R[n] - 4*BitCount(registers);
	if (instr.wback) 
		vm.set_reg(instr.rn, rn);
}
 

// STMDB<c> <Rn>{!},<registers>
string convert_stmdb_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("stmdb%s %s%s, {%s}", get_condition_string(cond),
										get_reg_name(instr.rn),
										instr.wback ? "!" : "",
										get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 LDMDB 											 *
// ***************************************************************************************

// LDMDB<c> <Rn>{!},<registers>
instr_32 parse_ldmdb_t1(const uint instr) {
	immutable reg_mask = slice(instr, 0, 16);
	reg[] reg_list;
	foreach (i; 0 .. 16)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
	return instr_32(rn:       cast(reg )slice(instr, 16, 4),
					wback:    cast(bool)slice(instr, 21, 1),
					reg_list: reg_list);
}

void
execute_ldmdb_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	// EncodingSpecificOperations();
	immutable rn   = vm.get_reg(instr.rn);
	// address = R[n] - 4*BitCount(registers);
	size_t 	  addr = rn - 4 * regs.length; 
	// for i = 0 to 14
	foreach (r; regs) {
		// if registers<i> == ‘1’ then
		// R[i] = MemA[address,4]; address = address + 4;
		immutable data = vm.read_word(addr);
		vm.set_reg(r, data);
		addr += 4;
	}
	// if wback && registers<n> == ‘0’ then R[n] = R[n] - 4*BitCount(registers);
	if (instr.wback && !regs.canFind(instr.rn))
		vm.set_reg(instr.rn, cast(uint)(rn - 4 * regs.length));
}

// LDMDB<c> <Rn>{!},<registers>
string convert_ldmdb_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldmdb%s %s%s, {%s}", get_condition_string(cond),
									    get_reg_name(instr.rn),
									    instr.wback && !instr.reg_list.canFind(instr.rn) ? "!" : "",
									    get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------