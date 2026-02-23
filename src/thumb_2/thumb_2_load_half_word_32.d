import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

import std.stdio;

// ***************************************************************************************
// *									   LDRH 										 *
// ***************************************************************************************

// ========================
//  Parse LDRSH(Immediate)
// ========================

instr_32 parse_ldrsh_imm_t1(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 12),
					add:   true,
					index: true,
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// LDRSH<c> <Rt>,[<Rn>,#-<imm8>]
// LDRSH<c> <Rt>,[<Rn>],#+/-<imm8>
// LDRSH<c> <Rt>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:4] 111110011011, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_ldrsh_imm_t2(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// ==============
//  Execute LDRH
// ==============

void 
execute_ldrsh_imm_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_ldrsh_imm(instr, vm);
}

void 
execute_ldrsh_imm_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_ldrsh_imm(instr, vm);
}

void 
execute_ldrsh_imm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	//if ConditionPassed() then
	//EncodingSpecificOperations();
	immutable    rn  	     = vm.get_reg(instr.rn);
	immutable    imm         = instr.imm;
	//offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm;
	//address = if index then offset_addr else R[n]
	const size_t addr        = instr.index ? offset_addr : rn;
	//data = MemU[address,2];
	immutable    data 		 = cast(int)cast(short)vm.read_half_word(addr);
	//if wback then R[n] = offset_addr;
	if (instr.wback) 
		vm.set_reg(instr.rn, offset_addr);
	//R[t] = SignExtend(data, 32);
	vm.set_reg(instr.rt, data);
}
// ---------------------------------------------------------------------------------------






