import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

import std.stdio;

// ***************************************************************************************
// *									   LDRSH 										 *
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

// ==========================
//  Execute LDRSH(Immediate)
// ==========================

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

// LDRSH<c> <Rt>,[<Rn>,#<imm12>]
string convert_ldrsh_imm_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrsh%s.w %s, [%s%s]", get_condition_string(cond),
										  get_reg_name(instr.rt),
										  get_reg_name(instr.rn),
										  get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   LDRH 										 *
// ***************************************************************************************

// LDRH<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
instr_32 parse_ldrh_reg_t2(const uint instr) {
	return instr_32(rm:	     cast(reg)slice(instr,  0, 4), 
					rt:	     cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4),
					shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					index:   true,
		            add:     true);
	// index = TRUE; add = TRUE; wback = FALSE;
}

void 
execute_ldrh_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
 	// if ConditionPassed() then
 	// EncodingSpecificOperations();
 	immutable rn   		   = vm.get_reg(instr.rn);
 	immutable rm 		   = vm.get_reg(instr.rm);
 	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
 	const uint offset      = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
 	// offset_addr = if add then (R[n] + offset) else (R[n] - offset);
 	const uint offset_addr = instr.add   ? rn + offset : rn - offset;
 	// address = if index then offset_addr else R[n];
 	const uint addr   	   = instr.index ? offset_addr : rn;
 	// data = MemU[address,2];
 	immutable  data        = vm.read_half_word(addr);
 	// if wback then R[n] = offset_addr;
 	// R[t] = ZeroExtend(data, 32);
 	vm.set_reg(instr.rt, cast(uint)data);
 }


// LDRH<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_ldrh_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrh%s.w %s, [%s, %s, lsl #%d]", get_condition_string(cond),
													get_reg_name(instr.rt),
													get_reg_name(instr.rn),
													get_reg_name(instr.rm),
													instr.shift_n);
}

// ***************************************************************************************
// *									   LDRH 										 *
// ***************************************************************************************

// LDRH<c>.W <Rt>,[<Rn>{,#<imm12>}]
instr_32 parse_ldrh_imm_t2(const uint instr) {
	return instr_32(imm: slice(instr, 0, 12),
					rt:  cast(reg)slice(instr, 12, 4),
					rn:  cast(reg)slice(instr, 16, 4));
}

void 
execute_ldrh_imm_t2
(vm_t)
(const ref instr_32 instr, vm_t vm) {
	// EncodingSpecificOperations();
	immutable rn      		 = vm.get_reg(instr.rm);
	immutable imm     		 = instr.imm; 
	// offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm; 
	// address = if index then offset_addr else R[n];
	const size_t addr 		 = instr.index ? offset_addr : rn;
	// data = MemU[address,2];
	immutable data           = vm.read_half_word(addr);
	// if wback then R[n] = offset_addr;
	// R[t] = ZeroExtend(data, 32);
	vm.set_reg(instr.rd, cast(uint)data);
}

// LDRH<c>.W <Rt>,[<Rn>{,#<imm12>}]
string convert_ldrh_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrh%s.w %s, [%s%s]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 get_reg_name(instr.rn),
										 get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									   LDRSH 										 *
// ***************************************************************************************

// LDRSH<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
instr_32 parse_ldrsh_reg_t2(const uint instr) {
	return instr_32(rt:		 cast(reg)slice(instr, 12, 4),
					rn: 	 cast(reg)slice(instr, 16, 4),
					rm:		 cast(reg)slice(instr,  0, 4),
					shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					index:   true,
					add:     true);
}

void 
execute_ldrsh_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable    rm          = vm.get_reg(instr.rm);
	immutable    rn          = vm.get_reg(instr.rn);
	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
	const uint   offset      = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// offset_addr = if add then (R[n] + offset) else (R[n] - offset);
	const size_t offset_addr = instr.add   ? rn + offset : rn - offset;
 	// address = if index then offset_addr else R[n];
 	const size_t addr        = instr.index ? offset_addr : rn;
	// data = MemU[address,2];
	immutable data           = cast(int)cast(short)vm.read_half_word(addr);
	// if wback then R[n] = offset_addr;
	// R[t] = SignExtend(data, 32);
	vm.set_reg(instr.rt, cast(uint)data);
}

// LDRSH<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_ldrsh_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("ldrsh%s.w %s, [%s, %s%s]", get_condition_string(cond),
											  get_reg_name(instr.rt),
											  get_reg_name(instr.rn),
											  get_reg_name(instr.rm),
											  get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------