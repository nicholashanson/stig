// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                 Store Single Data Item	    					         *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;
import std.format   : format;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *					                   STR  										 *
// ***************************************************************************************

// ======================
//  Parse STR(Immediate)
// ======================

// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_str_imm_t3(const uint instr) {
	return instr_32(rt:    cast(reg)slice(instr, 12,  4), 
					rn:    cast(reg)slice(instr, 16,  4),
					imm:   slice(instr,  0, 12),
					index: true, add: true);
}

// ======================
//  Parse STR(Immediate)
// ======================

// STRH<c> <Rt>,[<Rn>,#-<imm8>]
// STRH<c> <Rt>,[<Rn>],#+/-<imm8>
// STRH<c> <Rt>,[<Rn>,#+/-<imm8>]!
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [11] 1, [10] P, [9] U, [8] W, [7:0] imm8
instr_32 parse_str_imm_t4(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// ========================
//  Execute STR(Immediate)
// ========================

void 
execute_str_imm_t3
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_str_imm(instr, vm);
}

void 
execute_str_imm_t4
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	execute_str_imm(instr, vm);
}

void 
execute_str_imm
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	size_t offset_addr; 
	immutable rn    = vm.get_reg(instr.rn);
	offset_addr     = instr.add   ? rn + instr.imm : rn - instr.imm;
	size_t addr     = instr.index ? offset_addr    : rn;
	const uint data = vm.get_reg(instr.rt);
	vm.write_word(addr, data);
	if (instr.wback) 
		vm.set_reg(instr.rn, cast(uint)offset_addr);
}

// STR<c>.W <Rt>,[<Rn>,#<imm12>]
string convert_str_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
	return format("str%s.w %s, [%s, #%d]", get_condition_string(cond),
										   get_reg_name(instr.rt),
										   get_reg_name(instr.rn),
										   instr.imm);
}

// STR<c> <Rt>,[<Rn>,#-<imm8>]
// STR<c> <Rt>,[<Rn>],#+/-<imm8>
// STR<c> <Rt>,[<Rn>,#+/-<imm8>]!
string convert_str_imm_t4_to_string(const ref instr_32 instr, const condition cond) {
	return format("str%s.w %s, %s", get_condition_string(cond),
								    get_reg_name(instr.rt),
								    get_addr_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRB 										 *
// ***************************************************************************************

// =======================
//  Parse STRB(Immediate)
// =======================

// STRB<c>.W <Rt>,[<Rn>,#<imm12>]
// First Half-Word: [15:4] 111110001000, [3:0] Rn 
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_strb_imm_t2(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 12),
					add:   true,
					index: true,
					rt:    cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4));
}

// =======================
//  Parse STRB(Immediate)
// =======================

// STRB<c> <Rt>,[<Rn>,#-<imm8>]
// STRB<c> <Rt>,[<Rn>],#+/-<imm8>
// STRB<c> <Rt>,[<Rn>,#+/-<imm8>]!
// First Half-Word:[15:4] 111110001000, [3:0] Rn 
// Second Half-Word: [15:12] Rt, [11:0] imm12
instr_32 parse_strb_imm_t3(uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					wback: cast(bool)slice(instr,  8, 1),
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4));
}

// =========================
//  Execute STRB(Immediate)
// =========================

void 
execute_strb_imm_t2
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	return execute_strb_imm(instr, vm);
}

void 
execute_strb_imm_t3
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	return execute_strb_imm(instr, vm);
}

void 
execute_strb_imm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable    rn          = vm.get_reg(instr.rn);
	immutable    imm         = instr.imm;
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm;
	const size_t addr        = instr.index ? offset_addr : rn;
	uint         data        = vm.get_reg(instr.rt) & 0xff;
	vm.write_byte(addr, cast(ubyte)data);
	if (instr.wback) 
		vm.set_reg(instr.rn, cast(uint)offset_addr);
}

string convert_strb_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("strb%s.w %s, [%s, #%d]", get_condition_string(cond),
											get_reg_name(instr.rt),
											get_reg_name(instr.rn),
											instr.imm);
}

// STRB<c> <Rt>,[<Rn>,#-<imm8>]
// STRB<c> <Rt>,[<Rn>],#+/-<imm8>
// STRB<c> <Rt>,[<Rn>,#+/-<imm8>]!
string convert_strb_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
	return format("strb%s.w %s, %s", get_condition_string(cond),
									 get_reg_name(instr.rt),
									 get_addr_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRH 										 *
// ***************************************************************************************

// ======================
//  Parse STRH(Register)
// ======================

// STRH<c> <Rt>,[<Rn>,<Rm>]
// First Half-Word: [15:4] 111110000010, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_strh_reg_t2(const uint instr) {
	return instr_32(shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					add:     true,
					index:   true,
					rm:      cast(reg)slice(instr, 0,  4),
					rt:      cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4));
}

// ========================
//  Execute STRH(Register)
// ========================

void 
execute_strh_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm        = vm.get_reg(instr.rm); 
	immutable rn        = vm.get_reg(instr.rn);
	immutable rt        = vm.get_reg(instr.rt);
	const size_t offset = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());	
	const size_t addr   = rn + offset;
	const uint   target = (rt & 0xffff);
	vm.write_half_word(addr, cast(ushort)target);
}

// STRH<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_strh_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("strh%s.w %s, [%s, %s%s]", get_condition_string(cond),
									         get_reg_name(instr.rt),
									         get_reg_name(instr.rn),
									         get_reg_name(instr.rm),
									         get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRH 										 *
// ***************************************************************************************

// STRH<c>.W <Rt>,[<Rn>{,#<imm12>}]
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_strh_imm_t2(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 12),
					rt:    cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4),
					index: true, 
					add:   true);
}

// STRH<c> <Rt>,[<Rn>,#-<imm8>]
// STRH<c> <Rt>,[<Rn>],#+/-<imm8>
// STRH<c> <Rt>,[<Rn>,#+/-<imm8>]!
instr_32 parse_strh_imm_t3(const uint instr) {
	return instr_32(imm:   slice(instr, 0, 8),
					rt:    cast(reg )slice(instr, 12, 4),
					rn:    cast(reg )slice(instr, 16, 4),
					wback: cast(bool)slice(instr,  8, 1), 
					add:   cast(bool)slice(instr,  9, 1),
					index: cast(bool)slice(instr, 10, 1));
}

void
execute_strh_imm_t2 
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_strh_imm(instr, vm);
}

void 
execute_strh_imm_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	execute_strh_imm(instr, vm);
}

void 
execute_strh_imm
(vm_t)
(const ref instr_32 instr, ref vm_t vm) { 
	immutable rn 	  		 = vm.get_reg(instr.rn);
	immutable rt 	  		 = vm.get_reg(instr.rt);
	immutable imm     		 = instr.imm;
	const size_t offset_addr = instr.add   ? rn + imm    : rn - imm;
	const size_t addr        = instr.index ? offset_addr : rn;
	const ushort data 		 = cast(ushort)(rt & 0xffff);
	vm.write_half_word(addr, data);
	if (instr.wback) 
		vm.set_reg(instr.rn, cast(uint)offset_addr);
}

string convert_strh_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
	return format("strh%s.w %s, %s", get_condition_string(cond),
								     get_reg_name(instr.rt),
								     get_addr_string(instr));
}

string convert_strh_imm_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("strh%s.w %s, [%s%s]", get_condition_string(cond),
								         get_reg_name(instr.rt),
								         get_reg_name(instr.rn),
								         instr.imm != 0 ? get_imm_string(instr.imm) : "");
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *								       STR 											 *
// ***************************************************************************************

// =====================
//  Parse STR(Register)
// =====================

// STR<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
// First Half-Word: [15:4] 111110000100, [3:0] Rn
// Second Half-Word: [15:12] Rt, [5:4] imm2, [3:0] Rm
instr_32 parse_str_reg_t2(const uint instr) {
	return instr_32(rm:      cast(reg)slice(instr,  0, 4),
					shift_n: slice(instr, 4, 2),
					shift_t: shift_type.lsl,
					rt:      cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4));
}

// =======================
//  Execute STR(Register)
// =======================

void 
execute_str_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm      = vm.get_reg(instr.rm);
	const int offset  = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	const size_t addr = vm.get_reg(instr.rn) + offset;
	immutable data    = vm.get_reg(instr.rt);
	vm.write_word(addr, data);
}

// STR<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_str_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("str%s.w %s, [%s, %s%s]", get_condition_string(cond),
											get_reg_name(instr.rt),
											get_reg_name(instr.rn),
											get_reg_name(instr.rm),
											get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *					                   STRB 										 *
// ***************************************************************************************

// STRB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
instr_32 parse_strb_reg_t2(const uint instr) {
	return instr_32(shift_n: slice(instr, 4, 2),
					rm:  	 cast(reg)slice(instr,  0, 4),
					rt:      cast(reg)slice(instr, 12, 4),
					rn:      cast(reg)slice(instr, 16, 4),
					shift_t: shift_type.lsl);
}

void 
execute_strb_reg_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable  rm     = vm.get_reg(instr.rm);
	immutable  rn     = vm.get_reg(instr.rn);
	immutable  rt     = vm.get_reg(instr.rt);
	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
	const uint offset = shift(rm, instr.shift_t, instr.shift_n, vm.get_c());
	// address = R[n] + offset;
	const size_t addr = rn + offset;
	// MemU[address,1] = R[t]<7:0>;
	vm.write_byte(addr, cast(ubyte)rt);
}


// STRB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]
string convert_strb_reg_t2_to_string(const ref instr_32 instr, const condition cond) {
	return format("strb%s.w %s, [%s, %s%s]", get_condition_string(cond),
											 get_reg_name(instr.rt),
											 get_reg_name(instr.rn),
											 get_reg_name(instr.rm),
											 get_shift_string(instr));
}
// ---------------------------------------------------------------------------------------