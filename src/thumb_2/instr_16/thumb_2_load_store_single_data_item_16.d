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

// LDR<c> <Rt>,[<Rn>,<Rm>]
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

// LDR<c> <Rt>,[<Rn>,<Rm>]
string convert_ldr_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldr%s %s, [%s, %s]", get_condition_string(cond),
										get_reg_name(instr.rt),
										get_reg_name(instr.rn),
										get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRB 										 *
// ***************************************************************************************

// =======================
//  Parse LDRB(Immediate)
// =======================

// LDRB<c> <Rt>,[<Rn>{,#<imm5>}]
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
(const ref instr_16 instr, ref vm_t vm) {
	immutable rt   = vm.get_reg(instr.rt);
	immutable rn   = vm.get_reg(instr.rn);
	size_t addr    = rn + instr.imm;
	immutable data = vm.read_byte(addr);
	vm.set_reg(instr.rt, cast(uint)data);
}

// LDRB<c> <Rt>,[<Rn>{,#<imm5>}]
string convert_ldrb_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldrb%s %s, [%s%s]", get_condition_string(cond),
									   get_reg_name(instr.rt),
									   get_reg_name(instr.rn),
									   get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRH 										 *
// ***************************************************************************************

// =======================
//  Parse LDRH(Immediate)
// =======================

// LDRH<c> <Rt>,[<Rn>{,#<imm5>}]
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

// LDRH<c> <Rt>,[<Rn>{,#<imm5>}]
string convert_ldrh_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldrh%s %s, [%s%s]", get_condition_string(cond),
									   get_reg_name(instr.rt),
									   get_reg_name(instr.rn),
									   get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRH 										 *
// ***************************************************************************************
// Load Register Halfword (register) calculates an address from a base register value and 
// an offset register value, loads a halfword from memory, zero-extends it to form a 
// 32-bit word, and writes it to a register. The offset register value can be shifted left 
// by 0, 1, 2, or 3 bits.

// ======================
//  Parse LDRH(Register)
// ======================

// LDRH<c> <Rt>,[<Rn>,<Rm>]
instr_16 parse_ldrh_reg_t1(const ushort instr) {
	return instr_16(rt: cast(reg)slice(instr, 0, 3),
	            	rn: cast(reg)slice(instr, 3, 3),
	            	rm: cast(reg)slice(instr, 6, 3),
	            	index: true, add: true);
	// index = TRUE; add = TRUE; wback = FALSE;
}

// ========================
//  Execute LDRH(Register)
// ========================

void 
execute_ldrh_reg_t1
(vm_t)
(const instr_16 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
	immutable rm 			 = vm.get_reg(instr.rm);
	immutable rn 			 = vm.get_reg(instr.rn);
	// offset_addr = if add then (R[n] + offset) else (R[n] - offset);
	const size_t offset_addr = instr.add   ? rn + rm     : rn - rm;
	// address = if index then offset_addr else R[n];
	const size_t addr 		 = instr.index ? offset_addr : rn;
	// data = MemU[address,2];
	immutable data 			 = vm.read_half_word(addr);
	// if wback then R[n] = offset_addr;
	// R[t] = ZeroExtend(data, 32);
	vm.set_reg(instr.rt, data);
}

// LDRH<c> <Rt>,[<Rn>,<Rm>]
string convert_ldrh_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldrh%s %s, [%s, %s]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 get_reg_name(instr.rn),
										 get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRH 										 *
// ***************************************************************************************

// ======================
//  Parse STRH(Register)
// ======================

// STRH<c> <Rt>,[<Rn>,<Rm>]
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
	vm.write_half_word(addr, cast(ushort)target);
}

// STRH<c> <Rt>,[<Rn>,<Rm>]
string convert_strh_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("strh%s %s, [%s, %s]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 get_reg_name(instr.rn),
										 get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRB 										 *
// ***************************************************************************************

// =======================
//  Parse STRRB(Register)
// =======================

// STRB<c> <Rt>,[<Rn>,<Rm>]
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
	vm.write_byte(addr, data);
}

// STRB<c> <Rt>,[<Rn>,<Rm>]
string convert_strb_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("strb%s %s, [%s, %s]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 get_reg_name(instr.rn),
										 get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 STR 											 *
// ***************************************************************************************

// ======================
//  Parse STR(Immediate) 
// ======================

// STR<c> <Rt>, [<Rn>{,#<imm5>}]
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

string convert_str_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("str%s %s, [%s%s]", get_condition_string(cond),
									  get_reg_name(instr.rt),
									  get_reg_name(instr.rn),
									  get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDR 										 *
// ***************************************************************************************

// ======================
//  Parse LDR(Immediate)
// ======================

// LDR<c> <Rt>, [<Rn>{,#<imm5>}]
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
(const ref instr_16 instr, ref vm_t vm) {
	immutable    rn   = vm.get_reg(instr.rn);
	const size_t addr = rn + instr.imm;
	immutable    data = vm.read_word(addr);
	vm.set_reg(instr.rt, data);
}

// LDR<c> <Rt>, [<Rn>{,#<imm5>}]
string convert_ldr_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldr%s %s, [%s%s]", get_condition_string(cond),
								      get_reg_name(instr.rt),
								      get_reg_name(instr.rn),
								      get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRH 										 *
// ***************************************************************************************

// =======================
//  Parse STRH(Immediate)
// =======================

// STRH<c> <Rt>,[<Rn>{,#<imm5>}]
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
(const ref instr_16 instr, ref vm_t vm) {
	immutable    rt     = vm.get_reg(instr.rt);
	immutable    rn     = vm.get_reg(instr.rn);
	const size_t addr   = rn + instr.imm;
	auto         target = vm.read_word(addr);
	target = (target & 0xffff_0000) | rt;  
	vm.write_half_word(addr, cast(ushort)target);
}

// STRH<c> <Rt>,[<Rn>{,#<imm5>}]
string convert_strh_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("strh%s %s, [%s%s]", get_condition_string(cond),
									   get_reg_name(instr.rt),
									   get_reg_name(instr.rn),
									   get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 STRB 										 *
// ***************************************************************************************

// ========================
//  Parse STRRB(Immediate)
// ========================

// STRB<c> <Rt>,[<Rn>,#<imm5>]
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

// STRB<c> <Rt>,[<Rn>,#<imm5>]
string convert_strb_imm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("strb%s %s, [%s%s]", get_condition_string(cond),
									   get_reg_name(instr.rt),
									   get_reg_name(instr.rn),
									   get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// LDR<c> <Rt>,[SP{,#<imm8>}]
// [15:11] 10011, [10:8] Rt, [7:0] imm8
instr_16 parse_ldr_imm_t2(const ushort instr) {
	return instr_16(rt: cast(reg)slice(instr, 8, 3),
				    imm: slice(instr, 0, 8) << 2);
}

void 
execute_ldr_imm_t2
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	immutable    sp   = vm.get_sp();
	const size_t addr = sp + instr.imm;
	immutable    data = vm.read_word(addr);
	vm.set_reg(instr.rt, data);
}

// LDR<c> <Rt>,[SP{,#<imm8>}]
string convert_ldr_imm_t2_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldr%s %s, [sp%s]", get_condition_string(cond),
									  get_reg_name(instr.rt),
									  get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// STR<c> <Rt>,[SP,#<imm8>]
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
(const ref instr_16 instr, ref vm_t vm) {
	immutable rt      = vm.get_reg(instr.rt);
	const size_t addr = vm.get_sp() + instr.imm;
	vm.write_word(addr, rt);
}

string convert_str_imm_t2_to_string(const ref instr_16 instr, const condition cond) {
	return format("str%s %s, [sp, #%d]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									 STR 											 *
// ***************************************************************************************

// =====================
//  Parse STR(Register)
// =====================

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
	vm.write_word(addr, data);
}

string convert_str_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("str%s %s, [%s, %s]", get_condition_string(cond),
										get_reg_name(instr.rt),
										get_reg_name(instr.rn),
										get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *										 LDRB 										 *
// ***************************************************************************************

// ======================
//  Parse LDRB(Register)
// ======================

// LDRB<c> <Rt>,[<Rn>,<Rm>]
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
	immutable rn   = vm.get_reg(instr.rn);
	immutable rm   = vm.get_reg(instr.rm);
	size_t addr    = rn + rm;
	immutable data = vm.read_byte(addr);
	vm.set_reg(instr.rt, cast(uint)data);
}

string convert_ldrb_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldrb%s %s, [%s, %s]", get_condition_string(cond),
										 get_reg_name(instr.rt),
										 get_reg_name(instr.rn),
										 get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LDRSB 										 *
// ***************************************************************************************
// Load Register Signed Byte (register) calculates an address from a base register value 
// and an offset register value, loads a byte from memory, sign-extends it to form a 
// 32-bit word, and writes it to a register. The offset register value can be shifted left 
// by 0, 1, 2, or 3 bits.

// ==========================
//  Executre LDRSB(Register)
// ==========================

// LDRSB<c> <Rt>,[<Rn>,<Rm>]
instr_16 parse_ldrsb_reg_t1(const ushort instr) {
	// index = TRUE; add = TRUE; wback = FALSE;
	return instr_16(rt: cast(reg)slice(instr, 0, 3),
					rn: cast(reg)slice(instr, 3, 3),
					rm: cast(reg)slice(instr, 6, 3),
					index: true, add: true);
}

// ==========================
//  Executre LDRSB(Register)
// ==========================

void
execute_ldrsb_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	// if ConditionPassed() then
	// EncodingSpecificOperations();
	immutable    rm   		 = vm.get_reg(instr.rm);
	immutable    rn          = vm.get_reg(instr.rn);
	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
	// offset_addr = if add then (R[n] + offset) else (R[n] - offset);
	const size_t offset_addr = instr.add   ? rn + rm     : rn - rm;  
	// address = if index then offset_addr else R[n];
	const size_t addr 		 = instr.index ? offset_addr : rn;
	// R[t] = SignExtend(MemU[address,1], 32);
	immutable    data 		 = cast(int)cast(byte)vm.read_byte(addr);
	vm.set_reg(instr.rt, data);
}

// LDRSB<c> <Rt>,[<Rn>,<Rm>]
string convert_ldrsb_reg_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldrsb%s %s, [%s, %s]", get_condition_string(cond),
										  get_reg_name(instr.rt),
										  get_reg_name(instr.rn),
										  get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  LDRSH										 *
// ***************************************************************************************
// Load Register Signed Halfword (register) calculates an address from a base register 
// value and an offset register value, loads a halfword from memory, sign-extends it to 
// form a 32-bit word, and writes it to a register. The offset register value can be 
// shifted left by 0, 1, 2, or 3 bits.

// ==========================
//  Executre LDRSH(Register)
// ==========================

// LDRSH<c> <Rt>,[<Rn>,<Rm>]
instr_16 parse_ldrsh_reg_t1(const ushort instr) {
	// index = TRUE; add = TRUE; wback = FALSE;
	return instr_16(rt: cast(reg)slice(instr, 0, 3),
					rn: cast(reg)slice(instr, 3, 3),
					rm: cast(reg)slice(instr, 6, 3),
					index: true, add: true);
}

// ==========================
//  Executre LDRSB(Register)
// ==========================

void
execute_ldrsh_reg_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	// if ConditionPassed() then
	// EncodingSpecificOperations();
	immutable    rm   		 = vm.get_reg(instr.rm);
	immutable    rn  		 = vm.get_reg(instr.rn);
	// offset = Shift(R[m], shift_t, shift_n, APSR.C);
	// offset_addr = if add then (R[n] + offset) else (R[n] - offset);
	const size_t offset_addr = instr.add   ? rn + rm     : rn - rm;  
	// address = if index then offset_addr else R[n];
	const size_t addr 		 = instr.index ? offset_addr : rn;
	// R[t] = SignExtend(MemU[address,1], 32);
	immutable    data 		 = cast(int)cast(short)vm.read_half_word(addr);
	vm.set_reg(instr.rt, data);
}
// ---------------------------------------------------------------------------------------

