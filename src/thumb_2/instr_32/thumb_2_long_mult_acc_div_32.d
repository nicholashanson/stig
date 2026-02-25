// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *	           Long Multiply, Long Multiply Accumulate and Divide	    			 *    
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

private uint slice(const ulong instr, const uint shift, const uint width) {
	return cast(uint)((instr >> shift) & decimal_to_hex_mask(width));
}

private uint decimal_to_hex_mask(uint n) {
    return (1u << n) - 1;
}

// ***************************************************************************************
// *									  SMULL 										 *
// ***************************************************************************************
// Signed Multiply Long multiplies two 32-bit signed values to produce a 64-bit result.

// =============
//  Parse SMULL
// =============

// SMULL <RdLo>,<RdHi>,<Rn>,<Rm>
// First Half-Word: [15:4] 111110111000, [3:0] Rn
// Second Half-Word: [15:12] RdLo, [11:8] RdHi, [7:4] 0000, [3:1] Rm 
instr_32 parse_smull_t1(const uint instr) {
	return instr_32(rm:    cast(reg)slice(instr,  0, 4),
					rd_hi: cast(reg)slice(instr,  8, 4),
					rd_lo: cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4));
}

// ===============
//  Execute SMULL
// ===============

void 
execute_smull_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	const int rm 	  = vm.get_reg(instr.rm); 
	const int rn 	  = vm.get_reg(instr.rn);
	const long res    = cast(long)rm * cast(long)rn;
	const uint res_hi = cast(uint)((res >> 32) & 0xffff_ffff);
	const uint res_lo = cast(uint)( res        & 0xffff_ffff);
	vm.set_reg(instr.rd_lo, res_lo);
	vm.set_reg(instr.rd_hi, res_hi);  
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UDIV 											 *
// ***************************************************************************************
// Unsigned Divide divides a 32-bit unsigned integer register value by a 32-bit unsigned 
// integer register value, and writes the result to the destination register. The 
// condition code flags are not affected.

// ============
//  Parse UDIV
// ============

// UDIV<c> <Rd>,<Rn>,<Rm>
// First Half-Word: [15:4] 11110111011, [3:0] Rn
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 1111, [3:0] Rm 
instr_32 parse_udiv_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd:	cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

// ==============
//  Execute UDIV
// ==============

void 
execute_udiv_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	if (vm.get_reg(instr.rm) == 0) {
		vm.set_reg(instr.rd, 0);
		return;
	}
	const uint res = vm.get_reg(instr.rn) / vm.get_reg(instr.rm);
	vm.set_reg(instr.rd, res);
}

// UDIV<c> <Rd>,<Rn>,<Rm>
string convert_udiv_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("udiv%s %s, %s, %s", get_condition_string(cond), 
									   get_reg_name(instr.rd),
									   get_reg_name(instr.rn),
									   get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UMULL											 *
// ***************************************************************************************
// Unsigned Multiply Long multiplies two 32-bit unsigned values to produce a 64-bit 
// result.

// UMULL<c> <RdLo>,<RdHi>,<Rn>,<Rm>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01110, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_umull_t1(const uint instr) {
	return instr_32(rm:    cast(reg)slice(instr,  0, 4),
					rd_hi: cast(reg)slice(instr,  8, 4),
					rd_lo: cast(reg)slice(instr, 12, 4),
					rn:    cast(reg)slice(instr, 16, 4));
}

// ===============
//  Execute UMULL
// ===============

void 
execute_umull_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	ulong res =
        cast(ulong)(vm.get_reg(instr.rn)) *
        cast(ulong)(vm.get_reg(instr.rm));
    vm.set_reg(instr.rd_lo, cast(uint)res);
    vm.set_reg(instr.rd_hi, cast(uint)(res >> 32));
}

string convert_umull_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("umull%s %s, %s, %s, %s", get_condition_string(cond),
											get_reg_name(instr.rd_lo),
											get_reg_name(instr.rd_hi),
											get_reg_name(instr.rn),
											get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UMLAL											 *
// ***************************************************************************************

// Unsigned Multiply Accumulate Long multiplies two unsigned 32-bit values to produce a 
// 64-bit value, and accumulates this with a 64-bit value.


// UMLAL<c> <RdLo>,<RdHi>,<Rn>,<Rm>
instr_32 parse_umlal_t1(const uint instr) {
	return instr_32(rm:    cast(reg)slice(instr,  0, 4),
				    rd_hi: cast(reg)slice(instr,  8, 4),
				    rd_lo: cast(reg)slice(instr, 12, 4),
				    rn:    cast(reg)slice(instr, 16, 4));
}

void 
execute_umlal_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable   rn    = vm.get_reg(instr.rn);
	immutable   rm    = vm.get_reg(instr.rm);
	immutable   rd_hi = vm.get_reg(instr.rd_hi);
	immutable   rd_lo = vm.get_reg(instr.rd_lo);
	const ulong acc   = (cast(ulong)rd_hi << 32) | cast(ulong)rd_lo;
	// result = UInt(R[n]) * UInt(R[m]) + UInt(R[dHi]:R[dLo]);
	const ulong res   = (cast(ulong)rn * cast(ulong)rm) + acc;
	// R[dHi] = result<63:32>;
	vm.set_reg(instr.rd_hi, slice(res, 32, 32));
	// R[dLo] = result<31:0>;
	vm.set_reg(instr.rd_lo, slice(res,  0, 32));
}

// UMLAL<c> <RdLo>,<RdHi>,<Rn>,<Rm>
string convert_umlal_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("umlal%s %s, %s, %s, %s", get_condition_string(cond),
											get_reg_name(instr.rd_lo),
											get_reg_name(instr.rd_hi),
											get_reg_name(instr.rn),
											get_reg_name(instr.rm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  UMAAL											 *
// ***************************************************************************************

// Unsigned Multiply Accumulate Accumulate Long multiplies two unsigned 32-bit values to 
// produce a 64-bit value, adds two unsigned 32-bit values, and writes the 64-bit result 
// to two registers.

// UMAAL<c> <RdLo>,<RdHi>,<Rn>,<Rm>
instr_32 parse_umaal_t1(const uint instr) {
	return instr_32(rm:    cast(reg)slice(instr,  0, 4),
				    rd_hi: cast(reg)slice(instr,  8, 4),
				    rd_lo: cast(reg)slice(instr, 12, 4),
				    rn:    cast(reg)slice(instr, 16, 4));
}

void 
execute_umaal_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	immutable rn    = vm.get_reg(instr.rn);
	immutable rm    = vm.get_reg(instr.rm);
	immutable rd_hi = vm.get_reg(instr.rd_hi);
	immutable rd_lo = vm.get_reg(instr.rd_lo);
	// result = UInt(R[n]) * UInt(R[m]) + UInt(R[dHi]) + UInt(R[dLo]);
	const ulong res = (cast(ulong)rn * cast(ulong)rm) + cast(ulong)rd_hi + cast(ulong)rd_lo;
	// R[dHi] = result<63:32>;
	vm.set_reg(instr.rd_hi, slice(res, 32, 32));
	// R[dLo] = result<31:0>;
	vm.set_reg(instr.rd_lo, slice(res,  0, 32));
}


// UMAAL<c> <RdLo>,<RdHi>,<Rn>,<Rm>
string convert_umaal_t1_to_string(const ref instr_32 instr, const condition cond) {
	return format("umaal%s %s, %s, %s, %s", get_condition_string(cond),
											get_reg_name(instr.rd_lo),
											get_reg_name(instr.rd_hi),
											get_reg_name(instr.rn),
											get_reg_name(instr.rm));
}