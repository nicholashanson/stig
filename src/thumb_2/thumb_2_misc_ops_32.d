// ***************************************************************************************
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *			                  Miscellaneous Operations	    					     *    
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// *									    											 *
// ***************************************************************************************

import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ***************************************************************************************
// *					                   RBIT 										 *
// ***************************************************************************************
// Reverse Bits reverses the bit order in a 32-bit register.

// ============
//  Parse RBIT
// ============

enum field_tuples_rbit_t2 = [Tuple!(opcode, string[])(opcode.rbit_t2, ["rd","rm"])];
// RBIT<c> <Rd>,<Rm>
// First Half-Word: [15:4] 111110101001, [3:0] Rm
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 1010, [3:0] Rm
instr_32 parse_rbit_t2(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr, 0, 4),
					rd: cast(reg)slice(instr, 8, 4));
}

// ==============
//  Execute RBIT
// ==============

void 
execute_rbit_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// if !Consistent(Rm) then UNPREDICTABLE;
	uint v = vm.get_reg(instr.rm);
	uint res;
	foreach (i; 0 .. 32) {
        res = (res << 1) | (v & 1);
        v >>= 1;
    }
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									  CLZ 											 *
// ***************************************************************************************
// Count Leading Zeros returns the number of binary zero bits before the first binary one 
// bit in a value.

// ===========
//  Parse CLZ
// ===========

enum field_tuples_clz_t1 = [Tuple!(opcode, string[])(opcode.clz_t1, ["rd","rm"])];
// CLZ<c> <Rd>,<Rm>
// First Half-Word: [15:4] 111110101011, [3:0] Rm
// Second Half-Word: [15:12] 1111, [11:8] Rd, [7:4] 1000, [3:0] Rm
instr_32 parse_clz_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr, 0, 4),
					rd: cast(reg)slice(instr, 8, 4));
}

// =============
//  Execute CLZ
// =============

void 
execute_clz_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	// if !Consistent(Rm) then UNPREDICTABLE;
	uint rm = vm.get_reg(instr.rm);
	if (rm == 0) {
		vm.set_reg(instr.rd, 32);
		return;
	}
	int count = 0;
	for (int i = 31; i >= 0; i--) {
        if (rm & (1u << i))
            break;
        count++;
    }
   	vm.set_reg(instr.rd, count);
}

// ***************************************************************************************
// *									  SEL 											 *
// ***************************************************************************************
// Select Bytes selects each byte of its result from either its first operand or its 
// second operand, according to the values of the GE flags.

// ===========
//  Parse SEL
// ===========

enum field_tuples_sel_t1 = [Tuple!(opcode, string[])(opcode.sel_t1, ["rd","rn","rm"])];
// SEL<c> <Rd>,<Rn>,<Rm>
instr_32 parse_sel_t1(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr,  0, 4),
					rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

// =============
//  Execute SEL
// =============

void 
execute_sel_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
	int rn = vm.get_reg(instr.rn);
	int rm = vm.get_reg(instr.rm);
	int rd0 = vm.get_ge3() ? ((rn >> 24) & 0xff) : ((rm >> 24) & 0xff); 
	int rd1 = vm.get_ge2() ? ((rn >> 16) & 0xff) : ((rm >> 16) & 0xff); 
	int rd2 = vm.get_ge1() ? ((rn >>  8) & 0xff) : ((rm >>  8) & 0xff); 
	int rd3 = vm.get_ge0() ? ((rn      ) & 0xff) : ((rm      ) & 0xff); 
	int res = (rd0 << 24) | (rd1 << 16) | (rd2 << 8) | rd3;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *									REVSH										     *
// ***************************************************************************************
// Byte-Reverse Signed Halfword reverses the byte order in the lower 16-bit halfword of a 
// 32-bit register, and sign extends the result to 32 bits.

// REVSH<c>.W <Rd>,<Rm>
instr_32 parse_revsh_t2(const uint instr) {
	return instr_32(rm: cast(reg)slice(instr, 0, 4),
				    rd: cast(reg)slice(instr, 8, 4));
}

void 
execute_revsh_t2
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	immutable rm  = vm.get_reg(instr.rm);
	// bits(32) result;
	// result<31:8> = SignExtend(R[m]<7:0>, 24);
	// result<7:0> = R[m]<15:8>;
	immutable res = cast(int)((rm << 8) & 0x0000_ff00) | ((rm >> 8) & 0x0000_00ff);
	// R[d] = result;
	vm.set_reg(instr.rd, res);
}
// ---------------------------------------------------------------------------------------