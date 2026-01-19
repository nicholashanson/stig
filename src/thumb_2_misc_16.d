import std.typecons : Tuple;
import std.algorithm;
import std.format;
import std.conv;
import std.array;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;
import memory_sections;

// ----------------------------------------- POP -----------------------------------------

// ====================
//  Parse Pop Mult Reg
// ====================

enum field_tuples_pop_mult_reg = [Tuple!(opcode, string[])(opcode.pop_mult_reg, ["reg_list"])];
/*
	Miscellaneous 16-bit Instructions
	LDM <Rn>!,<registers>
	[15:9] 11001, [10:8] Rn, [7:0] register_list  
*/
instr_16 parse_pop_mult_reg(short instr) {
	instr_16 res;
	res.op = opcode.pop_mult_reg;
	ubyte p = cast(ubyte)((instr >> 8) & 0b1);
	ubyte reg_mask = cast(ubyte)(instr & 0xff);
	if (reg_mask & 0x01) res.reg_list ~= reg.r0;
	if (reg_mask & 0x02) res.reg_list ~= reg.r1;
	if (reg_mask & 0x04) res.reg_list ~= reg.r2;
	if (reg_mask & 0x08) res.reg_list ~= reg.r3;
	if (reg_mask & 0x10) res.reg_list ~= reg.r4;
	if (reg_mask & 0x20) res.reg_list ~= reg.r5;
	if (reg_mask & 0x40) res.reg_list ~= reg.r6;
	if (reg_mask & 0x80) res.reg_list ~= reg.r7;
	if (p) {
		res.reg_list ~= reg.pc;
	}
	return res;
}

// ======================
//  Execute POP MULT REG
// ======================

void execute_pop_mult_reg(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = stack_log();
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	string stack_s = cpu.sp_sel ? "PSP" : "MSP";
	f.writeln(format("Popping from %s at [%08X]", stack_s, cpu.pc));
	foreach (r; regs) {
		uint addr = cpu.get_sp();
		int val = mem.pop(cpu);
		cpu.set(r, val);
		f.writeln(format("%s: [%08X] popped from [%08X]", r.to!string, cpu.get(r), addr));
		f.flush();
	}
	if (regs.back == reg.pc) {
		if ((cpu.pc & 0xff000000) == 0xff000000) {
	        exception_return(cpu, mem, cpu.pc);
	        return;
	    }
		uint pc = cpu.get(reg.pc);
		pc &= ~0b1;
		cpu.set(reg.pc, pc);
	} else {
		cpu.increment_pc(2);
	}
} 
// ---------------------------------------------------------------------------------------

// ---------------------------------------- SXTB -----------------------------------------

enum field_tuples_sxtb = [Tuple!(opcode, string[])(opcode.sxtb, ["rd","rm"])];
/*
	Miscellaneous 16-bit Instructions
	SXTB <Rd>,<Rm>
	[15:6] 1011001001, [5:3] Rm, [2:0] Rd  
*/
instr_16 parse_sxtb(ushort instr) {
	instr_16 res;
	res.op   = opcode.sxtb;
	ubyte rd = cast(ubyte)( instr       & 0x7);
	ubyte rm = cast(ubyte)((instr >> 3) & 0x7);
	res.rd   = cast(reg)(rd);
	res.rm   = cast(reg)(rm);
	return res;
}

void execute_sxtb(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm = cpu.get(instr.rm);
	const uint res = (rm & 0xff);
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------