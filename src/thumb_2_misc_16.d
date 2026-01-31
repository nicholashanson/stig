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
instr_16 parse_pop_mult_reg(const ushort instr) {
	instr_16 res;
	res.op = opcode.pop_mult_reg;
	const ubyte p        = cast(ubyte)((instr >> 8) & 0x01);
	const ubyte reg_mask = cast(ubyte)( instr       & 0xff);
	foreach (i; 0 .. 8)
    	if (reg_mask & (1 << i))
        	res.reg_list ~= cast(reg)i;
	if (p) {
		res.reg_list ~= reg.pc;
	}
	return res;
}

// ======================
//  Execute POP MULT REG
// ======================

void execute_pop_mult_reg(const ref instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
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
		if ((cpu.pc & 0xff00_0000) == 0xff00_0000) {
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

// ---------------------------------------- PUSH -----------------------------------------

// =====================
//  Parse Push Mult Reg
// =====================

enum field_tuples_push_mult_reg = [Tuple!(opcode, string[])(opcode.push_mult_reg, ["reg_list"])];
/*
	Miscellaneous 16-bit Instructions
	PUSH <registers>
	[15:9] 1011010, [8] M, [7:0] register_list  
*/
instr_16 parse_push_mult_reg(short instr) {
	instr_16 res;
	res.op = opcode.push_mult_reg;
	const ubyte m        = cast(ubyte)((instr >> 8) & 0x01);
	const ubyte reg_mask = cast(ubyte)( instr       & 0xff);
	foreach (i; 0 .. 8)
    	if (reg_mask & (1 << i))
        	res.reg_list ~= cast(reg)i;
	if (m) {
		res.reg_list ~= reg.lr;
	}
	return res;
}

// =======================
//  Execute PUSH MULT REG
// =======================

void execute_push_mult_reg(instr_16 instr, ref cortex_m_cpu cpu, ref memory mem) {
	auto f = stack_log();
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a > cast(int)b);
	string stack_s = cpu.sp_sel ? "PSP" : "MSP";
	f.writeln(format("Pushing to %s at [%08X]", stack_s, cpu.pc));
	foreach (r; regs) {
		mem.push(cpu, cpu.get(r));
		f.writeln(format("%s: [%08X] pushed to [%08X]", r.to!string, cpu.get(r), cpu.get_sp()));
		f.flush();
	}
	cpu.increment_pc(2);
} 
// ---------------------------------------------------------------------------------------

// ---------------------------------------- SXTB -----------------------------------------

enum field_tuples_sxtb = [Tuple!(opcode, string[])(opcode.sxtb, ["rd","rm"])];
/*
	Miscellaneous 16-bit Instructions
	SXTB <Rd>,<Rm>
	[15:6] 1011001001, [5:3] Rm, [2:0] Rd  
*/
instr_16 parse_sxtb(const ushort instr) {
	instr_16 res;
	res.op   = opcode.sxtb;
	const ubyte rd = cast(ubyte)( instr       & 0x7);
	const ubyte rm = cast(ubyte)((instr >> 3) & 0x7);
	res.rd   = cast(reg)(rd);
	res.rm   = cast(reg)(rm);
	return res;
}

void execute_sxtb(const ref instr_16 instr, ref cortex_m_cpu cpu) {
	const uint rm  = cpu.get(instr.rm);
	const uint res = (rm & 0xff);
	cpu.set(instr.rd, res);
	cpu.increment_pc(2);
}
// ---------------------------------------------------------------------------------------